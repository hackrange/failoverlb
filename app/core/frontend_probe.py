"""
Asking this node's own web frontend whether it is actually serving.

Why this is not the same thing as `nginx_active`
------------------------------------------------

`nginx_active` comes from `systemctl is-active nginx`, which answers "is the
service running".  That is a liveness check, and on 24 August 2026 it is the
reason an outage lasted 73 minutes instead of one.

nginx workers aborted and left a shared memory lock held by a dead process.
Every worker respawned afterwards blocked on that lock forever.  The master
stayed up and kept the listening sockets, so:

  - systemd saw a healthy service and said `active`
  - the kernel went on completing TCP handshakes that no worker would ever read
  - clients connected, waited in silence, and gave up

The GSLB kept handing that node out for the whole outage, because the only
signal it had said the service was running.  It was.  It was not serving
anything.

So this asks the other question: put a real request through the public
listener and see whether a reply comes back.

What counts as failure, and why a hang has to
---------------------------------------------

A timeout is a failure here, not an inconclusive result.  That is the entire
point, because the thing being caught is silence rather than an error code.
Nothing cheaper catches it.  During that incident ICMP replied normally the
whole time, and port 80 completed its TCP handshake in 0.06 seconds before
going quiet, so a ping check and a plain TCP connect check would both have
called the node perfectly healthy.

What does not count as failure is the *status code*.  Any HTTP reply at all
means a worker read the request and wrote an answer, which is what we are
actually asking about.  A 404 from a node with no matching site is a serving
node.  Grading the status code here would mean this check starts failing
because somebody renamed a site, and a health signal that goes red for reasons
unrelated to health is one people learn to ignore.

Why the streaks
---------------

Withdrawing a node from DNS is not free, and a single dropped packet is not an
outage.  A node has to fail several times in a row before it is called down,
and succeed a couple of times before it is called up again.  The cost of being
slow here is one extra probe interval.  The cost of flapping is a name that
changes every thirty seconds, which is worse than either answer.
"""

import asyncio
import logging

import httpx

log = logging.getLogger("nfm.frontend")


class FrontendProbe:
    """
    Keeps the running verdict on whether this node's own listener serves.

    Deliberately holds its streaks in memory rather than the database.  The
    verdict is about right now, and a manager that has just restarted should
    work it out again from live probes rather than trusting what the last one
    believed before it went away.
    """

    def __init__(self):
        # None means "no verdict yet", which is not the same as False.  Nothing
        # is withdrawn on the strength of never having been asked.
        self.serving = None
        self.detail = "not probed yet"
        self._fails = 0
        self._passes = 0

    async def probe_once(self, host, port, server_name, timeout):
        """
        One request through the listener.  Returns (ok, detail).

        verify=False on purpose.  We are asking whether nginx answers, not
        whether its certificate is any good, and a node whose cert has expired
        is still serving every client that has not noticed.  Certificate expiry
        has its own alerting and should not be laundered through this.
        """
        url = f"https://{host}:{port}/"
        headers = {}
        extensions = {}
        if server_name:
            # Ask as a real client would, so we land in the right server block
            # rather than whichever one happens to be the default.
            headers["Host"] = server_name
            extensions["sni_hostname"] = server_name

        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(timeout)) as client:
                reply = await client.get(url, headers=headers, extensions=extensions)
        except httpx.TimeoutException:
            # The interesting one.  Connected, or did not even manage that, and
            # then nothing came back.  This is the wedge.
            return False, f"no answer within {timeout}s"
        except httpx.ConnectError as exc:
            return False, f"could not connect: {exc}"
        except httpx.HTTPError as exc:
            return False, f"request failed: {exc}"
        except (OSError, asyncio.TimeoutError) as exc:
            return False, f"request failed: {exc}"

        return True, f"answered {reply.status_code}"

    async def run_cycle(self, host, port, server_name, timeout, fail_after, pass_after):
        """
        Probe once and move the verdict if a streak is long enough.

        Returns the verdict, which is None until the first streak completes.
        """
        ok, detail = await self.probe_once(host, port, server_name, timeout)
        self.detail = detail

        if ok:
            self._passes += 1
            self._fails = 0
            if self.serving is not True and self._passes >= pass_after:
                if self.serving is False:
                    log.warning("this node's frontend is serving again: %s", detail)
                else:
                    log.info("this node's frontend is serving: %s", detail)
                self.serving = True
        else:
            self._fails += 1
            self._passes = 0
            if self.serving is not False and self._fails >= fail_after:
                # Loud, because this is the node taking itself out of DNS.
                log.error(
                    "this node's frontend has failed %d probes in a row (%s), "
                    "so it should stop being handed out",
                    self._fails, detail,
                )
                self.serving = False
            elif self.serving is not False:
                log.warning("frontend probe failed (%d of %d): %s",
                            self._fails, fail_after, detail)

        return self.serving


class FrontendWatchdog:
    """
    Restarts nginx when this node's own listener has stopped answering.

    Withdrawing the node from DNS routes around the problem.  It does not fix
    it, and on 24 August 2026 nothing did until a person restarted the box 73
    minutes in.  This is the part that fixes it.

    Why restart and not reload
    --------------------------

    A reload cannot clear this.  nginx's shared memory zones are created by the
    master at startup and survive a reload, so a zone left locked by a worker
    that died holding the lock is handed straight back to the new workers and
    they block on it too.  The logs from that incident show it plainly: there
    was a reload at 21:45:21, seconds after the crash storm, and the wedge
    carried on for another 72 minutes.  Only a full stop and start builds the
    zones again.

    Why it is rate limited
    ----------------------

    A restart that fixes nothing, repeated every cycle, is its own outage: it
    drops in flight connections over and over and hides the fault in a wall of
    log lines.  So there is a cooldown between attempts and a daily cap, and
    when the cap is reached this stops and says so.  A node that needs
    restarting five times a day has a problem a restart is not going to solve,
    and at that point the right thing is to stay withdrawn and be loud.

    The order matters.  DNS withdrawal is written first, on the cycle before
    this is reached, so clients are already being sent elsewhere by the time
    the listener drops for a restart.
    """

    def __init__(self):
        self._last_restart = None
        self._day = None
        self._today = 0

    def _rollover(self, now):
        day = int(now // 86400)
        if self._day != day:
            self._day = day
            self._today = 0

    def may_restart(self, now, cooldown, max_per_day):
        """Whether to try, and if not, why not.  Returns (ok, reason)."""
        self._rollover(now)

        if self._today >= max_per_day:
            return False, (f"already restarted nginx {self._today} times today, "
                           f"which is the limit.  Something here needs a person.")

        if self._last_restart is not None:
            waited = now - self._last_restart
            if waited < cooldown:
                return False, (f"restarted nginx {int(waited)}s ago, waiting "
                               f"{int(cooldown - waited)}s more before trying again")

        return True, ""

    async def repair(self, now, cooldown, max_per_day, detail=""):
        """
        Restart nginx, if we are allowed to right now.

        Returns True only when a restart actually ran and the agent said it
        worked.  Never raises: this is called from a scheduled job and a
        watchdog that takes the manager down with it is worse than no watchdog.
        """
        from app.core import audit
        from app.core.agent_client import AgentError, get_agent

        ok, why = self.may_restart(now, cooldown, max_per_day)
        if not ok:
            log.error("this node's frontend is still not serving, but %s", why)
            return False

        self._last_restart = now
        self._today += 1

        log.error("restarting nginx because this node's own listener stopped "
                  "answering (%s).  This is attempt %d today.", detail, self._today)

        try:
            result = await get_agent().service("restart")
        except AgentError as exc:
            log.error("could not ask the agent to restart nginx: %s", exc)
            audit.record("nginx_watchdog_restart", result="failure",
                         object_type="service", object_name="nginx",
                         detail=f"agent refused: {exc}")
            return False
        except Exception as exc:
            log.exception("the watchdog blew up asking for a restart")
            audit.record("nginx_watchdog_restart", result="failure",
                         object_type="service", object_name="nginx",
                         detail=f"watchdog error: {exc}")
            return False

        worked = bool(result.get("ok"))
        output = (result.get("output") or result.get("note") or "").strip()

        # The agent tests the config before it restarts and refuses if it does
        # not pass, which is the right call: restarting into a config nginx will
        # not load turns a wedge into a node that is properly down.
        audit.record(
            "nginx_watchdog_restart",
            result="success" if worked else "failure",
            object_type="service", object_name="nginx",
            detail=f"listener probe said: {detail}. agent said: {output}"[:65536],
        )

        if worked:
            log.warning("nginx restarted.  The listener should start answering "
                        "again within a couple of probes.")
        else:
            log.error("the restart did not work: %s", output)

        return worked


_probe = None
_watchdog = None


def get_probe():
    global _probe
    if _probe is None:
        _probe = FrontendProbe()
    return _probe


def get_watchdog():
    global _watchdog
    if _watchdog is None:
        _watchdog = FrontendWatchdog()
    return _watchdog
