"""
Asking this node's own web frontend whether it is actually serving.

`nginx_active` comes from `systemctl is-active nginx`, a liveness check.  On
August 24, 2026 that made an outage last 73 minutes instead of one: workers
aborted holding a shared memory lock, every respawned worker blocked on it,
and the master kept the listening sockets open.  systemd said active, the
kernel kept completing TCP handshakes, and clients waited in silence while
the GSLB kept handing the node out.

So this sends a real request through the public listener.

A timeout counts as failure; silence is exactly what we are catching.  Ping
and a plain TCP connect both looked healthy during that incident.  The
status code does not matter: any HTTP reply means a worker is serving, and
a check that fails because a site was renamed would soon be ignored.

Streaks: a node must fail several probes in a row to be marked down and pass
a couple to come back.  Being slow costs one probe interval; flapping DNS is
worse than either answer.
"""

import asyncio
import logging

import httpx

log = logging.getLogger("nfm.frontend")


class FrontendProbe:
    """
    Running verdict on whether this node's own listener serves.

    Kept in memory on purpose: after a restart the verdict is rebuilt from
    live probes rather than trusting stale state.
    """

    def __init__(self):
        # None means no verdict yet, which never triggers a withdrawal.
        self.serving = None
        self.detail = "not probed yet"
        self._fails = 0
        self._passes = 0

    async def probe_once(self, host, port, server_name, timeout):
        """
        One request through the listener.  Returns (ok, detail).

        verify=False on purpose: we only care whether nginx answers.
        Certificate expiry has its own alerting.
        """
        url = f"https://{host}:{port}/"
        headers = {}
        extensions = {}
        if server_name:
            # Land in the intended server block, not the default one.
            headers["Host"] = server_name
            extensions["sni_hostname"] = server_name

        try:
            async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(timeout)) as client:
                reply = await client.get(url, headers=headers, extensions=extensions)
        except httpx.TimeoutException:
            # The wedge case: nothing came back.
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
        Probe once and update the verdict if a streak is long enough.
        Returns the verdict (None until the first streak completes).
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
                # Loud: this takes the node out of DNS.
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
    Restarts nginx when this node's own listener stops answering.

    DNS withdrawal only routes around a wedge; this fixes it.  It must be a
    restart: shared memory zones survive a reload, so a lock held by a dead
    worker blocks the new workers too.  In the August 24, 2026 incident a
    reload at 21:45:21 changed nothing and the wedge lasted 72 more minutes.

    Rate limited with a cooldown and a daily cap.  Restarting every cycle
    just drops connections and buries the fault; at the cap the node stays
    withdrawn and logs loudly for a person.

    DNS withdrawal happens on an earlier cycle, so clients are already going
    elsewhere when the listener drops for the restart.
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

        True only when a restart ran and the agent reported success.  Never
        raises, since it runs from a scheduled job.
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

        # The agent refuses to restart if the config test fails; restarting
        # into a broken config would turn a wedge into a hard down.
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
