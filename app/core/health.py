"""
Watching the backends.

This is the piece that replaces the paid version's active health checks.  The
free nginx only notices a backend is bad after a real request to it already
failed, which means a user got the error first.  We probe on a schedule instead,
so a dead backend is out of the rotation before anybody hits it.

How a check turns into config:

  1. Probe every member on its interval.
  2. Count passes and fails in a row.  One bad check does nothing, because a
     single dropped packet is not an outage.
  3. Once a member crosses its threshold, its state flips.
  4. A state change asks for a config rewrite.  Those get debounced, so twenty
     backends flapping at once is still one reload.

The debounce is not a nicety.  Without it a network blip that fails thirty
checks at once would queue thirty reloads, and nginx would spend the next minute
doing nothing else.
"""

import asyncio
import json
import logging
import re
import ssl
import time
from collections import deque
from datetime import datetime, timezone

import httpx

from app.db import session_scope
from app.models import HealthEvent, MemberState, Pool, PoolMember, utcnow

log = logging.getLogger("nfm.health")

# Defaults for the three limits on how often a flapping backend may rewrite the
# config.  All three are settings now, and these are only the fallback for a
# caller that has no settings to hand.  See app/config.py for what they mean
# and why they are as slow as they are.
RELOAD_DEBOUNCE_SECONDS = 5
MIN_SECONDS_BETWEEN_RELOADS = 60
MAX_RELOADS_PER_HOUR = 12

# The window the hourly ceiling is counted over.
RELOAD_WINDOW_SECONDS = 3600


class HealthChecker:
    def __init__(self, node_name: str, on_change=None):
        self.node_name = node_name

        # Called when config needs rewriting.  Set by whoever wires this up,
        # normally the cluster manager, so a change here goes out to the fleet
        # rather than just this node.
        self.on_change = on_change

        self._running = False
        self._tasks = {}
        self._reload_pending = False
        self._last_reload = 0.0
        self._lock = asyncio.Lock()

        # When each of the last hour's config rewrites happened, so the ceiling
        # can be counted over a rolling window rather than a fixed one.  A
        # fixed window lets twice the limit through across its boundary, which
        # on a flapping fleet is exactly when it matters.
        self._recent_reloads = deque()

        # So the "something is flapping" message is said once per episode
        # rather than on every held change.
        self._throttle_announced = False

        # When each pool is next due a round of checks.  Keyed by pool id.
        # This is what lets a pool have its own interval while the loop itself
        # runs on the shortest one.
        self._next_due = {}

        # One client, reused.  Making a fresh one per check would redo the TLS
        # handshake every time and the connection pool would never do anything.
        self._client = None

    async def start(self):
        self._running = True

        # verify=False by default because backends very often have self signed
        # certs, and a health check that fails on the cert tells you nothing
        # about whether the app is up.  Per pool you can turn verification on.
        self._client = httpx.AsyncClient(
            verify=False,
            timeout=httpx.Timeout(10.0),
            follow_redirects=False,
            limits=httpx.Limits(max_connections=100, max_keepalive_connections=20),
        )
        log.info("health checker started")

    async def stop(self):
        self._running = False
        for task in self._tasks.values():
            task.cancel()
        if self._client:
            await self._client.aclose()

    # =========================================================================
    # The main loop
    # =========================================================================

    async def run_cycle(self):
        """
        Check everything once.

        Called on a timer by the scheduler.  We check every member of every pool
        at the same time rather than one after another, because a pool with 20
        backends and a 5 second timeout would take 100 seconds to walk serially,
        by which point the answers at the start are already stale.
        """
        if not self._running:
            return

        now = time.monotonic()

        with session_scope() as session:
            pools = session.query(Pool).filter(Pool.health_check_enabled == True).all()  # noqa: E712
            work = []
            for pool in pools:
                # Each pool sets its own interval, and this loop runs on the
                # shortest one in the fleet.  So we skip any pool that is not
                # due yet.  Without this, setting a pool to check every 60
                # seconds would do nothing, because the loop would check it
                # every time it ran anyway.
                due_at = self._next_due.get(pool.id, 0)
                if now < due_at:
                    continue
                self._next_due[pool.id] = now + max(pool.health_check_interval or 10, 2)

                for member in pool.members:
                    if not member.enabled:
                        continue
                    # An admin taking a box out beats any check.  Do not waste a
                    # probe on it and do not let a passing check put it back.
                    if member.admin_state == "maintenance":
                        continue
                    work.append((pool, member))

            if not work:
                return

            results = await asyncio.gather(
                *[self._check_member(pool, member) for pool, member in work],
                return_exceptions=True,
            )

            changed = False
            for (pool, member), result in zip(work, results):
                if isinstance(result, Exception):
                    log.error("check of %s blew up: %s", member.label, result)
                    continue
                if self._apply_result(session, pool, member, result):
                    changed = True

            session.commit()

        if changed:
            await self._request_reload()

    # =========================================================================
    # One check
    # =========================================================================

    async def _check_member(self, pool, member) -> dict:
        started = time.monotonic()
        port = pool.health_check_port or member.port

        try:
            if pool.effective_health_check_type == "tcp":
                ok, detail = await self._check_tcp(member.address, port,
                                                   pool.health_check_timeout)
            else:
                ok, detail = await self._check_http(pool, member, port)
        except asyncio.TimeoutError:
            ok, detail = False, f"timed out after {pool.health_check_timeout}s"
        except Exception as exc:
            ok, detail = False, f"{type(exc).__name__}: {exc}"

        elapsed = (time.monotonic() - started) * 1000
        return {"ok": ok, "detail": detail, "ms": round(elapsed, 1)}

    async def _check_tcp(self, address, port, timeout):
        """Just open a socket.  Right for databases and anything not http."""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(address, port), timeout=timeout
            )
            writer.close()
            await writer.wait_closed()
            return True, "connected"
        except asyncio.TimeoutError:
            return False, f"could not connect within {timeout}s"
        except OSError as exc:
            return False, f"connection failed: {exc}"

    async def _check_http(self, pool, member, port):
        scheme = "https" if pool.effective_health_check_type == "https" else "http"
        path = pool.health_check_path or "/"
        if not path.startswith("/"):
            path = "/" + path

        url = f"{scheme}://{member.address}:{port}{path}"

        headers = {}
        # The Host header matters a lot here.  A backend serving several sites
        # by name will hand back the wrong one, or a 404, if we do not tell it
        # which site we are asking about.  Then the health check says the
        # backend is down when it is perfectly fine.
        if pool.health_check_host_header:
            headers["Host"] = pool.health_check_host_header

        headers["User-Agent"] = "nginx-fleet-manager/health-check"

        # Send the pool token if there is one.  Without this, turning on backend
        # trust would make every health check fail the moment the backend starts
        # enforcing it, and the manager would mark a perfectly healthy pool down
        # and pull it out of service.  The check has to look like real traffic.
        if pool.token_active:
            token = pool.token
            if token:
                headers[pool.token_header or "X-Fleet-Token"] = token

        try:
            response = await self._client.request(
                pool.health_check_method or "GET",
                url,
                headers=headers,
                timeout=pool.health_check_timeout,
                extensions={"verify": pool.health_check_verify_tls},
            )
        except httpx.TimeoutException:
            return False, f"no answer within {pool.health_check_timeout}s"
        except httpx.ConnectError as exc:
            return False, f"could not connect: {exc}"
        except httpx.HTTPError as exc:
            return False, f"http error: {exc}"

        if not _status_matches(response.status_code, pool.health_check_expect_status):
            return False, (
                f"got status {response.status_code}, "
                f"wanted {pool.health_check_expect_status}"
            )

        if pool.health_check_expect_body:
            body = response.text[:65536]
            if pool.health_check_expect_body not in body:
                return False, f"body did not contain {pool.health_check_expect_body!r}"

        return True, f"status {response.status_code}"

    # =========================================================================
    # Turning a result into a state change
    # =========================================================================

    def _apply_result(self, session, pool, member, result) -> bool:
        """Update the member.  Gives back True when the state actually changed."""
        old_state = member.state
        member.last_check_at = utcnow()
        member.last_response_ms = result["ms"]
        member.check_count = (member.check_count or 0) + 1

        # Rolling average, weighted toward recent checks.  A plain average over
        # all time would take hours to notice a backend that just got slow.
        if member.avg_response_ms:
            member.avg_response_ms = round(member.avg_response_ms * 0.8 + result["ms"] * 0.2, 1)
        else:
            member.avg_response_ms = result["ms"]

        if result["ok"]:
            member.consecutive_ok += 1
            member.consecutive_fail = 0
            member.last_error = None
            # Cleared here, not on the transition, so a member that recovers
            # never carries a stale reason into the next render.
            member.down_reason = None

            if old_state != MemberState.UP and member.consecutive_ok >= (pool.health_check_rise or 2):
                member.state = MemberState.UP
                member.last_state_change = utcnow()
                self._record_event(session, pool, member, old_state, MemberState.UP,
                                   f"passed {member.consecutive_ok} checks in a row", result["ms"])
                self._start_slow_start(pool, member)
                return True
        else:
            member.consecutive_fail += 1
            member.consecutive_ok = 0
            member.fail_count = (member.fail_count or 0) + 1
            member.last_error = result["detail"][:500]

            if old_state != MemberState.DOWN and member.consecutive_fail >= (pool.health_check_fall or 3):
                member.state = MemberState.DOWN
                member.last_state_change = utcnow()
                # Captured once, at the transition, and left alone from here.
                # See PoolMember.down_reason for why this is not last_error.
                member.down_reason = (result["detail"] or "")[:255]
                self._record_event(session, pool, member, old_state, MemberState.DOWN,
                                   result["detail"], result["ms"])
                return True

        # Slow start ramp.  Once a member is up, its weight climbs back to
        # normal over the ramp window instead of taking full traffic instantly.
        if member.state == MemberState.UP and self._advance_slow_start(pool, member):
            return True

        return False

    # =========================================================================
    # Slow start, our stand in for the paid feature
    # =========================================================================

    def _start_slow_start(self, pool, member):
        """
        A member just came back.  Start it at a low weight.

        This is what stops a recovered backend from being knocked straight back
        over.  A JVM app that just restarted has a cold JIT and an empty
        connection pool, and giving it a third of your traffic immediately is a
        good way to make it fall over again.  Then it flaps, which is worse than
        it having stayed down.
        """
        cfg = pool.setting_map()
        if not cfg.get("slow_start_enabled"):
            return

        state = member.node_states()
        state["ramp_weight"] = 1
        state["ramp_started"] = time.time()
        member.per_node_state = json.dumps(state)
        log.info("%s is back, ramping it up from weight 1", member.label)

    def _advance_slow_start(self, pool, member) -> bool:
        """Move a ramping member's weight up a step.  True when it changed."""
        cfg = pool.setting_map()
        if not cfg.get("slow_start_enabled"):
            return False

        state = member.node_states()
        ramp_weight = state.get("ramp_weight")
        if ramp_weight is None or ramp_weight >= member.weight:
            return False

        window = int(cfg.get("slow_start_seconds", 60))
        started = state.get("ramp_started", time.time())
        elapsed = time.time() - started

        # Climb in a handful of steps.  Continuous would be nicer but every
        # change is a config reload, so five steps over the window is the right
        # trade between smooth and hammering nginx.
        steps = 5
        step_time = max(window / steps, 1)
        target_step = min(int(elapsed / step_time) + 1, steps)
        new_weight = max(1, round(member.weight * target_step / steps))

        if new_weight == ramp_weight:
            return False

        state["ramp_weight"] = new_weight
        if new_weight >= member.weight:
            state.pop("ramp_weight", None)
            state.pop("ramp_started", None)
            log.info("%s is back to full weight %s", member.label, member.weight)
        member.per_node_state = json.dumps(state)
        return True

    # =========================================================================
    # Adaptive weighting, our stand in for least_time
    # =========================================================================

    def adjust_weights(self, session, pool) -> bool:
        """
        Nudge weights based on how fast each backend has been answering.

        The paid version has least_time, which picks the fastest backend per
        request.  We cannot do that from out here, but we are already timing
        every health check, so we can lean traffic toward the quicker boxes.

        Two rails on this, because something that automatically moves traffic
        around can easily make a bad day worse:

          - weights move a little at a time, with a floor and a ceiling, so one
            slow check cannot pull a server out of rotation
          - if everything is slow we leave it alone, because that means the
            problem is downstream and shuffling weights would just pile load
            onto whichever box is least broken
        """
        cfg = pool.setting_map()
        if not cfg.get("adaptive_weight_enabled"):
            return False

        healthy = [m for m in pool.members
                   if m.enabled and m.state == MemberState.UP and m.avg_response_ms]
        if len(healthy) < 2:
            return False

        times = [m.avg_response_ms for m in healthy]
        fastest = min(times)
        average = sum(times) / len(times)

        # Everything is uniformly slow, so this is not a per backend problem.
        if fastest > float(cfg.get("adaptive_floor_ms", 1000)):
            log.debug("pool %s is slow across the board, leaving weights alone", pool.name)
            return False

        # Everything is close enough that moving weights would just be noise.
        if average > 0 and (max(times) - fastest) / average < 0.25:
            return False

        base = int(cfg.get("adaptive_base_weight", 10))
        min_w = int(cfg.get("adaptive_min_weight", 1))
        max_w = int(cfg.get("adaptive_max_weight", 20))

        changed = False
        for m in healthy:
            ideal = base * (fastest / m.avg_response_ms) if m.avg_response_ms else base
            ideal = max(min_w, min(max_w, round(ideal)))

            # Move one step at a time.  Jumping straight to the ideal makes
            # traffic slosh back and forth between backends every cycle.
            if ideal > m.weight:
                new = min(ideal, m.weight + 1)
            elif ideal < m.weight:
                new = max(ideal, m.weight - 1)
            else:
                continue

            if new != m.weight:
                log.info("adaptive weight: %s %s -> %s (avg %sms)",
                         m.label, m.weight, new, m.avg_response_ms)
                m.weight = new
                changed = True

        return changed

    # =========================================================================
    # Bookkeeping
    # =========================================================================

    def _record_event(self, session, pool, member, old_state, new_state, reason, ms):
        session.add(HealthEvent(
            pool_name=pool.name,
            member_address=member.label,
            node_name=self.node_name,
            old_state=old_state.value if hasattr(old_state, "value") else str(old_state),
            new_state=new_state.value if hasattr(new_state, "value") else str(new_state),
            reason=reason[:1000] if reason else None,
            response_ms=ms,
        ))
        level = log.warning if new_state == MemberState.DOWN else log.info
        level("%s in pool %s: %s -> %s (%s)",
              member.label, pool.name, old_state, new_state, reason)

    def _reload_limits(self):
        """The three limits, from settings, falling back to the constants."""
        try:
            from app.config import get_settings
            s = get_settings()
            return (s.health_reload_debounce,
                    s.health_reload_min_interval,
                    s.health_reload_max_per_hour)
        except Exception:
            return (RELOAD_DEBOUNCE_SECONDS,
                    MIN_SECONDS_BETWEEN_RELOADS,
                    MAX_RELOADS_PER_HOUR)

    async def _wait_for_room(self, cap):
        """
        Hold here until the last hour has room for another rewrite.

        Held, not dropped.  A change that is thrown away leaves the config
        disagreeing with reality until something unrelated happens to apply,
        and the whole point of this file is that the config says which backends
        are usable.  So a flapping pool makes the next rewrite late, never
        missing.
        """
        while True:
            now = time.time()
            while self._recent_reloads and now - self._recent_reloads[0] > RELOAD_WINDOW_SECONDS:
                self._recent_reloads.popleft()

            if len(self._recent_reloads) < cap:
                self._throttle_announced = False
                return

            wait = RELOAD_WINDOW_SECONDS - (now - self._recent_reloads[0]) + 1
            if not self._throttle_announced:
                self._throttle_announced = True
                log.error(
                    "backends have changed state often enough to rewrite the config "
                    "%d times in the last hour, which is the ceiling.  Something is "
                    "flapping and wants a person: check which pool is going up and "
                    "down, and consider raising its rise and fall thresholds.  The "
                    "pending change is not lost, it will be written in about %d "
                    "seconds.", cap, int(wait),
                )
            await asyncio.sleep(min(wait, 60))

    async def _request_reload(self):
        """
        Ask for a config rewrite, but not right this second.

        Three limits, and each one exists because of a different way this goes
        wrong.  The debounce collects a burst into one rewrite, so a switch
        rebooting and taking six backends with it is one reload rather than
        six.  The floor puts a hard minimum between rewrites.  The hourly
        ceiling catches the case neither of those does: a backend that flaps
        steadily, slowly, for hours.

        That last one is not theoretical.  On 24 August 2026 a pool went up and
        down repeatedly, each transition rewrote the config on every node, and
        four nginx reloads landed inside 102 seconds.  The fourth one killed
        every worker on one node and took the site down for over an hour.  The
        module that actually crashed has since been removed, but a health check
        that can drive nginx that hard is worth fixing on its own, because the
        next module to be unhappy about it will not announce itself either.
        """
        debounce, floor, cap = self._reload_limits()

        async with self._lock:
            if self._reload_pending:
                return
            self._reload_pending = True

        try:
            await asyncio.sleep(debounce)

            since_last = time.time() - self._last_reload
            if since_last < floor:
                await asyncio.sleep(floor - since_last)

            await self._wait_for_room(cap)

            async with self._lock:
                now = time.time()
                self._recent_reloads.append(now)
                self._last_reload = now
        finally:
            # Cleared however we leave, including cancellation.  Left set, this
            # node would never rewrite its config again for a health change and
            # would look perfectly healthy while doing it.
            async with self._lock:
                self._reload_pending = False

        if self.on_change:
            try:
                await self.on_change("health check state changed")
            except Exception:
                log.exception("could not push the config after a health change")


# ==============================================================================
# Helpers
# ==============================================================================

def _status_matches(status: int, expected: str) -> bool:
    """
    Does this status code count as healthy.

    Takes a comma separated list of codes and ranges, like "200-399" or
    "200,204,301".  Ranges are handy since most people mean "anything that is
    not an error" rather than one exact code.
    """
    if not expected:
        return 200 <= status < 400

    for part in str(expected).split(","):
        part = part.strip()
        if not part:
            continue
        if "-" in part:
            try:
                low, high = part.split("-", 1)
                if int(low) <= status <= int(high):
                    return True
            except ValueError:
                continue
        else:
            try:
                if status == int(part):
                    return True
            except ValueError:
                continue
    return False
