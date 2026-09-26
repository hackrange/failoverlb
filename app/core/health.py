"""
Active backend health checks, in place of the NGINX Plus feature.

Open source nginx only marks a backend bad after a real request fails.  This
probes members on a schedule instead:

  1. Probe each member on its pool's interval.
  2. Count consecutive passes and fails.
  3. Flip the member's state once it crosses the rise/fall threshold.
  4. Request a config rewrite.  Requests are debounced and rate limited, so
     many members changing at once still means one reload.
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

# Fallbacks for the reload rate limits; the real values come from settings.
# See app/config.py.
RELOAD_DEBOUNCE_SECONDS = 5
MIN_SECONDS_BETWEEN_RELOADS = 60
MAX_RELOADS_PER_HOUR = 12

# Window for MAX_RELOADS_PER_HOUR.
RELOAD_WINDOW_SECONDS = 3600


class HealthChecker:
    def __init__(self, node_name: str, on_change=None):
        self.node_name = node_name

        # Called when config needs rewriting.  Normally set by the cluster
        # manager so the change goes to the whole fleet.
        self.on_change = on_change

        self._running = False
        self._tasks = {}
        self._reload_pending = False
        self._last_reload = 0.0
        self._lock = asyncio.Lock()

        # Timestamps of recent rewrites, for a rolling hourly limit.  A fixed
        # window would allow twice the limit across its boundary.
        self._recent_reloads = deque()

        # Log the throttling message once per episode.
        self._throttle_announced = False

        # Next check time per pool id, so each pool keeps its own interval.
        self._next_due = {}

        # Shared client so connections and TLS sessions are reused.
        self._client = None

    async def start(self):
        self._running = True

        # verify=False by default since backends often use self signed
        # certs.  Pools can turn verification on.
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
        Run one round of checks for every pool that is due.

        Called by the scheduler.  Members are checked concurrently, since
        serial checks with timeouts would take too long on large pools.
        """
        if not self._running:
            return

        now = time.monotonic()

        with session_scope() as session:
            pools = session.query(Pool).filter(Pool.health_check_enabled == True).all()  # noqa: E712
            work = []
            for pool in pools:
                # The loop runs on the shortest interval; skip pools that
                # are not due yet.
                due_at = self._next_due.get(pool.id, 0)
                if now < due_at:
                    continue
                self._next_due[pool.id] = now + max(pool.health_check_interval or 10, 2)

                for member in pool.members:
                    if not member.enabled:
                        continue
                    # Maintenance overrides health; a passing check must
                    # not bring it back.
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
        """TCP connect check, for non-HTTP backends."""
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
        # Name-based virtual hosts need the right Host header, or they may
        # return the wrong site or a 404 and fail the check.
        if pool.health_check_host_header:
            headers["Host"] = pool.health_check_host_header

        headers["User-Agent"] = "nginx-fleet-manager/health-check"

        # Send the pool token, or backends enforcing it would fail every
        # check and be marked down.
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
        """Record a check result on the member.  True if config must change."""
        old_state = member.state
        member.last_check_at = utcnow()
        member.last_response_ms = result["ms"]
        member.check_count = (member.check_count or 0) + 1

        # Exponential moving average, so recent slowness shows up quickly.
        if member.avg_response_ms:
            member.avg_response_ms = round(member.avg_response_ms * 0.8 + result["ms"] * 0.2, 1)
        else:
            member.avg_response_ms = result["ms"]

        if result["ok"]:
            member.consecutive_ok += 1
            member.consecutive_fail = 0
            member.last_error = None
            # Cleared on any success, not only on the transition.
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
                # Set only at the transition.  See PoolMember.down_reason.
                member.down_reason = (result["detail"] or "")[:255]
                self._record_event(session, pool, member, old_state, MemberState.DOWN,
                                   result["detail"], result["ms"])
                return True

        # Slow start: step the weight of a recovered member back up.
        if member.state == MemberState.UP and self._advance_slow_start(pool, member):
            return True

        return False

    # =========================================================================
    # Slow start, our stand in for the paid feature
    # =========================================================================

    def _start_slow_start(self, pool, member):
        """
        Start a recovered member at weight 1.

        A freshly restarted app (cold caches, empty connection pools) can be
        knocked over again by full traffic and start flapping.
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
        """Advance a ramping member's weight.  True if it changed."""
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

        # Five steps over the window, since each step is a config reload.
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
        Shift weights toward faster backends, using health check timings.

        A rough substitute for the Plus least_time method.  Weights move one
        step per cycle within min/max bounds, and nothing changes when every
        member is slow, since that points to a shared downstream problem.
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

        # Slow across the board: not a per-backend problem.
        if fastest > float(cfg.get("adaptive_floor_ms", 1000)):
            log.debug("pool %s is slow across the board, leaving weights alone", pool.name)
            return False

        # Differences too small to act on.
        if average > 0 and (max(times) - fastest) / average < 0.25:
            return False

        base = int(cfg.get("adaptive_base_weight", 10))
        min_w = int(cfg.get("adaptive_min_weight", 1))
        max_w = int(cfg.get("adaptive_max_weight", 20))

        changed = False
        for m in healthy:
            ideal = base * (fastest / m.avg_response_ms) if m.avg_response_ms else base
            ideal = max(min_w, min(max_w, round(ideal)))

            # One step at a time to avoid oscillation.
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
        Wait until the rolling hourly limit has room for another rewrite.

        Changes are delayed, never dropped, so the config eventually matches
        actual backend state.
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
        Request a config rewrite, subject to three limits.

        The debounce merges a burst of changes into one rewrite, the floor
        sets a minimum gap between rewrites, and the hourly cap catches a
        backend that flaps slowly for hours.  On August 24, 2026 a flapping
        pool caused four reloads in 102 seconds, and the last one killed every
        worker on a node.
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
            # Must be cleared even on cancellation, or health changes would
            # silently never trigger a rewrite again.
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
    Whether a status code is healthy.  `expected` is a comma separated list
    of codes and ranges, e.g. "200-399" or "200,204,301"; empty means 2xx/3xx.
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
