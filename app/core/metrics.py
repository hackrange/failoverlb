"""
Connection and request numbers, with a short in-memory history.

Open source nginx only offers `stub_status`: seven server-wide numbers, none
per site.  Four are counters, so sampling twice gives a rate.

The recent detail lives in memory; a restart loses it and nginx's counters
carry on.  Longer history is kept by `metrics_store.py`.

Per-site and per-backend numbers (as NGINX Plus shows) would need access log
parsing; see docs/plus-parity.md.
"""
import logging
import time
from collections import deque

log = logging.getLogger("nfm.metrics")

# Two hours at one sample every fifteen seconds.
MAX_SAMPLES = 480

# Counters only mean something as a difference between two readings;
# gauges stand on their own.
COUNTERS = ("accepts", "handled", "requests")
GAUGES = ("active_connections", "reading", "writing", "waiting",
          "cpu_percent", "memory_percent", "memory_used", "memory_total",
          "load_1m", "swap_percent", "disk_percent")


def read_host() -> dict:
    """
    Host CPU, memory, load and disk from /proc.

    Read here, not through the agent: the agent runs with `ProcSubset=pid`
    and can't see /proc/stat or /proc/meminfo, and we won't widen the root
    component for a chart.  The container shares the host kernel's view.

    cpu is raw jiffies (counters); the caller turns two readings into a
    percentage.  Memory uses MemAvailable, not MemFree, which counts page
    cache as used and makes a healthy box look full.
    """
    out = {}

    try:
        with open("/proc/stat") as fh:
            for line in fh:
                if line.startswith("cpu "):
                    parts = [int(v) for v in line.split()[1:]]
                    names = ("user", "nice", "system", "idle", "iowait",
                             "irq", "softirq", "steal")
                    out["cpu"] = dict(zip(names, parts))
                    break
    except (OSError, ValueError):
        pass

    try:
        mem = {}
        with open("/proc/meminfo") as fh:
            for line in fh:
                key, _, rest = line.partition(":")
                bits = rest.strip().split()
                if bits and bits[0].isdigit():
                    mem[key] = int(bits[0]) * 1024
        total = mem.get("MemTotal", 0)
        available = mem.get("MemAvailable", 0)
        if total:
            out["memory_total"] = total
            out["memory_used"] = max(0, total - available)
            out["memory_percent"] = round((total - available) / total * 100, 1)
        swap_total = mem.get("SwapTotal", 0)
        if swap_total:
            out["swap_percent"] = round(
                (swap_total - mem.get("SwapFree", 0)) / swap_total * 100, 1)
    except (OSError, ValueError):
        pass

    try:
        with open("/proc/loadavg") as fh:
            out["load_1m"] = float(fh.read().split()[0])
    except (OSError, ValueError, IndexError):
        pass

    try:
        import shutil
        usage = shutil.disk_usage("/etc/nginx")
        if usage.total:
            out["disk_percent"] = round(usage.used / usage.total * 100, 1)
    except OSError:
        pass

    return out


def cpu_percent(older: dict, newer: dict):
    """
    Busy time between two /proc/stat readings, as a percentage.

    None when a reading is missing or the counters went backwards (a
    reboot).  A gap must not be drawn as zero.
    """
    if not older or not newer:
        return None
    busy_keys = ("user", "nice", "system", "irq", "softirq", "steal")
    try:
        total_old = sum(older.values())
        total_new = sum(newer.values())
        busy_old = sum(older.get(k, 0) for k in busy_keys)
        busy_new = sum(newer.get(k, 0) for k in busy_keys)
    except (TypeError, AttributeError):
        return None

    span = total_new - total_old
    if span <= 0:
        return None
    return round(max(0.0, min(100.0, (busy_new - busy_old) / span * 100)), 1)


class MetricsHistory:
    """Samples for one node, oldest first."""

    def __init__(self):
        self.samples = deque(maxlen=MAX_SAMPLES)

    def add(self, metrics: dict, host: dict = None, when: float = None):
        when = when or time.time()
        row = {"at": when}
        for key in COUNTERS:
            if key in metrics:
                row[key] = int(metrics[key])

        host = host or {}
        for key in GAUGES:
            if key in metrics:
                row[key] = int(metrics[key])
            elif key in host:
                row[key] = host[key]

        # Raw jiffies, kept internally for the next sample's percentage.
        if host.get("cpu"):
            row["_cpu"] = host["cpu"]
            previous = self.samples[-1].get("_cpu") if self.samples else None
            busy = cpu_percent(previous, host["cpu"])
            if busy is not None:
                row["cpu_percent"] = busy

        self.samples.append(row)

    def latest(self):
        if not self.samples:
            return None
        # Hide internal keys like the raw jiffies.
        return {k: v for k, v in self.samples[-1].items() if not k.startswith("_")}

    def rates(self):
        """
        Per second rates from the last two samples.  None with fewer than
        two samples.  A counter going backwards (nginx restarted) gives None
        for that rate rather than a negative number.
        """
        if len(self.samples) < 2:
            return None

        older, newer = self.samples[-2], self.samples[-1]
        seconds = newer["at"] - older["at"]
        if seconds <= 0:
            return None

        out = {}
        for key in COUNTERS:
            if key not in older or key not in newer:
                continue
            delta = newer[key] - older[key]
            if delta < 0:
                out[key + "_per_sec"] = None
                continue
            out[key + "_per_sec"] = round(delta / seconds, 2)

        # Accepted but not handled.  Nonzero means the box is out of worker
        # connections or file handles.
        if out.get("accepts_per_sec") is not None and out.get("handled_per_sec") is not None:
            out["dropped_per_sec"] = round(
                max(0.0, out["accepts_per_sec"] - out["handled_per_sec"]), 2)
        return out

    def series(self, key, limit=120):
        """
        Recent values of one key for a chart.  Missing values are omitted,
        not sent as zero, so the chart breaks the line at gaps (restarts,
        unreachable nodes).
        """
        rows = list(self.samples)[-limit:]
        return [{"at": round(r["at"], 1), "value": r[key]}
                for r in rows if r.get(key) is not None]

    def rate_series(self, limit=120):
        """
        Request rate between each pair of samples.  Pairs spanning a
        restart (counter went backwards) are skipped so the line breaks
        instead of spiking.
        """
        rows = list(self.samples)[-(limit + 1):]
        out = []
        for older, newer in zip(rows, rows[1:]):
            if "requests" not in older or "requests" not in newer:
                continue
            seconds = newer["at"] - older["at"]
            delta = newer["requests"] - older["requests"]
            if seconds <= 0 or delta < 0:
                continue
            out.append({"at": round(newer["at"], 1),
                        "value": round(delta / seconds, 2)})
        return out


class MemberHistory:
    """
    Samples for one backend from its exporter.

    Separate from node histories: we don't own backends, they may publish
    nothing, and the numbers may describe a machine or one process.  `level`
    travels with the numbers so a busy JVM isn't read as a busy box.
    """

    def __init__(self):
        self.samples = deque(maxlen=MAX_SAMPLES)
        self.level = None
        self.error = None

    def add(self, reading: dict, when: float = None):
        from app.core import exporters

        when = when or time.time()
        reading = dict(reading or {})
        reading["at"] = when

        row = {"at": when}
        for key in ("memory_percent", "memory_used", "memory_total", "load_1m"):
            if reading.get(key) is not None:
                row[key] = reading[key]

        previous = self._last_reading
        busy = exporters.cpu_percent(previous, reading)
        if busy is not None:
            row["cpu_percent"] = busy

        self._last_reading = reading
        self.level = reading.get("level") or self.level
        self.samples.append(row)

    _last_reading = None

    def latest(self):
        return dict(self.samples[-1]) if self.samples else None

    def series(self, key, limit=120):
        rows = list(self.samples)[-limit:]
        return [{"at": round(r["at"], 1), "value": r[key]}
                for r in rows if r.get(key) is not None]


class MetricsCollector:
    """
    Polls stub_status (local agent and peers) on a timer and keeps one
    history per node, so every node shows the whole fleet.
    """

    def __init__(self, node_name: str):
        self.node_name = node_name
        self.history = {}
        self.last_error = {}
        # Keyed by pool name, then by member label.
        self.members = {}

    def _member(self, pool_name: str, label: str) -> "MemberHistory":
        pool = self.members.setdefault(pool_name, {})
        if label not in pool:
            pool[label] = MemberHistory()
        return pool[label]

    async def collect_members(self):
        """
        Read each pool's backend exporters, where configured.

        Every node polls for itself, like the health checker, so a backend
        reachable from one node but not another shows up as a routing issue.

        Never raises; failures are recorded per backend.
        """
        import httpx

        from app.core import exporters
        from app.db import session_scope
        from app.models import Pool

        with session_scope() as session:
            wanted = []
            for pool in session.query(Pool).all():
                template = (pool.setting_map() or {}).get("member_metrics_url")
                if not template:
                    continue
                for member in pool.members:
                    if not member.enabled:
                        continue
                    wanted.append((pool.name, member.label,
                                   exporters.build_url(template, member.address,
                                                       member.port)))

        if not wanted:
            return

        async with httpx.AsyncClient(verify=False, timeout=httpx.Timeout(8.0),
                                     follow_redirects=False) as client:
            for pool_name, label, url in wanted:
                history = self._member(pool_name, label)

                # Re-check after expanding {host}: the save time check can't
                # see a member whose address is loopback.
                bad = exporters.unsafe_fetch_target(url)
                if bad:
                    history.error = bad
                    continue

                try:
                    response = await client.get(url)
                    if response.status_code != 200:
                        history.error = f"{url} answered {response.status_code}"
                        continue
                    body = response.text
                    if len(body) > exporters.MAX_BODY_BYTES:
                        history.error = "that endpoint answered with far too much text"
                        continue
                    reading = exporters.parse(body)
                    if not reading:
                        history.error = ("nothing recognisable at that endpoint.  "
                                         "It wants the Prometheus text format.")
                        continue
                    history.add(reading)
                    history.error = None
                except Exception as exc:
                    history.error = str(exc)

    def member_snapshot(self, with_series=False, limit=120) -> dict:
        out = {}
        for pool_name, members in self.members.items():
            rows = {}
            for label, hist in members.items():
                row = {
                    "latest": hist.latest(),
                    "level": hist.level,
                    "error": hist.error,
                    "samples": len(hist.samples),
                }
                if with_series:
                    row["series"] = {
                        key: hist.series(key, limit=limit)
                        for key in ("cpu_percent", "memory_percent")
                    }
                rows[label] = row
            out[pool_name] = rows
        return out

    def _for(self, node: str) -> MetricsHistory:
        if node not in self.history:
            self.history[node] = MetricsHistory()
        return self.history[node]

    async def collect(self):
        """One collection round.  Never raises."""
        from app.core.agent_client import get_agent
        from app.core.cluster import PeerClient, get_cluster
        from app.db import session_scope
        from app.models import Node

        host = read_host()
        try:
            result = await get_agent().nginx_metrics()
            if result.get("ok") and result.get("metrics"):
                self._for(self.node_name).add(result["metrics"], host=host)
                self.last_error.pop(self.node_name, None)
            else:
                # Keep host numbers even when nginx doesn't answer.
                self._for(self.node_name).add({}, host=host)
                self.last_error[self.node_name] = result.get("error") or "no numbers came back"
        except Exception as exc:
            self._for(self.node_name).add({}, host=host)
            self.last_error[self.node_name] = str(exc)

        cluster = get_cluster()
        try:
            with session_scope() as session:
                peers = [(p.id, p.name) for p in cluster.peers(session)]
        except Exception:
            return

        # Forget nodes that left the cluster, or a removed node keeps being
        # drawn on the dashboard with stale readings.
        known = {self.node_name} | {name for _id, name in peers}
        for gone in [name for name in self.history if name not in known]:
            self.history.pop(gone, None)
            self.last_error.pop(gone, None)
            log.info("%s is no longer in the cluster, so its numbers are "
                     "dropped from the dashboard", gone)

        for peer_id, peer_name in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == peer_id).first()
                    if not node:
                        continue
                    client = PeerClient(node, cluster.ca)
                # The key is `payload`, and the reply is already unwrapped
                # (/peer/agent returns what AgentClient.call returns).  Get
                # either wrong and a healthy peer reports "no numbers came
                # back".
                data = await client.call(
                    "/peer/agent",
                    {"verb": "nginx_metrics", "payload": {}},
                    timeout=15) or {}

                # The peer's /proc numbers come from its manager, not its
                # agent, which can't read /proc/stat (see read_host).
                try:
                    peer_host = await client.call("/peer/host-metrics", {},
                                                  timeout=15) or {}
                except Exception:
                    peer_host = {}

                if data.get("ok") and data.get("metrics"):
                    self._for(peer_name).add(data["metrics"], host=peer_host)
                    self.last_error.pop(peer_name, None)
                else:
                    self._for(peer_name).add({}, host=peer_host)
                    self.last_error[peer_name] = data.get("error") or "no numbers came back"
            except Exception as exc:
                # Unreachable peers are the cluster page's concern.
                self.last_error[peer_name] = str(exc)

    def snapshot(self, with_series=False, limit=120) -> dict:
        out = {}
        for node, hist in self.history.items():
            row = {
                "latest": hist.latest(),
                "rates": hist.rates(),
                "samples": len(hist.samples),
                "error": self.last_error.get(node),
            }
            if with_series:
                row["series"] = {
                    key: hist.series(key, limit=limit)
                    for key in ("cpu_percent", "memory_percent",
                                "active_connections", "load_1m")
                }
                row["series"]["requests_per_sec"] = hist.rate_series(limit=limit)
            out[node] = row
        for node, err in self.last_error.items():
            out.setdefault(node, {"latest": None, "rates": None,
                                  "samples": 0, "error": err})
        return out


_collector = None


def get_collector(node_name: str = None):
    global _collector
    if _collector is None:
        from app.config import get_settings
        _collector = MetricsCollector(node_name or get_settings().node_name)
    return _collector
