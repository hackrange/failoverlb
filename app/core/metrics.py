"""
Connection and request numbers, with a bit of history behind them.

The free nginx gives you `stub_status`, which is seven numbers for the whole
server and nothing per site.  That is much less than the paid version reports,
and it is still worth having, because four of those numbers are counters and a
counter you sample twice is a rate.

Kept in memory on purpose.  These are worth looking at while somebody is
watching a deploy or wondering why the box feels busy, and they are worthless
tomorrow.  Writing them to sqlite would mean a table that grows forever to
answer a question nobody asks about last week, on a manager whose whole point is
being simple enough to fix at 3am.  A restart loses the history and that is
fine: the counters carry on from where nginx has them.

The per site and per backend numbers that Plus shows are a different job and are
not here.  They need the access log read and parsed, which is written up in
docs/plus-parity.md as a plan rather than a feature.
"""
import logging
import time
from collections import deque

log = logging.getLogger("nfm.metrics")

# How many samples to keep.  At one every fifteen seconds this is two hours,
# which covers "what happened during the deploy" and stops well short of being
# a time series database.
MAX_SAMPLES = 480

# The counters, as opposed to the gauges.  A counter only means something when
# you take the difference between two readings; a gauge means something on its
# own.  Confusing the two gives you a graph of "requests since nginx started",
# which climbs forever and says nothing.
COUNTERS = ("accepts", "handled", "requests")
GAUGES = ("active_connections", "reading", "writing", "waiting",
          "cpu_percent", "memory_percent", "memory_used", "memory_total",
          "load_1m", "swap_percent", "disk_percent")


def read_host() -> dict:
    """
    What this box is doing, out of /proc.

    Read here rather than through the agent, and that is a deliberate choice
    about where the security boundary sits.  The agent runs with
    `ProcSubset=pid`, so /proc/stat and /proc/meminfo are invisible to it, and
    the fix is not to widen the one root component in the system for the sake
    of a chart.  The container can read these itself, it needs no privilege to
    do so, and the numbers are the host's because a container shares the
    kernel's view of them.

    cpu comes back as raw jiffies, which are counters.  Turning them into a
    percentage needs two readings and is done by the caller.

    Memory is available rather than free.  Free counts the page cache as used,
    so a healthy Linux box that has been up a week reads as out of memory when
    it has plenty, and somebody acts on that.
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

    None when either reading is missing or the counters went backwards, which
    happens on a reboot.  A gap in what we know is not zero percent, and a
    chart that draws it as zero says the box was idle when it was off.
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

        # The cpu jiffies themselves, kept so the next sample can work out a
        # percentage.  Not reported: a counter since boot is not a chart.
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
        # The raw jiffies are working state, not something to hand out.
        return {k: v for k, v in self.samples[-1].items() if not k.startswith("_")}

    def rates(self):
        """
        Per second rates worked out from the last two samples.

        Returns None when there is only one sample, which is honest: a rate
        needs two readings and there is no sensible number to show before the
        second one arrives.

        A counter going backwards means nginx restarted and started again from
        zero.  That is not a negative rate, it is a gap in what we know, so the
        rate comes back None rather than as a large wrong number.
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

        # Connections nginx accepted but did not handle.  Nearly always zero,
        # and when it is not, the box is out of worker connections or file
        # handles, which is worth knowing and is invisible in the other six.
        if out.get("accepts_per_sec") is not None and out.get("handled_per_sec") is not None:
            out["dropped_per_sec"] = round(
                max(0.0, out["accepts_per_sec"] - out["handled_per_sec"]), 2)
        return out

    def series(self, key, limit=120):
        """
        Recent values of one number, for drawing a line.

        A sample with no value for this key is left out rather than sent as
        zero, so the chart can break the line there.  Joining across a gap
        invents data, and the gaps are exactly the interesting moments: a
        restart, or a node nobody could reach.
        """
        rows = list(self.samples)[-limit:]
        return [{"at": round(r["at"], 1), "value": r[key]}
                for r in rows if r.get(key) is not None]

    def rate_series(self, limit=120):
        """
        Request rate over time, worked out between each pair of samples.

        Counters have to be differenced, and doing it here rather than in the
        page keeps the one place that knows a counter from a gauge in one
        place.  A pair that spans a restart, where the counter went backwards,
        is skipped so the line breaks instead of spiking.
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
    Samples for one backend, and what its exporter last said about itself.

    Kept apart from the node histories because a backend is a different kind of
    thing: we do not own it, it may publish nothing, and what it publishes may
    describe the whole machine or only one process.  Which of those it is has to
    travel with the numbers, or a JVM at 100% of one core reads as a box on
    fire.
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
    Asks the agent for stub_status on a timer and keeps what it says.

    One history per node.  The peers are asked through the same peer channel
    everything else uses, so a standby's numbers show up on whichever node
    somebody is looking at, which is the point of having a fleet view at all.
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
        Ask each pool's backends what they are doing, where they publish it.

        Every node does this for itself rather than one node doing it and
        sharing, which is the same choice the health checker makes and for the
        same reason: a backend one node can reach and another cannot is a
        routing problem, and seeing it split by node usually gives the answer
        straight away.

        Never raises.  A backend that publishes nothing, or has gone away, is a
        thing to report on a page and not a reason for the collector to stop.
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

                # Checked again here, because a template using {host} is only a
                # real address once a member's address has been put in it.  The
                # save time check cannot see that, so a backend whose address is
                # loopback would otherwise reach this untouched.
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
        """One round.  Never raises: this is a nicety, not a critical path."""
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
                # Still keep the host numbers.  nginx being unreachable is
                # exactly when somebody wants to know what the box is doing.
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

        # Forget nodes that are no longer in the cluster.
        #
        # This only ever added to the history, so a node that was removed kept
        # its last readings for as long as the process ran and went on being
        # drawn on the dashboard.  Somebody who has just taken a node out is
        # then looking at a page that says it is still there, which is the one
        # moment they need the page to be right.
        #
        # The readings are worth nothing once the node is gone: they are a
        # snapshot of a machine this cluster no longer talks to and cannot
        # refresh.
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
                # The key is `payload` and the answer is the agent's own reply
                # with nothing wrapped round it, because /peer/agent returns
                # what AgentClient.call gives back and that has already had the
                # envelope taken off.  Guessing either of those wrong gets you
                # "no numbers came back" from a node that answered perfectly.
                data = await client.call(
                    "/peer/agent",
                    {"verb": "nginx_metrics", "payload": {}},
                    timeout=15) or {}

                # The peer's own reading of its own /proc.  Asked of its
                # manager rather than its agent, because the agent cannot see
                # /proc/stat and widening it for a chart would be trading the
                # one root component's boundary for a nicety.
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
                # A peer being unreachable is the cluster page's story to tell,
                # not this one's.  Record it and carry on.
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
