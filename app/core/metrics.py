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
GAUGES = ("active_connections", "reading", "writing", "waiting")


class MetricsHistory:
    """Samples for one node, oldest first."""

    def __init__(self):
        self.samples = deque(maxlen=MAX_SAMPLES)

    def add(self, metrics: dict, when: float = None):
        when = when or time.time()
        row = {"at": when}
        for key in COUNTERS + GAUGES:
            if key in metrics:
                row[key] = int(metrics[key])
        self.samples.append(row)

    def latest(self):
        return dict(self.samples[-1]) if self.samples else None

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
        """Recent values of one number, for drawing a line."""
        rows = list(self.samples)[-limit:]
        return [{"at": r["at"], "value": r[key]} for r in rows if key in r]


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

        try:
            result = await get_agent().nginx_metrics()
            if result.get("ok") and result.get("metrics"):
                self._for(self.node_name).add(result["metrics"])
                self.last_error.pop(self.node_name, None)
            else:
                self.last_error[self.node_name] = result.get("error") or "no numbers came back"
        except Exception as exc:
            self.last_error[self.node_name] = str(exc)

        cluster = get_cluster()
        try:
            with session_scope() as session:
                peers = [(p.id, p.name) for p in cluster.peers(session)]
        except Exception:
            return

        for peer_id, peer_name in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == peer_id).first()
                    if not node:
                        continue
                    client = PeerClient(node, cluster.ca)
                answer = await client.call("/peer/agent",
                                           {"verb": "nginx_metrics", "args": {}},
                                           timeout=15)
                data = (answer or {}).get("data") or {}
                if data.get("ok") and data.get("metrics"):
                    self._for(peer_name).add(data["metrics"])
                    self.last_error.pop(peer_name, None)
                else:
                    self.last_error[peer_name] = data.get("error") or "no numbers came back"
            except Exception as exc:
                # A peer being unreachable is the cluster page's story to tell,
                # not this one's.  Record it and carry on.
                self.last_error[peer_name] = str(exc)

    def snapshot(self) -> dict:
        out = {}
        for node, hist in self.history.items():
            out[node] = {
                "latest": hist.latest(),
                "rates": hist.rates(),
                "samples": len(hist.samples),
                "error": self.last_error.get(node),
            }
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
