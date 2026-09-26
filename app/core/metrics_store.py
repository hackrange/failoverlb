"""
Telemetry that survives a restart.

`metrics.py` keeps fifteen second detail in memory for two hours.  This
stores longer history:

  - fold in-memory samples into one minute buckets,
  - roll those up into five minute buckets,
  - prune old rows so a load balancer doesn't fill its disk.

Every node stores the whole fleet's numbers, not just its own, so history
has no hole after a failover.  Buckets hold min, mean and max, never a
single sample, so spikes survive.
"""
import logging
import time

from sqlalchemy import delete, func, select

from app.db import session_scope
from app.models import MetricSample, json_set

log = logging.getLogger("nfm.metrics.store")

MINUTE = 60
FIVE_MINUTES = 5 * MINUTE

# Retention per tier: 48 hours of one minute detail (enough for "what
# happened during yesterday's deploy"), and 30 days of five minute buckets
# (8,640 points per node, already more than a chart draws).
KEEP_FINE = 48 * 3600
KEEP_COARSE = 30 * 24 * 3600

# Stored metrics.  Counters are converted to rates before they get here.
STORED = (
    "cpu_percent", "memory_percent", "swap_percent", "disk_percent",
    "load_1m", "active_connections", "reading", "writing", "waiting",
    "requests_per_sec", "accepts_per_sec", "handled_per_sec", "dropped_per_sec",
)


def _bucket(when: float, size: int) -> int:
    return int(when) // size * size


def _fold(rows) -> dict:
    """
    Fold readings into one bucket.  min and max matter most: an average
    alone hides a short spike.
    """
    out = {}
    for key in STORED:
        seen = [r[key] for r in rows if isinstance(r.get(key), (int, float))]
        if not seen:
            continue
        out[key] = {
            "min": round(min(seen), 2),
            "avg": round(sum(seen) / len(seen), 2),
            "max": round(max(seen), 2),
        }
    return out


def _merge(buckets) -> dict:
    """
    Merge folded buckets into one coarser bucket, keeping min of mins and
    max of maxes.  The mean of means is exact only for equal-sized buckets,
    which holds closely enough since the collector runs on a fixed timer.
    """
    out = {}
    for key in STORED:
        parts = [b[key] for b in buckets if key in b]
        if not parts:
            continue
        out[key] = {
            "min": round(min(p["min"] for p in parts), 2),
            "avg": round(sum(p["avg"] for p in parts) / len(parts), 2),
            "max": round(max(p["max"] for p in parts), 2),
        }
    return out


def _with_rates(rows):
    """
    Turn counters in a run of samples into per second rates.  (The
    collector only computes the latest rate, which is no use for a past
    bucket.)

    A counter going backwards means nginx restarted; that pair is skipped
    rather than recorded as a negative rate.
    """
    out = []
    for older, newer in zip(rows, rows[1:]):
        seconds = (newer.get("at") or 0) - (older.get("at") or 0)
        if seconds <= 0:
            continue
        row = dict(newer)
        for key in ("accepts", "handled", "requests"):
            if key in older and key in newer:
                delta = newer[key] - older[key]
                if delta >= 0:
                    row[key + "_per_sec"] = round(delta / seconds, 2)
        accepts = row.get("accepts_per_sec")
        handled = row.get("handled_per_sec")
        if accepts is not None and handled is not None:
            row["dropped_per_sec"] = round(max(0.0, accepts - handled), 2)
        out.append(row)
    return out


def write_minute(collector=None) -> dict:
    """
    Fold the last completed minute out of memory and store it.  The minute
    still filling is skipped, or the last chart point would keep changing.
    """
    from app.core.metrics import get_collector

    collector = collector or get_collector()
    edge = _bucket(time.time(), MINUTE) - MINUTE

    written = 0
    with session_scope() as session:
        for node, history in (getattr(collector, "history", None) or {}).items():
            # Include one sample before the bucket so the first reading has
            # a rate; otherwise the minimum comes out artificially low.
            window = [dict(s) for s in history.samples
                      if edge - 60 <= s.get("at", 0) < edge + MINUTE]
            rows = [r for r in _with_rates(window) if r.get("at", 0) >= edge]
            if not rows:
                continue

            folded = _fold(rows)
            if not folded:
                continue

            existing = session.query(MetricSample).filter(
                MetricSample.node == node,
                MetricSample.at == edge,
                MetricSample.resolution == "1m",
            ).first()
            if existing:
                existing.values = json_set(folded)
            else:
                session.add(MetricSample(node=node, at=edge, resolution="1m",
                                         values=json_set(folded)))
            written += 1

    return {"bucket": edge, "nodes": written}


def roll_up() -> dict:
    """
    Build five minute buckets for every completed window, right away.

    Rolling up only data past fine retention left the coarse tier missing
    the last 48 hours, so a 30 day view lacked the most recent two days.
    Both tiers stay current; only pruning makes them differ.
    """
    edge = _bucket(time.time(), FIVE_MINUTES)
    made = 0

    with session_scope() as session:
        # Finished windows only.
        rows = session.query(MetricSample).filter(
            MetricSample.resolution == "1m",
            MetricSample.at < edge,
        ).order_by(MetricSample.node, MetricSample.at).all()

        grouped = {}
        for row in rows:
            grouped.setdefault((row.node, _bucket(row.at, FIVE_MINUTES)), []).append(row)

        have = {(r.node, r.at, len(r.value_map()))
                for r in session.query(MetricSample).filter(
                    MetricSample.resolution == "5m").all()}
        seen = {(node, at) for node, at, _ in have}

        for (node, at), members in grouped.items():
            merged = _merge([m.value_map() for m in members])
            if not merged:
                continue
            existing = session.query(MetricSample).filter(
                MetricSample.node == node,
                MetricSample.at == at,
                MetricSample.resolution == "5m",
            ).first() if (node, at) in seen else None
            if existing:
                existing.values = json_set(merged)
            else:
                session.add(MetricSample(node=node, at=at, resolution="5m",
                                         values=json_set(merged)))
                made += 1

    return {"rolled": made, "before": edge}


def prune() -> dict:
    """
    Delete rows past retention.  Runs on every node; a standby with a full
    disk can't take over.
    """
    now = int(time.time())
    with session_scope() as session:
        fine = session.execute(delete(MetricSample).where(
            MetricSample.resolution == "1m",
            MetricSample.at < now - KEEP_FINE,
        )).rowcount or 0
        coarse = session.execute(delete(MetricSample).where(
            MetricSample.resolution == "5m",
            MetricSample.at < now - KEEP_COARSE,
        )).rowcount or 0

    if fine or coarse:
        log.info("pruned telemetry: %d fine, %d coarse", fine, coarse)
    return {"fine": fine, "coarse": coarse}


def tick() -> dict:
    """Everything the schedule needs, in the order it has to happen."""
    out = {}
    try:
        out["write"] = write_minute()
        out["rollup"] = roll_up()
        out["prune"] = prune()
    except Exception as exc:
        # Telemetry must never take the manager down.
        log.warning("could not keep telemetry: %s", exc)
        out["error"] = str(exc)
    return out


def series(start: int, end: int, nodes=None) -> dict:
    """
    Stored samples between two times, at the finest resolution kept that
    far back.  Zooming into a recent ten minutes must give one minute
    detail, not the flat top of a five minute bucket.

    The result names its resolution so the page can present five minute
    data as averages.
    """
    start, end = int(start), int(end)
    if end <= start:
        return {"resolution": None, "nodes": {}, "start": start, "end": end}

    with session_scope() as session:
        # Pick the tier by whether fine data is kept that far back, not by
        # what happens to be stored.  Checking stored data made a fresh
        # install answer a one hour query from the empty coarse tier.
        resolution = "1m" if start >= int(time.time()) - KEEP_FINE else "5m"

        query = session.query(MetricSample).filter(
            MetricSample.resolution == resolution,
            MetricSample.at >= start, MetricSample.at <= end,
        )
        if nodes:
            query = query.filter(MetricSample.node.in_(list(nodes)))
        rows = query.order_by(MetricSample.at).all()

        out = {}
        for row in rows:
            out.setdefault(row.node, []).append({"at": row.at, **row.value_map()})

        # Earliest stored sample, so the page can say when history is shorter
        # than the requested window rather than implying a quiet period.
        held = session.query(func.min(MetricSample.at)).scalar()

    return {"resolution": resolution, "nodes": out,
            "start": start, "end": end, "earliest": held}
