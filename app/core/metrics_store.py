"""
Telemetry that outlives a restart.

`metrics.py` keeps fifteen second detail in memory for two hours, which is the
right answer to "what is happening now" and no answer at all to "what did last
Tuesday look like".  This is the second question.

Three jobs, all cheap:

  * **Fold** the in memory samples into one minute buckets and write them down.
  * **Roll up** one minute buckets into five minute ones once they are old
    enough that nobody will zoom in that far.
  * **Prune**, because a table that grows forever on a box whose job is load
    balancing is a way to fill a disk, and filling the disk on a load balancer
    is a worse outage than any chart is worth.

**Every node writes the whole fleet's numbers, not just its own.**  Each node's
collector already gathers its peers, and each node keeps its own full copy of
everything else here for the same reason: after a failover the node somebody is
looking at is not the node that was collecting, and a history with a hole in it
exactly where the interesting event happened is worse than no history.

**Min, mean and max, never a sample.**  A five minute bucket holding one
reading throws away the spike that was the reason somebody is looking.
"""
import logging
import time

from sqlalchemy import delete, func, select

from app.db import session_scope
from app.models import MetricSample, json_set

log = logging.getLogger("nfm.metrics.store")

MINUTE = 60
FIVE_MINUTES = 5 * MINUTE

# How long each tier is kept.
#
# 48 hours of one minute detail covers "what happened during yesterday's
# deploy", which is the finest question anybody asks after the fact.  Thirty
# days of five minute buckets is what the owner asked for and is 8,640 points
# per node, already more than a chart draws.
KEEP_FINE = 48 * 3600
KEEP_COARSE = 30 * 24 * 3600

# What is worth writing down.  Rates are worked out from counters before they
# get here, because a counter since nginx started is not a chart.
STORED = (
    "cpu_percent", "memory_percent", "swap_percent", "disk_percent",
    "load_1m", "active_connections", "reading", "writing", "waiting",
    "requests_per_sec", "accepts_per_sec", "handled_per_sec", "dropped_per_sec",
)


def _bucket(when: float, size: int) -> int:
    return int(when) // size * size


def _fold(rows) -> dict:
    """
    Many readings into one bucket, keeping the shape of what happened.

    min and max are the whole point.  An average alone turns a thirty second
    spike inside a five minute window into a number that looks like a quiet
    afternoon.
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
    Several already folded buckets into one coarser bucket.

    The min of the mins and the max of the maxes, so a spike survives being
    rolled up.  The mean is a mean of means, which is only exactly right when
    the buckets hold the same number of readings; they do, because they are
    fixed width and the collector runs on a timer, and being a fraction out on
    an average is a far smaller lie than losing the peak.
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
    Turn the counters in a run of samples into per second rates.

    Done here rather than read from the collector because the collector only
    ever works out the rate between the two most recent samples, which is what
    the dashboard needs and is no use for a bucket that finished a minute ago.

    A counter going backwards means nginx restarted and counted from zero
    again.  That is a gap in what is known, not a negative rate, so the pair is
    skipped rather than written as a large wrong number.
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
    Fold the last completed minute out of memory and write it down.

    The *completed* minute, not the one still filling.  Writing a bucket that
    is still collecting means it is rewritten every time the job runs and the
    last point on every chart wobbles as it settles.
    """
    from app.core.metrics import get_collector

    collector = collector or get_collector()
    edge = _bucket(time.time(), MINUTE) - MINUTE

    written = 0
    with session_scope() as session:
        for node, history in (getattr(collector, "history", None) or {}).items():
            # One sample before the bucket as well, so the first reading inside
            # it has something to be a rate against.  Without it the first
            # fifteen seconds of every minute has no rate and the minimum comes
            # out lower than anything that happened.
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
    Keep the five minute tier current, not just eventually.

    The first version only folded buckets already past the fine retention
    window, which sounds tidy and leaves a hole: the coarse tier then has
    nothing for the most recent 48 hours, so asking for thirty days comes back
    missing the two days anybody actually cares about.

    So every completed five minute window gets a coarse bucket as soon as it is
    complete.  Both tiers stay current, the query picks one by how far back the
    question reaches, and pruning is what makes them differ rather than a race
    between two jobs.
    """
    edge = _bucket(time.time(), FIVE_MINUTES)
    made = 0

    with session_scope() as session:
        # Only windows that have finished.  A bucket still filling would be
        # rewritten on every run and its last point would wobble.
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
    Throw away what is past its keep, and say how much.

    Runs on every node.  A standby quietly filling its own disk is a standby
    that cannot be failed over to, which is discovered at the worst moment.
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
        # Telemetry is a nicety.  It must never be the reason a manager stops.
        log.warning("could not keep telemetry: %s", exc)
        out["error"] = str(exc)
    return out


def series(start: int, end: int, nodes=None) -> dict:
    """
    Everything stored between two times, at the finest resolution that covers it.

    **Resolution is chosen from what is stored, not from the span.**  Zooming
    from thirty days into ten minutes has to come back with one minute detail,
    or the spike somebody zoomed in on turns out to be the flat top of a five
    minute bucket, which is the chart inventing an answer at exactly the zoom
    where it cannot be checked.

    So the fine tier is asked first and used when it actually covers the range
    asked for.  The answer says which resolution it is, because a flat line at
    five minutes should be read as an average and not as nothing happening.
    """
    start, end = int(start), int(end)
    if end <= start:
        return {"resolution": None, "nodes": {}, "start": start, "end": end}

    with session_scope() as session:
        # Which tier, decided by how far back the question reaches rather than
        # by what happens to be stored.
        #
        # The first version asked whether the fine tier already held something
        # as old as the start, which is false for every window longer than the
        # history, so a fresh install answered a one hour question with the
        # coarse tier and no rows at all.  What matters is whether the fine tier
        # is *kept* that far back; if it is, it has whatever exists.
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

        # What is actually held, so the page can say when the history is
        # shorter than the window asked for rather than drawing a short line
        # and letting somebody read it as a quiet period.
        held = session.query(func.min(MetricSample.at)).scalar()

    return {"resolution": resolution, "nodes": out,
            "start": start, "end": end, "earliest": held}
