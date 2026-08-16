"""
The OWASP Core Rule Set, and keeping it on every node.

The engine is only half a WAF.  The rules are the half people mean when they
say ModSecurity, and they have the same problem the country database has: they
must be on every node or the node without them refuses the whole config and the
apply is turned away.  So this is deliberately the same shape as
`app/core/geoip.py`, down to the schedule names, rather than a second way of
doing the same job.

Two tracks, and the difference is what you are optimising for:

  lts       the 4.25 series, which is the first long term support line for CRS
            4.  Fewer new detections, far fewer new false positives.  Right for
            a box somebody installs and leaves alone.
  latest    whatever the newest release is.  Newest detections, and the newest
            false positives with them, which land on sites in blocking mode.

The manager names a track and nothing else.  The agent works out which release
that is, where to get it and where to put it, because a verb that took a URL
would be a way to unpack any tarball anywhere as root.
"""
import logging
from datetime import datetime, timedelta, timezone

from app.core import settings_store
from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.waf.rules")

TRACKS = ("lts", "latest")

# Same names and meanings as the country database, on purpose.  Never is a real
# answer: a fleet with no egress wants the rules put there once and left alone.
SCHEDULES = {
    "never": None,
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


def configured_track() -> str:
    """Which track to follow, defaulting to the safe one."""
    track = (settings_store.get("waf_crs_track") or "lts").strip().lower()
    return track if track in TRACKS else "lts"


async def install_on_fleet() -> dict:
    """
    Put the rule set on every node, and remember when.

    Every node rather than the one somebody is looking at, for the same reason
    the country database goes everywhere: a site is served by whichever node is
    active, and a config is only as appliable as the least equipped box.
    """
    track = configured_track()
    results = await ask_every_node("crs_install", {"track": track})

    ok = [name for name, r in results.items() if r.get("ok")]
    failed = {name: r.get("error") or r.get("detail") or "failed"
              for name, r in results.items() if not r.get("ok")}

    if ok:
        settings_store.set("waf_crs_last_install",
                           datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           actor="waf")

    # What each node ended up on, which is the thing worth knowing when they
    # disagree.  Two nodes on different rule set versions is not an outage, but
    # it is a site that behaves differently depending on which box answered,
    # and that is very hard to work out from the outside.
    versions = {name: r.get("version") for name, r in results.items() if r.get("ok")}
    if len(set(versions.values())) > 1:
        log.warning("the fleet is not on one rule set version: %s", versions)

    log.warning("rule set installed on %s%s", ", ".join(sorted(ok)) or "nothing",
                f", failed on {failed}" if failed else "")
    return {"ok": not failed, "installed": sorted(ok), "failed": failed,
            "track": track, "versions": versions}


async def fleet_status() -> dict:
    """What each node has, so the page can say rather than guess."""
    results = await ask_every_node("crs_status", {})

    nodes = {}
    for name, answer in results.items():
        nodes[name] = {
            "present": bool(answer.get("present")),
            "version": answer.get("version"),
            "track": answer.get("track"),
            "installed": answer.get("installed"),
            "rules": answer.get("rules"),
            "error": answer.get("error"),
        }

    present = [n for n in nodes.values() if n["present"]]
    versions = {n["version"] for n in present if n["version"]}

    return {
        "track": configured_track(),
        "schedule": (settings_store.get("waf_crs_refresh") or "never"),
        "last_install": settings_store.get("waf_crs_last_install"),
        "nodes": nodes,
        "everywhere": bool(nodes) and all(n["present"] for n in nodes.values()),
        # Said plainly rather than left for somebody to spot by comparing rows.
        "agreed": len(versions) <= 1,
    }


async def refresh_if_due() -> dict:
    """
    The scheduled half.  Cheap when there is nothing to do, which is most ticks.

    Runs from the active node only.  Two nodes fetching the same release at the
    same moment is bandwidth for nothing, and the install covers the whole fleet
    anyway.
    """
    from app.core.cluster import get_cluster
    from app.db import session_scope

    every = SCHEDULES.get((settings_store.get("waf_crs_refresh") or "never"))
    if not every:
        return {"skipped": "refresh is off"}

    with session_scope() as session:
        if not get_cluster().is_active(session):
            return {"skipped": "not the active node"}

    last = settings_store.get("waf_crs_last_install")
    if last:
        try:
            when = datetime.fromisoformat(last)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - when < every:
                return {"skipped": "not due yet"}
        except ValueError:
            pass

    log.info("the rule set is due a refresh")
    return await install_on_fleet()
