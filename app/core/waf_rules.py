"""
The OWASP Core Rule Set, and keeping it on every node.

Like the country database, the rules must be on every node or the node
without them rejects the config.  This mirrors `app/core/geoip.py`, down to
the schedule names.

Two tracks:

  lts       the 4.25 series, the first long term support line for CRS 4.
            Fewer new detections and far fewer new false positives.  Right
            for a box that is installed and left alone.
  latest    the newest release.  Newest detections, and newest false
            positives, which hit sites in blocking mode.

The manager only names a track.  The agent picks the release, source and
destination, since a verb that took a URL could unpack any tarball anywhere
as root.
"""
import logging
from datetime import datetime, timedelta, timezone

from app.core import settings_store
from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.waf.rules")

TRACKS = ("lts", "latest")

# Same names and meanings as the country database.  "never" is for fleets
# with no egress, where the rules are installed once by hand.
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
    Install the rule set on every node and record when.  Any node may end
    up active, so all of them need it.
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

    # Nodes on different rule set versions aren't an outage, but the site then
    # behaves differently depending on which box answers.  Hard to spot from
    # outside, so warn.
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
        "agreed": len(versions) <= 1,
    }


async def refresh_if_due() -> dict:
    """
    Scheduled refresh.  Cheap when nothing is due, which is most ticks.

    Only the active node runs it; the install covers the whole fleet anyway.
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
