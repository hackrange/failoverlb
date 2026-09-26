"""
The country database, and keeping it on every node.

Blocking by country needs a MaxMind format database next to nginx on every
node, or the node without one rejects the config and the apply fails.  This
installs it everywhere and keeps it current.

Two sources:

  db-ip     free, monthly, no account.  Asks for attribution, which the
            settings page shows.
  MaxMind   free, needs an account id and a license key from maxmind.com.

Both download to the same format.  The manager only names a source; the agent
picks the URL and path.  A verb that took a URL and a destination would let
the caller write any file as root, which the agent exists to prevent.
"""
import logging
from datetime import datetime, timedelta, timezone

from app.core import settings_store
from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.geoip")

SOURCES = ("dbip", "maxmind")

# Refresh intervals.  "never" is for fleets with no egress to either source,
# where the file is installed once by hand.
SCHEDULES = {
    "never": None,
    "daily": timedelta(days=1),
    "weekly": timedelta(days=7),
    "monthly": timedelta(days=30),
}


def configured_source() -> str:
    return (settings_store.get("geoip_source") or "").strip()


def _payload() -> dict:
    """What the agent needs to fetch it, worked out from the settings."""
    source = configured_source()
    if source not in SOURCES:
        raise ValueError("no country database source is set")

    payload = {"source": source}
    if source == "maxmind":
        payload["account_id"] = (settings_store.get("geoip_account_id") or "").strip()
        payload["license_key"] = (settings_store.get("geoip_license_key") or "").strip()
        if not payload["license_key"]:
            raise ValueError("MaxMind needs a licence key, which is not set")
    return payload


# Moved to fleet_verbs (the rule set install uses it too).  Alias kept for
# existing callers.
_ask_every_node = ask_every_node


async def install_on_fleet() -> dict:
    """
    Install the database on every node and record when.  Any node may end up
    active, so all of them need it.
    """
    payload = _payload()
    results = await _ask_every_node("geoip_install", payload)

    ok = [name for name, r in results.items() if r.get("ok")]
    failed = {name: r.get("error") or r.get("detail") or "failed"
              for name, r in results.items() if not r.get("ok")}

    if ok:
        settings_store.set("geoip_last_install",
                           datetime.now(timezone.utc).isoformat(timespec="seconds"),
                           actor="geoip")

    log.warning("country database installed on %s%s", ", ".join(sorted(ok)) or "nothing",
                f", failed on {failed}" if failed else "")
    return {"ok": not failed, "installed": sorted(ok), "failed": failed,
            "source": payload["source"]}


async def fleet_status() -> dict:
    """What each node has, so the page can say rather than guess."""
    results = await _ask_every_node("geoip_status", {})
    nodes = {}
    for name, answer in results.items():
        nodes[name] = {
            "present": bool(answer.get("present")),
            "bytes": answer.get("bytes"),
            "modified": answer.get("modified"),
            "source": answer.get("source"),
            "error": answer.get("error"),
        }
    return {
        "source": configured_source(),
        "schedule": (settings_store.get("geoip_refresh") or "never"),
        "last_install": settings_store.get("geoip_last_install"),
        "nodes": nodes,
        "everywhere": bool(nodes) and all(n["present"] for n in nodes.values()),
    }


async def refresh_if_due() -> dict:
    """
    Scheduled refresh.  Cheap when nothing is due, which is most ticks.

    Only the active node runs it; the install covers the whole fleet anyway.
    """
    from app.core.cluster import get_cluster
    from app.db import session_scope

    if configured_source() not in SOURCES:
        return {"skipped": "no source set"}

    every = SCHEDULES.get((settings_store.get("geoip_refresh") or "never"))
    if not every:
        return {"skipped": "refresh is off"}

    with session_scope() as session:
        if not get_cluster().is_active(session):
            return {"skipped": "not the active node"}

    last = settings_store.get("geoip_last_install")
    if last:
        try:
            when = datetime.fromisoformat(last)
            if when.tzinfo is None:
                when = when.replace(tzinfo=timezone.utc)
            if datetime.now(timezone.utc) - when < every:
                return {"skipped": "not due yet"}
        except ValueError:
            pass

    log.info("country database is due a refresh")
    return await install_on_fleet()
