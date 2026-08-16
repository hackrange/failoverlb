"""
The country database, and keeping it on every node.

Blocking by country needs a MaxMind format database next to nginx, on every
node, or the node without one refuses the whole config and the apply is turned
away.  Telling somebody to go and install a file on each box by hand is how a
feature ends up switched on in the GUI and broken in the fleet, so this puts it
there and keeps it current.

Two sources, and the only difference is whether you need an account:

  db-ip     free, monthly, nothing to sign up for.  Attribution is asked for,
            which the settings page shows.
  MaxMind   free, and wants an account id and a licence key.  Ask for one at
            maxmind.com if you would rather have theirs.

Both are the same format once downloaded, so nothing past the agent cares which
was used.  The manager never sends a URL or a path: it names a source, and the
agent decides everything else.  A verb that took a URL and a destination would
be a way to write any file anywhere as root, which is the one thing the agent
exists not to be.
"""
import asyncio
import logging
from datetime import datetime, timedelta, timezone

from app.core import settings_store

log = logging.getLogger("nfm.geoip")

SOURCES = ("dbip", "maxmind")

# How often to go and look, by name.  Never is a real answer: a fleet with no
# egress to either source wants the file put there once by hand and left alone.
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


async def _ask_every_node(verb: str, payload: dict) -> dict:
    """
    Run one verb here and on every peer.

    Imported inside the function like everything else that reaches the cluster,
    since those modules import this one back.

    The peer call takes {verb, payload} and not the arguments flattened out.
    Sent flat, the far agent is called with none of them and the failure reads
    like the two nodes disagreeing about the request rather than one of them
    never receiving it.
    """
    from app.config import get_settings
    from app.core.agent_client import get_agent
    from app.core.cluster import PeerClient, get_cluster
    from app.db import session_scope
    from app.models import Node

    me = get_settings().node_name
    cluster = get_cluster()
    results = {}

    try:
        results[me] = await get_agent().call(verb, **payload)
    except Exception as exc:
        results[me] = {"ok": False, "error": str(exc)}

    with session_scope() as session:
        peers = [n for n in session.query(Node).all() if not n.is_self]
        peer_rows = [(n.name, PeerClient(n, cluster.ca)) for n in peers]

    async def one(name, client):
        try:
            answer = await client.call("/peer/agent", {"verb": verb, "payload": payload})
            results[name] = answer.get("data") or answer
        except Exception as exc:
            results[name] = {"ok": False, "error": str(exc)}

    await asyncio.gather(*(one(name, client) for name, client in peer_rows))
    return results


async def install_on_fleet() -> dict:
    """
    Put the database on every node, and remember when.

    Every node rather than the one somebody is looking at, because a pool is
    served by whichever node is active and a config is only as appliable as the
    least equipped box in the fleet.
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
    The scheduled half.  Cheap when there is nothing to do, which is most ticks.

    Runs from the active node only.  Two nodes downloading the same database at
    the same moment is bandwidth for nothing, and the install covers the whole
    fleet anyway.
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
