"""
Run one agent verb on every node and collect each node's answer.

Used by anything that has to put a file on every box: a config is only as
appliable as the least equipped node, so installing on the local node alone
is not enough.

Cluster modules are imported inside the function to avoid import cycles.
"""
import asyncio
import logging

log = logging.getLogger("nfm.fleet")


async def ask_every_node(verb: str, payload: dict) -> dict:
    """
    Run one verb here and on every peer.  Returns {node name: answer}.

    A failing node answers with ok false and a reason instead of raising, so
    one unreachable box does not stop the rest from being updated.

    The peer call takes {verb, payload}, not flattened arguments.  Sent flat,
    the far agent gets no arguments at all and the error looks like a
    disagreement between nodes rather than a missing request.
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
