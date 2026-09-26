"""
Running one agent verb on every node, and collecting what each one said.

This started life inside the country database work and is now used by two
features, so it lives here rather than being copied.  Anything that has to put
a file on every box has the same problem: a config is only as appliable as the
least equipped node in the fleet, so installing on the node somebody happens to
be looking at is not enough.

Everything that reaches the cluster is imported inside the function, because
those modules import this kind of module back.
"""
import asyncio
import logging

log = logging.getLogger("nfm.fleet")


async def ask_every_node(verb: str, payload: dict) -> dict:
    """
    Run one verb here and on every peer.  Returns {node name: answer}.

    A node that fails answers like the agent would have, with ok false and a
    reason, rather than raising.  One unreachable box must not stop the others
    being told, or a fleet where one node is down can never be brought back
    into step with the rest.

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
