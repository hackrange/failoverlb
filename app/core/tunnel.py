"""
The tunnel, so a backend never needs a public address.

A workload dials out to the load balancers over WireGuard, and the pools reach
it back down the same tunnel.  Nothing inbound has to be opened at the customer
end, and the data centre never has to put the machine on the internet.

What this deliberately does not do
----------------------------------

**It is not a VPN.**  The workload gets a route to the cluster's tunnel
addresses and nothing else.  No default route, no outbound internet, no change
to where the workload's own traffic goes.  A tunnel that quietly becomes
somebody's gateway breaks their monitoring and their egress rules, and it is
the fastest way to have this banned by a security team.

**It is not a mesh.**  Each peer is allowed exactly one address, its own.  A
workload cannot reach another workload, and it cannot reach anything on the
cluster's own network.  That is enforced at both ends: AllowedIPs here is a
single host, and the script writes the same on the workload.

Every node, not just the active one
-----------------------------------

Both nodes hold a peer entry for every workload, because a pool is used by
whichever node is serving.  A workload peered with only the active node goes
dark at the first failover and looks exactly like a backend that has died.
"""
import ipaddress
import logging
import secrets

from app.core.crypto import hash_token
from app.models import TunnelNetwork, TunnelNodeKey, TunnelPeer

log = logging.getLogger("nfm.tunnel")

# How long an enrolment ticket is good for.  Long enough to walk to another
# machine and paste a command, short enough that one left in a chat log is not
# a way in next week.
ENROL_MINUTES = 120


def private_ranges():
    return [ipaddress.ip_network(c) for c in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def check_cidr(value: str):
    """
    The tunnel range has to be private, and big enough to be worth having.

    Refused rather than warned about.  A tunnel handing out public addresses is
    a routing accident that will be blamed on something else entirely, and it
    is not the kind of mistake somebody spots by reading a settings page.
    """
    try:
        network = ipaddress.ip_network(value, strict=True)
    except ValueError as exc:
        raise ValueError(f"that is not a network: {exc}")

    if network.version != 4:
        raise ValueError("the tunnel range has to be IPv4 for now")

    if not any(network.subnet_of(private) for private in private_ranges()):
        raise ValueError(
            "the tunnel range has to be a private one, inside 10.0.0.0/8, "
            "172.16.0.0/12 or 192.168.0.0/16.  Handing out public addresses "
            "over a tunnel is a routing problem somebody else will have to "
            "debug.")

    if network.prefixlen > 29:
        raise ValueError("that range is too small to hold the nodes and a "
                         "workload.  Use /29 or larger.")
    return network


def node_addresses(session, network):
    """One address per node, taken from the bottom of the range."""
    hosts = list(ipaddress.ip_network(network.cidr).hosts())
    out = {}
    for i, key in enumerate(session.query(TunnelNodeKey)
                            .order_by(TunnelNodeKey.node_name).all()):
        out[key.node_name] = str(hosts[i])
    return out


def next_free_address(session, network):
    """
    The next address a workload can have.

    Nodes sit at the bottom of the range, so workloads start after them.  A
    gap left by a removed workload is reused, because a long lived deployment
    that only ever counts upward runs out of a /24 while mostly empty.
    """
    net = ipaddress.ip_network(network.cidr)
    hosts = list(net.hosts())
    node_count = max(session.query(TunnelNodeKey).count(), 2)

    taken = {p.address for p in session.query(TunnelPeer)
             .filter(TunnelPeer.network_id == network.id).all()}
    taken |= set(node_addresses(session, network).values())

    for host in hosts[node_count:]:
        if str(host) not in taken:
            return str(host)
    raise ValueError(f"there is no room left in {network.cidr}")


def endpoint_host(node) -> str:
    """
    Pick the address a workload should dial to reach this node.

    A peer gets exactly one endpoint, so this is a choice and not a list, and
    it has to be the one the most machines can actually reach.

    public_ip is whatever the box goes out as, and a dual stack box goes out
    over IPv6.  That is the right answer for almost everything else we use it
    for and the wrong one here, because a workload on an IPv4 only network has
    no way to reach it at all.  It cost a full afternoon of a tunnel that was
    correct at both ends and carried nothing: one load balancer was published
    as IPv6 only, so the workload silently never had a route to it.

    So: a public IPv4 first, then the joining address if that is a public IPv4,
    then whatever is left.  IPv6 is a last resort rather than a preference.
    """
    candidates = [c for c in (node.public_ip, node.address) if c]

    def is_public_v4(value):
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False        # a name, which resolves to whatever it resolves to
        return addr.version == 4 and addr.is_global

    for c in candidates:
        if is_public_v4(c):
            return c
    return candidates[0] if candidates else ""


def new_enrol_token(peer) -> str:
    """
    A ticket that lets one machine onto the tunnel, once.

    Only the hash is stored, the same as the cluster join token, because
    anybody holding one of these can put a machine on your tunnel.
    """
    from datetime import timedelta

    from app.models import utcnow

    token = secrets.token_urlsafe(32)
    peer.enrol_token_hash = hash_token(token)
    peer.enrol_expires_at = utcnow() + timedelta(minutes=ENROL_MINUTES)
    return token


def peer_for_token(session, token: str):
    """The peer this ticket belongs to, if it is still good."""
    if not token:
        return None
    peer = session.query(TunnelPeer).filter(
        TunnelPeer.enrol_token_hash == hash_token(token)).first()
    if not peer or not peer.enrol_is_valid:
        return None
    return peer


def wanted_peers(session, network):
    """What every node's interface should contain."""
    return [
        {"name": p.name, "address": p.address, "public_key": p.public_key}
        for p in session.query(TunnelPeer)
        .filter(TunnelPeer.network_id == network.id)
        .filter(TunnelPeer.enabled.is_(True))
        .all()
        if p.public_key
    ]


async def apply_to_fleet(session=None):
    """
    Push the interface and the peer list to every node.

    Every node, always, rather than only the one that happens to be active.
    The whole point is that a pool member stays reachable across a failover,
    and a peer list that exists on one box only is exactly the failure this is
    meant to prevent.
    """
    from app.config import get_settings
    from app.core.agent_client import get_agent
    from app.core.cluster import PeerClient, get_cluster
    from app.db import session_scope

    me = get_settings().node_name
    cluster = get_cluster()

    with session_scope() as session:
        network = session.query(TunnelNetwork).first()
        if not network or not network.enabled:
            return {"ok": True, "skipped": "the tunnel is turned off"}

        peers = wanted_peers(session, network)
        addresses = node_addresses(session, network)
        prefix = ipaddress.ip_network(network.cidr).prefixlen
        peer_nodes = [(p.name, PeerClient(p, cluster.ca))
                      for p in cluster.peers(session)]

    done, failed = [], []

    def request_for(node_name):
        address = addresses.get(node_name)
        if not address:
            return None
        return {"address": f"{address}/{prefix}",
                "listen_port": network.listen_port,
                "peers": peers}

    # This node, through its own agent.
    own = request_for(me)
    if own:
        try:
            await get_agent().call("tunnel_apply", timeout=60, **own)
            done.append(me)
        except Exception as exc:
            log.error("could not update the tunnel here: %s", exc)
            failed.append({"node": me, "error": str(exc)[:200]})

    # The others, through the peer link.
    for node_name, client in peer_nodes:
        payload = request_for(node_name)
        if not payload:
            failed.append({"node": node_name,
                           "error": "this node has no tunnel address yet"})
            continue
        try:
            await client.call("/peer/agent",
                              {"verb": "tunnel_apply", "payload": payload})
            done.append(node_name)
        except Exception as exc:
            log.error("could not update the tunnel on %s: %s", node_name, exc)
            failed.append({"node": node_name, "error": str(exc)[:200]})

    return {"ok": not failed, "applied": done, "failed": failed}


async def ensure_node_keys():
    """
    Make sure every node has a tunnel key and knows its address.

    Asked of each node rather than generated centrally, because the private
    half must never exist anywhere but the box that uses it.
    """
    from app.config import get_settings
    from app.core.agent_client import get_agent
    from app.core.cluster import PeerClient, get_cluster
    from app.db import session_scope
    from app.models import Node

    me = get_settings().node_name
    cluster = get_cluster()

    with session_scope() as session:
        network = session.query(TunnelNetwork).first()
        if not network:
            return {"ok": False, "error": "no tunnel network is set up"}
        peer_nodes = [(p.name, PeerClient(p, cluster.ca))
                      for p in cluster.peers(session)]
        endpoints = {n.name: endpoint_host(n)
                     for n in session.query(Node).all()}

    results = {}
    try:
        answer = await get_agent().call("tunnel_key", timeout=30)
        results[me] = (answer.get("data") or answer).get("public_key")
    except Exception as exc:
        log.error("could not make a tunnel key here: %s", exc)

    for node_name, client in peer_nodes:
        try:
            answer = await client.call("/peer/agent",
                                       {"verb": "tunnel_key", "payload": {}})
            data = answer.get("data") or answer
            results[node_name] = data.get("public_key")
        except Exception as exc:
            log.error("could not make a tunnel key on %s: %s", node_name, exc)

    with session_scope() as session:
        network = session.query(TunnelNetwork).first()
        hosts = list(ipaddress.ip_network(network.cidr).hosts())
        for i, (node_name, public_key) in enumerate(sorted(results.items())):
            if not public_key:
                continue
            row = session.query(TunnelNodeKey).filter(
                TunnelNodeKey.node_name == node_name).first()
            if row is None:
                row = TunnelNodeKey(node_name=node_name)
                session.add(row)
            row.public_key = public_key
            row.address = str(hosts[i])
            # An operator's answer beats ours.  Ours is worked out from what
            # the box says about itself, which is right until it is not.
            host = (row.endpoint_override or "").strip() or \
                endpoints.get(node_name) or ""
            # Brackets around IPv6, or the colon before the port is just
            # another colon in the address and wg refuses the whole endpoint.
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            row.endpoint = f"{host}:{network.listen_port}"
        session.commit()

    return {"ok": True, "nodes": sorted(results)}
