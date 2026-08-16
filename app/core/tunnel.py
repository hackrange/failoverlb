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

from app.core.crypto import decrypt, encrypt, hash_token
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


def addresses_pools_point_at(session, network):
    """
    Tunnel addresses that a backend pool still names.

    A pool member is an address, not a machine.  Remove a workload and the
    member pointing at it is left behind, and the moment that address is given
    to a different workload the pool starts sending production traffic there,
    silently.  The Tunnel page tells people to put the address in a pool, so
    this is the normal case rather than a corner of one.
    """
    from app.models import PoolMember

    net = ipaddress.ip_network(network.cidr)
    out = set()
    for member in session.query(PoolMember).all():
        address = (member.address or "").strip()
        try:
            if ipaddress.ip_address(address) in net:
                out.add(address)
        except ValueError:
            continue        # a hostname, so not one of ours
    return out


def address_problem(session, network, wanted: str) -> str:
    """
    Why this address cannot be given to a workload, or empty when it can.

    Asking for a specific one is allowed, and it has an obvious use: putting a
    machine back where it was.  A pool member is an address rather than a
    machine, so re-adding web01 at the address web01 used to have is the one
    case where reuse is not just safe but the thing you actually want.

    Two things are still refused outright, because neither has a good outcome:

      * an address a load balancer holds, which would make the fleet argue with
        a workload about who it is
      * an address another workload already has, which is two machines claiming
        one identity and whichever handshakes last wins

    A pool pointing at it is **not** refused, only reported.  That is the
    re-adding case, and telling somebody which pools will start reaching this
    machine is more use than refusing and making them guess.
    """
    net = ipaddress.ip_network(network.cidr)
    try:
        address = ipaddress.ip_address(str(wanted).strip())
    except ValueError:
        return f"{wanted} is not an IP address"

    if address not in net:
        return f"{address} is outside {network.cidr}"
    if address == net.network_address or address == net.broadcast_address:
        return f"{address} is the network or broadcast address of {network.cidr}"

    for node, held in node_addresses(session, network).items():
        if held == str(address):
            return (f"{address} belongs to the load balancer {node}.  The "
                    f"bottom of the range is theirs.")

    for peer in (session.query(TunnelPeer)
                 .filter(TunnelPeer.network_id == network.id).all()):
        if peer.address == str(address):
            return f"the workload {peer.name} already has {address}"

    return ""


def pools_naming(session, network, address: str) -> list:
    """Which pools name this address, so somebody can be told before reuse."""
    from app.models import Pool, PoolMember

    out = []
    for member in session.query(PoolMember).all():
        if (member.address or "").strip() != str(address):
            continue
        pool = session.query(Pool).filter(Pool.id == member.pool_id).first()
        if pool:
            out.append(pool.name)
    return sorted(set(out))


def next_free_address(session, network):
    """
    The next address a workload can have.

    Counts upward and does not go back for gaps, until the top of the range is
    reached.  Reuse was the old rule, on the grounds that a deployment which
    only counts upward runs out of a /24 while mostly empty.  True, and 250
    workloads away; what reuse costs is immediate.  An address that belonged to
    a workload last week means something different this week, to a pool that
    still points at it, to a firewall rule somebody wrote, and to whoever
    remembers what used to be there.  None of that announces itself.

    Two things are never handed out, whichever way we are looking: an address
    in use, and one a pool still names even though the workload has gone.
    """
    net = ipaddress.ip_network(network.cidr)
    hosts = list(net.hosts())
    node_count = max(session.query(TunnelNodeKey).count(), 2)

    taken = {p.address for p in session.query(TunnelPeer)
             .filter(TunnelPeer.network_id == network.id).all()}
    taken |= set(node_addresses(session, network).values())
    taken |= addresses_pools_point_at(session, network)

    # Where the counting is up to.  Zero on a fleet that predates this, which
    # reads as "start after the nodes" and is right: everything below is either
    # in use or was never used at all.
    mark = max(int(network.address_high_water or 0), node_count)

    for index in range(mark, len(hosts)):
        if str(hosts[index]) not in taken:
            network.address_high_water = index + 1
            return str(hosts[index])

    # The top of the range is used up, so gaps are all there is.  Say so,
    # because from here on an address may have belonged to something else.
    for index in range(node_count, mark):
        if str(hosts[index]) not in taken:
            log.warning("tunnel range %s is full above %s, reusing the gap at %s",
                        network.cidr, hosts[mark - 1], hosts[index])
            return str(hosts[index])

    raise ValueError(f"there is no room left in {network.cidr}")


async def install_on_fleet():
    """
    Ask every node to install what the tunnel needs.

    Every node, not the one somebody happens to be looking at.  A workload
    peers with all of them so it can survive one going away, and a node that
    cannot carry the tunnel is a failover that does not work, discovered at
    the worst moment.
    """
    # Imported here rather than at the top, like every other function that
    # reaches the cluster.  These pull in the manager and the manager pulls in
    # this, so a top level import is a circular one.
    from app.config import get_settings
    from app.core.agent_client import get_agent
    from app.core.cluster import PeerClient, get_cluster
    from app.db import session_scope

    me = get_settings().node_name
    cluster = get_cluster()
    started, failed = {}, {}

    try:
        answer = await get_agent().call("tunnel_install", timeout=60)
        started[me] = (answer.get("data") or answer)
    except Exception as exc:
        failed[me] = str(exc)

    with session_scope() as session:
        peers = [(p.name, PeerClient(p, cluster.ca)) for p in cluster.peers(session)]

    for node_name, client in peers:
        try:
            answer = await client.call("/peer/agent",
                                       {"verb": "tunnel_install", "payload": {}})
            started[node_name] = (answer.get("data") or answer)
        except Exception as exc:
            failed[node_name] = str(exc)

    return {"ok": not failed, "started": started, "failed": failed}


async def install_status():
    """What each node has, and how any install in flight is going."""
    # Imported here rather than at the top, like every other function that
    # reaches the cluster.  These pull in the manager and the manager pulls in
    # this, so a top level import is a circular one.
    from app.config import get_settings
    from app.core.agent_client import get_agent
    from app.core.cluster import PeerClient, get_cluster
    from app.db import session_scope

    me = get_settings().node_name
    cluster = get_cluster()
    nodes = {}

    try:
        answer = await get_agent().call("tunnel_install_status", timeout=90)
        nodes[me] = (answer.get("data") or answer)
    except Exception as exc:
        nodes[me] = {"error": str(exc), "ready": False, "running": False}

    with session_scope() as session:
        peers = [(p.name, PeerClient(p, cluster.ca)) for p in cluster.peers(session)]

    for node_name, client in peers:
        try:
            answer = await client.call(
                "/peer/agent", {"verb": "tunnel_install_status", "payload": {}})
            nodes[node_name] = (answer.get("data") or answer)
        except Exception as exc:
            # A node we cannot ask is not a node that is ready.  Saying so
            # beats leaving it out and letting the page imply everything is
            # fine because nothing said otherwise.
            nodes[node_name] = {"error": str(exc), "ready": False, "running": False}

    return {
        "nodes": nodes,
        "all_ready": all(n.get("ready") for n in nodes.values()) if nodes else False,
        "any_running": any(n.get("running") for n in nodes.values()),
    }


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


def new_psk_token(peer) -> str:
    """
    A ticket for the one command that puts a key on a workload already on the
    tunnel.

    Deliberately not the enrolment ticket.  A workload being upgraded keeps its
    address, its own private key and its place in every pool that points at it,
    and re-enrolling it would change the first and regenerate the second.
    """
    from datetime import timedelta

    from app.models import utcnow

    token = secrets.token_urlsafe(32)
    peer.psk_token_hash = hash_token(token)
    peer.psk_expires_at = utcnow() + timedelta(minutes=ENROL_MINUTES)
    return token


def peer_for_psk_token(session, token: str):
    """The workload this upgrade ticket belongs to, if it is still good."""
    from app.models import utcnow

    peer = session.query(TunnelPeer).filter(
        TunnelPeer.psk_token_hash == hash_token(token)).first()
    if not peer or not peer.psk_expires_at:
        return None
    expires = peer.psk_expires_at
    if expires.tzinfo is None:
        from datetime import timezone
        expires = expires.replace(tzinfo=timezone.utc)
    if expires < utcnow():
        return None
    return peer


def peer_for_token(session, token: str):
    """The peer this ticket belongs to, if it is still good."""
    if not token:
        return None
    peer = session.query(TunnelPeer).filter(
        TunnelPeer.enrol_token_hash == hash_token(token)).first()
    if not peer or not peer.enrol_is_valid:
        return None
    return peer


def new_psk() -> str:
    """
    A WireGuard pre-shared key: 32 random bytes, base64, same as `wg genpsk`.

    Generated here rather than on the workload because both ends need the same
    value and this end is the one that can hand it to every load balancer.  It
    never crosses the wire in a handshake; it is only ever configured at both
    ends, which is what makes it useful against somebody who has recorded the
    traffic and later breaks Curve25519.
    """
    import base64
    return base64.b64encode(secrets.token_bytes(32)).decode()


def peer_psk(peer) -> str:
    """The stored key in the clear, or empty when this peer has none."""
    if not peer.psk_encrypted:
        return ""
    return decrypt(peer.psk_encrypted) or ""


def set_peer_psk(peer, value: str = None) -> str:
    """Give a peer a key, generating one unless a value is supplied."""
    value = value or new_psk()
    peer.psk_encrypted = encrypt(value)
    return value


def wanted_peers(session, network):
    """What every node's interface should contain."""
    return [
        # The key travels to the agent in the clear, over the peer link, which
        # is mutual TLS between nodes holding certificates from the same
        # private CA with a signature on every message.  Same trade the pool
        # tokens and the private keys already make, and for the same reason: a
        # key that does not reach every node is a workload that cannot connect
        # to whichever one is active.
        {"name": p.name, "address": p.address, "public_key": p.public_key,
         "psk": peer_psk(p)}
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
