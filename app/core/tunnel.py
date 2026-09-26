"""
WireGuard tunnel so backends do not need a public address.

A workload dials out to the load balancers and pools reach it back over the
same tunnel, so nothing inbound has to be opened on the workload side.

It is not a VPN: the workload only gets routes to the cluster's tunnel
addresses, with no default route or change to its own egress.  It is not a
mesh either: each peer's AllowedIPs is its single host address, on both ends,
so workloads cannot reach each other or the cluster network.

Every node holds a peer entry for every workload, since a pool is served by
whichever node is active.  Peering with only the active node would break at
the first failover.
"""
import ipaddress
import logging
import secrets

from app.core.crypto import decrypt, encrypt, hash_token
from app.models import TunnelNetwork, TunnelNodeKey, TunnelPeer

log = logging.getLogger("nfm.tunnel")

# Enrollment ticket lifetime.  Long enough to paste a command on another
# machine, short enough that a leaked ticket soon stops working.
ENROL_MINUTES = 120


def private_ranges():
    return [ipaddress.ip_network(c) for c in
            ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16")]


def check_cidr(value: str):
    """
    Validate the tunnel range: IPv4, RFC 1918 private, and /29 or larger.
    A public range is refused outright since it causes hard-to-trace routing
    problems.
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
    Tunnel addresses still referenced by a pool member.

    Pool members outlive the workload they pointed at, so handing such an
    address to a new workload would silently send it production traffic.
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
    Why this address cannot be assigned to a workload, or "" if it can.

    Requesting a specific address is allowed, mainly to put a re-added
    workload back at its old address.  Refused: addresses outside the range,
    network/broadcast, a load balancer's address, or one another workload
    holds.  An address a pool still names is allowed (that is the re-add
    case); callers report it via pools_naming().
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
    Next address for a new workload.

    Allocates upward from a high water mark and only falls back to gaps once
    the top of the range is used, so a freed address is not quickly reused
    while pools or firewall rules may still refer to it.  Addresses in use or
    still named by a pool are never returned.
    """
    net = ipaddress.ip_network(network.cidr)
    hosts = list(net.hosts())
    node_count = max(session.query(TunnelNodeKey).count(), 2)

    taken = {p.address for p in session.query(TunnelPeer)
             .filter(TunnelPeer.network_id == network.id).all()}
    taken |= set(node_addresses(session, network).values())
    taken |= addresses_pools_point_at(session, network)

    # Unset on older installs, which means "start after the node addresses".
    mark = max(int(network.address_high_water or 0), node_count)

    for index in range(mark, len(hosts)):
        if str(hosts[index]) not in taken:
            network.address_high_water = index + 1
            return str(hosts[index])

    # Range exhausted above the mark; reuse a gap and log it.
    for index in range(node_count, mark):
        if str(hosts[index]) not in taken:
            log.warning("tunnel range %s is full above %s, reusing the gap at %s",
                        network.cidr, hosts[mark - 1], hosts[index])
            return str(hosts[index])

    raise ValueError(f"there is no room left in {network.cidr}")


async def install_on_fleet():
    """
    Install the tunnel packages on every node, not just this one, so the
    tunnel survives a failover.
    """
    # Local imports: the cluster manager imports this module.
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
            # Unreachable counts as not ready rather than being omitted.
            nodes[node_name] = {"error": str(exc), "ready": False, "running": False}

    return {
        "nodes": nodes,
        "all_ready": all(n.get("ready") for n in nodes.values()) if nodes else False,
        "any_running": any(n.get("running") for n in nodes.values()),
    }


def endpoint_host(node) -> str:
    """
    The address a workload should dial to reach this node.

    Prefers a public IPv4 (public_ip, then the join address) over anything
    else.  A dual stack node reports an IPv6 public_ip, which a workload on
    an IPv4-only network cannot reach, and the tunnel then silently carries
    nothing.
    """
    candidates = [c for c in (node.public_ip, node.address) if c]

    def is_public_v4(value):
        try:
            addr = ipaddress.ip_address(value)
        except ValueError:
            return False        # a hostname
        return addr.version == 4 and addr.is_global

    for c in candidates:
        if is_public_v4(c):
            return c
    return candidates[0] if candidates else ""


def new_enrol_token(peer) -> str:
    """
    One-time enrollment ticket for a workload.  Only the hash is stored,
    like the cluster join token.
    """
    from datetime import timedelta

    from app.models import utcnow

    token = secrets.token_urlsafe(32)
    peer.enrol_token_hash = hash_token(token)
    peer.enrol_expires_at = utcnow() + timedelta(minutes=ENROL_MINUTES)
    return token


def new_psk_token(peer) -> str:
    """
    Ticket for adding a pre-shared key to an already enrolled workload.

    Separate from enrollment, which would change its address and regenerate
    its private key.
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
    WireGuard pre-shared key: 32 random bytes, base64, like `wg genpsk`.

    Generated here because every load balancer needs the same value.  It is
    never sent in a handshake, which is what protects recorded traffic if
    Curve25519 is later broken.
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
        # The PSK is sent in the clear to each node's agent, inside the
        # mutual TLS peer link with signed messages.  Every node needs it for
        # the workload to connect after a failover.
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
    Push the interface and peer list to every node, so pool members stay
    reachable after a failover.
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
    Make sure every node has a tunnel key and address.

    Each node generates its own key so the private half never leaves it.
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
            # A manual endpoint override wins over the detected address.
            host = (row.endpoint_override or "").strip() or \
                endpoints.get(node_name) or ""
            # IPv6 needs brackets or wg cannot tell the port apart.
            if ":" in host and not host.startswith("["):
                host = f"[{host}]"
            row.endpoint = f"{host}:{network.listen_port}"
        session.commit()

    return {"ok": True, "nodes": sorted(results)}
