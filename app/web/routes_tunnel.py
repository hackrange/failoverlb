"""
The tunnel: setting it up, and letting a workload enrol itself.

Two halves with very different rules.

The managed half sits behind the same login as everything else and is used by
whoever runs the load balancers.

The enrolment half is deliberately not behind a login, because the whole point
is that somebody on the workload can run one command and be done.  What stands
in for a login is the ticket in the URL: single use, expires in two hours, and
only its hash is stored.  Anybody holding one can put a machine on the tunnel,
so it is treated exactly like the cluster join token.

The script is served over https from a certificate this fleet holds, which is
the honest minimum for something piped into a shell.  It is also short, and
kept short on purpose, so that somebody whose policy requires reading it first
can actually do that.
"""
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import PlainTextResponse

from app.config import get_settings
from app.core import audit, tunnel
from app.db import session_scope
from app.models import TunnelNetwork, TunnelNodeKey, TunnelPeer, utcnow
from app.web.routes_api import ObjectGuard, changing, guard
from app.web.security import client_ip

log = logging.getLogger("nfm.tunnel.web")

router = APIRouter()

# The interface and helper the enrolment script lays down.  These were literals
# at the one call site that formats the script, which meant the removal command
# shown in the GUI could quietly stop matching what was actually installed.
IFACE = "nfm0"
BINARY = "/usr/local/bin/nfm-tunnel"

# What to run on the workload to undo the enrolment.
#
# Deliberately not "nfm-tunnel unenrol", even though that helper exists.  If
# enrolment stopped half way the helper is the part that never got written, and
# an undo command that depends on the thing you are undoing is no use exactly
# when it is needed.  This touches only the interface, config and key this
# fleet wrote.
#
# It leaves the wireguard package installed on purpose.  Removing a package the
# machine may be using for something else is not ours to do from a copied line.
UNENROL_COMMAND = (
    f"sudo bash -c 'systemctl disable --now wg-quick@{IFACE} 2>/dev/null || "
    f"wg-quick down {IFACE} 2>/dev/null; "
    f"rm -f /etc/wireguard/{IFACE}.conf /etc/wireguard/{IFACE}.key {BINARY}'"
)


# ==============================================================================
# The managed half
# ==============================================================================

def _network_json(network, session):
    keys = session.query(TunnelNodeKey).order_by(TunnelNodeKey.node_name).all()
    return {
        "id": network.id if network else None,
        "cidr": network.cidr if network else "10.77.0.0/24",
        "listen_port": network.listen_port if network else 51820,
        "enabled": bool(network.enabled) if network else False,
        "nodes": [{"node": k.node_name, "address": k.address,
                   "endpoint": k.endpoint, "public_key": k.public_key,
                   "endpoint_override": k.endpoint_override or ""}
                  for k in keys],
    }


def _pools_pointing_at(p):
    """
    Which pools name this workload's address.

    Said by name rather than as "if it is still in one", because the person
    deciding whether to remove it is the one who cannot see the pool pages from
    here, and because a member left behind is what turns a removed workload
    into somebody else's traffic later.
    """
    from sqlalchemy.orm import object_session

    from app.models import Pool, PoolMember

    session = object_session(p)
    if session is None or not p.address:
        return []
    rows = (session.query(Pool.name)
            .join(PoolMember, PoolMember.pool_id == Pool.id)
            .filter(PoolMember.address == p.address)
            .distinct().all())
    return sorted(name for (name,) in rows)


def _sites_using(p):
    """
    Which sites actually depend on this workload, by name.

    Pools are the mechanism and sites are the thing people care about.  "Two
    pools point at this" does not answer the question somebody is asking before
    they remove it, which is always "what breaks".  A pool nothing serves from
    breaks nothing; a pool behind three sites breaks three.

    Counts the sites' own pools and their paths' pools, because a site with one
    backend on the Basics tab and another on a path depends on both, and the
    second is the one that gets forgotten.
    """
    from sqlalchemy.orm import object_session

    from app.models import Location, PoolMember, VirtualHost

    session = object_session(p)
    if session is None or not p.address:
        return []

    pool_ids = {m.pool_id for m in session.query(PoolMember)
                .filter(PoolMember.address == p.address).all()}
    if not pool_ids:
        return []

    names = {h.name for h in session.query(VirtualHost)
             .filter(VirtualHost.pool_id.in_(pool_ids)).all()}
    for loc in session.query(Location).filter(Location.pool_id.in_(pool_ids)).all():
        if loc.host:
            names.add(loc.host.name)
    return sorted(names)


def _peer_json(p):
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "address": p.address,
        "enrolled": p.is_enrolled(),
        "enrolled_at": p.enrolled_at.isoformat() if p.enrolled_at else None,
        "enabled": p.enabled,
        "waiting_for_enrolment": bool(p.enrol_token_hash and not p.public_key),
        # Whether this peering survives somebody breaking Curve25519 later.
        # Shown per workload rather than as one number for the tunnel, because
        # a fleet is upgraded one workload at a time and the ones left are the
        # useful thing to see.
        "has_psk": p.has_psk,
        "unenrol_command": UNENROL_COMMAND,
        "used_by": _pools_pointing_at(p),
        "sites_using": _sites_using(p),
    }


@router.get("/api/tunnel")
async def get_tunnel(g: ObjectGuard = Depends(guard)):
    network = g.session.query(TunnelNetwork).first()
    peers = g.session.query(TunnelPeer).order_by(TunnelPeer.name).all()
    return {"network": _network_json(network, g.session),
            "peers": [_peer_json(p) for p in peers]}


@router.put("/api/tunnel")
async def set_tunnel(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("manage_cluster")
    payload = await request.json()

    network = g.session.query(TunnelNetwork).first()
    if network is None:
        network = TunnelNetwork()
        g.session.add(network)

    if "cidr" in payload:
        try:
            tunnel.check_cidr(str(payload["cidr"]))
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if network.peers and str(payload["cidr"]) != network.cidr:
            raise HTTPException(
                status_code=409,
                detail=("workloads are already enrolled on this range, so "
                        "changing it would strand them.  Remove them first."))
        network.cidr = str(payload["cidr"])

    if "listen_port" in payload:
        port = int(payload["listen_port"])
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail="that is not a port")
        network.listen_port = port

    if "enabled" in payload:
        network.enabled = bool(payload["enabled"])

    # Per node, what workloads should dial.  Blank means go back to working it
    # out ourselves rather than storing an empty string that overrides with
    # nothing and leaves the tunnel unreachable.
    for node_name, value in (payload.get("endpoints") or {}).items():
        row = g.session.query(TunnelNodeKey).filter(
            TunnelNodeKey.node_name == str(node_name)).first()
        if row is None:
            continue
        host = str(value or "").strip()
        if host and any(c in host for c in " \t/"):
            raise HTTPException(
                status_code=400,
                detail=(f"{host} is not a name or an address.  Give the name or "
                        f"address workloads should dial, with no port."))
        row.endpoint_override = host or None

    g.session.commit()

    if network.enabled:
        await tunnel.ensure_node_keys()
        await tunnel.apply_to_fleet()

    audit.record("tunnel.configure", user=g.user, object_type="tunnel",
                 object_name=network.cidr)
    with session_scope() as s:
        fresh = s.query(TunnelNetwork).first()
        return _network_json(fresh, s)


@router.get("/api/tunnel/install")
async def tunnel_install_status(g: ObjectGuard = Depends(guard)):
    """What each node has, so the page can offer the button only when it helps."""
    return await tunnel.install_status()


@router.post("/api/tunnel/install")
async def tunnel_install(g: ObjectGuard = Depends(changing)):
    """
    Install what the tunnel needs, on every node.

    Only when the tunnel is on.  Installing a network package on somebody's
    load balancers is not something to do because a page was open, and the
    tunnel being switched on is the closest thing there is to being asked.
    """
    g.require("manage_cluster")

    network = g.session.query(TunnelNetwork).first()
    if not network or not network.enabled:
        raise HTTPException(
            status_code=400,
            detail=("turn the tunnel on first.  Nothing is installed for a "
                    "feature that is switched off."))

    result = await tunnel.install_on_fleet()
    audit.record("tunnel.install", user=g.user, object_type="tunnel",
                 object_name=",".join(sorted(result.get("started") or {})) or "none")
    return result


@router.post("/api/tunnel/peers")
async def add_peer(request: Request, g: ObjectGuard = Depends(changing)):
    """Reserve an address for a workload and mint the ticket it enrols with."""
    g.require("manage_cluster")
    payload = await request.json()

    network = g.session.query(TunnelNetwork).first()
    if not network or not network.enabled:
        raise HTTPException(status_code=400,
                            detail="turn the tunnel on before adding workloads")

    name = str(payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="give the workload a name")
    if g.session.query(TunnelPeer).filter(TunnelPeer.name == name).first():
        raise HTTPException(status_code=409,
                            detail=f"there is already a workload called {name}")

    # An address can be asked for, and the reason is putting a machine back
    # where it was.  A pool member is an address rather than a machine, so
    # re-adding web01 at the address web01 had is the case where reuse is the
    # thing you want rather than a risk to be talked out of.
    #
    # The counter is left alone when one is chosen.  Bumping it would skip
    # everything between here and there, which is the opposite of what somebody
    # picking an address out of a gap is trying to do.
    wanted = str(payload.get("address") or "").strip()
    reusing = []
    if wanted:
        problem = tunnel.address_problem(g.session, network, wanted)
        if problem:
            raise HTTPException(status_code=409, detail=problem)
        address = wanted
        reusing = tunnel.pools_naming(g.session, network, address)
    else:
        try:
            address = tunnel.next_free_address(g.session, network)
        except ValueError as exc:
            raise HTTPException(status_code=409, detail=str(exc))

    peer = TunnelPeer(network_id=network.id, name=name, address=address,
                      description=(payload.get("description") or "")[:500] or None)
    # Every new workload gets a pre-shared key, with nothing extra to do.  It
    # goes into the enrolment script and into the peer block on every node at
    # the same moment, so there is no window and nobody has to know it happened.
    tunnel.set_peer_psk(peer)
    token = tunnel.new_enrol_token(peer)
    g.session.add(peer)
    g.session.commit()

    audit.record("tunnel.peer.add", user=g.user, object_type="tunnel_peer",
                 object_name=name)

    settings = get_settings()
    base = str(payload.get("base_url") or "").rstrip("/")
    if not base:
        base = f"https://{settings.node_address}"

    note = "single use, expires in two hours, treat it like a password"
    if reusing:
        # Said plainly rather than refused.  Somebody putting a machine back
        # wants exactly this; somebody who typed the wrong address needs to
        # know before the pool starts sending it production traffic.
        note += (f".  {', '.join(reusing)} already "
                 f"{'points' if len(reusing) == 1 else 'point'} at "
                 f"{address}, so {name} will start taking that traffic as soon "
                 f"as it enrols")

    return {
        **_peer_json(peer),
        "enrol_command": f"curl -sSL {base}/tunnel/enrol/{token} | sudo bash",
        "expires_in_minutes": tunnel.ENROL_MINUTES,
        "reusing": reusing,
        "note": note,
    }


@router.get("/api/tunnel/addresses")
async def tunnel_addresses(request: Request, g: ObjectGuard = Depends(guard)):
    """
    Who holds what in the tunnel range, and what can be picked.

    Exists because the counter only goes up, which is right and is also
    invisible: somebody adding and removing workloads while testing watches the
    numbers climb and reasonably concludes they are running out.  They are not.
    The gaps are all still there and can be asked for by name; this is the page
    that shows them.
    """
    import ipaddress

    g.require("view")

    network = g.session.query(TunnelNetwork).first()
    if not network:
        return {"configured": False, "addresses": []}

    net = ipaddress.ip_network(network.cidr)
    hosts = list(net.hosts())
    mark = int(network.address_high_water or 0)

    peers = {p.address: p.name for p in g.session.query(TunnelPeer)
             .filter(TunnelPeer.network_id == network.id).all()}
    nodes = {v: k for k, v in tunnel.node_addresses(g.session, network).items()}

    out = []
    # The whole range is 254 rows and nobody needs that.  Everything already
    # counted past, plus a few beyond, is the part somebody is choosing from.
    for index, host in enumerate(hosts[:max(mark + 8, 16)]):
        address = str(host)
        if address in nodes:
            out.append({"address": address, "state": "node",
                        "held_by": f"load balancer {nodes[address]}"})
        elif address in peers:
            out.append({"address": address, "state": "workload",
                        "held_by": peers[address]})
        else:
            pools = tunnel.pools_naming(g.session, network, address)
            out.append({
                "address": address,
                "state": "free",
                "held_by": "",
                "pools": pools,
                # Whether the counter has gone past it.  A free address below
                # the mark is one the automatic choice will skip, and is
                # exactly what somebody reusing an address is looking for.
                "in_a_gap": index < mark,
            })

    return {
        "configured": True,
        "cidr": network.cidr,
        "counter": mark,
        "next_automatic": next((a["address"] for a in out
                                if a["state"] == "free" and not a["in_a_gap"]), None),
        "addresses": out,
    }


@router.post("/api/tunnel/peers/{peer_id}/psk")
async def new_psk_link(peer_id: str, request: Request,
                       g: ObjectGuard = Depends(changing)):
    """
    A one command upgrade that puts a pre-shared key on a workload already on
    the tunnel.

    **This cannot be done from here alone, and it is worth saying why rather
    than looking like a missing feature.**  A WireGuard pre-shared key is never
    sent over the wire.  Both ends have to be told it separately, which is the
    entire reason it survives somebody breaking Curve25519 later.  There is no
    handshake that can carry it, so a command has to run on the workload.

    What this does is make that one command, once, per workload.  It keeps the
    workload's address, its own private key and its place in every pool, and it
    puts itself back if the tunnel does not come up within a minute.
    """
    g.require("manage_settings")

    peer = g.session.query(TunnelPeer).filter(
        TunnelPeer.id == int(peer_id)).first()
    if not peer:
        raise HTTPException(status_code=404, detail="no such workload")
    if not peer.is_enrolled():
        raise HTTPException(
            status_code=400,
            detail="that workload has never joined, so enrol it instead.  "
                   "Anything enrolling now gets a key as part of that.")
    if peer.has_psk:
        raise HTTPException(status_code=400,
                            detail=f"{peer.name} already has a pre-shared key")

    token = tunnel.new_psk_token(peer)
    g.session.commit()

    audit.record("tunnel.peer.psk.offer", user=g.user,
                 object_type="tunnel_peer", object_name=peer.name)

    settings = get_settings()
    base = str(request.headers.get("referer") or "").split("/tunnel")[0].rstrip("/")
    if not base:
        base = f"https://{settings.node_address}"

    return {
        "name": peer.name,
        "command": f"curl -sSL {base}/tunnel/psk/{token} | sudo bash",
        "expires_in_minutes": tunnel.ENROL_MINUTES,
        "note": ("Run it on that workload.  Fetching the link switches the key "
                 "on at this end, so run it rather than saving it for later, "
                 "and the workload is briefly offline while the two ends catch "
                 "up.  If it cannot get a handshake within a minute it undoes "
                 "itself."),
    }


@router.delete("/api/tunnel/peers/{peer_id}/psk")
async def drop_psk(peer_id: str, g: ObjectGuard = Depends(changing)):
    """
    Take the pre-shared key off a workload, at this end.

    The way out when an upgrade half happened: the load balancers took the key
    and the workload did not, so the workload cannot connect.  Removing it here
    puts things back to a plain WireGuard peering, which is weaker and working
    rather than stronger and down.
    """
    g.require("manage_settings")

    peer = g.session.query(TunnelPeer).filter(
        TunnelPeer.id == int(peer_id)).first()
    if not peer:
        raise HTTPException(status_code=404, detail="no such workload")

    peer.psk_encrypted = None
    peer.psk_applied_at = None
    peer.psk_token_hash = None
    peer.psk_expires_at = None
    name = peer.name
    g.session.commit()

    await tunnel.apply_to_fleet()
    audit.record("tunnel.peer.psk.remove", user=g.user,
                 object_type="tunnel_peer", object_name=name,
                 detail="back to a plain peering")
    return {"ok": True, "name": name,
            "note": "the workload should reconnect within a minute.  Take the "
                    "PresharedKey line out of its config too, or it will not."}


@router.post("/api/tunnel/peers/{peer_id}/enrol")
async def new_enrol_link(peer_id: str, request: Request,
                         g: ObjectGuard = Depends(changing)):
    """
    Mint a fresh enrolment command for a workload that has not joined yet.

    The old ticket cannot be shown again, because only its hash is kept, which
    is the right way to store it and the wrong reason to strand somebody.  The
    first version of this page showed the command once and left anybody who
    navigated away with a workload they could not enrol and no way back.

    Minting a new one replaces the old, so a link that went astray stops
    working the moment somebody asks for another.
    """
    g.require("manage_cluster")
    peer = g.get(TunnelPeer, peer_id)

    if peer.is_enrolled():
        raise HTTPException(
            status_code=409,
            detail=(f"{peer.name} is already on the tunnel.  Remove it first if "
                    f"you need to enrol that machine again."))

    token = tunnel.new_enrol_token(peer)
    g.session.commit()

    audit.record("tunnel.peer.relink", user=g.user, object_type="tunnel_peer",
                 object_name=peer.name)

    payload = {}
    try:
        payload = await request.json()
    except Exception:
        pass
    base = str(payload.get("base_url") or "").rstrip("/")
    if not base:
        base = f"https://{get_settings().node_address}"

    return {
        **_peer_json(peer),
        "enrol_command": f"curl -sSL {base}/tunnel/enrol/{token} | sudo bash",
        "expires_in_minutes": tunnel.ENROL_MINUTES,
    }


@router.patch("/api/tunnel/peers/{peer_id}")
async def edit_peer(peer_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    """
    Change the note on a workload.

    The note is the only thing here worth editing after the fact.  The name is
    what pools and sites are matched against by eye, and the address is what
    they are matched against in code, so changing either of those is a rename
    with consequences elsewhere rather than a correction.

    Notes go stale faster than anything else on this page.  A workload called
    web07 described as "the new billing box" is worse than one with no note at
    all once billing has moved, and if the only way to fix it is to remove the
    workload and enrol it again, nobody fixes it.

    No apply.  The tunnel config has no notes in it, so nothing on any node
    changes and pushing a fleet wide apply for a comment would be a lie about
    what happened.
    """
    g.require("manage_cluster")
    peer = g.get(TunnelPeer, peer_id)

    payload = await request.json() if await request.body() else {}
    if "description" not in payload:
        raise HTTPException(status_code=400, detail="there is nothing to change")

    was = peer.description or ""
    peer.description = (str(payload["description"] or "").strip() or None)
    g.session.commit()

    audit.record("tunnel.peer.edit", user=g.user, object_type="tunnel_peer",
                 object_name=peer.name,
                 changes={"description": {"from": was, "to": peer.description or ""}})
    return _peer_json(peer)


@router.delete("/api/tunnel/peers/{peer_id}")
async def remove_peer(peer_id: str, g: ObjectGuard = Depends(changing)):
    """
    Take a workload off the tunnel from this end.

    Works whether or not the machine still exists, which is the point: the
    common reason to press this is that somebody decommissioned it without
    unenrolling.
    """
    g.require("manage_cluster")
    peer = g.get(TunnelPeer, peer_id)
    name = peer.name
    g.session.delete(peer)
    g.session.commit()
    await tunnel.apply_to_fleet()
    audit.record("tunnel.peer.remove", user=g.user, object_type="tunnel_peer",
                 object_name=name)
    return {"ok": True, "removed": name}


# ==============================================================================
# The enrolment half, which has no login
# ==============================================================================

SCRIPT = """#!/usr/bin/env bash
# Put this machine on the {fleet} tunnel.
#
# What this does:
#   * installs wireguard if it is missing
#   * makes a key pair here, and sends only the public half
#   * writes one network interface, {iface}
#   * adds a route to {routes} and nothing else
#
# What it does not do:
#   * it does not change your default route
#   * it does not send your traffic anywhere
#   * it does not open any inbound port
#
# Remove it again with:  sudo {binary} unenrol
set -euo pipefail

IFACE={iface}
DIR=/etc/wireguard
CONF=$DIR/$IFACE.conf

if [ "$(id -u)" != "0" ]; then
  echo "run this with sudo" >&2; exit 1
fi

if ! command -v wg >/dev/null 2>&1; then
  echo "installing wireguard"
  if command -v apt-get >/dev/null 2>&1; then
    apt-get update -qq && apt-get install -y -qq wireguard
  elif command -v dnf >/dev/null 2>&1; then
    dnf install -y -q wireguard-tools
  elif command -v yum >/dev/null 2>&1; then
    yum install -y -q wireguard-tools
  else
    echo "could not work out how to install wireguard here" >&2; exit 1
  fi
fi

mkdir -p $DIR && chmod 700 $DIR
if [ ! -f $DIR/$IFACE.key ]; then
  wg genkey > $DIR/$IFACE.key
  chmod 600 $DIR/$IFACE.key
fi
PRIVATE=$(cat $DIR/$IFACE.key)
PUBLIC=$(echo "$PRIVATE" | wg pubkey)

cat > $CONF <<EOF
# Written by the {fleet} enrolment script.  Safe to remove with:
#   sudo {binary} unenrol
[Interface]
Address = {address}/32
PrivateKey = $PRIVATE
{peers}
EOF
chmod 600 $CONF

# Bring it up, and prove it came up.
#
# This used to hide every error from systemctl and assume the interface
# appeared.  A container whose kernel has no wireguard would print "done", and
# the only sign anything was wrong was a backend marked down later, with
# nothing anywhere connecting the two.  So each step now says what happened.

start_tunnel() {{
  systemctl enable --now wg-quick@$IFACE 2>/dev/null && return 0
  wg-quick down $IFACE >/dev/null 2>&1 || true
  wg-quick up $IFACE
}}

have_iface() {{ ip link show $IFACE >/dev/null 2>&1; }}

echo "starting the tunnel"
if ! start_tunnel >/dev/null 2>&1 || ! have_iface; then
  # Almost always the kernel, and almost always a container.  wireguard is in
  # the kernel from 5.6 on, but an unprivileged container gets whatever the
  # host loaded, and a host that never uses wireguard never loaded it.
  modprobe wireguard >/dev/null 2>&1 || true
  if [ ! -d /sys/module/wireguard ]; then
    echo "this kernel has no wireguard, trying the userspace one instead"
    if ! command -v wireguard-go >/dev/null 2>&1; then
      apt-get install -y -qq wireguard-go >/dev/null 2>&1 || true
    fi
    if command -v wireguard-go >/dev/null 2>&1 && [ -c /dev/net/tun ]; then
      # wg-quick will use this instead of asking the kernel for the interface.
      export WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
      mkdir -p /etc/systemd/system/wg-quick@$IFACE.service.d
      cat > /etc/systemd/system/wg-quick@$IFACE.service.d/userspace.conf <<EOF
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
EOF
      systemctl daemon-reload >/dev/null 2>&1 || true
      start_tunnel >/dev/null 2>&1 || true
    fi
  fi
fi

if ! have_iface; then
  echo >&2
  echo "could not create the $IFACE interface on this machine." >&2
  echo >&2
  if [ ! -d /sys/module/wireguard ] && ! command -v wireguard-go >/dev/null 2>&1; then
    echo "  This kernel has no wireguard and the userspace version is not" >&2
    echo "  available here.  Install it with:  apt-get install wireguard-go" >&2
  elif [ ! -c /dev/net/tun ]; then
    echo "  There is no /dev/net/tun, which a container normally has to be" >&2
    echo "  given.  For LXC, add this to the container config and restart it:" >&2
    echo "    lxc.cgroup2.devices.allow = c 10:200 rwm" >&2
    echo "    lxc.mount.entry = /dev/net dev/net none bind,create=dir" >&2
  else
    echo "  What it said:" >&2
    start_tunnel 2>&1 | sed "s/^/    /" >&2 || true
  fi
  echo >&2
  echo "Nothing was told to the load balancers, so remove the workload there" >&2
  echo "and add it again once this is sorted." >&2
  rm -f $CONF $DIR/$IFACE.key
  exit 1
fi

# Only now is it worth telling them who we are.  Sending the key before the
# interface exists is what made a machine show as enrolled in the GUI while it
# had no way to carry a packet.
echo "telling the load balancers who we are"
curl -sSf -X POST "{callback}" \\
     -H "Content-Type: application/json" \\
     -d "{{\\"public_key\\": \\"$PUBLIC\\"}}" >/dev/null

cat > {binary} <<'HELPER'
#!/usr/bin/env bash
set -euo pipefail
case "${{1:-}}" in
  unenrol)
    systemctl disable --now wg-quick@{iface} >/dev/null 2>&1 || \\
      wg-quick down {iface} >/dev/null 2>&1 || true
    rm -f /etc/wireguard/{iface}.conf /etc/wireguard/{iface}.key
    echo "off the tunnel.  Tell whoever runs the load balancers to remove it there too."
    ;;
  status) wg show {iface} 2>/dev/null || echo "the tunnel is not up" ;;
  *) echo "usage: {binary} [unenrol|status]" ;;
esac
HELPER
chmod 755 {binary}

# The interface existing is not the same as the tunnel working, and the gap
# between the two is a firewall that allows nothing outbound on the tunnel
# port.  Better to find that out here than from a backend marked down.
echo "waiting for the first handshake"
HANDSHAKE=0
for _ in $(seq 1 15); do
  if wg show $IFACE latest-handshakes 2>/dev/null \\
     | awk '{{ if ($2 != 0) found = 1 }} END {{ exit !found }}'; then
    HANDSHAKE=1
    break
  fi
  sleep 1
done

echo
if [ "$HANDSHAKE" = "1" ]; then
  echo "done.  This machine is {address} on the tunnel."
else
  echo "The tunnel is set up here, but nothing has answered yet."
  echo
  echo "  The interface is up and the load balancers have been told about it,"
  echo "  so the usual reason is that this machine cannot reach them on the"
  echo "  tunnel port outbound.  It is UDP, which some firewalls drop while"
  echo "  allowing everything else."
  echo
  echo "  It may still come up on its own.  Check with: {binary} status"
fi
echo "Nothing else about this machine's networking has been changed."
"""

PEER_BLOCK = """
[Peer]
# {node}
PublicKey = {public_key}
{psk_line}Endpoint = {endpoint}
# Only the load balancers, never a default route.  This is what keeps the
# tunnel from becoming this machine's way out to the internet.
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""


PSK_SCRIPT = """#!/usr/bin/env bash
# Put a pre-shared key on this workload's tunnel.
#
# Why: the tunnel's key exchange is Curve25519, which a quantum computer
# breaks, and traffic recorded today is decrypted whenever one arrives.  A
# pre-shared key is 32 bytes mixed into the handshake as an extra symmetric
# input, so breaking Curve25519 stops being enough on its own.  It is never
# sent over the wire; both ends have to be told it, which is why this has to
# run here rather than being pushed from the load balancers.
#
# What it changes: one line per peer in /etc/wireguard/{iface}.conf.  Your
# private key, your address and your routes are untouched, and this machine
# stays exactly where it is in every pool.
set -euo pipefail

IFACE={iface}
CONF=/etc/wireguard/$IFACE.conf
PSK='{psk}'

if [ "$(id -u)" != "0" ]; then echo "run this with sudo" >&2; exit 1; fi
if [ ! -f "$CONF" ]; then
  echo "no $CONF here, so this machine is not on the tunnel" >&2; exit 1
fi

cp -a "$CONF" "$CONF.before-psk"

# Written into the file first so it survives a reboot, then pushed into the
# live interface so it takes effect without dropping anything else.
#
# chr(10) rather than a backslash n, and that is not style.  This script is a
# Python string in routes_tunnel.py, so anything with a backslash in it is
# escaped once by the file and once by the string, and the first version of
# this shipped a newline in the middle of a quoted string.  The workload got
# "SyntaxError: unterminated string literal" and no key.  Nothing in here needs
# a backslash, so nothing in here has one.
python3 - "$CONF" "$PSK" <<'PYEOF'
import sys
path, psk = sys.argv[1], sys.argv[2]
out, seen = [], False
for line in open(path).read().splitlines():
    if line.strip().startswith("PresharedKey"):
        continue
    out.append(line)
    if line.strip() == "[Peer]":
        seen = True
    # One key line per peer block, straight after PublicKey so it reads well.
    if seen and line.strip().startswith("PublicKey"):
        out.append("PresharedKey = " + psk)
nl = chr(10)
open(path, "w").write(nl.join(out) + nl)
PYEOF

for PUB in $(wg show $IFACE peers 2>/dev/null); do
  wg set $IFACE peer "$PUB" preshared-key <(echo "$PSK")
done

echo "waiting for the tunnel to come back"
ok=0
for i in $(seq 1 30); do
  hs=$(wg show $IFACE latest-handshakes 2>/dev/null | awk '{{print $2}}' | sort -rn | head -1)
  now=$(date +%s)
  if [ -n "$hs" ] && [ "$hs" != "0" ] && [ $((now - hs)) -lt 40 ]; then ok=1; break; fi
  sleep 2
done

if [ "$ok" = "1" ]; then
  rm -f "$CONF.before-psk"
  echo
  echo "Done.  This tunnel now uses a pre-shared key."
  echo "Nothing else about this machine changed."
else
  echo
  echo "The tunnel did not come back within a minute, so this has been undone." >&2
  mv "$CONF.before-psk" "$CONF"
  for PUB in $(wg show $IFACE peers 2>/dev/null); do
    wg set $IFACE peer "$PUB" preshared-key /dev/null 2>/dev/null || true
  done
  echo "Tell whoever runs the load balancers to remove the key there too." >&2
  exit 1
fi
"""


@router.get("/tunnel/psk/{token}", response_class=PlainTextResponse)
async def psk_script(token: str, request: Request):
    """
    The one command that puts a pre-shared key on a workload already enrolled.

    **Fetching this activates the key on the load balancers**, because the
    alternative orderings are worse.  Both ends have to hold the same value, so
    there is a window either way; making it start when the script starts means
    the script is already running and about to close it, rather than depending
    on somebody coming back later.

    The window is a few seconds and WireGuard's keepalive re-handshakes
    through it.  If the script cannot get a handshake within a minute it puts
    the file back and takes the key off the interface, so a workload that
    cannot be upgraded ends up where it started rather than off the tunnel.

    Single use.  Only the hash of the ticket is stored, the same as the
    enrolment ticket, because anybody holding one can read a key that protects
    a tunnel.
    """
    from app.core import tunnel as tunnel_mod
    from app.models import utcnow

    with session_scope() as session:
        peer = tunnel_mod.peer_for_psk_token(session, token)
        if not peer:
            raise HTTPException(status_code=404,
                                detail="that link has been used already or has expired")
        if not peer.is_enrolled():
            raise HTTPException(
                status_code=400,
                detail="that workload has never joined the tunnel, so enrol it "
                       "instead and it will get a key as part of that")

        value = tunnel_mod.set_peer_psk(peer)
        peer.psk_applied_at = utcnow()
        # Burned on read.  A key that can be fetched twice is a key sitting in
        # somebody's shell history and still valid.
        peer.psk_token_hash = None
        peer.psk_expires_at = None
        name = peer.name
        session.commit()

    # The load balancers take it now, so by the time the script writes its end
    # the far end already agrees.
    await tunnel_mod.apply_to_fleet()

    audit.record("tunnel.peer.psk", user=None, source_ip=client_ip(request),
                 object_type="tunnel_peer", object_name=name,
                 detail="pre-shared key issued and applied on the fleet")

    return PSK_SCRIPT.format(iface=IFACE, psk=value)


@router.get("/tunnel/enrol/{token}", response_class=PlainTextResponse)
async def enrol_script(token: str, request: Request):
    """
    The script a workload pipes into bash.

    No login, because the ticket in the URL is the credential.  It is checked
    here rather than by the script, so an expired or spent ticket gets a
    sentence rather than a shell script that will not work.
    """
    with session_scope() as session:
        peer = tunnel.peer_for_token(session, token)
        if not peer:
            raise HTTPException(
                status_code=404,
                detail=("that enrolment link is not valid any more.  They are "
                        "single use and expire after two hours.  Ask for a "
                        "fresh one on the Tunnel page."))

        # Read while the session is open, because it is decrypted from the row
        # and the script is built after this block closes.
        psk = tunnel.peer_psk(peer)

        network = session.query(TunnelNetwork).first()
        keys = session.query(TunnelNodeKey).order_by(TunnelNodeKey.node_name).all()
        if not keys:
            raise HTTPException(status_code=503,
                                detail="the load balancers have no tunnel keys yet")

        # Every load balancer the workload will route down the tunnel.  Used
        # for the comment at the top of the script, which is a list, and never
        # as one peer's AllowedIPs, which is not.
        routes = ", ".join(f"{k.address}/32" for k in keys)

        # Each peer is allowed its own address and nothing else.
        #
        # AllowedIPs reads like a filter and is also a routing table: an
        # address belongs to exactly one peer, and when two peers claim the
        # same one the last one written wins.  Giving every peer the whole
        # list therefore pointed all of them at whichever load balancer came
        # last alphabetically.  Traffic to the other one was encrypted for the
        # wrong node and dropped where it arrived.
        #
        # It fails in a way that looks like a network problem on one node
        # only: the last load balancer works perfectly, the rest handshake,
        # count bytes out and receive almost nothing back.
        peers = "".join(
            PEER_BLOCK.format(node=k.node_name, public_key=k.public_key,
                              endpoint=k.endpoint, allowed=f"{k.address}/32",
                              psk_line=(f"PresharedKey = {psk}\n" if psk else ""))
            for k in keys)

        base = str(request.base_url).rstrip("/")
        return SCRIPT.format(
            fleet=get_settings().node_name,
            iface=IFACE,
            binary=BINARY,
            address=peer.address,
            routes=routes,
            peers=peers,
            callback=f"{base}/tunnel/enrol/{token}",
        )


@router.post("/tunnel/enrol/{token}")
async def enrol_callback(token: str, request: Request):
    """
    The workload telling us its public key, which is the only thing we want.

    The ticket is spent here.  From this point the peer is identified by its
    key, and the link cannot be used again by anybody who saw it go past.
    """
    payload = await request.json()
    public_key = str(payload.get("public_key") or "").strip()
    if not public_key:
        raise HTTPException(status_code=400, detail="no public key was sent")

    with session_scope() as session:
        peer = tunnel.peer_for_token(session, token)
        if not peer:
            raise HTTPException(status_code=404, detail="that link is not valid any more")
        peer.public_key = public_key
        peer.enrolled_at = utcnow()
        peer.enrol_token_hash = None
        peer.enrol_expires_at = None
        name, address = peer.name, peer.address
        session.commit()

    await tunnel.apply_to_fleet()
    log.warning("%s enrolled on the tunnel as %s", name, address)
    audit.record("tunnel.peer.enrolled", user=None, object_type="tunnel_peer",
                 object_name=name)
    return {"ok": True, "address": address}
