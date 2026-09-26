"""
The WireGuard tunnel: managing it, and letting a workload enroll itself.

The managed half sits behind the normal login.  The enrollment half has no
login so a workload can join with one command; the ticket in the URL is the
credential instead.  It is single use, expires in two hours, and only its hash
is stored, so treat it like the cluster join token.

The script is served over https and kept short so people can read it before
piping it into a shell.
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

# Interface and helper the enrollment script installs.  Shared constants so
# the removal command shown in the GUI always matches what was installed.
IFACE = "nfm0"
BINARY = "/usr/local/bin/nfm-tunnel"

# Undo command shown for a workload.  Not the nfm-tunnel helper, because a half
# finished enrollment may never have written it.  Only removes the interface,
# config and key we wrote; the wireguard package is left alone since the
# machine may use it for something else.
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
    Names of pools with a member at this workload's address.  A member left
    behind after removal would later send traffic to whoever gets the address.
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
    Names of sites that depend on this workload, i.e. what breaks if it goes.

    Includes pools used by a site's paths as well as its main pool.
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
        # Per workload, since workloads are upgraded to a PSK one at a time.
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

    # Per node endpoint override.  Blank clears it (store None, not "", or the
    # override would be empty and the tunnel unreachable).
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
    """Per node install state, so the page only offers the button if needed."""
    return await tunnel.install_status()


@router.post("/api/tunnel/install")
async def tunnel_install(g: ObjectGuard = Depends(changing)):
    """
    Install the tunnel packages on every node.  Refused unless the tunnel is
    switched on, which is our signal that the admin wants it.
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
    """Reserve an address for a workload and mint its enrollment ticket."""
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

    # A specific address may be requested, typically to put a machine back at
    # its old address so existing pool members keep working.  The counter is
    # left alone in that case; bumping it would skip the addresses in between.
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
    # Every new workload gets a pre-shared key.  It goes into the enrollment
    # script and every node's peer block together, so there is no gap.
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
        # Warn rather than refuse: reuse is usually intended, but a typo
        # should be caught before the pool sends it traffic.
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
    Who holds each address in the tunnel range, and which are free.

    The allocation counter only goes up, so after adding and removing
    workloads it looks like the range is running out.  This shows the gaps,
    which can still be requested explicitly.
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
    # Only show up to the counter plus a few, not the whole range.
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
                # Free but below the counter, so automatic allocation skips it.
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
    Mint a one-time command that adds a pre-shared key to an enrolled
    workload.

    A WireGuard PSK is never sent over the wire, so it cannot be pushed from
    here; something has to run on the workload.  The script keeps the address,
    private key and pool membership, and rolls back if the tunnel does not
    come up within a minute.
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
    Remove a workload's pre-shared key on the load balancer side.

    Recovery for a half finished upgrade where the nodes have the key and the
    workload does not.  Falls back to a plain peering.
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
    Mint a fresh enrollment command for a workload that has not joined yet.

    We only keep the ticket's hash, so the old command cannot be shown again.
    The new ticket replaces the old one, which stops working.
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
    Change a workload's description.

    Only the description is editable; name and address are referenced by
    pools and sites.  No apply, since the tunnel config does not include it.
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
    Remove a workload from the tunnel on our side.  Works even if the machine
    is already gone, which is the usual case.
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
# The enrollment half, which has no login
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
    Serve the PSK upgrade script for an enrolled workload.

    Fetching it activates the key on the load balancers.  Both ends must
    agree, so there is a short window either way; starting it here means the
    script is already running to close it.  Keepalive re-handshakes through
    the gap, and the script rolls back if no handshake arrives in a minute.

    Single use, and only the ticket's hash is stored.
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
        # Burned on read so the link in shell history is useless.
        peer.psk_token_hash = None
        peer.psk_expires_at = None
        name = peer.name
        session.commit()

    # Apply on the nodes now so they already agree when the script runs.
    await tunnel_mod.apply_to_fleet()

    audit.record("tunnel.peer.psk", user=None, source_ip=client_ip(request),
                 object_type="tunnel_peer", object_name=name,
                 detail="pre-shared key issued and applied on the fleet")

    return PSK_SCRIPT.format(iface=IFACE, psk=value)


@router.get("/tunnel/enrol/{token}", response_class=PlainTextResponse)
async def enrol_script(token: str, request: Request):
    """
    The enrollment script a workload pipes into bash.

    The ticket in the URL is the credential.  It is checked here so a bad
    ticket gets a readable error instead of a script that fails.
    """
    with session_scope() as session:
        peer = tunnel.peer_for_token(session, token)
        if not peer:
            raise HTTPException(
                status_code=404,
                detail=("that enrolment link is not valid any more.  They are "
                        "single use and expire after two hours.  Ask for a "
                        "fresh one on the Tunnel page."))

        # Read while the session is still open.
        psk = tunnel.peer_psk(peer)

        network = session.query(TunnelNetwork).first()
        keys = session.query(TunnelNodeKey).order_by(TunnelNodeKey.node_name).all()
        if not keys:
            raise HTTPException(status_code=503,
                                detail="the load balancers have no tunnel keys yet")

        # All node addresses, for the script's header comment only.  Never use
        # this as a peer's AllowedIPs.
        routes = ", ".join(f"{k.address}/32" for k in keys)

        # Each peer gets only its own address.  AllowedIPs is also a routing
        # table and the last peer to claim an address wins, so giving every
        # peer the full list routed everything to the last node.  The others
        # handshook fine but got almost no traffic back.
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
    The workload posts its public key.  The ticket is spent here; from now on
    the peer is identified by its key.
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
