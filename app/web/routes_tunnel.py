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

log = logging.getLogger("nfm.tunnel.web")

router = APIRouter()


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
                   "endpoint": k.endpoint, "public_key": k.public_key}
                  for k in keys],
    }


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

    g.session.commit()

    if network.enabled:
        await tunnel.ensure_node_keys()
        await tunnel.apply_to_fleet()

    audit.record("tunnel.configure", user=g.user, object_type="tunnel",
                 object_name=network.cidr)
    with session_scope() as s:
        fresh = s.query(TunnelNetwork).first()
        return _network_json(fresh, s)


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

    try:
        address = tunnel.next_free_address(g.session, network)
    except ValueError as exc:
        raise HTTPException(status_code=409, detail=str(exc))

    peer = TunnelPeer(network_id=network.id, name=name, address=address,
                      description=(payload.get("description") or "")[:500] or None)
    token = tunnel.new_enrol_token(peer)
    g.session.add(peer)
    g.session.commit()

    audit.record("tunnel.peer.add", user=g.user, object_type="tunnel_peer",
                 object_name=name)

    settings = get_settings()
    base = str(payload.get("base_url") or "").rstrip("/")
    if not base:
        base = f"https://{settings.node_address}"

    return {
        **_peer_json(peer),
        "enrol_command": f"curl -sSL {base}/tunnel/enrol/{token} | sudo bash",
        "expires_in_minutes": tunnel.ENROL_MINUTES,
        "note": ("single use, expires in two hours, treat it like a password"),
    }


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

echo "telling the load balancers who we are"
curl -sSf -X POST "{callback}" \\
     -H "Content-Type: application/json" \\
     -d "{{\\"public_key\\": \\"$PUBLIC\\"}}" >/dev/null

cat > $CONF <<EOF
# Written by the {fleet} enrolment script.  Safe to remove with:
#   sudo {binary} unenrol
[Interface]
Address = {address}/32
PrivateKey = $PRIVATE
{peers}
EOF
chmod 600 $CONF

systemctl enable --now wg-quick@$IFACE >/dev/null 2>&1 || {{
  wg-quick down $IFACE >/dev/null 2>&1 || true
  wg-quick up $IFACE
}}

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

echo
echo "done.  This machine is {address} on the tunnel."
echo "Nothing else about this machine's networking has been changed."
echo "Check it with: {binary} status"
"""

PEER_BLOCK = """
[Peer]
# {node}
PublicKey = {public_key}
Endpoint = {endpoint}
# Only the load balancers, never a default route.  This is what keeps the
# tunnel from becoming this machine's way out to the internet.
AllowedIPs = {allowed}
PersistentKeepalive = 25
"""


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

        network = session.query(TunnelNetwork).first()
        keys = session.query(TunnelNodeKey).order_by(TunnelNodeKey.node_name).all()
        if not keys:
            raise HTTPException(status_code=503,
                                detail="the load balancers have no tunnel keys yet")

        allowed = ", ".join(f"{k.address}/32" for k in keys)
        peers = "".join(
            PEER_BLOCK.format(node=k.node_name, public_key=k.public_key,
                              endpoint=k.endpoint, allowed=allowed)
            for k in keys)

        base = str(request.base_url).rstrip("/")
        return SCRIPT.format(
            fleet=get_settings().node_name,
            iface="nfm0",
            binary="/usr/local/bin/nfm-tunnel",
            address=peer.address,
            routes=allowed,
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
