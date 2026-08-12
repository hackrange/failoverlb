"""
Node to node endpoints.

Nothing here is reachable from a browser.  The listener demands a client
certificate signed by this cluster's CA, so the TLS handshake fails before any
of this code runs for anybody else.

On top of that, every route below verifies the message signature first.  The
certificate proves the caller is a cluster member.  The signature proves which
member, and that this exact body is what they sent.
"""

import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import get_settings
from app.core.agent_client import AgentError, get_agent
from app.core.cluster import ClusterError, verify_peer_request
from app.db import session_scope
from app.models import Node, NodeRole, utcnow

log = logging.getLogger("nfm.peer")

router = APIRouter()

# Biggest peer body we will read.  A whole rendered config for a large fleet is
# a few hundred KB, so this is generous.  It stops a peer, or something that got
# past the TLS layer, from making us allocate unbounded memory.
MAX_PEER_BODY = 64 * 1024 * 1024


async def authenticate(request: Request) -> tuple:
    """
    Check the caller and give back the node and the parsed body.

    Every route calls this first.  It is not a dependency on purpose: we need
    the raw bytes to check the signature, and reading the body twice is exactly
    the kind of thing that quietly breaks when FastAPI changes how it caches it.
    """
    import json

    body = await request.body()
    if len(body) > MAX_PEER_BODY:
        raise HTTPException(status_code=413, detail="that is too big")

    try:
        node = verify_peer_request(
            node_name=request.headers.get("X-NFM-Node"),
            timestamp=request.headers.get("X-NFM-Timestamp"),
            nonce=request.headers.get("X-NFM-Nonce"),
            body=body,
            signature=request.headers.get("X-NFM-Signature"),
            source_ip=request.client.host if request.client else "unknown",
        )
    except ClusterError as exc:
        log.warning("refused a peer request: %s", exc)
        # 401 with no detail about which check failed.  Telling a caller that
        # the signature was fine but the address was wrong helps them fix it.
        raise HTTPException(status_code=401, detail="not authorized")

    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="that was not valid json")

    return node, payload


# ==============================================================================
# Heartbeat
# ==============================================================================

@router.post("/peer/heartbeat")
async def heartbeat(request: Request):
    """
    Answer a peer's heartbeat and tell them how we are.

    This is also how the roster stays fresh in both directions.  They learn our
    state from the answer, and we learn theirs from what they sent.
    """
    node, payload = await authenticate(request)
    settings = get_settings()

    with session_scope() as session:
        # Update what we know about them from what they told us.
        peer = session.query(Node).filter(Node.name == node.name).first()
        if peer:
            peer.last_heartbeat = utcnow()
            peer.applied_version = payload.get("applied_version", peer.applied_version)
            peer.nginx_active = payload.get("nginx_active", peer.nginx_active)
            if payload.get("role"):
                try:
                    peer.role = NodeRole(payload["role"])
                except ValueError:
                    pass

        me = session.query(Node).filter(Node.name == settings.node_name).first()
        answer = {
            "node": settings.node_name,
            "role": me.role.value if me else "unknown",
            "priority": settings.cluster_priority,
            "applied_version": me.applied_version if me else 0,
            "nginx_active": me.nginx_active if me else False,
            "nginx_config_ok": me.nginx_config_ok if me else False,
            "nginx_version": me.nginx_version if me else None,
            # The whole configure line, so the other nodes can work out which
            # modules this box was actually built with.  Without it a node that
            # was built from a different module list looks identical to every
            # other one, and the first anybody knows is a setting that will not
            # apply for no visible reason.
            "nginx_build_info": me.nginx_build_info if me else None,
            "public_ip": me.public_ip if me else None,
            "local_addresses": me.local_address_list() if me else [],
            "load_average": me.load_average if me else None,
            "disk_free": me.disk_free_bytes if me else None,
        }
        session.commit()

    return answer


# ==============================================================================
# Config, the two phases
# ==============================================================================

@router.post("/peer/config/prepare")
async def config_prepare(request: Request):
    """
    Phase one.  Stage the config and test it, but do not go live.

    Answering ok here is a promise that this node can apply it.  Getting that
    promise from every node before anybody commits is the whole point.
    """
    node, payload = await authenticate(request)

    files = payload.get("files")
    version = payload.get("version")

    if not isinstance(files, dict) or not files:
        raise HTTPException(status_code=400, detail="no files were sent")

    log.info("staging version %s from %s", version, node.name)

    agent = get_agent()
    try:
        await agent.write_staging(files)
        result = await agent.test_staging()
    except AgentError as exc:
        log.error("could not stage version %s: %s", version, exc)
        return {"ok": False, "output": str(exc), "node": get_settings().node_name}

    if not result.get("ok"):
        log.warning("version %s failed its config test here: %s",
                    version, result.get("output", "")[:300])

    return {
        "ok": result.get("ok", False),
        "output": result.get("output", ""),
        "node": get_settings().node_name,
    }


@router.post("/peer/config/commit")
async def config_commit(request: Request):
    """Phase two.  Swap the staged config in and reload."""
    node, payload = await authenticate(request)
    version = payload.get("version")
    settings = get_settings()

    log.info("applying version %s, told to by %s", version, node.name)

    try:
        result = await get_agent().apply(reload=True, label=f"v{version}")
    except AgentError as exc:
        log.error("could not apply version %s: %s", version, exc)
        return {"ok": False, "output": str(exc), "node": settings.node_name}

    if result.get("ok"):
        with session_scope() as session:
            me = session.query(Node).filter(Node.name == settings.node_name).first()
            if me:
                me.applied_version = version
                me.last_sync_at = utcnow()
                me.nginx_config_ok = True
                me.last_error = None
            session.commit()
    else:
        log.error("apply of version %s failed: %s", version, result.get("output", "")[:300])

    return {
        "ok": result.get("ok", False),
        "output": result.get("output", ""),
        "node": settings.node_name,
    }


@router.post("/peer/config/rollback")
async def config_rollback(request: Request):
    """Put the previous config back.  Called when a fleet wide apply went bad."""
    node, payload = await authenticate(request)
    log.warning("rolling back, told to by %s", node.name)

    try:
        result = await get_agent().rollback(name=payload.get("backup"))
    except AgentError as exc:
        return {"ok": False, "output": str(exc)}

    return result


@router.post("/peer/config/status")
async def config_status(request: Request):
    """What version this node is on, and whether nginx is happy."""
    await authenticate(request)
    settings = get_settings()

    try:
        test = await get_agent().config_test()
    except AgentError as exc:
        test = {"ok": False, "output": str(exc)}

    with session_scope() as session:
        me = session.query(Node).filter(Node.name == settings.node_name).first()
        return {
            "node": settings.node_name,
            "applied_version": me.applied_version if me else 0,
            "applied_checksum": me.applied_checksum if me else None,
            "config_ok": test.get("ok", False),
            "config_output": test.get("output", ""),
        }


# ==============================================================================
# Certificates
# ==============================================================================

@router.post("/peer/acme/token")
async def acme_token(request: Request):
    """
    Put a challenge token on this node, or take it off again.

    This is what makes issuing a cert reliable across a cluster.  Lets Encrypt
    connects to whichever address DNS gives it, and we do not get to choose.  So
    every node holds the token and it does not matter which one they pick.
    """
    node, payload = await authenticate(request)

    action = payload.get("action")
    token = payload.get("token")

    agent = get_agent()
    try:
        if action == "write":
            result = await agent.acme_token_write(token=token, value=payload.get("value", ""))
        elif action == "delete":
            result = await agent.acme_token_delete(token=token)
        else:
            raise HTTPException(status_code=400, detail="action has to be write or delete")
    except AgentError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    return {"ok": True, "result": result}


@router.post("/peer/acme/issue")
async def acme_issue(request: Request):
    """
    Run certbot here.

    The active node sends this to whichever node currently owns the public
    address for the domain.  That node may well not be the active one, which is
    the entire reason this endpoint exists.
    """
    node, payload = await authenticate(request)

    log.info("running certbot for %s, asked by %s",
             payload.get("domains"), node.name)

    try:
        return await get_agent().certbot(**payload)
    except AgentError as exc:
        return {"ok": False, "output": str(exc)}


@router.post("/peer/cert/export")
async def cert_export(request: Request):
    """
    Hand a cert bundle over to another node.

    Yes, this includes the private key.  It has to: every node serves the same
    sites and only one of them could get the cert.  The channel is mutual TLS
    between two nodes holding certificates from the same private CA, and the
    caller has already proved which node it is with a signature.
    """
    node, payload = await authenticate(request)
    name = payload.get("name")

    try:
        return await get_agent().cert_export(name=name)
    except AgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/peer/cert/import")
async def cert_import(request: Request):
    """Take a cert bundle from the node that got it."""
    node, payload = await authenticate(request)

    try:
        result = await get_agent().cert_import(
            name=payload.get("name"),
            bundle=payload.get("bundle", {}),
        )
    except AgentError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Pick it up straight away.  nginx reads certificate files when it loads and
    # then holds them, so new bytes on disk change nothing until it looks again.
    # Without this the node quietly serves the old certificate until something
    # unrelated reloads it, and at renewal time that means serving an expired
    # one with a good one sitting next to it.
    #
    # A failed reload is logged, not raised.  The copy itself worked, and
    # answering with a 500 would tell the sending node that replication failed
    # when it did not.
    from app.core.acme import _reload_for_new_cert

    await _reload_for_new_cert(payload.get("name"))

    log.info("took a copy of cert %s from %s", payload.get("name"), node.name)
    return {"ok": True, "result": result}


# ==============================================================================
# Running a build on a peer
# ==============================================================================

# Verbs another node is allowed to ask this one to run.
#
# Deliberately a short list, not "whatever the caller names".  A peer being
# able to invoke any verb would make one compromised node as good as root on
# every other one, which is exactly the thing the agent's own verb list exists
# to prevent.  Forwarding everything would hand that away one level up.
#
# These four are what a fleet wide rebuild needs and nothing more.
PEER_AGENT_VERBS = {
    "nginx_upgrade",
    "nginx_upgrade_status",
    "nginx_revert",
    "status",
    "config_test",
}


@router.post("/peer/agent")
async def peer_agent(request: Request):
    """
    Let the node running an upgrade drive a build on this one.

    A rebuild has to be walked one node at a time from somewhere, and that
    somewhere is whichever node the admin clicked on.  This is how it reaches
    the others.
    """
    node, payload = await authenticate(request)

    verb = payload.get("verb")
    if verb not in PEER_AGENT_VERBS:
        log.warning("%s asked us to run %r, which is not on the list", node.name, verb)
        raise HTTPException(
            status_code=403,
            detail=f"{verb} is not something a peer may ask for",
        )

    args = payload.get("payload") or {}
    if not isinstance(args, dict):
        raise HTTPException(status_code=400, detail="payload has to be an object")

    log.info("%s asked us to run %s", node.name, verb)

    try:
        return await get_agent().call(verb, timeout=120, **args)
    except AgentError as exc:
        return {"ok": False, "error": str(exc)}


# ==============================================================================
# Joining
# ==============================================================================

@router.post("/peer/join")
async def join(request: Request):
    """
    Let a new node into the cluster.

    This one is different from everything else here, because a node that is
    joining does not have a certificate yet, so it cannot pass the normal
    checks.  It presents a join token instead, and the token is what gets it a
    signed certificate.

    Because of that the token is as good as a password.  They are single use,
    they expire in a couple of hours, and only the hash is stored.
    """
    import json

    from app.core.crypto import ClusterCA, encrypt, hash_token, new_token
    from app.models import JoinToken, NodeState

    body = await request.body()
    try:
        payload = json.loads(body) if body else {}
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="that was not valid json")

    token = payload.get("token", "")
    node_name = payload.get("node_name", "")
    address = payload.get("address", "")
    csr = payload.get("csr", "")
    priority = int(payload.get("priority", 100))

    if not all([token, node_name, address, csr]):
        raise HTTPException(status_code=400, detail="that join request is missing fields")

    import re

    if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", node_name):
        raise HTTPException(status_code=400, detail="that node name is not valid")

    ca = ClusterCA()
    if not ca.ca_key_path.is_file():
        raise HTTPException(
            status_code=400,
            detail="this node does not hold the cluster CA key, so it cannot admit members",
        )

    with session_scope() as session:
        row = session.query(JoinToken).filter(
            JoinToken.token_hash == hash_token(token)
        ).first()

        if not row or not row.is_valid:
            log.warning("refused a join from %s with a bad or used token", node_name)
            raise HTTPException(status_code=401, detail="that join token is not valid")

        existing = session.query(Node).filter(Node.name == node_name).first()
        if existing and not existing.is_self:
            log.info("%s is rejoining", node_name)

        # Sign their certificate.  The common name gets forced to the node name
        # we agreed on, so they cannot ask for a cert claiming to be somebody
        # else and then use it to impersonate that node.
        try:
            signed = ca.sign_node_csr(csr, node_name)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not sign that request: {exc}")

        # A shared key for signing messages, one per node.  Separate from the
        # certificate so a node can be cut off without reissuing anything.
        hmac_key = new_token(32)

        if existing:
            node = existing
        else:
            node = Node(name=node_name)
            session.add(node)

        node.address = address
        node.priority = priority
        node.peer_port = int(payload.get("peer_port", 7444))
        node.gui_port = int(payload.get("gui_port", 7443))
        node.hmac_key_encrypted = encrypt(hmac_key)
        node.cert_fingerprint = ca.cert_fingerprint(signed)
        node.state = NodeState.JOINING
        node.role = NodeRole.STANDBY
        node.joined_at = utcnow()
        node.is_self = False

        row.used_at = utcnow()
        row.used_by_node = node_name

        # Everything the joining node needs to know about the rest of the
        # cluster, including our own key so it can talk back to us.
        settings = get_settings()
        me = session.query(Node).filter(Node.name == settings.node_name).first()

        peers = []
        for other in session.query(Node).all():
            if other.name == node_name:
                continue
            peers.append({
                "name": other.name,
                "address": other.address,
                "peer_port": other.peer_port,
                "gui_port": other.gui_port,
                "priority": other.priority,
                "hmac_key": (
                    hmac_key if other.name == settings.node_name
                    else None
                ),
            })

        session.commit()

    log.warning("%s joined the cluster from %s", node_name, address)

    return {
        "ok": True,
        "certificate": signed,
        "ca_certificate": ca.ca_pem(),
        "hmac_key": hmac_key,
        "cluster": {
            "sponsor": get_settings().node_name,
            "peers": peers,
        },
    }


@router.post("/peer/roster")
async def roster(request: Request):
    """
    Tell a peer about every node we know, and take their list too.

    This is how a third node learns about the second one.  Everybody joins
    through one sponsor, so without this the new node would only know the box it
    joined through.
    """
    from app.core.crypto import encrypt
    from app.models import NodeState

    node, payload = await authenticate(request)

    incoming = payload.get("nodes", [])
    settings = get_settings()

    with session_scope() as session:
        for entry in incoming:
            name = entry.get("name")
            if not name or name == settings.node_name:
                continue

            existing = session.query(Node).filter(Node.name == name).first()
            if existing:
                # Never overwrite a key we already have from something a peer
                # told us.  Keys come from a join, not from gossip.
                existing.address = entry.get("address", existing.address)
                existing.priority = entry.get("priority", existing.priority)
                continue

            if not entry.get("hmac_key"):
                continue

            session.add(Node(
                name=name,
                address=entry.get("address", ""),
                peer_port=entry.get("peer_port", 7444),
                gui_port=entry.get("gui_port", 7443),
                priority=entry.get("priority", 100),
                hmac_key_encrypted=encrypt(entry["hmac_key"]),
                state=NodeState.OFFLINE,
                role=NodeRole.STANDBY,
            ))
            log.info("learned about node %s from %s", name, node.name)

        session.commit()

        return {
            "nodes": [
                {
                    "name": n.name,
                    "address": n.address,
                    "peer_port": n.peer_port,
                    "gui_port": n.gui_port,
                    "priority": n.priority,
                    "role": n.role.value,
                    "state": n.state.value,
                }
                for n in session.query(Node).all()
            ]
        }
