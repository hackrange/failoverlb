"""
Node to node endpoints.

Served only on the peer listener, which requires a client certificate signed
by the cluster CA. Every route also verifies the message signature first: the
certificate proves the caller is a member, the signature proves which member
and that the body is unaltered.
"""

import asyncio
import json
import logging

from fastapi import APIRouter, HTTPException, Request

from app.config import get_settings
from app.core.agent_client import AgentError, get_agent
from app.core.cluster import (
    ClusterError,
    adopt_peer_role,
    adopt_preferred_active,
    looks_like_a_wipe,
    preferred_active,
    verify_peer_request,
)
from app.core import snapshot as snapshot_store
from app.core.render import MANAGED_ROOT
from app.db import session_scope
from app.models import ConfigVersion, Node, NodeRole, utcnow

log = logging.getLogger("nfm.peer")

# Snapshots received with a prepare, held until the matching commit.
_staged_snapshots = {}

router = APIRouter()

# Upper bound on a peer request body. A full rendered config for a large
# fleet is a few hundred KB, so this is generous; it just prevents unbounded
# allocation.
MAX_PEER_BODY = 64 * 1024 * 1024


async def authenticate(request: Request) -> tuple:
    """
    Verify the caller and return (node, parsed body). Called first by every
    route. Not a FastAPI dependency because we need the raw bytes for the
    signature, and relying on body caching across a dependency is fragile.
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
        # Don't say which check failed; that only helps the caller probe.
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
    Answer a peer's heartbeat. Both sides learn each other's state: we
    record what they sent, they read our reply.
    """
    node, payload = await authenticate(request)
    settings = get_settings()

    with session_scope() as session:
        # Update our record of them from what they sent.
        peer = session.query(Node).filter(Node.name == node.name).first()
        if peer:
            peer.last_heartbeat = utcnow()
            peer.applied_version = payload.get("applied_version", peer.applied_version)
            peer.nginx_active = payload.get("nginx_active", peer.nginx_active)
            # Only update if the key is present. Older managers omit it, and
            # treating that as a failure would pull them out of DNS.
            if "nginx_serving" in payload:
                peer.nginx_serving = payload["nginx_serving"]
                peer.nginx_serving_detail = (payload.get("nginx_serving_detail") or "")[:255]
            if payload.get("role"):
                try:
                    adopt_peer_role(session, peer, NodeRole(payload["role"]),
                                    settings.node_name)
                except ValueError:
                    pass

    # Outside the session above: this writes settings rows, and nesting it
    # in the transaction holding the node rows can deadlock.
    if "preferred_active_at" in payload:
        adopt_preferred_active(payload.get("preferred_active"),
                               payload.get("preferred_active_at"))

    with session_scope() as session:
        me = session.query(Node).filter(Node.name == settings.node_name).first()
        _wanted, _wanted_at = preferred_active()
        answer = {
            "node": settings.node_name,
            "role": me.role.value if me else "unknown",
            "priority": settings.cluster_priority,
            # The operator's preferred active node. Newest instruction wins,
            # so whichever node heard it first passes it on.
            "preferred_active": _wanted,
            "preferred_active_at": _wanted_at,
            "applied_version": me.applied_version if me else 0,
            "nginx_active": me.nginx_active if me else False,
            "nginx_serving": me.nginx_serving if me else None,
            "nginx_serving_detail": me.nginx_serving_detail if me else None,
            "nginx_config_ok": me.nginx_config_ok if me else False,
            "waf_module_loaded": me.waf_module_loaded if me else None,
            "nginx_version": me.nginx_version if me else None,
            # Full configure line so peers can compare module builds. A node
            # built with different modules otherwise looks identical until a
            # setting fails to apply.
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
    Phase one: stage and test the config without going live. Answering ok
    is a promise this node can apply it.
    """
    node, payload = await authenticate(request)

    files = payload.get("files")
    version = payload.get("version")

    if not isinstance(files, dict) or not files:
        raise HTTPException(status_code=400, detail="no files were sent")

    # Refuse a config that would empty this node. The sender checks too, so
    # getting here means a forced push or an older sender. It's worth the
    # extra listing: a self-promoted node with a wiped config once queued
    # that empty config for the peer that was serving all the traffic.
    if not payload.get("force"):
        try:
            listing = await get_agent().list_dir(f"{MANAGED_ROOT}/sites")
            live = {f"sites/{e['name']}" for e in listing.get("entries", [])
                    if e.get("name", "").endswith(".conf")}
        except AgentError:
            live = set()          # can't tell, so don't block

        reason = looks_like_a_wipe({p: "" for p in live}, files)
        if reason:
            log.error("refusing version %s from %s: %s", version, node.name, reason)
            return {
                "ok": False,
                "node": get_settings().node_name,
                "output": (
                    f"Refused on {get_settings().node_name}, because {reason}\n\n"
                    f"This node is still serving what it has.  Nothing was changed."
                ),
            }

    # Held until commit, so a rolled back version doesn't leave its objects
    # behind as the newest thing this node knows about.
    snapshot = payload.get("snapshot")
    if isinstance(snapshot, dict) and snapshot.get("tables"):
        _staged_snapshots[version] = snapshot
        # Prune in case commits never arrive.
        for old in [v for v in _staged_snapshots if v < (version or 0) - 5]:
            _staged_snapshots.pop(old, None)

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
    """Phase two: swap the staged config in and reload."""
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

            # Keep the objects this version was rendered from, so a promoted
            # standby can change the config rather than just serve it.
            # Written at commit, not prepare, so rolled back versions leave
            # nothing behind.
            snapshot = _staged_snapshots.pop(version, None)
            if snapshot:
                existing = session.query(ConfigVersion).filter(
                    ConfigVersion.version == version
                ).first()
                if not existing:
                    session.add(ConfigVersion(
                        version=version,
                        checksum=payload.get("checksum") or "",
                        snapshot=json.dumps(snapshot),
                        rendered="{}",     # the files are on disk already
                        author=f"replicated from {node.name}",
                        summary="carried over with the config",
                        origin_node=node.name,
                    ))
            session.commit()

    # Load the objects behind the files we now serve, so the database always
    # matches what the node is serving. Otherwise a node that was down
    # during a promotion comes back with stale objects, becomes active
    # again, and silently undoes every change made while it was away.
    #
    # Separate session: a restore rewrites most config tables and wants its
    # own transaction.
    if result.get("ok") and snapshot:
        try:
            with session_scope() as session:
                written = snapshot_store.restore(session, snapshot)
            log.info("took on the config behind version %s: %s", version,
                     ", ".join(f"{k}={v}" for k, v in written.items() if v))
        except Exception as exc:
            # The apply succeeded and the node is serving correctly. Stale
            # objects are worth logging loudly, not undoing a good apply.
            log.error("applied version %s but could not take on its objects, so "
                      "this node's database is now behind what it is serving: %s",
                      version, exc)
    else:
        log.error("apply of version %s failed: %s", version, result.get("output", "")[:300])

    return {
        "ok": result.get("ok", False),
        "output": result.get("output", ""),
        "node": settings.node_name,
    }


@router.post("/peer/config/rollback")
async def config_rollback(request: Request):
    """Restore the previous config after a failed fleet wide apply."""
    node, payload = await authenticate(request)
    log.warning("rolling back, told to by %s", node.name)

    try:
        result = await get_agent().rollback(name=payload.get("backup"))
    except AgentError as exc:
        return {"ok": False, "output": str(exc)}

    return result


@router.post("/peer/config/status")
async def config_status(request: Request):
    """This node's config version and whether nginx accepts the config."""
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
    Write or delete a challenge token on this node. Every node holds the
    token because the CA connects to whatever address DNS gives it.
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
    Run certbot here. Sent by the active node to whichever node currently
    owns the domain's public address, which may not be the active one.
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
    Send a certificate bundle, including the private key, to another node.
    Every node serves the same sites and only one can obtain the cert. The
    channel is mutual TLS within the cluster CA and the caller is signature
    verified.
    """
    node, payload = await authenticate(request)
    name = payload.get("name")

    try:
        return await get_agent().cert_export(name=name)
    except AgentError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/peer/host-metrics")
async def peer_host_metrics(request: Request):
    """
    Host metrics for a peer's utilization page. Read from /proc by the
    manager, not the agent: the agent runs with ProcSubset=pid and can't see
    /proc/stat, and loosening the root component for a chart isn't worth it.
    Nothing here is sensitive.
    """
    node, _payload = await authenticate(request)
    from app.core.metrics import read_host

    return read_host()


@router.post("/peer/cert/forget")
async def cert_forget(request: Request):
    """
    Remove a deleted certificate's files from this node. Only our own
    folder, never certbot's; see the agent verb.
    """
    node, payload = await authenticate(request)
    try:
        return await get_agent().cert_forget(name=payload.get("name"))
    except AgentError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


@router.post("/peer/cert/import")
async def cert_import(request: Request):
    """Accept a certificate bundle from the node that obtained it."""
    node, payload = await authenticate(request)

    try:
        result = await get_agent().cert_import(
            name=payload.get("name"),
            bundle=payload.get("bundle", {}),
        )
    except AgentError as exc:
        raise HTTPException(status_code=500, detail=str(exc))

    # Reload so nginx picks up the new files; otherwise it keeps serving the
    # old cert, possibly past expiry. A failed reload is logged, not raised,
    # since the copy itself worked.
    from app.core.acme import _reload_for_new_cert

    await _reload_for_new_cert(payload.get("name"))

    log.info("took a copy of cert %s from %s", payload.get("name"), node.name)
    return {"ok": True, "result": result}


# ==============================================================================
# Running a build on a peer
# ==============================================================================

# Agent verbs a peer may ask this node to run. An explicit list, never
# "whatever the caller names": otherwise one compromised node would be root
# on every other, defeating the agent's own verb list.
PEER_AGENT_VERBS = {
    # Tunnel verbs touch only the tunnel's own files, and the private key is
    # never returned.
    "tunnel_key",
    "tunnel_apply",
    "tunnel_install",
    "tunnel_install_status",
    "tunnel_status",
    "tunnel_down",
    "nginx_upgrade",
    "nginx_upgrade_status",
    "nginx_revert",
    "status",
    "config_test",
    # Connection counts from stub_status, for the fleet view. Read only, no
    # filesystem arguments.
    "nginx_metrics",
    # GeoIP database. A node without it refuses the whole config, so any
    # node must be able to install it on the others. Takes only the name of
    # a known source, never a URL or path.
    "geoip_install",
    "geoip_status",
    # WAF rule set, same reasoning as GeoIP. Takes only a known track name.
    "crs_install",
    "crs_status",
    "crs_rule_ids",
    # WAF module load/status. The fleet must agree on whether the module is
    # loaded, or a site passes the config test on one node and fails on the
    # other. The install writes one file we control, tests, and rolls back
    # on failure.
    "waf_module",
    "waf_module_status",
    # WAF hits. A learning session needs every node's hits, since whichever
    # node was active during testing holds them. Read takes a site and a
    # timestamp; clear removes only that site's log.
    "waf_hits",
    "waf_hits_clear",
    "waf_log_status",
    # Surface model, same reason and arguments as hits. One node's log only
    # covers part of the traffic.
    "waf_surface",
    # Failed logins. Password spraying is spread thin on purpose, so one
    # node's view can fall under the threshold. Returns counts per address,
    # never usernames (the access log has none).
    "login_failures",
    # Log rotation, run fleet wide from the active node so a standby's disk
    # doesn't fill.
    "waf_log_rotate",
}


@router.post("/peer/agent")
async def peer_agent(request: Request):
    """
    Run an allowed agent verb on behalf of a peer. Used to drive fleet wide
    operations, like a rolling rebuild, from whichever node the admin is on.
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
        # Must be an error status, not 200 with ok=false. PeerClient returns
        # the body as-is, so callers would treat a refused verb as success;
        # a rolling upgrade once marked a peer "building" and waited out the
        # full 45 minute timeout for a build that never started.
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/peer/gslb")
async def peer_gslb(request: Request):
    """
    Accept the fleet's DNS zones from the active node.

    Zones render no nginx config, so they never travel with a config apply.
    Without this push a standby had no zones, ran no listener, and the fleet
    had one working nameserver instead of two.
    """
    node, payload = await authenticate(request)

    tables = payload.get("tables")
    if tables is None or not isinstance(tables, dict):
        raise HTTPException(status_code=400, detail="that had no zone data on it")

    with session_scope() as session:
        result = snapshot_store.restore_gslb(
            session, tables,
            sender_has_config=bool(payload.get("sender_has_config", True)))
        if result.get("refused"):
            session.rollback()
        else:
            session.commit()

    if result.get("refused"):
        log.error("refused the dns zones %s sent: %s", node.name, result["refused"])
        raise HTTPException(status_code=409, detail=result["refused"])

    # Nothing is started or stopped here; gslb.reconcile follows the zones on
    # its own timer and handles the socket bind safely.
    return {"ok": True, **result}


@router.post("/peer/accounts")
async def peer_accounts(request: Request):
    """
    Accept the fleet's accounts from the active node.

    Separate from config applies because account changes touch no nginx
    config. Revoking access has to reach every node immediately, not on the
    next site edit. The rules for what is merged, kept or refused (e.g. a set
    with no enabled admin) are in snapshot.py.
    """
    node, payload = await authenticate(request)

    rows = payload.get("users")
    if rows is None or not isinstance(rows, list):
        raise HTTPException(status_code=400, detail="that had no account list on it")

    with session_scope() as session:
        result = snapshot_store.restore_users(session, rows)
        session.commit()

    if result.get("refused"):
        # Fail loudly. A node silently keeping different accounts is exactly
        # what this path exists to prevent.
        log.error("refused the accounts %s sent: %s", node.name, result["refused"])
        raise HTTPException(status_code=409, detail=result["refused"])

    log.info("took on accounts from %s: %s", node.name,
             ", ".join(f"{k}={v}" for k, v in result.items()))
    return {"ok": True, **result}


# ==============================================================================
# Joining
# ==============================================================================

@router.post("/peer/join")
async def join(request: Request):
    """
    Admit a new node. Unlike every other route there is no signature check,
    since the joiner has no certificate yet; it presents a join token and gets
    a signed certificate back. Tokens are therefore as sensitive as passwords:
    single use, short lived, stored only as a hash.
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

        # Sign with the common name forced to the agreed node name, so the
        # joiner can't obtain a cert impersonating another node.
        try:
            signed = ca.sign_node_csr(csr, node_name)
        except Exception as exc:
            raise HTTPException(status_code=400, detail=f"could not sign that request: {exc}")

        # Per node HMAC key, separate from the certificate so a node can be
        # cut off without reissuing anything.
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

        # What the joiner needs about the rest of the cluster, including our
        # own key so it can talk back to us.
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

    # Send certificates once the new node has settled. The join carries the
    # config rows but not certificate files, so its first apply would fail
    # on a missing file. Not inline, because the node restarts to bring up
    # its peer listener as soon as it reads this response.
    asyncio.create_task(_send_certificates_after_join(node_name))

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



async def _send_certificates_after_join(node_name: str, tries: int = 10,
                                        gap: int = 15):
    """
    Copy every usable certificate to a newly joined node. Retried (10 tries,
    15s apart) since the node is restarting and we can't know when it will
    be listening. Failure doesn't undo the join; it's logged loudly instead.
    """
    from app.core.acme import AcmeError, get_cert_manager
    from app.models import Certificate

    await asyncio.sleep(gap)

    with session_scope() as session:
        cert_ids = [c.id for c in session.query(Certificate).all() if c.usable]
    if not cert_ids:
        return

    manager = get_cert_manager()
    for attempt in range(1, tries + 1):
        missing = []
        for cid in cert_ids:
            try:
                result = await manager.replicate(cid)
            except AcmeError as exc:
                log.warning("could not copy a certificate to %s: %s",
                            node_name, exc)
                missing.append(cid)
                continue
            if node_name not in (result.get("ok") or []):
                missing.append(cid)

        if not missing:
            log.info("%s has every certificate, so its first apply will not "
                     "fail on a missing file", node_name)
            return

        cert_ids = missing
        if attempt < tries:
            await asyncio.sleep(gap)

    log.error("%s is in the cluster but is missing %s certificate(s).  Its "
              "next apply will fail until they are copied.  Press Sync now on "
              "the Cluster page.", node_name, len(cert_ids))


@router.post("/peer/roster")
async def roster(request: Request):
    """
    Exchange node lists with a peer. Nodes join through one sponsor, so
    this is how a third node learns about the second.
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
                # Don't take keys from gossip; they only come from a join.
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


@router.post("/peer/settings")
async def peer_settings(request: Request):
    """
    Accept fleet wide settings from the node running a restore.

    Settings are otherwise node local, and after a restore a standby
    without, say, the ACME email or resolvers would behave differently once
    promoted. Values arrive in the clear over the peer channel (mutual TLS)
    and are encrypted again here with this node's key.
    """
    node, payload = await authenticate(request)

    rows = payload.get("settings")
    if not isinstance(rows, list):
        raise HTTPException(status_code=400, detail="settings has to be a list")

    from app.core.backup import _restore_settings

    with session_scope() as session:
        result = _restore_settings(session, rows)
        session.commit()

    log.info("%s sent us %s settings during a restore", node.name, result["restored"])
    return {"ok": True, **result}
