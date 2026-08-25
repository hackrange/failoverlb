"""
Node to node endpoints.

Nothing here is reachable from a browser.  The listener demands a client
certificate signed by this cluster's CA, so the TLS handshake fails before any
of this code runs for anybody else.

On top of that, every route below verifies the message signature first.  The
certificate proves the caller is a cluster member.  The signature proves which
member, and that this exact body is what they sent.
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

# Snapshots that arrived with a prepare and are waiting to see whether the
# commit follows.  Small, and cleared as versions move on.
_staged_snapshots = {}

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
            # Only move this if they actually said something.  An older manager
            # leaves the key out, and reading that as a failure would withdraw
            # them from DNS for running last week's build.
            if "nginx_serving" in payload:
                peer.nginx_serving = payload["nginx_serving"]
                peer.nginx_serving_detail = (payload.get("nginx_serving_detail") or "")[:255]
            if payload.get("role"):
                try:
                    adopt_peer_role(session, peer, NodeRole(payload["role"]),
                                    settings.node_name)
                except ValueError:
                    pass

    # Outside the session above.  Taking on the other node's copy of the
    # request writes settings rows of its own, and nesting that inside the
    # transaction holding the node rows is how two of these deadlock.
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
            # Which node somebody asked to be active.  Both nodes hold the same
            # value and the newest instruction wins, so whichever of the two
            # heard it first tells the other.
            "preferred_active": _wanted,
            "preferred_active_at": _wanted_at,
            "applied_version": me.applied_version if me else 0,
            "nginx_active": me.nginx_active if me else False,
            "nginx_serving": me.nginx_serving if me else None,
            "nginx_serving_detail": me.nginx_serving_detail if me else None,
            "nginx_config_ok": me.nginx_config_ok if me else False,
            "waf_module_loaded": me.waf_module_loaded if me else None,
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

    # Do not let another node empty this one.
    #
    # The active node checks this before sending, so reaching here means either
    # somebody forced it or the sender is running an older build.  Checking
    # again costs one directory listing and is the difference between losing one
    # node's config and losing the fleet's: the node that promoted itself and
    # wiped its own config queued the same empty config for the node that was
    # down, and that node was serving all the traffic.
    if not payload.get("force"):
        try:
            listing = await get_agent().list_dir(f"{MANAGED_ROOT}/sites")
            live = {f"sites/{e['name']}" for e in listing.get("entries", [])
                    if e.get("name", "").endswith(".conf")}
        except AgentError:
            live = set()          # cannot tell, so do not stand in the way

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

    # Held until the commit lands, so a version that gets rolled back does not
    # leave its objects behind as the newest thing this node knows about.
    snapshot = payload.get("snapshot")
    if isinstance(snapshot, dict) and snapshot.get("tables"):
        _staged_snapshots[version] = snapshot
        # A node that never commits would otherwise grow this forever.
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

            # Keep the objects this version was rendered from.
            #
            # A standby used to hold the files and nothing else, so being
            # promoted left it able to serve what it had and unable to change
            # any of it.  Keeping the snapshot is what makes a promotion useful
            # rather than merely survivable.
            #
            # Written here rather than at prepare time because prepare is a
            # promise and commit is the thing that happened.  A version that
            # was staged and then rolled back should not leave its objects
            # behind as the newest thing this node knows.
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

    # Take on the objects behind the files we just agreed to serve.
    #
    # The invariant worth having is simple: what a node has in its database is
    # what it is serving.  Without this the two drift the moment anything is
    # changed anywhere else, and the drift is silent and one directional.
    #
    # A node that was down while the other one was promoted comes back, is given
    # the files, serves them, and still has its own older objects.  It becomes
    # active again, renders from those, and quietly undoes every change made
    # while it was away.  Nothing warns anybody, because from its point of view
    # nothing changed.
    #
    # Outside the session above because a restore rewrites most of the config
    # tables and wants a transaction of its own.
    if result.get("ok") and snapshot:
        try:
            with session_scope() as session:
                written = snapshot_store.restore(session, snapshot)
            log.info("took on the config behind version %s: %s", version,
                     ", ".join(f"{k}={v}" for k, v in written.items() if v))
        except Exception as exc:
            # The files are applied and this node is serving correctly.  Failing
            # here means the objects are stale, which is worth shouting about
            # and is not worth undoing a good apply over.
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


@router.post("/peer/host-metrics")
async def peer_host_metrics(request: Request):
    """
    What this box is doing, for a peer's utilization page.

    Read out of /proc by this manager rather than by its agent, because the
    agent runs with ProcSubset=pid and cannot see /proc/stat.  Widening the one
    root component in the system so a chart can be drawn would be a poor trade,
    and the container needs no privilege to read these itself.

    Nothing here is a secret: cpu jiffies, memory totals and a load average.
    """
    node, _payload = await authenticate(request)
    from app.core.metrics import read_host

    return read_host()


@router.post("/peer/cert/forget")
async def cert_forget(request: Request):
    """
    Take a deleted certificate's files off this node.

    Only our own folder, never certbot's.  See the agent verb for why.
    """
    node, payload = await authenticate(request)
    try:
        return await get_agent().cert_forget(name=payload.get("name"))
    except AgentError as exc:
        raise HTTPException(status_code=500, detail=str(exc))


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
    # The tunnel.  Read only or write only to the tunnel's own files, and the
    # private key never comes back out of any of them.
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
    # Connection counts off stub_status.  Read only, no arguments that reach
    # the filesystem, and the whole reason for a fleet view is seeing the other
    # node's numbers on whichever page somebody happens to be on.
    "nginx_metrics",
    # The country database.  Installing it is a fleet wide job by nature: a node
    # without the file refuses the whole config, so the node somebody clicked on
    # has to be able to put it on the others.  Neither verb takes a URL or a
    # path, only the name of a source the agent already knows.
    "geoip_install",
    "geoip_status",
    # The firewall rule set, for exactly the same reason as the country
    # database above: a node without the rules refuses the whole config, so
    # whichever node somebody clicked on has to be able to put them on the
    # others.  Neither verb takes a URL or a path either, only the name of a
    # track the agent already knows.
    "crs_install",
    "crs_status",
    "crs_rule_ids",
    # Loading the module.  Read only in the status case, and the install case
    # writes one file whose contents this node decides, tests the result and
    # puts the old state back if nginx refuses it.  It has to be reachable from
    # a peer because the whole fleet has to agree about whether the module is
    # loaded: one node with it and one without is a site that works on one box
    # and fails its config test on the other.
    "waf_module",
    "waf_module_status",
    # The hits.  A learning session has to see what fired on every node, not
    # just the one somebody is looking at, because whichever node was active
    # when the testers ran is the one holding the evidence.  Reading takes a
    # site name and a timestamp; clearing throws away that site's own log and
    # nothing else.
    "waf_hits",
    "waf_hits_clear",
    "waf_log_status",
    # The surface, for the same reason as the hits and with the same arguments.
    # A positive model built from one node's log is built from half the walk,
    # and the half it missed is refused in production.
    "waf_surface",
    # Failed logins.  A password spray is spread thin across many addresses on
    # purpose, so asking one node halves the signal and can put it under the
    # threshold, which is the difference between reporting an attack and not.
    # Takes a site name, some paths and a timestamp; returns counts per
    # address and never a username, because the access log has none.
    "login_failures",
    # Rotation runs on a schedule from the active node, for the whole fleet,
    # because a standby filling its disk is a standby that cannot be failed
    # over to, which is found out at the worst moment.
    "waf_log_rotate",
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
        # This has to be a status, not a two hundred with ok=false in the body.
        #
        # Calling the agent on this node raises.  Calling it on a peer used to
        # return that envelope instead, and PeerClient hands a body straight
        # back, so the caller saw no exception and carried on as though the verb
        # had worked.  The upgrade walk did exactly that: lb02 refused to start
        # a build, the walk marked it "building" anyway, and it sat there for its
        # full forty five minute timeout before reporting that the build had not
        # finished in time.  The real reason was in the agent log the whole time.
        #
        # Since the walk does standbys first, that was the path it always took
        # first, and the node you clicked from was the only one that reported a
        # refused build honestly.
        raise HTTPException(status_code=502, detail=str(exc))


@router.post("/peer/gslb")
async def peer_gslb(request: Request):
    """
    Take on the fleet's DNS zones from the active node.

    Separate from the config apply for the same reason accounts are, and the
    consequence of not having it is worse.  A full snapshot only travels when
    the rendered nginx config changes, and a DNS zone changes no nginx config
    at all: it is answered by this manager's own listener, not by nginx.  So a
    zone created on the active node reached the standby only if somebody
    happened to edit a site afterwards, and usually never.

    A standby with no zones runs no listener and answers nothing, so the fleet
    looks like it has two nameservers and has one.  That is the whole promise
    of the feature, and it was failing in the one situation it exists for.
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

    # The listener follows the zones on its own timer, so nothing is started or
    # stopped here.  Doing it inline would mean a peer request holding a socket
    # bind, and reconcile already knows how to do it safely.
    return {"ok": True, **result}


@router.post("/peer/accounts")
async def peer_accounts(request: Request):
    """
    Take on the fleet's accounts from the active node.

    Separate from the config apply on purpose.  Nothing anybody does to an
    account changes a line of nginx config, so an account change would otherwise
    wait for an unrelated site edit to carry it across.  Taking somebody's access
    away is the case that matters: it has to land on every box now, not the next
    time a site is edited.

    The rules for what is taken on, what is kept, and the refusal when a set
    arrives with no enabled admin in it, are all in `snapshot.py`.
    """
    node, payload = await authenticate(request)

    rows = payload.get("users")
    if rows is None or not isinstance(rows, list):
        raise HTTPException(status_code=400, detail="that had no account list on it")

    with session_scope() as session:
        result = snapshot_store.restore_users(session, rows)
        session.commit()

    if result.get("refused"):
        # Say so out loud rather than answering as though it worked.  A node
        # quietly keeping different accounts from the rest of the fleet is the
        # thing this whole path exists to stop.
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

    # Send the site certificates after it has settled.
    #
    # Joining brings the config across, so the new node knows a site uses a
    # certificate called something.  It does not bring the certificate itself,
    # which lives as files rather than as rows, so the next apply renders a
    # config naming a file that is not there and nginx refuses it on that node
    # alone.  The apply is correctly rolled back everywhere and stays broken
    # until somebody presses Sync now, which only helps if they know to.
    #
    # Not sent inline, because the node restarts the moment this response is
    # read, to bring up its peer listener.  Anything pushed now arrives at a
    # container that is on its way down.
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
    Copy every usable certificate to a node that has just joined.

    Retried rather than attempted once, because the node is restarting when
    this starts and there is no moment we can name in advance when it will be
    listening again.  Ten tries fifteen seconds apart covers a slow container
    start without holding anything open.

    A failure here does not undo the join.  The node is a member either way,
    and a member missing a certificate is a thing to say loudly rather than a
    reason to throw away a join that worked.
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


@router.post("/peer/settings")
async def peer_settings(request: Request):
    """
    Take the fleet wide settings from the node running a restore.

    Settings have always been node local in this system, which is fine while
    somebody sets them on the box they are looking at and never fails over.
    It is not fine after a restore: the whole point is that every node ends up
    able to do the job, and a standby with no acme email and no resolvers is a
    node that looks ready and behaves differently the moment it is promoted.

    Values arrive in the clear, as they do everywhere else between peers, and
    are sealed again here with this node's own key.  The channel is mutual TLS
    between two nodes holding certificates from the same private CA.
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
