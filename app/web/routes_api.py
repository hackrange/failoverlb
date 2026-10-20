"""
The JSON API.

Every route works out who is asking from the session cookie, checks CSRF for
anything that writes, and fetches objects only through ObjectGuard, which does
the permission check.  No route queries a table by id directly, so none can
forget the check (this is what keeps BOLA/IDOR bugs out).
"""

import asyncio
import base64
import difflib
import ipaddress
import re as _re
import json
import logging
import time
import re
import socket

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session as DBSession

from app.auth.service import can, current_user
from app.catalog import CATEGORIES, all_features, plus_only_features, validate_value
from app.catalog.registry import get_feature
from app.config import get_settings
from app.core import audit, certs, error_pages, hostnames, settings_store
from app.core import repair as config_repair
from app.core.acme import AcmeError, get_cert_manager, pick_issuing_node, resolve_domain
from sqlalchemy.exc import OperationalError

from app.core.agent_client import AgentError, get_agent
from app.core.capabilities import fleet_capabilities, get_local_capabilities
from app.core.cluster import ClusterError, PeerClient, RoleNotSettled, get_cluster
from app.core.crypto import encrypt, new_token
from app.core.nginx_parser import ParseError, extract_settings, parse, quick_check
from app.core.render import OFFLOAD_ONLY_FORCES, Renderer, safe_name, safe_var
from app.core.snapshot import capture as snapshot_capture
from app.db import get_db, session_scope
from app.models import (
    AccessList,
    CacheZone,
    Certificate,
    CertificateAuthority,
    ConfigVersion,
    ConnLimitZone,
    ErrorPageImage,
    ErrorPageTemplate,
    GslbAnswer,
    GslbRecord,
    GslbZone,
    HealthEvent,
    Location,
    MapBlock,
    MemberState,
    Node,
    NodeRole,
    NodeState,
    Pool,
    PoolMember,
    RateLimitZone,
    StreamServer,
    User,
    VirtualHost,
    WafExclusion,
    WafProfile,
    LoginWatch,
    WafSession,
    WafSurfaceEntry,
    json_set,
    utcnow,
)
from app.web.security import (
    ObjectGuard,
    SESSION_COOKIE,
    check_csrf,
    client_ip,
    pick_fields,
    sandboxed_html_headers,
    validate_cidr,
    validate_hostname,
    validate_name,
    validate_port,
)

log = logging.getLogger("nfm.api")

router = APIRouter()


# ==============================================================================
# Who is asking
# ==============================================================================

def get_user(request: Request, db: DBSession = Depends(get_db)) -> User:
    token = request.cookies.get(SESSION_COOKIE)
    user = current_user(db, token, client_ip(request))
    if not user:
        raise HTTPException(status_code=401, detail="not signed in")
    db.commit()
    return user


def guard(request: Request, db: DBSession = Depends(get_db)) -> ObjectGuard:
    user = get_user(request, db)
    return ObjectGuard(db, user)


async def changing(request: Request, db: DBSession = Depends(get_db)) -> ObjectGuard:
    """For anything that writes.  Same as guard, plus the CSRF check."""
    await check_csrf(request)
    user = get_user(request, db)
    return ObjectGuard(db, user)


# ==============================================================================
# Names have to stay unique
# ==============================================================================

def _name_peers(model):
    """
    The tables a name must be unique across.

    nginx has one namespace for shared memory zones in the http block, so rate
    limit, connection limit and cache zones cannot share a name.  A clash makes
    nginx refuse the config on every node.
    """
    zones = (RateLimitZone, ConnLimitZone, CacheZone)
    return zones if model in zones else (model,)


def claim_name(session, model, name, what, exclude_id=None):
    """
    Refuse a name something else is already using (create and rename).

    A pool renamed onto a taken name is silent: the render keys files by name,
    so one upstream overwrites the other and sites quietly route to the wrong
    backends.

    We compare rendered names, since that is what collides.  Pools are also
    checked on the sticky-session variable form, which folds dots and dashes,
    so `shop-eu` and `shop_eu` would share `$sticky_shop_eu`.
    """
    wanted = safe_name(name)
    wanted_var = safe_var(name) if model is Pool else None

    for peer in _name_peers(model):
        for other in session.query(peer).all():
            # Skip the row being renamed.  Ids only match within one table.
            if exclude_id is not None and peer is model and other.id == exclude_id:
                continue
            if safe_name(other.name) == wanted:
                raise HTTPException(
                    status_code=409,
                    detail=f"there is already a {what} called {other.name}",
                )
            if wanted_var is not None and safe_var(other.name) == wanted_var:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{name} is too close to the pool called {other.name}.  "
                        f"Sticky sessions turn both of those into the same nginx "
                        f"variable, so one would quietly route on the other's cookie.  "
                        f"Pick a name that differs by more than a dot, dash or underscore."
                    ),
                )
    return name


# ==============================================================================
# Rendering and applying
# ==============================================================================

def render_current(session, ignore_health: bool = False) -> tuple:
    """
    Render everything in the database into config files.

    Returns (files, checksum, snapshot).  The snapshot is stored with the
    version so you can see what the config looked like at the time.
    """
    settings = get_settings()

    hosts = session.query(VirtualHost).all()
    pools = session.query(Pool).all()
    certs = session.query(Certificate).all()
    acls = session.query(AccessList).all()
    error_templates = session.query(ErrorPageTemplate).all()
    rate_zones = session.query(RateLimitZone).all()
    conn_zones = session.query(ConnLimitZone).all()
    cache_zones = session.query(CacheZone).all()
    maps = session.query(MapBlock).all()
    streams = session.query(StreamServer).all()
    nodes = session.query(Node).all()

    # Every node's address goes into the management allow list, so our own
    # health checks and peer traffic are never blocked by a user ACL, and new
    # nodes are covered automatically.
    node_addresses = []
    for node in nodes:
        if node.address:
            node_addresses.append(node.address)
        for entry in node.local_address_list():
            addr = entry.get("address")
            if addr and entry.get("scope") == "global":
                node_addresses.append(addr)

    # Plain dicts, not rows.  Some callers use the renderer after this
    # session closes, and touching a detached row there raises.
    waf_profiles = [
        {
            "name": p.name,
            "exclusions": [
                {"rule_id": e.rule_id, "path": e.path or "",
                 "message": e.message or ""}
                for e in p.exclusions
            ],
            # Positive model, if any.  A profile may have exclusions, a
            # surface, or both.
            "surface": [
                {"path": e.path, "methods": e.method_list()}
                for e in p.surface
            ],
        }
        for p in session.query(WafProfile).all()
    ]

    # Sessions recording the surface right now.  While one runs, full audit
    # logging is on for the tester addresses only, so the renderer has to know.
    # Read per render because it goes away when the session ends.
    waf_recording = {}
    for row in session.query(WafSession).filter(WafSession.ended_at.is_(None)).all():
        host = session.get(VirtualHost, row.host_id)
        if host and row.address_list():
            waf_recording[host.name] = row.address_list()

    renderer = Renderer(
        ignore_health=ignore_health,
        capabilities=fleet_capabilities(),
        node_addresses=sorted(set(node_addresses)),
        waf_profiles=waf_profiles,
        waf_recording=waf_recording,
        settings={
            "node_name": settings.node_name,
            # Falls back to the GUI allow list until set on the settings
            # page.  Not the same thing, but a sensible default.
            "management_networks": (
                settings_store.get("management_networks")
                or [str(n) for n in settings.admin_networks]
            ),
        },
    )

    files = renderer.render_all(
        hosts, pools, certs, acls, rate_zones, conn_zones, cache_zones, maps, streams,
        error_templates=error_templates,
    )

    # Full objects, not counts, so a standby promoted later can restore the
    # config from this.
    snapshot = snapshot_capture(session)
    snapshot["counts"] = {
        "hosts": len(hosts),
        "pools": len(pools),
        "certs": len(certs),
        "streams": len(streams),
    }

    return files, renderer.checksum(), snapshot


async def apply_current_config(author: str = "system", summary: str = "",
                               force: bool = False) -> dict:
    """
    Render everything and push it to the fleet.

    The single path used by both the health checker and API saves, so the two
    phase apply and queueing behave the same either way.
    """
    with session_scope() as session:
        files, checksum, snapshot = render_current(session)
        # Same render with health ignored, for the "saved but not live"
        # banner to compare against.
        _f, user_checksum, _s = render_current(session, ignore_health=True)

    return await get_cluster().apply_config(
        force=force,
        user_checksum=user_checksum,
        rendered=files,
        checksum=checksum,
        summary=summary,
        author=author,
        snapshot=snapshot,
    )


# ==============================================================================
# Status
# ==============================================================================

@router.get("/status")
async def status(request: Request, db: DBSession = Depends(get_db)):
    user = get_user(request, db)
    settings = get_settings()
    cluster = get_cluster()
    caps = get_local_capabilities()

    nodes = db.query(Node).all()
    pools = db.query(Pool).all()
    certs = db.query(Certificate).all()

    me = next((n for n in nodes if n.name == settings.node_name), None)

    return {
        "node": {
            "name": settings.node_name,
            "role": me.role.value if me else "unknown",
            "is_active": bool(me and me.role.value == "active"),
            "applied_version": me.applied_version if me else 0,
            "nginx_active": me.nginx_active if me else False,
            "public_ip": me.public_ip if me else None,
        },
        "nginx": caps.summary(),
        "cluster": {
            "total": len(nodes),
            "online": sum(1 for n in nodes if n.state.value == "online" or n.is_self),
            "pending": cluster.pending_summary(db),
        },
        "pools": {
            "total": len(pools),
            "degraded": sum(1 for p in pools if p.status_summary in ("degraded", "down")),
        },
        "certs": {
            "total": len(certs),
            "expiring": sum(1 for c in certs if c.status in ("expiring", "critical")),
            "expired": sum(1 for c in certs if c.status == "expired"),
        },
        "user": {"username": user.username, "role": user.role.value},
        "allowlist_set": bool(settings.admin_networks),
        "config": _pending_config(db),
    }


def _pending_config(session) -> dict:
    """
    Is there saved config that nginx has not been given yet.

    Saving and applying are separate so related changes can go out together.
    We work this out by rendering now and comparing to the last applied
    version, rather than keeping a flag that could drift.
    """
    try:
        _files, _checksum, _snapshot = render_current(session, ignore_health=True)
        checksum = _checksum
    except Exception as exc:
        # The apply will report a broken render properly.  Don't fail the
        # status endpoint over it.
        log.warning("could not work out whether config is pending: %s", exc)
        return {"dirty": False, "error": str(exc)[:200]}

    latest = session.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()

    # Rows from before user_checksum existed: treat as nothing pending, since
    # the next apply fills it in and a banner nobody can clear is worse.
    known = latest.user_checksum if latest else None
    return {
        "dirty": bool(latest is None or (known is not None and known != checksum)),
        "applied_version": latest.version if latest else 0,
        "never_applied": latest is None,
    }


@router.get("/config/pending")
async def pending_config_diff(g: ObjectGuard = Depends(guard)):
    """
    Show what applying would change, line by line.

    Diffed against the files the last applied version actually shipped, not a
    re-render of it.
    """
    files, _checksum, _snapshot = render_current(g.session)
    latest = g.session.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()
    previous = json.loads(latest.rendered or "{}") if latest else {}

    changes = []
    for path in sorted(set(previous) | set(files)):
        before = previous.get(path)
        after = files.get(path)
        if before == after:
            continue

        if before is None:
            kind = "added"
        elif after is None:
            kind = "removed"
        else:
            kind = "changed"

        diff = list(difflib.unified_diff(
            (before or "").splitlines(),
            (after or "").splitlines(),
            fromfile=f"applied/{path}",
            tofile=f"pending/{path}",
            lineterm="",
            n=2,
        ))
        # New files would diff as one huge addition, so just show the start.
        changes.append({
            "path": path,
            "kind": kind,
            "diff": diff[:120],
            "truncated": len(diff) > 120,
        })

    return {
        "applied_version": latest.version if latest else 0,
        "never_applied": latest is None,
        "changed_files": len(changes),
        "changes": changes,
    }


# ==============================================================================
# The feature catalog, which is also where the help text comes from
# ==============================================================================

# Settings whose choices are database rows rather than catalog options.  The
# catalog is static, so these features have `options=[]` and are filled in at
# request time.
#
# Both the catalog endpoint and the validator read this dict.  They used to
# disagree, so the editor offered zones the save then refused with an empty
# "has to be one of:".  Any select with no options must be listed here.
ZONE_CHOICES = {
    "limit_req_zone_name": (RateLimitZone, "rate limit zone", "Rate limits"),
    "limit_conn_zone_name": (ConnLimitZone, "connection limit zone", "Rate limits"),
    "proxy_cache_zone": (CacheZone, "cache zone", "Cache zones"),
}


@router.get("/catalog")
async def catalog(request: Request, context: str = "server",
                  db: DBSession = Depends(get_db)):
    """
    Every setting available in this context on this box.

    The forms and the ? help popups both come from this, so they cannot
    disagree.
    """
    get_user(request, db)
    # Fleet-wide capabilities, not this node's.  Offering something only some
    # nodes support gives a change that will not apply.
    caps = fleet_capabilities()
    version = caps.version_tuple

    # Zone pickers are filled from the database.  Keys come from ZONE_CHOICES,
    # which the validator also uses; only the label differs per zone type.
    _blank = {"limit_req_zone_name": "no rate limit",
              "limit_conn_zone_name": "no connection limit",
              "proxy_cache_zone": "no caching"}
    _describe = {
        "limit_req_zone_name": lambda z: f"{z.name} ({z.rate})",
        "limit_conn_zone_name": lambda z: z.name,
        "proxy_cache_zone": lambda z: f"{z.name} ({z.max_size} max)",
    }
    zone_options = {}
    for _key, (_model, _what, _page) in ZONE_CHOICES.items():
        _rows = db.query(_model).order_by(_model.name).all()
        zone_options[_key] = (
            [("", _blank.get(_key, f"no {_what}"))] +
            [(z.name, _describe[_key](z)) for z in _rows]
        )

    out = []
    for feature in all_features().values():
        if feature.edition != "oss":
            continue
        if context not in feature.contexts:
            continue
        # Has its own card elsewhere, so keep it out of the advanced list.
        if feature.own_screen:
            continue

        options = zone_options.get(feature.key, feature.options)

        out.append({
            "key": feature.key,
            "label": feature.label,
            "category": feature.category,
            "type": feature.type,
            "default": feature.default,
            "options": options,
            "unit": feature.unit,
            "placeholder": feature.placeholder,
            "advanced": feature.advanced,
            # Forced by SSL offload only mode, so the form can gray it out.
            # Read from the renderer's own list so the two cannot drift.
            "offload_forced": feature.key in OFFLOAD_ONLY_FORCES,
            "confirm": feature.confirm,
            "depends_on": feature.depends_on,
            "directive": feature.directive,
            "available": feature.is_available(caps.modules, version),
            "unavailable_reason": feature.unavailable_reason(caps.modules, version),
            "module": feature.module,
            "min_version": (
                ".".join(str(p) for p in feature.min_version)
                if feature.min_version else None
            ),
            "help": {
                "summary": feature.help.summary,
                "detail": feature.help.detail,
                "use_cases": feature.help.use_cases,
                "example": feature.help.example,
                "example_config": feature.help.example_config,
                "docs_url": feature.help.docs_url,
                "warning": feature.help.warning,
            },
        })

    return {
        "categories": [
            {"key": k, "label": label, "description": desc}
            for k, label, desc in CATEGORIES
        ],
        "features": out,
    }


# ==============================================================================
# The country database
# ==============================================================================

@router.get("/geoip")
async def geoip_state(request: Request, db: DBSession = Depends(get_db)):
    """
    The fleet's country database state, plus the country list, in one call so
    the page never renders half a picker.
    """
    get_user(request, db)

    from app.core import geoip
    from app.core.countries import COUNTRIES

    state = await geoip.fleet_status()
    state["countries"] = [{"code": code, "name": name}
                          for code, name in sorted(COUNTRIES.items(),
                                                   key=lambda kv: kv[1])]
    return state


@router.post("/geoip/install")
async def geoip_install(request: Request, g: ObjectGuard = Depends(changing)):
    """Download the database and install it on every node now."""
    g.require("manage_settings")

    from app.core import geoip

    try:
        result = await geoip.install_on_fleet()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit.record("geoip.install", user=g.user, object_type="setting",
                 object_name="country database",
                 result="success" if result.get("ok") else "failed",
                 detail=f"from {result.get('source')}, "
                        f"onto {', '.join(result.get('installed') or []) or 'nothing'}")
    if not result.get("ok"):
        raise HTTPException(
            status_code=502,
            detail="; ".join(f"{node}: {why}"
                             for node, why in (result.get("failed") or {}).items()))
    return result


# ==============================================================================
# The WAF rule set
# ==============================================================================

@router.get("/waf/rules")
async def waf_rules_state(request: Request, db: DBSession = Depends(get_db)):
    """What rule set each node has, and whether they agree."""
    get_user(request, db)

    from app.core import waf_rules

    return await waf_rules.fleet_status()


@router.post("/waf/rules/install")
async def waf_rules_install(request: Request, g: ObjectGuard = Depends(changing)):
    """Download the rule set and install it on every node now."""
    g.require("manage_settings")

    from app.core import waf_rules

    try:
        result = await waf_rules.install_on_fleet()
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    versions = result.get("versions") or {}
    audit.record("waf.rules.install", user=g.user, object_type="setting",
                 object_name="WAF rule set",
                 result="success" if result.get("ok") else "failed",
                 detail=f"{result.get('track')} track, "
                        f"onto {', '.join(result.get('installed') or []) or 'nothing'}"
                        + (f", version {sorted(set(versions.values()))[0]}"
                           if len(set(versions.values())) == 1 and versions else ""))
    if not result.get("ok"):
        raise HTTPException(
            status_code=502,
            detail="; ".join(f"{node}: {why}"
                             for node, why in (result.get("failed") or {}).items()))
    return result


# ==============================================================================
# Learning sessions, hits and profiles
# ==============================================================================

def _session_json(s):
    return {
        "id": s.id, "host_id": s.host_id,
        "addresses": s.address_list(),
        "previous_mode": s.previous_mode,
        "started_at": s.started_at.isoformat() if s.started_at else None,
        "started_by": s.started_by,
        "ended_at": s.ended_at.isoformat() if s.ended_at else None,
        "running": s.running,
        "note": s.note,
    }


def _profile_json(p, used_by=None):
    return {
        "id": p.id, "name": p.name, "description": p.description or "",
        "learned_from_site": p.learned_from_site,
        "learned_from_addresses": p.address_list(),
        "learned_at": p.learned_at.isoformat() if p.learned_at else None,
        "exclusions": [
            {"id": e.id, "rule_id": e.rule_id, "path": e.path or "",
             "message": e.message or "", "learned_from_ip": e.learned_from_ip,
             "sample_uri": e.sample_uri, "hits": e.hits,
             "created_at": e.created_at.isoformat() if e.created_at else None,
             "created_by": e.created_by}
            for e in p.exclusions
        ],
        "surface": [
            {"id": e.id, "path": e.path, "methods": e.method_list(),
             "sample_uri": e.sample_uri, "learned_from_ip": e.learned_from_ip,
             "hits": e.hits,
             "created_at": e.created_at.isoformat() if e.created_at else None,
             "created_by": e.created_by}
            for e in p.surface
        ],
        "used_by": used_by if used_by is not None else [],
    }


def _profile_users(session, name):
    """Which sites are pointed at this profile, by name."""
    return sorted(h.name for h in session.query(VirtualHost).all()
                  if (h.setting_map().get("waf_paranoia") or "") == f"custom:{name}")


@router.get("/waf/sessions/{host_id}")
async def waf_session_state(host_id: int, g: ObjectGuard = Depends(guard)):
    """The learning sessions for one site, newest first."""
    # Through the guard, so it answers 404 rather than 403 and an id cannot be
    # probed for existence.
    g.get(VirtualHost, host_id)
    db = g.session

    rows = (db.query(WafSession).filter(WafSession.host_id == host_id)
            .order_by(WafSession.started_at.desc()).limit(20).all())
    return {"sessions": [_session_json(s) for s in rows],
            "running": next((_session_json(s) for s in rows if s.running), None)}


@router.post("/waf/sessions/{host_id}/start")
async def waf_session_start(host_id: int, request: Request,
                            g: ObjectGuard = Depends(changing)):
    """
    Start a learning session with the given tester addresses.

    Never lowers protection.  ModSecurity logs every rule that fires regardless
    of the blocking threshold, so a blocking site keeps blocking.  Only a site
    with the firewall off is changed, and only up to watching.
    """
    from app.core.waf_hits import parse_addresses

    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)

    # Needs the WAF module on the fleet.  Setting waf_mode directly already
    # checks this, but this path writes waf_mode itself, and used to store
    # "watching" on a fleet that could not watch: nothing got collected, and
    # the site would silently start watching if the module was added later.
    feature = get_feature("waf_mode")
    caps = fleet_capabilities()
    if feature and not feature.is_available(caps.modules, caps.version_tuple):
        raise HTTPException(
            status_code=400,
            detail="a learning session needs the modsecurity module, which is "
                   "not compiled into every node's nginx.  Build it from the "
                   "NGINX Build page first, or the session would collect "
                   "nothing.")

    payload = await request.json() if await request.body() else {}
    networks, bad = parse_addresses(payload.get("addresses"))
    if bad:
        raise HTTPException(
            status_code=400,
            detail=f"could not read these as addresses: {', '.join(bad)}")
    if not networks:
        raise HTTPException(
            status_code=400,
            detail="name at least one tester address.  Without one, every hit "
                   "during the session looks equally trustworthy, including "
                   "anybody scanning the site while it runs.")

    running = (g.session.query(WafSession)
               .filter(WafSession.host_id == host_id,
                       WafSession.ended_at.is_(None)).first())
    if running:
        raise HTTPException(status_code=400,
                            detail="a session is already running on this site")

    cfg = host.setting_map()
    was = (cfg.get("waf_mode") or "off").strip()

    # Off is the only mode that changes, and it goes up rather than down.
    if was in ("", "off"):
        cfg["waf_mode"] = "watching"
        host.settings = json_set(cfg)

    row = WafSession(host_id=host_id,
                     addresses=json_set([str(n) for n in networks]),
                     previous_mode=was, started_by=g.user.username,
                     note=(payload.get("note") or "").strip()[:500] or None)
    g.session.add(row)
    g.session.commit()

    audit.record("waf.session.start", user=g.user, object_type="host",
                 object_name=host.name,
                 changes={"addresses": [str(n) for n in networks],
                          "mode_was": was, "mode_now": cfg.get("waf_mode")})
    return {"session": _session_json(row),
            "mode_changed": was in ("", "off"),
            "mode": cfg.get("waf_mode")}


@router.post("/waf/sessions/{session_id}/stop")
async def waf_session_stop(session_id: int, request: Request,
                           g: ObjectGuard = Depends(changing)):
    """
    Stop a session and return what it found.

    Does not save anything.  A person should review the results before they
    become policy, in case someone other than the testers passed through.
    """
    from app.core import waf_hits as hits_mod

    g.require("edit_sites")
    row = g.get(WafSession, session_id)
    if not row.running:
        raise HTTPException(status_code=400, detail="that session has already stopped")

    host = g.get(VirtualHost, row.host_id)
    since = row.started_at.timestamp() if row.started_at else None

    row.ended_at = utcnow()
    row.ended_by = g.user.username

    # Put the site back to its old mode if starting changed it.
    restored = None
    if (row.previous_mode or "off") in ("", "off"):
        cfg = host.setting_map()
        if (cfg.get("waf_mode") or "") == "watching":
            cfg["waf_mode"] = "off"
            host.settings = json_set(cfg)
            restored = "off"

    site_name = host.name
    g.session.commit()

    found = await hits_mod.fleet_hits(site_name, since=since)
    networks, _bad = hits_mod.parse_addresses(row.address_list())
    split = hits_mod.split_by_tester(found["groups"], networks)

    audit.record("waf.session.stop", user=g.user, object_type="host",
                 object_name=site_name,
                 detail=f"{len(split['candidates'])} candidates, "
                        f"{len(split['mixed'])} mixed, {len(split['others'])} other")

    return {"session": _session_json(row), "restored_mode": restored,
            "transactions": found["transactions"], "partial": found["partial"],
            "nodes": found["nodes"], **split}


@router.get("/waf/hits/{host_id}")
async def waf_hits_for_host(host_id: int, addresses: str = "",
                            since: float = None, until: float = None,
                            g: ObjectGuard = Depends(guard)):
    """
    What fired for one site, split into tester traffic and everything else.

    `until` lets a stopped session still be read.
    """
    from app.core import waf_hits as hits_mod

    host = g.get(VirtualHost, host_id)
    found = await hits_mod.fleet_hits(host.name, since=since, until=until)
    networks, bad = hits_mod.parse_addresses(addresses)
    split = hits_mod.split_by_tester(found["groups"], networks)

    return {"site": host.name, "transactions": found["transactions"],
            "partial": found["partial"], "nodes": found["nodes"],
            "unreadable_addresses": bad, **split}


@router.get("/login-watch/{host_id}")
async def login_watch_get(host_id: int, g: ObjectGuard = Depends(guard)):
    """The login watch settings for one site, and what they would find now."""
    host = g.get(VirtualHost, host_id)
    watch = g.session.query(LoginWatch).filter(
        LoginWatch.host_id == host_id).first()
    return {"site": host.name, "watch": _login_watch_json(watch)}


def _login_watch_json(watch):
    if watch is None:
        # Defaults so the form can draw before anything is saved.  401 and
        # 403 rather than 200: treating 200 as failure would flag every
        # successful form login as an attack.
        return {"configured": False, "enabled": False, "paths": [],
                "methods": ["POST"], "fail_statuses": [401, 403],
                "window_seconds": 300, "brute_threshold": 10,
                "spray_min_addresses": 12, "spray_min_failures": 20,
                "spray_max_per_address": 3, "slow_window_seconds": 21600,
                "slow_min_addresses": 25, "slow_min_failures": 60}
    return {
        "configured": True,
        "enabled": bool(watch.enabled),
        "paths": watch.path_list(),
        "methods": watch.method_list(),
        "fail_statuses": watch.fail_status_list(),
        "window_seconds": watch.window_seconds,
        "brute_threshold": watch.brute_threshold,
        "spray_min_addresses": watch.spray_min_addresses,
        "spray_min_failures": watch.spray_min_failures,
        "spray_max_per_address": watch.spray_max_per_address,
        "slow_window_seconds": watch.slow_window_seconds,
        "slow_min_addresses": watch.slow_min_addresses,
        "slow_min_failures": watch.slow_min_failures,
    }


@router.put("/login-watch/{host_id}")
async def login_watch_save(host_id: int, request: Request,
                           g: ObjectGuard = Depends(changing)):
    """
    Save what counts as a login on this site, and what counts as too many.

    Paths are validated like exclusion paths even though they only end up in
    a comparison, not in config.
    """
    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)
    payload = await request.json() if await request.body() else {}

    paths = [str(p).strip() for p in (payload.get("paths") or []) if str(p).strip()]
    for path in paths:
        problem = _waf_path_problem(path)
        if problem:
            raise HTTPException(status_code=400, detail=f"{path}: {problem}")

    enabled = bool(payload.get("enabled"))
    if enabled and not paths:
        raise HTTPException(
            status_code=400,
            detail="give it at least one login path, or it has nothing to "
                   "watch and would report nothing forever while looking on")

    methods = sorted({str(m).strip().upper() for m in (payload.get("methods") or ["POST"])
                      if re.fullmatch(r"[A-Za-z]{3,10}", str(m).strip())})
    if not methods:
        raise HTTPException(status_code=400, detail="give it at least one method")

    statuses = sorted({int(s) for s in (payload.get("fail_statuses") or [])
                       if str(s).isdigit() and 100 <= int(s) <= 599})
    if not statuses:
        raise HTTPException(
            status_code=400,
            detail="say which status codes mean a failed login on this "
                   "application.  There is no universal answer: a form that "
                   "re-renders with an error answers 200, an API answers 401")

    def number(key, low, high, fallback):
        try:
            value = int(payload.get(key, fallback))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail=f"{key} has to be a number")
        if not low <= value <= high:
            raise HTTPException(status_code=400,
                                detail=f"{key} has to be between {low} and {high}")
        return value

    watch = g.session.query(LoginWatch).filter(
        LoginWatch.host_id == host.id).first()
    if watch is None:
        watch = LoginWatch(host_id=host.id)
        g.session.add(watch)

    watch.enabled = enabled
    watch.paths = json_set(paths)
    watch.methods = json_set(methods)
    watch.fail_statuses = json_set(statuses)
    watch.window_seconds = number("window_seconds", 60, 3600, 300)
    watch.brute_threshold = number("brute_threshold", 3, 1000, 10)
    watch.spray_min_addresses = number("spray_min_addresses", 3, 10000, 12)
    watch.spray_min_failures = number("spray_min_failures", 3, 100000, 20)
    watch.spray_max_per_address = number("spray_max_per_address", 1, 100, 3)
    watch.slow_window_seconds = number("slow_window_seconds", 600, 604800, 21600)
    watch.slow_min_addresses = number("slow_min_addresses", 3, 10000, 25)
    watch.slow_min_failures = number("slow_min_failures", 3, 100000, 60)
    watch.updated_by = g.user.username
    g.session.commit()

    audit.record("login_watch.save", user=g.user, object_type="host",
                 object_name=host.name,
                 detail=f"{'on' if enabled else 'off'}, {len(paths)} paths")
    return {"site": host.name, "watch": _login_watch_json(watch)}


@router.get("/login-watch/{host_id}/findings")
async def login_watch_findings(host_id: int, g: ObjectGuard = Depends(guard)):
    """
    Current findings over both windows.

    The short window catches bursts; the long one catches the same attack run
    slowly to stay under five minute detectors.
    """
    import time as _time

    from app.core import login_watch as watch_mod

    host = g.get(VirtualHost, host_id)
    watch = g.session.query(LoginWatch).filter(
        LoginWatch.host_id == host_id).first()
    if watch is None or not watch.path_list():
        return {"site": host.name, "configured": False, "windows": []}

    now = _time.time()
    out = []
    for slow, seconds in ((False, watch.window_seconds),
                          (True, watch.slow_window_seconds)):
        found = await watch_mod.fleet_failures(
            host.name, watch.path_list(), watch.method_list(),
            watch.fail_status_list(), since=now - seconds)
        verdict = watch_mod.judge(found["addresses"], found["failures"],
                                  watch, seconds, slow=slow)
        out.append({
            "slow": slow,
            "window_seconds": seconds,
            "failures": found["failures"],
            "successes": found["successes"],
            "addresses": found["addresses"][:100],
            "addresses_seen": len(found["addresses"]),
            "partial": found["partial"],
            "nodes": found["nodes"],
            "findings": verdict["findings"],
        })

    return {"site": host.name, "configured": True,
            "enabled": bool(watch.enabled), "windows": out}


@router.get("/waf/surface/{host_id}")
async def waf_surface_for_host(host_id: int, addresses: str = "",
                               since: float = None, until: float = None,
                               g: ObjectGuard = Depends(guard)):
    """
    The application's surface for a site, split by who produced it.

    Same window arguments and split as the hits endpoint.  The split matters
    more here: a surface entry learned from a stranger permanently allows a
    path they found, which is what a positive model is meant to prevent.
    """
    from app.core import waf_hits as hits_mod

    host = g.get(VirtualHost, host_id)
    found = await hits_mod.fleet_surface(host.name, since=since, until=until)
    networks, bad = hits_mod.parse_addresses(addresses)
    split = hits_mod.split_surface_by_tester(found["entries"], networks)

    return {"site": host.name, "transactions": found["transactions"],
            "partial": found["partial"], "nodes": found["nodes"],
            "unreadable_addresses": bad, **split}


@router.post("/waf/profiles/{profile_id}/surface")
async def waf_surface_save(profile_id: int, request: Request,
                           g: ObjectGuard = Depends(changing)):
    """
    Merge a reviewed surface into a profile.

    Merged, not replaced, since walks are often done over several sittings.
    Removing a path is a separate action on the profiles page.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)
    payload = await request.json() if await request.body() else {}

    entries = payload.get("entries") or []
    if not entries:
        raise HTTPException(status_code=400,
                            detail="tick at least one path to put in it")

    have = {e.path: e for e in profile.surface}
    added = updated = 0

    for item in entries:
        path = (item.get("path") or "").strip()
        problem = _waf_path_problem(path)
        if problem or not path:
            raise HTTPException(status_code=400,
                                detail=problem or "a surface entry needs a path")

        methods = sorted({str(m).strip().upper() for m in (item.get("methods") or [])
                          if re.fullmatch(r"[A-Za-z]{3,10}", str(m).strip())})
        if not methods:
            raise HTTPException(
                status_code=400,
                detail=f"{path} has no methods on it, and a path that allows "
                       f"every method is a decision to make on purpose rather "
                       f"than by leaving a box empty")

        existing = have.get(path)
        if existing:
            # Methods only accumulate.  A later GET-only walk must not drop
            # a POST proven earlier.
            merged = sorted(set(existing.method_list()) | set(methods))
            if merged != existing.method_list():
                existing.methods = json_set(merged)
                updated += 1
            continue

        g.session.add(WafSurfaceEntry(
            profile_id=profile.id, path=path, methods=json_set(methods),
            sample_uri=(item.get("sample_uri") or "")[:500] or None,
            learned_from_ip=(item.get("learned_from_ip") or "")[:64] or None,
            hits=int(item.get("hits") or 0),
            created_by=g.user.username))
        added += 1

    g.session.commit()
    audit.record("waf.surface.save", user=g.user, object_type="waf_profile",
                 object_name=profile.name,
                 detail=f"{added} paths added, {updated} widened")
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.patch("/waf/profiles/{profile_id}/surface/{entry_id}")
async def waf_surface_edit(profile_id: int, entry_id: int, request: Request,
                           g: ObjectGuard = Depends(changing)):
    """
    Change a surface path or the methods it answers.

    Learning produces one row per object seen; editing lets you generalize to
    the pattern.  Without that, objects created after the walk are refused.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)
    payload = await request.json() if await request.body() else {}

    entry = next((e for e in profile.surface if e.id == entry_id), None)
    if entry is None:
        raise HTTPException(status_code=404,
                            detail="that path is not in this profile")

    if "path" in payload:
        path = (payload.get("path") or "").strip()
        problem = _waf_path_problem(path)
        if problem or not path:
            raise HTTPException(status_code=400,
                                detail=problem or "a surface entry needs a path")
        if any(e.id != entry.id and e.path == path for e in profile.surface):
            raise HTTPException(status_code=400,
                                detail=f"{path} is already in this profile")
        entry.path = path

    if "methods" in payload:
        methods = sorted({str(m).strip().upper() for m in (payload.get("methods") or [])
                          if re.fullmatch(r"[A-Za-z]{3,10}", str(m).strip())})
        if not methods:
            raise HTTPException(
                status_code=400,
                detail="a path needs at least one method, because a path that "
                       "allows every method is most of the protection gone")
        entry.methods = json_set(methods)

    g.session.commit()
    audit.record("waf.surface.edit", user=g.user, object_type="waf_profile",
                 object_name=profile.name,
                 detail=f"{entry.path}: {', '.join(entry.method_list())}")
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.delete("/waf/profiles/{profile_id}/surface/{entry_id}")
async def waf_surface_delete(profile_id: int, entry_id: int,
                             g: ObjectGuard = Depends(changing)):
    """
    Remove a path from the allowed surface.

    Refused while the profile is enforcing on a live site.  Unlike removing
    an exclusion (which makes the firewall check more), this starts refusing
    traffic that is being served now, as soon as the config is applied.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)

    entry = next((e for e in profile.surface if e.id == entry_id), None)
    if entry is None:
        raise HTTPException(status_code=404,
                            detail="that path is not in this profile")

    enforcing = [h.name for h in g.session.query(VirtualHost).all()
                 if (h.setting_map().get("waf_paranoia") or "") == f"custom:{profile.name}"
                 and (h.setting_map().get("waf_positive") or "") == "enforce"]
    if enforcing:
        raise HTTPException(
            status_code=400,
            detail=f"{', '.join(enforcing)} enforce this surface right now, so "
                   f"removing {entry.path} would start refusing it.  Put those "
                   f"sites into report mode first if you mean to.")

    path = entry.path
    g.session.delete(entry)
    g.session.commit()
    audit.record("waf.surface.delete", user=g.user, object_type="waf_profile",
                 object_name=profile.name, detail=f"{path} no longer allowed")
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.post("/waf/hits/{host_id}/clear")
async def waf_hits_clear(host_id: int, g: ObjectGuard = Depends(changing)):
    """
    Discard the learned evidence for one site, on every node.

    Exclusions already saved into a profile are left alone; removing them
    would start refusing traffic someone explicitly allowed.
    """
    from app.core import waf_hits as hits_mod

    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)
    name = host.name

    result = await hits_mod.clear_fleet(name)
    audit.record("waf.hits.clear", user=g.user, object_type="host",
                 object_name=name,
                 result="success" if result.get("ok") else "failed",
                 detail=f"cleared {sum(result.get('cleared', {}).values())} bytes")
    if not result.get("ok"):
        raise HTTPException(status_code=502, detail="; ".join(
            f"{n}: {w}" for n, w in (result.get("failed") or {}).items()))
    return result


@router.get("/waf/logs")
async def waf_log_state(request: Request, db: DBSession = Depends(get_db)):
    """How much disk the audit logs are using, per node."""
    from app.core import waf_hits as hits_mod

    get_user(request, db)
    return await hits_mod.log_status()


@router.get("/metrics/history")
async def metrics_history(request: Request, start: int = None, end: int = None,
                          db: DBSession = Depends(get_db)):
    """
    Stored telemetry between two times, at the finest resolution covering it.

    Takes a range, not a window name, so dragging to zoom works.  The response
    includes the resolution used and the oldest bucket held, so the page can
    explain averaged values and history shorter than the requested window.
    """
    from app.core import metrics_store

    get_user(request, db)
    now = int(time.time())
    end = int(end or now)
    start = int(start or (end - 3600))

    # We keep at most a month.  Clamp rather than refuse, so a zoom gets
    # whatever there is.
    span = end - start
    if span > metrics_store.KEEP_COARSE:
        start = end - metrics_store.KEEP_COARSE

    raw = metrics_store.series(start, end)

    # Same shape the live charts read, so zoomed and live charts share one
    # drawing routine.  value is the mean; min and max ride along so spikes
    # are not lost in five minute averages.
    nodes = {}
    for node, points in (raw.get("nodes") or {}).items():
        series = {}
        for point in points:
            at = point.get("at")
            for key, stat in point.items():
                if key == "at" or not isinstance(stat, dict):
                    continue
                series.setdefault(key, []).append({
                    "at": at,
                    "value": stat.get("avg"),
                    "min": stat.get("min"),
                    "max": stat.get("max"),
                })

        # The tiles above the charts read `latest` and `rates`, not `series`.
        # Without these, every stored-history window showed "no data" tiles.
        # Values come from the last bucket in the range, and `as_of` says when
        # that was, so a zoom into the past is not shown as current.
        latest, rates, as_of = {}, {}, None
        for key, points_for_key in series.items():
            if not points_for_key:
                continue
            last = points_for_key[-1]
            (rates if key.endswith("_per_sec") else latest)[key] = last["value"]
            as_of = max(as_of or 0, last["at"] or 0)

        nodes[node] = {"series": series, "latest": latest, "rates": rates,
                       "as_of": as_of, "samples": len(points)}

    return {
        "nodes": nodes,
        "resolution": raw.get("resolution"),
        "start": raw.get("start"),
        "end": raw.get("end"),
        "earliest": raw.get("earliest"),
        "minutes": max(1, (raw.get("end", 0) - raw.get("start", 0)) // 60),
        "stored": True,
    }


@router.post("/auth/oidc/test")
async def oidc_test(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Fetch the discovery document and report what came back.

    Only proves the URL resolves, TLS is accepted, and the document has the
    OpenID endpoints.  Client id, secret, redirect registration and group
    membership are only proven by a real login.  Still catches the most
    common mistake, a typo in the discovery URL.
    """
    import httpx

    from app.auth import oidc

    g.require("manage_settings")

    values = oidc.config()
    url = values["discovery_url"]
    if not url:
        raise HTTPException(status_code=400,
                            detail="save a discovery URL first, then test it")

    try:
        # Don't follow redirects.  We echo what we fetched back to the
        # caller, so following one would let an open redirect reach a host
        # that is not allowed.  Reporting the redirect is more useful anyway.
        async with httpx.AsyncClient(timeout=15, follow_redirects=False) as client:
            response = await client.get(url)
            if response.is_redirect:
                raise HTTPException(
                    status_code=502,
                    detail=f"that address redirects to "
                           f"{response.headers.get('location', 'somewhere else')}.  "
                           f"Put the address it ends at in the box instead.")
            response.raise_for_status()
            doc = response.json()
    except Exception as exc:
        raise HTTPException(status_code=502,
                            detail=f"could not read that discovery URL: {exc}")

    missing = [k for k in ("issuer", "authorization_endpoint", "token_endpoint",
                           "jwks_uri") if not doc.get(k)]
    if missing:
        raise HTTPException(
            status_code=502,
            detail="that answered, but it is not an OpenID discovery document: "
                   f"no {', '.join(missing)}")

    return {
        "ok": True,
        "issuer": doc.get("issuer"),
        "authorization_endpoint": doc.get("authorization_endpoint"),
        "token_endpoint": doc.get("token_endpoint"),
        "userinfo_endpoint": doc.get("userinfo_endpoint"),
        "supports_pkce": "S256" in (doc.get("code_challenge_methods_supported") or []),
        "client_id_set": bool(values["client_id"]),
        "secret_set": bool(values["client_secret"]),
        "redirect_uri": (values["redirect_base"].rstrip("/") + "/auth/oidc/callback"
                         if values["redirect_base"] else ""),
    }


@router.get("/waf/rule-ids")
async def waf_rule_ids(request: Request, db: DBSession = Depends(get_db)):
    """
    Every rule id the installed rule set defines, for checking exclusions.

    Asks this node only.  The rule set should be identical everywhere, and
    the settings page already flags nodes that disagree.
    """
    from app.core.agent_client import get_agent

    get_user(request, db)
    try:
        answer = await get_agent().call("crs_rule_ids")
    except Exception as exc:
        # This catches any exception, so its text may contain paths and
        # internal state.  Log it in full and return a summary instead.
        log.exception("could not read the rule ids from the agent")
        raise HTTPException(
            status_code=502,
            detail=f"could not read the rule set from this node "
                   f"({type(exc).__name__}).  The manager log has the detail.")
    return answer


@router.get("/waf/profiles")
async def waf_profiles(request: Request, db: DBSession = Depends(get_db)):
    """Every tuned profile, and which sites use it."""
    get_user(request, db)
    return {"profiles": [_profile_json(p, _profile_users(db, p.name))
                         for p in db.query(WafProfile).order_by(WafProfile.name).all()]}


@router.post("/waf/profiles")
async def waf_profile_create(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Save a set of ticked hits as a named profile.

    Provenance (site, addresses, request, date) is kept with each exclusion.
    An exclusion nobody can explain is one nobody will dare remove.
    """
    g.require("edit_sites")
    payload = await request.json() if await request.body() else {}

    name = (payload.get("name") or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="give the profile a name")
    if g.session.query(WafProfile).filter(WafProfile.name == name).first():
        raise HTTPException(status_code=400,
                            detail=f"there is already a profile called {name}")

    entries = payload.get("exclusions") or []
    # A surface-only profile with no exclusions is a valid policy, but the
    # caller has to say so, to catch empty profiles created by accident.
    if not entries and not payload.get("allow_empty"):
        raise HTTPException(status_code=400,
                            detail="tick at least one entry to put in it")

    profile = WafProfile(
        name=name,
        description=(payload.get("description") or "").strip()[:500] or None,
        learned_from_site=(payload.get("learned_from_site") or "").strip() or None,
        learned_from_addresses=json_set(payload.get("learned_from_addresses") or []),
        learned_at=utcnow(),
        updated_by=g.user.username,
    )
    g.session.add(profile)
    g.session.flush()

    seen = set()
    for entry in entries:
        try:
            rule_id = int(entry.get("rule_id"))
        except (TypeError, ValueError):
            continue
        path = (entry.get("path") or "").strip()
        if (rule_id, path) in seen:
            continue
        seen.add((rule_id, path))
        g.session.add(WafExclusion(
            profile_id=profile.id, rule_id=rule_id, path=path or None,
            message=(entry.get("message") or "")[:300] or None,
            learned_from_ip=(entry.get("learned_from_ip") or "")[:64] or None,
            sample_uri=(entry.get("sample_uri") or "")[:500] or None,
            hits=int(entry.get("hits") or 0),
            created_by=g.user.username,
        ))

    g.session.commit()
    audit.record("waf.profile.create", user=g.user, object_type="waf_profile",
                 object_name=name, detail=f"{len(seen)} exclusions")
    return _profile_json(profile, [])


@router.delete("/waf/profiles/{profile_id}")
async def waf_profile_delete(profile_id: int, g: ObjectGuard = Depends(changing)):
    """
    Delete a profile, unless a site is using it.

    A site whose profile vanished would fall back to the untuned rule set and
    start refusing traffic it was tuned to allow.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)
    users = _profile_users(g.session, profile.name)
    if users:
        raise HTTPException(
            status_code=400,
            detail=f"{', '.join(users)} still use this profile.  Point them at "
                   f"something else first.")

    name = profile.name
    g.session.delete(profile)
    g.session.commit()
    audit.record("waf.profile.delete", user=g.user, object_type="waf_profile",
                 object_name=name)
    return {"ok": True, "deleted": name}


# Characters not allowed in a hand-edited exclusion path.  A quote or line
# break would end the ModSecurity directive and let someone inject rules,
# e.g. one that turns checking off.  These do not go through the catalog's
# own breakout check, so we check here.
_WAF_PATH_BAD = re.compile(r'["\'\\\n\r;{}]')


def _waf_path_problem(path: str) -> str:
    """Why this exclusion path cannot be stored, or "" if it can."""
    if not path:
        return ""            # blank means the whole site, which is allowed
    if not path.startswith("/"):
        return "a path has to start with /"
    if len(path) > 500:
        return "that path is too long"
    if _WAF_PATH_BAD.search(path):
        return "a path cannot contain quotes, backslashes, semicolons, braces or line breaks"
    if "***" in path:
        return "use * for one path segment or ** for any number, not three"
    return ""


@router.post("/waf/profiles/{profile_id}/exclusions")
async def waf_exclusion_add(profile_id: int, request: Request,
                            g: ObjectGuard = Depends(changing)):
    """
    Add an exclusion to a profile by hand.

    Learning only covers what was exercised, so this lets people write the
    general case (e.g. for things created later).
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)
    payload = await request.json() if await request.body() else {}

    try:
        rule_id = int(payload.get("rule_id"))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="a rule id has to be a number")

    path = (payload.get("path") or "").strip()
    problem = _waf_path_problem(path)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    if any(e.rule_id == rule_id and (e.path or "") == path
           for e in profile.exclusions):
        raise HTTPException(
            status_code=400,
            detail=f"rule {rule_id} is already excused on {path or 'the whole site'}")

    g.session.add(WafExclusion(
        profile_id=profile.id, rule_id=rule_id, path=path or None,
        message=(payload.get("message") or "added by hand")[:300],
        created_by=g.user.username))
    g.session.commit()

    audit.record("waf.exclusion.add", user=g.user, object_type="waf_profile",
                 object_name=profile.name,
                 detail=f"rule {rule_id} on {path or 'the whole site'}")
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.patch("/waf/profiles/{profile_id}/exclusions/{exclusion_id}")
async def waf_exclusion_edit(profile_id: int, exclusion_id: int, request: Request,
                             g: ObjectGuard = Depends(changing)):
    """
    Change the path an exclusion covers.

    Learning on a per-object site (e.g. a git server) gives one row per object,
    such as `/team/apache2.git/git-upload-pack`.  Editing it to
    `/team/*.git/*` collapses those into one rule that also covers future
    objects.

    The star is stored as typed; the renderer turns it into a regex, so people
    never have to maintain `^/team/[^/]*\\.git/` by hand.  The evidence fields
    are not editable, since they are the record of why the rule exists.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)
    payload = await request.json() if await request.body() else {}

    entry = next((e for e in profile.exclusions if e.id == exclusion_id), None)
    if entry is None:
        raise HTTPException(status_code=404,
                            detail="that exclusion is not in this profile")

    path = (payload.get("path") or "").strip()
    problem = _waf_path_problem(path)
    if problem:
        raise HTTPException(status_code=400, detail=problem)

    if any(e.id != entry.id and e.rule_id == entry.rule_id
           and (e.path or "") == path for e in profile.exclusions):
        raise HTTPException(
            status_code=400,
            detail=f"rule {entry.rule_id} is already excused on "
                   f"{path or 'the whole site'} in this profile")

    was = entry.path or ""
    entry.path = path or None
    g.session.commit()

    audit.record("waf.exclusion.edit", user=g.user, object_type="waf_profile",
                 object_name=profile.name,
                 changes={"path": {"from": was or "(whole site)",
                                   "to": path or "(whole site)"},
                          "rule_id": entry.rule_id})
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.delete("/waf/profiles/{profile_id}/exclusions/{exclusion_id}")
async def waf_exclusion_delete(profile_id: int, exclusion_id: int,
                               g: ObjectGuard = Depends(changing)):
    """
    Remove one exclusion from a profile.

    Allowed even while sites use the profile.  It puts a rule back into force,
    so the worst case is the app breaking visibly, which can be undone.
    """
    g.require("edit_sites")
    profile = g.get(WafProfile, profile_id)

    entry = next((e for e in profile.exclusions if e.id == exclusion_id), None)
    if entry is None:
        raise HTTPException(status_code=404,
                            detail="that exclusion is not in this profile")

    rule_id, path = entry.rule_id, entry.path or ""
    g.session.delete(entry)
    g.session.commit()

    audit.record("waf.exclusion.delete", user=g.user, object_type="waf_profile",
                 object_name=profile.name,
                 detail=f"rule {rule_id} on {path or 'the whole site'} put back "
                        f"into force")
    return _profile_json(profile, _profile_users(g.session, profile.name))


@router.get("/catalog/plus")
async def catalog_plus(request: Request, db: DBSession = Depends(get_db)):
    """
    The NGINX Plus-only features, and what we built instead.

    Saves people from hunting for something that is not in the free version.
    """
    get_user(request, db)

    return {
        "features": [
            {
                "key": f.key,
                "label": f.label,
                "category": f.category,
                "summary": f.help.summary,
                "detail": f.help.detail,
                "oss_alternative": f.oss_alternative,
                "example_config": f.help.example_config,
                "docs_url": f.help.docs_url,
            }
            for f in plus_only_features()
        ]
    }


# ==============================================================================
# Sites
# ==============================================================================

HOST_FIELDS = {
    "name", "enabled", "server_names", "listen_http", "listen_https",
    "http_port", "https_port", "default_server", "http2", "force_https",
    "cert_id", "mode", "pool_id", "document_root", "redirect_target",
    "redirect_code", "settings", "access_list_id", "admin_only",
    "tls_offload_only",
    "error_page_template_id", "redirect_to_primary",
    "custom_config", "notes", "config_mode",
}


@router.get("/hosts")
async def list_hosts(g: ObjectGuard = Depends(guard)):
    hosts = g.list(VirtualHost)
    return {"hosts": [_host_summary(h) for h in hosts]}


@router.get("/hosts/{host_id}")
async def get_host(host_id: str, g: ObjectGuard = Depends(guard)):
    host = g.get(VirtualHost, host_id)
    return _host_detail(host)


def _seed_security_headers(host):
    """
    Write the catalog's header defaults onto a brand new site.

    For X-Frame-Options and Referrer-Policy, "don't send" is the empty string,
    which the forms cannot store, so a missing key renders as no header.  That
    means a new site's default has to be written here, or the form would show
    SAMEORIGIN while the config sent nothing.

    Create only, and only for unset keys; doing it on every save would put
    back a header someone chose to remove.  Imported sites do not come through
    here, so they keep whatever their original config did.
    """
    settings = host.setting_map()
    changed = False
    for key in ("x_frame_options", "referrer_policy"):
        if key in settings:
            continue
        feature = get_feature(key)
        if feature is None:
            continue
        settings[key] = feature.default
        changed = True
    if changed:
        host.settings = json.dumps(settings)


@router.post("/hosts")
async def create_host(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = pick_fields(await request.json(), HOST_FIELDS)

    # The name uniqueness check is in _apply_host_fields below, shared with
    # rename.
    name = validate_name(payload.get("name"), "site name")
    host = VirtualHost(name=name)
    _apply_host_fields(g, host, payload)
    _seed_security_headers(host)
    g.session.add(host)
    g.session.commit()

    audit.record("site.create", user=g.user, object_type="site", object_name=name,
                 changes=payload, source_ip=None)

    return _host_detail(host)


@router.post("/hosts/{host_id}/duplicate")
async def duplicate_host(host_id: str, request: Request,
                         g: ObjectGuard = Depends(changing)):
    """
    Copy a site, including its settings, paths and hand written config.

    Three things are deliberately not copied:

      * The certificate.  It covers the wrong names.  We copy how it was
        obtained (challenge, key type, authority, DNS credentials) and create
        and attach a certificate for the new names, but do not issue it: DNS
        and serving are usually not ready yet when a clone is made.
      * The hostnames.  They are asked for as part of the clone, since two
        server blocks with the same server_name means nginx silently serves
        whichever it parsed first.  Names already in use are refused.
      * Being enabled.  A copy starts disabled so a half edited site does not
        take traffic.
    """
    original = g.get(VirtualHost, host_id, "edit_sites")
    payload = await request.json() if await request.body() else {}

    name = validate_name(payload.get("name"), "site name")
    if g.session.query(VirtualHost).filter(VirtualHost.name == name).first():
        raise HTTPException(status_code=400,
                            detail=f"there is already a site called {name}")

    # Ask for hostnames at clone time so the copy is never live on the
    # original's hostname, even briefly.
    raw_names = payload.get("server_names")
    if isinstance(raw_names, str):
        raw_names = [n.strip() for n in raw_names.replace(",", "\n").splitlines()]
    names = [str(n).strip() for n in (raw_names or []) if str(n).strip()] or [name]

    clash = [h.name for h in g.session.query(VirtualHost).all()
             if set(h.name_list()) & set(names)]
    if clash:
        raise HTTPException(
            status_code=400,
            detail=f"{', '.join(clash)} already answers to one of those "
                   f"hostnames.  Two server blocks claiming the same name means "
                   f"nginx serves whichever it parsed first and the other looks "
                   f"broken for no visible reason.")

    copy = VirtualHost(
        name=name,
        server_names=json_set(names),
        enabled=False,
        listen_http=original.listen_http,
        listen_https=original.listen_https,
        http_port=original.http_port,
        https_port=original.https_port,
        default_server=False,      # only one site can be, and it is not this one
        http2=original.http2,
        force_https=original.force_https,
        redirect_to_primary=original.redirect_to_primary,
        mode=original.mode,
        pool_id=original.pool_id,
        document_root=original.document_root,
        redirect_target=original.redirect_target,
        redirect_code=original.redirect_code,
        settings=original.settings,
        access_list_id=original.access_list_id,
        error_page_template_id=original.error_page_template_id,
        admin_only=original.admin_only,
        tls_offload_only=original.tls_offload_only,
        custom_config=original.custom_config,
        config_mode=original.config_mode,
        notes=f"Copied from {original.name}." +
              (f"  {original.notes}" if original.notes else ""),
        updated_by=g.user.username,
    )
    g.session.add(copy)
    g.session.flush()

    # Copy the paths too; many sites keep most of their behavior there.
    for loc in original.locations:
        g.session.add(Location(
            host_id=copy.id,
            path=loc.path,
            match_type=loc.match_type,
            sort_order=loc.sort_order,
            mode=loc.mode,
            pool_id=loc.pool_id,
            document_root=loc.document_root,
            alias=loc.alias,
            redirect_target=loc.redirect_target,
            redirect_code=loc.redirect_code,
            settings=loc.settings,
            access_list_id=loc.access_list_id,
            error_page_template_id=loc.error_page_template_id,
            custom_config=loc.custom_config,
            enabled=loc.enabled,
        ))

    # A certificate for the new names, if asked for.  Created and attached but
    # not issued: issuing needs the hostname resolving here and the site
    # serving the challenge, and neither is usually true yet.  They can issue
    # it from the certificates page when ready.
    made_cert = None
    if payload.get("create_certificate"):
        source = original.cert

        # Certificate names are unique, and one may already exist (e.g. clone,
        # delete, clone again; the certificate outlives the site).  Creating
        # another used to raise a bare 500.  Reuse it if it covers these
        # names, otherwise refuse clearly.
        existing_cert = g.session.query(Certificate).filter(
            Certificate.name == names[0]).first()
        if existing_cert is not None:
            covers = set(existing_cert.domain_list() or [])
            if covers and set(names) <= covers:
                copy.cert_id = existing_cert.id
                g.session.commit()
                made_cert = {"id": existing_cert.id, "name": existing_cert.name,
                             "domains": sorted(covers), "issued": bool(existing_cert.not_after),
                             "reused": True}
                out = _host_detail(copy)
                out["certificate_created"] = made_cert
                audit.record("site.duplicate", user=g.user, object_type="site",
                             object_name=name,
                             detail=f"copied from {original.name}, attached the "
                                    f"certificate that already existed for "
                                    f"{names[0]}")
                return out
            raise HTTPException(
                status_code=409,
                detail=(f"there is already a certificate called {names[0]}, and it "
                        f"is for {', '.join(sorted(covers)) or 'nothing this site answers to'}.  "
                        f"Clone without a certificate and attach the right one, "
                        f"or rename that certificate first."))

        cert = Certificate(
            name=names[0],
            domains=json.dumps(names),
            source=source.source if source else "letsencrypt",
            challenge_type=source.challenge_type if source else "http-01",
            key_type=source.key_type if source else "ecdsa",
            auto_renew=bool(source.auto_renew) if source else True,
        )
        if source is not None:
            # Renew from the same authority as the original, so a bought
            # certificate does not silently switch issuer.
            cert.authority_id = source.authority_id
            cert.dns_plugin = source.dns_plugin
            cert.dns_credentials_encrypted = source.dns_credentials_encrypted
        g.session.add(cert)
        g.session.flush()
        copy.cert_id = cert.id
        made_cert = {"id": cert.id, "name": cert.name,
                     "domains": names, "issued": False}

    g.session.commit()

    audit.record("site.duplicate", user=g.user, object_type="site",
                 object_name=name,
                 detail=f"copied from {original.name}, "
                        f"{len(original.locations)} paths, disabled" +
                        (f", certificate {made_cert['name']} created and attached "
                         f"but not issued" if made_cert else ", no certificate"))

    out = _host_detail(copy)
    out["certificate_created"] = made_cert
    return out


async def _refuse_second_default_server(session, host, payload):
    """
    Refuse making this site the default server if it would clash.

    nginx allows one default server per address and port, and an apply is all
    or nothing, so a second one blocks every apply on the fleet.

    The clash can be another managed site, or a file outside the managed tree.
    `nginx-installer.sh` writes sites-enabled/default.conf with
    `listen 80 default_server`, which used to make every apply fail with a
    "duplicate default server" error naming a file the user never wrote.  We
    ask the node what is on disk and refuse at save time instead.
    """
    if not payload.get("default_server"):
        return
    if host is not None and host.default_server:
        return                       # already the default, nothing changing

    other = (session.query(VirtualHost)
             .filter(VirtualHost.default_server.is_(True),
                     VirtualHost.enabled.is_(True))
             .filter(VirtualHost.id != (host.id if host is not None else -1))
             .first())
    if other:
        raise HTTPException(
            status_code=409,
            detail=f"{other.name} is already the default site, and nginx allows "
                   f"only one.  Take it off {other.name} first.")

    from app.core.agent_client import get_agent

    try:
        answer = await get_agent().call("default_server_conflict")
    except Exception:
        # Don't guess if the node cannot be asked.  The apply still tests the
        # config on every node, so this just falls back to the old behavior.
        log.warning("could not ask this node about the default site")
        return

    # Only files we cannot take over count.  A sites-enabled symlink is
    # stood down at apply time and restored later, so it is fine; anything
    # else is someone's own file and we won't move it.
    blocked = answer.get("blocked")
    if blocked is None:                     # an agent from before this existed
        blocked = answer.get("files") or []
    if blocked:
        raise HTTPException(
            status_code=409,
            detail=f"this node already has a default site in "
                   f"{', '.join(blocked)}, which nginx will not allow twice.  "
                   f"That file is not managed here and is not something this "
                   f"tool will move for you.  Take default_server off it, or "
                   f"remove the file, and then set this.")


@router.put("/hosts/{host_id}")
async def update_host(host_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    host = g.get(VirtualHost, host_id, "edit_sites")
    payload = pick_fields(await request.json(), HOST_FIELDS)

    await _refuse_second_default_server(g.session, host, payload)

    before = _host_detail(host)
    _apply_host_fields(g, host, payload)
    g.session.commit()

    audit.record("site.update", user=g.user, object_type="site", object_name=host.name,
                 changes=audit.diff_fields(before, _host_detail(host)))

    return _host_detail(host)


@router.delete("/hosts/{host_id}")
async def delete_host(host_id: str, g: ObjectGuard = Depends(changing)):
    host = g.get(VirtualHost, host_id, "edit_sites")
    name = host.name
    g.session.delete(host)
    g.session.commit()

    audit.record("site.delete", user=g.user, object_type="site", object_name=name)
    return {"ok": True, "deleted": name}


def _apply_host_fields(g, host, payload):
    """
    Copy the allowed fields onto a site, checking each one.

    Settings are checked against the catalog, which the renderer also reads,
    so config nginx would reject is refused here rather than at apply time.
    """
    if "name" in payload:
        name = validate_name(payload["name"], "site name")
        claim_name(g.session, VirtualHost, name, "site", exclude_id=host.id)
        host.name = name

    if "server_names" in payload:
        names = payload["server_names"]
        if isinstance(names, str):
            names = [n.strip() for n in names.split() if n.strip()]
        if not names:
            raise HTTPException(status_code=400, detail="a site needs at least one server name")
        for n in names:
            validate_hostname(n)
        host.server_names = json.dumps(names)

    for field in ("enabled", "listen_http", "listen_https", "default_server",
                  "http2", "force_https", "admin_only", "redirect_to_primary",
                  "tls_offload_only"):
        if field in payload:
            setattr(host, field, bool(payload[field]))

    for field in ("http_port", "https_port"):
        if field in payload:
            setattr(host, field, validate_port(payload[field]))

    if "mode" in payload:
        if payload["mode"] not in ("proxy", "static", "redirect", "none"):
            raise HTTPException(status_code=400, detail="that site type is not one we know")
        host.mode = payload["mode"]

    # Foreign keys go through the guard too, so referencing an object you
    # cannot see fails the same as fetching it directly.
    for field, model in (("pool_id", Pool), ("cert_id", Certificate),
                         ("access_list_id", AccessList),
                         ("error_page_template_id", ErrorPageTemplate)):
        if field in payload:
            value = payload[field]
            if value in (None, "", 0):
                setattr(host, field, None)
            else:
                obj = g.get(model, value)
                setattr(host, field, obj.id)

    for field in ("document_root", "redirect_target", "notes", "custom_config"):
        if field in payload:
            setattr(host, field, payload[field] or None)

    if "redirect_code" in payload:
        code = int(payload["redirect_code"])
        if code not in (301, 302, 307, 308):
            raise HTTPException(status_code=400, detail="a redirect has to be 301, 302, 307 or 308")
        host.redirect_code = code

    if "config_mode" in payload:
        if payload["config_mode"] not in ("gui", "raw"):
            raise HTTPException(status_code=400, detail="config mode is gui or raw")
        # Raw server blocks are admin only.  Operators can change anything
        # through the forms, where every value is checked.
        if payload["config_mode"] == "raw":
            g.require("raw_config")

        # Leaving raw mode has to drop the hand written file.  In raw mode
        # `custom_config` is the whole file; in form mode it is a snippet
        # inserted inside the generated server block (where the importer puts
        # directives it could not represent).  Keeping a whole file there gave
        # `"server" directive is not allowed here` and blocked every apply.
        # Importer snippets are fragments and are kept.
        if (payload["config_mode"] == "gui"
                and host.config_mode == "raw"
                and _is_whole_file(host.custom_config)):
            host.custom_config = None
            log.info("cleared the hand written config on %s, since the form is "
                     "driving it again", host.name)

        host.config_mode = payload["config_mode"]

    if "settings" in payload:
        host.settings = json.dumps(_validate_settings(payload["settings"], "server"))

    host.updated_by = g.user.username


def _is_whole_file(text) -> bool:
    """
    Is this a complete config file rather than a snippet?

    A `server` block at the start of a line gives it away; snippets never
    have one.
    """
    if not text:
        return False
    return bool(_re.search(r"(?m)^\s*server\s*\{", str(text)))


def _validate_settings(raw, context: str) -> dict:
    """
    Check a settings blob against the catalog.

    Unknown keys are dropped rather than stored, so a typo does not sit there
    silently doing nothing.
    """
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="settings has to be an object")

    caps = fleet_capabilities()
    cleaned = {}
    problems = []

    for key, value in raw.items():
        feature = get_feature(key)
        if not feature:
            problems.append(f"there is no setting called {key}")
            continue
        if feature.edition != "oss":
            problems.append(f"{feature.label} is only in the paid nginx")
            continue
        if context not in feature.contexts:
            problems.append(f"{feature.label} cannot go in a {context} block")
            continue
        if not feature.is_available(caps.modules, caps.version_tuple):
            # The GUI sends the whole settings blob, so disabled checkboxes
            # arrive as false.  Accept and drop values that ask for nothing;
            # only refuse actually enabling a missing feature.  Refusing these
            # used to fail every save on a fleet missing any module.
            if not value or value == feature.default:
                continue
            problems.append(f"{feature.label} {feature.unavailable_reason(caps.modules, caps.version_tuple)}")
            continue

        # Zone picker: check against zones that exist.  The message lists
        # them, since the usual cause is a zone renamed or deleted later.
        zone = ZONE_CHOICES.get(key)
        if zone and value:
            model, what, page = zone
            with session_scope() as session:
                known = sorted(z.name for z in session.query(model).all())
            if value not in known:
                problems.append(
                    f"{feature.label}: there is no {what} called {value}." +
                    (f"  There is: {', '.join(known)}" if known
                     else f"  None exist yet, so make one on the {page} page first."))
                continue
            cleaned[key] = value
            continue

        # WAF strictness is a level or `custom:<profile>`.  Only the levels
        # are in the static catalog, so profiles are checked here (without
        # this, applying a profile always failed with a 400).  They are
        # checked against real profiles: an unknown name would render with no
        # exclusions and quietly refuse traffic that was meant to be allowed.
        if key == "waf_paranoia" and str(value).startswith("custom:"):
            wanted = str(value).split(":", 1)[1]
            with session_scope() as session:
                known = [p.name for p in session.query(WafProfile).all()]
            if wanted not in known:
                problems.append(
                    f"{feature.label}: there is no WAF profile called "
                    f"{wanted}." + (f"  There is: {', '.join(sorted(known))}"
                                    if known else "  None are saved yet."))
                continue
            cleaned[key] = value
            continue

        error = validate_value(feature, value)
        if error:
            problems.append(f"{feature.label}: {error}")
            continue

        cleaned[key] = value

    problems.extend(_cross_check(cleaned))

    if problems:
        raise HTTPException(status_code=400, detail="; ".join(problems[:8]))

    return cleaned


def _parse_size(value) -> int:
    """Turn an nginx size like 16k or 1m into bytes, or None."""
    import re as _re

    m = _re.fullmatch(r"(\d+)([kKmMgG]?)", str(value).strip())
    if not m:
        return None
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]


def _cross_check(settings: dict) -> list:
    """
    Settings that are each fine alone but wrong together.

    The proxy buffer check is the main one.  It is easy to hit, and nginx's
    error ("proxy_busy_buffers_size" must be less than the size of all
    "proxy_buffers" minus one buffer) names a directive the user never set.
    """
    problems = []

    # An enforcing positive model with nothing in it refuses the whole site.
    # The renderer won't write that either, but saving and then silently doing
    # nothing would leave someone thinking the site is locked down.
    positive = (settings.get("waf_positive") or "off").strip()
    if positive in ("report", "enforce"):
        chosen = (settings.get("waf_paranoia") or "").strip()
        if not chosen.startswith("custom:"):
            problems.append(
                "the allowed surface comes from a WAF profile, so strictness "
                "has to be set to one of your profiles rather than a plain "
                "level.  Record a round on this tab and save what it finds")
        else:
            wanted = chosen.split(":", 1)[1]
            with session_scope() as session:
                profile = session.query(WafProfile).filter(
                    WafProfile.name == wanted).first()
                count = len(profile.surface) if profile else 0
            if not count:
                problems.append(
                    f"the profile {wanted} has no allowed surface in it, and "
                    f"turning this on with an empty surface would refuse every "
                    f"request to the site.  Record a round and save what it finds")

    # Browsers never honor credentials with any origin.  Without this check
    # the site looks configured for CORS and refuses every call.
    if settings.get("cors_allow_credentials"):
        origins = settings.get("cors_allow_origin") or ["*"]
        if any(str(o).strip() == "*" for o in origins):
            problems.append(
                "cross site credentials cannot be used with an allowed origin "
                "of *, because a browser refuses that pair on purpose.  List "
                "the origins that are allowed instead")

    buffer_size = settings.get("proxy_buffer_size")
    buffers = settings.get("proxy_buffers")

    if buffer_size and buffers:
        import re as _re

        m = _re.fullmatch(r"(\d+)\s+(\S+)", str(buffers).strip())
        head = _parse_size(buffer_size)
        if m and head:
            count = int(m.group(1))
            one = _parse_size(m.group(2))
            if one and count:
                total = count * one
                # When unset, nginx computes proxy_busy_buffers_size as twice
                # the larger of the header buffer and one body buffer, and it
                # must fit in all buffers but one.  The renderer pins it, so we
                # only need to catch buffers too small for any value to work.
                busy = max(head, one)
                if busy > total - one:
                    need = busy + one
                    problems.append(
                        f"the proxy buffer sizes do not fit together.  With a header "
                        f"buffer of {buffer_size} and buffers of {buffers}, nginx works "
                        f"out an internal limit of {busy // 1024}k which has to fit in "
                        f"{(total - one) // 1024}k, and it does not.  Either raise the "
                        f"buffers to about {need // 1024}k in total, for example "
                        f"\"{max(count, (need // one) + 1)} {m.group(2)}\", or lower the "
                        f"header buffer"
                    )

    # Caching a logged in user's page and serving it to someone else is a
    # real data leak, and easy to set up by accident.
    if settings.get("proxy_cache_zone"):
        bypass = settings.get("proxy_cache_bypass") or []
        no_cache = settings.get("proxy_no_cache") or []
        if bypass and not no_cache:
            problems.append(
                "caching is set to skip the cache for some requests but not to stop "
                "storing them.  That means a logged in user gets a fresh page and "
                "their copy still lands in the cache for the next visitor.  Set "
                "\"never store when\" to the same list as \"skip the cache when\""
            )

    # Browsers refuse * with credentials, and working around that opens the
    # API to every site on the internet.
    if settings.get("cors_allow_credentials"):
        origins = settings.get("cors_allow_origin") or []
        if "*" in origins:
            problems.append(
                "CORS is set to allow credentials with an origin of *.  Browsers "
                "refuse that combination on purpose, because it would let any site "
                "make authenticated calls as your logged in users.  List the real "
                "origins instead"
            )

    return problems


def _host_summary(h):
    return {
        "id": h.id,
        "name": h.name,
        "enabled": h.enabled,
        "server_names": h.name_list(),
        "mode": h.mode,
        "pool": h.pool.name if h.pool else None,
        "pool_status": h.pool.status_summary if h.pool else None,
        "cert": h.cert.name if h.cert else None,
        "cert_status": h.cert.status if h.cert else None,
        "cert_days_left": h.cert.days_left if h.cert else None,
        "https": h.listen_https,
        "admin_only": h.admin_only,
    }


def _cert_coverage(h, cert):
    """
    Which of a site's names its certificate would not be accepted for.

    Catches e.g. a site serving example.com and www.example.com on a
    certificate covering only one.  Wildcards are matched properly:
    *.example.com covers www.example.com but not example.com.
    """
    if cert is None:
        return {"cert_covers": [], "uncovered": [], "checked": False}
    return {
        "cert_covers": cert.domain_list(),
        "uncovered": hostnames.uncovered(cert.domain_list(), h.name_list()),
        "checked": True,
    }


def _host_detail(h):
    return {
        **_host_summary(h),
        **_cert_coverage(h, h.cert),
        # Worked out here so the page need not know which names pair up.
        "www_partner": next(
            (p for p in (hostnames.www_partner(n) for n in h.name_list())
             if p and p not in h.name_list()), None),
        "listen_http": h.listen_http,
        "http_port": h.http_port,
        "https_port": h.https_port,
        "default_server": h.default_server,
        "http2": h.http2,
        "force_https": h.force_https,
        "redirect_to_primary": h.redirect_to_primary,
        "tls_offload_only": bool(h.tls_offload_only),
        "pool_id": h.pool_id,
        "cert_id": h.cert_id,
        "access_list_id": h.access_list_id,
        "error_page_template_id": h.error_page_template_id,
        "document_root": h.document_root,
        "redirect_target": h.redirect_target,
        "redirect_code": h.redirect_code,
        "settings": h.setting_map(),
        "custom_config": h.custom_config,
        "notes": h.notes,
        # Built by the same function as the locations endpoint.  A separate
        # copy here once left out fields like custom_config, and callers acting
        # on it skipped or blanked real hand written config.
        "locations": [
            _location_json(loc)
            for loc in sorted(h.locations, key=lambda x: x.sort_order or 0)
        ],
        "tunnel_workloads": _tunnels_behind(h),
    }


def _tunnels_behind(h):
    """
    Which tunnel workloads this site's traffic ends up at.

    That dependency (site, pool, member address, tunnel peer) is otherwise
    invisible on the site page.  Covers the site's own pool and its paths'
    pools, and matches on address, since that is what the tunnel assigned.
    """
    from sqlalchemy.orm import object_session

    from app.models import PoolMember, TunnelPeer

    session = object_session(h)
    if session is None:
        return []

    pool_ids = {h.pool_id} | {loc.pool_id for loc in h.locations}
    pool_ids.discard(None)
    if not pool_ids:
        return []

    addresses = {m.address for m in session.query(PoolMember)
                 .filter(PoolMember.pool_id.in_(pool_ids)).all() if m.address}
    if not addresses:
        return []

    peers = (session.query(TunnelPeer)
             .filter(TunnelPeer.address.in_(addresses))
             .order_by(TunnelPeer.name).all())

    return [{"id": p.id, "name": p.name, "address": p.address,
             "description": p.description or "",
             # A never-enrolled workload has never answered, which is a
             # different problem from one that is down.
             "enrolled": p.is_enrolled(), "enabled": bool(p.enabled)}
            for p in peers]


# ==============================================================================
# Pools
# ==============================================================================

POOL_FIELDS = {
    "name", "description", "lb_method", "hash_key", "hash_consistent",
    "keepalive", "keepalive_requests", "keepalive_timeout", "zone_size",
    "health_check_enabled", "health_check_type", "health_check_path",
    "health_check_method", "health_check_host_header", "health_check_expect_status",
    "health_check_expect_body", "health_check_interval", "health_check_timeout",
    "health_check_rise", "health_check_fall", "health_check_verify_tls",
    "health_check_port", "min_healthy_members", "settings",
    "token_enabled", "backend_tls", "backend_tls_name",
    "backend_kind", "backend_tls_verify", "backend_tls_ca",
}

MEMBER_FIELDS = {
    "address", "port", "weight", "backup", "max_fails", "fail_timeout",
    "max_conns", "enabled", "admin_state", "notes",
}

LB_METHODS = {"round_robin", "least_conn", "ip_hash", "hash", "random", "random_two", "fair"}


@router.get("/pools")
async def list_pools(g: ObjectGuard = Depends(guard)):
    return {"pools": [_pool_summary(p) for p in g.list(Pool)]}


@router.get("/pools/{pool_id}")
async def get_pool(pool_id: str, g: ObjectGuard = Depends(guard)):
    return _pool_detail(g.get(Pool, pool_id))


@router.post("/pools")
async def create_pool(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_pools")
    payload = pick_fields(await request.json(), POOL_FIELDS)

    # The name uniqueness check is in _apply_pool_fields below, shared with
    # rename.
    name = validate_name(payload.get("name"), "pool name")
    pool = Pool(name=name)

    # The settings page's default health check interval for new pools.
    # Applied before the payload, so an explicit value still wins.
    default_interval = settings_store.get("health_check_interval")
    if default_interval:
        try:
            pool.health_check_interval = int(default_interval)
        except (TypeError, ValueError):
            pass

    _apply_pool_fields(g.session, pool, payload)
    g.session.add(pool)
    g.session.commit()

    audit.record("pool.create", user=g.user, object_type="pool", object_name=name,
                 changes=payload)
    return _pool_detail(pool)


@router.put("/pools/{pool_id}")
async def update_pool(pool_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")
    payload = pick_fields(await request.json(), POOL_FIELDS)

    before = _pool_detail(pool)
    _apply_pool_fields(g.session, pool, payload)
    g.session.commit()

    audit.record("pool.update", user=g.user, object_type="pool", object_name=pool.name,
                 changes=audit.diff_fields(before, _pool_detail(pool)))
    return _pool_detail(pool)


@router.delete("/pools/{pool_id}")
async def delete_pool(pool_id: str, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")

    # A pool in use cannot be deleted: the site would proxy_pass to a missing
    # upstream and nginx would not start.
    users = g.session.query(VirtualHost).filter(VirtualHost.pool_id == pool.id).all()
    if users:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{pool.name} is still used by: {', '.join(h.name for h in users)}.  "
                f"Point those somewhere else first."
            ),
        )

    name = pool.name
    g.session.delete(pool)
    g.session.commit()

    audit.record("pool.delete", user=g.user, object_type="pool", object_name=name)
    return {"ok": True, "deleted": name}


# =============================================================================
# Pool tokens
#
# A shared secret nginx adds to requests it sends to a pool, so the backend can
# reject anything that did not come through the fleet.
#
# Rotation is two steps on purpose.  nginx can only send one value, so the safe
# order is: stage a new token, make the backends accept either, then activate.
# =============================================================================

@router.post("/pools/{pool_id}/token")
async def create_pool_token(pool_id: str, request: Request,
                            g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")
    payload = await request.json() if await request.body() else {}

    supplied = str(payload.get("value") or "").strip()
    if supplied:
        # A user-supplied secret.  Set a minimum length so a guessable one
        # cannot be used by accident.
        if len(supplied) < 16:
            raise HTTPException(
                status_code=400,
                detail="a token needs to be at least 16 characters, longer is better",
            )
        if len(supplied) > 256:
            raise HTTPException(status_code=400, detail="that token is too long, keep it under 256")

        # Allowlist the charset.  This goes into an nginx directive, where a
        # semicolon would end it early.  The renderer would refuse it, but only
        # after breaking the fleet's apply.
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]+", supplied):
            raise HTTPException(
                status_code=400,
                detail=(
                    "a token can only hold letters, digits and . _ ~ + / = -  "
                    "Anything else can break the nginx config it gets written into."
                ),
            )
        token = supplied
    else:
        token = new_token(32)

    if "header" in payload and payload["header"]:
        header = re.sub(r"[^A-Za-z0-9-]", "", str(payload["header"]))[:64]
        if not header:
            raise HTTPException(status_code=400, detail="a header name needs letters, digits or dashes")
        pool.token_header = header

    staged = bool(pool.token_encrypted)
    if staged:
        # Already sending one, so this is a rotation.  Stage it in next and
        # leave the live token alone until activation.
        pool.token_next_encrypted = encrypt(token)
    else:
        pool.token_encrypted = encrypt(token)
        pool.token_enabled = True
        pool.token_rotated_at = utcnow()

    g.session.commit()

    audit.record("pool.token_stage" if staged else "pool.token_create",
                 user=g.user, object_type="pool", object_name=pool.name,
                 changes={"header": pool.token_header, "supplied": bool(supplied)})

    return {
        "ok": True,
        "staged": staged,
        "header": pool.token_header,
        "value": token,
        "next_step": (
            "Add this to your backends so they accept it as well as the current one, "
            "then press Activate."
            if staged else
            "Add this to your backends, then apply the config so nginx starts sending it."
        ),
    }


@router.post("/pools/{pool_id}/token/activate")
async def activate_pool_token(pool_id: str, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")

    if not pool.token_next_encrypted:
        raise HTTPException(status_code=400, detail="there is no staged token to activate")

    pool.token_previous_encrypted = pool.token_encrypted
    pool.token_encrypted = pool.token_next_encrypted
    pool.token_next_encrypted = None
    pool.token_rotated_at = utcnow()
    g.session.commit()

    audit.record("pool.token_activate", user=g.user, object_type="pool",
                 object_name=pool.name)

    return {
        "ok": True,
        "next_step": (
            "Apply the config so nginx starts sending the new one.  Once that is "
            "done and traffic looks normal, remove the old token from your backends."
        ),
    }


@router.post("/pools/{pool_id}/token/cancel")
async def cancel_pool_token(pool_id: str, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")

    if not pool.token_next_encrypted:
        raise HTTPException(status_code=400, detail="there is no staged token to cancel")

    pool.token_next_encrypted = None
    g.session.commit()

    audit.record("pool.token_cancel", user=g.user, object_type="pool", object_name=pool.name)
    return {"ok": True, "message": "dropped the staged token, nothing on the wire changed"}


@router.get("/pools/{pool_id}/token")
async def reveal_pool_token(pool_id: str, g: ObjectGuard = Depends(guard)):
    """
    Return the actual token values.

    Anyone who can edit the pool can already change the token, so this reveals
    nothing new.  Still audited.
    """
    pool = g.get(Pool, pool_id, "edit_pools")

    if not pool.token_encrypted:
        raise HTTPException(status_code=404, detail="this pool has no token")

    audit.record("pool.token_reveal", user=g.user, object_type="pool",
                 object_name=pool.name)

    return {
        "header": pool.token_header,
        "current": pool.token,
        "staged": pool.token_next,
        "previous": pool.token_previous,
    }


@router.delete("/pools/{pool_id}/token")
async def delete_pool_token(pool_id: str, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")

    pool.token_enabled = False
    pool.token_encrypted = None
    pool.token_next_encrypted = None
    pool.token_previous_encrypted = None
    pool.token_rotated_at = None
    g.session.commit()

    audit.record("pool.token_delete", user=g.user, object_type="pool", object_name=pool.name)
    return {
        "ok": True,
        "message": (
            "Token turned off.  Apply the config, then stop checking for it on your "
            "backends.  Do it in that order or they will reject the fleet."
        ),
    }


def _apply_pool_fields(session, pool, payload):
    if "name" in payload:
        name = validate_name(payload["name"], "pool name")
        claim_name(session, Pool, name, "pool", exclude_id=pool.id)
        pool.name = name

    if "lb_method" in payload:
        if payload["lb_method"] not in LB_METHODS:
            raise HTTPException(
                status_code=400,
                detail=(
                    f"that load balancing method is not available.  "
                    f"Pick one of: {', '.join(sorted(LB_METHODS))}.  "
                    f"least_time and sticky are paid only, see the parity page."
                ),
            )
        pool.lb_method = payload["lb_method"]

    if "health_check_type" in payload:
        if payload["health_check_type"] not in ("http", "https", "tcp"):
            raise HTTPException(status_code=400, detail="check type has to be http, https or tcp")
        pool.health_check_type = payload["health_check_type"]

    if "health_check_method" in payload:
        method = str(payload["health_check_method"]).upper()
        if method not in ("GET", "HEAD", "POST", "OPTIONS"):
            raise HTTPException(status_code=400, detail="that check method is not allowed")
        pool.health_check_method = method

    for field in ("description", "hash_key", "health_check_path",
                  "health_check_host_header", "health_check_expect_status",
                  "health_check_expect_body", "keepalive_timeout", "zone_size"):
        if field in payload:
            setattr(pool, field, payload[field] or None)

    # token_enabled off stops sending the header but keeps the secret.  On
    # needs a token as well, which is set through its own endpoint.
    if "backend_kind" in payload:
        if payload["backend_kind"] not in ("servers", "site"):
            raise HTTPException(status_code=400,
                                detail="backend kind has to be servers or site")
        pool.backend_kind = payload["backend_kind"]

    # Goes straight into a directive, so it must be a plain path.  Blank
    # means the system bundle.
    if "backend_tls_ca" in payload:
        raw = (payload["backend_tls_ca"] or "").strip()
        if raw and not re.fullmatch(r"/[A-Za-z0-9._/-]{1,500}", raw):
            raise HTTPException(
                status_code=400,
                detail=("the CA file has to be an absolute path.  Leave it blank for the "
                        "system list, which is what a public certificate needs."),
            )
        pool.backend_tls_ca = raw or None

    for field in ("hash_consistent", "health_check_enabled", "health_check_verify_tls",
                  "token_enabled", "backend_tls_verify"):
        if field in payload:
            setattr(pool, field, bool(payload[field]))

    # Once someone sets this explicitly we stop inferring it from member
    # ports, even if they turn it off with a member on 443.
    if "backend_tls" in payload:
        pool.backend_tls = bool(payload["backend_tls"])
        pool.backend_tls_set = True

    # Goes into an nginx directive, so it must look like a hostname.  Bad
    # config here would block the whole fleet.
    if "backend_tls_name" in payload:
        raw = (payload["backend_tls_name"] or "").strip()
        if raw and not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", raw):
            raise HTTPException(
                status_code=400,
                detail=(
                    "the backend TLS name has to be a hostname, so letters, numbers, "
                    "dots, dashes and underscores only.  Leave it blank to take it "
                    "from the members."
                ),
            )
        pool.backend_tls_name = raw or None

    for field, low, high in (
        ("keepalive", 0, 10000),
        ("keepalive_requests", 1, 1000000),
        ("health_check_interval", 2, 3600),
        ("health_check_timeout", 1, 120),
        ("health_check_rise", 1, 20),
        ("health_check_fall", 1, 20),
        ("min_healthy_members", 0, 1000),
    ):
        if field in payload:
            try:
                value = int(payload[field])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{field} has to be a number")
            if not low <= value <= high:
                raise HTTPException(
                    status_code=400, detail=f"{field} has to be between {low} and {high}"
                )
            setattr(pool, field, value)

    if "health_check_port" in payload:
        value = payload["health_check_port"]
        pool.health_check_port = validate_port(value) if value else None

    if "settings" in payload:
        # Our own settings, not nginx directives, so they get their own check.
        pool.settings = json.dumps(_validate_pool_settings(payload["settings"]))


def _validate_pool_settings(raw) -> dict:
    """Check the settings for our replacements of the Plus features."""
    if not isinstance(raw, dict):
        raise HTTPException(status_code=400, detail="settings has to be an object")

    allowed = {
        "sticky_enabled": bool,
        "sticky_cookie_name": str,
        "sticky_cookie_max_age": int,
        "sticky_consistent": bool,
        "slow_start_enabled": bool,
        "slow_start_seconds": int,
        "adaptive_weight_enabled": bool,
        "adaptive_base_weight": int,
        "adaptive_min_weight": int,
        "adaptive_max_weight": int,
        "adaptive_floor_ms": int,
        # Where members publish metrics.  A template, since members are
        # usually identical boxes with the same exporter and port.
        "member_metrics_url": "url",

        # Path of the application on the backends when it is not the root.
        # A property of the backend, so it lives on the pool (people tried
        # typing it onto member addresses first).  Sites can override it.
        "backend_path": "path",
    }

    cleaned = {}
    for key, value in raw.items():
        expected = allowed.get(key)
        if expected is None:
            continue
        if expected is bool:
            cleaned[key] = bool(value)
        elif expected is int:
            try:
                cleaned[key] = int(value)
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{key} has to be a number")
        elif expected == "url":
            text = str(value or "").strip()
            if not text:
                cleaned[key] = ""
                continue
            # http or https only.  We fetch this on a timer, so other schemes
            # (file:, gopher:) could read things they should not.
            if not re.fullmatch(
                    r"https?://[A-Za-z0-9._:\[\]{}-]+(/[A-Za-z0-9._~:/?#@!$&'()*+,;=%{}-]*)?",
                    text):
                raise HTTPException(
                    status_code=400,
                    detail=("that has to be an http or https URL.  Use {host} where "
                            "the backend's address goes, like "
                            "http://{host}:9100/metrics"))
            if len(text) > 300:
                raise HTTPException(status_code=400, detail="that URL is too long")

            # Also check where it points, or this becomes an SSRF primitive
            # from the load balancer.  Only possible when the host is literal;
            # {host} templates are checked per member in metrics.py.
            from app.core.exporters import unsafe_fetch_target

            bad_target = unsafe_fetch_target(text)
            if bad_target:
                raise HTTPException(status_code=400, detail=bad_target)

            cleaned[key] = text
        elif expected == "path":
            # A backend path, not a URL.  We normalize the slashes ourselves
            # because the trailing slash changes how nginx replaces the
            # matched part of the path.
            text = str(value or "").strip()
            if not text:
                cleaned[key] = ""
                continue

            # Check before normalizing, or a pasted URL becomes a path like
            # /http://host:8080/shop/.
            if "://" in text or text.lower().startswith(("http:", "https:")):
                raise HTTPException(
                    status_code=400,
                    detail=("that is a URL.  This field is only the path the "
                            "application sits under on the backend, like "
                            "/shop/.  Where to reach the backend is the member "
                            "address and port"))

            if not text.startswith("/"):
                text = "/" + text
            if not text.endswith("/"):
                text += "/"
            if len(text) > 300:
                raise HTTPException(status_code=400, detail="that path is too long")
            if not re.fullmatch(r"/[A-Za-z0-9._~\-/%@!$&'()*+,;=]*", text):
                raise HTTPException(
                    status_code=400,
                    detail=("that has to be a path, like /shop/.  No scheme, no "
                            "host and no port: this is where the application "
                            "sits on the backend, not how to reach it"))
            cleaned[key] = text
        else:
            text = str(value)
            if not re.fullmatch(r"[A-Za-z0-9_-]{1,40}", text):
                raise HTTPException(status_code=400, detail=f"{key} has characters we cannot use")
            cleaned[key] = text

    return cleaned


def _pool_summary(p):
    return {
        "id": p.id,
        "name": p.name,
        "description": p.description,
        "lb_method": p.lb_method,
        "status": p.status_summary,
        "healthy": p.healthy_count,
        "total": p.total_count,
        "health_check_enabled": p.health_check_enabled,
    }


def _pool_detail(p):
    return {
        **_pool_summary(p),
        "hash_key": p.hash_key,
        "hash_consistent": p.hash_consistent,
        "keepalive": p.keepalive,
        "keepalive_requests": p.keepalive_requests,
        "keepalive_timeout": p.keepalive_timeout,
        "zone_size": p.zone_size,
        "min_healthy_members": p.min_healthy_members,
        "backend_tls": p.uses_backend_tls,
        "backend_tls_set": bool(p.backend_tls_set),
        "backend_tls_name": p.backend_tls_name,
        "backend_kind": p.backend_kind or "servers",
        "backend_tls_verify": bool(p.backend_tls_verify),
        "backend_tls_ca": p.backend_tls_ca,
        "backend_name": p.backend_name,
        "health_check": {
            "enabled": p.health_check_enabled,
            "type": p.effective_health_check_type,
            "path": p.health_check_path,
            "method": p.health_check_method,
            "host_header": p.health_check_host_header,
            "expect_status": p.health_check_expect_status,
            "expect_body": p.health_check_expect_body,
            "interval": p.health_check_interval,
            "timeout": p.health_check_timeout,
            "rise": p.health_check_rise,
            "fall": p.health_check_fall,
            "verify_tls": p.health_check_verify_tls,
            "port": p.health_check_port,
        },
        # Trust state without the secret.  The GUI only needs to know a
        # token exists and whether a rotation is in progress; the value would
        # end up in logs and browser caches.
        "trust": {
            "enabled": bool(p.token_enabled),
            "active": p.token_active,
            "header": p.token_header,
            "rotation_pending": p.token_rotation_pending,
            "has_previous": bool(p.token_previous_encrypted),
            "rotated_at": p.token_rotated_at.isoformat() if p.token_rotated_at else None,
        },
        "settings": p.setting_map(),
        "members": [_member_detail(m) for m in p.members],
    }


def _member_detail(m):
    return {
        "id": m.id,
        "address": m.address,
        "port": m.port,
        "label": m.label,
        "weight": m.weight,
        "backup": m.backup,
        "enabled": m.enabled,
        "admin_state": m.admin_state,
        "state": m.effective_state.value,
        "max_fails": m.max_fails,
        "fail_timeout": m.fail_timeout,
        "max_conns": m.max_conns,
        "last_check_at": m.last_check_at.isoformat() if m.last_check_at else None,
        "last_error": m.last_error,
        "last_response_ms": m.last_response_ms,
        "avg_response_ms": m.avg_response_ms,
        "check_count": m.check_count,
        "fail_count": m.fail_count,
        "notes": m.notes,
    }


# ---- members ----------------------------------------------------------------

@router.post("/pools/{pool_id}/members")
async def add_member(pool_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")
    payload = pick_fields(await request.json(), MEMBER_FIELDS)

    address = str(payload.get("address", "")).strip()
    if not address:
        raise HTTPException(status_code=400, detail="a backend needs an address")

    # Must be an IP or hostname, since it goes into a config file.
    import re

    if not re.fullmatch(r"[A-Za-z0-9._:\[\]-]{1,253}", address):
        raise HTTPException(status_code=400, detail="that backend address is not valid")

    port = validate_port(payload.get("port", 80))
    await _must_resolve(address)

    existing = g.session.query(PoolMember).filter(
        PoolMember.pool_id == pool.id,
        PoolMember.address == address,
        PoolMember.port == port,
    ).first()
    if existing:
        raise HTTPException(status_code=409, detail=f"{address}:{port} is already in this pool")

    member = PoolMember(pool_id=pool.id, address=address, port=port)
    _apply_member_fields(member, payload)
    g.session.add(member)
    g.session.commit()

    audit.record("pool.member.add", user=g.user, object_type="pool",
                 object_name=pool.name, changes={"member": f"{address}:{port}"})
    return _member_detail(member)


@router.post("/pools/{pool_id}/members/bulk")
async def add_members_bulk(pool_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    """
    Add a list of backends in one go.

    Every line is validated before anything is saved.  A half loaded pool is
    worse than a rejected one: you cannot tell which lines made it, and
    re-adding the list would collide with them.
    """
    pool = g.get(Pool, pool_id, "edit_pools")

    body = await request.json()
    text = body.get("text")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=400, detail="paste some backends first")

    if len(text) > 100_000:
        raise HTTPException(status_code=400, detail="that is too much at once, split it up")

    # Existing members, so every duplicate line can be reported at once.
    seen = {
        (m.address, m.port)
        for m in g.session.query(PoolMember).filter(PoolMember.pool_id == pool.id).all()
    }

    parsed = []
    problems = []
    duplicates = []

    for number, raw in enumerate(text.splitlines(), start=1):
        line = raw.split("#")[0].strip().rstrip(",")
        if not line:
            continue

        address, port = _split_backend(line)
        if not address:
            problems.append(f"line {number}: cannot read {raw.strip()!r}")
            continue
        if not re.fullmatch(r"[A-Za-z0-9._:\[\]-]{1,253}", address):
            problems.append(f"line {number}: {address} is not a valid address")
            continue
        try:
            port = validate_port(port)
        except HTTPException:
            problems.append(f"line {number}: {port} is not a valid port")
            continue

        if (address, port) in seen:
            duplicates.append(f"{address}:{port}")
            continue

        seen.add((address, port))
        parsed.append((address, port))

    # Resolve names concurrently.  Serially, each miss waits out its own
    # timeout and fifty names looks hung.
    if parsed:
        checks = await asyncio.gather(
            *[_must_resolve(address) for address, _port in parsed],
            return_exceptions=True,
        )
        for (address, _port), outcome in zip(parsed, checks):
            if isinstance(outcome, HTTPException):
                problems.append(f"{address} does not resolve from this node")
            elif isinstance(outcome, BaseException):
                problems.append(f"{address} could not be looked up: {outcome}")

    if problems:
        raise HTTPException(
            status_code=400,
            detail="nothing was added.  " + "  ".join(problems[:10]),
        )

    if not parsed:
        raise HTTPException(
            status_code=400,
            detail=(
                f"every one of those is already in this pool: {', '.join(duplicates[:10])}"
                if duplicates else "there were no backends in that"
            ),
        )

    for address, port in parsed:
        g.session.add(PoolMember(pool_id=pool.id, address=address, port=port))
    g.session.commit()

    audit.record("pool.member.add", user=g.user, object_type="pool",
                 object_name=pool.name,
                 changes={"added": [f"{a}:{p}" for a, p in parsed]})

    return {
        "added": [f"{a}:{p}" for a, p in parsed],
        "skipped": duplicates,
    }


async def _must_resolve(address: str):
    """
    Refuse a backend name this box cannot resolve.

    nginx resolves upstream names at load time, so an unresolvable name is not
    a down backend but a config nginx refuses to load, which blocks the whole
    fleet.  Its "host not found in upstream" error also shows up later and
    somewhere else.

    Only proves the name resolves from this node; the two phase apply catches
    a standby with different DNS.
    """
    bare = address.strip("[]")
    try:
        ipaddress.ip_address(bare)
        return
    except ValueError:
        pass

    try:
        await asyncio.wait_for(
            asyncio.get_running_loop().getaddrinfo(bare, None), timeout=5
        )
    except (socket.gaierror, asyncio.TimeoutError, OSError):
        raise HTTPException(
            status_code=400,
            detail=(
                f"{address} does not resolve from this node.  nginx looks names up when "
                f"it loads the config, so it would refuse to start and no config could be "
                f"applied anywhere.  Check the spelling, or use the address instead if "
                f"this name only exists somewhere else."
            ),
        )


def _split_backend(line: str):
    """
    Pull an address and port out of one pasted line.

    Accepts host:8080, host 8080, host,8080, host, and [::1]:8080.  A bare
    host means port 80.
    """
    line = line.replace("\t", " ").replace(",", " ").strip()

    # Bracketed IPv6: the port is only what follows the closing bracket.
    if line.startswith("["):
        end = line.find("]")
        if end == -1:
            return None, None
        address = line[: end + 1]
        rest = line[end + 1:].lstrip(":").strip()
        return address, (rest.split()[0] if rest.split() else 80)

    parts = line.split()
    if len(parts) > 2:
        return None, None
    if len(parts) == 2:
        return parts[0], parts[1]

    single = parts[0]
    if single.count(":") == 1:
        address, _sep, port = single.partition(":")
        return address, (port or 80)
    if single.count(":") > 1:
        # Unbracketed IPv6: a port is indistinguishable from another group,
        # so ask for brackets rather than guess.
        return None, None
    return single, 80


@router.put("/members/{member_id}")
async def update_member(member_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    member = g.get(PoolMember, member_id, "edit_pools")
    payload = pick_fields(await request.json(), MEMBER_FIELDS)

    before = _member_detail(member)
    _apply_member_fields(member, payload)
    g.session.commit()

    audit.record("pool.member.update", user=g.user, object_type="pool",
                 object_name=member.pool.name,
                 changes=audit.diff_fields(before, _member_detail(member)))
    return _member_detail(member)


@router.post("/members/{member_id}/state")
async def set_member_state(member_id: str, request: Request,
                           g: ObjectGuard = Depends(changing)):
    """
    Take a backend in or out by hand.

    Draining stops new connections but lets existing ones finish, so a box
    can be patched without cutting anyone off mid request.
    """
    member = g.get(PoolMember, member_id, "drain_member")
    payload = await request.json()

    state = payload.get("state")
    if state not in ("up", "down", "draining", "maintenance"):
        raise HTTPException(
            status_code=400,
            detail="state has to be up, down, draining or maintenance",
        )

    old = member.admin_state
    member.admin_state = state
    g.session.commit()

    audit.record("pool.member.state", user=g.user, object_type="pool",
                 object_name=member.pool.name,
                 changes={"member": member.label, "from": old, "to": state})

    result = await apply_current_config(
        author=g.user.username,
        summary=f"{member.label} set to {state}",
    )
    return {"ok": True, "state": state, "apply": result}


@router.delete("/members/{member_id}")
async def delete_member(member_id: str, g: ObjectGuard = Depends(changing)):
    member = g.get(PoolMember, member_id, "edit_pools")
    label = member.label
    pool_name = member.pool.name
    g.session.delete(member)
    g.session.commit()

    audit.record("pool.member.delete", user=g.user, object_type="pool",
                 object_name=pool_name, changes={"member": label})
    return {"ok": True, "deleted": label}


# Balancing methods that do not allow "backup" servers.  nginx's own error
# ("balancing method does not support parameter backup") is unhelpful and
# only shows up at apply, so we explain it at save time.
NO_BACKUP_METHODS = {
    "ip_hash": "sending each visitor to the same backend by their address",
    "hash": "sending each request to a backend chosen by a value you set",
    "random": "picking a backend at random",
}


def _check_backup_allowed(member, payload):
    if not payload.get("backup"):
        return
    pool = getattr(member, "pool", None)
    method = getattr(pool, "lb_method", "") or ""
    why = NO_BACKUP_METHODS.get(method)
    if not why:
        return
    raise HTTPException(
        status_code=400,
        detail=(
            f"This pool balances by {why}, and nginx does not allow a backup "
            f"server with that method.  A backup is only used when every other "
            f"server is down, and a method that always sends the same visitor "
            f"to the same backend has no way to express that.\n\n"
            f"Either switch the pool to round robin or least connections, or "
            f"leave this server as a normal member."))


def _apply_member_fields(member, payload):
    _check_backup_allowed(member, payload)
    for field, low, high in (("weight", 1, 1000), ("max_fails", 0, 100),
                             ("max_conns", 0, 100000)):
        if field in payload:
            try:
                value = int(payload[field])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400, detail=f"{field} has to be a number")
            if not low <= value <= high:
                raise HTTPException(status_code=400,
                                    detail=f"{field} has to be between {low} and {high}")
            setattr(member, field, value)

    for field in ("backup", "enabled"):
        if field in payload:
            setattr(member, field, bool(payload[field]))

    if "fail_timeout" in payload:
        import re

        if not re.fullmatch(r"\d+[smh]?", str(payload["fail_timeout"])):
            raise HTTPException(status_code=400, detail="fail timeout should look like 10s")
        member.fail_timeout = payload["fail_timeout"]

    if "admin_state" in payload:
        if payload["admin_state"] not in ("up", "down", "draining", "maintenance"):
            raise HTTPException(status_code=400, detail="that admin state is not one we know")
        member.admin_state = payload["admin_state"]

    if "notes" in payload:
        member.notes = str(payload["notes"])[:500] if payload["notes"] else None


# ==============================================================================
# Applying
# ==============================================================================

@router.post("/apply")
async def apply(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Push the current config to the whole fleet.

    Every node stages and tests it before any node applies it; see
    cluster.apply_config for what happens if one refuses.
    """
    g.require("apply_config")

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    summary = str(payload.get("summary", "manual apply"))[:500]

    # Force confirms that removing every site is intended.  Off by default:
    # the legitimate case is rare and the accidental one takes the fleet down.
    force = bool(payload.get("force"))
    if force:
        log.warning("%s applied with force, so the wipe check was skipped",
                    g.user.username)

    # Turn the expected failures into useful responses instead of a bare 500:
    #   ClusterError: a refusal with a reason, passed back as is.
    #   Locked database: SQLite allows one writer, so an apply racing another
    #     commit is refused by the driver.  Worth a retry, so say so.
    #   RoleNotSettled: for a few seconds after a restart no election has run
    #     yet.  Also a retry, not "you are on the wrong node".
    try:
        result = await apply_current_config(author=g.user.username, summary=summary,
                                            force=force)
    except RoleNotSettled as exc:
        log.info("apply refused, the fleet has not settled its roles yet: %s", exc)
        raise HTTPException(status_code=503, detail=str(exc))
    except ClusterError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except OperationalError as exc:
        if "database is locked" in str(exc).lower():
            log.warning("apply refused, the database was busy: %s", exc)
            raise HTTPException(
                status_code=503,
                detail="the database was busy with another change, so nothing "
                       "was applied.  Try again in a moment.")
        raise

    audit.record(
        "config.apply",
        user=g.user,
        object_type="config",
        object_name=f"v{result.get('version', '?')}",
        result="success" if result.get("ok") else "failed",
        detail=result.get("error") or json.dumps(result.get("applied_to", [])),
        config_version=result.get("version"),
    )

    if not result.get("ok"):
        raise HTTPException(status_code=409, detail=result)

    return result


@router.get("/preview")
async def preview(g: ObjectGuard = Depends(guard)):
    """Show the config we would write, without writing it."""
    files, checksum, _ = render_current(g.session)

    current = g.session.query(ConfigVersion).order_by(
        ConfigVersion.version.desc()
    ).first()

    return {
        "checksum": checksum,
        "unchanged": bool(current and current.checksum == checksum),
        "files": files,
        "current_version": current.version if current else 0,
    }


@router.post("/repair")
async def repair(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Work out what would have to be removed for nginx to accept this config.

    Two steps.  Without `confirm` it changes nothing and returns the lines it
    would comment out, each with nginx's reason.  With `confirm` it makes
    those changes but does not apply; the normal apply still stages and tests
    on every node.

    Kept separate from apply on purpose.  Directives removed here can be real
    controls (`ssl_verify_client`, `ssl_protocols`), and silently weakening
    TLS inside an apply is worse than an apply that fails loudly.
    """
    g.require("edit_sites")
    payload = await request.json() if await request.body() else {}
    confirm = bool(payload.get("confirm"))

    def render():
        files, _checksum, _snapshot = render_current(g.session)
        return files

    async def test(files):
        """Stage and test only; nothing goes live."""
        agent = get_agent()
        await agent.write_staging(files)
        answer = await agent.test_staging()
        return bool(answer.get("ok")), str(answer.get("output") or "")

    try:
        result = await config_repair.plan_repair(g.session, render, test)
    except AgentError as exc:
        raise HTTPException(status_code=400,
                            detail=f"could not check the config: {exc}")

    if confirm and result["changes"]:
        g.session.commit()
        for change in result["changes"]:
            audit.record("config.repair", user=g.user, object_type="site",
                         object_name=change["site"],
                         detail=f"{change['where']}: took out {change['line']} "
                                f"because nginx said {change['reason']}")
        log.warning("%s repaired %d line(s) of config", g.user.username,
                    len(result["changes"]))
    else:
        # Computed against the session and deliberately discarded.
        g.session.rollback()

    return {
        "already_loads": result["ok"],
        "would_load_after": result["fixed"],
        "changes": result["changes"],
        "kept": bool(confirm and result["changes"]),
        "nginx_said": result["output"],
        "could_not_repair": result["unrepairable"],
    }


@router.get("/hosts/{host_id}/config")
async def get_host_config(host_id: str, g: ObjectGuard = Depends(guard)):
    """
    The nginx config this site renders to.

    Generated and read only in gui mode; in raw mode it is what was typed.
    """
    host = g.get(VirtualHost, host_id)

    files, _, _ = render_current(g.session)
    from app.core.render import _safe_name

    key = f"sites/{_safe_name(host.name)}.conf"

    return {
        "mode": host.config_mode or "gui",
        "generated": files.get(key, ""),
        "custom_config": host.custom_config or "",
        "editable": (host.config_mode or "gui") == "raw",
    }


@router.put("/hosts/{host_id}/config")
async def put_host_config(host_id: str, request: Request,
                          g: ObjectGuard = Depends(changing)):
    """
    Save hand written config for a site.

    Checked by our parser, then by nginx in the context of the full config.
    Anything that fails nginx -t is not stored, since it would leave a site
    that cannot be applied.
    """
    host = g.get(VirtualHost, host_id, "raw_config")
    payload = await request.json()
    text = payload.get("config", "")

    if not isinstance(text, str):
        raise HTTPException(status_code=400, detail="config has to be text")
    if len(text) > 512 * 1024:
        raise HTTPException(status_code=400, detail="that config is unreasonably large")

    problems = quick_check(text)
    fatal = [p for p in problems if p["severity"] == "error"]
    if fatal:
        raise HTTPException(status_code=400, detail={
            "error": "that config has problems",
            "problems": problems,
        })

    # Swap this site's file for the candidate and test the whole config.
    from app.core.render import _safe_name

    files, _, _ = render_current(g.session)
    files[f"sites/{_safe_name(host.name)}.conf"] = text

    try:
        agent = get_agent()
        await agent.write_staging(files)
        result = await agent.test_staging()
    except AgentError as exc:
        raise HTTPException(status_code=400, detail=f"could not check it: {exc}")

    if not result.get("ok"):
        raise HTTPException(status_code=400, detail={
            "error": "nginx will not load that",
            "output": result.get("output", ""),
        })

    before = host.custom_config
    host.custom_config = text
    host.config_mode = "raw"
    host.updated_by = g.user.username
    g.session.commit()

    audit.record("site.raw_config", user=g.user, object_type="site",
                 object_name=host.name,
                 changes={"length": {"from": len(before or ""), "to": len(text)}})

    return {"ok": True, "problems": problems}


@router.post("/config/validate")
async def validate_config(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Check raw config in the editor before it is saved.

    Our quick parser catches obvious mistakes instantly, then nginx itself
    has the final say.
    """
    payload = await request.json()
    text = payload.get("config", "")

    problems = quick_check(text)

    # Skip nginx if our own pass already found something fatal.
    nginx_result = None
    if not any(p["severity"] == "error" for p in problems):
        try:
            # Test in the context of the full config.  Alone, a site lacks
            # log formats and upstreams and fails for unrelated reasons.  And
            # staging is shared, so writing only this file would wipe what
            # else was staged and break the next apply.
            files, _, _ = render_current(g.session)
            files["sites/_candidate.conf"] = text

            agent = get_agent()
            await agent.write_staging(files)
            nginx_result = await agent.test_staging()
        except AgentError as exc:
            nginx_result = {"ok": False, "output": str(exc)}

    return {
        "problems": problems,
        "nginx": nginx_result,
        "ok": (
            not any(p["severity"] == "error" for p in problems)
            and (nginx_result is None or nginx_result.get("ok", False))
        ),
    }


@router.post("/config/parse")
async def parse_config(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Parse config back into GUI settings, so the editor works both ways
    (e.g. typing client_max_body_size 50m updates the form).
    """
    payload = await request.json()
    text = payload.get("config", "")

    try:
        config = parse(text)
    except ParseError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    servers = []
    for block in config.server_blocks():
        names = block.get_value("server_name", "")
        servers.append({
            "server_names": names.split() if names else [],
            "listen": [d.arg_string() for d in block.find("listen")],
            "settings": extract_settings(block),
        })

    return {"servers": servers, "upstreams": len(config.upstream_blocks())}


# ==============================================================================
# Cluster
# ==============================================================================

@router.get("/cluster")
async def cluster_status(g: ObjectGuard = Depends(guard)):
    cluster = get_cluster()
    settings = get_settings()

    nodes = g.session.query(Node).all()
    pending = cluster.pending_summary(g.session)

    latest = g.session.query(ConfigVersion).order_by(
        ConfigVersion.version.desc()
    ).first()

    return {
        "current_version": latest.version if latest else 0,
        "this_node": settings.node_name,
        "nodes": [
            {
                "name": n.name,
                "address": n.address,
                "role": n.role.value,
                "state": n.state.value,
                "priority": n.priority,
                "is_self": n.is_self,
                "forced_standby": n.forced_standby,
                "applied_version": n.applied_version,
                "in_sync": bool(latest and n.applied_version == latest.version),
                "nginx_version": n.nginx_version,
                "nginx_active": n.nginx_active,
                "public_ip": n.public_ip,
                "last_heartbeat": n.last_heartbeat.isoformat() if n.last_heartbeat else None,
                "seconds_since_heartbeat": n.seconds_since_heartbeat,
                "last_error": n.last_error,
                "pending_changes": pending.get(n.name, {}).get("count", 0),
                "load_average": n.load_average,
            }
            for n in nodes
        ],
    }


@router.post("/cluster/join-token")
async def make_join_token(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("join_nodes")
    payload = await request.json() if await request.body() else {}

    token = get_cluster().create_join_token(
        g.session,
        created_by=g.user.username,
        note=str(payload.get("note", ""))[:255],
    )

    audit.record("cluster.join_token", user=g.user, object_type="cluster",
                 object_name="join token issued")

    settings = get_settings()
    sponsor = f"{settings.node_address}:{settings.peer_port}"

    # The new box does not have the project yet, so the command must fetch
    # the code first.
    repo = settings.repo_url
    target = settings.install_dir

    return {
        "token": token,
        "expires_in_hours": 2,
        "sponsor": sponsor,
        "repo_url": repo,
        "install_dir": target,
        "command": (
            f"sudo git clone {repo} {target} \\\n"
            f"  && sudo {target}/failoverlb_setup.sh --join {sponsor} --token {token}"
        ),
        "command_have_code": (
            f"sudo ./failoverlb_setup.sh --join {sponsor} --token {token}"
        ),
        "note": "single use, expires in 2 hours, treat it like a password",
    }


@router.post("/cluster/failover")
async def failover(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("failover")
    payload = await request.json()
    target = (payload.get("node") or "").strip()

    try:
        await get_cluster().failover_to(target, actor=g.user.username)
    except ClusterError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    # Only give a reason when the roster says the node cannot take the role.
    # Moving the role takes a couple of seconds with nobody active in the
    # middle, and that is not a fault.
    from app.core.cluster import preferred_active
    wanted, _asked_at = preferred_active()
    with session_scope() as session:
        active = session.query(Node).filter(Node.role == NodeRole.ACTIVE).first()
        active_name = active.name if active else None
        chosen = (session.query(Node).filter(Node.name == target).first()
                  if target else None)
        unfit = ""
        if chosen is not None:
            if chosen.forced_standby:
                unfit = "it is pinned to standby"
            elif chosen.state == NodeState.OFFLINE:
                unfit = "it is not answering"

    if not target:
        message = (f"Back to the election deciding, and it has picked "
                   f"{active_name}." if active_name else
                   "Back to the election deciding.")
    elif active_name == target:
        message = f"{target} is the active node."
    elif unfit:
        message = (f"{target} is written down as the one to be active and "
                   f"cannot take it yet, because {unfit}.  It will take over "
                   f"when that changes, and until then "
                   f"{active_name or 'the election'} holds it.")
    else:
        message = (f"{target} is written down as the one to be active.  Moving "
                   f"the role takes a few seconds, so it may still be settling.")

    audit.record("cluster.failover", user=g.user, object_type="cluster",
                 object_name=target or "automatic",
                 detail=(f"asked for {target}" if target
                         else "went back to letting the election decide")
                        + f", active is now {active_name}")
    return {
        "ok": True,
        "requested": target or None,
        "active": active_name,
        "automatic": not wanted,
        "settling": bool(target) and active_name != target and not unfit,
        "message": message,
    }


@router.delete("/cluster/nodes/{node_name}")
async def remove_node(node_name: str, g: ObjectGuard = Depends(changing)):
    """
    Remove a node from the cluster.

    A phantom node still counts toward quorum and can stop the real nodes
    from electing anyone.

    Only forgets the node here; nothing is uninstalled, since the node is
    usually not answering anyway.  If it is still running, stop it, or its
    heartbeats will bring it back.
    """
    node = g.session.query(Node).filter(Node.name == node_name).first()
    if not node:
        raise HTTPException(status_code=404, detail="not found")

    g.require("manage_cluster")

    if node.is_self:
        raise HTTPException(
            status_code=400,
            detail=(
                "a node cannot remove itself.  Do it from another node, or if "
                "this is the last one you want the whole install gone rather "
                "than a node removed."
            ),
        )

    if node.role == NodeRole.ACTIVE:
        raise HTTPException(
            status_code=400,
            detail=(
                f"{node_name} is the active node.  Make another node active "
                f"first, so there is somewhere for changes to go."
            ),
        )

    g.session.delete(node)
    g.session.commit()

    audit.record("cluster.node_remove", user=g.user, object_type="cluster",
                 object_name=node_name, detail=f"removed {node_name} from the cluster")

    # Re-run the election now rather than waiting for the timer.  Dropping a
    # dead node is often what lets the survivors elect someone.
    try:
        await get_cluster().run_election()
    except Exception as exc:
        log.warning("election after removing %s did not run: %s", node_name, exc)

    return {"ok": True, "removed": node_name}


@router.post("/cluster/resync")
async def resync(g: ObjectGuard = Depends(changing)):
    """
    Push the current config, and certificates, to any node that is behind.

    Certificates are included so a node that joined after one was issued
    catches up when someone presses Sync.
    """
    g.require("manage_cluster")
    await get_cluster().drain_pending()

    certs_done, certs_failed = 0, []
    with session_scope() as session:
        cert_ids = [
            c.id for c in session.query(Certificate).all()
            if c.usable
        ]

    manager = get_cert_manager()
    for cid in cert_ids:
        try:
            await manager.replicate(cid)
            certs_done += 1
        except AcmeError as exc:
            certs_failed.append(str(exc)[:120])
            log.warning("resync could not copy certificate %s: %s", cid, exc)

    audit.record("cluster.resync", user=g.user, object_type="cluster",
                 detail=f"config plus {certs_done} certificate(s)")
    return {"ok": True, "certificates_copied": certs_done, "certificate_errors": certs_failed}


# ==============================================================================
# Zones and access lists
# ==============================================================================
#
# Shared objects sites point at.  nginx declares them once at the http level,
# which is why they are not per-site settings, and lets several sites share
# one bucket (usually what you want for e.g. a login rate limit).

ZONE_MODELS = {
    "rate": RateLimitZone,
    "conn": ConnLimitZone,
    "cache": CacheZone,
}


@router.get("/zones")
async def list_zones(g: ObjectGuard = Depends(guard)):
    return {
        "rate": [
            {"id": z.id, "name": z.name, "description": z.description,
             "key": z.key, "zone_size": z.zone_size, "rate": z.rate,
             "used_by": _zone_users(g.session, "limit_req_zone_name", z.name)}
            for z in g.session.query(RateLimitZone).order_by(RateLimitZone.name).all()
        ],
        "conn": [
            {"id": z.id, "name": z.name, "description": z.description,
             "key": z.key, "zone_size": z.zone_size,
             "used_by": _zone_users(g.session, "limit_conn_zone_name", z.name)}
            for z in g.session.query(ConnLimitZone).order_by(ConnLimitZone.name).all()
        ],
        "cache": [
            {"id": z.id, "name": z.name, "description": z.description,
             "path": z.path, "levels": z.levels,
             "keys_zone_size": z.keys_zone_size, "max_size": z.max_size,
             "inactive": z.inactive,
             "used_by": _zone_users(g.session, "proxy_cache_zone", z.name)}
            for z in g.session.query(CacheZone).order_by(CacheZone.name).all()
        ],
        "access_lists": [
            {"id": a.id, "name": a.name, "description": a.description,
             "allow": a.allows(), "deny": a.denies(),
             "default_action": a.default_action,
             "include_management": a.include_management,
             "basic_auth_enabled": a.basic_auth_enabled,
             "basic_auth_realm": a.basic_auth_realm,
             "basic_auth_users": [u.get("username") for u in a.auth_users()],
             "use_real_ip": a.use_real_ip,
             "real_ip_header": a.real_ip_header,
             "real_ip_from": a.trusted_proxies(),
             "used_by": [h.name for h in g.session.query(VirtualHost)
                         .filter(VirtualHost.access_list_id == a.id).all()]}
            for a in g.session.query(AccessList).order_by(AccessList.name).all()
        ],
    }


def _zone_users(session, setting_key: str, zone_name: str) -> list:
    """Which sites use this zone, so one in use cannot be deleted."""
    users = []
    for host in session.query(VirtualHost).all():
        if host.setting_map().get(setting_key) == zone_name:
            users.append(host.name)
        for loc in host.locations:
            if loc.setting_map().get(setting_key) == zone_name:
                users.append(f"{host.name}{loc.path}")
    return sorted(set(users))


@router.post("/zones/{kind}")
async def create_zone(kind: str, request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")

    model = ZONE_MODELS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="not found")

    payload = await request.json()
    name = validate_name(payload.get("name"), "zone name")
    claim_name(g.session, model, name, "zone")

    zone = model(name=name, description=(payload.get("description") or "")[:500] or None)
    _apply_zone_fields(kind, zone, payload)

    g.session.add(zone)
    g.session.commit()

    audit.record(f"zone.{kind}.create", user=g.user, object_type="zone",
                 object_name=name, changes=payload)
    return {"id": zone.id, "name": zone.name}


@router.put("/zones/{kind}/{zone_id}")
async def update_zone(kind: str, zone_id: str, request: Request,
                      g: ObjectGuard = Depends(changing)):
    model = ZONE_MODELS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="not found")

    zone = g.get(model, zone_id, "edit_sites")
    payload = await request.json()

    if "name" in payload:
        new_name = validate_name(payload["name"], "zone name")
        if new_name != zone.name:
            # The name links the zone to its sites, so renaming one in use
            # would break them.
            users = _zone_users(g.session, _setting_for(kind), zone.name)
            if users:
                raise HTTPException(
                    status_code=409,
                    detail=(
                        f"{zone.name} is still used by: {', '.join(users)}.  "
                        f"Point those at something else before renaming it."
                    ),
                )
            claim_name(g.session, model, new_name, "zone", exclude_id=zone.id)
            zone.name = new_name

    if "description" in payload:
        zone.description = (payload.get("description") or "")[:500] or None

    _apply_zone_fields(kind, zone, payload)
    g.session.commit()

    audit.record(f"zone.{kind}.update", user=g.user, object_type="zone",
                 object_name=zone.name, changes=payload)
    return {"ok": True}


@router.delete("/zones/{kind}/{zone_id}")
async def delete_zone(kind: str, zone_id: str, g: ObjectGuard = Depends(changing)):
    model = ZONE_MODELS.get(kind)
    if not model:
        raise HTTPException(status_code=404, detail="not found")

    zone = g.get(model, zone_id, "edit_sites")
    users = _zone_users(g.session, _setting_for(kind), zone.name)
    if users:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{zone.name} is still used by: {', '.join(users)}.  "
                f"nginx will not load a config that points at a zone which is "
                f"not declared, so those have to be changed first."
            ),
        )

    name = zone.name
    g.session.delete(zone)
    g.session.commit()

    audit.record(f"zone.{kind}.delete", user=g.user, object_type="zone", object_name=name)
    return {"ok": True, "deleted": name}


def _setting_for(kind: str) -> str:
    return {
        "rate": "limit_req_zone_name",
        "conn": "limit_conn_zone_name",
        "cache": "proxy_cache_zone",
    }[kind]


def _apply_zone_fields(kind: str, zone, payload: dict):
    import re as _re

    if "key" in payload and kind in ("rate", "conn"):
        key = str(payload["key"]).strip()
        # One or more nginx variables only; this goes into a directive.
        if not _re.fullmatch(r"[$A-Za-z0-9_]{1,120}", key):
            raise HTTPException(
                status_code=400,
                detail="the key has to be an nginx variable like $binary_remote_addr",
            )
        zone.key = key

    for field in ("zone_size", "keys_zone_size", "max_size"):
        if field in payload and hasattr(zone, field):
            value = str(payload[field]).strip()
            if not _re.fullmatch(r"\d+[kKmMgG]?", value):
                raise HTTPException(status_code=400,
                                    detail=f"{field} should look like 10m or 1g")
            setattr(zone, field, value)

    if "rate" in payload and kind == "rate":
        value = str(payload["rate"]).strip()
        if not _re.fullmatch(r"\d+r/[sm]", value):
            raise HTTPException(
                status_code=400,
                detail="the rate should look like 10r/s or 30r/m, requests per second or minute",
            )
        zone.rate = value

    if "inactive" in payload and kind == "cache":
        value = str(payload["inactive"]).strip()
        if not _re.fullmatch(r"\d+[smhd]?", value):
            raise HTTPException(status_code=400, detail="inactive should look like 60m")
        zone.inactive = value

    if "levels" in payload and kind == "cache":
        value = str(payload["levels"]).strip()
        if not _re.fullmatch(r"[12](:[12]){0,2}", value):
            raise HTTPException(status_code=400,
                                detail="levels should look like 1:2")
        zone.levels = value

    if "path" in payload and kind == "cache":
        path = str(payload["path"]).strip()
        if not path.startswith("/") or _re.search(r"[;{}\s]", path):
            raise HTTPException(status_code=400, detail="that is not a valid path")
        # Keep cache paths to known locations so a mistake cannot fill a
        # partition something else depends on.
        if not path.startswith(("/var/cache/", "/srv/", "/data/")):
            raise HTTPException(
                status_code=400,
                detail="cache paths have to be under /var/cache, /srv or /data",
            )
        zone.path = path


# ==============================================================================
# Error page templates
# ==============================================================================

def _error_template_summary(t):
    return {
        "id": t.id,
        "name": t.name,
        "description": t.description,
        "codes": t.code_list(),
        "image_count": len(t.images or []),
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


def _error_template_detail(session, t):
    out = _error_template_summary(t)
    out["html"] = t.html or ""
    out["images"] = [
        {
            "id": i.id,
            "name": i.name,
            "content_type": i.content_type,
            "size_bytes": i.size_bytes,
            "token": "{{image:%s}}" % i.name,
        }
        for i in sorted(t.images or [], key=lambda x: x.name)
    ]
    # Count paths as well as sites; counting only sites made the refusal
    # below miss half the users.
    used = [h.name for h in session.query(VirtualHost)
            .filter(VirtualHost.error_page_template_id == t.id).all()]
    used += [f"{loc.host.name}{loc.path}" for loc in session.query(Location)
             .filter(Location.error_page_template_id == t.id).all()
             if loc.host]
    out["used_by"] = sorted(used)
    out["placeholders"] = [
        {"token": token, "what": what} for token, what in error_pages.PLACEHOLDER_HELP
    ]
    return out


@router.get("/error-pages")
async def list_error_templates(g: ObjectGuard = Depends(guard)):
    return {"templates": [_error_template_summary(t) for t in g.list(ErrorPageTemplate)]}


@router.get("/error-pages/{template_id}")
async def get_error_template(template_id: str, g: ObjectGuard = Depends(guard)):
    return _error_template_detail(g.session, g.get(ErrorPageTemplate, template_id))


@router.get("/error-pages/{template_id}/preview")
async def preview_error_template(template_id: str, code: int = 404,
                                 g: ObjectGuard = Depends(guard)):
    """
    Render one error page exactly as the fleet would.

    Uses the renderer's own function so the preview cannot disagree with the
    real page.  Returned as HTML; see sandboxed_html_headers for what stops it
    running user markup on our origin.
    """
    template = g.get(ErrorPageTemplate, template_id)
    try:
        code = error_pages.valid_codes([code])[0]
        body = error_pages.render_page(
            template, code, error_pages.images_for(template)
        )
    except error_pages.ErrorPageProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except IndexError:
        raise HTTPException(status_code=400, detail="pick a status code to preview")

    return HTMLResponse(content=body, headers=sandboxed_html_headers())


@router.post("/error-pages")
async def create_error_template(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = await request.json()

    name = validate_name(payload.get("name"), "template name")
    claim_name(g.session, ErrorPageTemplate, name, "error page template")

    template = ErrorPageTemplate(
        name=name,
        html=error_pages.starter_html(),
        codes=json.dumps(error_pages.DEFAULT_CODES),
    )
    _apply_error_template_fields(g, template, payload)
    g.session.add(template)
    g.session.commit()

    audit.record("error_page.create", user=g.user, object_type="error_page",
                 object_name=name)
    return _error_template_detail(g.session, template)


@router.put("/error-pages/{template_id}")
async def update_error_template(template_id: str, request: Request,
                                g: ObjectGuard = Depends(changing)):
    template = g.get(ErrorPageTemplate, template_id, "edit_sites")
    payload = await request.json()

    _apply_error_template_fields(g, template, payload)
    g.session.commit()

    audit.record("error_page.update", user=g.user, object_type="error_page",
                 object_name=template.name)
    return _error_template_detail(g.session, template)


@router.delete("/error-pages/{template_id}")
async def delete_error_template(template_id: str, g: ObjectGuard = Depends(changing)):
    template = g.get(ErrorPageTemplate, template_id, "edit_sites")

    # Unlike a pool, a missing template cannot break a site (nginx falls back
    # to its own page).  Still refused, so the person knows it affects those
    # sites.
    users = [h.name for h in g.session.query(VirtualHost)
             .filter(VirtualHost.error_page_template_id == template.id).all()]
    users += [f"{loc.host.name}{loc.path}" for loc in g.session.query(Location)
              .filter(Location.error_page_template_id == template.id).all()
              if loc.host]
    if users:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{template.name} is still used by: {', '.join(sorted(users))}.  "
                f"Those would go back to the stock nginx pages.  Take it off "
                f"them first if that is what you want."
            ),
        )

    name = template.name
    g.session.delete(template)
    g.session.commit()

    audit.record("error_page.delete", user=g.user, object_type="error_page",
                 object_name=name)
    return {"ok": True}


def _apply_error_template_fields(g, template, payload):
    if "name" in payload:
        name = validate_name(payload["name"], "template name")
        claim_name(g.session, ErrorPageTemplate, name, "error page template",
                   exclude_id=template.id)
        template.name = name

    if "description" in payload:
        template.description = (payload.get("description") or "")[:500] or None

    if "codes" in payload:
        try:
            codes = error_pages.valid_codes(payload["codes"])
        except error_pages.ErrorPageProblem as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        if not codes:
            raise HTTPException(
                status_code=400,
                detail=("a template that answers for no status codes never gets "
                        "shown.  Pick at least one."),
            )
        template.codes = json.dumps(codes)

    if "html" in payload:
        body = payload["html"]
        if not isinstance(body, str) or not body.strip():
            raise HTTPException(status_code=400, detail="the page cannot be empty")
        if len(body.encode("utf-8")) > error_pages.MAX_PAGE_BYTES:
            raise HTTPException(
                status_code=400,
                detail=(f"that page is bigger than "
                        f"{error_pages.MAX_PAGE_BYTES // 1024}KB, which is a lot "
                        f"for something you serve when the site is already "
                        f"struggling."),
            )
        template.html = body

    template.updated_by = getattr(g.user, "username", None)


@router.post("/error-pages/{template_id}/images")
async def upload_error_image(template_id: str, request: Request,
                             g: ObjectGuard = Depends(changing)):
    """
    Upload an image for a template.

    The name only ever serves as a lookup key in {{image:...}} and never
    becomes a path; images live in the database and are inlined.
    """
    template = g.get(ErrorPageTemplate, template_id, "edit_sites")
    payload = await request.json()

    name = validate_name(payload.get("name"), "picture name")
    raw_b64 = payload.get("data") or ""
    if not isinstance(raw_b64, str):
        raise HTTPException(status_code=400, detail="send the picture as base64")

    # Strip a data: prefix, which is what a browser FileReader sends.
    if raw_b64.startswith("data:"):
        raw_b64 = raw_b64.split(",", 1)[-1]

    try:
        raw = base64.b64decode(raw_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="that upload is not valid base64")

    try:
        content_type = error_pages.sniff_image(raw, payload.get("filename", ""))
    except error_pages.ErrorPageProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    existing = [i for i in (template.images or []) if i.name != name]
    total = sum(i.size_bytes or 0 for i in existing) + len(raw)
    if total > error_pages.MAX_IMAGES_TOTAL_BYTES:
        raise HTTPException(
            status_code=400,
            detail=(f"that would take this template past "
                    f"{error_pages.MAX_IMAGES_TOTAL_BYTES // 1024}KB of pictures.  "
                    f"They all travel to every node on every apply."),
        )

    # Same name replaces, so a re-uploaded logo does not leave the old one
    # eating the size budget.
    for image in list(template.images or []):
        if image.name == name:
            g.session.delete(image)
    g.session.flush()

    g.session.add(ErrorPageImage(
        template_id=template.id,
        name=name,
        content_type=content_type,
        data=base64.b64encode(raw).decode(),
        size_bytes=len(raw),
    ))
    g.session.commit()

    audit.record("error_page.image.add", user=g.user, object_type="error_page",
                 object_name=f"{template.name}/{name}",
                 changes={"content_type": content_type, "size_bytes": len(raw)})
    g.session.refresh(template)
    return _error_template_detail(g.session, template)


@router.delete("/error-pages/{template_id}/images/{image_id}")
async def delete_error_image(template_id: str, image_id: str,
                             g: ObjectGuard = Depends(changing)):
    template = g.get(ErrorPageTemplate, template_id, "edit_sites")

    image = next((i for i in (template.images or []) if str(i.id) == str(image_id)), None)
    if image is None:
        raise HTTPException(status_code=404, detail="not found")

    name = image.name
    g.session.delete(image)
    g.session.commit()

    audit.record("error_page.image.delete", user=g.user, object_type="error_page",
                 object_name=f"{template.name}/{name}")
    g.session.refresh(template)
    return _error_template_detail(g.session, template)


@router.get("/metrics/members")
async def member_metrics(minutes: int = 60, g: ObjectGuard = Depends(guard)):
    """
    What each pool's backends report about themselves.

    Empty for pools with no metrics URL, which is normal; the page shows
    "not measured" rather than an empty chart that reads as zero.
    """
    g.require("view")
    from app.core.metrics import get_collector

    minutes = max(1, min(int(minutes or 60), 240))
    return {
        "minutes": minutes,
        "pools": get_collector().member_snapshot(with_series=True,
                                                 limit=minutes * 2),
        # Pools set up for metrics, so the page can tell "publishes nothing"
        # from "never asked".
        "configured": _pools_with_metrics(g.session),
    }


def _pools_with_metrics(session):
    out = {}
    for pool in session.query(Pool).all():
        out[pool.name] = bool((pool.setting_map() or {}).get("member_metrics_url"))
    return out


@router.get("/metrics/series")
async def metrics_series(minutes: int = 60, g: ObjectGuard = Depends(guard)):
    """
    The same numbers as /metrics, with history.

    `minutes` is capped by what is kept in memory (a couple of hours); asking
    for more just returns what there is, and the page says how far back it
    goes.
    """
    g.require("view")
    from app.core.metrics import get_collector

    minutes = max(1, min(int(minutes or 60), 240))
    # One sample every fifteen seconds.
    limit = minutes * 4
    return {
        "minutes": minutes,
        "nodes": get_collector().snapshot(with_series=True, limit=limit),
    }


@router.get("/metrics")
async def nginx_metrics(g: ObjectGuard = Depends(guard)):
    """
    Connection and request numbers for every node, with rates.

    Comes from stub_status, where most numbers are counters, so rates come
    from the difference between readings (see app/core/metrics.py).  Per site
    and per backend numbers need access log parsing; that is planned in
    docs/plus-parity.md.
    """
    g.require("view")
    from app.core.metrics import get_collector
    return {"nodes": get_collector().snapshot()}


# ==============================================================================
# GSLB, answering DNS so a name follows the healthy nodes
# ==============================================================================

GSLB_ZONE_FIELDS = {"name", "enabled", "description", "soa_primary",
                    "soa_contact", "soa_refresh", "soa_retry", "soa_expire",
                    "soa_minimum", "nameservers"}
GSLB_RECORD_FIELDS = {"name", "enabled", "description", "record_type", "ttl",
                      "policy", "when_all_down"}
GSLB_ANSWER_FIELDS = {"value", "node_id", "priority", "enabled"}

RECORD_TYPES = ("A", "AAAA", "CNAME")
POLICIES = ("all", "failover")
WHEN_DOWN = ("serve_all", "serve_none")


def _gslb_zone_json(z, session=None):
    return {
        "id": z.id,
        "name": z.name,
        "enabled": z.enabled,
        "description": z.description,
        "soa_primary": z.soa_primary or "",
        "soa_contact": z.soa_contact,
        "soa_refresh": z.soa_refresh,
        "soa_retry": z.soa_retry,
        "soa_expire": z.soa_expire,
        "soa_minimum": z.soa_minimum,
        "soa_serial": z.soa_serial,
        "nameservers": z.nameserver_list(),
        "records": [_gslb_record_json(r) for r in z.records],
    }


def _gslb_record_json(r):
    return {
        "id": r.id,
        "name": r.name,
        "fqdn": r.fqdn(),
        "enabled": r.enabled,
        "description": r.description,
        "record_type": r.record_type,
        "ttl": r.ttl,
        "policy": r.policy,
        "when_all_down": r.when_all_down,
        "answers": [
            {"id": a.id, "value": a.value, "node_id": a.node_id,
             # Use the stored name.  node_id refers to a different machine on
             # any node other than the one that wrote the row.
             "node_name": (a.node_name
                           or (a.node.name if a.node else None)),
             "priority": a.priority, "enabled": a.enabled,
             # Shown next to the answer it is about.
             "address_warning": _answer_warnings().get(a.id)}
            for a in r.answers
        ],
    }


def _answer_warnings():
    """
    Answers whose address does not belong to the node they are tied to.

    Computed once per request and cached on the session, so large zones do
    not walk the node table for every answer.
    """
    from app.core import gslb
    from app.db import session_scope

    with session_scope() as session:
        return {w["answer_id"]: w for w in gslb.answer_address_warnings(session)}


@router.get("/gslb/zones")
async def list_gslb_zones(g: ObjectGuard = Depends(guard)):
    from app.core import gslb

    server = gslb.get_server()
    return {
        "zones": [_gslb_zone_json(z) for z in g.list(GslbZone)],
        # What the listener is actually doing.  A zone in the database is not
        # the same as a zone the world can resolve.
        "server": {
            "listening": bool(server._running),
            "address": server.address,
            "port": server.port,
            "zones_loaded": len(server.data.zones),
            "built_at": server.data.built_at,
            "stats": server.stats,
        },
        # Which nodes would be handed out right now.
        "healthy_nodes": sorted(gslb.healthy_node_names(g.session)),
        # Nodes an answer can be tied to, with the address each would give.
        # The picker needs node ids, which the cluster page does not expose.
        # Split by address family because the record type decides which is
        # valid; a node's public address is often IPv6, which an A record
        # cannot take.
        "nodes": [
            {
                "id": n.id,
                "name": n.name,
                "address_v4": _pick_family(n, 4),
                "address_v6": _pick_family(n, 6),
                "peer_address": n.address,
            }
            for n in g.session.query(Node).order_by(Node.name).all()
        ],
    }


def _pick_family(node, family: int):
    """
    The address of this node to publish in DNS, for one family.

    Prefers the public address, since the peer address is often private and
    would be unreachable from outside.
    """
    for candidate in (node.public_ip, node.address):
        if not candidate:
            continue
        try:
            parsed = ipaddress.ip_address(str(candidate).strip())
        except ValueError:
            continue
        if parsed.version == family:
            return str(parsed)
    return ""


@router.get("/gslb/zones/{zone_id}")
async def get_gslb_zone(zone_id: str, g: ObjectGuard = Depends(guard)):
    return _gslb_zone_json(g.get(GslbZone, zone_id))


@router.post("/gslb/zones")
async def create_gslb_zone(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = pick_fields(await request.json(), GSLB_ZONE_FIELDS)

    name = _gslb_zone_name(payload.get("name"))
    if g.session.query(GslbZone).filter(GslbZone.name == name).first():
        raise HTTPException(status_code=409,
                            detail=f"there is already a zone called {name}")

    zone = GslbZone(name=name)
    _apply_gslb_zone(g, zone, payload)
    g.session.add(zone)
    g.session.commit()

    audit.record("gslb.zone.create", user=g.user, object_type="gslb_zone",
                 object_name=name, changes=payload)
    _gslb_reload()
    return _gslb_zone_json(zone)


@router.put("/gslb/zones/{zone_id}")
async def update_gslb_zone(zone_id: str, request: Request,
                           g: ObjectGuard = Depends(changing)):
    zone = g.get(GslbZone, zone_id, "edit_sites")
    payload = pick_fields(await request.json(), GSLB_ZONE_FIELDS)
    _apply_gslb_zone(g, zone, payload)
    # Bump the serial on every change.  Nothing transfers zones today, but
    # this keeps adding a secondary later possible.
    zone.soa_serial = (zone.soa_serial or 1) + 1
    g.session.commit()

    audit.record("gslb.zone.update", user=g.user, object_type="gslb_zone",
                 object_name=zone.name, changes=payload)
    _gslb_reload()
    return _gslb_zone_json(zone)


@router.delete("/gslb/zones/{zone_id}")
async def delete_gslb_zone(zone_id: str, g: ObjectGuard = Depends(changing)):
    zone = g.get(GslbZone, zone_id, "edit_sites")
    name = zone.name
    g.session.delete(zone)
    g.session.commit()
    audit.record("gslb.zone.delete", user=g.user, object_type="gslb_zone",
                 object_name=name)
    _gslb_reload()
    return {"ok": True, "deleted": name}


def _gslb_zone_name(raw) -> str:
    name = str(raw or "").strip().strip(".").lower()
    if not name or len(name) > 253:
        raise HTTPException(status_code=400, detail="give the zone a name")
    if not hostnames.HOST_RE.match(name) or "." not in name:
        raise HTTPException(
            status_code=400,
            detail=("that is not a domain name.  A zone looks like "
                    "gslb.example.com, and it is nearly always a name below "
                    "one you already own rather than the whole domain."))
    return name


def _apply_gslb_zone(g, zone, payload):
    if "name" in payload:
        name = _gslb_zone_name(payload["name"])
        clash = g.session.query(GslbZone).filter(GslbZone.name == name).first()
        if clash and clash.id != zone.id:
            raise HTTPException(status_code=409,
                                detail=f"there is already a zone called {name}")
        zone.name = name

    if "description" in payload:
        zone.description = (payload.get("description") or "")[:500] or None
    if "enabled" in payload:
        zone.enabled = bool(payload["enabled"])

    for field, low, high in (("soa_refresh", 60, 86400),
                             ("soa_retry", 60, 86400),
                             ("soa_expire", 3600, 2419200),
                             ("soa_minimum", 1, 86400)):
        if field in payload:
            try:
                value = int(payload[field])
            except (TypeError, ValueError):
                raise HTTPException(status_code=400,
                                    detail=f"{field} has to be a number of seconds")
            if not low <= value <= high:
                raise HTTPException(
                    status_code=400,
                    detail=f"{field} has to be between {low} and {high} seconds")
            setattr(zone, field, value)

    for field in ("soa_primary", "soa_contact"):
        if field in payload:
            value = str(payload[field] or "").strip().strip(".")
            if value and not hostnames.HOST_RE.match(value.replace("@", ".")):
                raise HTTPException(status_code=400,
                                    detail=f"{field} does not look like a name")
            setattr(zone, field, value or None)

    if "nameservers" in payload:
        raw = payload["nameservers"]
        if isinstance(raw, str):
            raw = [n.strip() for n in raw.replace(",", " ").split() if n.strip()]
        cleaned = []
        for entry in raw or []:
            name = str(entry).strip().strip(".").lower()
            if not name:
                continue
            if not hostnames.HOST_RE.match(name):
                raise HTTPException(status_code=400,
                                    detail=f"{entry} is not a nameserver name")
            if name not in cleaned:
                cleaned.append(name)
        # Warn rather than refuse, since a zone may be built before its
        # delegation exists.
        zone.nameservers = json.dumps(cleaned)


@router.post("/gslb/zones/{zone_id}/records")
async def create_gslb_record(zone_id: str, request: Request,
                             g: ObjectGuard = Depends(changing)):
    zone = g.get(GslbZone, zone_id, "edit_sites")
    payload = pick_fields(await request.json(), GSLB_RECORD_FIELDS)

    record = GslbRecord(zone_id=zone.id)
    _apply_gslb_record(record, payload)
    g.session.add(record)
    g.session.commit()

    audit.record("gslb.record.create", user=g.user, object_type="gslb_record",
                 object_name=record.fqdn(zone.name), changes=payload)
    _gslb_reload()
    return _gslb_record_json(record)


@router.put("/gslb/records/{record_id}")
async def update_gslb_record(record_id: str, request: Request,
                             g: ObjectGuard = Depends(changing)):
    record = g.get(GslbRecord, record_id, "edit_sites")
    payload = pick_fields(await request.json(), GSLB_RECORD_FIELDS)
    _apply_gslb_record(record, payload)
    g.session.commit()
    audit.record("gslb.record.update", user=g.user, object_type="gslb_record",
                 object_name=record.fqdn(), changes=payload)
    _gslb_reload()
    return _gslb_record_json(record)


@router.delete("/gslb/records/{record_id}")
async def delete_gslb_record(record_id: str, g: ObjectGuard = Depends(changing)):
    record = g.get(GslbRecord, record_id, "edit_sites")
    name = record.fqdn()
    g.session.delete(record)
    g.session.commit()
    audit.record("gslb.record.delete", user=g.user, object_type="gslb_record",
                 object_name=name)
    _gslb_reload()
    return {"ok": True, "deleted": name}


def _apply_gslb_record(record, payload):
    if "name" in payload:
        label = str(payload["name"] or "@").strip().strip(".").lower() or "@"
        if label not in ("@", "*"):
            check = label[2:] if label.startswith("*.") else label
            if not hostnames.HOST_RE.match(check):
                raise HTTPException(
                    status_code=400,
                    detail=("that is not a name.  Use @ for the zone itself, a "
                            "label like www, or * for a wildcard."))
        record.name = label

    if "record_type" in payload:
        value = str(payload["record_type"] or "A").upper()
        if value not in RECORD_TYPES:
            raise HTTPException(status_code=400,
                                detail=f"the type is one of {', '.join(RECORD_TYPES)}")
        record.record_type = value

    if "ttl" in payload:
        try:
            ttl = int(payload["ttl"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="the ttl is a number of seconds")
        if not 1 <= ttl <= 86400:
            raise HTTPException(status_code=400,
                                detail="the ttl has to be between 1 and 86400 seconds")
        record.ttl = ttl

    if "policy" in payload:
        if payload["policy"] not in POLICIES:
            raise HTTPException(status_code=400,
                                detail=f"the policy is one of {', '.join(POLICIES)}")
        record.policy = payload["policy"]

    if "when_all_down" in payload:
        if payload["when_all_down"] not in WHEN_DOWN:
            raise HTTPException(status_code=400,
                                detail="that is not something to do when everything is down")
        record.when_all_down = payload["when_all_down"]

    for field in ("enabled",):
        if field in payload:
            setattr(record, field, bool(payload[field]))
    if "description" in payload:
        record.description = (payload.get("description") or "")[:500] or None


@router.post("/gslb/records/{record_id}/answers")
async def create_gslb_answer(record_id: str, request: Request,
                             g: ObjectGuard = Depends(changing)):
    record = g.get(GslbRecord, record_id, "edit_sites")
    payload = pick_fields(await request.json(), GSLB_ANSWER_FIELDS)

    answer = GslbAnswer(record_id=record.id)
    _apply_gslb_answer(g, record, answer, payload)
    g.session.add(answer)
    g.session.commit()

    audit.record("gslb.answer.add", user=g.user, object_type="gslb_record",
                 object_name=record.fqdn(), changes=payload)
    _gslb_reload()
    # Saved either way.  Pointing an answer at a floating address or at
    # something in front of the node is legitimate, and we cannot tell that
    # from a typo.
    return _gslb_record_json(record)


@router.delete("/gslb/answers/{answer_id}")
async def delete_gslb_answer(answer_id: str, g: ObjectGuard = Depends(changing)):
    answer = g.get(GslbAnswer, answer_id, "edit_sites")
    record = answer.record
    g.session.delete(answer)
    g.session.commit()
    audit.record("gslb.answer.remove", user=g.user, object_type="gslb_record",
                 object_name=record.fqdn() if record else "?")
    _gslb_reload()
    return {"ok": True}


def _apply_gslb_answer(g, record, answer, payload):
    if "value" in payload:
        value = str(payload["value"] or "").strip()
        if not value:
            raise HTTPException(status_code=400, detail="an answer needs a value")

        if record.record_type in ("A", "AAAA"):
            try:
                parsed = ipaddress.ip_address(value)
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail=f"an {record.record_type} answer has to be an address")
            wanted = 4 if record.record_type == "A" else 6
            if parsed.version != wanted:
                raise HTTPException(
                    status_code=400,
                    detail=(f"that is an IPv{parsed.version} address and this is an "
                            f"{record.record_type} record, which carries IPv{wanted}"))
        else:
            if not hostnames.HOST_RE.match(value.strip(".")):
                raise HTTPException(status_code=400,
                                    detail="a CNAME answer has to be a name")
        answer.value = value

    if "node_id" in payload:
        node_id = payload["node_id"]
        if node_id in (None, "", 0):
            answer.node_id = None
            answer.node_name = None
        else:
            node = g.get(Node, node_id)
            answer.node_id = node.id
            # The name is what survives replication; the id is only for this
            # node's own pages.
            answer.node_name = node.name

    if "priority" in payload:
        try:
            answer.priority = max(0, min(int(payload["priority"]), 65535))
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="the priority is a number")

    if "enabled" in payload:
        answer.enabled = bool(payload["enabled"])

    if record.record_type == "CNAME":
        others = [a for a in record.answers if a.id != answer.id]
        if others:
            raise HTTPException(
                status_code=409,
                detail=("a CNAME can only have one answer.  That is the rule in "
                        "DNS itself, not ours: a name is either an alias for one "
                        "other name or it is not an alias."))


def _gslb_reload():
    """
    Rebuild the listener's snapshot now instead of waiting up to ten seconds
    for the timer, so a dig right after saving shows the new answer.
    """
    try:
        from app.core import gslb

        gslb.refresh()
        server = gslb.get_server()
        if server.data.zones and not server._running:
            server.start()
    except Exception as exc:
        log.error("could not reload the gslb zones: %s", exc)

    _publish_gslb()


def _publish_gslb():
    """
    Send the zones to the other nodes.

    The DNS listener answers from the database, not from nginx files.  Rows
    travel between nodes with the config snapshot, which only ships when the
    rendered nginx config changes, and a DNS edit changes no nginx file.  So
    without this the zones stayed on one node, and the node meant to take
    over when it died answered nothing.

    Forced, because the renderer reports "nothing changed" for a DNS edit.
    """
    async def _go():
        try:
            await apply_current_config(
                author="system",
                summary="dns zones changed, sending them to the other nodes",
                force=True,
            )
        except Exception as exc:
            log.error("could not send the dns zones to the other nodes: %s", exc)

    try:
        asyncio.get_running_loop().create_task(_go())
    except RuntimeError:
        # No loop means a script or test, not a request.  The local listener
        # is current and other nodes catch up at the next apply.
        log.debug("no event loop, so the dns zones were not pushed from here")



# ==============================================================================
# Paid certificate authorities
# ==============================================================================

AUTHORITY_FIELDS = {"name", "description", "directory_url", "eab_kid",
                    "eab_hmac_key", "preferred_chain", "enabled"}


def _authority_json(a):
    return {
        "id": a.id,
        "name": a.name,
        "description": a.description,
        "directory_url": a.directory_url,
        "eab_kid": a.eab_kid,
        # Never the key itself, only whether one is stored.
        "eab_hmac_key_set": bool(a.eab_hmac_key_encrypted),
        "preferred_chain": a.preferred_chain,
        "enabled": a.enabled,
        "in_use_by": [c.name for c in a.certificates],
        "last_tested_at": a.last_tested_at.isoformat() if a.last_tested_at else None,
        "last_test_ok": a.last_test_ok,
        "last_test_error": a.last_test_error,
    }


@router.get("/authorities")
async def list_authorities(g: ObjectGuard = Depends(guard)):
    return {"authorities": [_authority_json(a)
                            for a in g.list(CertificateAuthority)]}


@router.post("/authorities")
async def create_authority(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_certs")
    payload = pick_fields(await request.json(), AUTHORITY_FIELDS)
    authority = CertificateAuthority()
    _apply_authority(g, authority, payload, creating=True)
    g.session.add(authority)
    g.session.commit()
    audit.record("authority.create", user=g.user, object_type="authority",
                 object_name=authority.name)
    return _authority_json(authority)


@router.put("/authorities/{authority_id}")
async def update_authority(authority_id: str, request: Request,
                           g: ObjectGuard = Depends(changing)):
    g.require("edit_certs")
    authority = g.get(CertificateAuthority, authority_id)
    payload = pick_fields(await request.json(), AUTHORITY_FIELDS)
    _apply_authority(g, authority, payload)
    g.session.commit()
    audit.record("authority.update", user=g.user, object_type="authority",
                 object_name=authority.name, changes=list(payload))
    return _authority_json(authority)


@router.delete("/authorities/{authority_id}")
async def delete_authority(authority_id: str, g: ObjectGuard = Depends(changing)):
    g.require("edit_certs")
    authority = g.get(CertificateAuthority, authority_id)
    # Refused rather than cascaded.  A certificate whose authority is gone
    # cannot renew, and would not say so until the renewal.
    if authority.certificates:
        names = ", ".join(c.name for c in authority.certificates)
        raise HTTPException(
            status_code=409,
            detail=(f"{authority.name} issued {names}, so it cannot be removed "
                    f"while those exist.  Renewal needs the authority that "
                    f"issued them."))
    name = authority.name
    g.session.delete(authority)
    g.session.commit()
    audit.record("authority.delete", user=g.user, object_type="authority",
                 object_name=name)
    return {"ok": True, "deleted": name}


@router.post("/authorities/{authority_id}/test")
async def test_authority(authority_id: str, g: ObjectGuard = Depends(changing)):
    """
    Register an account with this authority and keep only the result.

    Bad EAB credentials look fine when typed and only fail at first use,
    months later at renewal.  This surfaces the problem while someone is
    still looking.
    """
    g.require("edit_certs")
    authority = g.get(CertificateAuthority, authority_id)

    from app.core.acme import test_authority_credentials

    result = await test_authority_credentials(authority)
    authority.last_tested_at = utcnow()
    authority.last_test_ok = bool(result.get("ok"))
    authority.last_test_error = (result.get("error") or "")[:2000] or None
    g.session.commit()

    audit.record("authority.test", user=g.user, object_type="authority",
                 object_name=authority.name,
                 changes={"ok": authority.last_test_ok})
    return _authority_json(authority)


def _apply_authority(g, authority, payload, creating=False):
    from app.core.crypto import encrypt

    if "name" in payload or creating:
        name = str(payload.get("name") or "").strip()
        if not name:
            raise HTTPException(status_code=400, detail="give the authority a name")
        clash = g.session.query(CertificateAuthority).filter(
            CertificateAuthority.name == name).first()
        if clash and clash.id != authority.id:
            raise HTTPException(status_code=409,
                                detail=f"there is already an authority called {name}")
        authority.name = name

    if "directory_url" in payload or creating:
        url = str(payload.get("directory_url") or "").strip()
        if not url.startswith("https://"):
            raise HTTPException(
                status_code=400,
                detail="the directory address has to start with https://")
        authority.directory_url = url

    if "eab_kid" in payload:
        authority.eab_kid = str(payload["eab_kid"] or "").strip() or None

    if "eab_hmac_key" in payload:
        value = str(payload["eab_hmac_key"] or "").strip()
        # Blank keeps the stored key, so editing the name does not require
        # re-entering it.
        if value:
            authority.eab_hmac_key_encrypted = encrypt(value)

    if "preferred_chain" in payload:
        authority.preferred_chain = str(payload["preferred_chain"] or "").strip() or None

    if "description" in payload:
        authority.description = (payload.get("description") or "")[:500] or None

    if "enabled" in payload:
        authority.enabled = bool(payload["enabled"])


# ==============================================================================
# Map blocks, which is nginx's lookup table
# ==============================================================================

# Variables a map may read.  nginx rejects an unknown source variable at load
# time on every node, blocking the whole fleet, so we check at save time.
MAP_SOURCE_VARIABLES = {
    "$host", "$hostname", "$http_host", "$https", "$scheme", "$request_method",
    "$request_uri", "$uri", "$document_uri", "$args", "$query_string",
    "$remote_addr", "$remote_port", "$remote_user", "$server_addr",
    "$server_name", "$server_port", "$server_protocol", "$request_length",
    "$content_type", "$content_length", "$status", "$body_bytes_sent",
    "$bytes_sent", "$connection", "$connection_requests", "$msec",
    "$request_time", "$time_iso8601", "$time_local", "$is_args", "$pid",
    "$realpath_root", "$request_filename", "$document_root",
    "$ssl_protocol", "$ssl_cipher", "$ssl_server_name", "$ssl_session_reused",
    "$ssl_client_verify", "$ssl_client_s_dn", "$ssl_client_i_dn",
    "$proxy_protocol_addr", "$proxy_protocol_port",
    "$binary_remote_addr", "$geoip_country_code", "$http_user_agent",
    "$http_referer", "$http_cookie", "$http_x_forwarded_for",
    "$upstream_addr", "$upstream_status", "$upstream_response_time",
}

# Variable families where any suffix is valid (nginx creates them on demand).
MAP_SOURCE_PREFIXES = (
    "$http_", "$arg_", "$cookie_", "$sent_http_", "$upstream_http_",
    "$upstream_cookie_", "$ssl_", "$geoip_", "$proxy_protocol_tlv_",
)

# Names a map must not produce, because nginx already defines them and its
# error ("the duplicate variable") says nothing about maps.
MAP_RESERVED_RESULTS = {
    v.lstrip("$") for v in MAP_SOURCE_VARIABLES
} | {"args", "uri", "host", "status", "scheme", "request", "document_uri"}

MAP_FIELDS = {"name", "description", "source_variable", "result_variable",
              "default_value", "entries", "hostnames"}


def _map_json(m):
    return {
        "id": m.id,
        "name": m.name,
        "description": m.description,
        "source_variable": m.source_variable,
        "result_variable": m.result_variable,
        "default_value": m.default_value or "",
        "hostnames": m.hostnames,
        "entries": m.entry_list(),
    }


def _known_source(value: str) -> bool:
    if value in MAP_SOURCE_VARIABLES:
        return True
    if any(value.startswith(p) and len(value) > len(p) for p in MAP_SOURCE_PREFIXES):
        return True
    return False


@router.get("/maps")
async def list_maps(g: ObjectGuard = Depends(guard)):
    return {
        "maps": [_map_json(m) for m in g.list(MapBlock)],
        # Offered in the page so nobody has to guess.
        "sources": sorted(MAP_SOURCE_VARIABLES),
        "prefixes": list(MAP_SOURCE_PREFIXES),
    }


@router.get("/maps/{map_id}")
async def get_map(map_id: str, g: ObjectGuard = Depends(guard)):
    return _map_json(g.get(MapBlock, map_id))


@router.post("/maps")
async def create_map(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = pick_fields(await request.json(), MAP_FIELDS)

    name = validate_name(payload.get("name"), "map name")
    claim_name(g.session, MapBlock, name, "map")

    block = MapBlock(name=name, source_variable="$host", result_variable="x")
    _apply_map_fields(g, block, payload)
    g.session.add(block)
    g.session.commit()

    audit.record("map.create", user=g.user, object_type="map", object_name=name,
                 changes=payload)
    return _map_json(block)


@router.put("/maps/{map_id}")
async def update_map(map_id: str, request: Request,
                     g: ObjectGuard = Depends(changing)):
    block = g.get(MapBlock, map_id, "edit_sites")
    payload = pick_fields(await request.json(), MAP_FIELDS)

    before = _map_json(block)
    _apply_map_fields(g, block, payload)
    g.session.commit()

    audit.record("map.update", user=g.user, object_type="map",
                 object_name=block.name,
                 changes=audit.diff_fields(before, _map_json(block)))
    return _map_json(block)


@router.delete("/maps/{map_id}")
async def delete_map(map_id: str, g: ObjectGuard = Depends(changing)):
    block = g.get(MapBlock, map_id, "edit_sites")

    # nginx will not start if a variable in use has no map.  We cannot
    # reliably see into raw config or setting text, so we report what we find
    # rather than refusing.
    variable = "$" + (block.result_variable or "").lstrip("$")
    users = []
    for host in g.session.query(VirtualHost).all():
        haystack = (host.custom_config or "") + json.dumps(host.setting_map())
        if variable in haystack:
            users.append(host.name)
    for loc in g.session.query(Location).all():
        haystack = (loc.custom_config or "") + json.dumps(loc.setting_map())
        if variable in haystack and loc.host:
            users.append(f"{loc.host.name}{loc.path}")

    if users:
        raise HTTPException(
            status_code=409,
            detail=(f"{variable} is still used by: {', '.join(sorted(set(users)))}.  "
                    f"nginx will not start with a variable nothing sets, so take "
                    f"it out of those first."))

    name = block.name
    g.session.delete(block)
    g.session.commit()

    audit.record("map.delete", user=g.user, object_type="map", object_name=name)
    return {"ok": True, "deleted": name}


def _apply_map_fields(g, block, payload):
    if "name" in payload:
        name = validate_name(payload["name"], "map name")
        claim_name(g.session, MapBlock, name, "map", exclude_id=block.id)
        block.name = name

    if "description" in payload:
        block.description = (payload.get("description") or "")[:500] or None

    if "source_variable" in payload:
        source = str(payload["source_variable"] or "").strip()
        if not source.startswith("$"):
            source = "$" + source
        if not re.fullmatch(r"\$[A-Za-z0-9_]{1,64}", source):
            raise HTTPException(
                status_code=400,
                detail="a variable is a dollar sign and then letters, numbers and underscores")
        if not _known_source(source):
            raise HTTPException(
                status_code=400,
                detail=(f"nginx does not know a variable called {source}.  It "
                        f"refuses to start on an unknown one, which would stop "
                        f"every node applying anything, so it is refused here "
                        f"instead.  The page lists the ones that work."))
        block.source_variable = source

    if "result_variable" in payload:
        result = str(payload["result_variable"] or "").strip().lstrip("$")
        if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]{0,63}", result):
            raise HTTPException(
                status_code=400,
                detail="the name it sets has to be letters, numbers and underscores")
        if result in MAP_RESERVED_RESULTS:
            raise HTTPException(
                status_code=400,
                detail=(f"nginx already has a variable called ${result}, and a "
                        f"map cannot take a name that is taken.  It says "
                        f'"the duplicate variable" and will not start.'))
        # nginx accepts two maps writing one variable and silently uses one.
        for other in g.session.query(MapBlock).all():
            if other.id == block.id:
                continue
            if (other.result_variable or "").lstrip("$") == result:
                raise HTTPException(
                    status_code=409,
                    detail=(f"the map {other.name} already sets ${result}.  nginx "
                            f"takes one of them without saying which, so this is "
                            f"refused rather than left to surprise somebody."))
        block.result_variable = result

    if "default_value" in payload:
        block.default_value = _check_map_text(payload["default_value"], "the default")

    if "hostnames" in payload:
        block.hostnames = bool(payload["hostnames"])

    if "entries" in payload:
        raw = payload["entries"]
        if not isinstance(raw, list):
            raise HTTPException(status_code=400, detail="entries has to be a list")
        if len(raw) > 2000:
            raise HTTPException(
                status_code=400,
                detail="that is more than 2000 entries, which wants a file rather than a form")

        clean, seen = [], set()
        for row in raw:
            if not isinstance(row, dict):
                raise HTTPException(status_code=400, detail="each entry is an object")
            match = _check_map_text(row.get("match"), "a match")
            value = _check_map_text(row.get("value"), "a value")
            if not match:
                continue
            if match in seen:
                # nginx uses the first and ignores the rest, so the second
                # entry would never fire.
                raise HTTPException(
                    status_code=409,
                    detail=(f"{match} is in this map twice.  nginx uses the first "
                            f"one and the other never fires."))
            seen.add(match)
            clean.append({"match": match, "value": value})
        block.entries = json.dumps(clean)


def _check_map_text(value, what):
    """
    Check a map match or value the way the renderer will write it.

    Backslashes are allowed since most maps are regexes.  Refused is anything
    that would end the directive early or break out of the quotes; see
    map_value in render.py.
    """
    text = "" if value is None else str(value).strip()
    if re.search(r"[;{}\n\r]", text):
        raise HTTPException(
            status_code=400,
            detail=f"{what} cannot contain a semicolon, a brace or a newline")
    trailing = len(text) - len(text.rstrip("\\"))
    if trailing % 2:
        raise HTTPException(
            status_code=400,
            detail=(f"{what} ends in a single backslash, which would run past the "
                    f"end of the line.  A regular expression cannot end that way "
                    f"either."))
    if len(text) > 500:
        raise HTTPException(status_code=400, detail=f"{what} is too long")
    return text


# ==============================================================================
# Streams, which is plain TCP and UDP with no http anywhere
# ==============================================================================

STREAM_FIELDS = {
    "name", "enabled", "listen_port", "listen_address", "protocol",
    "proxy_protocol", "pool_id", "ssl_enabled", "cert_id", "settings",
    "access_list_id", "custom_config",
}

# Ports the manager itself listens on.  Giving one to a stream would cut off
# the GUI.
def _reserved_ports():
    settings = get_settings()
    return {
        settings.gui_port: "the GUI",
        settings.peer_port: "the port the nodes talk to each other on",
        7081: "the nginx status endpoint",
    }


def _stream_json(s):
    return {
        "id": s.id,
        "name": s.name,
        "enabled": s.enabled,
        "listen_address": s.listen_address,
        "listen_port": s.listen_port,
        "protocol": "udp" if (s.udp or s.protocol == "udp") else "tcp",
        "proxy_protocol": s.proxy_protocol,
        "pool_id": s.pool_id,
        "pool_name": s.pool.name if s.pool else None,
        "ssl_enabled": s.ssl_enabled,
        "cert_id": s.cert_id,
        "access_list_id": s.access_list_id,
        "settings": s.setting_map(),
        "custom_config": s.custom_config,
    }


@router.get("/streams")
async def list_streams(g: ObjectGuard = Depends(guard)):
    have_stream = True
    try:
        have_stream = fleet_capabilities().has("stream")
    except Exception:
        pass
    return {
        "streams": [_stream_json(s) for s in g.list(StreamServer)],
        # nginx needs --with-stream.  The installer builds it that way, but a
        # binary from elsewhere may not have it.
        "supported": have_stream,
    }


@router.get("/streams/{stream_id}")
async def get_stream(stream_id: str, g: ObjectGuard = Depends(guard)):
    return _stream_json(g.get(StreamServer, stream_id))


@router.post("/streams")
async def create_stream(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = pick_fields(await request.json(), STREAM_FIELDS)

    name = validate_name(payload.get("name"), "stream name")
    claim_name(g.session, StreamServer, name, "stream")

    stream = StreamServer(name=name, listen_port=0)
    _apply_stream_fields(g, stream, payload)
    g.session.add(stream)
    g.session.commit()

    audit.record("stream.create", user=g.user, object_type="stream",
                 object_name=name, changes=payload)
    return _stream_json(stream)


@router.put("/streams/{stream_id}")
async def update_stream(stream_id: str, request: Request,
                        g: ObjectGuard = Depends(changing)):
    stream = g.get(StreamServer, stream_id, "edit_sites")
    payload = pick_fields(await request.json(), STREAM_FIELDS)

    before = _stream_json(stream)
    _apply_stream_fields(g, stream, payload)
    g.session.commit()

    audit.record("stream.update", user=g.user, object_type="stream",
                 object_name=stream.name,
                 changes=audit.diff_fields(before, _stream_json(stream)))
    return _stream_json(stream)


@router.delete("/streams/{stream_id}")
async def delete_stream(stream_id: str, g: ObjectGuard = Depends(changing)):
    stream = g.get(StreamServer, stream_id, "edit_sites")
    name = stream.name
    g.session.delete(stream)
    g.session.commit()

    audit.record("stream.delete", user=g.user, object_type="stream",
                 object_name=name)
    return {"ok": True, "deleted": name}


def _apply_stream_fields(g, stream, payload):
    if "name" in payload:
        name = validate_name(payload["name"], "stream name")
        claim_name(g.session, StreamServer, name, "stream", exclude_id=stream.id)
        stream.name = name

    if "protocol" in payload:
        proto = str(payload["protocol"]).lower()
        if proto not in ("tcp", "udp"):
            raise HTTPException(status_code=400, detail="it is tcp or udp")
        stream.protocol = proto
        # The model has both a protocol column and a udp flag, and the
        # renderer reads either, so keep them in sync here.
        stream.udp = proto == "udp"

    if "listen_port" in payload:
        try:
            port = int(payload["listen_port"])
        except (TypeError, ValueError):
            raise HTTPException(status_code=400, detail="that is not a port number")
        if not 1 <= port <= 65535:
            raise HTTPException(status_code=400, detail="a port is 1 to 65535")

        reserved = _reserved_ports()
        if port in reserved:
            raise HTTPException(
                status_code=400,
                detail=(f"port {port} is {reserved[port]}.  Taking it would cut "
                        f"you off from the thing you are using to take it."))

        # A site on the same port makes nginx refuse to start, which would
        # block every apply on the fleet.
        clash = g.session.query(VirtualHost).filter(
            VirtualHost.enabled.is_(True)).all()
        for host in clash:
            if host.listen_http and host.http_port == port:
                raise HTTPException(
                    status_code=409,
                    detail=(f"the site {host.name} already listens on {port}.  "
                            f"nginx will not start with two things on one port."))
            if host.listen_https and host.https_port == port:
                raise HTTPException(
                    status_code=409,
                    detail=(f"the site {host.name} already listens on {port} for "
                            f"https.  nginx will not start with two things on one port."))
        stream.listen_port = port

    if "listen_address" in payload:
        addr = str(payload["listen_address"] or "0.0.0.0").strip()
        if addr not in ("0.0.0.0", "[::]", "::"):
            try:
                ipaddress.ip_address(addr.strip("[]"))
            except ValueError:
                raise HTTPException(
                    status_code=400,
                    detail="that has to be an address on this box, or 0.0.0.0 for all of them")
        stream.listen_address = addr

    # Same for two streams on one address and port.
    port = stream.listen_port
    proto = "udp" if stream.udp else "tcp"
    for other in g.session.query(StreamServer).all():
        if other.id == stream.id or not other.enabled:
            continue
        other_proto = "udp" if (other.udp or other.protocol == "udp") else "tcp"
        if (other.listen_port == port and other_proto == proto
                and other.listen_address == stream.listen_address):
            raise HTTPException(
                status_code=409,
                detail=(f"{other.name} already listens on "
                        f"{stream.listen_address}:{port} for {proto}."))

    for field, model in (("pool_id", Pool), ("cert_id", Certificate),
                         ("access_list_id", AccessList)):
        if field in payload:
            value = payload[field]
            if value in (None, "", 0):
                setattr(stream, field, None)
            else:
                setattr(stream, field, g.get(model, value).id)

    for field in ("enabled", "proxy_protocol", "ssl_enabled"):
        if field in payload:
            setattr(stream, field, bool(payload[field]))

    if "custom_config" in payload:
        stream.custom_config = payload["custom_config"] or None

    if "settings" in payload:
        raw = payload["settings"] or {}
        if not isinstance(raw, dict):
            raise HTTPException(status_code=400, detail="settings has to be an object")
        clean = {}
        # Short list on purpose.  Most of the catalog is http-only, so streams
        # take these few settings plus hand written config for anything else.
        for key in ("proxy_timeout", "proxy_connect_timeout"):
            value = str(raw.get(key) or "").strip()
            if not value:
                continue
            if not re.fullmatch(r"\d+[smhd]?", value):
                raise HTTPException(
                    status_code=400,
                    detail=f"{key} looks like 60s, 5m or 1h")
            clean[key] = value

        # TLS settings do apply to streams.  A stream with no list keeps its
        # existing version pair; setting one here changes it, as for a site.
        if raw.get("ssl_protocols"):
            wanted = raw["ssl_protocols"]
            if isinstance(wanted, str):
                wanted = wanted.split()
            if not isinstance(wanted, list):
                raise HTTPException(
                    status_code=400,
                    detail="ssl_protocols is a list like [\"TLSv1.2\", \"TLSv1.3\"]")
            allowed = ("TLSv1", "TLSv1.1", "TLSv1.2", "TLSv1.3")
            picked = [str(p).strip() for p in wanted if str(p).strip()]
            bad = [p for p in picked if p not in allowed]
            if bad:
                raise HTTPException(
                    status_code=400,
                    detail=f"{', '.join(bad)}: it is one of {', '.join(allowed)}")
            if not picked:
                raise HTTPException(
                    status_code=400,
                    detail=("a stream doing TLS needs at least one version.  "
                            "Turn TLS off instead of emptying the list."))
            # Always in version order, so equivalent lists render the same.
            clean["ssl_protocols"] = [p for p in allowed if p in picked]

        for key in ("ssl_post_quantum", "ssl_post_quantum_only"):
            if key in raw:
                clean[key] = bool(raw[key])

        stream.settings = json.dumps(clean)

    if stream.ssl_enabled and not stream.cert_id:
        raise HTTPException(
            status_code=400,
            detail=("a stream doing TLS needs a certificate.  Pick one, or turn "
                    "TLS off and let the backend handle it."))


# ---- access lists ------------------------------------------------------------

@router.post("/access-lists")
async def create_access_list(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_access_lists")
    payload = await request.json()

    name = validate_name(payload.get("name"), "access list name")
    claim_name(g.session, AccessList, name, "access list")

    acl = AccessList(name=name)
    _apply_acl_fields(acl, payload)
    g.session.add(acl)
    g.session.commit()

    audit.record("access_list.create", user=g.user, object_type="access_list",
                 object_name=name, changes=payload)
    return {"id": acl.id, "name": acl.name}


@router.put("/access-lists/{acl_id}")
async def update_access_list(acl_id: str, request: Request,
                             g: ObjectGuard = Depends(changing)):
    acl = g.get(AccessList, acl_id, "edit_access_lists")
    payload = await request.json()

    if "name" in payload:
        name = validate_name(payload["name"], "access list name")
        claim_name(g.session, AccessList, name, "access list", exclude_id=acl.id)
        acl.name = name
    _apply_acl_fields(acl, payload)
    g.session.commit()

    audit.record("access_list.update", user=g.user, object_type="access_list",
                 object_name=acl.name, changes=payload)
    return {"ok": True}


@router.delete("/access-lists/{acl_id}")
async def delete_access_list(acl_id: str, g: ObjectGuard = Depends(changing)):
    acl = g.get(AccessList, acl_id, "edit_access_lists")

    # Check everything that can use an access list, not just sites.  Checking
    # only sites let a list protecting a path (the usual setup for an admin
    # area) or a stream be deleted, and the next render silently dropped its
    # rules, leaving the path public.
    used_by = [h.name for h in g.session.query(VirtualHost)
               .filter(VirtualHost.access_list_id == acl.id).all()]
    used_by += [f"{loc.host.name}{loc.path}" if loc.host else f"path {loc.path}"
                for loc in g.session.query(Location)
                .filter(Location.access_list_id == acl.id).all()]
    used_by += [f"stream {s.name}" for s in g.session.query(StreamServer)
                .filter(StreamServer.access_list_id == acl.id).all()]
    if used_by:
        raise HTTPException(
            status_code=409,
            detail=f"still used by: {', '.join(used_by)}",
        )

    name = acl.name
    g.session.delete(acl)
    g.session.commit()
    audit.record("access_list.delete", user=g.user, object_type="access_list",
                 object_name=name)
    return {"ok": True, "deleted": name}


def _apply_acl_fields(acl, payload: dict):
    for field, attr in (("allow", "allow_entries"), ("deny", "deny_entries")):
        if field in payload:
            entries = payload[field]
            if isinstance(entries, str):
                entries = [e.strip() for e in entries.replace(",", "\n").splitlines() if e.strip()]
            for entry in entries:
                validate_cidr(entry)
            setattr(acl, attr, json.dumps(entries))

    if "default_action" in payload:
        if payload["default_action"] not in ("allow", "deny"):
            raise HTTPException(status_code=400, detail="default action is allow or deny")
        acl.default_action = payload["default_action"]

    for field in ("include_management", "basic_auth_enabled", "use_real_ip"):
        if field in payload:
            setattr(acl, field, bool(payload[field]))

    if "basic_auth_realm" in payload:
        realm = str(payload["basic_auth_realm"])[:255]
        import re as _re

        if _re.search(r'["\n\r;{}]', realm):
            raise HTTPException(status_code=400, detail="that realm has characters we cannot use")
        acl.basic_auth_realm = realm or "Restricted"

    if "real_ip_header" in payload:
        if payload["real_ip_header"] not in ("X-Forwarded-For", "X-Real-IP", "CF-Connecting-IP"):
            raise HTTPException(status_code=400, detail="that real ip header is not one we write")
        acl.real_ip_header = payload["real_ip_header"]

    if "real_ip_from" in payload:
        proxies = payload["real_ip_from"]
        if isinstance(proxies, str):
            proxies = [p.strip() for p in proxies.replace(",", "\n").splitlines() if p.strip()]
        for proxy in proxies:
            validate_cidr(proxy)
        acl.real_ip_from = json.dumps(proxies)

    # Refuse "use the forwarded address" with no trusted sources.  Without a
    # set_real_ip_from line nginx ignores the header, so rules apply to the
    # connecting address (e.g. the CDN's) while the page says otherwise.
    # Only checked when this save touches those fields, so an unrelated edit
    # to a list already in this state is not refused.
    touched = "use_real_ip" in payload or "real_ip_from" in payload
    if touched and acl.use_real_ip and not acl.trusted_proxies():
        raise HTTPException(
            status_code=400,
            detail="trusting a forwarded address needs at least one trusted "
                   "proxy, or the header is ignored and the setting does "
                   "nothing.  Add the address of whatever sits in front, or "
                   "turn the setting off.")

    # Basic auth users.  Only the hash is stored.
    if "add_user" in payload:
        entry = payload["add_user"] or {}
        username = str(entry.get("username", "")).strip()
        password = entry.get("password") or ""

        import re as _re

        if not _re.fullmatch(r"[A-Za-z0-9._@-]{1,64}", username):
            raise HTTPException(status_code=400, detail="that username is not valid")
        if len(password) < 8:
            raise HTTPException(status_code=400,
                                detail="a basic auth password should be at least 8 characters")

        users = acl.auth_users()
        users = [u for u in users if u.get("username") != username]
        users.append({"username": username, "hash": _htpasswd_hash(password)})
        acl.basic_auth_users = json.dumps(users)

    if "remove_user" in payload:
        target = str(payload["remove_user"])
        acl.basic_auth_users = json.dumps(
            [u for u in acl.auth_users() if u.get("username") != target]
        )


def _htpasswd_hash(password: str) -> str:
    """
    Hash a basic auth password in APR1, the htpasswd default nginx reads.

    Not a strong hash by modern standards, but that is the format.  Basic auth
    is a speed bump on top of the IP rules, and the help text says so.
    """
    import base64
    import hashlib
    import os as _os

    salt = base64.b64encode(_os.urandom(6)).decode()[:8].replace("+", ".")
    magic = "$apr1$"

    text = (password + magic + salt).encode()
    bin_hash = hashlib.md5((password + salt + password).encode()).digest()

    for i in range(len(password), 0, -16):
        text += bin_hash[:min(16, i)]

    i = len(password)
    while i:
        text += bytes([0]) if i & 1 else password[0].encode()
        i >>= 1

    bin_hash = hashlib.md5(text).digest()

    for i in range(1000):
        chunk = b""
        chunk += password.encode() if i & 1 else bin_hash
        if i % 3:
            chunk += salt.encode()
        if i % 7:
            chunk += password.encode()
        chunk += bin_hash if i & 1 else password.encode()
        bin_hash = hashlib.md5(chunk).digest()

    itoa64 = "./0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    out = ""
    for a, b, c in ((0, 6, 12), (1, 7, 13), (2, 8, 14), (3, 9, 15), (4, 10, 5)):
        v = (bin_hash[a] << 16) | (bin_hash[b] << 8) | bin_hash[c]
        for _ in range(4):
            out += itoa64[v & 0x3F]
            v >>= 6
    v = bin_hash[11]
    for _ in range(2):
        out += itoa64[v & 0x3F]
        v >>= 6

    return f"{magic}{salt}${out}"


# ==============================================================================
# Rebuilding nginx
# ==============================================================================

@router.get("/upgrade/plan")
async def upgrade_plan(request: Request, nginx_version: str = None,
                       openssl_version: str = None,
                       g: ObjectGuard = Depends(guard)):
    """What a rebuild would do, before committing to a long build."""
    g.require("upgrade_nginx")
    from app.core.upgrade import get_upgrade_runner

    return await get_upgrade_runner().plan(nginx_version, openssl_version)


@router.get("/upgrade/status")
async def upgrade_status(g: ObjectGuard = Depends(guard)):
    g.require("upgrade_nginx")
    from app.core.upgrade import get_upgrade_runner

    return dict(get_upgrade_runner().state)


@router.post("/upgrade/start")
async def upgrade_start(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("upgrade_nginx")
    from app.core.upgrade import UpgradeError, get_upgrade_runner

    payload = await request.json() if await request.body() else {}

    # The WAF module is a build option, so it is set here.  Stored before the
    # rolling rebuild starts because every node reads it as it goes, and the
    # fleet must agree on it.
    if "with_modsecurity" in payload:
        settings_store.set("waf_module", bool(payload["with_modsecurity"]),
                           actor=g.user.username)

    try:
        result = await get_upgrade_runner().start(
            nginx_version=(payload.get("nginx_version") or "").strip() or None,
            openssl_version=(payload.get("openssl_version") or "").strip() or None,
            actor=g.user.username,
            force=bool(payload.get("force")),
        )
    except UpgradeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit.record("nginx.upgrade.requested", user=g.user, object_type="fleet",
                 changes={"nginx": payload.get("nginx_version"),
                          "openssl": payload.get("openssl_version"),
                          "waf_module": payload.get("with_modsecurity")})
    return result


@router.post("/upgrade/revert")
async def upgrade_revert(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("upgrade_nginx")
    from app.core.upgrade import UpgradeError, get_upgrade_runner

    payload = await request.json()
    node = payload.get("node")
    if not node:
        raise HTTPException(status_code=400, detail="which node")

    try:
        return await get_upgrade_runner().revert(node)
    except UpgradeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.get("/upgrade/modules")
async def upgrade_modules(g: ObjectGuard = Depends(guard)):
    """
    What each node was built with, and where they differ.  Lives next to the
    upgrade page because adding a module means rebuilding.
    """
    g.require("view")
    from app.core.capabilities import fleet_capabilities, module_differences

    caps = fleet_capabilities()
    diff = module_differences()

    return {
        "common": sorted(caps.modules),
        "common_count": len(caps.modules),
        "third_party": caps.third_party,
        "differences": diff,
        "nginx_version": caps.nginx_version,
        "openssl_version": caps.openssl_version,
        "post_quantum": caps.supports_post_quantum(),
        # So the checkbox reflects the current setting rather than defaulting
        # to off and dropping the module on the next rebuild.
        "waf_module": bool(settings_store.get("waf_module")),
    }


# ==============================================================================
# Certificates
# ==============================================================================

@router.get("/certs")
async def list_certs(g: ObjectGuard = Depends(guard)):
    certs = g.list(Certificate)
    return {
        "certs": [
            {
                "id": c.id,
                "name": c.name,
                "domains": c.domain_list(),
                "source": c.source,
                "status": c.status,
                "days_left": c.days_left,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "issuer": c.issuer,
                "issued_by_node": c.issued_by_node,
                "auto_renew": c.auto_renew,
                "challenge_type": c.challenge_type,
                "synced_nodes": list(c.sync_map().keys()),
                "last_error": c.last_renewal_error,
                "renewal_failures": c.renewal_failures,
                # Nothing renews uploaded certificates, so the page has to warn
                # about expiry.  A row still waiting on an authority has no
                # certificate yet and should not look broken.
                "has_material": c.has_material(),
                "awaiting_csr": bool(c.csr_pem and not c.not_after),
                # Names served by sites using this certificate that it does
                # not cover.
                "short_of": sorted({
                    name
                    for h in c.hosts
                    for name in hostnames.uncovered(c.domain_list(), h.name_list())
                }),
            }
            for c in certs
        ]
    }


@router.post("/certs")
async def create_cert(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_certs")
    payload = await request.json()

    domains = payload.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.replace(",", " ").split() if d.strip()]
    if not domains:
        raise HTTPException(status_code=400, detail="a certificate needs at least one domain")

    for d in domains:
        validate_hostname(d)

    name = payload.get("name") or domains[0].replace("*.", "")
    validate_name(name.replace(".", "_"), "certificate name")

    if g.session.query(Certificate).filter(Certificate.name == name).first():
        raise HTTPException(status_code=409, detail=f"there is already a certificate called {name}")

    challenge = payload.get("challenge_type", "http-01")
    if challenge not in ("http-01", "dns-01"):
        raise HTTPException(status_code=400, detail="challenge has to be http-01 or dns-01")

    # Let's Encrypt only issues wildcards over dns-01, so catch it early.
    if any(d.startswith("*.") for d in domains) and challenge != "dns-01":
        raise HTTPException(
            status_code=400,
            detail="a wildcard certificate has to use dns-01, http-01 cannot do wildcards",
        )

    cert = Certificate(
        name=name,
        domains=json.dumps(domains),
        source=payload.get("source", "letsencrypt"),
        challenge_type=challenge,
        key_type=payload.get("key_type", "ecdsa"),
        auto_renew=bool(payload.get("auto_renew", True)),
    )

    # Authority to issue and renew from.  Empty means Let's Encrypt.
    if payload.get("authority_id"):
        authority = g.get(CertificateAuthority, payload["authority_id"])
        if not authority.enabled:
            raise HTTPException(
                status_code=400,
                detail=f"{authority.name} is turned off, so it cannot issue.")
        if not authority.has_credentials():
            raise HTTPException(
                status_code=400,
                detail=(f"{authority.name} has no account credentials saved, so "
                        f"registration would be refused.  Add them on the Paid "
                        f"Authorities page and press Test."))
        cert.authority_id = authority.id

    if challenge == "dns-01":
        from app.core.crypto import encrypt

        cert.dns_plugin = payload.get("dns_plugin")
        if payload.get("dns_credentials"):
            cert.dns_credentials_encrypted = encrypt(payload["dns_credentials"])

    g.session.add(cert)
    g.session.commit()

    audit.record("cert.create", user=g.user, object_type="cert", object_name=name,
                 changes={"domains": domains, "challenge": challenge})
    return {"id": cert.id, "name": cert.name}


# ---- certificates we did not get from Lets Encrypt ---------------------------

def _cert_name_for(payload, domains, what="certificate"):
    name = (payload.get("name") or (domains[0] if domains else "")).replace("*.", "")
    if not name:
        raise HTTPException(status_code=400, detail=f"give the {what} a name")
    validate_name(name.replace(".", "_"), f"{what} name")
    return name


def _store_material(g, cert, material, source):
    """
    Store the certificate and key on the row together, or not at all.  Half a
    pair has caused problems before, on disk and in the database.
    """
    from app.core.crypto import encrypt

    cert.source = source
    cert.uploaded_fullchain = material["fullchain"]
    cert.uploaded_privkey_encrypted = encrypt(material["privkey"])
    cert.domains = json.dumps(material["domains"])
    cert.not_before = material["not_before"]
    cert.not_after = material["not_after"]
    cert.issuer = material["issuer"][:255]
    cert.serial = material["serial"][:128]
    cert.fingerprint = material["fingerprint"][:128]

    # Nothing renews these, so auto_renew must be off.  Otherwise they sit in a
    # renewal queue that can never succeed and hide that someone has to act.
    cert.auto_renew = False
    cert.csr_pem = None
    cert.csr_created_at = None


@router.post("/certs/analyse")
async def analyse_cert_upload(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Describe an upload before anything is stored.  Uses the same call as the
    save, so the preview and what is stored cannot disagree.
    """
    g.require("edit_certs")
    payload = await request.json()

    try:
        material = certs.analyse_upload(
            cert_data=_decode_upload(payload.get("certificate")),
            key_data=_decode_upload(payload.get("private_key")),
            chain_data=_decode_upload(payload.get("chain")),
            pkcs12_data=_decode_upload(payload.get("pkcs12")),
            password=payload.get("password") or None,
        )
    except certs.CertProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    return _material_summary(material)


def _material_summary(material):
    """Everything worth showing, never the private key."""
    return {
        "subject": material["subject"],
        "issuer": material["issuer"],
        "domains": material["domains"],
        "not_before": material["not_before"].isoformat(),
        "not_after": material["not_after"].isoformat(),
        "serial": material["serial"],
        "fingerprint": material["fingerprint"],
        "key": material["key"],
        "self_signed": material["self_signed"],
        "chain_length": material["chain_length"],
        "warnings": material["warnings"],
    }


def _decode_upload(value):
    """
    Decode a field that may be pasted text or a base64 file from the browser.
    Certificates are usually pasted; PKCS12 never can be.
    """
    if not value:
        return None
    if isinstance(value, str) and value.startswith("data:"):
        value = value.split(",", 1)[-1]
        try:
            return base64.b64decode(value, validate=True)
        except Exception:
            raise HTTPException(status_code=400, detail="that upload is not valid base64")
    return value


@router.post("/certs/upload")
async def upload_cert(request: Request, g: ObjectGuard = Depends(changing)):
    """Upload an existing certificate and place it on every node."""
    g.require("edit_certs")
    payload = await request.json()

    try:
        material = certs.analyse_upload(
            cert_data=_decode_upload(payload.get("certificate")),
            key_data=_decode_upload(payload.get("private_key")),
            chain_data=_decode_upload(payload.get("chain")),
            pkcs12_data=_decode_upload(payload.get("pkcs12")),
            password=payload.get("password") or None,
        )
    except certs.CertProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    name = _cert_name_for(payload, material["domains"])

    cert = g.session.query(Certificate).filter(Certificate.name == name).first()
    replacing = cert is not None
    if replacing and cert.source == "letsencrypt" and cert.not_after:
        raise HTTPException(
            status_code=409,
            detail=(
                f"{name} is a Lets Encrypt certificate this system renews.  "
                f"Uploading over it would leave the renewal pointed at a "
                f"certificate it did not issue.  Use a different name, or delete "
                f"that one first."
            ),
        )
    if not replacing:
        cert = Certificate(name=name)
        g.session.add(cert)

    _store_material(g, cert, material, "uploaded")
    g.session.commit()

    result = await _place_and_report(cert.id)
    audit.record("cert.upload", user=g.user, object_type="cert", object_name=name,
                 changes={"domains": material["domains"],
                          "not_after": material["not_after"].isoformat(),
                          "replaced": replacing})
    return {"id": cert.id, "name": name, "replaced": replacing,
            "placed": result, **_material_summary(material)}


@router.post("/certs/self-signed")
async def create_self_signed(request: Request, g: ObjectGuard = Depends(changing)):
    """Create a self-signed certificate, for names no public CA will sign."""
    g.require("edit_certs")
    payload = await request.json()

    domains = payload.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.replace(",", " ").split() if d.strip()]

    try:
        material = certs.self_signed(
            domains,
            key_type=payload.get("key_type", "ecdsa"),
            key_size=int(payload.get("key_size") or 2048),
            days=int(payload.get("days") or certs.SELF_SIGNED_DEFAULT_DAYS),
            subject=payload.get("subject") or {},
        )
    except certs.CertProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="those key settings are not valid")

    name = _cert_name_for(payload, material["domains"])
    if g.session.query(Certificate).filter(Certificate.name == name).first():
        raise HTTPException(status_code=409,
                            detail=f"there is already a certificate called {name}")

    cert = Certificate(name=name)
    g.session.add(cert)
    _store_material(g, cert, material, "self_signed")
    g.session.commit()

    result = await _place_and_report(cert.id)
    audit.record("cert.self_signed", user=g.user, object_type="cert",
                 object_name=name, changes={"domains": material["domains"],
                                            "key": material["key"]})
    return {"id": cert.id, "name": name, "placed": result,
            **_material_summary(material)}


@router.post("/certs/csr")
async def create_csr(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Create a signing request and keep the key here.

    The row has no certificate and so no not_after, which means the renderer
    ignores it.  A pending request is harmless while the authority is slow.
    """
    g.require("edit_certs")
    payload = await request.json()

    domains = payload.get("domains") or []
    if isinstance(domains, str):
        domains = [d.strip() for d in domains.replace(",", " ").split() if d.strip()]

    try:
        made = certs.make_csr(domains,
                              key_size=int(payload.get("key_size") or 2048),
                              subject=payload.get("subject") or {})
    except certs.CertProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="that key length is not valid")

    name = _cert_name_for(payload, made["domains"])
    if g.session.query(Certificate).filter(Certificate.name == name).first():
        raise HTTPException(status_code=409,
                            detail=f"there is already a certificate called {name}")

    from app.core.crypto import encrypt

    cert = Certificate(
        name=name,
        domains=json.dumps(made["domains"]),
        source="uploaded",
        auto_renew=False,
        csr_pem=made["csr"],
        csr_created_at=utcnow(),
        uploaded_privkey_encrypted=encrypt(made["privkey"]),
    )
    g.session.add(cert)
    g.session.commit()

    audit.record("cert.csr", user=g.user, object_type="cert", object_name=name,
                 changes={"domains": made["domains"], "key": made["key"]})
    return {"id": cert.id, "name": name, "csr": made["csr"],
            "domains": made["domains"], "key": made["key"],
            "subject": made["subject"]}


@router.get("/certs/{cert_id}/csr")
async def get_csr(cert_id: str, g: ObjectGuard = Depends(guard)):
    cert = g.get(Certificate, cert_id)
    if not cert.csr_pem:
        raise HTTPException(status_code=404, detail="there is no signing request on this one")
    return {"name": cert.name, "csr": cert.csr_pem,
            "domains": cert.domain_list(),
            "created_at": cert.csr_created_at.isoformat() if cert.csr_created_at else None}


@router.post("/certs/{cert_id}/csr/complete")
async def complete_csr(cert_id: str, request: Request,
                       g: ObjectGuard = Depends(changing)):
    """Pair the certificate an authority returned with the key we kept."""
    cert = g.get(Certificate, cert_id, "edit_certs")
    payload = await request.json()

    if not cert.csr_pem or not cert.uploaded_privkey_encrypted:
        raise HTTPException(
            status_code=409,
            detail="there is no outstanding signing request on this certificate")

    from app.core.crypto import decrypt

    stored_key = decrypt(cert.uploaded_privkey_encrypted)
    if not stored_key:
        raise HTTPException(
            status_code=409,
            detail=("the key held for this request will not decrypt, which "
                    "happens when NFM_SECRET_KEY changed.  The request cannot be "
                    "completed, so make a new one."))

    try:
        material = certs.complete_csr(
            stored_key,
            cert_data=_decode_upload(payload.get("certificate")),
            chain_data=_decode_upload(payload.get("chain")),
        )
    except certs.CertProblem as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    _store_material(g, cert, material, "uploaded")
    g.session.commit()

    result = await _place_and_report(cert.id)
    audit.record("cert.csr.complete", user=g.user, object_type="cert",
                 object_name=cert.name,
                 changes={"not_after": material["not_after"].isoformat()})
    return {"id": cert.id, "name": cert.name, "placed": result,
            **_material_summary(material)}


async def _place_and_report(cert_id):
    """
    Write the material to every node, without ever failing the save.

    The row is committed first on purpose.  A peer being down just means a
    copy to make later, and the file check fixes it within a minute.
    """
    try:
        return await get_cert_manager().place_material(cert_id)
    except Exception as exc:
        log.error("stored the certificate but could not write it everywhere: %s", exc)
        return {"ok": [], "failed": [{"node": "?", "error": str(exc)}]}


@router.post("/certs/{cert_id}/issue")
async def issue_cert(cert_id: str, g: ObjectGuard = Depends(changing)):
    cert = g.get(Certificate, cert_id, "edit_certs")

    try:
        result = await get_cert_manager().issue(cert.id, actor=g.user.username)
    except AcmeError as exc:
        audit.record("cert.issue", user=g.user, object_type="cert",
                     object_name=cert.name, result="failed", detail=str(exc))
        raise HTTPException(status_code=400, detail=str(exc))

    detail = (f"issued by {result.get('issued_by')}" if result.get("renewed")
              else result.get("message"))
    audit.record("cert.issue", user=g.user, object_type="cert", object_name=cert.name,
                 detail=detail)
    return result


@router.post("/certs/{cert_id}/replicate")
async def replicate_cert(cert_id: str, g: ObjectGuard = Depends(changing)):
    """
    Push a certificate to every node again.

    Replication used to run only at issue time, so nodes that joined later
    never got existing certificates and there was no way to fix that.  Safe
    to run any time; nodes that have the files just get them rewritten.
    """
    cert = g.get(Certificate, cert_id, "edit_certs")

    # Issued certificates are exported from whichever node certbot wrote them
    # on.  Ones we hold material for are written from the database; certbot
    # knows nothing about those.
    try:
        if cert.has_material():
            result = await get_cert_manager().place_material(cert.id)
        else:
            result = await get_cert_manager().replicate(cert.id)
    except AcmeError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit.record("cert.replicate", user=g.user, object_type="cert",
                 object_name=cert.name,
                 detail=f"copied to {len(result.get('ok', []))} node(s)")
    return result


@router.get("/certs/{cert_id}/where")
async def cert_placement(cert_id: str, g: ObjectGuard = Depends(guard)):
    """
    Show which node would get this certificate, and why.

    The first thing to check when issuance fails: DNS answers and node
    addresses side by side.
    """
    cert = g.get(Certificate, cert_id)
    domains = cert.domain_list()
    if not domains:
        raise HTTPException(status_code=400, detail="that certificate has no domains")

    placement = await pick_issuing_node(domains[0])

    # Include the stored DNS check, which may show the record has pointed
    # elsewhere for a while.
    placement["dns_health"] = cert.dns_warning
    placement["dns_ok"] = bool(cert.dns_ok)
    return placement


@router.delete("/certs/{cert_id}")
async def delete_cert(cert_id: str, g: ObjectGuard = Depends(changing)):
    cert = g.get(Certificate, cert_id, "edit_certs")

    users = g.session.query(VirtualHost).filter(VirtualHost.cert_id == cert.id).all()
    if users:
        raise HTTPException(
            status_code=409,
            detail=(
                f"that certificate is still used by: {', '.join(h.name for h in users)}.  "
                f"nginx will not start with an ssl listener and no certificate, so "
                f"change those sites first."
            ),
        )

    name = cert.name
    g.session.delete(cert)
    g.session.commit()

    # Remove the files from every node too.  Deleting the row used to leave
    # the private key on every box indefinitely, and for uploaded certificates
    # this is the only copy.  Never touch certbot's folder; it keeps renewal
    # state there and `certbot delete` handles it.
    forgotten = await _forget_cert_files(name)

    audit.record("cert.delete", user=g.user, object_type="cert", object_name=name,
                 changes={"files_removed_from": forgotten["ok"],
                          "files_left_on": [f["node"] for f in forgotten["failed"]]})
    return {"ok": True, "deleted": name, "files": forgotten}


async def _forget_cert_files(name):
    """
    Remove a certificate's files fleet wide, without ever failing the delete.

    Nodes that are down keep their files for now; what was left where goes
    into the audit log.
    """
    results = {"ok": [], "failed": []}
    settings = get_settings()

    try:
        await get_agent().cert_forget(name=name)
        results["ok"].append(settings.node_name)
    except Exception as exc:
        results["failed"].append({"node": settings.node_name, "error": str(exc)})

    cluster = get_cluster()
    try:
        with session_scope() as session:
            peers = [(p.id, p.name) for p in cluster.peers(session)]
    except Exception as exc:
        log.error("could not list peers to clear up %s: %s", name, exc)
        return results

    for peer_id, peer_name in peers:
        try:
            with session_scope() as session:
                node = session.query(Node).filter(Node.id == peer_id).first()
                if not node:
                    continue
                client = PeerClient(node, cluster.ca)
            await client.call("/peer/cert/forget", {"name": name}, timeout=30)
            results["ok"].append(peer_name)
        except Exception as exc:
            log.error("could not remove %s from %s: %s", name, peer_name, exc)
            results["failed"].append({"node": peer_name, "error": str(exc)})

    return results


@router.get("/dns/lookup")
async def dns_lookup(domain: str, g: ObjectGuard = Depends(guard)):
    validate_hostname(domain)
    return await resolve_domain(domain)


# ==============================================================================
# The certbot hook endpoint
# ==============================================================================

@router.post("/acme/hook")
async def acme_hook(request: Request):
    """
    Called by the certbot hook scripts on this host.

    No session or CSRF, since the caller is a shell script.  Instead the
    request must come from this machine, carry the shared secret the hooks
    were written with, and can only publish or remove a challenge token.
    Anyone who passes all three is already on the box and could write the
    token file directly.
    """
    from app.core import acme_hooks
    from app.core.acme import ChallengeCoordinator

    # Must be a local caller.  Check properly rather than by string: on a dual
    # stack listener 127.0.0.1 can arrive as "::ffff:127.0.0.1", and loopback
    # is all of 127.0.0.0/8.
    source = client_ip(request)
    try:
        is_local = ipaddress.ip_address(
            source[7:] if source.startswith("::ffff:") else source
        ).is_loopback
    except ValueError:
        is_local = source == "localhost"

    if not is_local:
        log.warning(
            "acme hook called from %s, which is not this machine.  The hook runs "
            "on the host and talks to 127.0.0.1, so this usually means the "
            "container is not on host networking and docker is rewriting the "
            "source address.", source,
        )
        raise HTTPException(status_code=404, detail="not found")

    sent = request.headers.get("X-NFM-Hook-Secret", "")
    expected = acme_hooks.get_hook_secret()

    import secrets as _secrets

    if not sent or not _secrets.compare_digest(sent, expected):
        log.warning("acme hook called with the wrong secret")
        raise HTTPException(status_code=403, detail="no")

    payload = await request.json()
    action = payload.get("action")
    token = payload.get("token", "")

    coordinator = ChallengeCoordinator()

    if action == "publish":
        result = await coordinator.publish(token, payload.get("value", ""))
        log.info("challenge token published to %s node(s)", len(result.get("ok", [])))
        return {"ok": True, "nodes": result.get("ok", []), "failed": result.get("failed", [])}

    if action == "cleanup":
        await coordinator.cleanup(token)
        return {"ok": True}

    raise HTTPException(status_code=400, detail="action is publish or cleanup")


# ==============================================================================
# Health and history
# ==============================================================================

@router.get("/health/events")
async def health_events(g: ObjectGuard = Depends(guard), limit: int = 100):
    limit = max(1, min(int(limit), 500))
    rows = g.session.query(HealthEvent).order_by(
        HealthEvent.timestamp.desc()
    ).limit(limit).all()

    return {
        "events": [
            {
                "timestamp": e.timestamp.isoformat(),
                "pool": e.pool_name,
                "member": e.member_address,
                "node": e.node_name,
                "from": e.old_state,
                "to": e.new_state,
                "reason": e.reason,
                "response_ms": e.response_ms,
            }
            for e in rows
        ]
    }


@router.get("/versions")
async def list_versions(g: ObjectGuard = Depends(guard), limit: int = 50):
    limit = max(1, min(int(limit), 200))
    rows = g.session.query(ConfigVersion).order_by(
        ConfigVersion.version.desc()
    ).limit(limit).all()

    return {
        "versions": [
            {
                "version": v.version,
                "checksum": v.checksum[:12],
                "author": v.author,
                "summary": v.summary,
                "created_at": v.created_at.isoformat(),
                "applied": v.applied,
                "origin_node": v.origin_node,
            }
            for v in rows
        ]
    }


@router.get("/versions/{version}/diff")
async def version_diff(version: int, g: ObjectGuard = Depends(guard)):
    """
    What one applied version changed against the one before it.

    Both sides are the files actually shipped, not a re-render from today's
    objects.
    """
    row = g.session.query(ConfigVersion).filter(
        ConfigVersion.version == version
    ).first()
    if not row:
        raise HTTPException(status_code=404, detail="no such version")

    before_row = g.session.query(ConfigVersion).filter(
        ConfigVersion.version < version
    ).order_by(ConfigVersion.version.desc()).first()

    after = json.loads(row.rendered or "{}")
    before = json.loads(before_row.rendered or "{}") if before_row else {}

    changes = []
    for path in sorted(set(before) | set(after)):
        old, new = before.get(path), after.get(path)
        if old == new:
            continue
        diff = list(difflib.unified_diff(
            (old or "").splitlines(), (new or "").splitlines(),
            fromfile=f"v{before_row.version if before_row else 0}/{path}",
            tofile=f"v{version}/{path}", lineterm="", n=2,
        ))
        changes.append({
            "path": path,
            "kind": "added" if old is None else ("removed" if new is None else "changed"),
            "diff": diff[:120],
            "truncated": len(diff) > 120,
        })

    return {
        "version": version,
        "compared_to": before_row.version if before_row else None,
        "changed_files": len(changes),
        "changes": changes,
    }


@router.post("/rollback")
async def rollback(request: Request, g: ObjectGuard = Depends(changing)):
    """Restore the last known good config on this node."""
    g.require("rollback")
    payload = await request.json() if await request.body() else {}

    # Accept a version number as well as an archive name.  `version` used to
    # be ignored: the agent fell back to the newest archive (the live config)
    # and returned ok: true while nothing changed.
    name = payload.get("backup")
    wanted = payload.get("version")
    if name is None and wanted is not None:
        try:
            wanted = int(wanted)
        except (TypeError, ValueError):
            raise HTTPException(status_code=400,
                                detail="version has to be a number")
        try:
            listing = await get_agent().list_backups()
        except AgentError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        archives = [b["name"] for b in (listing.get("backups") or [])]
        match = [a for a in archives if a.endswith(f"-v{wanted}.tar.gz")]
        if not match:
            have = sorted(
                int(a.rsplit("-v", 1)[1].split(".")[0])
                for a in archives if "-v" in a and a.rsplit("-v", 1)[1][0].isdigit()
            )
            raise HTTPException(
                status_code=404,
                detail=(f"there is no saved config for version {wanted} on this "
                        f"node.  " + (f"There is: {', '.join(str(v) for v in have[-10:])}"
                                      if have else "There are none at all.")))
        name = match[0]

    try:
        result = await get_agent().rollback(name=name)
    except AgentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    if wanted is not None:
        result["version"] = wanted

    audit.record("config.rollback", user=g.user, object_type="config",
                 result="success" if result.get("ok") else "failed",
                 detail=result.get("output"))
    return result


@router.get("/audit")
async def audit_log(g: ObjectGuard = Depends(guard), limit: int = 100):
    from app.models import AuditLog

    limit = max(1, min(int(limit), 500))
    rows = g.session.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()

    return {
        "entries": [
            {
                "timestamp": r.timestamp.isoformat(),
                "username": r.username,
                "role": r.user_role,
                "source_ip": r.source_ip,
                "action": r.action,
                "object_type": r.object_type,
                "object_name": r.object_name,
                "result": r.result,
                "detail": r.detail,
                "changes": r.change_map(),
            }
            for r in rows
        ]
    }


# ==============================================================================
# Importing somebody else's config
# ==============================================================================

@router.post("/import/preview")
async def import_preview(request: Request, g: ObjectGuard = Depends(guard)):
    """
    Show what a config would become, without writing anything.

    A read on purpose, so someone evaluating the tool can point it at their
    live config without committing to anything.
    """
    g.require("edit_sites")
    payload = await request.json()

    from app.core.importer import analyse

    return analyse(payload.get("config") or "")


@router.post("/import")
async def import_apply(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Create what the preview described.

    The config is parsed again here rather than trusting a plan from the
    browser, which would let a caller create anything it liked.
    """
    g.require("edit_sites")
    g.require("edit_pools")
    payload = await request.json()

    from app.core.importer import analyse, apply_plan

    plan = analyse(payload.get("config") or "")
    if not plan.get("ok"):
        raise HTTPException(status_code=400, detail=plan.get("error", "that config would not parse"))

    result = apply_plan(
        g.session,
        plan,
        chosen_sites=payload.get("sites"),
        chosen_pools=payload.get("pools"),
    )
    g.session.commit()

    audit.record("config.import", user=g.user, object_type="fleet",
                 detail=f"imported {len(result['sites'])} sites and "
                        f"{len(result['pools'])} pools")

    # Nothing is applied.  Everything lands disabled so it can be reviewed
    # before it reaches nginx.
    return {"ok": True, **result,
            "message": "imported and left switched off.  Look them over, turn on "
                       "the ones you want, then apply."}


# ==============================================================================
# Paths within a site
# ==============================================================================

# `_apply_location_fields` below is the only definition of what a path
# accepts.  (An old, unused LOCATION_FIELDS tuple was removed so nobody trusts
# a list that can drift.)

MATCH_TYPES = {"prefix", "exact", "preferential", "regex", "regex_i"}
LOCATION_MODES = {"proxy", "static", "redirect", "deny"}


def _location_json(loc) -> dict:
    return {
        "id": loc.id,
        "path": loc.path,
        "match_type": loc.match_type,
        "mode": loc.mode,
        "pool_id": loc.pool_id,
        "pool": loc.pool.name if loc.pool else None,
        "document_root": loc.document_root,
        "alias": loc.alias,
        "redirect_target": loc.redirect_target,
        "redirect_code": loc.redirect_code,
        "access_list_id": loc.access_list_id,
        "error_page_template_id": loc.error_page_template_id,
        "access_list": loc.access_list.name if loc.access_list else None,
        "custom_config": loc.custom_config or "",
        "enabled": bool(loc.enabled),
        "sort_order": loc.sort_order or 0,
        # Must be returned here.  When it was missing, the editor showed the
        # box cleared on reload, and the next unrelated save turned it off.
        "strip_prefix": bool(loc.strip_prefix),
        "mount_site": bool(loc.mount_site),
        "settings": loc.setting_map(),
    }


def _apply_location_fields(loc, payload, g):
    if "path" in payload:
        path = (payload.get("path") or "").strip()
        if not path:
            raise HTTPException(status_code=400, detail="a path is required")
        if any(c in path for c in "{};\n\r"):
            raise HTTPException(status_code=400,
                                detail="a path cannot contain braces, semicolons or newlines")
        loc.path = path

    if "match_type" in payload:
        value = payload.get("match_type") or "prefix"
        if value not in MATCH_TYPES:
            raise HTTPException(status_code=400, detail=f"{value} is not a match type")
        loc.match_type = value

    if "mode" in payload:
        value = payload.get("mode") or "proxy"
        if value not in LOCATION_MODES:
            raise HTTPException(status_code=400, detail=f"{value} is not a mode")
        loc.mode = value

    for field, model in (("pool_id", Pool), ("access_list_id", AccessList),
                         ("error_page_template_id", ErrorPageTemplate)):
        if field in payload:
            value = payload[field]
            if value in (None, "", 0):
                setattr(loc, field, None)
            else:
                setattr(loc, field, g.get(model, value).id)

    for field in ("document_root", "alias", "redirect_target", "custom_config"):
        if field in payload:
            setattr(loc, field, payload.get(field) or None)

    if "redirect_code" in payload:
        loc.redirect_code = int(payload.get("redirect_code") or 301)
    if "enabled" in payload:
        loc.enabled = bool(payload.get("enabled"))

    if "strip_prefix" in payload:
        loc.strip_prefix = bool(payload.get("strip_prefix"))
    if "mount_site" in payload:
        loc.mount_site = bool(payload.get("mount_site"))
    if "sort_order" in payload:
        loc.sort_order = int(payload.get("sort_order") or 0)

    # Mounting only makes sense on prefix matches.  Exact and regex matches
    # have nothing underneath to rewrite, so refuse rather than silently
    # ignore.
    if loc.mount_site and loc.match_type not in ("prefix", "preferential"):
        raise HTTPException(
            status_code=400,
            detail="serving a whole site under a path needs a prefix match, "
                   f"and this path is set to {loc.match_type}")
    if loc.mount_site and loc.mode != "proxy":
        raise HTTPException(
            status_code=400,
            detail="serving a whole site under a path means proxying to a pool, "
                   f"and this path is set to {loc.mode}")
    if loc.mount_site and (loc.path or "").strip("/") == "":
        raise HTTPException(
            status_code=400,
            detail="a path of / is already the root, so there is no prefix to "
                   "serve a site under")

    if "settings" in payload and isinstance(payload["settings"], dict):
        # Same catalog validation as a site, so nothing refused on the site
        # can be set on a location instead.
        loc.settings = json.dumps(_validate_settings(payload["settings"], "location"))


@router.get("/hosts/{host_id}/locations")
async def list_locations(host_id: str, g: ObjectGuard = Depends(guard)):
    g.require("view")
    host = g.get(VirtualHost, host_id)
    return {"locations": [_location_json(l) for l in
                          sorted(host.locations, key=lambda x: x.sort_order or 0)]}


@router.post("/hosts/{host_id}/locations")
async def create_location(host_id: str, request: Request,
                          g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)
    payload = await request.json()

    existing = sorted(host.locations, key=lambda x: x.sort_order or 0)
    loc = Location(
        host_id=host.id,
        path=(payload.get("path") or "/").strip(),
        match_type="prefix",
        mode="proxy",
        # Append at the end.  Order decides which path wins, so adding at the
        # top could take traffic from an existing path.
        sort_order=(existing[-1].sort_order or 0) + 10 if existing else 10,
        enabled=True,
    )
    _apply_location_fields(loc, payload, g)
    g.session.add(loc)
    g.session.commit()

    audit.record("location.create", user=g.user, object_type="location",
                 object_name=f"{host.name}{loc.path}")
    return _location_json(loc)


@router.put("/locations/{loc_id}")
async def update_location(loc_id: str, request: Request,
                          g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    loc = g.get(Location, loc_id)
    _apply_location_fields(loc, await request.json(), g)
    g.session.commit()

    audit.record("location.update", user=g.user, object_type="location",
                 object_name=loc.path)
    return _location_json(loc)


@router.delete("/locations/{loc_id}")
async def delete_location(loc_id: str, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    loc = g.get(Location, loc_id)
    path = loc.path
    g.session.delete(loc)
    g.session.commit()

    audit.record("location.delete", user=g.user, object_type="location",
                 object_name=path)
    return {"ok": True}


@router.post("/hosts/{host_id}/locations/order")
async def reorder_locations(host_id: str, request: Request,
                            g: ObjectGuard = Depends(changing)):
    """
    Set the order of a site's paths in one step.

    Order decides which path handles a request.  Saving positions one at a
    time would briefly leave two paths sharing one.
    """
    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)
    payload = await request.json()

    wanted = payload.get("order") or []
    by_id = {l.id: l for l in host.locations}
    for position, loc_id in enumerate(wanted, start=1):
        loc = by_id.get(int(loc_id))
        if loc is not None:
            loc.sort_order = position * 10
    g.session.commit()

    return {"ok": True, "order": [l.id for l in
                                  sorted(host.locations, key=lambda x: x.sort_order or 0)]}
