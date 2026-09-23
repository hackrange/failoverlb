"""
The JSON API.

Every route in here follows the same three steps and in the same order:

  1. Work out who is asking (the session cookie).
  2. Check CSRF, for anything that changes something.
  3. Fetch objects only through ObjectGuard, which does the permission check.

Step three is what keeps the BOLA and IDOR bugs out.  There is no route that
queries a table by id directly, so there is no route that can forget the check.
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
    Everything a name has to be unique against, which is not always one table.

    nginx keeps a single list of shared memory zones for the whole http block,
    so a rate limit zone and a connection limit zone called the same thing are
    not two names, they are one name declared twice for different uses.  nginx
    refuses that outright, and it refuses it on every node, so the fleet stops
    being able to apply anything at all until somebody works out which of the
    two zones is the new one.  Checking only within a kind, which is what
    creating used to do, lets that straight through.
    """
    zones = (RateLimitZone, ConnLimitZone, CacheZone)
    return zones if model in zones else (model,)


def claim_name(session, model, name, what, exclude_id=None):
    """
    Refuse a name something else is already using.

    Creating has always checked this.  Renaming never did, and the two go
    through different code, so a rename onto a name in use went straight
    through.  For a pool that is worse than a duplicate create would have been,
    because nothing fails: the render keys its files by the name, so the second
    pool written wins, the first one's upstream is simply not in the config, and
    the apply succeeds.  A site pointed at the pool that lost then sends its
    traffic to the other pool's backends and nobody is told.

    The comparison is on the rendered form of the name rather than the name as
    typed, because that is what decides whether two objects collide.  For a pool
    it is stricter again: sticky sessions turn the name into an nginx variable,
    and a variable cannot hold a dot or a dash, so two pools called `shop-eu`
    and `shop_eu` are different rows sharing one `$sticky_shop_eu`.
    """
    wanted = safe_name(name)
    wanted_var = safe_var(name) if model is Pool else None

    for peer in _name_peers(model):
        for other in session.query(peer).all():
            # Only the row being renamed is allowed to keep its own name, and
            # ids only mean anything within their own table.
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
    Turn everything in the database into config files.

    Gives back (files, checksum, snapshot).  The snapshot is what gets stored
    against the version so you can see what the config looked like then.
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
    # health checks and peer traffic never get blocked by an ACL somebody wrote
    # for the public.  This is the bit that means adding a node later does not
    # need anybody to remember to update a list.
    node_addresses = []
    for node in nodes:
        if node.address:
            node_addresses.append(node.address)
        for entry in node.local_address_list():
            addr = entry.get("address")
            if addr and entry.get("scope") == "global":
                node_addresses.append(addr)

    # Read out as plain dictionaries rather than handed to the renderer as
    # rows.  The renderer outlives this session in some callers, and a row read
    # after its session closes is a 500 on one path only, which is a bug this
    # project has already spent an afternoon on.
    waf_profiles = [
        {
            "name": p.name,
            "exclusions": [
                {"rule_id": e.rule_id, "path": e.path or "",
                 "message": e.message or ""}
                for e in p.exclusions
            ],
            # The positive model, if this profile has one.  A profile can carry
            # exclusions, a surface, or both, because they are two halves of
            # one policy for one application.
            "surface": [
                {"path": e.path, "methods": e.method_list()}
                for e in p.surface
            ],
        }
        for p in session.query(WafProfile).all()
    ]

    # Sessions that are recording the surface right now.
    #
    # The renderer needs these because a recording session changes the config:
    # full audit logging is switched on for the tester addresses and for nobody
    # else, so what the log holds is the shape of the application rather than
    # the shape of the attacks against it.  It goes off again when the session
    # ends, which is why this is read per render rather than stored on the site.
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
            # What an admin typed on the settings page, falling back to the GUI
            # allow list when nothing has been set there yet.  Those are two
            # different things, but the allow list is a sensible starting guess.
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

    # The objects themselves, not a count of them.  This is what lets a node
    # that was a standby put the config back when it gets promoted, and it used
    # to be four numbers, which restored nothing.
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
    Render everything and push it out to the fleet.

    This is the one path everything uses.  The health checker calls it when a
    backend changes state, and the API calls it when somebody saves.  Having one
    path means the two phase apply and the queueing behave the same either way.
    """
    with session_scope() as session:
        files, checksum, snapshot = render_current(session)
        # The same render with health ignored, stored alongside, so the
        # "saved but not live" banner has something honest to compare against.
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
    Is there anything saved that nginx has not been given yet.

    Saving and applying are deliberately separate, so you can make three related
    changes and push them out together rather than reloading nginx three times
    and living through two half finished states.  The cost of that split is that
    saving looks finished when it is not, and the config quietly drifts from
    what is running until somebody notices.

    Worked out by rendering what the config would be now and comparing it to the
    version that actually went out.  A stored flag would be cheaper and would
    lie the moment anything changed a row without going through the page that
    sets it.  This cannot drift, because it is the same render the apply itself
    would do.
    """
    try:
        _files, _checksum, _snapshot = render_current(session, ignore_health=True)
        checksum = _checksum
    except Exception as exc:
        # A render that blows up is its own problem and the apply will report it
        # properly.  Do not take the whole status endpoint down over it.
        log.warning("could not work out whether config is pending: %s", exc)
        return {"dirty": False, "error": str(exc)[:200]}

    latest = session.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()

    # An older row has no user_checksum, from before this existed.  Treat that
    # as nothing pending rather than showing a banner nobody can clear, since
    # the next apply fills it in.
    known = latest.user_checksum if latest else None
    return {
        "dirty": bool(latest is None or (known is not None and known != checksum)),
        "applied_version": latest.version if latest else 0,
        "never_applied": latest is None,
    }


@router.get("/config/pending")
async def pending_config_diff(g: ObjectGuard = Depends(guard)):
    """
    Show what applying would actually change, line by line.

    Knowing that something is unapplied is only half an answer.  The other half
    is what, and without it the only way to find out is to apply and watch,
    which is the wrong order for anything that touches a load balancer.

    Diffed against the files the last applied version actually shipped, not a
    fresh render of it, so this is a genuine before and after rather than two
    guesses about the same thing.
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
        # A whole new file diffs as one huge block of additions, which is true
        # and unreadable.  Enough to see what it is, not the entire thing.
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

# Settings whose choices are rows in the database rather than a list in the
# catalog.
#
# The catalog is deliberately static: it describes nginx, and nginx does not
# change while the process is running.  A zone is something somebody made an
# hour ago, so these three features carry `options=[]` and get their choices
# filled in at request time.
#
# **Both sides have to know that, and for a long time only one did.**  The
# catalog endpoint filled the dropdowns from the database, so the site editor
# offered real zones.  The validator did not, so `validate_value` ran the
# select check against an empty option list and refused every value, including
# the ones the page had just offered.  Caching, rate limiting and connection
# limiting could each be chosen and none of them could be saved: the answer was
# a 400 reading "has to be one of:" with nothing after the colon.
#
# One dict now, read by both, so the two cannot drift apart again.  Adding a
# fourth means adding it here and nowhere else, and checks/catalog_sweep.py
# fails if a select with no options is missing from it.
ZONE_CHOICES = {
    "limit_req_zone_name": (RateLimitZone, "rate limit zone", "Rate limits"),
    "limit_conn_zone_name": (ConnLimitZone, "connection limit zone", "Rate limits"),
    "proxy_cache_zone": (CacheZone, "cache zone", "Cache zones"),
}


@router.get("/catalog")
async def catalog(request: Request, context: str = "server",
                  db: DBSession = Depends(get_db)):
    """
    Every setting available in this context, on this box.

    The GUI builds its forms from this, and the ? popups read the same data, so
    the help can never end up describing something the form does not do.
    """
    get_user(request, db)
    # The fleet view, not this node's.  Offering something only some of your
    # boxes were built with produces a change that will not apply and no
    # obvious reason why.
    caps = fleet_capabilities()
    version = caps.version_tuple

    # The zone pickers have no fixed choices, they are whatever you have made.
    # Filling them here means the site editor offers real zones rather than an
    # empty dropdown nobody can use.
    #
    # The keys come from ZONE_CHOICES, which the validator also reads, so a
    # picker can never again offer something the save refuses.  Only the label
    # is written out per zone type, because what is worth showing beside a name
    # differs: a rate for a rate limit, a size for a cache.
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
        # Has a card of its own on the page that uses it, so it is not in the
        # long list of advanced settings as well.
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
            # Whether SSL offload only mode decides this one, so the form can
            # grey it out and say why rather than letting somebody set a value
            # the renderer is going to override.  Read from the renderer's own
            # list, because two copies of it would drift the first time the mode
            # covered one more setting.
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
    What the fleet has, and every country somebody could pick.

    The country list goes with it rather than in its own call, because the page
    needs both to draw anything and two round trips would let it render half a
    picker.
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
    """Fetch the database and put it on every node, now."""
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
    """Fetch the rule set and put it on every node, now."""
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
    # Through the guard, which checks the permission and answers 404 rather
    # than 403, so an id cannot be probed for existence.  This used to fetch
    # the row itself behind get_user, which only asks whether somebody is
    # signed in.
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
    Begin watching, with the addresses that count as testers.

    **Starting a session never lowers protection.**  A site that is blocking
    keeps blocking: ModSecurity logs every rule that fires whether or not the
    score reaches the threshold, so there is nothing to gain by weakening it
    and a great deal to lose.  Only a site with the firewall off is changed,
    and it is changed to watching, which refuses nothing.

    A button labelled "start watching" that quietly turned a site's firewall
    off is the sort of thing that gets found out during an incident.
    """
    from app.core.waf_hits import parse_addresses

    g.require("edit_sites")
    host = g.get(VirtualHost, host_id)

    # There has to be an engine to learn from.
    #
    # This is the second door to the same setting and it was not locked.
    # Setting waf_mode directly is refused on a fleet without the module, but
    # starting a session writes waf_mode itself, further down, and went round
    # the check.  It answered success, stored "watching" on a site that cannot
    # watch anything, and the person running the round would exercise their
    # whole application before finding out that nothing had been collected.
    # The stored mode is the worse half: it sits there doing nothing until
    # somebody builds the module, and then that site quietly starts watching.
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
    Stop watching, and hand back everything the session found.

    Collects and presents; it does not save.  Stopping and whitelisting in one
    step would rest the whole safeguard on nobody having wandered past during
    the window, and the point of naming testers is that a person looks at the
    result before it becomes policy.
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

    # Put the site back where it was, if starting had moved it.
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
    What fired for one site, split into what a tester produced and what did not.

    `until` is how a session that has already stopped can still be read.  The
    window was open ended, so the page could only ever ask about the session
    running right now, and stopping one hid the evidence it had just gathered.
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
        # The defaults, so the form has something to draw before anybody saves.
        # 401 and 403 rather than 200, because guessing that a 200 is a failure
        # would report every successful login on a form based application as an
        # attack, and a detector that cries wolf on day one is switched off on
        # day one.
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

    The paths are checked the same way an exclusion path is, because they end
    up in a comparison rather than in config, and a value nobody validated
    reaching a comparison is only ever one refactor away from reaching
    somewhere worse.
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
    What the log says right now, over both windows.

    Two windows on purpose.  The short one catches a burst.  The long one
    catches the same attack run slowly, which is what somebody does once they
    know detectors use five minute windows, and it is the one most likely to be
    quietly missing from anybody else's.
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
    The application's own shape, split by who produced it.

    The positive model's version of the hits endpoint.  Same window arguments,
    same split, and the split matters more here: an exclusion learned from a
    stranger switches one rule off, while a surface entry learned from a
    stranger permanently allows a path they found, which is the exact thing a
    positive model exists to stop.
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
    Put a reviewed surface into a profile.

    Merged rather than replaced, because a walk is rarely done in one sitting.
    Somebody exercises the admin pages on Tuesday and the reporting pages on
    Thursday, and a save that replaced would throw Tuesday away without saying
    so.  Removing a path is its own action on the profiles page, where the
    consequence is visible.
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
            # Methods are added to, never narrowed by a later save.  A second
            # walk that only did GET must not quietly remove the POST somebody
            # proved on the first.
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

    The same job as editing an exclusion path and for the same reason: learning
    produces one row per object it saw, and the useful rule is the pattern
    behind them.  On a positive model it matters more, because a path that was
    never generalised means every object created after the walk is refused.
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
    Take a path out of the allowed surface.

    Refused when the profile is enforcing on a live site, which is the opposite
    of how removing an exclusion works, and the difference is which way the
    risk runs.  Removing an exclusion puts a rule back into force, so the
    firewall checks more.  Removing a path from a surface **refuses traffic
    that is currently being served**, and it does it the moment the config is
    applied.
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
    Throw away what was learned for one site, on every node.

    Only the evidence.  Exclusions already saved into a profile are decisions
    taken from that evidence and are left alone, because a clear that quietly
    removed them would put a site back to refusing traffic somebody had
    explicitly allowed.
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
    Stored telemetry between two times, at the finest resolution that covers it.

    Takes a range rather than a window name, because the page lets somebody drag
    across a chart to zoom and "the last hour" cannot express "twenty past two
    until half past".

    The answer carries the resolution it drew from and the oldest bucket held,
    so the page can say a flat line is a five minute average rather than
    nothing happening, and can say when the history is shorter than the window
    asked for instead of drawing a short line somebody reads as a quiet period.
    """
    from app.core import metrics_store

    get_user(request, db)
    now = int(time.time())
    end = int(end or now)
    start = int(start or (end - 3600))

    # A month is the most that is kept, so asking for more is asking for
    # something that cannot exist.  Clamped rather than refused: somebody
    # dragging a chart should get what there is.
    span = end - start
    if span > metrics_store.KEEP_COARSE:
        start = end - metrics_store.KEEP_COARSE

    raw = metrics_store.series(start, end)

    # Reshaped into what the charts already read, rather than teaching the page
    # a second shape.  One drawing routine for live and stored history means a
    # zoomed chart cannot quietly render differently from a live one.
    #
    # value is the mean, with min and max carried alongside.  A five minute
    # bucket drawn as its mean alone is where a spike goes to die, so the
    # numbers that keep it are on every point whether the chart draws them yet
    # or not.
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
        #
        # They were left out of this answer when it was written, so every
        # window drawn from stored history showed three tiles reading "no data"
        # while the charts underneath drew correctly.  It looked like CPU,
        # memory and requests had stopped being collected, and it only looked
        # right on the shortest window, which is the one served from memory.
        #
        # The numbers come from the last bucket in the range, so on a zoom into
        # last Tuesday the tiles say what it was at the end of last Tuesday
        # rather than what it is now.  `as_of` carries that timestamp so the
        # page can say which, because a tile that reads as the present tense
        # while somebody is looking at the past is the same bug wearing a
        # different hat.
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
    Fetch the discovery document and say what came back.

    **Honest about what it proves.**  It proves the address resolves, the TLS
    is acceptable to this node, and the document is an OpenID one with the
    endpoints in it.  It does not prove the client id is right, the secret is
    right, the redirect address is registered, or that anybody is in the
    groups.  Only a real login proves those, which is why the mode that turns
    local passwords off wants one to have happened.

    Worth having anyway, because a typo in the discovery URL is the single most
    common way this is set up wrong, and finding it here beats finding it on
    the login page in front of somebody who cannot get in.
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
        # Redirects are not followed.  This reflects what it fetched back to
        # the caller, so following one turns any open redirect on a permitted
        # host into a way to reach one that is not.  Reporting the redirect is
        # also more useful to whoever is configuring the provider than quietly
        # following it and describing somewhere else.
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
    Every rule id the installed rule set defines, so exclusions can be checked.

    Asked of this node only.  The rule set is installed identically on every
    node and the settings page already says loudly when they disagree, so
    asking the whole fleet for a list that should be the same everywhere would
    cost a round trip per node to answer the same question.
    """
    from app.core.agent_client import get_agent

    get_user(request, db)
    try:
        answer = await get_agent().call("crs_rule_ids")
    except Exception as exc:
        # The only place here that hands an unclassified exception's text to a
        # caller.  Everything else in this file catches a named type whose
        # message was written for a person; this catches anything at all, so
        # its text can carry absolute paths and internal state.  Logged in full
        # and summarised out, the same way the agent already does it.
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

    The provenance travels with it, which site, which addresses, which
    request and what date, because an exclusion nobody can explain is one nobody
    will dare remove, and a WAF full of those checks nothing.
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
    # A profile can start life holding a surface and no exclusions, which is a
    # perfectly good policy: this application is these paths, and the rules
    # underneath have never been wrong about it.  The caller says so, because
    # an empty profile created by accident is still worth refusing.
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

    Refused with the list rather than allowed, the same as deleting a pool a
    site points at.  A site whose profile vanished would fall back to an
    untuned rule set and start refusing traffic it was tuned to allow, which is
    an outage produced by a tidy up.
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


# The path an exclusion applies to, which people edit by hand.
#
# A quote or a line break would end the ModSecurity directive early and start
# writing rules of its own, and a rule that switches off checking is the worst
# possible thing to let somebody inject.  Same reasoning as the catalog's own
# breakout check, applied here because these do not go through the catalog.
_WAF_PATH_BAD = re.compile(r'["\'\\\n\r;{}]')


def _waf_path_problem(path: str) -> str:
    """Why this exclusion path cannot be stored, or empty when it can."""
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

    Learning produces these from evidence, which is the right way round, but it
    can only produce what somebody exercised.  A repository created next week
    is not in any learned path, so there has to be a way to write the general
    case yourself.
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

    This is what makes learning usable on anything with a path per object.  A
    git server produces one row per repository, so a learning round gives
    `/trice/apache2.git/git-upload-pack` and will give another for every
    repository that ever exists.  Editing that to `/trice/*.git/*` turns
    dozens of rows into one that also covers the repository somebody makes
    next week.

    The star is kept as a star.  What is stored is what the page shows and
    what a person edits; the translation into a regular expression happens in
    the renderer, because asking somebody to maintain
    `^/trice/[^/]*\\.git/` is how a tuned profile stops being reviewed.

    The evidence is deliberately not editable.  Which address it was learned
    from, and what the rule said, are the record of why somebody decided this,
    and a note that can be rewritten is not a record.
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
    Take one exclusion out of a profile.

    Not refused when sites are using the profile, unlike deleting the profile
    itself, and the difference is which way the risk runs.  Deleting a profile
    a site points at leaves it pointing at nothing, which is an outage.
    Removing one exclusion puts a rule back into force, which is the firewall
    checking more rather than less.  It may well break the application again,
    and that is a thing somebody can see and undo, not a fleet going dark.
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
    The paid only features, and what we built instead.

    Shown on its own page.  It looks odd to advertise what you cannot have, but
    the alternative is somebody spending an hour looking for sticky sessions
    before finding out it is not in the free version.
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

    X-Frame-Options and Referrer-Policy are the two whose "do not send the
    header" option is the empty string, which the forms cannot store: an empty
    value means cleared and the key is left out.  So the renderer treats a
    missing key as no header, and the value a new site gets has to be written
    down here instead of living in a fallback nobody can override.

    The form already shows the catalog default selected on a new site, so
    without this the dropdown would say SAMEORIGIN while the rendered config
    sent nothing, which is the same class of lie the fallback was.

    Only on create, and only for keys nobody set.  Doing it in
    _apply_host_fields would put the header back every time somebody saved after
    choosing not to send it, which is the bug this is fixing.

    Deliberately not for an imported site: those are built straight from
    somebody's existing nginx config and do not come through here, so a config
    that never sent these headers does not start sending them because we
    imported it.
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

    # The name check lives in _apply_host_fields, which runs below, so that
    # creating and renaming cannot drift apart the way they already did once.
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
    Copy a site, with everything that makes it behave the way it does.

    Most sites in a fleet are the fifth one like the other four.  Rebuilding
    the settings, the paths and the hand written config by eye is how the fifth
    one ends up subtly different from the rest, and the difference is found
    months later by whoever is debugging only that site.

    **Three things are deliberately not copied**, and each of them would be a
    bug if it were:

      * **The certificate itself.**  It is issued for names this copy does not
        have, and pointing a new site at it would serve a certificate that does
        not match the address people typed, which browsers refuse loudly.  What
        *can* be copied is how it was obtained, the challenge type, key type,
        authority and DNS credentials, so asking for a certificate for the new
        names is a tick rather than a form.  It is created and attached here
        and issued by the normal certificate flow, because issuing needs DNS to
        already point at this fleet and the site to be serving, and neither is
        true in the second a clone is made.
      * **The names it answers to.**  Asked for as part of the clone rather
        than copied, because two server blocks claiming the same server_name
        means nginx quietly serves whichever it parsed first and the other site
        looks broken for no visible reason.  A hostname already claimed by
        another site is refused here rather than discovered later.
      * **Being switched on.**  A copy arrives disabled.  It is a starting
        point somebody is about to edit, and a half edited site taking traffic
        the moment it is created is not what anybody meant by duplicate.
    """
    original = g.get(VirtualHost, host_id, "edit_sites")
    payload = await request.json() if await request.body() else {}

    name = validate_name(payload.get("name"), "site name")
    if g.session.query(VirtualHost).filter(VirtualHost.name == name).first():
        raise HTTPException(status_code=400,
                            detail=f"there is already a site called {name}")

    # The hostnames are asked for at clone time rather than left to be fixed
    # afterwards.  Changing the name and the names it answers to are the same
    # job, and splitting them across two screens is how a clone ends up live on
    # the original's hostname for the minute in between.
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

    # The paths as well.  A site whose behaviour lives in its locations would
    # come back as an empty shell without these, which looks like the copy
    # worked and is the least useful half of it.
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

    # A certificate for the new names, if asked for.
    #
    # Created and attached, not issued.  Issuing reaches Lets Encrypt, needs
    # the new hostname already resolving to this fleet and the site already
    # serving the challenge, and a clone is disabled and usually made before
    # the DNS exists.  Trying anyway would fail most of the time and leave
    # somebody unpicking a half made clone rather than pressing one button on
    # the certificates page when they are ready.
    made_cert = None
    if payload.get("create_certificate"):
        source = original.cert

        # A certificate for this hostname may already exist, and the name is
        # unique.  Creating one regardless meant an unhandled database error
        # and a bare 500 on the clone dialog, with nothing saying why.  It is
        # easy to reach: clone a site, delete it, clone it again, and the
        # certificate outlives the site that was deleted.
        #
        # Reuse it when it is a certificate for these names, since that is the
        # thing the tick was asking for.  Refuse clearly when it is not, rather
        # than attaching a certificate for somewhere else.
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
            # Renew from wherever the original came from.  A clone of a site on
            # a bought certificate that quietly renewed from somewhere else is
            # a change nobody asked for and nobody sees until a browser
            # complains about the issuer.
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
    Somebody is making this site the default one.  Is that going to work?

    nginx allows one default server per address and port and refuses to start
    with two, and an apply is all or nothing, so a second one does not break
    the site that asked for it, it stops **the whole fleet applying anything**.

    Two ways that happens.  Another managed site already has it, which we can
    see in our own database.  Or something outside the managed tree has it,
    which we cannot: `nginx-installer.sh` writes a catch all at
    sites-enabled/default.conf with `listen 80 default_server`, and nothing in
    the manager knew that file was there.  So the tick box saved, redisplayed,
    rendered correctly, and then every apply was refused with "a duplicate
    default server for 0.0.0.0:80" naming a file the person never wrote.

    Asked of the node rather than assumed, because the answer is about what is
    on disk today, and refused here rather than at apply time so it costs one
    save instead of everybody's next change.
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
        # If the node cannot be asked, do not invent an answer.  The apply
        # still checks the config on every node before anything goes live, so
        # the worst case is the old behaviour rather than a wrong refusal.
        log.warning("could not ask this node about the default site")
        return

    # Only the ones the manager cannot take over.  A symlink in sites-enabled
    # is stood down at apply time and put back when no managed site wants the
    # role, so it is not a reason to refuse the setting.  Anything else is
    # somebody's own file and an apply does not get to move it quietly.
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

    Settings get checked against the catalog, which is the same thing the
    renderer reads.  A value that would produce config nginx will not load gets
    refused here rather than at apply time.
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

    # Foreign keys go through the guard too, so pointing a site at a pool you
    # are not allowed to see fails the same way as asking for it directly.
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
        # Writing a whole server block by hand is an admin thing.  An operator
        # can change any setting they like through the forms, where every value
        # is checked, but hand written config is a much bigger door.
        if payload["config_mode"] == "raw":
            g.require("raw_config")

        # Going back to the form has to take the hand written file with it.
        #
        # `custom_config` means two different things depending on the mode.  In
        # raw mode it is the whole file, `server { ... }` and all.  In form mode
        # it is a snippet pasted **inside** the generated server block, which is
        # where the importer puts directives it could not represent.  So
        # switching back left a complete file being injected inside a server
        # block, nginx said `"server" directive is not allowed here`, and
        # because an apply is all or nothing, that one site stopped the whole
        # fleet applying anything at all.  The error named a filename, not the
        # switch that caused it.
        #
        # Only when it really is a whole file.  An importer snippet is a
        # fragment and stays, because that one is doing its job.
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

    A `server` block at the start of a line is the tell.  A snippet meant to go
    inside a server block never has one, and a whole file always does.  Used
    when a site leaves raw config mode, so the file it was being served from
    does not get pasted inside the generated block afterwards.
    """
    if not text:
        return False
    return bool(_re.search(r"(?m)^\s*server\s*\{", str(text)))


def _validate_settings(raw, context: str) -> dict:
    """
    Check a settings blob against the catalog.

    Anything we do not recognize is dropped rather than stored.  Keeping unknown
    keys around would mean a typo silently does nothing forever while the person
    who made it swears they set the value.
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
            # Refusing to turn something off that cannot be on is nonsense, and
            # it used to take the whole save with it.  The GUI sends the entire
            # settings blob, a disabled checkbox still reads as false, so every
            # save on a fleet missing any module was refused with a message
            # naming a feature the person had not touched.  A value that asks
            # for nothing is accepted and dropped; only actually asking for the
            # feature is refused.
            if not value or value == feature.default:
                continue
            problems.append(f"{feature.label} {feature.unavailable_reason(caps.modules, caps.version_tuple)}")
            continue

        # A zone picker, whose choices are rows rather than catalog options.
        # Checked against what exists, and the message names what does, because
        # the usual cause is a zone that was renamed or deleted after a site
        # was pointed at it.
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

        # WAF strictness is a level or the name of a tuned profile, and only
        # the levels can be in the catalog.
        #
        # The catalog is static by design and a profile is a database row that
        # did not exist when it was written, so `custom:whatever` failed the
        # select check and every attempt to apply a profile came back 400.  The
        # picker offered profiles, the renderer understood them, the save was
        # the one link in the chain that did not, so the feature had never
        # worked end to end.
        #
        # Checked against the profiles that exist rather than waved through.  A
        # name that matches nothing renders a site with no exclusions at all,
        # which is a site refusing traffic somebody believed they had allowed,
        # and it would do it quietly.
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
    """Turn an nginx size like 16k or 1m into bytes.  None if it is not one."""
    import re as _re

    m = _re.fullmatch(r"(\d+)([kKmMgG]?)", str(value).strip())
    if not m:
        return None
    n = int(m.group(1))
    return n * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[m.group(2).lower()]


def _cross_check(settings: dict) -> list:
    """
    Settings that are each fine alone and wrong together.

    Checking values one at a time is not enough, because nginx has rules about
    how some of them relate.  The proxy buffer one below is the worst of them:
    it is easy to hit, and the error nginx gives is

      "proxy_busy_buffers_size" must be less than the size of all
      "proxy_buffers" minus one buffer

    which mentions a directive you never set, and does not say what to do.
    Catching it here with an explanation beats letting somebody meet that.
    """
    problems = []

    # A positive model with nothing in it refuses the whole site.
    #
    # The renderer already refuses to write that and says so in the config, but
    # a setting that saves and then quietly does nothing is worse than one that
    # will not save: somebody ticks enforce, sees no error, and believes the
    # site is locked down when it is not.  So it is caught here, where there is
    # a person to tell.
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

    # Credentials plus any origin is a pair no browser will use.  The help text
    # on both settings says so, and until now nothing stopped somebody saving
    # it, which leaves a site that looks configured for cross site calls and
    # refuses every one of them with a message about the origin.
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
                # nginx works out proxy_busy_buffers_size for you when you do
                # not set it, as twice the bigger of the header buffer and one
                # body buffer.  That figure then has to fit inside everything
                # except one buffer.
                # The renderer pins proxy_busy_buffers_size for us, so this
                # only has to catch the case where no value can satisfy nginx
                # at all, which means the buffers really are too small.
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

    # Caching a page for a logged in user and handing it to somebody else is a
    # real data leak, and it is an easy one to set up by accident.
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

    # * with credentials is refused by browsers, and working around the refusal
    # opens the API to every site on the internet.
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

    The check nobody has that everybody needs.  A site serving example.com and
    www.example.com on a certificate carrying only one of them is green on the
    site page, valid on the certificate page, and a browser warning on the name
    nobody tested.  Both lists are already in the database, so saying it costs
    nothing.

    Wildcards are worked out rather than compared as text, because
    *.example.com covers www.example.com and does not cover example.com, and
    that is the trap people meet the day they buy one.
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
        # What adding the www would mean for this site, worked out here so the
        # page does not have to know the rules about which names have a pair.
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
        # The same shape the locations endpoint returns, from the same
        # function, rather than a second list written out here.
        #
        # The copy that used to live here left out custom_config, among other
        # fields, so a caller reading a site's paths from this endpoint was
        # told every one of them had no hand written config.  Anything acting
        # on that then skips the path that does have some, or writes it back
        # empty.  Both happened.  Two serialisers for one object drift the
        # moment somebody adds a field to whichever they were looking at.
        "locations": [
            _location_json(loc)
            for loc in sorted(h.locations, key=lambda x: x.sort_order or 0)
        ],
        "tunnel_workloads": _tunnels_behind(h),
    }


def _tunnels_behind(h):
    """
    Which tunnel workloads this site's traffic actually ends up at.

    The dependency is real and completely invisible: a site points at a pool,
    the pool names an address, and that address belongs to a machine that is
    only reachable because it is on the tunnel.  Nothing on the site page says
    so, so somebody removing a workload, or wondering why a site broke when the
    tunnel went down, has to walk pools and members by hand to find out.

    Both the site's own pool and the pools its paths use, since a site with one
    backend on the Basics tab and another on a path depends on both, and the
    one that gets forgotten is always the second.

    Matched on address rather than on name.  The pool member holds whatever
    somebody typed, and what makes it a tunnel workload is that the address is
    the one the tunnel handed out.
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
             # Said out loud, because a workload that was never enrolled is a
             # backend that has never once answered, and that is a different
             # problem from one that is simply down.
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

    # The name check lives in _apply_pool_fields, which runs below, so that
    # creating and renaming cannot drift apart the way they already did once.
    name = validate_name(payload.get("name"), "pool name")
    pool = Pool(name=name)

    # The Settings page calls this "the default health check interval" and says
    # it is "only the default for a new pool".  Nothing read it, so a new pool
    # took the hardcoded ten seconds from the column and the setting was saved,
    # redisplayed and completely inert.  Seed it here, before the payload is
    # applied, so anything sent explicitly still wins.
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

    # A pool a site is using cannot just vanish, the site would render a
    # proxy_pass at an upstream that does not exist and nginx would not start.
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
# The shared secret nginx puts on requests it sends to a pool, so the backend
# can turn away anything that did not come through the fleet.
#
# Rotating takes two steps on purpose.  You cannot change both ends at the same
# instant, and nginx can only send one value, so the only safe order is: stage a
# new one, teach the backends to accept either, then activate.  A single button
# that swapped it would break every request in the gap.
# =============================================================================

@router.post("/pools/{pool_id}/token")
async def create_pool_token(pool_id: str, request: Request,
                            g: ObjectGuard = Depends(changing)):
    pool = g.get(Pool, pool_id, "edit_pools")
    payload = await request.json() if await request.body() else {}

    supplied = str(payload.get("value") or "").strip()
    if supplied:
        # Somebody bringing a secret their backends already check.  Keep the bar
        # high enough that a guessable one cannot be set by accident.
        if len(supplied) < 16:
            raise HTTPException(
                status_code=400,
                detail="a token needs to be at least 16 characters, longer is better",
            )
        if len(supplied) > 256:
            raise HTTPException(status_code=400, detail="that token is too long, keep it under 256")

        # Hold this to a plain charset rather than blocking a list of bad
        # characters.  This value gets written into an nginx directive, and a
        # semicolon in there ends the directive early and turns the rest into
        # config.  The renderer would catch it and refuse, but by then the whole
        # fleet's apply is broken over one bad field, so it gets caught here.
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
        # Already sending one, so this is a rotation.  Park it in next and leave
        # what nginx is sending alone until somebody activates.
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
    Hand back the actual values.

    Anybody who can edit this pool can already change the token, so showing it
    to them gives away nothing they could not get anyway.  It is audited because
    reading a secret is worth a line in the log even when it is allowed.
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

    # token_enabled can be switched off here, which stops nginx sending the
    # header without throwing the secret away.  Turning it on does nothing on
    # its own: there has to be a token as well, which is its own endpoint.
    if "backend_kind" in payload:
        if payload["backend_kind"] not in ("servers", "site"):
            raise HTTPException(status_code=400,
                                detail="backend kind has to be servers or site")
        pool.backend_kind = payload["backend_kind"]

    # A path that goes straight into a directive, so it has to look like a path
    # and nothing else.  Blank means the system bundle.
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

    # Somebody touching the switch settles it.  From here on we do what they
    # said and stop working it out from the member ports, including when they
    # turn it off with a member on 443, which is theirs to decide.
    if "backend_tls" in payload:
        pool.backend_tls = bool(payload["backend_tls"])
        pool.backend_tls_set = True

    # The SNI name goes on the wire and into an nginx directive, so it has to
    # look like a hostname.  A stray space or semicolon here would land straight
    # in the config, and a config nginx will not load blocks the whole fleet.
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
        # Pool settings are our own, not nginx directives, so they get their own
        # small check rather than going through the catalog.
        pool.settings = json.dumps(_validate_pool_settings(payload["settings"]))


def _validate_pool_settings(raw) -> dict:
    """Check the settings behind our stand ins for the paid features."""
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
        # Where this pool's backends publish what they are doing.  A template,
        # since the members of a pool are nearly always the same kind of box
        # with the same exporter on the same port, and one field per member is
        # how it ends up half filled in.
        "member_metrics_url": "url",

        # Where the application sits on these backends, when it is not at the
        # root.  It belongs here because it is a fact about the backend and not
        # about any one site pointed at it, and because this is where people
        # look for it: the first attempt at setting it was typing the path onto
        # a member address, which is host and port and gets refused for the
        # want of a valid port.  A site can still override it.
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
            # http or https, and nothing else.  This is a URL the manager will
            # fetch on a timer, so a file: or a gopher: here would be somebody
            # pointing it at something it should not read.
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

            # Where it points, as well as what scheme it uses.  The manager
            # fetches this on a timer from a load balancer, so an address only
            # it can reach is a request forgery primitive rather than a metrics
            # endpoint.
            #
            # Only checkable here when the host is written out.  A template
            # using {host} becomes a different address per member, so that case
            # is checked again where the URL is actually built, in metrics.py.
            from app.core.exporters import unsafe_fetch_target

            bad_target = unsafe_fetch_target(text)
            if bad_target:
                raise HTTPException(status_code=400, detail=bad_target)

            cleaned[key] = text
        elif expected == "path":
            # A path on the backend, not a URL and not a host.  The slashes are
            # put right here rather than asked of whoever typed it, because the
            # trailing one is what makes nginx swap the matched part of the
            # path instead of gluing the two together, and that is exactly the
            # kind of one character difference nobody should have to know.
            text = str(value or "").strip()
            if not text:
                cleaned[key] = ""
                continue

            # Checked before the slashes are put right, or a whole URL becomes
            # a path called /http://host:8080/shop/ and renders a proxy_pass
            # nobody meant.  Said plainly, because pasting the backend's URL in
            # here is the obvious thing to try.
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
        # What the trust setup looks like, without the secret in it.  The GUI
        # needs to know there is a token and whether a rotation is half done.
        # It does not need the value, and putting it in every pool response
        # would splash it across logs and browser caches for no reason.
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

    # Either an IP or a hostname.  Both are fine, but it has to be one of them,
    # since this ends up in a config file.
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

    Typing them one at a time is fine for two and miserable for thirty, and
    thirty is exactly when a typo slips through and you do not notice until
    something is quietly getting no traffic.

    Every line is checked before a single one is saved.  A half loaded pool is
    worse than a rejected one, because you cannot tell by looking which lines
    made it, and adding the list again would collide with the half that did.
    """
    pool = g.get(Pool, pool_id, "edit_pools")

    body = await request.json()
    text = body.get("text")
    if not isinstance(text, str) or not text.strip():
        raise HTTPException(status_code=400, detail="paste some backends first")

    if len(text) > 100_000:
        raise HTTPException(status_code=400, detail="that is too much at once, split it up")

    # What is already here, so we can say which lines are duplicates rather than
    # failing on the first one and making them find it.
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

    # Look the names up together.  One at a time is fine for three and slow
    # enough to look broken for fifty, since every miss waits out its own
    # timeout before the next one starts.
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
    Refuse a backend name this box cannot look up.

    nginx resolves the names in an upstream block when it loads the config, not
    when a request arrives.  A name that does not resolve is not a backend that
    is down, it is a config nginx refuses to load at all, and since one node
    saying no stops the whole fleet, one typo here blocks every change on every
    node until somebody finds it.

    The error nginx gives is "host not found in upstream", which arrives later,
    from a different page, about a file the person never opened.  Saying it here
    costs one lookup and points at the box they are typing into.

    This only proves the name resolves from this node.  A standby with different
    DNS can still fail the apply, and the two phase apply is what catches that.
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
    Pull an address and a port out of one line.

    People paste these from all sorts of places, so take the shapes that turn up
    rather than making them reformat a list they already have:
    host:8080, host 8080, host,8080, host, and [::1]:8080 for IPv6.

    A bare host means port 80, same as adding one by hand.
    """
    line = line.replace("\t", " ").replace(",", " ").strip()

    # IPv6 in brackets keeps its colons, so the port is only what follows the
    # closing bracket.  Splitting on the last colon would take the address apart.
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
        # Bare IPv6 with no brackets.  There is no way to tell a port from
        # another group, so ask for brackets rather than guess wrong.
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

    Draining is the polite one.  The member stops taking new connections but
    existing ones finish, so you can patch a box without cutting anybody off
    mid request.
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


# nginx refuses "backup" on a server in a pool that balances by hashing.  Its
# own message is "balancing method does not support parameter backup", which
# is true and tells somebody looking at a screen nothing about what to do.
#
# Caught here so it is said in words, before the change is saved, rather than
# surfacing out of a failed apply.
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
    Push the current config out to the whole fleet.

    Every node stages and tests it before any node applies it.  See
    cluster.apply_config for the details of what happens if one says no.
    """
    g.require("apply_config")

    try:
        payload = await request.json()
    except Exception:
        payload = {}

    summary = str(payload.get("summary", "manual apply"))[:500]

    # Force is how somebody says they really do mean to remove every site.  It
    # is off unless asked for, because the case it exists for is rare and the
    # case it guards against takes the fleet down.
    force = bool(payload.get("force"))
    if force:
        log.warning("%s applied with force, so the wipe check was skipped",
                    g.user.username)

    # Two things that can go wrong here and used to come back as a bare
    # "Internal Server Error", which tells somebody nothing and hides an
    # answer they could have acted on.
    #
    # A ClusterError is a refusal with a reason in it, so it goes back as one.
    # A locked database is the other: SQLite allows one writer, and an apply
    # started while something else is still committing gets refused by the
    # driver rather than by us.  That one is worth retrying, and saying so is
    # the whole difference between "try that again" and "the tool is broken".
    #
    # RoleNotSettled is the third, and it is a retry rather than a refusal: for
    # a few seconds after a restart this node has stood itself down and no
    # election has run yet.  A 409 there reads as "you are on the wrong box",
    # which is what the old message said and it was not true.
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
    """
    Show the config we would write, without writing it.

    Worth having before a big change.  Reading the diff is a lot faster than
    working out what went wrong afterwards.
    """
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
    Work out what would have to come out for nginx to take this config.

    Two steps on purpose, and this is the first one.  With no `confirm` it
    changes nothing and gives back the list of lines it would comment out, each
    with the reason nginx gave, so somebody can read it before agreeing.  With
    `confirm` it makes those same changes and stops there: it does not apply, so
    the config still has to be pushed the normal way and still gets staged and
    tested on every node first.

    Not folded into apply.  Apply goes to the whole fleet and its audit entry
    says "applied", so a directive quietly disappearing inside it would be a
    change nobody sanctioned and nobody could find afterwards.  The ones that go
    missing here are exactly the ones worth noticing: `ssl_verify_client` and
    `ssl_protocols` are real controls, and a config error turning into weaker
    TLS without a word is a worse outcome than an apply that fails loudly.
    """
    g.require("edit_sites")
    payload = await request.json() if await request.body() else {}
    confirm = bool(payload.get("confirm"))

    def render():
        files, _checksum, _snapshot = render_current(g.session)
        return files

    async def test(files):
        """Stage it and ask nginx.  Staging only, so nothing goes live."""
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
        # Worked out against the session and deliberately not kept.
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
    The nginx this site turns into.

    In gui mode this is generated, so it is read only and there to be looked at.
    In raw mode it is what the person typed, and it is what gets written.
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

    Checked twice before it is stored: our own parser for the obvious mistakes,
    then nginx itself in the context of the whole config.  Storing something
    that fails nginx -t would leave a site that cannot be applied and no obvious
    way back, so it does not get saved at all.
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

    # Try it against nginx in place, so a site that would not load never gets
    # stored.  We swap this site's file for the candidate and test the lot.
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
    Check a raw config someone typed, before they save it.

    Two passes.  Ours is instant and catches the obvious things right in the
    editor.  Then it goes to nginx itself, which is the only thing that really
    knows.  Nothing gets saved on the strength of our check alone.
    """
    payload = await request.json()
    text = payload.get("config", "")

    problems = quick_check(text)

    # Only bother nginx if our own pass found nothing fatal.  No point in a
    # round trip to tell somebody about a missing brace we already spotted.
    nginx_result = None
    if not any(p["severity"] == "error" for p in problems):
        try:
            # Test the candidate in the context of everything else, not on its
            # own.  Two reasons.  A site alone has no log formats or upstreams,
            # so it fails for reasons that have nothing to do with what was
            # typed.  And staging is shared, so writing just this one file would
            # throw away whatever was staged and leave the next apply broken.
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
    Read a config back into GUI settings.

    This is the half that makes the editor two way.  Somebody types
    client_max_body_size 50m into the file and the form picks it up.
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

    # The new box does not have the project on it yet, so the command has to get
    # the code there first.  Handing somebody a command that starts with the
    # name of a script they do not have is a good way to waste their afternoon.
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

    # Say what is true now, and do not invent a reason for it.
    #
    # The first cut of this said the chosen node was "not in a fit state"
    # whenever it was not yet active, which is wrong most of the time: moving
    # the role takes a couple of seconds and there is a moment in the middle
    # where neither node holds it.  Reporting that as a fault sends somebody
    # looking for a problem that is about to fix itself.  So the only time a
    # reason is given is when the roster actually says the node cannot take it.
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
    Take a node out of the cluster.

    There was no way to do this at all, which is a problem the moment somebody
    registers the wrong box.  A node that is not really there still counts
    towards quorum, so a phantom entry can stop the real nodes electing anybody
    and there was no way to clear it out short of editing the database.

    This only forgets the node here.  It does not reach out and uninstall
    anything, because the usual reason for doing this is that the node is not
    answering in the first place.  If it is still running out there, stop it or
    it will carry on heartbeating and reappear.
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

    # Roles are worked out from who is left, so run that again now rather than
    # waiting for the timer.  Dropping a dead node is often the thing that lets
    # the survivors elect somebody.
    try:
        await get_cluster().run_election()
    except Exception as exc:
        log.warning("election after removing %s did not run: %s", node_name, exc)

    return {"ok": True, "removed": node_name}


@router.post("/cluster/resync")
async def resync(g: ObjectGuard = Depends(changing)):
    """
    Push the current config at anybody who is behind, right now.

    Certificates go too.  Config was the only thing this caught, so a node that
    joined after a certificate was issued stayed without it and pressing Sync
    now did not help, which is the one button anybody would try.  Sync should
    mean everything the other nodes need, not just the config files.
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
# These are the shared pieces sites point at.  nginx wants them declared once at
# the http level and then used further down, which is why they are their own
# objects rather than settings on a site.  It also means several sites can share
# one bucket, which is usually what you want for something like a login limit.

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
    """Which sites point at this zone.  Stops somebody deleting one still in use."""
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
            # Renaming a zone a site still points at would break that site's
            # config, because the name is what links the two.
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
        # An nginx variable, possibly a couple joined together.  Anything else
        # would end up written straight into a directive.
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
        # Somewhere sensible, not anywhere on the disk.  A cache path pointed at
        # the wrong place fills a partition somebody was relying on.
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
    # Sites and paths both, because deleting one that a path is using is
    # exactly as much of a change as deleting one a site is using, and only
    # counting sites made the refusal below miss half of them.
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
    What one page really looks like, rendered the same way the fleet renders it.

    Deliberately the same function the renderer calls, not a second one that
    does nearly the same thing.  A preview that is its own code path is a
    preview that can be right about a page which then comes out wrong.

    Handed back as HTML rather than as a string in some json, because a person
    looking at their page wants to see the page.  See sandboxed_html_headers
    for what stops that being a way of running their markup on our origin.
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

    # Unlike a pool, a template going away cannot break a site: nginx falls back
    # to its own page and keeps the real status.  It still gets refused, because
    # a template being deleted out from under four sites is a change to four
    # sites and the person doing it should know that before it happens.
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
    Take a picture for a template.

    The name is ours, not the uploader's: it goes through validate_name and it
    is only ever used as a lookup key in {{image:...}}.  Nothing here ever
    becomes a path, which is the point of keeping these in the database and
    inlining them rather than writing them out as files.
    """
    template = g.get(ErrorPageTemplate, template_id, "edit_sites")
    payload = await request.json()

    name = validate_name(payload.get("name"), "picture name")
    raw_b64 = payload.get("data") or ""
    if not isinstance(raw_b64, str):
        raise HTTPException(status_code=400, detail="send the picture as base64")

    # Strip a data: prefix, since that is what a browser FileReader hands over.
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

    # Same name replaces, so re-uploading a logo does not leave the old one
    # behind taking up the budget and never being referenced by anything.
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
    What each pool's backends say they are doing.

    Empty for a pool that has no metrics URL set, which is not an error: most
    backends publish nothing and the page says not measured rather than drawing
    an empty chart, because an empty chart reads as zero.
    """
    g.require("view")
    from app.core.metrics import get_collector

    minutes = max(1, min(int(minutes or 60), 240))
    return {
        "minutes": minutes,
        "pools": get_collector().member_snapshot(with_series=True,
                                                 limit=minutes * 2),
        # Which pools are set up to be asked at all, so the page can tell a
        # pool that publishes nothing from one that has never been looked at.
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
    The same numbers as /metrics, with the history behind them.

    `minutes` is capped by what is kept, which is a couple of hours in memory.
    Asking for more than that is not an error, it just gets what there is: the
    page says how far back the data really goes rather than drawing a flat line
    across a window nobody has numbers for.
    """
    g.require("view")
    from app.core.metrics import get_collector

    minutes = max(1, min(int(minutes or 60), 240))
    # One sample every fifteen seconds, so four a minute.
    limit = minutes * 4
    return {
        "minutes": minutes,
        "nodes": get_collector().snapshot(with_series=True, limit=limit),
    }


@router.get("/metrics")
async def nginx_metrics(g: ObjectGuard = Depends(guard)):
    """
    Connection and request numbers for every node, with rates.

    stub_status is what free nginx gives, and four of its seven numbers are
    counters, so the useful part is the difference between two readings rather
    than the readings themselves.  See app/core/metrics.py.

    Deliberately not per site or per backend.  Those need the access log read,
    which is a real piece of work and is written up in docs/plus-parity.md as a
    plan rather than pretended to be here.
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
             # The stored name, not a lookup through node_id.  On any node
             # other than the one that wrote the row, that id is a different
             # machine, so resolving it here would report the wrong node.
             "node_name": (a.node_name
                           or (a.node.name if a.node else None)),
             "priority": a.priority, "enabled": a.enabled,
             # Next to the answer rather than in a list somewhere else, so it
             # is in front of the person editing the thing it is about.
             "address_warning": _answer_warnings().get(a.id)}
            for a in r.answers
        ],
    }


def _answer_warnings():
    """
    Answers whose address does not belong to the node they are tied to.

    Worked out once per request and cached on the session, because a zone with
    many records would otherwise walk the node table for every answer.
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
        # What the listener is actually doing, because a zone that exists in
        # the database and a zone the world can resolve are different things
        # and the gap between them is the whole of what goes wrong here.
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
        # The nodes an answer can be tied to, with the address each one would
        # hand out.  The cluster page does not publish node ids and there is no
        # reason it should, but an answer is stored against one, so the picker
        # has to get them from somewhere.
        #
        # Split by family rather than offered as one address, because the
        # record type decides which one is even legal.  A node's public address
        # here is quite often the IPv6 one, and handing that to an A record
        # produces something that looks filled in and cannot be saved.
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
    The address of this node worth putting in public DNS, for one family.

    The public one first where we know it, because the address a node uses to
    reach its peers is often private, and a private address in public DNS is a
    mistake nobody notices until somebody outside cannot get in.
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
    # Every change bumps the serial.  Nothing here transfers a zone today, so
    # it changes nothing that works, and a zone whose serial never moves is a
    # zone no secondary could ever be added to later.
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
        # Said rather than refused, because a zone can be built before the
        # delegation is in place and refusing would force the wrong order.
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
    # Saved either way.  A warning here is advice, not a refusal: pointing an
    # answer at a floating address, or at something in front of the node, is a
    # real thing people do and the product cannot tell it from a typo.
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
            # The name is what survives the trip to another node.  The id is
            # kept only so this box's own pages can resolve it without a join.
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
    Rebuild the listener's snapshot straight away rather than waiting.

    The timer would pick it up within ten seconds, and somebody who just saved
    a record and immediately ran dig would see the old answer and reasonably
    conclude it had not worked.
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

    Everything else here is served by nginx from files, and those files reach
    the other nodes on an apply.  DNS is the exception: the listener answers
    out of the database, so on any node whose database has not got the zones,
    it answers nothing at all.

    The config snapshot is what carries database rows between nodes, and it
    only travels when the rendered nginx config changes.  Editing a DNS record
    changes no nginx file, so without this the zones stayed on the box they
    were typed into and every other node stayed silent.  On a feature whose
    whole job is to survive a node dying, the node that stays silent is the one
    that was supposed to take over.

    Forced, because "nothing changed" is exactly the answer the renderer gives
    for a DNS edit, and that answer is what used to stop the zones moving.
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
        # No loop, which means a script or a test rather than a request.  The
        # local listener is already up to date, and the timer on each node will
        # bring the rest along at the next apply.
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
        # Never the key itself, only whether one is stored.  The same rule the
        # dns credentials already follow.
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
    # Refused rather than cascaded, the same as a pool a site is using.  A
    # certificate whose authority has gone cannot be renewed, and it would not
    # say so until the renewal.
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
    Register an account against this authority, and keep nothing but the answer.

    Worth its own button because these credentials are wrong in a particular
    way: they look fine when they are typed and they fail at first use, which
    is at a renewal months later at whatever hour the timer runs.  Trying it
    now turns that into a red message while somebody is still looking at it.
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
        # Blank means leave the stored one alone, so somebody editing the name
        # does not have to paste the key again.
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

# Variables a map is allowed to read.
#
# Not a nicety.  nginx refuses a map whose source variable it does not know,
# with "unknown variable", and it refuses it at load time on every node, so one
# typo here stops the whole fleet applying anything at all until somebody works
# out which map is to blame.  Checking on the way in turns that into a message
# next to the box it was typed in.
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

# Whole families of them, where the bit after the prefix is whatever the client
# sent.  nginx makes these up on demand so any name after the prefix is fine.
MAP_SOURCE_PREFIXES = (
    "$http_", "$arg_", "$cookie_", "$sent_http_", "$upstream_http_",
    "$upstream_cookie_", "$ssl_", "$geoip_", "$proxy_protocol_tlv_",
)

# Names a map must not produce, because nginx already has them and says
# "the duplicate variable" rather than anything about a map.
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
        # What a map is allowed to read, so the page can offer them rather than
        # leaving somebody to guess and take the fleet down with a typo.
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

    # A map nothing reads is dead weight; a map something reads is load bearing,
    # and nginx will not start with a variable that has no map behind it.  We
    # cannot see into raw config or a setting's text reliably, so this looks and
    # says what it found rather than refusing outright.
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
        # Two maps writing one variable is accepted by nginx and only one of
        # them wins, silently, which is a worse day than a refusal.
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
                # nginx takes the first and ignores the rest, so the second one
                # is a rule somebody wrote that will never fire.
                raise HTTPException(
                    status_code=409,
                    detail=(f"{match} is in this map twice.  nginx uses the first "
                            f"one and the other never fires."))
            seen.add(match)
            clean.append({"match": match, "value": value})
        block.entries = json.dumps(clean)


def _check_map_text(value, what):
    """
    A match or a value, checked the way the renderer will write it.

    Backslashes are allowed on purpose, because a map is mostly regular
    expressions and almost every useful one has a backslash in it.  What is
    refused is what would end the directive early or run past the closing
    quote.  See map_value in render.py, which does the writing.
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

# Ports the manager itself answers on.  Handing one to a stream takes the GUI
# away from whoever is doing it, from inside the GUI, which is a bad afternoon.
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
        # Said out loud rather than left to a config that silently does nothing.
        # nginx has to be built --with-stream and the installer does that, but a
        # binary from somewhere else may not be.
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
        # The model carries both a protocol column and a udp flag, and the
        # renderer reads either one.  Setting them together here is the only
        # thing stopping them disagreeing, which is a stream that says udp on
        # the page and listens on tcp.
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

        # A site already listening there is the other way to lose a service, and
        # nginx would refuse to start rather than quietly picking one, so the
        # whole fleet stops applying anything until somebody spots it.
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

    # Two streams on one address and port is the same refusal as above, and
    # worth catching here rather than at apply time on somebody else's node.
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
        # A short list on purpose.  The catalog is written for http and most of
        # it means nothing on a raw socket, so rather than offer settings that
        # quietly do nothing, a stream takes these few and hand written config
        # for anything else.
        for key in ("proxy_timeout", "proxy_connect_timeout"):
            value = str(raw.get(key) or "").strip()
            if not value:
                continue
            if not re.fullmatch(r"\d+[smhd]?", value):
                raise HTTPException(
                    status_code=400,
                    detail=f"{key} looks like 60s, 5m or 1h")
            clean[key] = value

        # The TLS ones do mean something on a raw socket, and until they were
        # allowed through here the renderer had a version pair written into it
        # and no way to say otherwise.  A stream that has never been given a
        # list keeps the pair it has always had; setting one here is how it
        # moves, the same as a site.
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
            # Keep the file in version order however the list arrived, so two
            # streams that mean the same thing render the same way.
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

    # Everything that can point at an access list, not just sites.
    #
    # This used to ask about sites alone, so a list protecting one path, or a
    # tcp service, could be deleted out from under it.  The row kept its
    # access_list_id, the id no longer existed, and the next render quietly
    # dropped every rule: the path went from protected to public with nothing
    # said and nothing to see on the page.  Protecting a path rather than a
    # whole site is the normal shape for an admin area, so it was easy to
    # reach.
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

    # Trusting a forwarded address with nobody named to trust it from.
    #
    # It is not dangerous, it is inert: without a set_real_ip_from line nginx
    # trusts no source, so the header is ignored and the rules are applied to
    # the address the connection really came from.  Which is exactly the
    # problem.  The tick box is on, the page says the forwarded address is
    # being used, and it is not, so somebody puts their CDN in front and
    # wonders why every visitor arrives wearing the CDN's address.
    #
    # A setting that is saved, redisplayed and does nothing is worse than no
    # setting.  Refused here with the fix in the message, the same as the
    # other four values this API refuses.  One access list on this fleet was
    # already sitting in exactly this state, found by the access list round.
    # Only when this save is actually about the forwarded address, so that an
    # unrelated edit to a list that is already in this state is not refused
    # for something the person did not touch.  That is the shape of bug this
    # project has shipped twice: saving one setting undoing another.
    touched = "use_real_ip" in payload or "real_ip_from" in payload
    if touched and acl.use_real_ip and not acl.trusted_proxies():
        raise HTTPException(
            status_code=400,
            detail="trusting a forwarded address needs at least one trusted "
                   "proxy, or the header is ignored and the setting does "
                   "nothing.  Add the address of whatever sits in front, or "
                   "turn the setting off.")

    # Basic auth users.  The password is hashed here and the plain one never
    # stored, same as any other password in this tool.
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
    Hash a basic auth password the way nginx expects to read it.

    APR1 is what htpasswd writes by default and what nginx understands.  It is
    not a good hash by modern standards, and that is a property of the format
    rather than a choice.  Basic auth over https is a speed bump on top of the
    IP rules, not the thing holding the door shut, and the help text says so.
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
    """What a rebuild would do, before anybody commits to forty minutes of it."""
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

    # The WAF module is a build option, so it is decided here rather than on a
    # page of its own.  Stored before the walk starts, because every node in
    # the walk reads it as it goes: the whole fleet has to come out of this
    # agreeing about whether the module is there.
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
    What each node was built with, and where they differ.

    Adding a module means rebuilding, so this sits next to the upgrade page
    rather than off on its own.
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
        # What the next rebuild will do about the WAF module, so the checkbox
        # on the page shows what is actually in force rather than defaulting to
        # off and quietly turning it off on the next rebuild.
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
                # Nothing renews an uploaded one, so the page has to be the
                # thing that says the expiry is coming.  A row waiting on an
                # authority has no certificate at all yet and should not read
                # as a broken one.
                "has_material": c.has_material(),
                "awaiting_csr": bool(c.csr_pem and not c.not_after),
                # Names the sites using this certificate serve and it does not
                # carry.  A browser warning waiting to happen, and both lists
                # are right here, so there is no excuse for not saying it.
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

    # A wildcard can only be done over dns-01.  Lets Encrypt will not issue one
    # from an http challenge, so catching it here saves a confusing failure.
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

    # Which authority to buy it from, and to renew it from later.  Empty is
    # Lets Encrypt, which is what every existing certificate is.
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
    Put the certificate and its key on the row, together, or not at all.

    Written as one step on purpose.  Half of a pair on a row is the same
    problem as half of a pair on disk, and this system has met that twice.
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

    # Nothing renews these for us.  Lets Encrypt certificates get a renewal
    # scheduled and these get a warning on the page instead, so leaving
    # auto_renew on would put them in a queue that can never do anything for
    # them and hide the fact that a person has to act.
    cert.auto_renew = False
    cert.csr_pem = None
    cert.csr_created_at = None


@router.post("/certs/analyse")
async def analyse_cert_upload(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Say what an upload is before anything is kept.

    Same call the save uses, so what somebody is shown and what gets stored
    cannot disagree.  A preview that is its own code path is a preview that can
    be right about a certificate which then goes in wrong.
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
    """Everything worth showing, and never the private key."""
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
    Take a field that might be pasted text or a base64 file from the browser.

    A certificate is usually pasted and a PKCS12 never can be, so both arrive
    through the same fields and this works out which is which.
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
    """Take a certificate somebody already has and put it on every node."""
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
    """Make one on the spot, for a name no public authority will sign."""
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
    Make a signing request, and keep the key here.

    The row this creates has no certificate on it yet, so it has no not_after,
    so the renderer will not point nginx at it.  That is what makes a half
    finished request harmless to leave sitting there while an authority takes
    its time.
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
    """Pair the certificate an authority sent back with the key we kept."""
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
    Write the material to every node, and never let that fail the save.

    The row is already committed by the time this runs, and that ordering is
    deliberate.  A peer being down is a copy to make later, not a reason to
    throw away a certificate somebody just uploaded, and the file check puts it
    right on its own within the minute.
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

    audit.record("cert.issue", user=g.user, object_type="cert", object_name=cert.name,
                 detail=f"issued by {result.get('issued_by')}")
    return result


@router.post("/certs/{cert_id}/replicate")
async def replicate_cert(cert_id: str, g: ObjectGuard = Depends(changing)):
    """
    Push a certificate out to every node again.

    Replication used to happen only as the last step of issuing.  That is fine
    until the fleet changes afterwards: a node that joins later was never sent
    the certificates that already existed, so it sat there missing them with no
    way to ask for a copy.  "pushed to 1 of 2" and no button to do anything
    about it.

    Safe to run whenever.  A node that already has the files just gets the same
    bytes written over the top.
    """
    cert = g.get(Certificate, cert_id, "edit_certs")

    # Which way round depends on where the files actually are.
    #
    # An issued certificate is exported from whichever node certbot wrote it
    # on.  One we hold the material for is written from the database, and
    # asking certbot's folder for it gets "no cert called that", which is a
    # confusing way to be told the button was pointed at the wrong code.
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

    Worth its own endpoint.  When issuance fails this is the first thing to
    look at, and it tells you what DNS says versus what your nodes think their
    addresses are, side by side.
    """
    cert = g.get(Certificate, cert_id)
    domains = cert.domain_list()
    if not domains:
        raise HTTPException(status_code=400, detail="that certificate has no domains")

    placement = await pick_issuing_node(domains[0])

    # The stored check too, so the dialog you opened because issuance looked
    # wrong also tells you the record has been pointing elsewhere for a while.
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

    # Take the files off every node as well.
    #
    # Deleting the row used to leave the private key on the disk of every box,
    # forever.  Nothing pointed at it and nothing listed it, so the only way to
    # find out was to go and look, which nobody does until an audit.  It
    # mattered more once certificates could be uploaded, because then this is
    # the only copy anywhere and deleting it is the only way to get rid of it.
    #
    # Never certbot's folder.  It keeps renewal state next to its copies and
    # `certbot delete` is the way to remove those.
    forgotten = await _forget_cert_files(name)

    audit.record("cert.delete", user=g.user, object_type="cert", object_name=name,
                 changes={"files_removed_from": forgotten["ok"],
                          "files_left_on": [f["node"] for f in forgotten["failed"]]})
    return {"ok": True, "deleted": name, "files": forgotten}


async def _forget_cert_files(name):
    """
    Remove a certificate's files fleet wide, without ever failing the delete.

    A node being down is a file to clear up later, not a reason to keep a row
    somebody asked to be rid of.  What is left where goes in the audit log, so
    there is a record rather than a surprise.
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

    No session and no CSRF, because the caller is a shell script certbot ran,
    not a browser.  Three things stand in for that:

      the request has to come from this machine
      it has to carry the shared secret the hooks were written with
      it can only publish or remove a challenge token, nothing else

    Getting all three means already being on the box, at which point the token
    file could have been written directly anyway.
    """
    from app.core import acme_hooks
    from app.core.acme import ChallengeCoordinator

    # Has to be a local caller.  Test this properly rather than by comparing
    # strings: a connection to 127.0.0.1 can arrive as "::ffff:127.0.0.1" when
    # the listener is dual stack, and any loopback address is 127.anything, not
    # just 127.0.0.1.  A literal list misses both, and the failure looks like
    # the hook URL being wrong rather than the address being rejected.
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

    Both sides come out of what was actually shipped, so this is history rather
    than a guess.  Re-rendering the older one from today's objects would show
    what it would look like now, which is a different and much less useful
    question.
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
    """Put the last known good config back on this node."""
    g.require("rollback")
    payload = await request.json() if await request.body() else {}

    # Take a version number as well as an archive name.
    #
    # Everything else in this tool speaks in version numbers: the versions list,
    # the diff, the audit trail.  So `version` is the obvious thing to send
    # here, and it used to be ignored: the agent fell back to the newest
    # archive, which is the config that is already live, and the answer came
    # back `ok: true`.  Asking to go back to a known good version and being
    # told it worked while nothing changed is the worst possible behaviour for
    # the one button somebody presses when they are already in trouble.
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
    Work out what a config would become.  Writes nothing.

    Deliberately a read.  Somebody weighing up whether to adopt this tool should
    be able to point it at their live config and see the answer without having
    committed to anything, and without needing the permission that changes
    things.
    """
    g.require("edit_sites")
    payload = await request.json()

    from app.core.importer import analyse

    return analyse(payload.get("config") or "")


@router.post("/import")
async def import_apply(request: Request, g: ObjectGuard = Depends(changing)):
    """
    Make what the preview described.

    The config is parsed again here rather than trusting a plan posted back by
    the browser.  A plan is a list of objects to create, and taking one from the
    client would let anybody who can reach this endpoint make whatever they
    liked, whatever the preview actually said.
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

    # Nothing is applied here.  Everything lands disabled and unapplied, so the
    # person can look at what arrived before any of it reaches nginx.
    return {"ok": True, **result,
            "message": "imported and left switched off.  Look them over, turn on "
                       "the ones you want, then apply."}


# ==============================================================================
# Paths within a site
# ==============================================================================

# There was a LOCATION_FIELDS tuple here that read exactly like the list of what
# a path accepts and was referenced by nothing at all.  It is gone rather than
# updated: a list nothing reads cannot be wrong in a way anybody notices, so it
# drifts, and then somebody trusts it.  `_apply_location_fields` below is the
# only answer to what a path accepts.

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
        # Stored, written and accepted on the way in, and left out of here,
        # which is the shape of bug that undoes itself.  The path editor reads
        # this to draw the checkbox, so the box came back clear on every reload
        # however it was saved, and the next save of that path posted the clear
        # box back and turned the setting off.  Nobody unticked anything: the
        # site simply started 404ing again after an unrelated edit.
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

    # A mount only means anything where a path can have something under it.  On
    # an exact or a regex match there is no prefix to take off and no set of URLs
    # beneath it, so the rewriting would fire on one URL and mislead about the
    # rest.  Refused rather than ignored, because a checkbox that saves and does
    # nothing is the bug this whole area has already had once.
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
        # Validated the same way a site's are, and against the same catalog, so
        # a setting that is not real cannot be smuggled in on a location when it
        # would be refused on the site above it.
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
        # On the end by default.  Order is what decides which path wins, so a
        # new one going to the top would quietly take traffic from something
        # that was already working.
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
    Set the order of the paths on a site.

    Worth its own endpoint rather than a field on each save, because the order
    is the thing that decides which path handles a request and it has to move as
    one piece.  Saving them one at a time leaves a moment where two share a
    position, and which one wins then is down to the database.
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
