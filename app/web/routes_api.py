"""
The JSON API.

Every route in here follows the same three steps and in the same order:

  1. Work out who is asking (the session cookie).
  2. Check CSRF, for anything that changes something.
  3. Fetch objects only through ObjectGuard, which does the permission check.

Step three is what keeps the BOLA and IDOR bugs out.  There is no route that
queries a table by id directly, so there is no route that can forget the check.
"""

import json
import logging

from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.orm import Session as DBSession

from app.auth.service import can, current_user
from app.catalog import CATEGORIES, all_features, plus_only_features, validate_value
from app.catalog.registry import get_feature
from app.config import get_settings
from app.core import audit, settings_store
from app.core.acme import AcmeError, get_cert_manager, pick_issuing_node, resolve_domain
from app.core.agent_client import AgentError, get_agent
from app.core.capabilities import fleet_capabilities, get_local_capabilities
from app.core.cluster import ClusterError, get_cluster
from app.core.nginx_parser import ParseError, extract_settings, parse, quick_check
from app.core.render import Renderer
from app.db import get_db, session_scope
from app.models import (
    AccessList,
    CacheZone,
    Certificate,
    ConfigVersion,
    ConnLimitZone,
    HealthEvent,
    Location,
    MapBlock,
    MemberState,
    Node,
    Pool,
    PoolMember,
    RateLimitZone,
    StreamServer,
    User,
    VirtualHost,
)
from app.web.security import (
    ObjectGuard,
    SESSION_COOKIE,
    check_csrf,
    client_ip,
    pick_fields,
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
# Rendering and applying
# ==============================================================================

def render_current(session) -> tuple:
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

    renderer = Renderer(
        capabilities=fleet_capabilities(),
        node_addresses=sorted(set(node_addresses)),
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
        hosts, pools, certs, acls, rate_zones, conn_zones, cache_zones, maps, streams
    )

    snapshot = {
        "hosts": len(hosts),
        "pools": len(pools),
        "certs": len(certs),
        "streams": len(streams),
    }

    return files, renderer.checksum(), snapshot


async def apply_current_config(author: str = "system", summary: str = "") -> dict:
    """
    Render everything and push it out to the fleet.

    This is the one path everything uses.  The health checker calls it when a
    backend changes state, and the API calls it when somebody saves.  Having one
    path means the two phase apply and the queueing behave the same either way.
    """
    with session_scope() as session:
        files, checksum, snapshot = render_current(session)

    return await get_cluster().apply_config(
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
    }


# ==============================================================================
# The feature catalog, which is also where the help text comes from
# ==============================================================================

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

    out = []
    for feature in all_features().values():
        if feature.edition != "oss":
            continue
        if context not in feature.contexts:
            continue

        out.append({
            "key": feature.key,
            "label": feature.label,
            "category": feature.category,
            "type": feature.type,
            "default": feature.default,
            "options": feature.options,
            "unit": feature.unit,
            "placeholder": feature.placeholder,
            "advanced": feature.advanced,
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


@router.post("/hosts")
async def create_host(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("edit_sites")
    payload = pick_fields(await request.json(), HOST_FIELDS)

    name = validate_name(payload.get("name"), "site name")
    if g.session.query(VirtualHost).filter(VirtualHost.name == name).first():
        raise HTTPException(status_code=409, detail=f"there is already a site called {name}")

    host = VirtualHost(name=name)
    _apply_host_fields(g, host, payload)
    g.session.add(host)
    g.session.commit()

    audit.record("site.create", user=g.user, object_type="site", object_name=name,
                 changes=payload, source_ip=None)

    return _host_detail(host)


@router.put("/hosts/{host_id}")
async def update_host(host_id: str, request: Request, g: ObjectGuard = Depends(changing)):
    host = g.get(VirtualHost, host_id, "edit_sites")
    payload = pick_fields(await request.json(), HOST_FIELDS)

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
        host.name = validate_name(payload["name"], "site name")

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
                  "http2", "force_https", "admin_only"):
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
                         ("access_list_id", AccessList)):
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
        host.config_mode = payload["config_mode"]

    if "settings" in payload:
        host.settings = json.dumps(_validate_settings(payload["settings"], "server"))

    host.updated_by = g.user.username


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
            problems.append(f"{feature.label} {feature.unavailable_reason(caps.modules, caps.version_tuple)}")
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


def _host_detail(h):
    return {
        **_host_summary(h),
        "listen_http": h.listen_http,
        "http_port": h.http_port,
        "https_port": h.https_port,
        "default_server": h.default_server,
        "http2": h.http2,
        "force_https": h.force_https,
        "pool_id": h.pool_id,
        "cert_id": h.cert_id,
        "access_list_id": h.access_list_id,
        "document_root": h.document_root,
        "redirect_target": h.redirect_target,
        "redirect_code": h.redirect_code,
        "settings": h.setting_map(),
        "custom_config": h.custom_config,
        "notes": h.notes,
        "locations": [
            {
                "id": loc.id,
                "path": loc.path,
                "match_type": loc.match_type,
                "mode": loc.mode,
                "pool_id": loc.pool_id,
                "sort_order": loc.sort_order,
                "enabled": loc.enabled,
                "settings": loc.setting_map(),
            }
            for loc in sorted(h.locations, key=lambda x: x.sort_order)
        ],
    }


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

    name = validate_name(payload.get("name"), "pool name")
    if g.session.query(Pool).filter(Pool.name == name).first():
        raise HTTPException(status_code=409, detail=f"there is already a pool called {name}")

    pool = Pool(name=name)
    _apply_pool_fields(pool, payload)
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
    _apply_pool_fields(pool, payload)
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


def _apply_pool_fields(pool, payload):
    if "name" in payload:
        pool.name = validate_name(payload["name"], "pool name")

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

    for field in ("hash_consistent", "health_check_enabled", "health_check_verify_tls"):
        if field in payload:
            setattr(pool, field, bool(payload[field]))

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
        else:
            text = str(value)
            import re

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
        "health_check": {
            "enabled": p.health_check_enabled,
            "type": p.health_check_type,
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


def _apply_member_fields(member, payload):
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

    result = await apply_current_config(author=g.user.username, summary=summary)

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
    return {
        "token": token,
        "expires_in_hours": 2,
        "command": (
            f"sudo bash nginx-gui-mgmt_setup.sh --join {settings.node_address}:{settings.peer_port} "
            f"--token {token}"
        ),
        "note": "single use, expires in 2 hours, treat it like a password",
    }


@router.post("/cluster/failover")
async def failover(request: Request, g: ObjectGuard = Depends(changing)):
    g.require("failover")
    payload = await request.json()
    target = payload.get("node")

    try:
        await get_cluster().failover_to(target, actor=g.user.username)
    except ClusterError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

    audit.record("cluster.failover", user=g.user, object_type="cluster",
                 object_name=target, detail=f"made {target} active")
    return {"ok": True, "active": target}


@router.post("/cluster/resync")
async def resync(g: ObjectGuard = Depends(changing)):
    """Push the current config at anybody who is behind, right now."""
    g.require("manage_cluster")
    await get_cluster().drain_pending()
    audit.record("cluster.resync", user=g.user, object_type="cluster")
    return {"ok": True}


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

    return await pick_issuing_node(domains[0])


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

    audit.record("cert.delete", user=g.user, object_type="cert", object_name=name)
    return {"ok": True, "deleted": name}


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

    source = client_ip(request)
    if source not in ("127.0.0.1", "::1", "localhost"):
        log.warning("acme hook called from %s, which is not this machine", source)
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


@router.post("/rollback")
async def rollback(request: Request, g: ObjectGuard = Depends(changing)):
    """Put the last known good config back on this node."""
    g.require("rollback")
    payload = await request.json() if await request.body() else {}

    try:
        result = await get_agent().rollback(name=payload.get("backup"))
    except AgentError as exc:
        raise HTTPException(status_code=400, detail=str(exc))

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
