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
import json
import logging
import re
import socket

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import HTMLResponse
from sqlalchemy.orm import Session as DBSession

from app.auth.service import can, current_user
from app.catalog import CATEGORIES, all_features, plus_only_features, validate_value
from app.catalog.registry import get_feature
from app.config import get_settings
from app.core import audit, error_pages, settings_store
from app.core.acme import AcmeError, get_cert_manager, pick_issuing_node, resolve_domain
from app.core.agent_client import AgentError, get_agent
from app.core.capabilities import fleet_capabilities, get_local_capabilities
from app.core.cluster import ClusterError, get_cluster
from app.core.crypto import encrypt, new_token
from app.core.nginx_parser import ParseError, extract_settings, parse, quick_check
from app.core.render import Renderer, safe_name, safe_var
from app.core.snapshot import capture as snapshot_capture
from app.db import get_db, session_scope
from app.models import (
    AccessList,
    CacheZone,
    Certificate,
    ConfigVersion,
    ConnLimitZone,
    ErrorPageImage,
    ErrorPageTemplate,
    HealthEvent,
    Location,
    MapBlock,
    MemberState,
    Node,
    NodeRole,
    Pool,
    PoolMember,
    RateLimitZone,
    StreamServer,
    User,
    VirtualHost,
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

    renderer = Renderer(
        ignore_health=ignore_health,
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
    zone_options = {
        "limit_req_zone_name": [("", "no rate limit")] + [
            (z.name, f"{z.name} ({z.rate})")
            for z in db.query(RateLimitZone).order_by(RateLimitZone.name).all()
        ],
        "limit_conn_zone_name": [("", "no connection limit")] + [
            (z.name, z.name)
            for z in db.query(ConnLimitZone).order_by(ConnLimitZone.name).all()
        ],
        "proxy_cache_zone": [("", "no caching")] + [
            (z.name, f"{z.name} ({z.max_size} max)")
            for z in db.query(CacheZone).order_by(CacheZone.name).all()
        ],
    }

    out = []
    for feature in all_features().values():
        if feature.edition != "oss":
            continue
        if context not in feature.contexts:
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
    "error_page_template_id",
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

    # The name check lives in _apply_host_fields, which runs below, so that
    # creating and renaming cannot drift apart the way they already did once.
    name = validate_name(payload.get("name"), "site name")
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
        "error_page_template_id": h.error_page_template_id,
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

    # Force is how somebody says they really do mean to remove every site.  It
    # is off unless asked for, because the case it exists for is rare and the
    # case it guards against takes the fleet down.
    force = bool(payload.get("force"))
    if force:
        log.warning("%s applied with force, so the wipe check was skipped",
                    g.user.username)

    result = await apply_current_config(author=g.user.username, summary=summary,
                                        force=force)

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
            f"  && sudo {target}/nginx-gui-mgmt_setup.sh --join {sponsor} --token {token}"
        ),
        "command_have_code": (
            f"sudo ./nginx-gui-mgmt_setup.sh --join {sponsor} --token {token}"
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

    users = g.session.query(VirtualHost).filter(VirtualHost.access_list_id == acl.id).all()
    if users:
        raise HTTPException(
            status_code=409,
            detail=f"still used by: {', '.join(h.name for h in users)}",
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
                          "openssl": payload.get("openssl_version")})
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

    try:
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

LOCATION_FIELDS = (
    "path", "match_type", "mode", "document_root", "alias",
    "redirect_target", "redirect_code", "custom_config", "enabled",
    "sort_order",
)

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
    if "sort_order" in payload:
        loc.sort_order = int(payload.get("sort_order") or 0)

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
