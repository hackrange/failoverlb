"""
HTML page routes.

Server rendered templates with a little JavaScript on top.  No build step and
no frontend framework, so the GUI works on an isolated network without a
bundle to fetch.
"""

import json
import hashlib
import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from app.auth import oidc
from app.core import settings_store
from app.auth.service import (
    authenticate_local,
    begin_totp,
    can,
    create_session,
    current_user,
    enroll_totp,
    hash_password,
    password_problems,
    resume_totp,
    revoke_session,
    save_totp,
)
from app.config import get_settings
from app.core import audit, error_pages, hostnames
from app.core.capabilities import get_local_capabilities
from app.core.cluster import get_cluster
from app.db import get_db, session_scope
from app.models import (
    AccessList, Certificate, ConfigVersion, ErrorPageTemplate, Node, Pool,
    VirtualHost,
)
from app.web.security import (
    SESSION_COOKIE,
    check_csrf,
    client_ip,
    ensure_csrf_token,
    issue_csrf_token,
)

log = logging.getLogger("nfm.pages")

router = APIRouter()

TEMPLATE_DIR = Path(__file__).parent / "templates"
templates = Jinja2Templates(directory=str(TEMPLATE_DIR))


def _asset_version() -> str:
    """
    Short hash of everything the browser runs: app.js, app.css and templates.

    Used to bust the static asset cache after an upgrade, and compared against
    the stamp on every API response so an open tab can tell it is running
    stale inline JavaScript.  Templates are included for that second reason.

    Hashed from file contents, not mtimes.  Mtimes differ between nodes
    running the same commit, which made pages falsely report themselves as
    out of date when served by one node and answered by another.
    """
    digest = hashlib.sha256()
    static = Path(__file__).parent / "static"
    files = [static / "app.js", static / "app.css"]
    files += sorted(TEMPLATE_DIR.glob("*.html"))
    seen = False
    for path in files:
        try:
            digest.update(path.name.encode())
            digest.update(path.read_bytes())
            seen = True
        except OSError:
            continue
    return digest.hexdigest()[:12] if seen else "dev"


ASSET_VERSION = _asset_version()
templates.env.globals["asset_version"] = ASSET_VERSION


# ==============================================================================
# Helpers
# ==============================================================================

def _p(path: str) -> str:
    """Put the prefix on an internal path.  Used by every redirect."""
    return (get_settings().root_path.rstrip("/") or "") + path


def page_user(request: Request, db: DBSession):
    token = request.cookies.get(SESSION_COOKIE)
    user = current_user(db, token, client_ip(request))
    if user:
        db.commit()
    return user


def require_page_user(request: Request, db: DBSession):
    user = page_user(request, db)
    if not user:
        raise HTTPException(status_code=307, headers={"Location": _p("/login")})
    return user


def _own_role() -> str:
    """
    This node's role as a plain string.

    Read fresh on every render because it changes on failover.  Returned as a
    string, not an ORM object, since the session is closed by the time the
    layout touches it.
    """
    from app.models import Node

    try:
        with session_scope() as session:
            node = session.query(Node).filter(
                Node.name == get_settings().node_name
            ).first()
            if not node or not node.role:
                return "unknown"
            return node.role.value
    except Exception:
        # The layout must still render if the database is unavailable.
        return "unknown"


def render(request: Request, template: str, user, csrf_token: str = None, **context):
    """
    Render a page with everything the layout needs.

    The nonce comes from the security middleware and goes on any inline script,
    which is what lets the CSP stay strict instead of allowing unsafe-inline.
    """
    settings = get_settings()

    return templates.TemplateResponse(
        request,
        template,
        {
            "user": user,
            # Passed on every page.  The role chip used to fall back to
            # "standby" on pages that did not supply it, which was wrong.
            "node_role": _own_role(),
            "can": lambda perm: can(user, perm),
            "node_name": settings.node_name,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "active_page": template.replace(".html", "").replace("site_detail", "sites").replace("pool_detail", "pools"),
            # URL prefix for every link, so the GUI works behind a sub-path.
            "base": settings.root_path.rstrip("/"),
            # Plain form posts cannot set a header, so they carry the CSRF
            # token in a hidden field rendered from this value.
            "csrf_token": csrf_token or "",
            **context,
        },
    )


# ==============================================================================
# Login
# ==============================================================================

@router.get("/login", response_class=HTMLResponse)
async def login_page(request: Request, db: DBSession = Depends(get_db),
                     error: str = None, stage: str = "password"):
    if page_user(request, db):
        return RedirectResponse(_p("/"), status_code=303)

    token = ensure_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "error": error,
            "stage": stage,
            "oidc_enabled": oidc.is_configured(),
            "local_enabled": settings_store.local_passwords_allowed(),
            "node_name": get_settings().node_name,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "base": get_settings().root_path.rstrip("/"),
            "csrf_token": token,
        },
    )
    issue_csrf_token(response, token)
    return response


def _totp_page(request: Request, half: str, error: str = None):
    """
    Second login stage (TOTP code).

    Carries a ticket instead of the password.  Needs the same CSRF handling as
    the first stage: the token rendered into the page and set as the cookie.
    """
    csrf = ensure_csrf_token(request)
    response = templates.TemplateResponse(
        request,
        "login.html",
        {
            "stage": "totp",
            "half": half,
            "error": error,
            "oidc_enabled": oidc.is_configured(),
            "local_enabled": settings_store.local_passwords_allowed(),
            "node_name": get_settings().node_name,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "base": get_settings().root_path.rstrip("/"),
            "csrf_token": csrf,
        },
    )
    issue_csrf_token(response, csrf)
    return response


@router.post("/auth/login", response_class=HTMLResponse)
async def do_login(request: Request, db: DBSession = Depends(get_db),
                   username: str = Form(None), password: str = Form(None),
                   totp: str = Form(None), half: str = Form(None)):
    await check_csrf(request)
    ip = client_ip(request)

    # First stage posts username and password.  The TOTP stage posts a ticket
    # ("half") meaning the password was already accepted, so the password is
    # not kept in the page between the two steps.
    if half:
        result = resume_totp(db, half, totp, ip)
        username = (result.user.username if result.user else username) or ""
    else:
        if not username or password is None:
            raise HTTPException(status_code=400, detail="username and password please")
        result = authenticate_local(db, username.strip(), password, totp, ip)
    db.commit()

    if not result.ok:
        audit.record("auth.login", user=username, source_ip=ip,
                     result="failed", detail=result.reason)
        if result.needs_totp and half:
            # Keep the ticket so a mistyped code does not mean retyping the
            # password.  The lockout still limits guesses.
            return _totp_page(request, half, error=result.reason)
        return await login_page(
            request, db,
            error=result.reason,
            stage="totp" if result.needs_totp else "password",
        )

    if result.needs_enrollment:
        # Local accounts must enroll a second factor before going further.
        # Audited as a login anyway, since a session now exists.
        token = create_session(db, result.user, ip, request.headers.get("user-agent"))
        db.commit()
        audit.record("auth.login", user=result.user, source_ip=ip,
                     detail="password accepted, sent to set up an authenticator")
        response = RedirectResponse(_p("/enroll"), status_code=303)
        _set_session_cookie(response, token)
        issue_csrf_token(response)
        return response

    if result.needs_totp:
        return _totp_page(request, begin_totp(result.user, ip))

    token = create_session(db, result.user, ip, request.headers.get("user-agent"))
    db.commit()

    audit.record("auth.login", user=result.user, source_ip=ip)
    log.info("%s signed in from %s", result.user.username, ip)

    target = "/change-password" if result.user.must_change_password else "/"
    # Must go through _p like every other redirect, or a GUI served under a
    # prefix sends the user to whatever owns the bare root after login.
    response = RedirectResponse(_p(target), status_code=303)
    _set_session_cookie(response, token)
    issue_csrf_token(response, token)
    return response


def _set_session_cookie(response, token):
    settings = get_settings()
    response.set_cookie(
        SESSION_COOKIE,
        token,
        max_age=settings.session_timeout_minutes * 60,
        # HttpOnly keeps the session out of reach of XSS.  SameSite=Strict
        # is part of the CSRF defense.
        httponly=True,
        secure=True,
        samesite="strict",
        path=(settings.root_path.rstrip("/") or "") + "/",
    )


@router.get("/logout")
@router.post("/logout")
async def logout(request: Request, db: DBSession = Depends(get_db)):
    token = request.cookies.get(SESSION_COOKIE)
    user = page_user(request, db)
    if token:
        revoke_session(db, token)
        db.commit()
    if user:
        audit.record("auth.logout", user=user, source_ip=client_ip(request))

    response = RedirectResponse(_p("/login"), status_code=303)
    response.delete_cookie(SESSION_COOKIE, path="/")
    return response


# ---- OIDC -------------------------------------------------------------------

@router.get("/auth/oidc/start")
async def oidc_start(request: Request):
    if not oidc.is_configured():
        raise HTTPException(status_code=400, detail="single sign on is not set up")

    try:
        url = await oidc.begin_login(client_ip(request))
    except oidc.OIDCError as exc:
        return RedirectResponse(_p(f"/login?error={exc}"), status_code=303)

    return RedirectResponse(url, status_code=303)


@router.get("/auth/oidc/callback")
async def oidc_callback(request: Request, db: DBSession = Depends(get_db),
                        code: str = None, state: str = None, error: str = None):
    ip = client_ip(request)

    # Checked again here: SSO may have been switched off while this login was
    # in flight, and the reply must not create a session.
    if not oidc.is_configured():
        return RedirectResponse(
            _p("/login?error=single sign on is switched off on this fleet"),
            status_code=303)

    if error:
        return RedirectResponse(_p(f"/login?error=the provider said: {error}"), status_code=303)
    if not code or not state:
        return RedirectResponse(_p("/login?error=that sign on reply was incomplete"), status_code=303)

    try:
        profile = await oidc.complete_login(code, state, ip)
        user = oidc.sync_user(db, profile)
    except oidc.OIDCError as exc:
        audit.record("auth.oidc", user=None, source_ip=ip, result="failed", detail=str(exc))
        return RedirectResponse(_p(f"/login?error={exc}"), status_code=303)

    token = create_session(db, user, ip, request.headers.get("user-agent"))
    db.commit()

    audit.record("auth.login", user=user, source_ip=ip, detail="via single sign on")
    log.info("%s signed in through SSO from %s", user.username, ip)

    response = RedirectResponse(_p("/"), status_code=303)
    _set_session_cookie(response, token)
    issue_csrf_token(response, token)
    return response


# ---- TOTP enrollment --------------------------------------------------------

@router.get("/enroll", response_class=HTMLResponse)
async def enroll_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    if user.totp_enrolled:
        return RedirectResponse(_p("/"), status_code=303)

    setup = enroll_totp(user)
    request.session_setup = setup

    # Keep the pending secret server side (encrypted) rather than in a hidden
    # field, so it does not round-trip through the browser.
    from app.models import SystemSetting

    row = db.query(SystemSetting).filter(
        SystemSetting.key == f"totp_pending_{user.id}"
    ).first()
    if not row:
        row = SystemSetting(key=f"totp_pending_{user.id}")
        db.add(row)

    import json

    from app.core.crypto import encrypt

    row.value = encrypt(json.dumps({
        "secret": setup["secret"],
        "recovery_hashes": setup["recovery_hashes"],
    }))
    row.encrypted = True
    db.commit()

    token = ensure_csrf_token(request)
    response = render(request, "enroll.html", user, csrf_token=token,
                      qr=setup["qr_data_uri"],
                      secret=setup["secret"],
                      recovery_codes=setup["recovery_codes"])
    issue_csrf_token(response, token)
    return response


@router.post("/enroll")
async def do_enroll(request: Request, db: DBSession = Depends(get_db),
                    code: str = Form(...)):
    await check_csrf(request)
    user = require_page_user(request, db)

    import json

    from app.core.crypto import decrypt
    from app.models import SystemSetting

    row = db.query(SystemSetting).filter(
        SystemSetting.key == f"totp_pending_{user.id}"
    ).first()
    if not row:
        return RedirectResponse(_p("/enroll"), status_code=303)

    pending = json.loads(decrypt(row.value))

    import pyotp

    if not pyotp.TOTP(pending["secret"]).verify(code.strip(), valid_window=1):
        setup_again = RedirectResponse(_p("/enroll?error=that+code+is+not+right"), status_code=303)
        return setup_again

    save_totp(user, pending["secret"], pending["recovery_hashes"])
    db.delete(row)
    db.commit()

    audit.record("auth.totp_enrolled", user=user, source_ip=client_ip(request))
    log.info("%s finished setting up their authenticator", user.username)

    return RedirectResponse(_p("/"), status_code=303)


@router.get("/change-password", response_class=HTMLResponse)
async def change_password_page(request: Request, db: DBSession = Depends(get_db),
                               error: str = None):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "change_password.html", user, csrf_token=token, error=error)
    issue_csrf_token(response, token)
    return response


@router.post("/change-password")
async def do_change_password(request: Request, db: DBSession = Depends(get_db),
                             new_password: str = Form(...),
                             confirm_password: str = Form(...)):
    await check_csrf(request)
    user = require_page_user(request, db)

    if new_password != confirm_password:
        return RedirectResponse(_p("/change-password?error=those+do+not+match"), status_code=303)

    problems = password_problems(new_password)
    if problems:
        from urllib.parse import quote

        return RedirectResponse(
            _p(f"/change-password?error={quote('; '.join(problems))}"), status_code=303
        )

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()

    audit.record("auth.password_changed", user=user, source_ip=client_ip(request))
    return RedirectResponse(_p("/"), status_code=303)


# ==============================================================================
# The pages
# ==============================================================================

@router.get("/", response_class=HTMLResponse)
async def dashboard(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    settings = get_settings()

    if user.must_change_password:
        return RedirectResponse(_p("/change-password"), status_code=303)
    if user.source.value == "local" and not user.totp_enrolled:
        return RedirectResponse(_p("/enroll"), status_code=303)

    nodes = db.query(Node).all()
    pools = db.query(Pool).all()
    hosts = db.query(VirtualHost).all()
    certs = db.query(Certificate).all()

    latest = db.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()
    me = next((n for n in nodes if n.name == settings.node_name), None)
    pending = get_cluster().pending_summary(db)

    token = ensure_csrf_token(request)
    response = render(
        request, "dashboard.html", user, csrf_token=token,
        nodes=nodes,
        pools=pools,
        hosts=hosts,
        certs=certs,
        me=me,
        latest_version=latest.version if latest else 0,
        pending=pending,
        caps=get_local_capabilities(),
        allowlist_set=bool(settings.admin_networks),
        degraded_pools=[p for p in pools if p.status_summary in ("degraded", "down")],
        expiring_certs=[c for c in certs if c.status in ("expiring", "critical", "expired")],
    )
    issue_csrf_token(response, token)
    return response


@router.get("/sites", response_class=HTMLResponse)
async def sites_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "sites.html", user, csrf_token=token,
        hosts=db.query(VirtualHost).order_by(VirtualHost.name).all(),
        pools=db.query(Pool).order_by(Pool.name).all(),
        certs=db.query(Certificate).order_by(Certificate.name).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/sites/{host_id}", response_class=HTMLResponse)
async def site_detail(host_id: str, request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)

    # Same object guard as the API, so access rules match.
    from app.web.security import ObjectGuard

    guard = ObjectGuard(db, user)
    host = guard.get(VirtualHost, host_id)
    acls = db.query(AccessList).order_by(AccessList.name).all()

    token = ensure_csrf_token(request)
    response = render(
        request, "site_detail.html", user, csrf_token=token,
        host=host,
        pools=db.query(Pool).order_by(Pool.name).all(),
        certs=db.query(Certificate).order_by(Certificate.name).all(),
        access_lists=acls,
        acl_summary=[_acl_summary(a) for a in acls],
        error_templates=db.query(ErrorPageTemplate)
                          .order_by(ErrorPageTemplate.name).all(),
        # Computed server side so the wildcard matching rule lives in one
        # place (app/core/hostnames.py), not in JavaScript too.
        uncovered_names=(hostnames.uncovered(host.cert.domain_list(),
                                             host.name_list())
                         if host.cert else []),
        www_partner=next(
            (p for p in (hostnames.www_partner(n) for n in host.name_list())
             if p and p not in host.name_list()), None),
        cert_wildcards=[d for d in (host.cert.domain_list() if host.cert else [])
                        if d.startswith("*.")],
        # Which site nginx serves over https for a name it does not
        # recognize, e.g. this site's names while it is switched off.
        #
        # An explicit default_server wins.  Otherwise: the installer's
        # placeholder is the port 80 default but has no https listener, so
        # nginx falls back to the first server block parsed.  Our config is
        # included by glob, so that is the alphabetically first site with
        # https enabled.
        default_site=next(
            (h.name for h in db.query(VirtualHost)
             .filter(VirtualHost.default_server.is_(True)).all()),
            next((h.name for h in sorted(
                    db.query(VirtualHost).filter(
                        VirtualHost.enabled.is_(True),
                        VirtualHost.listen_https.is_(True)).all(),
                    key=lambda x: x.name)
                  if h.name != host.name), None)),
        # A certificate row exists before it is issued.  Until the files
        # exist the https block is left out, since nginx will not start
        # with an ssl listener pointing at missing files.
        cert_ready=bool(host.cert and (host.cert.status or "") == "valid"
                        and host.cert.not_after),
        # Lets the page warn before an access list locks the viewer out.
        viewer_ip=client_ip(request),
        node_addresses=_management_addresses(db),
    )
    issue_csrf_token(response, token)
    return response


def _acl_summary(acl) -> dict:
    """Access list fields the site page uses to preview its effect."""
    return {
        "id": acl.id,
        "name": acl.name,
        "allow": acl.allows(),
        "deny": acl.denies(),
        "default_action": acl.default_action,
        "include_management": bool(acl.include_management),
        "use_real_ip": bool(acl.use_real_ip),
        "basic_auth": bool(acl.basic_auth_enabled),
        # Basic auth with no users is not rendered (nginx would reject every
        # request), so the page needs the count to say so.
        "auth_users": len(acl.auth_users()),
    }


def _management_addresses(db) -> list:
    """Addresses covered by "always allow the management network"."""
    from app.core.settings_store import get as setting

    out = []
    for node in db.query(Node).all():
        if node.address:
            out.append(node.address)
        for entry in node.local_address_list():
            addr = entry.get("address")
            if addr and entry.get("scope") == "global":
                out.append(addr)
    out.extend(setting("management_networks") or [])
    return sorted(set(out))


@router.get("/import", response_class=HTMLResponse)
async def import_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "import.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/pools", response_class=HTMLResponse)
async def pools_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "pools.html", user, csrf_token=token,
        pools=db.query(Pool).order_by(Pool.name).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/pools/{pool_id}", response_class=HTMLResponse)
async def pool_detail(pool_id: str, request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)

    from app.web.security import ObjectGuard

    guard = ObjectGuard(db, user)
    pool = guard.get(Pool, pool_id)

    token = ensure_csrf_token(request)
    response = render(
        request, "pool_detail.html", user, csrf_token=token,
        pool=pool, settings=pool.setting_map(),
        # Token state only, never the secret.  The page fetches the value
        # on demand when the user clicks Show.
        trust_json=json.dumps({
            "enabled": bool(pool.token_enabled),
            "active": pool.token_active,
            "header": pool.token_header or "X-Fleet-Token",
            "rotation_pending": pool.token_rotation_pending,
            "has_previous": bool(pool.token_previous_encrypted),
            "rotated_at": pool.token_rotated_at.isoformat() if pool.token_rotated_at else None,
        }),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/zones", response_class=HTMLResponse)
async def zones_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "zones.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/utilization", response_class=HTMLResponse)
async def utilization_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "utilization.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/gslb", response_class=HTMLResponse)
async def gslb_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "gslb.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/tunnel", response_class=HTMLResponse)
async def tunnel_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "tunnel.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/authorities", response_class=HTMLResponse)
async def authorities_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "authorities.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/maps", response_class=HTMLResponse)
async def maps_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "maps.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/streams", response_class=HTMLResponse)
async def streams_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "streams.html", user, csrf_token=token,
        pools=db.query(Pool).order_by(Pool.name).all(),
        certs=db.query(Certificate).order_by(Certificate.name).all(),
        access_lists=db.query(AccessList).order_by(AccessList.name).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/waf-profiles", response_class=HTMLResponse)
async def waf_profiles_page(request: Request, db: DBSession = Depends(get_db)):
    """
    Fleet-wide list of WAF profiles.

    Profiles are created from a site's learning session but can be shared by
    many sites, so this page shows usage, validity against the installed
    rules, and deletion.
    """
    from app.models import WafProfile

    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "waf_profiles.html", user, csrf_token=token,
        profiles=db.query(WafProfile).order_by(WafProfile.name).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/error-pages", response_class=HTMLResponse)
async def error_pages_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "error_pages.html", user, csrf_token=token,
        templates_list=db.query(ErrorPageTemplate).order_by(ErrorPageTemplate.name).all(),
        default_codes=error_pages.DEFAULT_CODES,
        messages=error_pages.MESSAGES,
        placeholders=error_pages.PLACEHOLDER_HELP,
        max_image_kb=error_pages.MAX_IMAGE_BYTES // 1024,
        max_total_kb=error_pages.MAX_IMAGES_TOTAL_BYTES // 1024,
    )
    issue_csrf_token(response, token)
    return response


@router.get("/certificates", response_class=HTMLResponse)
async def certs_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "certificates.html", user, csrf_token=token,
        certs=db.query(Certificate).order_by(Certificate.name).all(),
        nodes=db.query(Node).all(),
        # Site names, so a new certificate can be prefilled from a site.
        sites_with_names=[
            {"name": h.name, "names": [n for n in h.name_list()
                                       if hostnames.is_real_name(n)]}
            for h in db.query(VirtualHost).order_by(VirtualHost.name).all()
            if any(hostnames.is_real_name(n) for n in h.name_list())
        ],
        # Names each certificate fails to cover; see app/core/hostnames.py.
        short_of={
            c.id: sorted({
                name
                for h in c.hosts
                for name in hostnames.uncovered(c.domain_list(), h.name_list())
            })
            for c in db.query(Certificate).all()
        },
    )
    issue_csrf_token(response, token)
    return response


@router.get("/cluster", response_class=HTMLResponse)
async def cluster_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    latest = db.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()

    from app.core.capabilities import module_differences

    token = ensure_csrf_token(request)
    response = render(
        request, "cluster.html", user, csrf_token=token,
        modules=module_differences(),
        nodes=db.query(Node).order_by(Node.priority.desc()).all(),
        pending=get_cluster().pending_summary(db),
        latest_version=latest.version if latest else 0,
        versions=db.query(ConfigVersion).order_by(
            ConfigVersion.version.desc()
        ).limit(20).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/upgrade", response_class=HTMLResponse)
async def upgrade_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "upgrade.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response


@router.get("/parity", response_class=HTMLResponse)
async def parity_page(request: Request, db: DBSession = Depends(get_db)):
    """
    Feature comparison against NGINX Plus, Kemp LoadMaster and HAProxy ALOHA.

    Covers both directions: Plus-only features an admin may look for, and
    what this project does that the commercial products do not.  The URL is
    still /parity so existing links keep working.
    """
    from app.catalog import plus_only_features
    from app.catalog.comparison import (by_category, only_here, pricing,
                                        product_totals, totals)

    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "parity.html", user, csrf_token=token,
                      features=plus_only_features(),
                      groups=by_category(), only_here=only_here(),
                      scores=product_totals(), pricing=pricing(),
                      totals=totals())
    issue_csrf_token(response, token)
    return response


@router.get("/changes", response_class=HTMLResponse)
async def changes_page(request: Request, db: DBSession = Depends(get_db)):
    """Pending changes and recent config versions on one page."""
    from app.models import ConfigVersion

    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "changes.html", user, csrf_token=token, active_page="changes",
        versions=db.query(ConfigVersion)
                   .order_by(ConfigVersion.version.desc()).limit(50).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/audit", response_class=HTMLResponse)
async def audit_page(request: Request, db: DBSession = Depends(get_db)):
    from app.models import AuditLog

    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(
        request, "audit.html", user, csrf_token=token,
        entries=db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(200).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/backup", response_class=HTMLResponse)
async def backup_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "backup.html", user, csrf_token=token)
    issue_csrf_token(response, token)
    return response
