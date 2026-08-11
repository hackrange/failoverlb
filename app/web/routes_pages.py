"""
The pages people actually look at.

Server rendered HTML with a small amount of JavaScript on top.  No build step,
no framework, no node_modules.  For a management tool that has to work on an
isolated network at 3am, plain HTML that renders without JavaScript beats a
single page app that needs a bundle to load first.
"""

import logging
from pathlib import Path

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates
from sqlalchemy.orm import Session as DBSession

from app.auth import oidc
from app.auth.service import (
    authenticate_local,
    can,
    create_session,
    current_user,
    enroll_totp,
    hash_password,
    password_problems,
    revoke_session,
    save_totp,
)
from app.config import get_settings
from app.core import audit
from app.core.capabilities import get_local_capabilities
from app.core.cluster import get_cluster
from app.db import get_db
from app.models import Certificate, ConfigVersion, Node, Pool, VirtualHost
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
            "can": lambda perm: can(user, perm),
            "node_name": settings.node_name,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "active_page": template.replace(".html", "").replace("site_detail", "sites").replace("pool_detail", "pools"),
            # Everything in the templates is built from this, so the whole GUI
            # works the same whether it is at the root or behind a prefix.
            "base": settings.root_path.rstrip("/"),
            # Forms that post normally cannot set a header, so they carry the
            # token in a hidden field instead.  It has to be rendered into the
            # page, which means we need the value before the cookie is set.
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
            "node_name": get_settings().node_name,
            "csp_nonce": getattr(request.state, "csp_nonce", ""),
            "base": get_settings().root_path.rstrip("/"),
            "csrf_token": token,
        },
    )
    issue_csrf_token(response, token)
    return response


@router.post("/auth/login", response_class=HTMLResponse)
async def do_login(request: Request, db: DBSession = Depends(get_db),
                   username: str = Form(...), password: str = Form(...),
                   totp: str = Form(None)):
    await check_csrf(request)
    ip = client_ip(request)

    result = authenticate_local(db, username.strip(), password, totp, ip)
    db.commit()

    if not result.ok:
        audit.record("auth.login", user=username, source_ip=ip,
                     result="failed", detail=result.reason)
        return await login_page(
            request, db,
            error=result.reason,
            stage="totp" if result.needs_totp else "password",
        )

    if result.needs_enrollment:
        # A local account without a second factor does not get in.  They set one
        # up first.  This is the weakest way into the tool otherwise.
        #
        # Still log it as a login.  The password was right and a session now
        # exists, so as far as the audit trail is concerned somebody got in.
        # Only logging the ones that made it all the way through would leave a
        # first login missing from the record entirely.
        token = create_session(db, result.user, ip, request.headers.get("user-agent"))
        db.commit()
        audit.record("auth.login", user=result.user, source_ip=ip,
                     detail="password accepted, sent to set up an authenticator")
        response = RedirectResponse(_p("/enroll"), status_code=303)
        _set_session_cookie(response, token)
        issue_csrf_token(response)
        return response

    if result.needs_totp:
        # The second stage of signing in, where they type the code from their
        # authenticator.  This form needs the same token treatment as the first
        # stage: rendered into the page and set as the cookie, both the same
        # value.  Miss it here and only people who already have an authenticator
        # set up are affected, which is everybody from their second login
        # onwards.
        csrf = ensure_csrf_token(request)
        response = templates.TemplateResponse(
            request,
            "login.html",
            {
                "stage": "totp",
                "username": username,
                "password": password,
                "oidc_enabled": oidc.is_configured(),
                "node_name": get_settings().node_name,
                "csp_nonce": getattr(request.state, "csp_nonce", ""),
                "base": get_settings().root_path.rstrip("/"),
                "csrf_token": csrf,
            },
        )
        issue_csrf_token(response, csrf)
        return response

    token = create_session(db, result.user, ip, request.headers.get("user-agent"))
    db.commit()

    audit.record("auth.login", user=result.user, source_ip=ip)
    log.info("%s signed in from %s", result.user.username, ip)

    target = "/change-password" if result.user.must_change_password else "/"
    # _p, not the bare path.  This one held a variable rather than a literal, so
    # an earlier sweep that prefixed every redirect walked straight past it.
    # The result was that signing in sent you to / on whatever hostname this is
    # served under, which when something else owns that root means you land on
    # a completely different application and think the login failed.
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
        # HttpOnly so a cross site scripting bug cannot read the session and
        # walk off with it.  Strict so the cookie is not attached to requests
        # started from anywhere else, which is half the CSRF protection.
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

    # Stash the parts we need to finish enrollment.  Held in the session row
    # rather than a hidden form field so the secret never travels back through
    # the browser a second time.
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

    # Through the same guard the API uses, so a site you are not allowed to see
    # answers the same way whether you ask for the page or the JSON.
    from app.web.security import ObjectGuard

    guard = ObjectGuard(db, user)
    host = guard.get(VirtualHost, host_id)

    token = ensure_csrf_token(request)
    response = render(
        request, "site_detail.html", user, csrf_token=token,
        host=host,
        pools=db.query(Pool).order_by(Pool.name).all(),
        certs=db.query(Certificate).order_by(Certificate.name).all(),
    )
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
    )
    issue_csrf_token(response, token)
    return response


@router.get("/cluster", response_class=HTMLResponse)
async def cluster_page(request: Request, db: DBSession = Depends(get_db)):
    user = require_page_user(request, db)
    latest = db.query(ConfigVersion).order_by(ConfigVersion.version.desc()).first()

    token = ensure_csrf_token(request)
    response = render(
        request, "cluster.html", user, csrf_token=token,
        nodes=db.query(Node).order_by(Node.priority.desc()).all(),
        pending=get_cluster().pending_summary(db),
        latest_version=latest.version if latest else 0,
        versions=db.query(ConfigVersion).order_by(
            ConfigVersion.version.desc()
        ).limit(20).all(),
    )
    issue_csrf_token(response, token)
    return response


@router.get("/parity", response_class=HTMLResponse)
async def parity_page(request: Request, db: DBSession = Depends(get_db)):
    """
    What the paid nginx has, and what we built instead.

    Worth a page of its own.  Every one of these is something an admin will go
    looking for in the nginx docs, and finding out an hour later that it needs a
    subscription is a bad afternoon.
    """
    from app.catalog import plus_only_features

    user = require_page_user(request, db)
    token = ensure_csrf_token(request)
    response = render(request, "parity.html", user, csrf_token=token, features=plus_only_features())
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
