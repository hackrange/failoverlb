"""
The account page (your own password, authenticator, recovery codes and
sessions), the admin users page, and the settings page.

Changing a second factor always asks for the current password and a current
code.  A logged-in session alone is not enough, or a hijacked session could
swap the authenticator for the attacker's and lock the real owner out.
"""

import json
import logging

import pyotp
from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from sqlalchemy.orm import Session as DBSession

from app.auth.service import (
    can,
    check_totp,
    enroll_totp,
    hash_password,
    password_problems,
    revoke_all_for_user,
    save_totp,
    verify_password,
)
from app.config import get_settings
from app.core import audit
from app.core.crypto import decrypt, encrypt
from app.db import get_db
from app.models import AuthSource, Session as SessionRow, SystemSetting, User, UserRole, utcnow
from app.web.routes_pages import _p, render, require_page_user
from app.web.security import (
    SESSION_COOKIE,
    check_csrf,
    client_ip,
    ensure_csrf_token,
    issue_csrf_token,
    validate_name,
)

log = logging.getLogger("nfm.account")

router = APIRouter()

# Setting key prefix for a half finished authenticator swap.  The new secret
# is stored here encrypted until the user proves it works, so it never goes
# back through the browser a second time.
PENDING_PREFIX = "totp_pending_"


def _pending_key(user_id: int) -> str:
    return f"{PENDING_PREFIX}{user_id}"


def _stash_pending(db, user_id: int, secret: str, recovery_hashes: list):
    row = db.query(SystemSetting).filter(
        SystemSetting.key == _pending_key(user_id)
    ).first()
    if not row:
        row = SystemSetting(key=_pending_key(user_id))
        db.add(row)
    row.value = encrypt(json.dumps({
        "secret": secret,
        "recovery_hashes": recovery_hashes,
    }))
    row.encrypted = True
    db.commit()


def _take_pending(db, user_id: int):
    row = db.query(SystemSetting).filter(
        SystemSetting.key == _pending_key(user_id)
    ).first()
    if not row:
        return None
    try:
        data = json.loads(decrypt(row.value))
    except (TypeError, ValueError):
        return None
    return data, row


# ==============================================================================
# Your own account
# ==============================================================================

@router.get("/account", response_class=HTMLResponse)
async def account_page(request: Request, db: DBSession = Depends(get_db),
                       error: str = None, ok: str = None):
    user = require_page_user(request, db)

    sessions = db.query(SessionRow).filter(
        SessionRow.user_id == user.id,
        SessionRow.revoked == False,  # noqa: E712
    ).order_by(SessionRow.last_seen_at.desc()).all()

    current_hash = None
    token = request.cookies.get(SESSION_COOKIE)
    if token:
        from app.core.crypto import hash_token

        current_hash = hash_token(token)

    try:
        recovery_left = len(json.loads(user.recovery_codes or "[]"))
    except json.JSONDecodeError:
        recovery_left = 0

    csrf = ensure_csrf_token(request)
    response = render(
        request, "account.html", user, csrf_token=csrf,
        error=error, ok=ok,
        sessions=[s for s in sessions if s.is_valid],
        current_session_hash=current_hash,
        recovery_left=recovery_left,
    )
    issue_csrf_token(response, csrf)
    return response


async def _push_accounts():
    """
    Push account changes to the other nodes now instead of waiting for the
    timer, so an old password stops working everywhere promptly.  Never
    raises: the change is already saved here and the timer is the fallback.
    """
    try:
        from app.core.cluster import get_cluster

        await get_cluster().replicate_accounts()
    except Exception as exc:      # noqa: BLE001
        log.warning("could not send the account change to the other nodes now, "
                    "the sync will pick it up: %s", exc)


@router.post("/account/password")
async def change_own_password(request: Request, db: DBSession = Depends(get_db),
                              current_password: str = Form(...),
                              new_password: str = Form(...),
                              confirm_password: str = Form(...)):
    await check_csrf(request)
    user = require_page_user(request, db)

    if user.source != AuthSource.LOCAL:
        return _back("your password is managed by single sign on, not here")

    # Ask for the current password even though they are signed in, so an
    # unattended session cannot be used to lock the owner out.
    if not verify_password(user.password_hash, current_password):
        audit.record("account.password_change", user=user, source_ip=client_ip(request),
                     result="failed", detail="current password was wrong")
        return _back("that is not your current password")

    if new_password != confirm_password:
        return _back("the two new passwords do not match")

    problems = password_problems(new_password)
    if problems:
        return _back("; ".join(problems))

    user.password_hash = hash_password(new_password)
    user.must_change_password = False
    db.commit()

    audit.record("account.password_change", user=user, source_ip=client_ip(request))
    await _push_accounts()
    return _back(ok="password changed")


# ---- swapping the authenticator ---------------------------------------------

@router.post("/account/totp/start")
async def start_totp_change(request: Request, db: DBSession = Depends(get_db),
                            current_password: str = Form(...),
                            current_code: str = Form(...)):
    """
    Start moving to a new authenticator.

    Needs the password plus a code from the old authenticator (or a recovery
    code), so a signed in browser alone cannot swap the second factor.
    """
    await check_csrf(request)
    user = require_page_user(request, db)

    if user.source != AuthSource.LOCAL:
        return _back("your sign in is handled by single sign on, so there is no authenticator here")

    if not verify_password(user.password_hash, current_password):
        audit.record("account.totp_change", user=user, source_ip=client_ip(request),
                     result="failed", detail="password was wrong")
        return _back("that password is not right")

    # check_totp also accepts a recovery code, for when the old phone is gone.
    if user.totp_enrolled and not check_totp(user, current_code):
        db.commit()   # a used recovery code is spent even on a failure path
        audit.record("account.totp_change", user=user, source_ip=client_ip(request),
                     result="failed", detail="code or recovery code was wrong")
        return _back("that code is not right.  Use a code from your current app, or one of your recovery codes.")

    setup = enroll_totp(user)
    _stash_pending(db, user.id, setup["secret"], setup["recovery_hashes"])

    audit.record("account.totp_change_started", user=user, source_ip=client_ip(request))

    csrf = ensure_csrf_token(request)
    response = render(
        request, "totp_change.html", user, csrf_token=csrf,
        qr=setup["qr_data_uri"],
        secret=setup["secret"],
        recovery_codes=setup["recovery_codes"],
    )
    issue_csrf_token(response, csrf)
    return response


@router.post("/account/totp/confirm")
async def confirm_totp_change(request: Request, db: DBSession = Depends(get_db),
                              code: str = Form(...)):
    """
    Finish the swap once the new app produces a valid code.  Until then the
    old authenticator keeps working.
    """
    await check_csrf(request)
    user = require_page_user(request, db)

    pending = _take_pending(db, user.id)
    if not pending:
        return _back("that authenticator setup expired, start again")

    data, row = pending

    if not pyotp.TOTP(data["secret"]).verify(str(code).strip(), valid_window=1):
        return _back("that code did not match the new app.  Check your phone's clock is right.")

    save_totp(user, data["secret"], data["recovery_hashes"])
    db.delete(row)

    # Sign out everywhere else, in case the change is because somebody else
    # got into the account.
    revoked = revoke_all_for_user(db, user.id, "authenticator was changed")
    db.commit()

    # Fresh session for this browser so the user stays signed in.
    from app.auth.service import create_session
    from app.web.routes_pages import _set_session_cookie

    token = create_session(db, user, client_ip(request), request.headers.get("user-agent"))
    db.commit()

    await _push_accounts()
    audit.record("account.totp_changed", user=user, source_ip=client_ip(request),
                 detail=f"new authenticator set up, {revoked} other session(s) signed out")
    log.warning("%s changed their authenticator from %s", user.username, client_ip(request))

    response = RedirectResponse(_p("/account?ok=authenticator+changed"), status_code=303)
    _set_session_cookie(response, token)
    issue_csrf_token(response)
    return response


@router.post("/account/recovery-codes")
async def regenerate_recovery_codes(request: Request, db: DBSession = Depends(get_db),
                                    current_password: str = Form(...),
                                    current_code: str = Form(...)):
    """Issue a fresh set of recovery codes.  The old ones stop working."""
    await check_csrf(request)
    user = require_page_user(request, db)

    if not verify_password(user.password_hash, current_password):
        return _back("that password is not right")
    if not check_totp(user, current_code):
        db.commit()
        return _back("that code is not right")

    import secrets as _secrets

    from app.core.crypto import hash_token

    codes = [_secrets.token_hex(4) for _ in range(10)]
    user.recovery_codes = json.dumps([hash_token(c) for c in codes])
    db.commit()

    await _push_accounts()
    audit.record("account.recovery_codes_regenerated", user=user,
                 source_ip=client_ip(request))

    csrf = ensure_csrf_token(request)
    response = render(request, "recovery_codes.html", user, csrf_token=csrf, codes=codes)
    issue_csrf_token(response, csrf)
    return response


@router.post("/account/sessions/revoke")
async def revoke_other_sessions(request: Request, db: DBSession = Depends(get_db)):
    """Sign out everywhere except this browser."""
    await check_csrf(request)
    user = require_page_user(request, db)

    from app.core.crypto import hash_token

    keep = hash_token(request.cookies.get(SESSION_COOKIE) or "")

    rows = db.query(SessionRow).filter(
        SessionRow.user_id == user.id,
        SessionRow.revoked == False,  # noqa: E712
        SessionRow.token_hash != keep,
    ).all()
    for row in rows:
        row.revoked = True
        row.revoked_reason = "signed out from the account page"
    db.commit()

    audit.record("account.sessions_revoked", user=user, source_ip=client_ip(request),
                 detail=f"{len(rows)} session(s)")
    return _back(ok=f"signed out {len(rows)} other session(s)")


def _back(error: str = None, ok: str = None):
    from urllib.parse import quote

    if error:
        return RedirectResponse(_p(f"/account?error={quote(error)}"), status_code=303)
    return RedirectResponse(_p(f"/account?ok={quote(ok or 'done')}"), status_code=303)


# ==============================================================================
# Other people's accounts, for admins
# ==============================================================================

@router.get("/users", response_class=HTMLResponse)
async def users_page(request: Request, db: DBSession = Depends(get_db),
                     error: str = None, ok: str = None):
    user = require_page_user(request, db)
    if not can(user, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can manage users")

    csrf = ensure_csrf_token(request)
    response = render(
        request, "users.html", user, csrf_token=csrf,
        users=db.query(User).order_by(User.username).all(),
        error=error, ok=ok,
    )
    issue_csrf_token(response, csrf)
    return response


@router.post("/users/{user_id}/reset-totp")
async def admin_reset_totp(user_id: int, request: Request,
                           db: DBSession = Depends(get_db)):
    """
    Clear someone's authenticator, for a lost phone with no recovery codes
    left.  They enroll a new one at their next password sign in.

    Logged loudly on purpose: removing a second factor is exactly what an
    attacker with admin access would do.
    """
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    target = db.query(User).filter(User.id == int(user_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="not found")

    target.totp_enrolled = False
    target.totp_secret_encrypted = None
    target.recovery_codes = "[]"
    target.failed_attempts = 0
    target.locked_until = None

    revoked = revoke_all_for_user(db, target.id, "authenticator was reset by an admin")
    db.query(SystemSetting).filter(
        SystemSetting.key == _pending_key(target.id)
    ).delete()
    db.commit()

    audit.record("user.totp_reset", user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=target.username,
                 detail=f"authenticator cleared, {revoked} session(s) signed out")
    log.warning("%s reset the authenticator on %s", actor.username, target.username)

    return _users_back(ok=f"{target.username} will set up a new authenticator at their next sign in")


@router.post("/users/{user_id}/unlock")
async def admin_unlock(user_id: int, request: Request, db: DBSession = Depends(get_db)):
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    target = db.query(User).filter(User.id == int(user_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="not found")

    target.failed_attempts = 0
    target.locked_until = None
    db.commit()

    audit.record("user.unlock", user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=target.username)
    return _users_back(ok=f"unlocked {target.username}")


@router.post("/users/{user_id}/enabled")
async def admin_set_enabled(user_id: int, request: Request,
                            db: DBSession = Depends(get_db),
                            enabled: str = Form(...)):
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    target = db.query(User).filter(User.id == int(user_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="not found")

    turning_on = enabled == "true"

    # Never disable the last admin.  Recovering from that means hand editing
    # the database.
    if not turning_on and target.id == actor.id:
        return _users_back("you cannot disable your own account")
    if not turning_on and _would_leave_no_admin(db, target):
        return _users_back("that is the only admin left, so it has to stay enabled")

    target.enabled = turning_on
    if not turning_on:
        revoke_all_for_user(db, target.id, "account was disabled")
    db.commit()

    audit.record("user.enabled" if turning_on else "user.disabled",
                 user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=target.username)
    return _users_back(ok=f"{target.username} {'enabled' if turning_on else 'disabled'}")


@router.post("/users/{user_id}/role")
async def admin_set_role(user_id: int, request: Request,
                         db: DBSession = Depends(get_db), role: str = Form(...)):
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    target = db.query(User).filter(User.id == int(user_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="not found")
    # Not your own role, same as delete.  A self-demoted admin is locked out
    # of this page and needs a shell on the box to get back.
    if target.id == actor.id:
        return _users_back("you cannot change your own role")

    try:
        new_role = UserRole(role)
    except ValueError:
        return _users_back("that is not a role")

    if new_role != UserRole.ADMIN and _would_leave_no_admin(db, target):
        return _users_back("that is the only admin left, so the role cannot change")

    old = target.role.value
    target.role = new_role

    # Don't let existing sessions keep the old permissions.
    revoke_all_for_user(db, target.id, "role changed")
    db.commit()

    audit.record("user.role_change", user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=target.username,
                 changes={"role": {"from": old, "to": new_role.value}})
    return _users_back(ok=f"{target.username} is now {new_role.value}")


@router.post("/users/create")
async def admin_create_user(request: Request, db: DBSession = Depends(get_db),
                            username: str = Form(...), full_name: str = Form(""),
                            email: str = Form(""), role: str = Form("viewer"),
                            password: str = Form(...)):
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    username = validate_name(username.strip(), "username")

    if db.query(User).filter(User.username == username).first():
        return _users_back(f"there is already an account called {username}")

    problems = password_problems(password)
    if problems:
        return _users_back("; ".join(problems))

    try:
        user_role = UserRole(role)
    except ValueError:
        return _users_back("that is not a role")

    db.add(User(
        username=username,
        full_name=full_name.strip() or None,
        email=email.strip() or None,
        source=AuthSource.LOCAL,
        role=user_role,
        password_hash=hash_password(password),
        enabled=True,
        # So the admin-typed password never becomes a long lived secret.
        must_change_password=True,
        created_by=actor.username,
    ))
    db.commit()

    audit.record("user.create", user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=username,
                 changes={"role": user_role.value})
    return _users_back(ok=f"made {username}, they set a password and an authenticator at first sign in")


@router.post("/users/{user_id}/delete")
async def admin_delete_user(user_id: int, request: Request,
                            db: DBSession = Depends(get_db)):
    await check_csrf(request)
    actor = require_page_user(request, db)
    if not can(actor, "manage_users"):
        raise HTTPException(status_code=403, detail="only an admin can do that")

    target = db.query(User).filter(User.id == int(user_id)).first()
    if not target:
        raise HTTPException(status_code=404, detail="not found")
    if target.id == actor.id:
        return _users_back("you cannot delete your own account")
    if _would_leave_no_admin(db, target):
        return _users_back("that is the only admin left")

    name = target.username
    db.delete(target)
    db.commit()

    audit.record("user.delete", user=actor, source_ip=client_ip(request),
                 object_type="user", object_name=name)
    return _users_back(ok=f"deleted {name}")


def _would_leave_no_admin(db, target: User) -> bool:
    """Is this the last enabled admin."""
    if target.role != UserRole.ADMIN:
        return False
    remaining = db.query(User).filter(
        User.role == UserRole.ADMIN,
        User.enabled == True,  # noqa: E712
        User.id != target.id,
    ).count()
    return remaining == 0


def _users_back(error: str = None, ok: str = None):
    from urllib.parse import quote

    if error:
        return RedirectResponse(_p(f"/users?error={quote(error)}"), status_code=303)
    return RedirectResponse(_p(f"/users?ok={quote(ok or 'done')}"), status_code=303)


# ==============================================================================
# Settings
# ==============================================================================

def _sso_capable_admins(db) -> list:
    """
    Enabled admins who have completed at least one provider sign in.

    `oidc_subject` is only set by a completed login, so this is proof the
    round trip works, which is what we want before turning passwords off.
    """
    return [u.username for u in db.query(User).filter(
        User.role == UserRole.ADMIN,
        User.enabled.is_(True),
        User.oidc_subject.isnot(None),
        User.oidc_subject != "",
    ).all()]


def _auth_mode_problem(db, mode: str) -> str:
    """
    Why this sign in mode cannot be selected, or "" when it can.

    Provider-only is the one setting that can silently lock everyone out, so
    it is refused until an enabled admin has signed in through the provider
    at least once while local passwords still worked.
    """
    from app.auth import oidc
    from app.core import settings_store

    if mode not in settings_store.AUTH_MODES:
        return "that is not one of the sign in modes"

    if mode == "local":
        return ""

    if not oidc.has_details():
        return ("single sign on needs a discovery URL, a client id and an "
                "address to come back to before it can be switched on")

    if mode == "oidc":
        capable = _sso_capable_admins(db)
        if not capable:
            return ("no admin has signed in through single sign on yet, so "
                    "turning local passwords off would lock everybody out.  "
                    "Leave this on local or single sign on, sign in that way "
                    "once, then come back and switch")

    return ""


@router.get("/settings", response_class=HTMLResponse)
async def settings_page(request: Request, db: DBSession = Depends(get_db),
                        error: str = None, ok: str = None):
    user = require_page_user(request, db)
    if not can(user, "manage_settings"):
        raise HTTPException(status_code=403, detail="only an admin can change settings")

    from app.auth import oidc
    from app.core import settings_store

    env = get_settings()
    csrf = ensure_csrf_token(request)

    # Everything the sign in card needs, including whether provider-only is
    # allowed yet.  That is an account question, so it is answered here and
    # not in the template.
    capable = _sso_capable_admins(db)
    auth = {
        "mode": settings_store.auth_mode(),
        "modes": settings_store.AUTH_MODES,
        "has_details": oidc.has_details(),
        "sso_admins": capable,
        "can_go_oidc_only": bool(capable) and oidc.has_details(),
        "from_env": bool(env.oidc_enabled and not settings_store.get("auth_mode")),
        "values": {
            key: settings_store.get(key) or ""
            for key in ("oidc_discovery_url", "oidc_client_id",
                        "oidc_redirect_base", "oidc_groups_claim",
                        "oidc_admin_group", "oidc_operator_group",
                        "oidc_viewer_group")
        },
        "secret_set": bool(settings_store.get("oidc_client_secret")),
    }

    response = render(
        request, "settings.html", user, csrf_token=csrf,
        values=settings_store.all_visible(), auth=auth,
        error=error, ok=ok,
        env={
            "node_name": env.node_name,
            "node_address": env.node_address,
            "gui_port": env.gui_port,
            "peer_port": env.peer_port,
            "cluster_priority": env.cluster_priority,
            "admin_allowlist": env.admin_allowlist,
            "session_timeout": env.session_timeout_minutes,
            "oidc_enabled": env.oidc_enabled,
            "root_path": env.root_path,
        },
    )
    issue_csrf_token(response, csrf)
    return response


@router.post("/settings")
async def save_settings(request: Request, db: DBSession = Depends(get_db),
                        acme_email: str = Form(""),
                        acme_staging: str = Form(None),
                        acme_renew_days_before: str = Form("30"),
                        management_networks: str = Form(""),
                        dns_resolvers: str = Form(""),
                        dns_use_system_resolver: str = Form(None),
                        health_check_interval: str = Form("10"),
                        geoip_source: str = Form(""),
                        geoip_account_id: str = Form(""),
                        geoip_license_key: str = Form(""),
                        geoip_refresh: str = Form("monthly"),
                        auth_mode: str = Form("local"),
                        oidc_discovery_url: str = Form(""),
                        oidc_client_id: str = Form(""),
                        oidc_client_secret: str = Form(""),
                        oidc_redirect_base: str = Form(""),
                        oidc_groups_claim: str = Form("groups"),
                        oidc_admin_group: str = Form("nginx-admins"),
                        oidc_operator_group: str = Form("nginx-operators"),
                        oidc_viewer_group: str = Form("nginx-viewers")):
    await check_csrf(request)
    user = require_page_user(request, db)
    if not can(user, "manage_settings"):
        raise HTTPException(status_code=403, detail="only an admin can change settings")

    import ipaddress
    import re
    from urllib.parse import quote

    from app.core import settings_store

    email = acme_email.strip()
    # Blank is allowed.  Only check the shape when something was typed.
    if email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}", email):
        return RedirectResponse(
            _p(f"/settings?error={quote('that does not look like an email address')}"),
            status_code=303,
        )

    networks = []
    for line in management_networks.replace(",", "\n").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_network(line, strict=False)
        except ValueError:
            return RedirectResponse(
                _p(f"/settings?error={quote(f'{line} is not a valid network.  Try 10.20.30.0/24')}"),
                status_code=303,
            )
        networks.append(line)

    try:
        days = int(acme_renew_days_before)
        interval = int(health_check_interval)
    except ValueError:
        return RedirectResponse(
            _p(f"/settings?error={quote('those numbers are not numbers')}"), status_code=303
        )

    if not 1 <= days <= 89:
        return RedirectResponse(
            _p(f"/settings?error={quote('renew days has to be between 1 and 89')}"),
            status_code=303,
        )
    if not 2 <= interval <= 300:
        return RedirectResponse(
            _p(f"/settings?error={quote('the check interval has to be between 2 and 300 seconds')}"),
            status_code=303,
        )

    resolvers = []
    for line in dns_resolvers.replace(",", "\n").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            ipaddress.ip_address(line)
        except ValueError:
            return RedirectResponse(
                _p(f"/settings?error={quote(f'{line} is not an IP address.  DNS servers are addresses, not names.')}"),
                status_code=303,
            )
        resolvers.append(line)

    before = settings_store.all_visible()

    settings_store.set("acme_email", email, user.username)
    settings_store.set("acme_staging", bool(acme_staging), user.username)
    settings_store.set("acme_renew_days_before", days, user.username)
    settings_store.set("management_networks", networks, user.username)
    settings_store.set("dns_resolvers", resolvers, user.username)
    settings_store.set("dns_use_system_resolver", bool(dns_use_system_resolver), user.username)
    settings_store.set("health_check_interval", interval, user.username)

    # Country database.  The license key field is always empty on load
    # (secrets never go to the browser), so only write it when one was typed.
    from app.core import geoip

    source = geoip_source.strip()
    if source not in ("", *geoip.SOURCES):
        return RedirectResponse(
            _p(f"/settings?error={quote('that is not a country database source')}"),
            status_code=303)
    schedule = geoip_refresh.strip() or "never"
    if schedule not in geoip.SCHEDULES:
        return RedirectResponse(
            _p(f"/settings?error={quote('that is not a refresh schedule')}"),
            status_code=303)

    # Sign in provider details are saved before the mode check below, so a
    # half finished setup is kept even if the chosen mode is refused.
    settings_store.set("oidc_discovery_url", oidc_discovery_url.strip(), user.username)
    settings_store.set("oidc_client_id", oidc_client_id.strip(), user.username)
    settings_store.set("oidc_redirect_base", oidc_redirect_base.strip().rstrip("/"),
                       user.username)
    settings_store.set("oidc_groups_claim", oidc_groups_claim.strip() or "groups",
                       user.username)
    settings_store.set("oidc_admin_group", oidc_admin_group.strip() or "nginx-admins",
                       user.username)
    settings_store.set("oidc_operator_group",
                       oidc_operator_group.strip() or "nginx-operators", user.username)
    settings_store.set("oidc_viewer_group",
                       oidc_viewer_group.strip() or "nginx-viewers", user.username)

    # Empty on every load, so only write it when one was typed.
    if oidc_client_secret.strip():
        settings_store.set("oidc_client_secret", oidc_client_secret.strip(),
                           user.username)

    problem = _auth_mode_problem(db, auth_mode)
    if problem:
        return RedirectResponse(_p(f"/settings?error={quote(problem)}"), status_code=303)
    settings_store.set("auth_mode", auth_mode, user.username)

    settings_store.set("geoip_source", source, user.username)
    settings_store.set("geoip_refresh", schedule, user.username)
    settings_store.set("geoip_account_id", geoip_account_id.strip(), user.username)
    if geoip_license_key.strip():
        settings_store.set("geoip_license_key", geoip_license_key.strip(),
                           user.username)

    audit.record("settings.update", user=user, source_ip=client_ip(request),
                 object_type="settings",
                 changes={
                     "acme_email": {"from": before["acme_email"]["value"], "to": email or "(none)"},
                     "acme_staging": {"from": before["acme_staging"]["value"], "to": bool(acme_staging)},
                     "management_networks": {"to": networks},
                 })

    from urllib.parse import quote as q

    return RedirectResponse(_p(f"/settings?ok={q('settings saved')}"), status_code=303)
