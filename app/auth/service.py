"""
Local accounts, TOTP, sessions and roles.

Local accounts are the break glass path: they keep working when the identity
provider is down.  Since they have to stand on their own, TOTP is mandatory.
"""

import base64
import io
import json
import logging
import secrets
import time
from datetime import timedelta

import pyotp
from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError

from app.config import get_settings
from app.core.crypto import decrypt, encrypt, hash_token, new_token
from app.models import AuthSource, Session, User, UserRole, utcnow

log = logging.getLogger("nfm.auth")

# argon2id with the recommended server parameters.  memory_cost is in KiB
# (64 MiB per hash), which is what blunts GPU cracking.
_hasher = PasswordHasher(
    time_cost=3,
    memory_cost=65536,
    parallelism=4,
    hash_len=32,
    salt_len=16,
)

TOTP_ISSUER = "Failover LB"
RECOVERY_CODE_COUNT = 10


# ==============================================================================
# Passwords
# ==============================================================================

def hash_password(password: str) -> str:
    return _hasher.hash(password)


def verify_password(stored_hash: str, password: str) -> bool:
    """
    Check a password.  Never raises, so a corrupt stored hash is a failed
    login rather than a 500 that reveals the account exists.
    """
    if not stored_hash or not password:
        return False
    try:
        _hasher.verify(stored_hash, password)
        return True
    except (VerifyMismatchError, VerificationError, InvalidHashError):
        return False
    except Exception:
        log.exception("something went wrong checking a password")
        return False


def needs_rehash(stored_hash: str) -> bool:
    """Was this hashed with weaker settings than we use now."""
    try:
        return _hasher.check_needs_rehash(stored_hash)
    except Exception:
        return False


def password_problems(password: str) -> list:
    """
    Reasons a password is too weak, or an empty list.

    Favors length over character class rules, which mostly produce
    "Password1!".
    """
    problems = []

    if len(password) < 12:
        problems.append("has to be at least 12 characters")
    if len(password) > 200:
        problems.append("has to be under 200 characters")

    # Reject a common word only when it makes up most of the password.  A
    # plain substring check would also refuse a good long passphrase such as
    # "correct-horse-battery-password-42".
    lowered = password.lower()
    for common in ("password", "nginx", "admin", "letmein", "changeme",
                   "welcome", "qwerty", "123456"):
        if common in lowered and len(common) * 2 > len(password):
            problems.append(
                f"is too close to {common!r}, which is one of the first things guessed.  "
                f"A longer passphrase can contain it, this one is mostly it."
            )
            break

    if password and len(set(password)) < 5:
        problems.append("uses too few different characters")

    return problems


# ==============================================================================
# TOTP
# ==============================================================================

def enroll_totp(user: User) -> dict:
    """
    Start TOTP setup.  Gives back the secret, a QR code and recovery codes.

    The QR code is rendered locally as a data URI.  Using an external chart
    service would leak the secret and fail on isolated networks.
    """
    secret = pyotp.random_base32()

    uri = pyotp.TOTP(secret).provisioning_uri(
        name=user.username,
        issuer_name=TOTP_ISSUER,
    )

    import qrcode

    qr = qrcode.QRCode(version=1, box_size=6, border=2)
    qr.add_data(uri)
    qr.make(fit=True)
    image = qr.make_image(fill_color="black", back_color="white")

    buffer = io.BytesIO()
    image.save(buffer, format="PNG")
    data_uri = "data:image/png;base64," + base64.b64encode(buffer.getvalue()).decode()

    codes = [secrets.token_hex(4) for _ in range(RECOVERY_CODE_COUNT)]

    return {
        "secret": secret,
        "uri": uri,
        "qr_data_uri": data_uri,
        "recovery_codes": codes,
        # Only hashes are stored, so a stolen database yields no usable codes.
        "recovery_hashes": [hash_token(c) for c in codes],
    }


def check_totp(user: User, code: str) -> bool:
    """
    Check a 6 digit code, or a recovery code.

    Accepts one step either side of now to allow for clock drift.

    Each code is accepted only once (RFC 6238 section 5.2): the last used time
    step is stored and anything at or before it is refused as a replay.  The
    step is stored rather than the code, so the row is useless if read.
    """
    if not code:
        return False

    code = code.strip().replace(" ", "")

    secret = decrypt(user.totp_secret_encrypted)
    if secret:
        totp = pyotp.TOTP(secret)
        # Find the step the code matches and refuse replays before
        # recording success.
        now = int(time.time()) // totp.interval
        used = user.totp_last_step
        for offset in (0, -1, 1):
            step = now + offset
            if not totp.verify(code, for_time=step * totp.interval):
                continue
            if used is not None and step <= used:
                log.warning("%s replayed a TOTP code from step %s", user.username, step)
                return False
            user.totp_last_step = step
            return True

    # Recovery codes are single use.
    return _consume_recovery_code(user, code)


# Logins that passed the password check but not yet TOTP, keyed by ticket.
# The ticket replaces re-posting the password from a hidden field.  Kept in
# memory only; a restart just means retyping the password.
_HALF_AUTH = {}
_HALF_AUTH_SECONDS = 300


def begin_totp(user: User, source_ip: str = None) -> str:
    """
    Record a successful password check and return a ticket for the TOTP step.

    The ticket is bound to the source address, otherwise it would act as a
    password equivalent until it expires.
    """
    _expire_half_auth()
    token = new_token(32)
    _HALF_AUTH[token] = {
        "user_id": user.id,
        "expires": time.time() + _HALF_AUTH_SECONDS,
        "source_ip": source_ip,
    }
    return token


def resume_totp(session, token: str, code: str, source_ip: str = None):
    """
    Finish a login whose password was already accepted.

    Applies the same checks as authenticate_local (account exists, enabled,
    not locked; wrong codes count toward lockout).  A wrong code leaves the
    ticket valid; a correct one consumes it.
    """
    _expire_half_auth()
    generic = "that sign in attempt expired, start again"

    entry = _HALF_AUTH.get(token or "")
    if not entry:
        return AuthResult(False, reason=generic)
    if entry["source_ip"] and source_ip and entry["source_ip"] != source_ip:
        log.warning("a half finished login was resumed from %s, issued to %s",
                    source_ip, entry["source_ip"])
        _HALF_AUTH.pop(token, None)
        return AuthResult(False, reason=generic)

    user = session.query(User).filter(User.id == entry["user_id"]).first()
    if not user or not user.enabled:
        _HALF_AUTH.pop(token, None)
        return AuthResult(False, reason=generic)

    if user.is_locked:
        return AuthResult(
            False,
            reason=f"that account is locked until {user.locked_until:%H:%M UTC} "
                   f"after too many bad attempts",
        )

    if not check_totp(user, code):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= get_settings().max_login_attempts:
            user.locked_until = utcnow() + timedelta(
                minutes=get_settings().lockout_minutes)
        return AuthResult(False, reason="that code is not right",
                          needs_totp=True)

    _HALF_AUTH.pop(token, None)
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    user.last_login_ip = source_ip
    return AuthResult(True, user=user)


def _expire_half_auth():
    now = time.time()
    for token in [t for t, e in _HALF_AUTH.items() if e["expires"] < now]:
        _HALF_AUTH.pop(token, None)


def _consume_recovery_code(user: User, code: str) -> bool:
    try:
        stored = json.loads(user.recovery_codes or "[]")
    except json.JSONDecodeError:
        return False

    candidate = hash_token(code)
    if candidate not in stored:
        return False

    stored.remove(candidate)
    user.recovery_codes = json.dumps(stored)
    log.warning("%s used a recovery code, %s left", user.username, len(stored))
    return True


def save_totp(user: User, secret: str, recovery_hashes: list):
    user.totp_secret_encrypted = encrypt(secret)
    user.recovery_codes = json.dumps(recovery_hashes)
    user.totp_enrolled = True


# ==============================================================================
# Logging in
# ==============================================================================

class AuthResult:
    def __init__(self, ok, user=None, reason=None, needs_totp=False,
                 needs_enrollment=False):
        self.ok = ok
        self.user = user
        self.reason = reason
        self.needs_totp = needs_totp
        self.needs_enrollment = needs_enrollment


def authenticate_local(session, username: str, password: str,
                       totp_code: str = None, source_ip: str = None) -> AuthResult:
    """
    Check a local login.

    Every failure returns the same message so usernames cannot be enumerated.
    Unknown users still pay for an argon2 hash to keep timing the same.
    """
    settings = get_settings()
    generic = "that username or password is not right"

    # Enforce SSO-only mode here; hiding the form is not enough since the
    # endpoint can still be posted to.  The explicit message reveals nothing
    # about any account, so it does not need to be generic.
    from app.core import settings_store
    if not settings_store.local_passwords_allowed():
        return AuthResult(
            False,
            reason="this fleet signs in through single sign on only, so a "
                   "username and password will not get you in",
        )

    user = session.query(User).filter(
        User.username == username,
        User.source == AuthSource.LOCAL,
    ).first()

    if not user:
        # Burn the same time we would have spent on a real check.
        _hasher.hash(password or "x")
        return AuthResult(False, reason=generic)

    if not user.enabled:
        return AuthResult(False, reason=generic)

    if user.is_locked:
        remaining = user.locked_until
        return AuthResult(
            False,
            reason=f"that account is locked until {remaining:%H:%M UTC} after too many bad attempts",
        )

    if not verify_password(user.password_hash, password):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= settings.max_login_attempts:
            user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
            log.warning(
                "locked %s after %s bad attempts from %s",
                username, user.failed_attempts, source_ip,
            )
        return AuthResult(False, reason=generic)

    # Password was right.  Now the second factor.
    if not user.totp_enrolled:
        # Must enroll TOTP before getting any further.
        return AuthResult(True, user=user, needs_enrollment=True)

    if not totp_code:
        return AuthResult(True, user=user, needs_totp=True)

    if not check_totp(user, totp_code):
        user.failed_attempts = (user.failed_attempts or 0) + 1
        if user.failed_attempts >= settings.max_login_attempts:
            user.locked_until = utcnow() + timedelta(minutes=settings.lockout_minutes)
        return AuthResult(False, reason="that code is not right", needs_totp=True)

    # All good.  Clear the counter and note the login.
    user.failed_attempts = 0
    user.locked_until = None
    user.last_login_at = utcnow()
    user.last_login_ip = source_ip

    if needs_rehash(user.password_hash):
        # Upgrade the hash while we have the plaintext.
        user.password_hash = hash_password(password)

    return AuthResult(True, user=user)


# ==============================================================================
# Sessions
# ==============================================================================

def create_session(session, user: User, source_ip: str = None,
                   user_agent: str = None) -> str:
    """
    Start a session and give back the cookie value.

    Sessions are stored server side so they can be revoked.  Only the token
    hash is stored.
    """
    settings = get_settings()
    token = new_token(32)

    session.add(Session(
        token_hash=hash_token(token),
        user_id=user.id,
        expires_at=utcnow() + timedelta(minutes=settings.session_timeout_minutes),
        ip_address=source_ip,
        user_agent=(user_agent or "")[:500],
    ))
    return token


def current_user(session, token: str, source_ip: str = None):
    """
    Look up who a session token belongs to.

    Also slides the expiry forward, so the timeout only catches idle sessions.
    """
    if not token:
        return None

    settings = get_settings()
    row = session.query(Session).filter(
        Session.token_hash == hash_token(token)
    ).first()

    if not row or not row.is_valid:
        return None

    user = row.user
    if not user or not user.enabled:
        return None

    row.last_seen_at = utcnow()
    row.expires_at = utcnow() + timedelta(minutes=settings.session_timeout_minutes)

    return user


def revoke_session(session, token: str, reason: str = "signed out"):
    row = session.query(Session).filter(
        Session.token_hash == hash_token(token)
    ).first()
    if row:
        row.revoked = True
        row.revoked_reason = reason[:255]


def revoke_all_for_user(session, user_id: int, reason: str = "revoked by an admin"):
    """
    Revoke every session a user has.

    Called on disable, role change and password change, so old permissions
    do not linger in a live session.
    """
    rows = session.query(Session).filter(
        Session.user_id == user_id,
        Session.revoked == False,  # noqa: E712
    ).all()
    for row in rows:
        row.revoked = True
        row.revoked_reason = reason[:255]
    return len(rows)


def cleanup_expired(session) -> int:
    """Clear out old sessions.  Runs on a timer."""
    cutoff = utcnow() - timedelta(days=7)
    count = session.query(Session).filter(Session.expires_at < cutoff).delete()
    return count


# ==============================================================================
# Roles
# ==============================================================================

# Explicit per-role permission sets, so a new permission has to be granted
# deliberately.
ROLE_PERMISSIONS = {
    UserRole.VIEWER: {
        "view",
    },
    UserRole.OPERATOR: {
        "view",
        "edit_sites", "edit_pools", "edit_certs", "edit_access_lists",
        "apply_config", "reload_nginx", "drain_member", "rollback",
    },
    UserRole.ADMIN: {
        "view",
        "edit_sites", "edit_pools", "edit_certs", "edit_access_lists",
        "apply_config", "reload_nginx", "drain_member", "rollback",
        "manage_users", "manage_cluster", "manage_settings",
        "failover", "join_nodes", "upgrade_nginx", "raw_config",
    },
}


def can(user: User, permission: str) -> bool:
    if not user or not user.enabled:
        return False
    return permission in ROLE_PERMISSIONS.get(user.role, set())


def require_role(user: User, permission: str):
    """Raise if they cannot.  Used as a guard at the top of a route."""
    from fastapi import HTTPException

    if not can(user, permission):
        raise HTTPException(
            status_code=403,
            detail=f"your role ({user.role.value if user else 'none'}) cannot {permission}",
        )


def role_for_groups(groups: list) -> UserRole:
    """
    Turn a group list from the identity provider into a role.

    The highest matching role wins.  Returns None if no group matches.
    """
    from app.core import settings_store

    names = settings_store.oidc_config()
    lowered = {str(g).lower() for g in (groups or [])}

    if names["admin_group"].lower() in lowered:
        return UserRole.ADMIN
    if names["operator_group"].lower() in lowered:
        return UserRole.OPERATOR
    if names["viewer_group"].lower() in lowered:
        return UserRole.VIEWER
    return None


# ==============================================================================
# First run
# ==============================================================================

def ensure_bootstrap_admin(session) -> dict:
    """
    Make the first admin account if there are no users at all.

    The password is random and logged once, rather than a shipped default.
    It must be changed, and TOTP enrolled, on first login.
    """
    if session.query(User).count() > 0:
        return {}

    password = secrets.token_urlsafe(18)

    user = User(
        username="admin",
        full_name="Break glass admin",
        source=AuthSource.LOCAL,
        role=UserRole.ADMIN,
        password_hash=hash_password(password),
        enabled=True,
        must_change_password=True,
        created_by="first run",
    )
    session.add(user)
    session.commit()

    log.warning("=" * 70)
    log.warning("Made the first admin account.")
    log.warning("  username: admin")
    log.warning("  password: %s", password)
    log.warning("")
    log.warning("This is shown once and never again.  Log in, change it, and set")
    log.warning("up your authenticator app.")
    log.warning("=" * 70)

    return {"username": "admin", "password": password}
