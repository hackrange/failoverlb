"""
Local accounts, TOTP, sessions and roles.

Local accounts are the break glass path.  They keep working when the identity
provider is down, which is the entire reason they exist.  If your SSO is broken
you may well need to get into the load balancer to fix it, and an admin tool
that can only be reached through the thing that is broken is not much use.

Because of that they have to be strong on their own, so TOTP is not optional.
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

# argon2id, which is what you should use for passwords now.  The parameters are
# the ones the argon2 people suggest for a server: enough memory that building
# a GPU rig to crack these stops being cheap.
#
# memory_cost is in KiB, so 64 MiB per hash.  That is the number that actually
# does the work here.  A GPU has plenty of cores but not much memory per core,
# so a memory hungry hash is what takes away their advantage.
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
    Check a password.

    Always returns a bool and never raises, so a corrupt hash in the database
    reads as a failed login rather than a 500 that tells the caller the account
    exists.
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
    Check a password is not trivially bad.

    Length first, because it matters far more than the character classes people
    usually get asked for.  A long passphrase beats a short one with a symbol
    jammed in, and forcing symbols mostly produces Password1! on repeat.
    """
    problems = []

    if len(password) < 12:
        problems.append("has to be at least 12 characters")
    if len(password) > 200:
        problems.append("has to be under 200 characters")

    # Block the obvious ones without punishing a long passphrase that happens to
    # contain the word.
    #
    # A plain substring check refuses "correct-horse-battery-password-42", which
    # is a perfectly good password, and it does it with a message that sounds
    # like the person did something wrong.  Worse, somebody hitting that on the
    # forced change screen can easily think the change went through when it did
    # not, and then find themselves locked out with the old password they have
    # already forgotten.
    #
    # What actually makes "password123" weak is that the guessable part is
    # nearly the whole thing.  So compare lengths: if the common word is most of
    # the password, it is weak.  If it is a small part of something much longer,
    # the length is doing the work and the word does not matter.
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

    The QR code is drawn here and handed over as a data URI.  Plenty of tools
    send the secret off to a Google chart URL to make the image, which quietly
    hands your second factor to somebody else.  We draw it locally, and it also
    means this works on a network with no route to the internet.
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
        # Only the hashes go in the database.  Same reasoning as passwords: a
        # stolen database should not hand somebody a way in.
        "recovery_hashes": [hash_token(c) for c in codes],
    }


def check_totp(user: User, code: str) -> bool:
    """
    Check a 6 digit code, or a recovery code.

    valid_window=1 accepts the code either side of now.  Phone clocks drift, and
    people start typing a code with two seconds left on it.  Without the window
    you get a stream of complaints that the codes do not work.

    **A code is accepted once and never again.**  The window is what makes that
    necessary: without it the same six digits authenticate as often as somebody
    submits them, for up to about ninety seconds.  RFC 6238 section 5.2
    requires the verifier to refuse a code it has already taken, and the reason
    is the ordinary one, which is that a code can be seen.  Over a shoulder, in
    a screen share, through a proxy relaying a real login.  The attacker still
    needs the password, so this is an amplifier rather than a way in, and it is
    an amplifier worth removing.

    Which step was used is recorded rather than which code, because the step is
    what the comparison needs and because it will not do as a password
    equivalent if the row is ever read.
    """
    if not code:
        return False

    code = code.strip().replace(" ", "")

    secret = decrypt(user.totp_secret_encrypted)
    if secret:
        totp = pyotp.TOTP(secret)
        # Which step this code belongs to, checked across the same window the
        # verify below allows.  Asked first, so a replay is refused before it
        # can be counted as a success anywhere.
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

    # Recovery codes.  Single use, so we take it out of the list once it works.
    return _consume_recovery_code(user, code)


# Logins that have passed the password and not yet the code.
#
# The second stage used to carry the password back through the browser in a
# hidden field and post it again with the code.  Autoescaping meant that was
# not an injection point, but it put the credential in the page's DOM and in
# the tab's history for the length of the login, and sent it twice instead of
# once.  A credential that only needs to exist for one request should not
# outlive it.
#
# In memory rather than in the database, because it is worth nothing after a
# few minutes and there is no reason to write a half authenticated state to
# disk.  A restart loses it, which costs somebody one retype.
_HALF_AUTH = {}
_HALF_AUTH_SECONDS = 300


def begin_totp(user: User, source_ip: str = None) -> str:
    """
    Remember that this account got its password right, and hand back a ticket.

    Bound to the address it was issued to.  A ticket that works from anywhere
    would be a password equivalent for five minutes, which is most of what this
    change was meant to remove.
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
    Finish a login that already got the password right.

    Runs the same checks the one shot path does, in the same order and against
    the same counter, so nothing is weaker for having been split in two: the
    account has to still exist, still be enabled and not be locked, and a wrong
    code still climbs toward the lockout.

    The ticket survives a wrong code on purpose.  Burning it would mean typing
    the password again after every mistyped digit, and the lockout already
    bounds how many guesses anybody gets.  It is burned the moment one works.
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

    Every failure gives back the same message.  Saying "no such user" tells an
    attacker which names are real, and then they only have to work on the
    passwords.  Telling them nothing means they have to guess both.

    We also run the password check even when the account does not exist.  Argon2
    takes a noticeable amount of time on purpose, so returning instantly for an
    unknown name is itself an answer.  Doing the work anyway keeps the timing
    the same either way.
    """
    settings = get_settings()
    generic = "that username or password is not right"

    # Refused before anything is checked when the fleet is on the provider
    # only.  Hiding the form on the login page is presentation; this is the
    # part that means it, because a form nobody can see is still a URL anybody
    # can post to.
    #
    # Said plainly rather than through `generic`.  The usual reason for a vague
    # message is not telling an attacker which usernames are real, and this
    # answer tells them nothing about any account: it is the same for a name
    # that exists, a name that does not, and an empty box.
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
        # A local account with no second factor is the weakest way into this
        # thing, so they set one up before they get any further.
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
        # Quietly upgrade the hash while we have the password in hand.  This is
        # the only moment we can, so it is worth taking.
        user.password_hash = hash_password(password)

    return AuthResult(True, user=user)


# ==============================================================================
# Sessions
# ==============================================================================

def create_session(session, user: User, source_ip: str = None,
                   user_agent: str = None) -> str:
    """
    Start a session and give back the cookie value.

    Sessions live in the database rather than only in a signed cookie, so an
    admin can actually revoke one.  A signed cookie you cannot revoke is fine
    right up until the day somebody leaves and you need to cut them off now.

    Only the hash is stored.  Same reason as passwords.
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

    Also slides the expiry forward, so somebody actively working does not get
    logged out mid change.  The timeout is meant to catch an abandoned browser,
    not to interrupt somebody in the middle of something.
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
    Kill every session a user has.

    Called when somebody is disabled, has their role changed, or changes their
    password.  A role change that leaves the old session alive means the person
    keeps their old permissions until they happen to log out.
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

# What each role can do.  Kept as an explicit list rather than worked out from
# the role name, so adding a permission means deciding who gets it rather than
# it appearing somewhere by accident.
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

    Highest wins.  Somebody in both the admin and viewer groups is an admin,
    which is what people expect, and it means adding somebody to the admin group
    works without having to remove them from anything first.
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

    The password is random and printed to the log once.  A shipped default like
    admin/admin is how these tools end up on the internet with the default still
    set, and it is not worth the small convenience.

    They have to change it and set up TOTP on first login.
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
