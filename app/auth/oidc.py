"""
Single sign on.

Standard OpenID Connect authorization code flow with PKCE.  Works with Okta,
Entra, Keycloak, Google, anything that publishes a discovery document.

Local accounts keep working alongside SSO by default, so a provider outage
(possibly behind this very load balancer) does not lock admins out.

Settings can switch a fleet to SSO only, disabling local passwords.  That mode
can only be chosen after an admin has completed an SSO login, and
`auth-recovery.sh` in the install directory turns local passwords back on from
a shell if the provider breaks.

Settings live in the database via `settings_store`, with `NFM_OIDC_*`
environment variables as a fallback.  Always read them through `config()`.
"""

import base64
import hashlib
import json
import logging
import secrets
import time
from urllib.parse import urlencode

import httpx
import jwt
from jwt import PyJWKClient

from app.auth.service import role_for_groups
from app.models import AuthSource, User, UserRole, utcnow

log = logging.getLogger("nfm.oidc")

# Discovery documents rarely change; cache them to save a round trip per
# login.
_discovery_cache = {}
_DISCOVERY_TTL = 3600

# Logins in flight: PKCE verifier keyed by state.
_pending = {}
_PENDING_TTL = 600


class OIDCError(Exception):
    pass


async def get_discovery() -> dict:
    url = config()["discovery_url"]

    if not url:
        raise OIDCError("no OIDC discovery URL is set")

    cached = _discovery_cache.get(url)
    if cached and time.time() - cached["fetched"] < _DISCOVERY_TTL:
        return cached["doc"]

    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(url)
            response.raise_for_status()
            doc = response.json()
    except httpx.HTTPError as exc:
        raise OIDCError(f"could not read the discovery document: {exc}")
    except json.JSONDecodeError:
        raise OIDCError("the discovery URL did not return json")

    for field in ("authorization_endpoint", "token_endpoint", "issuer", "jwks_uri"):
        if field not in doc:
            raise OIDCError(f"the discovery document is missing {field}")

    _discovery_cache[url] = {"doc": doc, "fetched": time.time()}
    return doc


def _redirect_uri() -> str:
    base = config()["redirect_base"].rstrip("/")
    if not base:
        raise OIDCError("nobody has set the address the provider sends people "
                        "back to, under Settings")
    return f"{base}/auth/oidc/callback"


async def begin_login(source_ip: str = None) -> str:
    """
    Start a login and return the provider URL to redirect to.

    `state` is checked on the callback to prevent login CSRF.  PKCE makes a
    stolen authorization code useless without the verifier.
    """
    doc = await get_discovery()

    state = secrets.token_urlsafe(32)
    verifier = secrets.token_urlsafe(64)
    challenge = base64.urlsafe_b64encode(
        hashlib.sha256(verifier.encode()).digest()
    ).decode().rstrip("=")

    _cleanup_pending()
    _pending[state] = {
        "verifier": verifier,
        "created": time.time(),
        "source_ip": source_ip,
    }

    params = {
        "response_type": "code",
        "client_id": config()["client_id"],
        "redirect_uri": _redirect_uri(),
        "scope": "openid profile email groups",
        "state": state,
        "code_challenge": challenge,
        "code_challenge_method": "S256",
    }

    return f"{doc['authorization_endpoint']}?{urlencode(params)}"


async def complete_login(code: str, state: str, source_ip: str = None) -> dict:
    """Exchange the code for tokens and verify the id_token."""

    pending = _pending.pop(state, None)
    if not pending:
        raise OIDCError(
            "that login attempt is not one we started, or it took too long.  Try again."
        )

    if time.time() - pending["created"] > _PENDING_TTL:
        raise OIDCError("that login took too long, start again")

    doc = await get_discovery()

    data = {
        "grant_type": "authorization_code",
        "code": code,
        "redirect_uri": _redirect_uri(),
        "client_id": config()["client_id"],
        "code_verifier": pending["verifier"],
    }
    secret = config()["client_secret"]
    if secret:
        data["client_secret"] = secret

    try:
        async with httpx.AsyncClient(timeout=20) as client:
            response = await client.post(
                doc["token_endpoint"],
                data=data,
                headers={"Accept": "application/json"},
            )
    except httpx.HTTPError as exc:
        raise OIDCError(f"could not reach the token endpoint: {exc}")

    if response.status_code >= 400:
        raise OIDCError(f"the provider refused the code: {response.text[:300]}")

    tokens = response.json()
    id_token = tokens.get("id_token")
    if not id_token:
        raise OIDCError("the provider did not send back an id_token")

    claims = await _verify_id_token(id_token, doc)

    # Some providers leave groups out of the id_token; fall back to userinfo.
    groups = claims.get(config()["groups_claim"]) or []
    if not groups and doc.get("userinfo_endpoint") and tokens.get("access_token"):
        groups = await _fetch_groups(doc["userinfo_endpoint"], tokens["access_token"])

    return {
        "subject": claims.get("sub"),
        "username": claims.get("preferred_username") or claims.get("email") or claims.get("sub"),
        "email": claims.get("email"),
        "full_name": claims.get("name"),
        "groups": groups,
        "claims": claims,
    }


async def _verify_id_token(id_token: str, doc: dict) -> dict:
    """
    Verify the id_token signature against the provider's JWKS, plus issuer,
    audience and expiry.  Do not loosen this: an unverified token can claim
    to be anyone.
    """

    try:
        jwk_client = PyJWKClient(doc["jwks_uri"], cache_keys=True, lifespan=3600)
        signing_key = jwk_client.get_signing_key_from_jwt(id_token)
    except Exception as exc:
        raise OIDCError(f"could not get the signing key from the provider: {exc}")

    try:
        claims = jwt.decode(
            id_token,
            signing_key.key,
            algorithms=["RS256", "RS384", "RS512", "ES256", "ES384"],
            audience=config()["client_id"],
            issuer=doc["issuer"],
            options={
                "verify_signature": True,
                "verify_exp": True,
                "verify_aud": True,
                "verify_iss": True,
                "require": ["exp", "iat", "iss", "aud", "sub"],
            },
            leeway=30,
        )
    except jwt.ExpiredSignatureError:
        raise OIDCError("that token has expired, try logging in again")
    except jwt.InvalidAudienceError:
        raise OIDCError("that token was issued for a different application")
    except jwt.InvalidIssuerError:
        raise OIDCError("that token came from an issuer we do not trust")
    except jwt.InvalidTokenError as exc:
        raise OIDCError(f"the token did not check out: {exc}")

    return claims


async def _fetch_groups(userinfo_url: str, access_token: str) -> list:
    try:
        async with httpx.AsyncClient(timeout=15) as client:
            response = await client.get(
                userinfo_url,
                headers={"Authorization": f"Bearer {access_token}"},
            )
            if response.status_code >= 400:
                return []
            return response.json().get(config()["groups_claim"]) or []
    except (httpx.HTTPError, json.JSONDecodeError):
        return []


def sync_user(session, profile: dict) -> User:
    """
    Find or make the local record for an SSO user.

    The role is recomputed from groups on every login, so directory changes
    take effect at next login.  Users are matched on the stable `sub` claim,
    not the username or email.
    """
    subject = profile.get("subject")
    if not subject:
        raise OIDCError("the provider did not send a subject claim")

    role = role_for_groups(profile.get("groups"))
    if role is None:
        raise OIDCError(
            "your account is not in any of the groups that grant access here.  "
            "Ask whoever runs the directory to add you."
        )

    user = session.query(User).filter(
        User.oidc_subject == subject,
        User.source == AuthSource.OIDC,
    ).first()

    if not user:
        # Never take over an existing local account with the same name, or a
        # directory user named "admin" would become the break glass admin.
        username = profile.get("username") or subject
        clash = session.query(User).filter(User.username == username).first()
        if clash:
            username = f"{username} (sso)"

        user = User(
            username=username[:64],
            source=AuthSource.OIDC,
            oidc_subject=subject,
            created_by="oidc",
        )
        session.add(user)
        log.info("made an account for SSO user %s with role %s", username, role.value)

    user.email = profile.get("email")
    user.full_name = profile.get("full_name")
    user.role = role
    user.enabled = True
    user.last_login_at = utcnow()

    session.commit()
    return user


def _cleanup_pending():
    now = time.time()
    for state, entry in list(_pending.items()):
        if now - entry["created"] > _PENDING_TTL:
            _pending.pop(state, None)


def config() -> dict:
    """
    OIDC settings: database first, `NFM_OIDC_*` environment as fallback.

    Single source so a login cannot start against one provider and finish
    against another.
    """
    from app.core import settings_store
    return settings_store.oidc_config()


def has_details() -> bool:
    """
    Whether the required provider details are filled in.

    Separate from `is_configured` so Settings can show "configured but
    switched off".
    """
    values = config()
    return bool(values["discovery_url"] and values["client_id"]
                and values["redirect_base"])


def is_configured() -> bool:
    """
    Whether SSO should be offered right now: the auth mode allows it and the
    details are present.  "Local only" wins even with a full configuration.
    """
    from app.core import settings_store
    return settings_store.oidc_offered() and has_details()
