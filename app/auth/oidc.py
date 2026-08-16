"""
Single sign on.

Standard OpenID Connect authorization code flow with PKCE.  Works with Okta,
Entra, Keycloak, Google, anything that publishes a discovery document.

Local accounts keep working alongside this by default, and that default is
deliberate.  It is the thing most SSO integrations get wrong: if the identity
provider is down, and it is behind the load balancer you need to fix, you have
locked yourself out of the tool you need to fix it.

A fleet can now be set to this only, from Settings, which switches local
passwords off.  There is a real reason to want that, because leaving passwords
on means the provider's lockout, second factor and leaver process all have a
way round them.  It is guarded on the way in and on the way out.  On the way
in, the mode cannot be chosen until an admin has completed a login this way, so
intention is never enough.  On the way out, `auth-recovery.sh` in the install
directory turns local passwords back on from a shell, without the browser and
without the provider, which is the door that does not depend on the thing that
broke.

Where the settings come from: the database, through `settings_store`, with the
`NFM_OIDC_*` environment variables behind them as a fallback.  Read through
`config()` and never straight from the environment, or half the flow ends up
talking to one provider and half to another.
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

# Discovery documents barely ever change, and fetching one on every login adds a
# round trip to somebody else's server before anybody can get in.
_discovery_cache = {}
_DISCOVERY_TTL = 3600

# Login attempts in flight.  Holds the PKCE verifier and the state value between
# sending somebody off to the provider and them coming back.
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
    Start a login and give back the URL to send the browser to.

    Two things get generated here and both matter.

    state is random and gets checked when they come back.  Without it, somebody
    can hand a victim a crafted callback URL and log them into an account the
    attacker controls, which is login CSRF.

    PKCE is the code_verifier and its hash.  It stops a stolen authorization
    code being useful to anybody who does not also hold the verifier.  It was
    designed for mobile apps but there is no reason not to use it here.
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
    """
    Finish the login.  Swaps the code for tokens and checks the id_token.
    """

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

    # Groups sometimes are not in the id_token, usually because the provider
    # keeps it small.  If we did not get any, ask the userinfo endpoint.
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
    Check the id_token properly.

    This is the part that must not be skipped or loosened.  An id_token is only
    worth anything if the signature is checked against the provider's published
    keys, and the issuer and audience are checked too.

    Decoding it without verifying, which is a very common shortcut because it is
    one line shorter, means anybody can hand us a token they wrote themselves
    claiming to be an admin.
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

    The role comes from their groups and gets refreshed on every login.  That
    matters: somebody removed from the admin group in your directory should stop
    being an admin here the next time they log in, without anybody having to
    remember to come and change it.

    We match on the subject claim, not the username.  Usernames and email
    addresses change when people get married or change departments.  The subject
    does not.
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
        # Do not let an SSO login take over an existing local account with the
        # same name.  That would be a way to get in as the break glass admin by
        # making an account with a matching name in the directory.
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
    Where every value in this module comes from.

    The settings page writes these to the database and the environment is the
    fallback, so an install that set `NFM_OIDC_*` before the page existed keeps
    working untouched.  Read through one function rather than nine scattered
    lookups, because the bug that prevents is a login that starts against the
    provider in the database and finishes against the one in the environment.
    """
    from app.core import settings_store
    return settings_store.oidc_config()


def has_details() -> bool:
    """
    Whether enough has been filled in for a login to have a chance.

    Deliberately separate from `is_configured`.  The settings page needs to
    show "the details are here but the mode has it switched off", and a single
    boolean cannot say that.
    """
    values = config()
    return bool(values["discovery_url"] and values["client_id"]
                and values["redirect_base"])


def is_configured() -> bool:
    """
    Whether the provider should be offered on the login page right now.

    Two questions, both of which have to be yes: the mode allows it, and enough
    details exist to try.  The mode is checked first because "local only" has
    to win even when a provider is fully configured, which is the state
    somebody is in while they are still setting one up.
    """
    from app.core import settings_store
    return settings_store.oidc_offered() and has_details()
