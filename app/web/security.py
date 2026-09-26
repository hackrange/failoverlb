"""
Security layer for the web app: client address handling, middleware, CSRF,
object lookups and input validation.

The main guard is against broken object level authorization (BOLA/IDOR),
where /api/pools/7 checks that you're logged in but not that you may see
pool 7. Objects on a load balancer aren't owned by individual users, so the
rule here is permission based, but the discipline is the same: every lookup
by id goes through ObjectGuard, and routes have no other way to fetch an
object, so they can't forget the check.
"""

import ipaddress
import logging
import re
import secrets
import time

from fastapi import HTTPException, Request
from fastapi.responses import JSONResponse, RedirectResponse
from starlette.middleware.base import BaseHTTPMiddleware

from app.auth.service import can
from app.config import get_settings

log = logging.getLogger("nfm.security")

CSRF_COOKIE = "nfm_csrf"
SESSION_COOKIE = "nfm_session"

# Methods that change state and therefore need a CSRF token. GET and HEAD
# must never change anything.
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths where a one time ticket in the URL stands in for the admin allow
# list, because the machine that needs them is by definition not on it.
# Every entry must be a path whose credential is such a ticket: single use,
# short lived, stored only as a hash.
TICKETED_PATHS = (
    "/tunnel/enrol/",     # a workload joining the tunnel
    "/tunnel/psk/",       # a workload already on it, taking a pre-shared key
)

# Paths that skip the login check. Matched exactly or by strict prefix,
# never a substring test.
PUBLIC_PATHS = {
    "/healthz",
    "/login",
    "/auth/login",
    "/auth/oidc/start",
    "/auth/oidc/callback",
    "/static",
}


# ==============================================================================
# Where the request came from
# ==============================================================================

def client_ip(request: Request) -> str:
    """
    The real client address, used by the allow list, login rate limit,
    account lockout and audit log.

    X-Forwarded-For is only trusted when the connection comes from an
    address in trusted_proxies (empty by default). Trusting it from anyone
    lets a client claim a management address; not setting it behind a proxy
    makes every visitor look like the proxy (often loopback), and the allow
    list quietly passes everyone.

    Walk the header from the right, the end our proxies append to, and take
    the first address that isn't a trusted proxy. The left end is whatever
    the client wrote.
    """
    peer = request.client.host if request.client else "unknown"

    trusted = get_settings().trusted_proxy_networks
    if not trusted or not ip_allowed(_bare(peer), trusted):
        return peer

    forwarded = request.headers.get("x-forwarded-for", "")
    for candidate in reversed([p.strip() for p in forwarded.split(",") if p.strip()]):
        bare = _bare(candidate)
        try:
            ipaddress.ip_address(bare)
        except ValueError:
            # Junk in the header. Stop rather than skip it; everything to
            # the left is untrustworthy now.
            break
        if not ip_allowed(bare, trusted):
            return bare

    # All hops were trusted proxies, or there was no header. Use the peer.
    return peer


def _bare(ip: str) -> str:
    """Strip the ::ffff: that a dual stack listener puts on a v4 address."""
    text = str(ip)
    return text[7:] if text.startswith("::ffff:") else text


def _is_loopback(ip: str) -> bool:
    """
    True for loopback. Parsed rather than string compared, since a dual
    stack listener reports "::ffff:127.0.0.1" and loopback is all of
    127.0.0.0/8.
    """
    try:
        return ipaddress.ip_address(
            ip[7:] if ip.startswith("::ffff:") else ip
        ).is_loopback
    except ValueError:
        return ip == "localhost"


def ip_allowed(ip: str, networks) -> bool:
    if not networks:
        # Nothing configured means no restriction. The dashboard warns about
        # this rather than locking everyone out.
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ==============================================================================
# Middleware
# ==============================================================================

# A response sets this to keep its own security headers. The middleware
# strips it before the response goes out.
SANDBOX_OPT_OUT = "X-NFM-Own-Security-Headers"


def sandboxed_html_headers() -> dict:
    """
    Headers for serving HTML someone else wrote (the error page preview).

    CSP `sandbox` gives the document its own origin, so even opened directly
    it can't read our cookies, storage or the framing page. That's what makes
    it safe on the GUI's host. Inline styles and data: images are allowed so
    the preview is accurate; scripts and all fetches are off, so a preview
    can't phone home or probe the network from an admin's browser.
    """
    return {
        SANDBOX_OPT_OUT: "1",
        "Content-Security-Policy": (
            "sandbox; "
            "default-src 'none'; "
            "style-src 'unsafe-inline'; "
            "img-src data:; "
            "frame-ancestors 'self'"
        ),
        "X-Frame-Options": "SAMEORIGIN",
    }


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers on every response.

    The CSP can be strict because every asset is ours and same origin: no
    CDN, external fonts or analytics. Inline scripts need a nonce.

    The error page preview is the one exception. It sets its own stricter
    sandboxed policy and signals that with SANDBOX_OPT_OUT; see
    sandboxed_html_headers.
    """

    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        # MutableHeaders has no pop. The marker must not reach the browser;
        # it would just advertise our middleware.
        if response.headers.get(SANDBOX_OPT_OUT):
            del response.headers[SANDBOX_OPT_OUT]
            # It brought its own CSP and frame rules; don't overwrite them.
            response.headers["X-Content-Type-Options"] = "nosniff"
            response.headers["Referrer-Policy"] = "no-referrer"
            response.headers["Cache-Control"] = "no-store"
            return response

        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            # Styles keep unsafe-inline because a few components set inline
            # widths. Style injection is far less dangerous than script, and
            # nonces on every style attribute aren't worth it.
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' data:; "
            "font-src 'self'; "
            "connect-src 'self'; "
            "form-action 'self'; "
            "frame-ancestors 'none'; "
            "base-uri 'self'; "
            "object-src 'none'"
        )

        response.headers["Content-Security-Policy"] = csp
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "DENY"
        response.headers["Referrer-Policy"] = "no-referrer"
        response.headers["Permissions-Policy"] = (
            "geolocation=(), microphone=(), camera=(), payment=(), usb=()"
        )
        response.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        response.headers["Cross-Origin-Resource-Policy"] = "same-origin"

        # The GUI is HTTPS only, so HSTS is safe.
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

        # Build id on every response. Most of the GUI's JavaScript is inline,
        # so a tab left open across an upgrade keeps running old code, and the
        # failures look like feature bugs. Every page talks to the API, so the
        # client can compare this for free without polling.
        from app.web.routes_pages import ASSET_VERSION
        response.headers["X-NFM-Build"] = ASSET_VERSION

        # Never cache management pages; a shared machine shouldn't keep your
        # nginx config in its browser cache.
        if not request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response


class AdminAllowlistMiddleware(BaseHTTPMiddleware):
    """
    Drop anything from outside the management networks. Runs before the
    login page renders, so a stolen password from the wrong network has
    nowhere to be typed.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        networks = settings.admin_networks

        # Health endpoint stays open for docker and external checks. It
        # returns nothing sensitive.
        if request.url.path == "/healthz":
            return await call_next(request)

        # The ticketed tunnel paths are open on purpose. A workload joining
        # the tunnel is on someone else's network and will never be on the
        # allow list. The ticket in the path stands in for it: single use,
        # two hour expiry, stored only as a hash. Without a valid one these
        # return nothing.
        #
        # Every ticketed path must be listed in TICKETED_PATHS. The PSK path
        # was once missed, and workloads got an HTML 404 piped into bash.
        #
        # Strip the root path first. Matching the raw path works at the root
        # but blocks every enrollment on an install served under a prefix.
        _root = get_settings().root_path.rstrip("/")
        _path = request.url.path
        if _root and _path.startswith(_root):
            _path = _path[len(_root):] or "/"
        if _path.startswith(TICKETED_PATHS):
            return await call_next(request)

        ip = client_ip(request)

        # Loopback always passes. The certbot hooks on this host post to
        # 127.0.0.1 to publish challenge tokens, and a real allow list won't
        # include it, so issuance used to fail with a confusing 404.
        #
        # This gives nothing away: anyone on loopback is already on the box
        # and can read the database. The hook endpoint also requires a
        # shared secret, and everything else requires a session.
        if _is_loopback(ip):
            return await call_next(request)

        if not ip_allowed(ip, networks):
            log.warning("turned away %s %s from %s, not on the allow list",
                        request.method, request.url.path, ip)
            # 404, not 403: don't confirm anything is here.
            return JSONResponse({"detail": "not found"}, status_code=404)

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Throttle login attempts per address.

    The auth layer's lockout protects one account. This catches password
    spraying across many usernames, which never trips a per account
    lockout. An in-memory dict is enough for a management GUI; it resets on
    restart.
    """

    def __init__(self, app, max_attempts=10, window_seconds=300):
        super().__init__(app)
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts = {}

    async def dispatch(self, request: Request, call_next):
        # Strip the root path first. Without this the check never matched
        # on installs served under a prefix, and the limiter silently did
        # nothing. AdminAllowlistMiddleware does the same for the same
        # reason.
        #
        # Only /auth/login is limited; the second factor is posted there
        # too, alongside the password.
        root = get_settings().root_path.rstrip("/")
        path = request.url.path
        if root and path.startswith(root):
            path = path[len(root):] or "/"

        if path != "/auth/login":
            return await call_next(request)
        if request.method != "POST":
            return await call_next(request)

        ip = client_ip(request)
        now = time.time()

        hits = [t for t in self._attempts.get(ip, []) if now - t < self.window]

        if len(hits) >= self.max_attempts:
            log.warning("rate limited login attempts from %s", ip)
            return JSONResponse(
                {"detail": "too many login attempts, wait a few minutes"},
                status_code=429,
                headers={"Retry-After": str(self.window)},
            )

        hits.append(now)
        self._attempts[ip] = hits

        # Keep the dict bounded on a box that gets scanned.
        if len(self._attempts) > 10000:
            cutoff = now - self.window
            self._attempts = {
                k: [t for t in v if t > cutoff]
                for k, v in self._attempts.items()
                if any(t > cutoff for t in v)
            }

        return await call_next(request)


# ==============================================================================
# CSRF
# ==============================================================================

def new_csrf_token() -> str:
    """
    Make a CSRF token. Separate from setting the cookie because a server
    rendered form needs the value before the response exists; the caller
    passes the same token to both.
    """
    return secrets.token_urlsafe(32)


def ensure_csrf_token(request: Request) -> str:
    """
    Reuse this browser's existing token, or make one.

    Minting a new token per page render rewrites the shared cookie and
    breaks forms already open in other tabs with a confusing CSRF error.
    A double submit token is a secret, not a nonce, so keeping it for the
    cookie's lifetime costs nothing.
    """
    existing = request.cookies.get(CSRF_COOKIE)
    # Replace a malformed or hand edited cookie rather than comparing it.
    if existing and 20 <= len(existing) <= 128 and existing.replace("-", "").replace("_", "").isalnum():
        return existing
    return new_csrf_token()


def issue_csrf_token(response, token: str = None) -> str:
    """
    Set the CSRF cookie (double submit pattern).

    Page JavaScript reads the cookie and echoes it in a header. A cross site
    form post carries the cookie but can't read it to set the header.
    SameSite=Strict on the session cookie is a second layer, since browser
    SameSite support has had gaps.
    """
    token = token or new_csrf_token()
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=86400,
        # Must be readable by our own script so it can be copied into a
        # header.
        httponly=False,
        secure=True,
        samesite="strict",
        # Scope to our prefix so we don't scatter cookies over other apps on
        # the same host.
        path=(get_settings().root_path.rstrip("/") or "") + "/",
    )
    return token


async def check_csrf(request: Request):
    """
    Raise unless the submitted token matches the cookie.

    fetch based API calls send an X-CSRF-Token header. Login, enrollment and
    password forms are plain posts with no JavaScript, so they send a hidden
    field instead. Signing in must work even when the page's scripts don't.
    """
    if request.method not in UNSAFE_METHODS:
        return

    cookie_token = request.cookies.get(CSRF_COOKIE)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="CSRF cookie missing, reload the page")

    sent = request.headers.get("X-CSRF-Token")

    if not sent:
        # Only parse a real form post; .form() on JSON gives nothing useful.
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            try:
                # Starlette caches the parsed form, so the route's Form(...)
                # parameters still get the body.
                form = await request.form()
                sent = form.get("csrf_token")
            except Exception:
                sent = None

    if not sent:
        raise HTTPException(status_code=403, detail="CSRF token missing, reload the page")

    if not secrets.compare_digest(cookie_token, str(sent)):
        log.warning("CSRF mismatch on %s from %s", request.url.path, client_ip(request))
        raise HTTPException(status_code=403, detail="CSRF token does not match, reload the page")


# ==============================================================================
# Object level checks, the BOLA and IDOR guard
# ==============================================================================

class ObjectGuard:
    """
    The only way to fetch an object by id.

    Checks the permission, looks the object up, and returns 404 for both
    "doesn't exist" and "not allowed" so ids can't be probed. Routes have no
    other way to fetch rows by id, so they can't skip the check.
    """

    def __init__(self, session, user):
        self.session = session
        self.user = user

    def get(self, model, object_id, permission: str = "view"):
        if not can(self.user, permission):
            # Same as not found; a 403 would confirm the object exists.
            raise HTTPException(status_code=404, detail="not found")

        # Ids come from the URL. Convert explicitly rather than handing an
        # arbitrary string to the ORM.
        try:
            oid = int(object_id)
        except (TypeError, ValueError):
            raise HTTPException(status_code=404, detail="not found")

        if oid < 1:
            raise HTTPException(status_code=404, detail="not found")

        obj = self.session.query(model).filter(model.id == oid).first()
        if not obj:
            raise HTTPException(status_code=404, detail="not found")

        return obj

    def list(self, model, permission: str = "view"):
        if not can(self.user, permission):
            raise HTTPException(status_code=403, detail="you cannot view these")
        return self.session.query(model).all()

    def require(self, permission: str):
        if not can(self.user, permission):
            raise HTTPException(
                status_code=403,
                detail=f"your role cannot {permission.replace('_', ' ')}",
            )


# ==============================================================================
# Mass assignment
# ==============================================================================

def pick_fields(payload: dict, allowed: set) -> dict:
    """
    Keep only the fields declared editable, to prevent mass assignment
    (posting {"role": "admin"} alongside a name). Always an allow list: with
    a deny list every new field is editable until someone remembers.
    """
    return {k: v for k, v in (payload or {}).items() if k in allowed}


# ==============================================================================
# Input checks
# ==============================================================================

# Names that become filenames and nginx identifiers. Strict on purpose.
SAFE_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$")

HOSTNAME_RE = re.compile(
    r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)*"
    r"[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?$"
)


def validate_name(name: str, what: str = "name") -> str:
    if not name or not SAFE_NAME_RE.match(str(name)):
        raise HTTPException(
            status_code=400,
            detail=(
                f"that {what} is not valid.  Letters, numbers, dots, dashes and "
                f"underscores only, starting with a letter or number, up to 64 characters."
            ),
        )
    return str(name)


def validate_hostname(name: str) -> str:
    """
    Check a server_name. "_" is allowed because nginx uses it for the catch
    all server.
    """
    if name == "_":
        return name
    if not name or len(name) > 253 or not HOSTNAME_RE.match(str(name)):
        raise HTTPException(status_code=400, detail=f"{name!r} is not a valid hostname")
    return str(name)


def validate_cidr(value: str) -> str:
    try:
        ipaddress.ip_network(value, strict=False)
        return value
    except ValueError:
        raise HTTPException(
            status_code=400,
            detail=f"{value!r} is not a valid address or network.  Try 10.20.30.0/24 or 10.20.30.5",
        )


def validate_port(value) -> int:
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise HTTPException(status_code=400, detail="that port is not a number")
    if not 1 <= port <= 65535:
        raise HTTPException(status_code=400, detail="a port has to be between 1 and 65535")
    return port
