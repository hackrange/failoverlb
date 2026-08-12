"""
The security layer for the web app.

Everything in here is aimed at the OWASP top ten, and a couple of items get
special attention because they are the ones that actually bite tools like this.

Broken object level authorization, which OWASP calls BOLA and everybody else
calls IDOR, is number one on their API list for a reason.  It is the bug where
/api/pools/7 checks that you are logged in but never checks that pool 7 is
anything to do with you.  Change the number, get somebody else's data.

The usual advice is "check ownership", which does not quite fit here, because a
load balancer's objects are not owned by individual users.  So the rule here is
different but the discipline is the same: every object lookup goes through one
function that takes the current user and the permission needed, and there is no
other way to fetch an object by id.  A route physically cannot forget the check,
because there is nowhere else to get the object from.
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

# Methods that change something.  These need a CSRF token.  GET and HEAD do not,
# and must not change anything, which is why they do not need one.
UNSAFE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}

# Paths that skip the login check.  Kept short on purpose and checked by exact
# match or a strict prefix, never with a loose "in" test, because a substring
# check here is how /healthz-but-actually-admin sneaks through.
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
    Work out the real client address.

    We do NOT read X-Forwarded-For here, and that is deliberate.  Anybody can
    send that header, so trusting it would let somebody put a management network
    address in it and walk straight through the allow list below.

    The GUI is meant to be reached directly.  If you really do put a proxy in
    front of it, that proxy has to be the thing enforcing the allow list.
    """
    if request.client:
        return request.client.host
    return "unknown"


def _is_loopback(ip: str) -> bool:
    """
    Is this the machine talking to itself.

    Written out rather than compared against a list of strings.  A connection to
    127.0.0.1 turns up as "::ffff:127.0.0.1" on a dual stack listener, and
    loopback is the whole of 127.0.0.0/8, not one address.  A literal list
    misses both.
    """
    try:
        return ipaddress.ip_address(
            ip[7:] if ip.startswith("::ffff:") else ip
        ).is_loopback
    except ValueError:
        return ip == "localhost"


def ip_allowed(ip: str, networks) -> bool:
    if not networks:
        # Nothing configured means no restriction.  The GUI shouts about this on
        # the dashboard rather than silently locking everybody out.
        return True
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in networks)


# ==============================================================================
# Middleware
# ==============================================================================

class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers on every response.

    The CSP is strict because it can be.  This is our own GUI, we control every
    asset, and everything is served from the same origin.  There is no CDN, no
    outside font, no analytics.  So default-src 'self' just works, and there is
    no reason to weaken it.

    No unsafe-inline for scripts.  Any inline script gets a nonce.
    """

    async def dispatch(self, request: Request, call_next):
        nonce = secrets.token_urlsafe(16)
        request.state.csp_nonce = nonce

        response = await call_next(request)

        csp = (
            "default-src 'self'; "
            f"script-src 'self' 'nonce-{nonce}'; "
            # Styles keep unsafe-inline because a few components set things like
            # a progress bar width inline.  Style injection is a much smaller
            # problem than script injection, and locking this down would mean a
            # nonce on every style attribute for very little gain.
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

        # The GUI is https only, so this is safe and worth having.
        response.headers["Strict-Transport-Security"] = "max-age=31536000"

        # Management pages should never be cached.  A shared machine with a page
        # of your nginx config sitting in the browser cache is not great.
        if not request.url.path.startswith("/static"):
            response.headers["Cache-Control"] = "no-store, no-cache, must-revalidate"
            response.headers["Pragma"] = "no-cache"

        return response


class AdminAllowlistMiddleware(BaseHTTPMiddleware):
    """
    Drop anything from outside the management networks.

    This runs before the login page even renders.  A stolen password from the
    wrong network gets nothing, because there is nothing to type it into.
    """

    async def dispatch(self, request: Request, call_next):
        settings = get_settings()
        networks = settings.admin_networks

        # The health endpoint stays open so a load balancer or docker can check
        # us without being on the list.  It returns nothing sensitive.
        if request.url.path == "/healthz":
            return await call_next(request)

        ip = client_ip(request)

        # Loopback always gets through, whatever the allow list says.
        #
        # The manager calls itself.  The certbot hooks run on this host and post
        # to 127.0.0.1 to publish a challenge token, and an allow list of real
        # management networks does not contain 127.0.0.1, so the manager was
        # turning away its own hook and certificates could never be issued.  The
        # 404 it returned looked like a broken hook URL and sent people looking
        # at DNS and port 80.
        #
        # This gives nothing away.  Reaching us on loopback means already being
        # on this box, and anybody there can read the database and write the
        # challenge file by hand.  The endpoints that matter do their own checks
        # on top: the hook wants a shared secret, everything else wants a
        # session.
        if _is_loopback(ip):
            return await call_next(request)

        if not ip_allowed(ip, networks):
            log.warning("turned away %s %s from %s, not on the allow list",
                        request.method, request.url.path, ip)
            # 404 rather than 403.  There is no reason to confirm to somebody
            # off the allow list that there is anything here at all.
            return JSONResponse({"detail": "not found"}, status_code=404)

        return await call_next(request)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    Slow down login attempts.

    The account lockout in the auth layer protects one account.  This protects
    the box: somebody spraying one common password across a list of usernames
    never trips a single account's lockout, because each account only sees one
    attempt.

    A dict in memory is enough.  This is a management GUI with a handful of
    users, not a public site, and it resets on restart which is fine.
    """

    def __init__(self, app, max_attempts=10, window_seconds=300):
        super().__init__(app)
        self.max_attempts = max_attempts
        self.window = window_seconds
        self._attempts = {}

    async def dispatch(self, request: Request, call_next):
        if request.url.path not in ("/auth/login", "/auth/totp"):
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

        # Keep the dict from growing forever on a box that gets scanned.
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
    Make a CSRF token.

    Split out from setting the cookie because a server rendered form needs the
    value while the page is being built, and the cookie only gets set on the
    response afterwards.  Both halves have to be the same string or the check
    fails, so the caller makes the token once and passes it to both.
    """
    return secrets.token_urlsafe(32)


def ensure_csrf_token(request: Request) -> str:
    """
    Reuse the token this browser already has, or make one if it has none.

    Minting a fresh token on every page render sounds tidier and quietly breaks
    things.  The cookie is shared across the whole browser, so rendering a
    second page rewrites it, and the form sitting in the first tab is now
    holding a value that no longer matches.  Submitting it fails with a CSRF
    error that makes no sense to the person looking at it, and reloading
    "fixes" it, which makes the whole thing look flaky rather than broken.

    A token is a random secret, not a nonce.  Keeping the same one for the life
    of the cookie is the normal way to do double submit and gives up nothing.
    """
    existing = request.cookies.get(CSRF_COOKIE)
    # Sanity check what came back.  A cookie somebody hand edited should be
    # replaced rather than trusted into a comparison.
    if existing and 20 <= len(existing) <= 128 and existing.replace("-", "").replace("_", "").isalnum():
        return existing
    return new_csrf_token()


def issue_csrf_token(response, token: str = None) -> str:
    """
    Put a CSRF token in a cookie.

    Double submit pattern.  The token goes in a cookie the page's JavaScript can
    read, and the page sends it back in a header.  A form posted from another
    site can carry the cookie, because browsers attach cookies to cross site
    posts, but it cannot read that cookie to set the header.  Same origin policy
    stops it.

    SameSite=Strict on the session cookie is the other half.  Belt and braces,
    because SameSite handling has had gaps in various browsers over the years.
    """
    token = token or new_csrf_token()
    response.set_cookie(
        CSRF_COOKIE,
        token,
        max_age=86400,
        # Readable by our own script on purpose.  This is the one cookie that
        # has to be, because the page needs to copy it into a header.
        httponly=False,
        secure=True,
        samesite="strict",
        # Scope the cookie to our prefix so we do not scatter cookies over
        # whatever else is served on the same hostname.
        path=(get_settings().root_path.rstrip("/") or "") + "/",
    )
    return token


async def check_csrf(request: Request):
    """
    Raise unless the token the caller sent matches the cookie.

    Two ways to send it, because we have two kinds of caller.

    The API pages use fetch and set an X-CSRF-Token header.  That is the clean
    way and it is what most of the app does.

    The login, enrolment and password forms post normally, with no JavaScript
    involved.  A plain form cannot set a header, so those send the token in a
    hidden field instead.  Keeping those forms working without JavaScript is
    deliberate: signing in is the one thing that has to work even when something
    else on the page is broken.
    """
    if request.method not in UNSAFE_METHODS:
        return

    cookie_token = request.cookies.get(CSRF_COOKIE)
    if not cookie_token:
        raise HTTPException(status_code=403, detail="CSRF cookie missing, reload the page")

    sent = request.headers.get("X-CSRF-Token")

    if not sent:
        # Only look at the form for a real form post.  Calling .form() on a JSON
        # body would try to parse it as a form and give nothing useful.
        content_type = request.headers.get("content-type", "")
        if content_type.startswith(("application/x-www-form-urlencoded", "multipart/form-data")):
            try:
                # Starlette caches the parsed form, so reading it here does not
                # steal the body from the Form(...) parameters on the route.
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

    Every route that takes an id in the URL goes through here.  It does three
    things in one place:

      1. Checks the user holds the permission this action needs.
      2. Looks the object up.
      3. Returns 404, not 403, when the object does not exist or they cannot
         have it.

    Point three is worth being deliberate about.  A 403 on an object that exists
    and a 404 on one that does not lets somebody map out what is on the system
    just by counting ids.  Same answer either way means they learn nothing.

    Point one is what stops the classic version of this bug.  There is no path
    where a route fetches a row itself and forgets the check, because routes do
    not have a way to fetch rows by id at all.
    """

    def __init__(self, session, user):
        self.session = session
        self.user = user

    def get(self, model, object_id, permission: str = "view"):
        if not can(self.user, permission):
            # Deliberately the same as not found.  Telling somebody "you are not
            # allowed to see pool 7" confirms pool 7 exists.
            raise HTTPException(status_code=404, detail="not found")

        # Ids come out of the URL, so they are strings that could be anything.
        # int() them explicitly rather than handing them to the ORM, so a
        # cleverly shaped id cannot end up somewhere it should not.
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
    Take only the fields we said were editable.

    Guards against mass assignment, which is the bug where a form posts
    {"name": "x", "role": "admin"} and the code helpfully sets both because it
    loops over whatever arrived.

    Allow list, never a deny list.  A deny list means every new field is
    editable by default until somebody remembers to add it, and they will not.
    """
    return {k: v for k, v in (payload or {}).items() if k in allowed}


# ==============================================================================
# Input checks
# ==============================================================================

# Names that become filenames and nginx identifiers.  Strict on purpose.
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
    Check a server_name.

    The underscore is allowed as a special case because nginx uses it for the
    catch all server, and it is not a real hostname.
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
