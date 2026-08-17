"""
The two paths a site level rewrite must not touch, and why each one hurts.

A rewrite written on a site runs in the server rewrite phase, before nginx has
picked a location.  That is what somebody typing one means by it, and it is
also why it reaches two paths they never meant to change:

  The certificate challenge.  ^/(.*)$ /app/$1 turns
  /.well-known/acme-challenge/TOKEN into /app/.well-known/..., the location
  that serves the challenge stops matching, and issuing a certificate fails
  with a 403.  Worse on a site that already has one: it keeps working and then
  silently fails to renew sixty days later, unattended.

  Our own error pages.  Serving one is an internal redirect, and nginx restarts
  an internal redirect at the server rewrite phase, so the rules run a second
  time on the page meant to explain the first error.  /__nfm_error/x/404.html
  becomes /app/__nfm_error/x/404.html, the internal location stops matching,
  and nginx will not recurse into an error page, so the visitor gets the stock
  nginx page.  Reported from a real farm: template applied, config reads
  correctly, plain nginx page on screen, nothing in the log naming the rewrite.

Both guards are one `if` with a `break`, and both are easy to lose in a later
edit because the config still reads correctly with them gone.  Neither shows up
in nginx -t.  So this file checks the lines are there, in front of the rules,
and reading the right variable.

The error page guard was also proved against a real nginx by hand, serving the
generated block on a loopback port and fetching a missing path: without it the
answer is nginx's own 404 page, with it the site's template.  Worth repeating
the same way if this ever gets rewritten, because everything below is still
only reading text.

Nothing here applies config, restarts a service or writes to the database.

    docker exec -i nginx-fleet-manager python < checks/rewrite_guards.py
"""
import json
import socket
import sys

from app.core import error_pages
from app.core.render import Renderer
from app.db import session_scope
from app.models import (
    ErrorPageTemplate, Location, Pool, PoolMember, VirtualHost, json_set,
)
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail}")


def agent(request):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(120)
    sock.connect(SOCKET)
    sock.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    sock.close()
    return json.loads(buf.decode())


# The shape of the rule that found this, with a made up prefix in place of the
# real one.  It already steps around the challenge itself, which is the tell:
# somebody hit that trap, fixed it by hand, and had no way to know about the
# second one.  The long opaque prefix is kept because that is the case that
# hurts: the rewritten error page path is nowhere near anything on disk.
FARM_RULE = "^/(?!\\.well-known/)(.*)$ /AAAA-BBBB-CCCC-DDDD-EEEE-FFFF/$1 break"

_tpl = ErrorPageTemplate(name="rw-guard", html=error_pages.starter_html(),
                         codes=json_set([404, 502]))
_tpl.id = 940
_tpl.images = []

_pool = Pool(name="rw_guard_pool", lb_method="round_robin")
_pool.id = 940
_pool.members = [PoolMember(address="192.0.2.10", port=8080,
                            enabled=True, admin_state="up")]


def render_files(site_rules, path_rules=None, template=True):
    """Every file for one scratch site.  Never touches the database."""
    host = VirtualHost(
        name="rwguard.invalid", enabled=True, server_names='["rwguard.invalid"]',
        listen_http=True, listen_https=False, force_https=False, mode="proxy",
        http_port=80, https_port=443,
        settings=json.dumps({"rewrite_rules": site_rules}))
    host.id = 940
    host.pool_id = 940
    host.pool = _pool
    if template:
        host.error_page_template_id = 940

    loc = Location(host_id=940, path="/", match_type="prefix", mode="proxy",
                   pool_id=940, enabled=True, sort_order=10,
                   settings=json.dumps({"rewrite_rules": path_rules or []}))
    loc.id = 940
    loc.pool = _pool
    host.locations = [loc]

    return Renderer().render_all(
        [host], [_pool], [], [], [], [], [], [], [],
        error_templates=[_tpl] if template else [])


def render(site_rules, path_rules=None, template=True):
    """Just the scratch site's own config, which is what most checks read."""
    return render_files(site_rules, path_rules, template).get(
        "sites/rwguard.invalid.conf", "")


def main():
    print("\n  Rewrite guards\n")

    conf = render([FARM_RULE])

    guard = f"if ($uri ~ ^{error_pages.URI_PREFIX}/)"
    check("a site with a rewrite gets the error page guard",
          guard in conf,
          "without it a site level rewrite mangles the internal redirect that "
          "fetches the error page, and the visitor sees nginx's stock page")

    check("the guard still steps around the certificate challenge",
          "if ($request_uri ~ ^/\\.well-known/acme-challenge/)" in conf,
          "the older guard went missing, so certificate renewal breaks quietly")

    # Order is the whole point.  A guard written after the rules has already
    # lost: the rules ran.
    if guard in conf and FARM_RULE.split()[0] in conf:
        check("both guards come before the rules they protect against",
              conf.index(guard) < conf.index(f"rewrite {FARM_RULE};")
              and conf.index("acme-challenge") < conf.index(f"rewrite {FARM_RULE};"),
              "a guard after the rules does nothing at all")

    # $uri, not $request_uri.  This is the one that looks right and is not:
    # during an internal redirect $request_uri still holds what the client
    # asked for, so the guard would never match the error page path.
    check("the error page guard reads $uri, not $request_uri",
          guard in conf and f"$request_uri ~ ^{error_pages.URI_PREFIX}" not in conf,
          "$request_uri keeps the client's original path through an internal "
          "redirect, so a $request_uri test never sees the error page at all")

    # The guard has to name the same prefix the error_page lines use, or it
    # guards a path nothing ever asks for.
    check("the guard names the prefix the error_page lines actually use",
          f"error_page 404 {error_pages.URI_PREFIX}/" in conf
          and f"location ^~ {error_pages.URI_PREFIX}/" in conf,
          "the guard and the error pages disagree about the prefix")

    # A site with no rewrites should stay clean.  An unconditional `if` block on
    # every site is noise in a file people read, and noise gets deleted.
    quiet = render([])
    check("a site with no rewrites gets no guards",
          "acme-challenge) {" not in quiet and guard not in quiet,
          "guards written for a site that has nothing to guard against")

    # Guards belong at server level only.  A location's own rewrites run after
    # nginx has already picked the location, and the internal error page
    # location is ^~ so it wins outright: the rules there never see it.
    path_only = render([], path_rules=["^/api/v1/(.*)$ /$1 break"])
    check("a path's own rewrites get no guards",
          guard not in path_only,
          "a guard inside a location is dead weight: the error page never "
          "reaches that location in the first place")

    # And a site with rewrites but no template still gets the guard, because
    # somebody can apply a template later without touching the rewrite.
    later = render([FARM_RULE], template=False)
    check("the guard is there before a template is applied",
          guard in later,
          "applying a template would otherwise silently need the rewrite "
          "edited as well, which is exactly what nobody knows to do")

    # Real nginx on the real config, which catches a guard that is syntactically
    # wrong.  It cannot catch a guard that is simply absent, which is why every
    # check above exists.
    wrote = agent({"verb": "write_staging", "files": render_files([FARM_RULE])})
    if not wrote.get("ok"):
        check("nginx accepts the guarded config", False,
              f"could not stage: {wrote.get('error')}")
    else:
        result = agent({"verb": "test_staging"}).get("data", {})
        check("nginx accepts the guarded config", bool(result.get("ok")),
              (result.get("output") or "").strip())

        # Put the real config back.  Staging is shared, and leaving a scratch
        # site in it means the next person to press Check and repair, or to
        # look at what is staged, is reading this check's leftovers.  Nothing
        # here was ever applied, so this only rewrites a directory.
        with session_scope() as session:
            live, _checksum, _snapshot = render_current(session)
        back = agent({"verb": "write_staging", "files": live})
        check("staging is back to the real config",
              back.get("ok") and "sites/rwguard.invalid.conf" not in live,
              "the scratch site is still staged, clean it up before applying")

    failed = results.count(False)
    print(f"\n  {len(results) - failed} passed, {failed} failed\n")
    return 1 if failed else 0


sys.exit(main())
