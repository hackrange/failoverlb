"""
Telling nginx the backend sits under a path, without a rewrite rule.

The setting exists because the obvious way to do this is wrong in a way that
takes days to find.  A rewrite rule that adds a prefix has to be written at the
site level, and a site level rewrite runs in the rewrite phase, before nginx
has picked a location, so it rewrites every request on the site: the ACME
challenge and the internal error pages along with the traffic it was meant for.
People carve those two back out with a negative lookahead, the site works, and
then the next thing that needs carving out arrives and nobody remembers why the
lookahead is there.  Watched exactly that happen on a live fleet.

A path on proxy_pass does the same job in the content phase, inside the one
location that proxies, where it cannot reach anything else.

What has to hold:

  the path reaches proxy_pass, and nothing writes a rewrite for it
  the challenge and the error pages are untouched
  the redirects the backend sends come back without the path on them
  anything set by hand is written first, because nginx takes the first
    proxy_redirect that matches and stops
  a regex location gets the rewrite form instead, because nginx refuses a URI
    on proxy_pass there and would refuse the whole config with it

Proved against a real nginx as well, serving the generated block: a request for
/thing reaches the backend as /shop/thing, the challenge file still comes back,
a backend 404 still shows the site's template, and a backend redirect to
/shop/dir/ reaches the browser as /dir/.

Nothing here writes to the database or applies config.

    docker exec -i nginx-fleet-manager python < checks/backend_path.py
"""
import json
import socket
import sys

from app.core import error_pages
from app.core.render import Renderer
from app.models import (
    ErrorPageTemplate, Location, Pool, PoolMember, VirtualHost, json_set,
)

SOCKET = "/run/nginxmgr/agent.sock"
PREFIX = "/HYET-TEST-PREFIX/"

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:300]}")


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


_tpl = ErrorPageTemplate(name="bp-guard", html=error_pages.starter_html(),
                         codes=json_set([404]))
_tpl.id = 950
_tpl.images = []

_pool = Pool(name="bp_pool", lb_method="round_robin")
_pool.id = 950
_pool.members = [PoolMember(address="192.0.2.10", port=8080,
                            enabled=True, admin_state="up")]


def render_files(settings, match_type="prefix", path="/"):
    host = VirtualHost(
        name="bpath.invalid", enabled=True, server_names='["bpath.invalid"]',
        listen_http=True, listen_https=False, force_https=False, mode="proxy",
        http_port=80, https_port=443, settings=json.dumps({}))
    host.id = 950
    host.pool_id = 950
    host.pool = _pool
    host.error_page_template_id = 950

    loc = Location(host_id=950, path=path, match_type=match_type, mode="proxy",
                   pool_id=950, enabled=True, sort_order=10,
                   settings=json.dumps(settings))
    loc.id = 950
    loc.pool = _pool
    host.locations = [loc]

    return Renderer().render_all(
        [host], [_pool], [], [], [], [], [], [], [], error_templates=[_tpl])


def render(settings, match_type="prefix", path="/"):
    return render_files(settings, match_type, path).get(
        "sites/bpath.invalid.conf", "")


def main():
    print("\n  A backend under a path of its own\n")

    conf = render({"backend_path": PREFIX})

    check("the path goes on proxy_pass",
          f"proxy_pass http://bp_pool{PREFIX};" in conf,
          "without it the backend gets the request at the root and answers 404, "
          "which reads as the backend being broken")

    # The whole point of the setting.  A rewrite anywhere at server level would
    # be the thing this exists to avoid.
    server_level = conf.split("    location ")[0]
    check("no rewrite rule is written for it",
          "rewrite" not in server_level,
          "a site level rewrite is what this setting exists to avoid, because "
          "it runs before nginx picks a location and so hits the challenge and "
          "the error pages too")

    check("the certificate challenge is untouched",
          "location ^~ /.well-known/acme-challenge/" in conf
          and PREFIX not in conf.split("acme-challenge/")[1].split("}")[0],
          "the challenge has to be served from disk exactly as asked for, or "
          "issuing and renewing both fail")

    check("the error pages are untouched",
          f"location ^~ {error_pages.URI_PREFIX}/" in conf
          and f"error_page 404 {error_pages.URI_PREFIX}/" in conf,
          "the error page path must not gain the backend's prefix")

    # Three rules, because a backend says where it sent you in three ways.
    check("the backend's own path is taken off its redirects",
          f"proxy_redirect http://$host{PREFIX} /;" in conf
          and f"proxy_redirect https://$host{PREFIX} /;" in conf
          and f"proxy_redirect {PREFIX} /;" in conf,
          "without these the visitor's address bar grows a path the site does "
          "not answer on")

    # And the one that catches a backend naming itself, or its own port, which
    # a rule scoped to $host alone reads straight past.  Found on a real nginx
    # while this was being built: the backend answered
    # http://site:8080/PREFIX/dir/ and the path stayed on.
    check("a backend that names its own port is caught too",
          f"proxy_redirect ~^https?://[^/]+{PREFIX}(.*)$ /$1;" in conf,
          "a backend on a port of its own puts that port in the Location, and "
          "the scoped rules do not match it")

    check("the catch all is written last",
          conf.index(f"proxy_redirect {PREFIX} /;")
          < conf.index(f"proxy_redirect ~^https?://[^/]+{PREFIX}"),
          "nginx takes the first rule that matches, so the narrow ones have to "
          "be tried before the pattern")

    # Order, which is the whole game with proxy_redirect.
    hand = render({"backend_path": PREFIX, "proxy_redirect": "/mine/ /"})
    if "proxy_redirect /mine/ /;" in hand:
        check("a rule set by hand is written before the generated ones",
              hand.index("proxy_redirect /mine/ /;")
              < hand.index(f"proxy_redirect http://$host{PREFIX} /;"),
              "nginx takes the first proxy_redirect that matches and stops, so "
              "a hand written rule written second can never fire")
    else:
        check("a rule set by hand is written at all", False, hand[:300])

    check("and it says so in the config",
          "written" in hand and "above" in hand,
          "somebody reading this block should not have to know that the order "
          "is what makes it work")

    # A regex location cannot carry a URI on proxy_pass.  nginx refuses the
    # whole config, which takes every site on the node down, not just this one.
    rx = render({"backend_path": PREFIX}, match_type="regex", path="^/api/")
    check("a regex path does not get a uri on proxy_pass",
          f"proxy_pass http://bp_pool{PREFIX};" not in rx,
          "nginx refuses a uri on proxy_pass in a regex location and refuses "
          "the whole config with it")

    check("a regex path gets the rewrite form instead, inside the location",
          f"rewrite ^(.*)$ {PREFIX.rstrip('/')}$1 break;" in rx,
          "same result, written the way nginx allows there")

    check("and that rewrite is inside the location, not at server level",
          "rewrite" not in rx.split("    location ")[0],
          "a rewrite at server level is the trap this setting exists to avoid, "
          "and putting one there for a regex path would walk straight into it")

    # Set on the pool, which is where it belongs and where people look for it.
    # The first attempt at setting this was typing the path onto a member's
    # address, which is host and port, and being told the port was not valid.
    _pool.settings = json_set({"backend_path": PREFIX})
    try:
        from_pool = render({})
        check("a path set on the pool reaches proxy_pass",
              f"proxy_pass http://bp_pool{PREFIX};" in from_pool,
              "the pool is where this belongs, because it is a fact about the "
              "backend rather than about any one site pointed at it")

        check("a path set on the pool gets its redirects rewritten too",
              f"proxy_redirect {PREFIX} /;" in from_pool,
              "half the feature is taking the path back off what the backend "
              "says about itself")

        # And a site can still say otherwise, for the same backend reached two
        # ways.
        override = render({"backend_path": "/other/"})
        check("a site overrides what the pool says",
              "proxy_pass http://bp_pool/other/;" in override
              and PREFIX not in override,
              "the more specific setting has to win, or the override is a "
              "field that silently does nothing")
    finally:
        _pool.settings = json_set({})

    # A site that does not use the setting must be exactly as it was.
    plain = render({})
    check("a site without the setting is unchanged",
          "proxy_pass http://bp_pool;" in plain
          and "proxy_redirect" not in plain,
          "this setting must cost nothing to the sites that do not use it")

    # Real nginx on the real thing.
    for label, files in (("prefix path", render_files({"backend_path": PREFIX})),
                         ("regex path", render_files({"backend_path": PREFIX},
                                                     match_type="regex",
                                                     path="^/api/"))):
        wrote = agent({"verb": "write_staging", "files": files})
        if not wrote.get("ok"):
            check(f"nginx accepts the config, {label}", False,
                  f"could not stage: {wrote.get('error')}")
            continue
        result = agent({"verb": "test_staging"}).get("data", {})
        check(f"nginx accepts the config, {label}", bool(result.get("ok")),
              (result.get("output") or "").strip())

    # Put the real config back.  Staging is shared.
    from app.db import session_scope
    from app.web.routes_api import render_current
    with session_scope() as session:
        live, _c, _s = render_current(session)
    back = agent({"verb": "write_staging", "files": live})
    check("staging is back to the real config",
          back.get("ok") and "sites/bpath.invalid.conf" not in live,
          "the scratch site is still staged, clean it up before applying")

    failed = results.count(False)
    print(f"\n  {len(results) - failed} passed, {failed} failed\n")
    return 1 if failed else 0


sys.exit(main())
