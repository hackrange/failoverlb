"""
Blocking a country, and the two things that quietly went wrong doing it.

Both defects here got all the way onto a fleet, because both of them look
perfect in the rendered config and only show up in a running nginx:

  The error page.  A refusal is a 403, and a 403 with a template on it is an
  internal redirect, which nginx restarts at the server rewrite phase, which is
  where the country test lives.  So the error page request was refused as well,
  nginx will not recurse into an error page, and the visitor got the stock
  nginx page instead of the site's.  The fix is a scope map that says "skip"
  while nginx is fetching one of our own error pages.

  The caching.  A map is worked out once per request and remembered, so the
  scope map above changed nothing at all until both maps were marked volatile.
  This is the half that is easy to lose in a later edit: the config still reads
  correctly with it gone.

Everything happens on a scratch site inside a transaction that gets rolled
back, and the config is staged and tested, never applied.

    docker exec -i nginx-fleet-manager python < checks/geo_blocking.py
"""
import json
import socket
import sys

from app.core import error_pages
from app.core.render import GEOIP_DATABASE
from app.db import session_scope
from app.models import Certificate, Location, Pool, VirtualHost
from app.web.routes_api import render_current

SCRATCH = "check-geo.invalid"
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


def render_blocking(codes):
    """The whole config, with one scratch site refusing these countries."""
    with session_scope() as session:
        pool = session.query(Pool).first()
        cert = session.query(Certificate).filter(
            Certificate.not_after.isnot(None)).first()
        site = VirtualHost(
            name=SCRATCH,
            server_names=json.dumps([SCRATCH]),
            enabled=True,
            listen_http=True,
            listen_https=bool(cert),
            cert_id=cert.id if cert else None,
            mode="proxy" if pool else "static",
            pool_id=pool.id if pool else None,
            document_root=None if pool else "/var/www/site1",
            settings=json.dumps({"geoip2_country_block": codes}),
        )
        session.add(site)
        session.flush()
        session.add(Location(host_id=site.id, path="/", match_type="prefix",
                             mode="proxy" if pool else "static",
                             pool_id=pool.id if pool else None,
                             document_root=None if pool else "/var/www/site1",
                             enabled=True, sort_order=10))
        session.flush()
        try:
            files, _checksum, _snapshot = render_current(session)
        finally:
            session.rollback()
    return files


def main():
    print("\n  Country blocking\n")

    files = render_blocking(["CN", "RU"])
    maps = files.get("maps/geoip.conf", "")
    site = files.get(f"sites/{SCRATCH.replace('.', '_')}.conf", "") or "".join(
        text for path, text in files.items()
        if path.startswith("sites/") and SCRATCH in text)

    check("the lookup is written once, at the http level",
          "geoip2 " + GEOIP_DATABASE in maps, maps[:200])
    check("the site gets a map of its own and a test",
          "$nfm_geo_" in site and "return 403;" in site, site[:200])
    check("the countries asked for are in the map",
          "CN 1;" in maps and "RU 1;" in maps, maps)

    # The error page defect.  Both halves, because either one alone leaves the
    # visitor looking at nginx's stock page.
    check("the country map is keyed on the scope as well as the country",
          '"$nfm_geo_scope$nfm_geoip2_country"' in maps,
          "keyed on the country alone, so the error page is refused too")
    check("the scope map exists and knows the error page prefix",
          "map $uri $nfm_geo_scope" in maps
          and error_pages.URI_PREFIX in maps,
          "no scope map, so an internal redirect to an error page is tested again")
    check("both maps are volatile",
          maps.count("volatile;") >= 2,
          "a map is worked out once per request and remembered, so without this "
          "the scope map changes nothing and the error page is still refused")

    # A code that is not a country cannot reach the config, because nginx would
    # take some of them as a regex and the rest as nonsense.
    files = render_blocking(["CN", "not a country", "??"])
    maps = files.get("maps/geoip.conf", "")
    check("a code that is not two letters is dropped",
          "CN 1;" in maps and "not a country" not in maps and "?? 1;" not in maps,
          maps)

    # And nothing for a site that blocks nowhere.  Asked of this site's own map
    # rather than of the file, because a real site on this fleet may be
    # blocking, and then the file is there for a good reason.
    files = render_blocking([])
    mine = "$nfm_geo_" + SCRATCH.replace(".", "_").replace("-", "_")
    check("a site that blocks nowhere gets no map and no test",
          mine not in files.get("maps/geoip.conf", "")
          and not any(mine in text for path, text in files.items()
                      if path.startswith("sites/")),
          "an empty list still wrote a country test for the site")

    # Real nginx, through the agent, on the config with blocking in it.
    files = render_blocking(["CN", "RU"])
    wrote = agent({"verb": "write_staging", "files": files})
    if not wrote.get("ok"):
        check("nginx accepts the config", False, f"could not stage: {wrote.get('error')}")
    else:
        result = agent({"verb": "test_staging"}).get("data", {})
        output = (result.get("output") or "").strip()
        if "MMDB_open" in output or "GeoIP" in output:
            check("nginx accepts the config", False,
                  "no country database on this node, so nginx refuses the whole "
                  f"config: {output}")
        else:
            check("nginx accepts the config", bool(result.get("ok")), output)

    failed = results.count(False)
    print(f"\n  {len(results) - failed} passed, {failed} failed\n")
    return 1 if failed else 0


sys.exit(main())
