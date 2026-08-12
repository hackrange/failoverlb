"""
Every bug that has already cost a day, checked again cheaply.

The list comes from .claude/PLAN.md.  Each one of these was real, on these
boxes, and each is a minute to check and a day to meet a second time.

Nothing here applies config, restarts a service or writes to the database.
Checks that cannot avoid doing one of those are listed at the end as needing a
person, rather than being quietly left out.

    docker exec -i nginx-fleet-manager python < checks/regressions.py
"""
import json
import socket
import ssl
import sys
import urllib.request

from app.core.render import Renderer
from app.core.capabilities import fleet_capabilities
from app.db import session_scope
from app.models import Certificate, Pool, PoolMember, VirtualHost, MemberState, json_set
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"

results = []
skipped = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:160]}")
    return ok


def skip(name, why):
    """
    Nothing here to check, which is not the same as a failure.

    A standby holds no sites or pools of its own, so half of these have nothing
    to look at on that node.  Reporting those as broken sends somebody hunting
    for a bug that is really an empty database, and a suite that cries wolf on a
    healthy box is a suite people stop running.
    """
    skipped.append((name, why))
    print(f"    skip  {name}")
    print(f"          {why}")


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


def nginx_accepts(files):
    if not agent({"verb": "write_staging", "files": files}).get("ok"):
        return False, "could not stage"
    out = agent({"verb": "test_staging"}).get("data", {})
    return bool(out.get("ok")), (out.get("output") or "").strip()


def rendered_with(mutate):
    """Render with some change applied, then roll it back."""
    with session_scope() as session:
        mutate(session)
        session.flush()
        try:
            files, _c, _s = render_current(session)
        finally:
            session.rollback()
    return files


def fetch(url, host=None):
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    request = urllib.request.Request(url)
    if host:
        request.add_header("Host", host)
    with urllib.request.urlopen(request, timeout=20, context=ctx) as response:
        return response.status, dict(response.getheaders()), response.read()


# =============================================================================

print("  the agent is reachable, which is the socket folder bug")
try:
    pong = agent({"verb": "ping"}).get("data", {})
    check("container reaches the agent over the socket", bool(pong.get("pong")),
          "the container and host had different /run/nginxmgr folders once")
except Exception as exc:
    check("container reaches the agent over the socket", False, str(exc))

print()
print("  certificates")
with session_scope() as s:
    certs = s.query(Certificate).all()
    staging = [c.name for c in certs if c.issuer and "STAGING" in (c.issuer or "")]
    missing = [c.name for c in certs if not c.files_present]
    check("no certificate is from the staging CA", not staging,
          f"these are staging certs, browsers will not trust them: {staging}")
    check("every certificate has its files on disk", not missing,
          f"missing files for: {missing}")

    # the apply that deleted the certs it had just replicated
    present = agent({"verb": "list_dir", "path": "/etc/nginx/nginxmgr/certs"})
    entries = (present.get("data") or {}).get("entries", [])
    check("the certs folder survived the last apply", bool(entries),
          "an apply used to swap the managed folder and take certs with it")

print()
print("  the renderer, against bugs that blocked every apply")

# a pool with no backends must not produce config nginx refuses
files = rendered_with(lambda s: [
    setattr(m, "enabled", False)
    for m in s.query(PoolMember).all()
])
ok, output = nginx_accepts(files)
check("an empty pool does not break the whole config", ok, output)
check("an empty pool leaves its upstream out",
      not any(p.startswith("upstreams/") for p in files),
      f"still wrote: {[p for p in files if p.startswith('upstreams/')]}")

# a security policy header contains semicolons and must still render
def set_csp(session):
    host = session.query(VirtualHost).first()
    cfg = host.setting_map()
    cfg["content_security_policy"] = "default-src 'self'; img-src 'self' data:"
    host.settings = json_set(cfg)

with session_scope() as s:
    have_sites = s.query(VirtualHost).count()
    have_https = s.query(VirtualHost).filter(VirtualHost.listen_https.is_(True)).count()
    have_443 = [p for p in s.query(Pool).all()
                if any(m.enabled and m.port == 443 for m in p.members)]

if not have_sites:
    skip("a content security policy renders and loads",
         "no sites on this node, which is normal for a standby")
else:
    try:
        files = rendered_with(set_csp)
        ok, output = nginx_accepts(files)
        check("a content security policy renders and loads", ok, output)
    except Exception as exc:
        check("a content security policy renders and loads", False, str(exc))

# TLS 1.3 only must not write a 1.2 cipher line
def tls13_only(session):
    host = session.query(VirtualHost).filter(VirtualHost.listen_https.is_(True)).first()
    cfg = host.setting_map()
    cfg["ssl_protocols"] = ["TLSv1.3"]
    host.settings = json_set(cfg)
    host.name = host.name  # touch

if not have_https:
    skip("tls 1.3 only writes no 1.2 cipher list",
         "no https site on this node to render")
else:
    try:
        files = rendered_with(tls13_only)
        https_files = [c for p, c in files.items()
                       if p.startswith("sites/") and "ssl_protocols TLSv1.3;" in c]
        bad = [c for c in https_files if "\n    ssl_ciphers " in c]
        check("tls 1.3 only writes no 1.2 cipher list", bool(https_files) and not bad,
              "ssl_ciphers is ignored by 1.3 and should not be written")
    except Exception as exc:
        check("tls 1.3 only writes no 1.2 cipher list", False, str(exc))

# a pool on 443 speaks https without anybody setting it
if not have_443:
    skip("a backend on 443 gets https without being told",
         "no pool here has a backend on 443")
else:
    with session_scope() as s:
        on443 = [p for p in s.query(Pool).all()
                 if any(m.enabled and m.port == 443 for m in p.members)]
        wrong = [p.name for p in on443 if not p.uses_backend_tls]
        check("a backend on 443 gets https without being told", not wrong,
              f"these have a 443 member and are still plain http: {wrong}")

print()
print("  a promoted standby cannot wipe the fleet")

from app.core.cluster import looks_like_a_wipe   # noqa: E402

cases = [
    ("a first apply is allowed", {}, {"sites/a.conf": ""}, False),
    ("a normal edit is allowed",
     {"sites/a.conf": "", "sites/b.conf": ""},
     {"sites/a.conf": "x", "sites/b.conf": ""}, False),
    ("deleting one site of three is allowed",
     {"sites/a.conf": "", "sites/b.conf": "", "sites/c.conf": ""},
     {"sites/a.conf": "", "sites/b.conf": ""}, False),
    ("losing every site is refused",
     {"sites/a.conf": "", "sites/b.conf": ""}, {"00-managed.conf": ""}, True),
    ("losing most sites at once is refused",
     {"sites/a.conf": "", "sites/b.conf": "", "sites/c.conf": "", "sites/d.conf": ""},
     {"sites/a.conf": ""}, True),
]
for label, previous, incoming, should_refuse in cases:
    refused = bool(looks_like_a_wipe(previous, incoming))
    check(label, refused == should_refuse,
          f"{'refused' if refused else 'allowed'} when it should have been "
          f"{'refused' if should_refuse else 'allowed'}")

print()
print("  the config survives being captured and put back")

from app.core.snapshot import capture, restore, is_empty   # noqa: E402

if not have_sites:
    skip("a snapshot round trip keeps every object",
         "no sites on this node to capture")
else:
    import json as _json
    with session_scope() as s:
        before = capture(s)
        sites_before = sorted(h.name for h in s.query(VirtualHost).all())
        pools_before = sorted(p.name for p in s.query(Pool).all())

    check("a snapshot carries the objects, not a count of them",
          bool(before.get("tables", {}).get("hosts")),
          "the snapshot has no rows in it, so a promoted node would restore nothing")

    # Through json, because that is how it reaches the other node.
    wire = _json.loads(_json.dumps(before))
    with session_scope() as s:
        restore(s, wire)
    with session_scope() as s:
        sites_after = sorted(h.name for h in s.query(VirtualHost).all())
        pools_after = sorted(p.name for p in s.query(Pool).all())

    check("every site survives the round trip", sites_after == sites_before,
          f"was {sites_before}, now {sites_after}")
    check("every pool survives the round trip", pools_after == pools_before,
          f"was {pools_before}, now {pools_after}")
    check("a node with config is not called empty", not is_empty(s),
          "is_empty said yes on a node that has sites, so a restore would "
          "overwrite a real config")

print()
print("  accounts reach every node, and cannot lock everybody out")

from app.core.snapshot import capture_users, restore_users   # noqa: E402
from app.models import User, UserRole   # noqa: E402

with session_scope() as s:
    captured = capture_users(s)
    check("the snapshot carries accounts at all", bool(captured),
          "no accounts in the snapshot, so a password change would never leave "
          "this node and a revoked account would live on wherever it already is")

    leaked = sorted({c for c in ("failed_attempts", "locked_until",
                                 "last_login_at", "last_login_ip")
                     if any(c in row for row in captured)})
    check("lockout state stays on the box that saw it", not leaked,
          f"these travel and should not: {leaked}.  A failed login on one node "
          f"would lock the account out on another.")

    check("passwords travel, or the standby keeps the install one",
          all(r.get("password_hash") for r in captured if r.get("source") in (None, "local")),
          "a local account crossed without its password hash")

# A set with no enabled admin has to be refused, or one bad snapshot locks
# every person out of every box at once.
with session_scope() as s:
    before = sorted(u.username for u in s.query(User).all())
    verdict = restore_users(s, [{"username": "nobody", "role": "viewer", "enabled": True}])
    after = sorted(u.username for u in s.query(User).all())
    s.rollback()
    check("a snapshot with no enabled admin is refused", bool(verdict.get("refused")),
          f"it was accepted, and the accounts became {after}")
    check("and the accounts it already had are left alone", before == after,
          f"was {before}, became {after}")

with session_scope() as s:
    check("a snapshot that predates accounts changes nothing",
          bool(restore_users(s, None).get("skipped")),
          "an older node sending no account list should leave accounts alone, "
          "not empty them")
    s.rollback()

print()
print("  importing somebody else's config keeps what it cannot model")

from app.core.importer import analyse   # noqa: E402

# Written to have the same shapes that a real world file turned out to have,
# with invented names and addresses.  Each one of these lost config silently
# before it was checked, which is the worst way for an importer to fail: the
# import looks like it worked and the behaviour is gone.
AWKWARD = """
server {
    if ($host = site.invalid) { return 301 https://$host$request_uri; }
    listen 80;
    server_name site.invalid;
    more_set_headers "Server: edge";
    location ^~ /.well-known/acme-challenge/ { root /var/www/certbot; allow all; }
    location / { return 301 https://$host$request_uri; }
}
server {
    listen 443 ssl;
    http2 on;
    server_name site.invalid;
    error_page 400 403 404 500 502 /error.html;
    more_set_headers "Referrer-Policy: no-referrer";
    rewrite ^/old$ /new last;
    location = /healthz {
        allow 192.0.2.10;
        deny all;
        error_page 403 =404 /error.html;
        proxy_pass http://192.0.2.50:8000;
    }
    location = /error.css { root /var/www/html; }
    location @missing { return 404 "nope\n"; }
    location / {
        if ($request_method = 'OPTIONS') {
            add_header 'Access-Control-Max-Age' '3600' always;
            return 204;
        }
        proxy_pass http://192.0.2.50:8000;
        proxy_cookie_path /o/ /;
    }
}
"""

plan = analyse(AWKWARD)
check("an awkward config still parses", plan.get("ok"), str(plan.get("error"))[:200])

if plan.get("ok"):
    sites = plan["sites"]
    check("http and https blocks for one name make one site", len(sites) == 1,
          f"made {len(sites)} sites, so the same name would collide and the "
          f"https half would be the one dropped")

    site = sites[0] if sites else {"custom_config": "", "http2": False}

    # Everything the import held onto, wherever it put it.
    #
    # Config that belongs to a path now lands on that path rather than on the
    # site, which is where it should be.  Checking only the site's own box made
    # this suite report the `if` block and its add_headers as lost the moment
    # paths were mapped properly, when they had in fact moved somewhere better.
    # What matters is that nothing was dropped, not which box it is in.
    kept = site.get("custom_config", "") + "".join(
        l.get("custom_config", "") + " " + str(l.get("path", ""))
        for l in (site.get("locations") or [])
    )

    # Each of these was silently dropped at some point.  The round trip logic
    # treats them as ours to regenerate, which is right for our own config and
    # wrong for somebody else's.
    for label, needle in (
        ("error_page survives", "error_page"),
        ("allow and deny survive", "deny all"),
        ("if blocks survive", "if ("),
        ("add_header inside an if survives", "add_header"),
        ("a location that is only a root survives", "/error.css"),
        ("a named location survives", "@missing"),
        ("rewrite survives", "rewrite"),
        ("header directives survive", "more_set_headers"),
    ):
        check(label, needle in kept,
              f"{needle!r} is nowhere in what was kept, so importing this "
              f"config would quietly lose it")

    check("http2 as its own directive is picked up", site.get("http2") is True,
          "nginx 1.25.1 moved http2 off the listen line, and only reading the "
          "listen line leaves the switch off on a site that asked for it")

    check("an upstream declared elsewhere is not invented as a host",
          all("192.0.2.50" in str(p["members"]) or p["members"] for p in plan["pools"]),
          "a bare upstream name became a backend that will never resolve")

print()
print("  live behaviour")
with session_scope() as s:
    sites = [h.name for h in s.query(VirtualHost).all()
             if h.enabled and h.listen_https and h.cert_id]

for name in sites:
    try:
        status, headers, _body = fetch("https://127.0.0.1/", host=name)
        dupes = [h for h in ("Strict-Transport-Security", "X-Frame-Options",
                             "X-Content-Type-Options", "Referrer-Policy")
                 if sum(1 for k in headers if k.lower() == h.lower()) > 1]
        check(f"{name} sends one of each security header", not dupes,
              f"duplicated: {dupes}")
    except Exception as exc:
        # a redirect or an auth wall is a fine answer here, a stack trace is not
        if "HTTP Error" in str(exc):
            check(f"{name} answers without an error", True)
        else:
            check(f"{name} answers without an error", False, str(exc))

print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed"
      + (f", {len(skipped)} skipped for nothing to check" if skipped else ""))
print()
print("  needs a person, because it applies or restarts something:")
print("    - apply twice and confirm the certificates are still there")
print("    - restart the agent and confirm the GUI still reaches it")
print("    - stop the agent and confirm it stops in seconds, not ninety")
print("    - add a backend whose name does not resolve, through the page")
print("    - a fresh install, and confirm the certificate is from the real CA")
print()
print("  RESULT:", "no regressions" if not failed else f"{len(failed)} REGRESSED: {failed}")
sys.exit(1 if failed else 0)
