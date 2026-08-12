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
