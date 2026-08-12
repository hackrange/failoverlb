"""
Try to write nginx config through the settings, and fail to.

Every value a person types ends up in a config file that runs as root's child.
A value that can close a directive early can add directives of its own, and the
one that matters is not a clever payload, it is somebody pasting a header value
with a semicolon in it and quietly changing what their load balancer does.

Also here: the two ways the renderer is supposed to degrade rather than take the
fleet down.  A certificate whose files have gone should cost that site its https
block and nothing else, and a pool with no backends should cost that site and
nothing else.  Both were real outages before they were behaviours.

Nothing is applied.  Scratch objects live in a transaction that is rolled back.

    docker exec -i nginx-fleet-manager python < checks/render_safety.py
"""
import json
import socket
import sys

from app.core.nginx_parser import parse
from app.core.render import esc, esc_header_value
from app.db import session_scope
from app.models import Certificate, PoolMember, VirtualHost, json_set
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"

results = []
skipped = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


def skip(name, why):
    skipped.append(name)
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
    with session_scope() as session:
        mutate(session)
        session.flush()
        try:
            files, _c, _s = render_current(session)
        finally:
            session.rollback()
    return files


# =============================================================================

print("  values that try to become config")

# The payload is not exotic on purpose.  This is what somebody pastes.
ATTEMPTS = [
    "value; root /etc",
    "value; } server { listen 9999;",
    'value" ; add_header X-Bad "1',
    "value\nadd_header X-Bad 1;",
    "value\\; escaped",
]

for attempt in ATTEMPTS:
    try:
        written = esc(attempt)
        # Getting a value back is fine as long as it cannot end the directive.
        # Quoted is safe; bare with a semicolon in it is not.
        safe = written.startswith('"') and written.endswith('"')
        check(f"esc refuses or quotes {attempt[:28]!r}", safe,
              f"wrote it bare: {written}")
    except ValueError:
        check(f"esc refuses or quotes {attempt[:28]!r}", True)

print()
print("  header values, which are allowed semicolons and nothing else")

value = esc_header_value("default-src 'self'; img-src *")
check("a policy header keeps its semicolons", "img-src" in value and value.startswith('"'),
      f"wrote {value}")

quoted = esc_header_value('he said "hello"; then left')
check("a quote inside is escaped so it cannot close the string",
      quoted.count('\\"') == 2 and quoted.startswith('"') and quoted.endswith('"'),
      f"wrote {quoted}")

for bad in ("a\nadd_header X-Bad 1", "a\rsomething"):
    try:
        esc_header_value(bad)
        check(f"a newline in a header value is refused ({bad[:12]!r})", False,
              "header injection would have been written")
    except ValueError:
        check(f"a newline in a header value is refused ({bad[:12]!r})", True)

print()
print("  a value with config in it, through the real renderer and real nginx")

with session_scope() as s:
    have_site = s.query(VirtualHost).count()

if not have_site:
    skip("a hostile setting cannot add directives",
         "no sites on this node, which is normal for a standby")
else:
    def hostile(session):
        host = session.query(VirtualHost).first()
        cfg = host.setting_map()
        cfg["content_security_policy"] = 'default-src *; } server { listen 9999; #'
        host.settings = json_set(cfg)

    try:
        files = rendered_with(hostile)

        # Structure, not a substring search.  The text "listen 9999" does appear
        # in the output, inside the quoted header value where it is harmless,
        # and searching for it called that an injection.  The question is
        # whether nginx would read it as config, so ask the parser.
        listens = []
        for path, text in files.items():
            if not path.startswith("sites/"):
                continue
            for server in parse(f"http {{\n{text}\n}}").server_blocks():
                listens += [d.arg_string() for d in server.find("listen")]

        check("the injected server block is not a server block",
              not any("9999" in listen for listen in listens),
              f"a setting created a listener: {listens}")

        header = [line.strip() for text in files.values()
                  for line in text.splitlines() if "9999" in line]
        check("the value is quoted, so it is a header and not config",
              all(line.count('"') >= 2 for line in header) if header else True,
              f"written bare: {header}")

        ok, output = nginx_accepts(files)
        check("nginx still loads the config", ok, output)
    except ValueError:
        # Refusing outright is also a correct answer, as long as it refuses.
        check("the injected server block is not a server block", True,
              "the renderer refused the value rather than writing it")
        check("the value is quoted, so it is a header and not config", True, "")
        check("nginx still loads the config", True, "nothing was written to test")

print()
print("  degrading instead of taking the fleet down")

with session_scope() as s:
    have_cert_site = s.query(VirtualHost).filter(
        VirtualHost.cert_id.isnot(None)).count()
    have_members = s.query(PoolMember).count()

if not have_cert_site:
    skip("a certificate with no files costs one site, not the fleet",
         "no site here uses a certificate")
else:
    def cert_gone(session):
        for cert in session.query(Certificate).all():
            cert.files_present = False

    files = rendered_with(cert_gone)
    text = "".join(v for k, v in files.items() if k.startswith("sites/"))
    ok, output = nginx_accepts(files)
    check("a certificate with no files still gives config nginx loads", ok, output)
    check("the https block is left out rather than pointing at nothing",
          "ssl_certificate " not in text,
          "it wrote a certificate path for files that are not there")
    check("the site says why in the file", "files are not on this node" in text,
          "the https block vanished with no explanation in the file")

if not have_members:
    skip("an empty pool costs one site, not the fleet", "no pool members here")
else:
    def members_gone(session):
        for member in session.query(PoolMember).all():
            member.enabled = False

    files = rendered_with(members_gone)
    text = "".join(v for k, v in files.items() if k.startswith("sites/"))
    ok, output = nginx_accepts(files)
    check("an empty pool still gives config nginx loads", ok, output)
    check("the site returns 503 rather than naming a missing upstream",
          "return 503;" in text, "no 503, so it is proxying to an upstream that is gone")
    check("no upstream file is written for it",
          not any(k.startswith("upstreams/") for k in files),
          f"wrote {[k for k in files if k.startswith('upstreams/')]}")

print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed"
      + (f", {len(skipped)} skipped" if skipped else ""))
print()
print("  what this does not cover:")
print("    - the catalog's own checks on the way in, which are the first gate")
print("    - raw config mode, where somebody is writing nginx config on purpose")
print()
print("  RESULT:", "nothing got written that should not be" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
