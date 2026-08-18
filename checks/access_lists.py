"""
An access list has to reach the plain http server, not only the https one.

`_render_body` writes the allow and deny rules, and both server blocks call it,
but only the https call passed the access list along.  The http call left the
argument out, so it defaulted to None and the rules were silently dropped from
port 80.

What that looked like on a real fleet: the site's page listed the rules, the
rendered config showed them, `nginx -t` passed, and the site answered anybody
who asked for it over http.  On a site with no certificate, which is every site
while somebody is still setting it up, http is the only way in and the whole
list was doing nothing at all.  Found by asking for the site from two different
source addresses instead of reading the config.

Two things came out of fixing it that are easy to get wrong in the other
direction, so they are checked here too:

  The certificate challenge must stay reachable.  Server level allow and deny
  apply to every location under them, so a site that allows one office would
  otherwise refuse the certificate authority and lose the ability to renew.

  Management only sites already worked on http, because that path reads the
  host rather than the access list.  The fix must not make those rules appear
  twice.

Nothing is applied and nothing is written.  Scratch objects live in a
transaction that is rolled back, the same as render_safety.py.

    docker exec -i nginx-fleet-manager python < checks/access_lists.py
"""
import json
import socket
import sys

from app.db import session_scope
from app.models import AccessList, VirtualHost
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"

ALLOWED = "203.0.113.7/32"
PROXY = "198.51.100.9/32"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {str(detail)[:300]}")
    return ok


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


def rules(block):
    """
    Only the access control lines out of a block, for the failure message.

    Printing the surrounding config instead would put whoever's backend
    addresses and hostnames this box is really carrying into the terminal, and
    from there into whatever somebody pastes into a ticket.  The lines this
    check is about are the only ones it needs to show.
    """
    keep = ("allow ", "deny ", "auth_basic", "set_real_ip_from", "real_ip_header",
            "real_ip_recursive", "return 301", "location ^~ /.well-known")
    found = [l for l in block.splitlines() if l.strip().startswith(keep)]
    return "\n".join(found) or "[no access control lines in that block at all]"


def http_block(text):
    """
    Just the plain http server out of a site's config file.

    Split on the listen line rather than by counting braces, because the point
    of every check here is which of the two blocks a line landed in, and a
    whole file search cannot tell them apart.  A file with no https block at
    all still gives the right answer.
    """
    blocks = []
    current = []
    for line in text.splitlines():
        if line.startswith("server {"):
            if current:
                blocks.append("\n".join(current))
            current = [line]
        elif current:
            current.append(line)
    if current:
        blocks.append("\n".join(current))
    for block in blocks:
        if "listen 443" not in block and "listen 80" in block:
            return block
    return ""


def rendered_with(mutate):
    with session_scope() as session:
        mutate(session)
        session.flush()
        try:
            files, _c, _s = render_current(session)
        finally:
            session.rollback()
    return files


def scratch_acl(session, **fields):
    acl = AccessList(
        name="check-scratch-access-list",
        allow_entries=json.dumps([ALLOWED]),
        deny_entries="[]",
        default_action="deny",
        include_management=False,
        basic_auth_enabled=False,
        use_real_ip=False,
        real_ip_from="[]",
    )
    for key, value in fields.items():
        setattr(acl, key, value)
    session.add(acl)
    session.flush()
    return acl


def a_site(session, **fields):
    """
    A site that really exists on this box, borrowed for the length of a
    transaction.  Rendering against a made up site would prove the renderer
    works on made up sites.
    """
    host = (session.query(VirtualHost)
            .filter(VirtualHost.enabled.is_(True))
            .order_by(VirtualHost.id)
            .first())
    if host is None:
        return None
    for key, value in fields.items():
        setattr(host, key, value)
    return host


print("\n  an access list on the plain http server\n")

with session_scope() as probe_session:
    first = (probe_session.query(VirtualHost)
             .filter(VirtualHost.enabled.is_(True))
             .order_by(VirtualHost.id).first())
    if first is None:
        print("    there are no sites on this box, so this check cannot run")
        sys.exit(0)
    SITE = first.name
    FILE = f"sites/{SITE}.conf"

print(f"    borrowing {SITE} for the length of a rolled back transaction")


# ---- the defect itself -----------------------------------------------------

def plain_http(session):
    acl = scratch_acl(session)
    host = a_site(session, access_list_id=acl.id, force_https=False,
                  listen_http=True)
    host.access_list_id = acl.id


files = rendered_with(plain_http)
block = http_block(files.get(FILE, ""))
check("there is a plain http server block to look at", bool(block),
      list(files)[:5])
check("the http block carries the allow rule", f"allow {ALLOWED};" in block, rules(block))
check("and denies what is not matched", "\n    deny all;" in block, rules(block))
check("the rules are at server level, not buried in a location",
      block.count(f"allow {ALLOWED};") == 1
      and not block.split(f"allow {ALLOWED};")[0].rstrip().endswith("{"),
      rules(block))


# ---- the thing the fix must not break --------------------------------------

check("the certificate challenge stays open to everybody",
      "location ^~ /.well-known/acme-challenge/" in block
      and "allow all;" in block.split("location ^~ /.well-known/acme-challenge/")[1][:400],
      rules(block))


# ---- basic auth travels with it --------------------------------------------

def with_password(session):
    acl = scratch_acl(session, basic_auth_enabled=True,
                      basic_auth_users=json.dumps([{"username": "u", "hash": "x"}]))
    a_site(session, access_list_id=acl.id, force_https=False, listen_http=True)


block = http_block(rendered_with(with_password).get(FILE, ""))
check("a password on the list reaches http too", "auth_basic " in block, rules(block))
check("and names the password file", "auth_basic_user_file" in block, rules(block))


# ---- the forwarded address settings ----------------------------------------

def with_real_ip(session):
    acl = scratch_acl(session, use_real_ip=True,
                      real_ip_header="X-Forwarded-For",
                      real_ip_from=json.dumps([PROXY]))
    a_site(session, access_list_id=acl.id, force_https=False, listen_http=True)


block = http_block(rendered_with(with_real_ip).get(FILE, ""))
check("the trusted proxy reaches http too", f"set_real_ip_from {PROXY};" in block,
      rules(block))
check("with the header it reads", "real_ip_header X-Forwarded-For;" in block, rules(block))
check("and the chain read from our end", "real_ip_recursive on;" in block, rules(block))


# ---- a redirect only block is still a block --------------------------------

def redirecting(session):
    acl = scratch_acl(session)
    host = a_site(session, access_list_id=acl.id, force_https=True,
                  listen_http=True, listen_https=True)
    return host


files = rendered_with(redirecting)
block = http_block(files.get(FILE, ""))
if "return 301 https://" in block:
    check("a redirect only http block still applies the rules",
          f"allow {ALLOWED};" in block, rules(block))
    check("and refuses before saying where the site really is",
          block.find(f"allow {ALLOWED};") < block.find("return 301 https://"),
          rules(block))
else:
    check("a redirect only http block still applies the rules", True,
          "this site has no certificate, so http serves rather than redirects")
    check("and refuses before saying where the site really is", True, "not applicable")


# ---- management only sites must not double up ------------------------------

def management_only(session):
    a_site(session, access_list_id=None, admin_only=True, force_https=False,
           listen_http=True)


block = http_block(rendered_with(management_only).get(FILE, ""))
check("a management only site still denies the rest on http",
      "\n    deny all;" in block, rules(block))
check("and its allow lines are written once, not twice",
      max([block.count(line) for line in
           {l.strip() for l in block.splitlines() if l.strip().startswith("allow ")}]
          or [1]) == 1,
      "\n".join(l for l in block.splitlines() if "allow " in l))


# ---- and nginx has to accept the result ------------------------------------

print()
print("  and real nginx has to load it")

files = rendered_with(with_real_ip)
staged = agent({"verb": "write_staging", "files": files})
if not staged.get("ok"):
    check("the config could be staged", False, staged)
else:
    out = agent({"verb": "test_staging"}).get("data", {})
    check("nginx loads a config with an access list on the http block",
          bool(out.get("ok")), (out.get("output") or "").strip())

# Put the real config back in staging, or the next person to look at the
# staged directory finds this check's leftovers.
with session_scope() as session:
    real, _c, _s = render_current(session)
agent({"verb": "write_staging", "files": real})

failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: an access list reaches both server blocks ({len(results)} checks)\n")
