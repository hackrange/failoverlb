"""
Every bug that has already cost a day, checked again cheaply.

The list comes from the project notes.  Each one of these was real, on these
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

import datetime as _dt

from cryptography import x509 as _x509
from cryptography.hazmat.primitives import hashes as _hashes
from cryptography.hazmat.primitives import serialization as _ser
from cryptography.hazmat.primitives.asymmetric import rsa as _rsa
from cryptography.x509.oid import NameOID as _NameOID

# Imported under another name: this file already uses `certs` for a list of
# rows further down, and the shadowing turns every call here into an
# AttributeError on a list.
from app.core import certs as cert_tools
from app.core import error_pages
from app.core import hostnames
from app.core.render import Renderer
from app.core.capabilities import fleet_capabilities
from app.db import session_scope
from app.models import (
    CacheZone, Certificate, ConnLimitZone, ErrorPageImage, ErrorPageTemplate,
    Location, MapBlock, MemberState, Pool, PoolMember, StreamServer,
    VirtualHost, json_set,
)
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

# Every config table has to be in the snapshot, and this is checked by walking
# the models rather than by listing them here, because a list here would have
# the same hole as the one it is checking.
#
# The hole is easy to make and quiet.  The GSLB tables were added, the feature
# worked perfectly on the node it was built on, and the zones were in no
# snapshot at all: they never reached the standby and were in no backup.  For a
# failover feature that means the spare nameserver answers nothing, which is
# discovered at the one moment it was supposed to help.
#
# Anything deliberately kept off a snapshot goes in the set below with a reason
# next to it, so leaving a table out stays a decision rather than an oversight.
NOT_REPLICATED = {
    # The fleet's own bookkeeping.  Each box keeps its own view of who is in
    # the cluster and what it has applied, and copying one node's view onto
    # another is how two boxes end up disagreeing about which of them is which.
    "Node", "JoinToken", "ConfigVersion", "PendingChange",
    # Written where it happened and read there.  An audit log that travelled
    # would say a thing was done on a box that never did it.
    "AuditLog", "HealthEvent", "Session",
    # Per box on purpose: ports, addresses, and the rest of the local install.
    "SystemSetting",
    # Users do travel, through their own path, so that the per box columns like
    # lockout state stay on the box that saw the failed logins.
    "User",
}

from app.core.snapshot import TABLES as _SNAP_TABLES
from app import models as _models
from app.models import Base as _Base

_covered = {model.__name__ for _key, model in _SNAP_TABLES}
_missing = sorted(
    name for name, obj in vars(_models).items()
    if isinstance(obj, type) and issubclass(obj, _Base) and obj is not _Base
    and getattr(obj, "__tablename__", None)
    and name not in _covered and name not in NOT_REPLICATED
)
# A snapshot from an older node must not delete what it has never heard of.
# This is the rolling upgrade case: for the whole length of an upgrade, one box
# is sending snapshots that are missing whatever the newer box just learned
# about, and the newer box used to empty those tables and report success.
if not have_sites:
    skip("an older snapshot leaves unknown tables alone", "no sites on this node")
else:
    with session_scope() as s:
        full = _json.loads(_json.dumps(capture(s)))

    older = _json.loads(_json.dumps(full))
    dropped = older["tables"].pop("pools", None)
    kept_before = len(full["tables"].get("pools") or [])

    with session_scope() as s:
        restore(s, older)
    with session_scope() as s:
        kept_after = s.query(Pool).count()

    check("a snapshot that omits a table does not empty it",
          kept_before == 0 or kept_after == kept_before,
          f"had {kept_before} pools, an older snapshot that never mentioned "
          f"them left {kept_after}.  A rolling upgrade would delete config.")

    # Put the real one back so the rest of the run sees the node it started on.
    with session_scope() as s:
        restore(s, full)

# Replicated config must not identify a node by its id.
#
# Node rows are deliberately per box, so the ids only mean something in the
# database that issued them.  A config row that travels and carries a node id
# points at whatever the receiving box happens to have under that number, which
# is a different machine.  On two nodes the mappings come out as exact mirror
# images.
#
# That cost a DNS failover its whole purpose: the surviving node dropped itself
# from the answer and kept handing out the address of the box that was down,
# and it could only ever show up during the failure it exists to handle.
#
# The rule is not "never reference a node".  It is that anything referencing
# one has to carry the name too, because that means the same thing everywhere.
_by_id = []
for _key, _model in _SNAP_TABLES:
    for _col in _model.__table__.columns:
        if not any(str(fk.column) == "nodes.id" for fk in _col.foreign_keys):
            continue
        if "node_name" not in _model.__table__.columns:
            _by_id.append(f"{_model.__name__}.{_col.name}")

check("replicated config identifies nodes by name, not id", not _by_id,
      f"{', '.join(_by_id)} points at a node by id on a row that travels "
      f"between nodes.  That id is a different machine on every other box.  "
      f"Add a node_name column and match on that.")

check("every config table is in the snapshot", not _missing,
      f"{', '.join(_missing)} would not reach a standby and would not be in a "
      f"backup.  Add it to TABLES in snapshot.py, or to NOT_REPLICATED in this "
      f"check with the reason it stays on one box.")

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
print("  two objects cannot end up sharing a name")
# Renaming used to skip the uniqueness check that creating has always had, and
# the result was silent rather than loud: the render keys its files by name, so
# the second pool written wins and the first one's upstream is simply not in the
# config.  nginx loads fine, the apply succeeds, and a site pointed at the pool
# that lost sends its traffic to the other pool's backends.


def _pool(name, address):
    p = Pool(name=name, lb_method="round_robin")
    p.members = [PoolMember(address=address, port=8080, enabled=True, admin_state="up")]
    return p


files = Renderer().render_all(
    [], [_pool("dup_check", "192.0.2.10"), _pool("dup_check", "192.0.2.11")],
    [], [], [], [], [], [], [])
upstreams = [k for k in files if k.startswith("upstreams/")]
check("two pools with one name render as one file, which is why it is refused",
      len(upstreams) == 1,
      "if this ever renders two files the reasoning behind claim_name has "
      "changed and the check below needs rewriting, not deleting")

# The rule itself, rather than the damage it prevents.  claim_name compares the
# rendered form of the name, so it also catches two pools that differ only by a
# separator: sticky sessions turn both into the same $sticky_ variable.
from app.web.routes_api import claim_name  # noqa: E402


class _FakeQuery:
    def __init__(self, rows):
        self.rows = rows

    def all(self):
        return self.rows


class _FakeSession:
    def __init__(self, rows):
        self.rows = rows

    def query(self, _model):
        return _FakeQuery(self.rows)


class _Row:
    def __init__(self, row_id, name):
        self.id = row_id
        self.name = name


existing = _FakeSession([_Row(1, "shop-eu"), _Row(2, "other")])


def _refused(name, exclude_id=None):
    try:
        claim_name(existing, Pool, name, "pool", exclude_id=exclude_id)
        return False
    except Exception:
        return True


check("renaming a pool onto another pool's name is refused",
      _refused("shop-eu", exclude_id=2),
      "a rename onto a name in use redirects traffic silently, so it has to be "
      "a 409 and not a surprise")

check("a name that differs only by a separator is refused",
      _refused("shop_eu", exclude_id=2),
      "shop-eu and shop_eu are two rows and one $sticky_shop_eu, so one pool "
      "would route on the other one's cookie")

check("a pool keeping its own name is not refused",
      not _refused("shop-eu", exclude_id=1),
      "saving a pool without touching the name must not trip the check on itself")

check("an unused name is allowed",
      not _refused("shop-us", exclude_id=2),
      "the check has gone from catching collisions to refusing everything")

# nginx has one list of shared memory zones for the whole http block, so a rate
# limit zone and a connection limit zone with the same name is one name declared
# twice for different uses.  nginx refuses it, on every node, which means the
# whole fleet can apply nothing until somebody finds the pair.
zone_rows = _FakeSession([_Row(1, "api_limit")])


def _zone_refused(model, name):
    try:
        claim_name(zone_rows, model, name, "zone")
        return False
    except Exception:
        return True


check("a connection zone cannot take a rate zone's name",
      _zone_refused(ConnLimitZone, "api_limit"),
      "the two share nginx's shared memory namespace, so this pair blocks every "
      "apply on every node until one of them is renamed")

check("a cache zone cannot take a rate zone's name",
      _zone_refused(CacheZone, "api_limit"),
      "same namespace again, and the same fleet wide block")

check("a zone name nothing is using is allowed",
      not _zone_refused(ConnLimitZone, "api_burst"),
      "checking across the kinds must not turn into refusing every zone name")

def _refuses_image(raw):
    try:
        error_pages.sniff_image(raw, "upload")
        return False
    except error_pages.ErrorPageProblem:
        return True


print()
print("  custom error pages")
# Two things here cost real time to find and neither is visible in the code.
#
# nginx answers 403 when it cannot *read* the file an error_page points at, and
# it throws the real status away doing it, so a 502 from a dead backend becomes
# a 403 about nothing.  Everything else we stage is 0640 root because the nginx
# master reads it while it is still root, but these are read by a worker after
# it has dropped to www-data.  A missing page is fine, nginx falls back to its
# own and keeps the status.  Only an unreadable one lies.
#
# And a template with a status code nginx will not take used to throw out of
# the render, which stops every unrelated change on every node.


def _template(name, codes, body=None, image=None):
    t = ErrorPageTemplate(
        name=name,
        html=body if body is not None else error_pages.starter_html(),
        codes=json_set(codes),
    )
    t.images = [image] if image else []
    return t


_logo = ErrorPageImage(
    name="logo", content_type="image/png", size_bytes=68,
    data=("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGA"
          "hKmMIQAAAABJRU5ErkJggg=="))

_tpl = _template("regress-style", [404, 502],
                 '<h1>{{code}} {{message}}</h1><p>{{explain}}</p>'
                 '<img src="{{image:logo}}">', _logo)
_tpl.id = 901

_ep_pool = Pool(name="regress_ep_pool", lb_method="round_robin")
_ep_pool.id = 901
_ep_pool.members = [PoolMember(address="192.0.2.10", port=8080,
                               enabled=True, admin_state="up")]

_ep_host = VirtualHost(name="ep.invalid", enabled=True, server_names='["ep.invalid"]',
                       listen_http=True, listen_https=False, force_https=False,
                       mode="proxy", settings="{}")
_ep_host.id = 901
_ep_host.pool_id = 901
_ep_host.pool = _ep_pool
_ep_host.error_page_template_id = 901

_files = Renderer().render_all([_ep_host], [_ep_pool], [], [], [], [], [], [], [],
                               error_templates=[_tpl])
_conf = _files.get("sites/ep.invalid.conf", "")
_page = _files.get("errorpages/regress-style/502.html", "")

check("the pages are staged under errorpages, which the agent writes 0644",
      all(p.startswith("errorpages/") for p in _files if p.endswith(".html")),
      "the agent decides the mode from the first path segment, so a page "
      "written anywhere else comes out root only and nginx answers 403 "
      "instead of the status it meant to send")

check("the code is in the page before nginx ever sees it",
      "502" in _page and "Bad Gateway" in _page and "{{" not in _page,
      "nothing substitutes at request time, so an unswapped placeholder is a "
      "placeholder the visitor reads")

check("pictures are inlined rather than fetched",
      "data:image/png;base64," in _page,
      "an error page that has to fetch something can be broken at exactly the "
      "moment the site is already in trouble")

check("the page location is internal", "        internal;" in _conf,
      "without it anybody can fetch the 500 page off a site that is perfectly "
      "well, and it is a prefix match so it is reachable by name")

check("nothing but reading a file happens in that location",
      "proxy_pass" not in _conf.split("__nfm_error/ {")[-1].split("}")[0],
      "it is served from a location that must not be able to see the rest of "
      "the config")

_broken = _template("regress-broken", [99])
_broken.id = 902
_broken_host = VirtualHost(name="broken.invalid", enabled=True,
                           server_names='["broken.invalid"]', listen_http=True,
                           listen_https=False, force_https=False, mode="proxy",
                           settings="{}")
_broken_host.id = 902
_broken_host.pool_id = 901
_broken_host.pool = _ep_pool
_broken_host.error_page_template_id = 902

try:
    _files2 = Renderer().render_all([_ep_host, _broken_host], [_ep_pool], [], [], [],
                                    [], [], [], [],
                                    error_templates=[_tpl, _broken])
    _survived = ("sites/ep.invalid.conf" in _files2
                 and "sites/broken.invalid.conf" in _files2)
except Exception as exc:
    _survived = False
    _files2 = {}

check("a template that cannot render does not stop every other change",
      _survived,
      "this threw out of the render once, which blocks the whole fleet until "
      "somebody works out which template is at fault")

check("the site using the bad template just gets no error page lines",
      "__nfm_error" not in _files2.get("sites/broken.invalid.conf", "__nfm_error"),
      "a site pointing at a broken template has to fall back to the stock "
      "pages, not carry directives to files that were never written")

_unused = _template("regress-unused", [404])
_unused.id = 903
_files3 = Renderer().render_all([_ep_host], [_ep_pool], [], [], [], [], [], [], [],
                                error_templates=[_tpl, _unused])
check("a template nothing points at is not written out",
      not any(p.startswith("errorpages/regress-unused/") for p in _files3),
      "a half finished page would otherwise land in the live config on every "
      "node and grow the bundle for no reason")

check("an upload that is not a picture is refused",
      _refuses_image(b"this is plain text"),
      "the check is on the file's own first bytes, because what the browser "
      "said it was is only the name the uploader typed")

check("an SVG with script in it is refused",
      _refuses_image(b'<svg xmlns="http://www.w3.org/2000/svg"><script>x</script></svg>'),
      "a browser will not run it inside an img tag, but the same file dropped "
      "into a page later would, and the upload cannot know which it will be")

check("a real PNG is accepted",
      not _refuses_image(b"\x89PNG\r\n\x1a\n" + b"rest of a png"),
      "the sniffing has gone from catching fakes to refusing everything")

# A path can have a different error page from the rest of its site, and nginx
# has a rule here that catches everybody: error_page is inherited from the
# server into a location only when the location has none of its own, and a
# single rule in a location throws away every inherited one.  So a path with a
# small template inside a site with a bigger one would silently serve the stock
# pages for every code the small one did not cover.  Confirmed against real
# nginx before the renderer was written to work around it.
_site_tpl = _template("regress-site", [404, 500, 502], "<p>{{code}} SITE</p>")
_site_tpl.id = 911
_path_tpl = _template("regress-path", [404], "<p>{{code}} PATH</p>")
_path_tpl.id = 912

_loc_host = VirtualHost(name="paths.invalid", enabled=True,
                        server_names='["paths.invalid"]', listen_http=True,
                        listen_https=False, force_https=False, mode="proxy",
                        settings="{}")
_loc_host.id = 911
_loc_host.pool_id = 901
_loc_host.pool = _ep_pool
_loc_host.error_page_template_id = 911

_api_loc = Location(path="/api/", match_type="prefix", mode="proxy",
                    sort_order=10, enabled=True, settings="{}")
_api_loc.id = 911
_api_loc.pool_id = 901
_api_loc.pool = _ep_pool
_api_loc.error_page_template_id = 912

_plain_loc = Location(path="/", match_type="prefix", mode="proxy",
                      sort_order=20, enabled=True, settings="{}")
_plain_loc.id = 912
_plain_loc.pool_id = 901
_plain_loc.pool = _ep_pool

_loc_host.locations = [_api_loc, _plain_loc]

_lfiles = Renderer().render_all([_loc_host], [_ep_pool], [], [], [], [], [], [], [],
                                error_templates=[_site_tpl, _path_tpl])
_lconf = _lfiles.get("sites/paths.invalid.conf", "")
_api_block = _lconf.split("location /api/ {")[-1].split("\n    }")[0]

check("a path can point at a different template from its site",
      "error_page 404 /__nfm_error/regress-path/404.html;" in _api_block,
      "the path's own template has to win for the codes it covers")

check("the site's rules are written back in for codes the path does not cover",
      "error_page 502 /__nfm_error/regress-site/502.html;" in _api_block,
      "nginx throws away every inherited error_page as soon as a location has "
      "one of its own, so leaving these out means that path silently serves "
      "the stock page for every other code")

check("each template gets its own block to be served from",
      ("location ^~ /__nfm_error/regress-site/ {" in _lconf
       and "location ^~ /__nfm_error/regress-path/ {" in _lconf),
      "one shared prefix would mean the second template was never reachable")

check("a path with its own template gets interception turned on",
      "proxy_intercept_errors on;" in _api_block,
      "without it the backend's own error goes straight through and the "
      "template on that path is never reached")

check("both templates are written out when a path uses the second one",
      ("errorpages/regress-path/404.html" in _lfiles
       and "errorpages/regress-site/502.html" in _lfiles),
      "only collecting the templates sites point at leaves a path pointing at "
      "directives with no files behind them")

check("a path with no template of its own writes no error_page lines",
      "error_page" not in _lconf.split("location / {")[-1].split("\n    }")[0],
      "it has to inherit the server block's, which is nginx's own behaviour "
      "and the reason the plain case needs nothing written at all")

print()
print("  certificates that did not come from Lets Encrypt")
# The pair check is the whole feature.  A key and a certificate that are not a
# pair is a documented trap here that crash looped the process twice, and nginx
# loads a mismatched pair without a word and then fails every handshake, so the
# only place it can be caught is before anything is stored.


def _mk_cert(cn, issuer_key=None, issuer=None, ca=True, sans=None, days=400):
    key = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = _x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, cn)])
    now = _dt.datetime.now(_dt.timezone.utc)
    builder = (_x509.CertificateBuilder().subject_name(subject)
               .issuer_name(issuer or subject)
               .public_key(key.public_key())
               .serial_number(_x509.random_serial_number())
               .not_valid_before(now - _dt.timedelta(days=1))
               .not_valid_after(now + _dt.timedelta(days=days))
               .add_extension(_x509.BasicConstraints(ca=ca, path_length=None), True))
    if sans:
        builder = builder.add_extension(
            _x509.SubjectAlternativeName([_x509.DNSName(n) for n in sans]), False)
    return key, builder.sign(issuer_key or key, _hashes.SHA256())


def _pem(cert):
    return cert.public_bytes(_ser.Encoding.PEM).decode()


def _keypem(key):
    return key.private_bytes(_ser.Encoding.PEM, _ser.PrivateFormat.PKCS8,
                             _ser.NoEncryption()).decode()


_root_k, _root_c = _mk_cert("Regress Root")
_int_k, _int_c = _mk_cert("Regress Intermediate", issuer_key=_root_k, issuer=_root_c.subject)
_leaf_k, _leaf_c = _mk_cert("leaf.invalid", issuer_key=_int_k, issuer=_int_c.subject,
                            ca=False, sans=["leaf.invalid", "www.leaf.invalid"])


def _upload_refused(cert_pem, key_pem):
    try:
        cert_tools.analyse_upload(cert_data=cert_pem, key_data=key_pem)
        return False
    except cert_tools.CertProblem:
        return True


check("a key that does not match the certificate is refused",
      _upload_refused(_pem(_leaf_c), _keypem(_int_k)),
      "nginx loads a mismatched pair without complaining and then fails every "
      "handshake, so this is the only place it can be caught")

check("a matching pair is accepted",
      not _upload_refused(_pem(_leaf_c), _keypem(_leaf_k)),
      "the pair check has gone from catching mismatches to refusing everything")

# Handed over root first, which plenty of tools write.
_bundle = cert_tools.analyse_upload(
    cert_data=_pem(_root_c) + _pem(_int_c) + _pem(_leaf_c),
    key_data=_keypem(_leaf_k))

check("the leaf is found even when the bundle is written root first",
      _bundle["domains"] == ["leaf.invalid", "www.leaf.invalid"],
      "taking the first certificate in the file is right most of the time and "
      "wrong often enough to matter")

check("the chain comes out leaf first",
      _bundle["fullchain"].index(_pem(_leaf_c)) == 0,
      "a chain in the wrong order works on some clients and fails on others, "
      "which is a miserable thing to debug from the outside")

check("the self signed root is left out of the chain",
      _pem(_root_c) not in _bundle["fullchain"] and _bundle["chain_length"] == 2,
      "sending the root costs bytes on every handshake and helps nobody, since "
      "a client that trusts it already has it")

# Both dates in the past, since a certificate cannot end before it starts.
_expired_k = _rsa.generate_private_key(public_exponent=65537, key_size=2048)
_then = _dt.datetime.now(_dt.timezone.utc)
_expired_c = (
    _x509.CertificateBuilder()
    .subject_name(_x509.Name([_x509.NameAttribute(_NameOID.COMMON_NAME, "old.invalid")]))
    .issuer_name(_int_c.subject)
    .public_key(_expired_k.public_key())
    .serial_number(_x509.random_serial_number())
    .not_valid_before(_then - _dt.timedelta(days=400))
    .not_valid_after(_then - _dt.timedelta(days=5))
    .add_extension(_x509.SubjectAlternativeName([_x509.DNSName("old.invalid")]), False)
    .sign(_int_k, _hashes.SHA256()))
_expired = cert_tools.analyse_upload(cert_data=_pem(_expired_c), key_data=_keypem(_expired_k))
check("an expired certificate is stored but said out loud",
      any("expired" in w for w in _expired["warnings"]),
      "refusing it outright would stop somebody staging a replacement, and "
      "saying nothing would let it go live")

_solo = cert_tools.analyse_upload(cert_data=_pem(_leaf_c), key_data=_keypem(_leaf_k))
check("a leaf with no intermediates warns about the chain",
      any("intermediate" in w for w in _solo["warnings"]),
      "some clients keep a copy and are fine, others refuse the site outright, "
      "which is the worst way for this to be discovered")

_ss = cert_tools.self_signed(["self.invalid", "192.0.2.7"], key_type="ecdsa")
check("a self signed certificate carries its names as SANs",
      set(_ss["domains"]) == {"self.invalid", "192.0.2.7"},
      "every client stopped reading the common name years ago, so a "
      "certificate with names only there is one nothing will accept")
check("a self signed certificate is honest about what it is",
      _ss["self_signed"] and any("browsers will warn" in w for w in _ss["warnings"]),
      "this is the one people reach for in a hurry and then leave in place")

for _size in (2048, 4096):
    _req = cert_tools.make_csr(["req.invalid"], key_size=_size)
    _parsed = _x509.load_pem_x509_csr(_req["csr"].encode())
    check(f"a signing request at {_size} is valid and asks for the right names",
          _parsed.is_signature_valid
          and [n.value for n in _parsed.extensions.get_extension_for_class(
              _x509.SubjectAlternativeName).value] == ["req.invalid"],
          "an authority refuses a request it cannot verify, and a request with "
          "no SANs produces a certificate nothing modern accepts")

try:
    cert_tools.make_csr(["req.invalid"], key_size=1024)
    _weak_refused = False
except cert_tools.CertProblem:
    _weak_refused = True
check("a key length no authority will sign is refused up front",
      _weak_refused,
      "finding out months later that the request cannot be issued is the whole "
      "cost of not checking here")

# A row waiting on an authority holds a key and no certificate.  It must not
# reach the renderer, because a config pointing at a certificate that does not
# exist yet is a config nginx will not load, and then nothing can be applied
# anywhere.
_waiting = Certificate(name="waiting.invalid", domains=json_set(["waiting.invalid"]),
                       source="uploaded", csr_pem="-----BEGIN CERTIFICATE REQUEST-----")
check("a certificate still waiting on an authority is not usable",
      not _waiting.usable and not _waiting.has_material(),
      "the renderer would otherwise point nginx at files nobody has written, "
      "and one of those stops every apply on every node")

_ready = Certificate(name="ready.invalid", domains=json_set(["ready.invalid"]),
                     source="uploaded", uploaded_fullchain=_pem(_leaf_c),
                     uploaded_privkey_encrypted="x", not_after=_dt.datetime(2030, 1, 1))
check("one we hold the material for knows it can rebuild itself",
      _ready.has_material() and _ready.usable,
      "this is what lets a node that turns up without the files write them "
      "back from the database instead of waiting for a person")

print()
print("  files nginx workers have to read")
# Two of these now, a week apart.  The nginx master reads config while it is
# still root, so 0640 root is right for all of it and is what keeps the backend
# tokens off a compromised worker.  A worker has dropped to www-data by the
# time it opens anything at request time, and 0640 there is not a permission
# error anybody can see: an error page comes back as 403 instead of the real
# status, and a htpasswd makes every password attempt a 500 with the reason in
# a log about a file nobody has heard of.  Basic auth had never worked once.


def _modes_under(folder):
    answer = agent({"verb": "list_dir", "path": f"/etc/nginx/nginxmgr/{folder}"})
    if not answer.get("ok"):
        return None
    return {e["name"]: e.get("mode")
            for e in (answer.get("data") or {}).get("entries", [])
            if not e.get("is_dir")}


_conf_modes = _modes_under("sites") or {}
if not _conf_modes:
    skip("staged config stays root only",
         "no site files on this node, which is normal for a standby")
else:
    # World readable is the thing to catch.  Group readable is fine here
    # because the group is root, and testing for it flags 0640, which is
    # exactly what these are supposed to be.
    _leaky = [n for n, m in _conf_modes.items() if m is None or m & 0o004]
    check("staged config is not world readable", not _leaky,
          f"these carry backend tokens and htpasswd paths: {_leaky}")

for _folder, _why in (
        ("auth", "auth_basic is checked by a worker, so a root only htpasswd "
                 "makes every password attempt a 500"),
        ("errorpages", "an unreadable error page makes nginx answer 403 and "
                       "throw away the status it meant to send")):
    _modes = _modes_under(_folder)
    if _modes is None:
        skip(f"{_folder} is readable by an nginx worker",
             f"nothing in {_folder} on this node to look at")
    elif not _modes:
        skip(f"{_folder} is readable by an nginx worker",
             f"{_folder} is empty on this node")
    else:
        _bad = [n for n, m in _modes.items() if m is None or not m & 0o004]
        check(f"{_folder} is readable by an nginx worker", not _bad,
              f"{_why}.  Not readable: {_bad}")

print()
print("  reading a backend's own numbers")
# These come off somebody else's server, in a format we do not control, and
# every one of these was a decision rather than an implementation detail.
from app.core import exporters as _exp  # noqa: E402

_NODE = """
node_cpu_seconds_total{cpu="0",mode="idle"} 1000.0
node_cpu_seconds_total{cpu="0",mode="user"} 100.0
node_cpu_seconds_total{cpu="1",mode="idle"} 1000.0
node_cpu_seconds_total{cpu="1",mode="user"} 100.0
node_memory_MemTotal_bytes 8.0e+09
node_memory_MemAvailable_bytes 2.0e+09
"""
_NODE_LATER = _NODE.replace('mode="idle"} 1000.0', 'mode="idle"} 1005.0') \
                   .replace('mode="user"} 100.0', 'mode="user"} 105.0')

_a = _exp.parse(_NODE)
_b = _exp.parse(_NODE_LATER)

check("a machine exporter is read as the machine",
      _a.get("level") == "machine" and _a.get("memory_percent") == 75.0,
      "node_exporter is the case everybody has, and 6 of 8 GB in use is 75%")

check("cpu comes from the difference between two reads",
      _exp.cpu_percent(_a, _b) == 50.0,
      "these are counters of seconds, so a single read gives a percentage "
      "since boot, which never moves")

check("counters going backwards is a gap rather than a negative",
      _exp.cpu_percent(_b, _a) is None,
      "that is a restart, and drawing it as a number invents one")

_APP = ("process_cpu_seconds_total 120.0\n"
        "process_resident_memory_bytes 2.68435456e+08\n")
_p1 = _exp.parse(_APP); _p1["at"] = 1000
_p2 = _exp.parse(_APP.replace("120.0", "123.0")); _p2["at"] = 1010
check("an application exporter is labelled as one process",
      _p1.get("level") == "process" and _exp.cpu_percent(_p1, _p2) == 30.0,
      "a JVM at 100% of one core is not a busy machine, and a chart that does "
      "not say which it is showing gets acted on")

check("a machine exporter beside an application one is not overwritten",
      _exp.parse(_NODE + _APP).get("memory_percent") == 75.0,
      "otherwise the box's memory becomes one process's, which reads as a "
      "server using 256MB and is quietly wrong")

for _junk, _label in ((None, "nothing"), ("", "empty"),
                      ("<html>no</html>", "an html page"),
                      ("total nonsense here", "words")):
    check(f"{_label} gives nothing rather than raising",
          _exp.parse(_junk) == {},
          "a backend answering with the wrong thing is a message on a page, "
          "not an exception in the collector")

check("the url template fills in the member",
      _exp.build_url("http://{host}:{port}/m", "192.0.2.10", 8080)
      == "http://192.0.2.10:8080/m",
      "one template per pool, because a field per member is how it ends up "
      "half filled in")

print()
print("  the paid feature stand ins")
# Sticky sessions were shipped, documented, and had never worked.  The cookie
# was written on every response and its value was the backend that had just
# answered.  That is not merely "not sticky": the hash of an address lands on
# some other backend, whose address then gets written into the cookie, so a
# client walks round the pool one request at a time.  Found by following the
# cookie the way a browser does rather than by sending a fixed one.

_sticky_pool = Pool(name="sticky_check", lb_method="round_robin", zone_size="64k",
                    settings=json_set({"sticky_enabled": True,
                                       "sticky_cookie_name": "nfm_route",
                                       "sticky_consistent": True}))
_sticky_pool.id = 951
_sticky_pool.members = [
    PoolMember(address="192.0.2.51", port=80, enabled=True, admin_state="up", weight=1),
    PoolMember(address="192.0.2.52", port=80, enabled=True, admin_state="up", weight=1),
]
_sticky_site = VirtualHost(name="stickycheck", enabled=True,
                           server_names=json_set(["sticky.invalid"]),
                           listen_http=True, listen_https=False, force_https=False,
                           http_port=80, mode="proxy", settings="{}")
_sticky_site.id = 951
_sticky_site.pool_id = 951
_sticky_site.pool = _sticky_pool

_sticky_files = Renderer().render_all([_sticky_site], [_sticky_pool], [], [], [],
                                      [], [], [], [])
_sticky_map = _sticky_files.get("maps/sticky-sticky_check.conf", "")
_sticky_conf = _sticky_files.get("sites/stickycheck.conf", "")

check("the sticky cookie is not the backend address",
      "$upstream_addr" not in _sticky_map and "$upstream_addr" not in _sticky_conf,
      "writing the address that just served means the next hash lands "
      "somewhere else and the client walks round the pool")

check("the cookie value is something stable instead",
      "$request_id" in _sticky_map,
      "what makes a client stick is the same string coming back every time, "
      "not what the string says")

check("the cookie is only handed out when there is not one already",
      'default "";' in _sticky_map and "$sticky_set_sticky_check" in _sticky_conf,
      "an empty value writes no header at all, which is how this is done "
      "without an if block.  Setting it every time overwrites the route the "
      "client was given and undoes the whole feature")

check("the upstream still hashes on the cookie",
      "hash $sticky_sticky_check consistent;" in
      _sticky_files.get("upstreams/sticky_check.conf", ""),
      "the hash is the half that does the routing")

print()
print("  the www case")
# A wildcard covers exactly one label.  Getting that wrong in either direction
# is a site that looks right everywhere in the manager and warns in a browser,
# which is the failure this whole check exists to prevent.

check("a wildcard covers the www",
      hostnames.covers(["*.example.com"], "www.example.com"),
      "if this is wrong the warning fires on a site that is perfectly fine and "
      "people learn to ignore it")
check("a wildcard does not cover the bare domain",
      not hostnames.covers(["*.example.com"], "example.com"),
      "this is the trap people meet the day they buy a wildcard, and treating "
      "it as covered means the warning never fires when it should")
check("a wildcard does not cover two labels down",
      not hostnames.covers(["*.example.com"], "a.b.example.com"),
      "one label means one label")
check("an exact name still covers itself",
      hostnames.covers(["example.com", "*.example.com"], "example.com"),
      "the pair people actually buy has to come out clean")
check("the catch all server name is never reported as uncovered",
      hostnames.uncovered(["example.com"], ["_"]) == [],
      "_ is nginx's catch all, nothing can be issued for it, and reporting it "
      "puts a warning on the default site that can never be cleared")
check("a site short of one name says which one",
      hostnames.uncovered(["example.com"], ["example.com", "www.example.com"])
      == ["www.example.com"],
      "the whole point is naming the name, since the site page is otherwise "
      "green and the certificate page says valid")

check("the www is offered on a bare domain and not on a subdomain",
      hostnames.www_partner("example.com") == "www.example.com"
      and hostnames.www_partner("api.example.com") is None,
      "offering www.api.example.com is noise nobody wants")
check("the offer works the other way round too",
      hostnames.www_partner("www.example.com") == "example.com",
      "somebody who typed the www first still wants the bare name")
check("a two part suffix is understood",
      hostnames.www_partner("example.co.uk") == "www.example.co.uk"
      and hostnames.www_partner("a.example.co.uk") is None,
      "example.co.uk has three labels and is still the domain itself")

# The redirect block, and the one thing that made it wrong the first time.
_www_cert = Certificate(name="pair", domains=json_set(["pair.invalid", "www.pair.invalid"]),
                        source="uploaded", not_after=_dt.datetime(2030, 1, 1),
                        files_present=True)
_www_cert.id = 941
_www_pool = Pool(name="www_pool", lb_method="round_robin", settings="{}")
_www_pool.id = 941
_www_pool.members = [PoolMember(address="192.0.2.40", port=80, enabled=True,
                                admin_state="up")]
_www_site = VirtualHost(name="pairsite", enabled=True,
                        server_names=json_set(["pair.invalid", "www.pair.invalid"]),
                        listen_http=True, listen_https=True, force_https=False,
                        http_port=80, https_port=443, http2=False, mode="proxy",
                        settings="{}", redirect_to_primary=True)
_www_site.id = 941
_www_site.pool_id = 941
_www_site.pool = _www_pool
_www_site.cert_id = 941

_www_conf = Renderer().render_all([_www_site], [_www_pool], [_www_cert], [], [],
                                  [], [], [], []).get("sites/pairsite.conf", "")
_redirect_block = _www_conf.split("server {")[1] if "server {" in _www_conf else ""

check("the moved name gets its own server block",
      "server_name www.pair.invalid;" in _www_conf
      and "return 301 https://pair.invalid$request_uri;" in _www_conf,
      "leaving it on the main block means nginx matches it there and the "
      "redirect is never reached")

check("the redirect is inside a location, not at the server level",
      "location / {" in _redirect_block,
      "a return at the server level runs in the rewrite phase, before nginx "
      "picks a location, so it beats the challenge block and the certificate "
      "covering that name could never be renewed.  Writing it the obvious way "
      "produced exactly that")

check("the moved name can still answer a certificate challenge",
      "/.well-known/acme-challenge/" in _redirect_block,
      "without it the name drops off the certificate at the first renewal")

check("the redirect block carries the certificate",
      "ssl_certificate " in _redirect_block,
      "a browser asked for https does the handshake before it sees any "
      "redirect, so no certificate here is a warning rather than a 301")

_www_site.redirect_to_primary = False
_both_conf = Renderer().render_all([_www_site], [_www_pool], [_www_cert], [], [],
                                   [], [], [], []).get("sites/pairsite.conf", "")
check("serving both names writes one block with both on it",
      "server_name pair.invalid www.pair.invalid;" in _both_conf
      and "return 301 https://pair.invalid" not in _both_conf,
      "the default has to stay the simple thing it was")

print()
print("  map blocks")
# A map is mostly regular expressions, and esc() refuses backslashes, so the
# very first realistic entry made the whole render raise.  A render that raises
# stops every unrelated change on every node until somebody works out which row
# of which map is to blame, which is the same shape as the content security
# policy bug and is the worst way for a typo to be reported.


def _map(mid, name, entries, default="none", src="$http_referer", res="out"):
    m = MapBlock(name=name, source_variable=src, result_variable=res,
                 default_value=default, entries=json_set(entries))
    m.id = mid
    return m


_map_files = Renderer().render_all(
    [], [], [], [], [], [], [],
    [_map(931, "regexes", [
        {"match": r"~*google\.", "value": "search engine"},
        {"match": "~*^$", "value": "direct"},
        {"match": "plain", "value": "1"},
    ])], [])
_map_conf = _map_files.get("maps/regexes.conf", "")

check("a map with a backslash in a regex still renders",
      bool(_map_conf) and r"google\." in _map_conf,
      "esc refuses backslashes, which is right for an ordinary directive and "
      "wrong for a map, where nearly every useful match has one")

check("a map value with a space in it comes out quoted",
      '"search engine"' in _map_conf,
      "unquoted, nginx counts the words and says 'invalid number of the map "
      "parameters'")

check("an empty match is written as something nginx can read",
      '"~*^$"' in _map_conf,
      "quoting is what makes an empty or odd match work at all")

_bad_map = _map(932, "hasbadrow", [
    {"match": "good", "value": "1"},
    {"match": "bad; } server { listen 1.2.3.4:9; } #", "value": "2"},
    {"match": "alsogood", "value": "3"},
])
try:
    _bad_files = Renderer().render_all([], [], [], [], [], [], [], [_bad_map], [])
    _bad_conf = _bad_files.get("maps/hasbadrow.conf", "")
    _survived = True
except Exception:
    _bad_conf = ""
    _survived = False

check("one bad row does not take the whole render with it",
      _survived,
      "raising here blocks every apply on every node, and the row is one line "
      "somebody typed on a form")

check("the bad row is dropped and the good ones kept",
      "server {" not in _bad_conf and '"good"' in _bad_conf
      and '"alsogood"' in _bad_conf,
      "a match that would close the block has to come out, and everything "
      "around it has to survive")

_empty_default = _map(933, "emptydefault", [{"match": "a", "value": "1"}],
                      default='""')
_ed_conf = Renderer().render_all(
    [], [], [], [], [], [], [], [_empty_default], []).get("maps/emptydefault.conf", "")
check("the old way of storing an empty default still means empty",
      'default "";' in _ed_conf,
      "rows made before this stored the two characters as the value, and "
      "quoting that again gives a default of two literal quote marks, which "
      "nothing will ever match")

print()
print("  tcp and udp proxying")
# Three things here were found by running real nginx against real output, and
# none of them is visible from reading the code.
#
# http and stream keep separate upstream namespaces, so a pool declared for the
# sites is invisible to a stream.  nginx says "no port in upstream", which reads
# like the pool is malformed rather than like it is in the wrong half.
#
# stream refuses ip_hash, keepalive and fair outright.  A pool with any of those
# on it, pointed at a stream, stops the whole config loading.
#
# And shared memory zone names are one namespace across the entire config, not
# one per block, so a pool used by a site and a stream declared its zone twice
# and nginx refused the lot.

_st_pool = Pool(name="stream_pool", lb_method="ip_hash", keepalive=32,
                zone_size="64k", settings="{}")
_st_pool.id = 921
_st_pool.members = [PoolMember(address="192.0.2.30", port=5432,
                               enabled=True, admin_state="up")]

_st_site = VirtualHost(name="shared.invalid", enabled=True,
                       server_names='["shared.invalid"]', listen_http=True,
                       listen_https=False, force_https=False, http_port=80,
                       mode="proxy", settings="{}")
_st_site.id = 921
_st_site.pool_id = 921
_st_site.pool = _st_pool

_st = StreamServer(name="db", enabled=True, listen_port=15432,
                   listen_address="0.0.0.0", protocol="tcp", udp=False,
                   proxy_protocol=False, settings="{}")
_st.id = 921
_st.pool_id = 921
_st.pool = _st_pool

_st_files = Renderer().render_all([_st_site], [_st_pool], [], [], [], [], [], [],
                                  [_st])
_st_conf = _st_files.get("stream/nfm-stream.conf", "")

check("a stream renders into its own top level file",
      bool(_st_conf) and _st_conf.count("stream {") == 1,
      "stream is a sibling of http, not something inside it, so it cannot be "
      "another file in the include list that goes in the http block")

check("the pool is declared again inside the stream block",
      "upstream stream_pool {" in _st_conf,
      "http and stream keep separate upstream namespaces, so a stream cannot "
      "see the upstream the sites use and nginx says 'no port in upstream'")

check("the stream copy gets its own shared memory zone name",
      "stream_pool_stream_zone" in _st_conf
      and "zone stream_pool_zone" not in _st_conf,
      "shared memory zones are one namespace for the whole config, so the same "
      "name in both halves is refused and every apply fails everywhere")

check("ip_hash is translated rather than written into a stream",
      "ip_hash" not in _st_conf and "hash $remote_addr" in _st_conf,
      "stream refuses ip_hash outright, so a pool with it on stops the whole "
      "config loading the moment a stream points at it")

check("keepalive is left out of the stream copy",
      "keepalive" not in _st_conf,
      "stream refuses keepalive, and it would mean nothing there anyway")

check("the http upstream still has what it should",
      "ip_hash;" in _st_files.get("upstreams/stream_pool.conf", "")
      and "keepalive 32;" in _st_files.get("upstreams/stream_pool.conf", ""),
      "translating for the stream must not quietly change what the sites get")

_st_empty_pool = Pool(name="empty_stream_pool", lb_method="round_robin", settings="{}")
_st_empty_pool.id = 922
_st_empty_pool.members = []
_st_broken = StreamServer(name="nowhere", enabled=True, listen_port=15999,
                          listen_address="0.0.0.0", protocol="tcp", settings="{}")
_st_broken.id = 922
_st_broken.pool_id = 922
_st_broken.pool = _st_empty_pool

_st_files2 = Renderer().render_all([], [_st_pool, _st_empty_pool], [], [], [], [],
                                   [], [], [_st, _st_broken])
check("a stream whose pool is empty is left out rather than written",
      "15999" not in _st_files2.get("stream/nfm-stream.conf", ""),
      "a raw socket has no status code to answer with, so there is nothing to "
      "degrade to, and naming an upstream that is not there stops nginx loading")

check("the other streams still render alongside it",
      "15432" in _st_files2.get("stream/nfm-stream.conf", ""),
      "one bad stream must not take the rest with it")

_st_off = StreamServer(name="off", enabled=False, listen_port=15998,
                       listen_address="0.0.0.0", protocol="tcp", settings="{}")
_st_off.id = 923
_st_off.pool_id = 921
_st_off.pool = _st_pool
_st_files3 = Renderer().render_all([], [_st_pool], [], [], [], [], [], [], [_st_off])
check("no stream file at all when nothing is enabled",
      "stream/nfm-stream.conf" not in _st_files3,
      "an empty stream block is a block nginx still has to accept, and the "
      "include is a glob so writing nothing is the tidier answer")

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
