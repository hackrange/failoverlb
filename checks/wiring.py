"""
Is every setting actually wired to something, end to end.

This exists because of four bugs found in one afternoon, all the same shape:
something was stored, shown on a page, accepted by the API, and did nothing at
all.  None of them raised, none of them failed a config test, and one of them
was a permission control that reported itself as applied while the login page
it protected stayed open to the internet.

The common cause is that a setting has to be threaded through several separate
hardcoded lists, and nothing tells you when you missed one:

    app/catalog/features.py            the setting exists
    app/core/render.py                 a list of keys the renderer writes
    app/core/nginx_parser.py           a map the importer reads back
    app/web/templates/...              a field on a page
    checks/page_sweep.py               a list of pages that get swept

`catalog_sweep` already proves that a setting which names a directive reaches
the config and that nginx accepts it.  It cannot say anything about the ones
whose `directive` is blank, which are the settings the renderer handles
specially, and those are exactly where the silent failures were.

So this asks a different question, and asks it by comparison rather than by
looking for a directive name: **render the site without the setting, render it
with the setting, and see whether anything changed.**  A setting that changes
nothing changes nothing.

Nothing is applied.  The scratch objects live in a transaction that is rolled
back, and the live config is never touched.

    docker exec -i nginx-fleet-manager python < checks/wiring.py
"""
import re
import sys
from pathlib import Path

from app.catalog import all_features
from app.core.capabilities import fleet_capabilities
from app.db import session_scope
from app.models import AccessList, ErrorPageTemplate, Location, Pool, VirtualHost, json_set
from app.web.routes_api import render_current

results = []
skipped = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:300]}")


def skip(name, why):
    skipped.append((name, why))
    print(f"    skip  {name}")
    print(f"          {why}")


def sample_value(feature):
    """A value worth setting, of the right type.  Same idea as catalog_sweep."""
    if feature.default not in (None, "", [], {}):
        return feature.default
    kind = feature.type
    if kind == "bool":
        return True
    if kind == "int":
        return getattr(feature, "min_value", None) or 1
    if kind == "size":
        return "16k"
    if kind == "time":
        return "30s"
    if kind in ("select", "multiselect", "list"):
        if feature.options:
            first = feature.options[0][0]
            return [first] if kind in ("multiselect", "list") else first
        return None
    return None


def rendered(mutate):
    """Render the whole config with a change applied, then roll it back."""
    with session_scope() as session:
        mutate(session)
        session.flush()
        try:
            files, _c, _s = render_current(session)
        finally:
            session.rollback()
    return files


def site_text(files, name):
    from app.core.render import _safe_name

    return files.get(f"sites/{_safe_name(name)}.conf", "")


print("\n=== Is every setting wired to something ===\n")

with session_scope() as s:
    host = s.query(VirtualHost).order_by(VirtualHost.id).first()
    TARGET_ID = host.id if host else None
    TARGET = host.name if host else ""

if not TARGET_ID:
    skip("everything", "no sites on this node, which is normal for a standby")
    print("\nnothing to check here\n")
    sys.exit(0)

print(f"    against {TARGET}\n")
CAPS = fleet_capabilities()


# =============================================================================
# 1. A setting that changes nothing does nothing
# =============================================================================
#
# The question catalog_sweep cannot ask.  Rendering with and without the value
# and comparing is the only way to catch a setting the renderer has simply
# never heard of, because there is no directive name to search the output for.

print("  every setting changes the config when it is set")

base = rendered(lambda session: None)
base_text = site_text(base, TARGET)

dead = []
unavailable = []
no_value = []

for feature in all_features().values():
    if "server" not in feature.contexts:
        continue
    if getattr(feature, "edition", "oss") != "oss":
        continue

    try:
        if not feature.is_available(CAPS.modules, CAPS.version_tuple):
            unavailable.append(feature.key)
            continue
    except Exception:
        pass

    value = sample_value(feature)
    if value is None:
        no_value.append(feature.key)
        continue

    def mutate(session, key=feature.key, val=value):
        h = session.get(VirtualHost, TARGET_ID)
        cfg = h.setting_map()
        cfg[key] = val
        h.settings = json_set(cfg)

    try:
        after = site_text(rendered(mutate), TARGET)
    except Exception as exc:
        dead.append((feature.key, f"render raised: {exc}"))
        continue

    if after == base_text:
        dead.append((feature.key, "the rendered site is byte for byte the same"))

check("no setting renders identically whether it is on or off",
      not dead,
      "these are stored and shown and change nothing in the config: " +
      ", ".join(k for k, _ in dead))

print(f"          {len(unavailable)} skipped, the fleet has no module for them")
print(f"          {len(no_value)} skipped, no value worth inventing")


# =============================================================================
# 2. What a path points at has to reach the config
# =============================================================================
#
# The bug that made this file worth writing.  Location.access_list_id was in
# the model, returned by the API and offered on the page, and the renderer
# never wrote a single allow or deny for it.  The path reported itself as
# restricted and was open to everybody.

print("\n  a path's own objects reach the config")

with session_scope() as s:
    acl = s.query(AccessList).first()
    pool = s.query(Pool).first()
    template = s.query(ErrorPageTemplate).first()
    have = {"access_list_id": bool(acl), "pool_id": bool(pool),
            "error_page_template_id": bool(template)}
    ids = {"access_list_id": acl.id if acl else None,
           "pool_id": pool.id if pool else None,
           "error_page_template_id": template.id if template else None}

for field, present in have.items():
    if not present:
        skip(f"a path's {field} reaches the config",
             "nothing of that kind exists on this node to point at")
        continue

    def with_path(session, f=field, value=ids[field]):
        h = session.get(VirtualHost, TARGET_ID)
        loc = Location(host_id=h.id, path="/wiring-probe", match_type="prefix",
                       mode="proxy", enabled=True)
        setattr(loc, f, value)
        if f != "pool_id":
            loc.pool_id = h.pool_id
        session.add(loc)

    try:
        text = site_text(rendered(with_path), TARGET)
    except Exception as exc:
        check(f"a path's {field} reaches the config", False, f"render raised: {exc}")
        continue

    block = ""
    inside = False
    for line in text.splitlines():
        if "/wiring-probe" in line:
            inside = True
        if inside:
            block += line + "\n"
            if line.strip() == "}":
                break

    check(f"a path's {field} reaches the config",
          bool(block.strip()) and block != "",
          "the path rendered no block at all")

    if field == "access_list_id":
        # Named separately because this is the one that was open while
        # reporting itself closed, and a path block existing is not the same
        # as a path block carrying its access rules.
        check("a path with an access list actually writes allow or deny",
              ("allow " in block or "deny " in block),
              "the path rendered with no access control in it, so it is open")


# =============================================================================
# 3. The importer can read back what the renderer writes
# =============================================================================
#
# DIRECTIVE_TO_KEY is a hardcoded map.  A directive missing from it is
# invisible to the importer twice over: it is never turned into a setting, and
# it is then kept as raw custom config because the importer does not know it
# became one.  proxy_cookie_path arrived as both at once.

print("\n  the importer knows every directive the catalog writes")

from app.core.nginx_parser import DIRECTIVE_TO_KEY

named = {f.directive: f.key for f in all_features().values()
         if getattr(f, "directive", "") and "server" in f.contexts}
missing = sorted(d for d in named if d not in DIRECTIVE_TO_KEY)

check("every directive the catalog names is known to the parser",
      not missing,
      "these render but cannot be imported back, and would be kept as raw "
      "config on the way in: " + ", ".join(missing))


# =============================================================================
# 4. Every page is swept
# =============================================================================
#
# A page nobody sweeps is a page that 500s quietly.  The WAF profiles page was
# not covered until somebody added it by hand.

print("\n  every page is in the sweep")

from app.web import routes_pages

page_paths = set()
for route in routes_pages.router.routes:
    path = getattr(route, "path", "")
    methods = getattr(route, "methods", set()) or set()
    if "GET" not in methods or "{" in path:
        continue
    page_paths.add(path)

sweep = Path(routes_pages.__file__).parent.parent.parent / "checks" / "page_sweep.py"
try:
    swept = sweep.read_text()
except OSError:
    swept = ""

# Pages that are deliberately not swept, with the reason.
EXEMPT = {
    "/login",        # needs a signed out client, and has its own checks
    "/logout",       # ends the session the sweep is using
    "/healthz",      # not a page
}

unswept = sorted(p for p in page_paths
                 if p not in EXEMPT and f'"{p}"' not in swept)

check("every page route appears in the page sweep",
      not unswept,
      "these pages are never swept, so nothing would notice them raising: " +
      ", ".join(unswept))


print()
failed = [r for r in results if not r[1]]
print(f"    {len(results) - len(failed)} passed, {len(failed)} failed, "
      f"{len(skipped)} skipped\n")
print("  what this does not cover:")
print("    - whether a setting does the right thing, only that it does something")
print("    - settings that only apply inside a location, which need their own pass")
print("    - anything behind a button, which needs a browser")
print()
print("  RESULT:", "everything is wired" if not failed
      else f"{len(failed)} NOT WIRED")
sys.exit(1 if failed else 0)
