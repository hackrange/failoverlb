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
    """
    A value that is deliberately **not** the default.

    The first version used the default, which is exactly the wrong choice and
    produced a page of false alarms: setting gzip to the value gzip already has
    renders identical config, by definition, so every setting whose default is
    already applied looked dead.

    What this check asks is whether changing a setting changes the config, so
    the value has to differ from what the site would do anyway.
    """
    kind = feature.type
    default = feature.default

    if kind == "bool":
        return not bool(default)

    if kind in ("select", "multiselect", "list"):
        options = [o[0] for o in (feature.options or [])]
        if not options:
            return None
        if kind == "select":
            for option in options:
                if option != default:
                    return option
            return None
        # A list or multiselect: something other than whatever is default.
        for option in options:
            if [option] != (default or []):
                return [option]
        return None

    if kind == "int":
        base = default if isinstance(default, int) else 0
        top = getattr(feature, "max_value", None)
        candidate = base + 1
        if top is not None and candidate > top:
            candidate = base - 1
        return candidate if candidate >= 0 else None

    if kind == "size":
        return "3k" if str(default) != "3k" else "7k"

    if kind == "time":
        return "37s" if str(default) != "37s" else "41s"

    if kind == "string":
        # Only where a made up string is safe to render.  Anything that becomes
        # a regex, a path or a list of arguments is left to catalog_sweep,
        # which has a value invention rule of its own and nginx to judge it.
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
    """
    Everything the render produced, not just the site's own file.

    Comparing only sites/<name>.conf missed any setting whose effect lands
    somewhere else in the bundle, and several do: the WAF writes a rule file
    under waf/, cross site access and country blocking write maps, a pool
    writes an upstream.  waf_paranoia was reported as dead for exactly this
    reason while it was writing the paranoia level into the rule file all
    along.
    """
    return "\n".join(f"--- {path}\n{text}"
                     for path, text in sorted(files.items()))


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

# What has to be set before a setting means anything.
#
# Each of these was checked in the renderer rather than assumed.  A rate limit
# only writes when it has a zone to count against (render.py, _limit_lines), and
# the whole proxy_cache family only writes inside a proxy_cache block.  Filled
# in from real objects on this node, because a zone name that does not exist
# renders nothing either.
with session_scope() as _s:
    from app.models import CacheZone, ConnLimitZone, RateLimitZone

    _req = _s.query(RateLimitZone).first()
    _conn = _s.query(ConnLimitZone).first()
    _cache = _s.query(CacheZone).first()
    REQ_ZONE = _req.name if _req else None
    CONN_ZONE = _conn.name if _conn else None
    CACHE_ZONE = _cache.name if _cache else None

PREREQUISITE = {
    "limit_req_burst": {"limit_req_zone_name": REQ_ZONE},
    "limit_req_nodelay": {"limit_req_zone_name": REQ_ZONE},
    "limit_req_status": {"limit_req_zone_name": REQ_ZONE},
    "limit_conn_count": {"limit_conn_zone_name": CONN_ZONE},
    "limit_conn_status": {"limit_conn_zone_name": CONN_ZONE},
    # The setting is called proxy_cache_zone.  proxy_cache is the nginx
    # directive it writes, and naming the directive here meant the
    # prerequisite set a key the catalog does not have, which the settings
    # validator drops without complaint.  So caching was never switched on for
    # these, they correctly rendered nothing, and the check reported five
    # settings as unwired that were fine.  A check failing for the wrong reason
    # is the mirror of the failure this file's README warns about.
    "proxy_cache_valid": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_key": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_bypass": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_no_cache": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_use_stale": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_min_uses": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_lock": {"proxy_cache_zone": CACHE_ZONE},
    "proxy_cache_background_update": {"proxy_cache_zone": CACHE_ZONE},
    # The header saying whether a response came from cache is only written
    # when there is a cache to come from.
    "cache_status_header": {"proxy_cache_zone": CACHE_ZONE},
    "cache_status_header": {"proxy_cache": CACHE_ZONE},

    # Read out of the renderer the same way as the rest, by finding what it
    # tests before it writes the setting.
    "csp_report_only": {"content_security_policy": "default-src 'self'"},
    "cors_allow_methods": {"cors_enabled": True, "cors_allow_origin": "https://x.example"},
    "cors_allow_headers": {"cors_enabled": True, "cors_allow_origin": "https://x.example"},
    "cors_allow_credentials": {"cors_enabled": True, "cors_allow_origin": "https://x.example"},
    "websocket_timeout": {"websocket_enabled": True},
    "autoindex": {"try_files": "$uri $uri/ =404"},
    "fancyindex_exact_size": {"fancyindex": True},
    "fancyindex_name_length": {"fancyindex": True},
    # Strictness only means anything once the WAF is checking something, which
    # the check found on its own and is exactly what it is for.
    "waf_paranoia": {"waf_mode": "watching"},
}

# Settings that need the site to be a different shape, not another setting.
#
# Skipped with the reason rather than reported as dead, because the check is
# built around one scratch site and changing its mode or its certificate would
# be testing something other than the setting.
NEEDS_A_DIFFERENT_SITE = {
    "proxy_ssl_verify": "only written for a pool that speaks https, and the "
                        "pool page owns it there",
    "proxy_ssl_server_name": "same as proxy_ssl_verify",
    "proxy_intercept_errors": "only written when the site has error pages of "
                              "its own",
    "ssl_stapling": "only written for a certificate that names an OCSP "
                    "responder",
    "autoindex": "only meaningful on a site serving files",
    "fancyindex": "only meaningful on a site serving files",
    "server_header_mode": "written into the http level file, not the site",
    # The positive model refuses to write itself when the profile it points at
    # has no allowed surface, because a default deny with nothing allowed
    # refuses every request to the site.  So setting it alone correctly renders
    # nothing, and proving it renders needs a profile with a surface in it,
    # which is what checks/waf.py builds and asserts against real nginx.
    "waf_positive": "renders nothing until the profile it points at has a "
                    "surface, which checks/waf.py covers properly",
}

print("  every setting changes the config when it is set")

base = rendered(lambda session: None)
base_text = site_text(base, TARGET)

dead = []
unavailable = []
no_value = []
needs_companion = []
needs_site = []

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

    # Some settings only mean anything once another one is set, and testing
    # them alone would report a long list of settings that are perfectly well
    # wired.  A check that cries wolf gets ignored, which is worse than not
    # having it, so the companion goes in first and the setting is judged on
    # top of that.
    if feature.key in NEEDS_A_DIFFERENT_SITE:
        needs_site.append(feature.key)
        continue

    extra = dict(PREREQUISITE.get(feature.key) or {})
    if extra and any(v is None for v in extra.values()):
        needs_companion.append(feature.key)
        continue

    def mutate(session, key=feature.key, val=value, companions=extra):
        h = session.get(VirtualHost, TARGET_ID)
        cfg = h.setting_map()
        cfg.update(companions)
        cfg[key] = val
        h.settings = json_set(cfg)

    def only_companions(session, companions=extra):
        h = session.get(VirtualHost, TARGET_ID)
        cfg = h.setting_map()
        cfg.update(companions)
        h.settings = json_set(cfg)

    try:
        after = site_text(rendered(mutate), TARGET)
        before = site_text(rendered(only_companions), TARGET) if extra else base_text
    except Exception as exc:
        dead.append((feature.key, f"render raised: {exc}"))
        continue

    if after == before:
        dead.append((feature.key, "the rendered site is byte for byte the same"))

check("no setting renders identically whether it is on or off",
      not dead,
      "these are stored and shown and change nothing in the config: " +
      ", ".join(k for k, _ in dead))

print(f"          {len(unavailable)} skipped, the fleet has no module for them")
print(f"          {len(no_value)} skipped, no value worth inventing")
print(f"          {len(needs_companion)} skipped, their companion object does "
      f"not exist on this node")
print(f"          {len(needs_site)} skipped, they need a site of a different "
      f"shape than the one tested")


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

# Directives the importer handles some other way, each checked rather than
# waved through.  These take several arguments or appear many times, so the
# importer keeps them as custom config on the way in instead of trying to fold
# them back into one setting.  That is a deliberate trade and not a gap.
#
# Anything not on this list and not in the map is a real hole: it would render
# happily and come back as raw config on the next import, so the two halves of
# a round trip would disagree.
IMPORTED_ANOTHER_WAY = {
    "error_page",          # many per site, and the templates are their own object
    "rewrite",             # a regex and a replacement, kept verbatim
    "sub_filter",          # a pair, and order matters
    "more_set_headers",    # arbitrary header text
    "more_clear_headers",
    "proxy_hide_header",   # appears many times
    "resolver",            # several addresses and a validity
    "ssl_conf_command",    # a name and a value
    "open_file_cache",     # several arguments
    "proxy_cache",         # names a zone object rather than carrying a value
}

missing = sorted(d for d in named
                 if d not in DIRECTIVE_TO_KEY and d not in IMPORTED_ANOTHER_WAY)

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

if not swept:
    # The checks folder is piped in from the host rather than living in the
    # image, so from inside the container there is nothing to read.  Saying so
    # beats reporting every page as unswept, which is what the first version
    # did and would have taught people to ignore this whole file.
    skip("every page route appears in the page sweep",
         "checks/page_sweep.py is not readable from inside the container, so "
         "this pass only works when run against a checkout")
else:
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
