"""
The web application firewall, from the setting to config nginx will load.

Four things are worth checking and only one of them is "does it render".

  * The module has to be there.  Without it the site must degrade to a comment
    rather than writing a directive nginx cannot parse, which would fail the
    apply for every site on the node and not just this one.
  * The rules file must be beside the site config and must not be included as
    nginx config.  It is ModSecurity syntax, and nginx meeting it would refuse
    the whole config.
  * The mode has to reach the engine.  Watching means DetectionOnly, and a
    watching site that quietly refuses traffic is the worst outcome this
    feature has.
  * nginx has to actually load the result, rules and all, which is the only
    check here that proves anything about the engine.

Nothing is applied.  Scratch objects live in a transaction that is rolled back.

    docker exec -i nginx-fleet-manager python < checks/waf.py
"""
import json
import socket
import sys

from app.core.render import CRS_ROOT, _safe_name
from app.db import session_scope
from app.models import (WafExclusion, WafProfile, WafSurfaceEntry,
                        VirtualHost, json_set)
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"

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


def agent(payload):
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(120)
    s.connect(SOCKET)
    s.sendall((json.dumps(payload) + "\n").encode())
    return json.loads(s.makefile().readline())


def rendered_with(mutate):
    with session_scope() as session:
        mutate(session)
        session.flush()
        try:
            files, _c, _s = render_current(session)
        finally:
            session.rollback()
    return files


def with_waf(mode, paranoia=None):
    """
    Put one named site into a mode, and leave every other site alone.

    Always the same site, chosen by id, and every assertion below is about
    *that* site's file rather than about the whole render.  The first version
    of this asked whether the render contained exactly one firewall file and
    whether any file mentioned modsecurity, which was true only while nobody
    had turned the feature on for real.  The moment two sites were switched to
    watching on a live fleet, a correct render failed the check.

    That is the shape of test this project has already written down as worse
    than none: it passed because of the state of the box, not because of the
    code.
    """
    def mutate(session):
        host = session.get(VirtualHost, TARGET_ID)
        cfg = host.setting_map()
        cfg["waf_mode"] = mode
        if paranoia:
            cfg["waf_paranoia"] = paranoia
        host.settings = json_set(cfg)
    return mutate


print("\n=== The web application firewall ===\n")

with session_scope() as s:
    site_count = s.query(VirtualHost).count()
    first = s.query(VirtualHost).order_by(VirtualHost.id).first()
    TARGET_ID = first.id if first else None
    TARGET_NAME = first.name if first else ""

if not site_count:
    skip("everything", "no sites on this node, which is normal for a standby")
    print("\nnothing to check here\n")
    sys.exit(0)

# The one file every assertion below is about.
TARGET_FILE = f"waf/{_safe_name(TARGET_NAME)}.conf"
TARGET_SITE = f"sites/{_safe_name(TARGET_NAME)}.conf"
print(f"    testing against {TARGET_NAME}\n")

module = agent({"verb": "waf_module_status"}).get("data") or {}
built = bool(module.get("built"))
loaded = bool(module.get("loaded"))

print(f"    module built: {built}, loaded: {loaded}\n")

crs = agent({"verb": "crs_status"}).get("data") or {}
print(f"    rule set: {crs.get('version') or 'not installed'}, "
      f"{crs.get('rules') or 0} files\n")


# =============================================================================
# What gets written
# =============================================================================

files = rendered_with(with_waf("watching"))

mine = files.get(TARGET_SITE, "")

if built:
    check("a rules file is written for this site",
          TARGET_FILE in files,
          f"expected {TARGET_FILE}, got {sorted(p for p in files if p.startswith('waf/'))}")

    check("this site points at its own rules file",
          f"modsecurity_rules_file /etc/nginx/nginxmgr/{TARGET_FILE};" in mine
          and "modsecurity on;" in mine,
          "no modsecurity directives in this site's config")
else:
    check("without the module the site degrades to a comment",
          TARGET_FILE not in files and "modsecurity on;" not in mine,
          "the module is missing and directives were written anyway")

    check("and says why, in the config",
          "without the modsecurity module" in mine,
          "no explanation was left in the config")


# =============================================================================
# The mode has to survive the trip
# =============================================================================

if built:
    rules_text = files.get(TARGET_FILE, "")

    check("watching means DetectionOnly",
          "SecRuleEngine DetectionOnly" in rules_text,
          f"engine line was: {[l for l in rules_text.splitlines() if 'SecRuleEngine' in l]}")

    blocking = rendered_with(with_waf("block"))
    blocking_text = blocking.get(TARGET_FILE, "")
    check("blocking means On",
          "SecRuleEngine On" in blocking_text,
          f"engine line was: {[l for l in blocking_text.splitlines() if 'SecRuleEngine' in l]}")

    # Block known malicious is a locked preset.  The thing worth asserting is
    # not the number but that it ignores a strictness somebody else set: the
    # mode promises "safe without tuning", and it can only keep that promise by
    # overriding a level that was raised on the assumption of tuning.
    known = rendered_with(with_waf("block_known", paranoia="3"))
    known_text = known.get(TARGET_FILE, "")
    check("block known malicious blocks on one critical rule, as CRS ships",
          "SecRuleEngine On" in known_text
          and "inbound_anomaly_score_threshold=5" in known_text,
          "the threshold is not the rule set's own default")

    check("block known malicious pins strictness to 1 whatever the site says",
          "blocking_paranoia_level=1" in known_text,
          "a strictness of 3 leaked into the locked preset")

    # Off means off for *this* site.  Other sites keep whatever they were
    # set to, which is why this asks about one file rather than about the
    # absence of the whole folder.
    off = rendered_with(with_waf("off"))
    check("off writes nothing for this site",
          TARGET_FILE not in off
          and "modsecurity" not in off.get(TARGET_SITE, ""),
          "off still wrote firewall config for this site")

    # Order is the silent one.  A variable set after the rules are included is
    # read too late, the config tests clean, and the setting does nothing.
    strict = rendered_with(with_waf("watching", paranoia="3"))
    strict_text = strict.get(TARGET_FILE, "")
    setvar = strict_text.find("blocking_paranoia_level=3")
    include = strict_text.find(f"Include {CRS_ROOT}/rules/")
    check("the paranoia level is set before the rules are included",
          setvar != -1 and include != -1 and setvar < include,
          f"setvar at {setvar}, rules include at {include}")

    check("bodies are kept out of the audit log",
          "SecAuditLogParts ABFHZ" in rules_text
          and "SecAuditLogFormat JSON" in rules_text,
          "the audit log parts would capture a request body")


# =============================================================================
# Does nginx load it
# =============================================================================

if not built:
    skip("nginx loads the rules", "the module is not in this build")
elif not crs.get("version"):
    skip("nginx loads the rules", "no rule set is installed on this node")
else:
    ok, output = (lambda f: (
        agent({"verb": "write_staging", "files": f}).get("ok"),
        agent({"verb": "test_staging"}).get("data", {}),
    ))(files)

    detail = (output.get("output") or "").strip() if isinstance(output, dict) else ""
    check("nginx loads the site, the module and the whole rule set",
          bool(ok) and bool(output.get("ok")),
          detail)


# =============================================================================
# A tuned profile, where the ordering fails silently
# =============================================================================

if not built:
    skip("a custom profile renders and loads", "the module is not in this build")
elif not crs.get("version"):
    skip("a custom profile renders and loads", "no rule set is installed")
else:
    from app.models import WafExclusion, WafProfile

    def with_profile(session):
        profile = WafProfile(name="_check_probe", learned_from_site=TARGET_NAME)
        session.add(profile)
        session.flush()
        session.add(WafExclusion(profile_id=profile.id, rule_id=942100,
                                 path=None, message="site wide"))
        session.add(WafExclusion(profile_id=profile.id, rule_id=930110,
                                 path="/upload", message="one path"))
        host = session.get(VirtualHost, TARGET_ID)
        cfg = host.setting_map()
        cfg["waf_mode"] = "block"
        cfg["waf_paranoia"] = "custom:_check_probe"
        host.settings = json_set(cfg)

    profiled = rendered_with(with_profile)
    text = profiled.get(TARGET_FILE, "")

    include = text.find(f"Include {CRS_ROOT}/rules/")
    remove = text.find("SecRuleRemoveById 942100")

    # This is the assertion worth having.  SecRuleRemoveById is read while the
    # config loads and needs the rule to exist already, so before the include
    # it is a directive about nothing: no error, no warning, and the rule stays
    # on.  The config tests clean and the site keeps refusing the traffic
    # somebody thought they had allowed.
    check("a site wide exclusion is written after the rules, where it works",
          include != -1 and remove != -1 and remove > include,
          f"include at {include}, removal at {remove}")

    check("a path scoped exclusion is scoped to the path",
          'ctl:ruleRemoveById=930110' in text and "@beginsWith /upload" in text,
          "the path exclusion was not written as a scoped control")

    check("a profile runs at strictness 1 and gets its strictness from tuning",
          "blocking_paranoia_level=1" in text,
          "a custom profile did not fall back to level 1")

    ok = agent({"verb": "write_staging", "files": profiled}).get("ok")
    out = agent({"verb": "test_staging"}).get("data", {})
    check("nginx loads a site with a tuned profile on it",
          bool(ok) and bool(out.get("ok")),
          (out.get("output") or "").strip())



# ---------------------------------------------------------------------------
# Wildcards in an exclusion path
#
# Learning gives one row per object it saw, so anything with a path per object
# fills a profile with near duplicates and still misses whatever is created
# tomorrow.  A git server is the example that forced this: one exclusion per
# repository, forever.  So a path can carry a star and the renderer turns it
# into a regular expression on the way out.
#
# The escaping is the part that has to be right.  `.git` has a dot in it, and
# an unescaped dot matches any character, so a careless translation of
# `/trice/*.git/` would also excuse `/trice/anythingXgit/`, which is a rule
# switched off on a path nobody chose.
print()
print("  wildcards in an exclusion path")

import re as _re
from app.core.render import waf_path_to_regex

_cases = [
    ("/trice/*.git/*",
     ["/trice/apache2.git/git-upload-pack", "/trice/site.git/info/refs"],
     ["/trice/anythingXgit/x", "/other/a.git/x", "/trice/a/b.git/x"]),
    ("/api/**/edit", ["/api/v1/deep/edit"], ["/apix/v1/edit"]),
    ("/upload", ["/upload", "/upload/more"], ["/other"]),
]
for glob, should, shouldnt in _cases:
    rx = waf_path_to_regex(glob)
    check(f"{glob} matches what it should",
          all(_re.search(rx, u) for u in should),
          f"{rx} missed one of {should}")
    check(f"{glob} matches nothing it should not",
          not any(_re.search(rx, u) for u in shouldnt),
          f"{rx} wrongly matched one of {shouldnt}")

check("a star is not left in the regular expression as a literal",
      "*" not in waf_path_to_regex("/a/*/b").replace("[^/]*", "").replace(".*", ""),
      "an unconverted star would be a regex quantifier on the wrong thing")

# And the same thing through a real render, because a translation that is
# right in isolation and never reaches the config file is worth nothing.
def _render_with_paths(paths):
    """Render the target site against a scratch profile holding these paths."""
    def mutate(session):
        profile = WafProfile(name="check-waf-glob-scratch",
                             learned_from_site=TARGET_NAME)
        session.add(profile)
        session.flush()
        for i, path in enumerate(paths):
            session.add(WafExclusion(profile_id=profile.id,
                                     rule_id=942100 + i, path=path))
        host = session.get(VirtualHost, TARGET_ID)
        cfg = host.setting_map()
        cfg["waf_mode"] = "block"
        cfg["waf_paranoia"] = "custom:check-waf-glob-scratch"
        host.settings = json_set(cfg)
    return rendered_with(mutate).get(TARGET_FILE, "")


# Same guard as the positive model below: with no module there is no rules
# file, so these would read an empty string and report three failures about
# nothing.  The translation itself is checked above without a render.
if not built:
    skip("the exclusions through a real render",
         "no modsecurity module on this node, so there is no rules file to "
         "read.  The glob translation above is checked either way.")
else:
    _out = _render_with_paths(["/upload", "/trice/*.git/*"])
    check("a plain path still uses the cheap operator",
          "@beginsWith /upload" in _out,
          "every request would pay for a regular expression it does not need")
    check("a path with a star renders as a regular expression",
          "@rx ^/trice/[^/]*\\.git/[^/]*" in _out,
          f"beginsWith would compare the star literally and never match.  "
          f"Got: {[l for l in _out.splitlines() if 'trice' in l]}")
    check("the dot in .git is escaped in the rendered rule",
          "\\.git" in _out,
          "an unescaped dot matches any character, so the exclusion would also "
          "cover paths nobody chose")


# ---------------------------------------------------------------------------
# The positive model
#
# The opposite idea from everything above.  The rules describe attacks and
# anything they do not recognise is allowed; a surface describes the
# application and anything not on it is refused.
#
# The rule shape here was checked against a real ModSecurity before it was
# written, not reasoned about, and two things came out of that which are easy
# to get wrong and impossible to spot by reading:
#
#   * REQUEST_FILENAME is the path with the query string already off.
#     REQUEST_URI still has it, so a model built on REQUEST_URI would treat
#     /search?q=a and /search?q=b as different pages and refuse the third
#     search anybody did.
#   * a trailing slash is a different string.  nginx hands back /about or
#     /about/ depending on how somebody linked it, so every path rule has to
#     end /?$ or half the site is refused for a reason nobody can see.
print()
print("  the positive model")


def _render_surface(entries, positive, methods=None):
    def mutate(session):
        profile = WafProfile(name="check-waf-surface-scratch",
                             learned_from_site=TARGET_NAME)
        session.add(profile)
        session.flush()
        for path in entries:
            session.add(WafSurfaceEntry(
                profile_id=profile.id, path=path,
                methods=json_set(methods or ["GET", "HEAD"])))
        host = session.get(VirtualHost, TARGET_ID)
        cfg = host.setting_map()
        cfg["waf_mode"] = "block"
        cfg["waf_paranoia"] = "custom:check-waf-surface-scratch"
        cfg["waf_positive"] = positive
        host.settings = json_set(cfg)
    return rendered_with(mutate).get(TARGET_FILE, "")


# Only when the module is here.  Without it the renderer writes no rules
# file at all, which is correct and is checked further up, but every
# assertion below then reads an empty string: three reported a failure
# that was not real, and the fourth crashed on it and took the eight
# after it with it.  A check that stops silently is worse than none.
if not built:
    skip("the positive model",
         "no modsecurity module on this node, so there is no rules file "
         "to read.  Run this on a node with the module built.")
else:
    _off = _render_surface(["/about"], "off")
    check("off writes no surface rules at all",
          "tx.fw_allowed" not in _off,
          "a site with the surface off must be exactly as it was before this "
          "feature existed")

    _report = _render_surface(["/about", "/user/*/profile"], "report")
    check("report sets the flag to zero before anything else",
          'setvar:tx.fw_allowed=0' in _report)
    check("report allows the paths it was given",
          "^/about/?$" in _report and "^/user/[^/]*/profile/?$" in _report,
          "the wildcard has to survive into the rule or every object made after "
          "the walk is refused")
    check("every path rule tolerates a trailing slash",
          _report.count("/?$") >= 2,
          "nginx hands back /about or /about/ depending on the link, and a model "
          "that allowed one and refused the other would be reported as broken")
    check("report refuses nothing",
          "deny" not in _report.split("# The allowed surface")[1],
          "report mode exists so somebody can see the gaps before they cost "
          "anything, and a report that denies is not a report")
    check("report still says what it would have refused",
          "log" in _report and "would have been refused" in _report,
          "a report that logs nothing tells nobody anything")

    _enforce = _render_surface(["/about"], "enforce")
    check("enforce actually denies",
          "deny,status:403" in _enforce)
    check("the deny is the last word, after the rule set and the exclusions",
          _enforce.index("tx.fw_allowed") > _enforce.index("Include"),
          "a rule read before the rule set is included is read too early, which "
          "is the silent failure this file already warns about twice")
    check("the deny names the method and path it refused",
          "%{REQUEST_METHOD}" in _enforce and "%{REQUEST_FILENAME}" in _enforce,
          "without this the log says something was refused and not what")
    check("the path is matched on REQUEST_FILENAME, not REQUEST_URI",
          "REQUEST_FILENAME" in _enforce and 'SecRule REQUEST_URI "@rx ^/' not in _enforce,
          "REQUEST_URI carries the query string, so /search?q=a and /search?q=b "
          "would be two different pages")

    _methods = _render_surface(["/about"], "enforce", methods=["GET", "POST"])
    check("the methods a path answers are enforced",
          "^(?:GET|POST)$" in _methods,
          "a POST to a page that only ever served GET is exactly what a positive "
          "model is for")

    _empty = _render_surface([], "enforce")
    check("an empty surface refuses to write itself rather than refusing the site",
          "tx.fw_allowed" not in _empty and "no surface" in _empty,
          "a default deny with nothing allowed refuses every request, so this has "
          "to be left out and said out loud in the config")

    # And through real nginx, because a rule set that is right in a string and
    # will not load is worth nothing.
    def _surface_files():
        def mutate(session):
            profile = WafProfile(name="check-waf-surface-nginx",
                                 learned_from_site=TARGET_NAME)
            session.add(profile)
            session.flush()
            for path, methods in (("/about", ["GET", "HEAD"]),
                                  ("/user/*/profile", ["GET"]),
                                  ("/api/**/edit", ["POST", "PUT"])):
                session.add(WafSurfaceEntry(profile_id=profile.id, path=path,
                                            methods=json_set(methods)))
            session.add(WafExclusion(profile_id=profile.id, rule_id=930110,
                                     path="/upload"))
            host = session.get(VirtualHost, TARGET_ID)
            cfg = host.setting_map()
            cfg["waf_mode"] = "block"
            cfg["waf_paranoia"] = "custom:check-waf-surface-nginx"
            cfg["waf_positive"] = "enforce"
            host.settings = json_set(cfg)
        return rendered_with(mutate)


    _files = _surface_files()
    _ok = agent({"verb": "write_staging", "files": _files}).get("ok")
    _out = agent({"verb": "test_staging"}).get("data", {})
    check("nginx loads a site enforcing a surface, with exclusions underneath it",
          bool(_ok) and bool(_out.get("ok")),
          (_out.get("output") or "").strip())

print()
failed = [r for r in results if not r[1]]
print(f"    {len(results) - len(failed)} passed, {len(failed)} failed, "
      f"{len(skipped)} skipped\n")
sys.exit(1 if failed else 0)
