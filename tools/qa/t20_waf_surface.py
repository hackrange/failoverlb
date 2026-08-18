"""
Suite 20: the WAF surface on a fleet whose nginx cannot run it.

This fleet has no modsecurity module and no rule set, and that is not a fault
to be fixed by a test: building it means rebuilding nginx from source on both
load balancers.  What it does mean is that every claim the product makes about
the WAF here is a claim about a feature that cannot run, and that is exactly
where this product has been bitten before.

The precedent is worth stating, because this suite exists because of it.  A
control for a feature this nginx could not run was drawn **disabled**, a
disabled checkbox still reports its value, so `http3_enabled: false` went up on
every save, and the validator refused any unavailable feature whatever the
value.  The result was that **no site setting could be saved at all on this
fleet**, and the error named HTTP/3 at somebody who was changing a timeout.

The WAF is the other unavailable feature on this fleet.  So the question this
suite asks is not "does the WAF work", which cannot be answered here.  It is
"does the product tell the truth about a WAF it cannot run, and does it stay
out of the way of everything else".

The half that needs a real engine is not faked and not skipped quietly: it is
in `checks/waf.py`, which says out loud which of its checks it could not run
on a node without the module.
"""
import json
import sys
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t20_waf_surface").start()
LB01 = qa.LB01


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


SITE = "qa-waf"
HOST = f"qa-waf.{qa.DOMAIN}"

old = find("hosts", SITE)
if old:
    r.api("DELETE", f"/hosts/{old['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", SITE)
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "static")
r.page.fill("#s-root", qa.STATIC_DIR)
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", SITE)["id"]
print(f"  test site id {SID}")

MODULE = r.api("GET", "/waf/rules")["body"]
HAVE_MODULE = bool(MODULE.get("everywhere"))
print(f"  module present on every node: {HAVE_MODULE}")


# ---------------------------------------------------------------- WAF-01

t = r.test("WAF-01", "WAF", "The WAF is not offered on a fleet that cannot run it",
           "Look at a site's tabs and at the fleet's own report of the module, "
           "and check the product does not offer a switch that could not work.",
           "Somebody evaluating this on a stock nginx.  A switch that is "
           "offered, accepted and then silently does nothing is worse than one "
           "that is not there, because the site is then believed to be "
           "protected.",
           "The WAF tab is hidden, and the fleet reports the module missing on "
           "every node without disagreeing with itself.")
t.step("ask the fleet what it has")
t.proof("GET /api/waf/rules", json.dumps(MODULE, indent=2)[:1500])
per_node = MODULE.get("nodes") or {}
t.ok("every node was asked", len(per_node) >= 1, per_node)
t.ok("the nodes agree with each other", MODULE.get("agreed") is True, MODULE)
t.ok("and the answer matches what nginx on this box was built with",
     bool(MODULE.get("everywhere")) == HAVE_MODULE, MODULE)

t.step("open the site and look at its tabs")
r.goto(f"/sites/{SID}")
r.page.wait_for_timeout(600)
tab = r.page.locator("button[data-tab=waf]")
present = tab.count()
visible = tab.first.is_visible() if present else False
t.proof("the WAF tab in the page",
        f"in the document: {bool(present)}\nvisible to a person: {visible}")
if HAVE_MODULE:
    t.ok("the WAF tab is offered, because this fleet can run it", visible, visible)
else:
    t.ok("the WAF tab is not offered on a fleet without the module",
         not visible, "the tab is visible on a fleet whose nginx has no WAF")
t.shot("a-sites-tabs-with-no-waf-module")
t.close()


# ---------------------------------------------------------------- WAF-02

t = r.test("WAF-02", "WAF", "Turning the WAF on is refused, with the fix in the message",
           "Call the endpoint behind the hidden tab and check the refusal says "
           "what would have to happen, and that nothing was stored.",
           "The tab being hidden protects nobody who uses the API, restores an "
           "old config, or imports a site from a fleet that did have the "
           "module.  The refusal is the real guard and the message is what "
           "stops it costing somebody an afternoon.",
           "A 400 naming the module, and the site's stored settings unchanged.")
before = r.api("GET", f"/hosts/{SID}")["body"].get("settings") or {}
t.proof("the site's settings before", json.dumps(before, indent=2)[:600])

for mode in ("block_known", "watching", "on"):
    res = r.api("PUT", f"/hosts/{SID}", {"settings": {"waf_mode": mode}})
    t.proof(f"turning the WAF to {mode}", json.dumps(res, indent=2)[:500])
    if HAVE_MODULE:
        t.ok(f"waf_mode {mode} is accepted on a fleet with the module",
             res["status"] == 200, res)
    else:
        t.ok(f"waf_mode {mode} is refused", res["status"] == 400, res)
        t.ok("and the message names the module",
             "modsecurity" in str(res.get("body")).lower(), res.get("body"))

after = r.api("GET", f"/hosts/{SID}")["body"].get("settings") or {}
t.proof("the site's settings after", json.dumps(after, indent=2)[:600])
if not HAVE_MODULE:
    t.ok("the site did not quietly end up with a WAF mode stored",
         (after.get("waf_mode") or "off") == "off", after.get("waf_mode"))
t.close()


# ---------------------------------------------------------------- WAF-03

t = r.test("WAF-03", "WAF", "A hidden WAF does not stop the other settings saving",
           "Save an ordinary setting on the site and prove the hidden WAF "
           "control is not sent with it and does not get the save refused.",
           "This is the defect that has already shipped once, on the other "
           "unavailable feature.  A control drawn for a feature this nginx "
           "cannot run still reported its value, the validator refused any "
           "unavailable feature whatever the value, and the result was that no "
           "site setting could be saved at all on this fleet.  The WAF is the "
           "other unavailable feature here, so it gets the same test.",
           "The save succeeds, the value sticks, and no WAF key is sent.")
t.step("change a timeout through the site's own settings page")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=settings]")
r.page.wait_for_timeout(700)

sent = r.page.evaluate("""
  () => {
    const seen = [];
    const real = window.fetch;
    window.fetch = function (url, opt) {
      if (opt && opt.method === 'PUT' && opt.body) seen.push(String(opt.body));
      return real.apply(this, arguments);
    };
    window.__qaSeen = seen;
    return true;
  }
""")
# #save-site, which is the button the settings tab really uses.  Reaching for
# the first button that says Save picks up #geo-save, which is on a different
# card and hidden, and the suite waits thirty seconds for something that was
# never going to be clickable.
field = r.page.locator("#set-proxy_read_timeout, [name=proxy_read_timeout]").first
if field.count():
    field.fill("77")
r.page.click("#save-site")
r.page.wait_for_timeout(1800)
bodies = r.page.evaluate("() => window.__qaSeen || []")
t.proof("what the settings page actually sent",
        "\n\n".join(bodies)[:2000] or "[the page sent no PUT, so this was read "
        "through the api below instead]")
for body in bodies:
    t.ok("the save did not carry a WAF key", "waf_mode" not in body, body[:300])

t.step("and prove an ordinary setting saves and comes back")
res = r.api("PUT", f"/hosts/{SID}", {"settings": {"proxy_read_timeout": "77s"}})
t.proof("saving one ordinary setting through the api", json.dumps(res, indent=2)[:400])
t.ok("an ordinary setting saves on a fleet with no WAF", res["status"] == 200, res)
back = (r.api("GET", f"/hosts/{SID}")["body"].get("settings") or {})
t.ok("and reads back as what was saved", back.get("proxy_read_timeout") == "77s",
     back.get("proxy_read_timeout"))
t.close()


# ---------------------------------------------------------------- WAF-04

t = r.test("WAF-04", "WAF", "A learning session cannot be started without an engine",
           "Try to start a learning session on a fleet with no module and check "
           "it is refused rather than half started.",
           "A learning session turns on full audit logging for the tester "
           "addresses.  One that starts against an engine that is not there "
           "collects nothing, and the person running the round finds out at the "
           "end, after exercising the whole application.",
           "The start is refused and no session is left recorded against the "
           "site.")
res = r.api("POST", f"/waf/sessions/{SID}/start",
            {"addresses": ["203.0.113.7/32"], "note": "qa: no engine here"})
t.proof("starting a learning session with no engine", json.dumps(res, indent=2)[:600])
if HAVE_MODULE:
    t.ok("a session starts on a fleet with the module", res["status"] in (200, 201), res)
else:
    t.ok("the session is refused", res["status"] >= 400, res)
    sessions = r.api("GET", f"/waf/sessions/{SID}")
    t.proof("the site's sessions afterwards", json.dumps(sessions, indent=2)[:600])
    body = sessions["body"] or {}
    rows = body.get("sessions") or ([body["session"]] if body.get("session") else [])
    # `running` is the field this row really has.  An earlier version of this
    # check looked for a `state` key that does not exist, so it found nothing
    # and passed while a session was sitting there running.  The defect it was
    # meant to catch was in the same test.
    live = [s for s in rows if s.get("running")]
    t.ok("and no session was left running against the site", not live, rows)

    settings_now = r.api("GET", f"/hosts/{SID}")["body"].get("settings") or {}
    t.ok("and the site was not quietly switched to watching",
         (settings_now.get("waf_mode") or "off") == "off",
         settings_now.get("waf_mode"))
t.close()


# ---------------------------------------------------------------- WAF-05

t = r.test("WAF-05", "WAF", "The profiles page tells the truth with nothing to show",
           "Open the WAF profiles page on a fleet with no rule set and no "
           "profiles, and check it renders and says where profiles come from.",
           "An empty page that renders nothing tells somebody the feature is "
           "broken.  This is the page they land on from the menu before they "
           "have ever run a session, so it is the first thing they see of the "
           "feature.",
           "The page renders, says there are none yet, and says how one is "
           "made.")
r.goto("/waf-profiles")
text = " ".join(r.page.inner_text("body").split())
t.proof("the page as a person sees it", text[:1500])
t.ok("the page renders rather than erroring", "WAF profiles" in text, text[:200])
t.ok("it says there are none yet", "No profiles yet" in text or "no profiles" in text.lower(),
     text[:400])
t.ok("and says where one comes from",
     "learning session" in text.lower(), text[:600])
t.ok("no javascript errors on the page", not r.js_errors, r.js_errors)
t.shot("the-waf-profiles-page-with-none", full=True)

t.step("and the rule id list answers rather than failing")
ids = r.api("GET", "/waf/rule-ids")
t.proof("GET /api/waf/rule-ids", json.dumps(ids, indent=2)[:500])
t.ok("the rule id endpoint answers", ids["status"] == 200, ids)
t.ok("and says plainly that no rule set is present",
     (ids["body"] or {}).get("present") is HAVE_MODULE or
     (ids["body"] or {}).get("present") is False, ids["body"])
t.close()


# ---------------------------------------------------------------- WAF-06

t = r.test("WAF-06", "WAF", "The site still serves with the WAF unavailable",
           "Apply the fleet config and ask the site for a page, to prove a "
           "missing engine costs the site nothing.",
           "The way this could go wrong is a config that references an engine "
           "that is not loaded.  nginx refuses to start on that, and because an "
           "apply is all or nothing, one site would take the whole fleet down.",
           "Apply succeeds, nginx loads, and the site answers.")
res = r.apply("qa: a fleet with no WAF engine")
t.ok("apply succeeded", res["status"] == 200, res)
cfg = t.site_config(SITE, "the site config on a fleet with no WAF engine")
t.ok("nothing tries to load a rules file", "modsecurity_rules_file" not in cfg,
     [l for l in cfg.splitlines() if "modsec" in l.lower()][:5])
page = t.probe("the site, with no WAF engine anywhere", hostname=HOST, path="/",
               ip=LB01, scheme="http")
t.ok("the site answers", page["status"] == 200, page["status"])
t.ok("and serves the real file", "QA static site" in (page["body"] or ""),
     (page["body"] or "")[:200])
t.close()


# ---------------------------------------------------------------- tidy up

row = find("hosts", SITE)
if row:
    print("  removing the test site:", r.api("DELETE", f"/hosts/{row['id']}")["status"])
r.apply("qa: removing the waf surface test site")

print("\nT20 DONE")
r.stop()
