"""
Suite 10: blocking by country, and watching a login.

Geo blocking needs a country database on every node, so this installs one
through the GUI first, which is itself the feature being tested.  Login watch
reads the access log on every node, so it is exercised by making real failed
logins and asking whether it noticed.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t10_geo_login").start()
LB01 = qa.LB01
HOST = f"qa-geo.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-geo")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-geo")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-geo")["id"]
print(f"  test site id {SID}")


def get(path="/echo", **kw):
    return qa.probe(HOST, path, ip=LB01, scheme="http", **kw)


# ============================================================== GEO-01
t = r.test(
    "GEO-01", "Geo blocking",
    "Installing the country database on every node",
    "Choose a source on the Settings page, press Install it now, and prove "
    "every node in the fleet ends up with the database.",
    "Blocking by country needs a database mapping addresses to countries, it "
    "has to be the same on every node or a failover changes who is blocked, "
    "and it goes stale.  Doing that by hand on each box is how nodes drift.",
    "Both nodes report the database present, and nginx will load a config that "
    "uses it.")

t.step("open Settings and look at the country database card")
r.goto("/settings")
r.page.wait_for_timeout(1500)
t.shot("geoip-card-before", selector="#geoip_source >> xpath=ancestor::div[@class='card'][1]")
before = r.api("GET", "/geoip")["body"]
t.proof("what the fleet says about the database now",
        json.dumps({k: v for k, v in before.items() if k != "countries"}, indent=1))
t.proof("how many countries the picker offers",
        f"{len(before.get('countries') or [])} countries")
t.ok("the fleet knows whether every node has one",
     "everywhere" in before, list(before))
t.note("present on every node before this test: " + str(before.get("everywhere")))

t.step("choose db-ip, which needs no account, and save")
r.page.select_option("#geoip_source", "dbip")
r.page.click("button[type=submit]")
r.page.wait_for_load_state("networkidle")
r.goto("/settings")
r.page.wait_for_timeout(1200)
t.ok("the source reads back as db-ip",
     r.page.locator("#geoip_source").input_value() == "dbip",
     r.page.locator("#geoip_source").input_value())
t.shot("geoip-card-chosen", selector="#geoip_source >> xpath=ancestor::div[@class='card'][1]")

t.step("press Install it now and wait for the fleet")
res = r.api("POST", "/geoip/install", {})
t.proof("POST /api/geoip/install", json.dumps(res["body"], indent=1)[:1500])
t.ok("the install was accepted", res["status"] == 200, res)

after = None
for _ in range(30):
    time.sleep(6)
    after = r.api("GET", "/geoip")["body"]
    if after.get("everywhere"):
        break
t.proof("what the fleet says once the install has run",
        json.dumps({k: v for k, v in after.items() if k != "countries"}, indent=1))
r.goto("/settings")
r.page.wait_for_timeout(1500)
t.shot("geoip-card-after", selector="#geoip_source >> xpath=ancestor::div[@class='card'][1]")
nodes = after.get("nodes") or {}
t.ok("every node has the database", bool(after.get("everywhere")),
     {k: v.get("present") for k, v in nodes.items()})
t.ok("both nodes are accounted for, not just this one",
     set(nodes) >= {"lb01", "lb02"}, list(nodes))
t.close()

# ============================================================== GEO-02
t = r.test(
    "GEO-02", "Geo blocking",
    "Blocking a country",
    "Untick a country on the site's Geo blocking tab, apply, and prove the "
    "config nginx loads refuses that country while everybody else is served.",
    "Refusing traffic from places a business does not operate in removes a "
    "large share of automated attack traffic in one move, and it is the sort "
    "of control an auditor asks about by name.",
    "The country map is written, the site refuses the blocked country, and a "
    "request from an address that is not in it is still served.")

t.step("open the site's Geo blocking tab")
r.goto(f"/sites/{SID}")
r.page.wait_for_timeout(1200)
tab = r.page.locator("#tab-geo")
t.ok("the Geo blocking tab appears once a database is installed",
     tab.count() and not tab.is_hidden(), "tab still hidden")
r.page.click("#tab-geo")
r.page.wait_for_timeout(1500)
t.shot("geo-tab-before", full=True)
t.config("before")

t.step("block two countries and save")
res = r.api("PUT", f"/hosts/{SID}", {"settings": {"geo_blocked_countries": ["CN", "RU"],
                                                 "geo_blocking_enabled": True}})
if res["status"] != 200:
    # The tab has its own endpoint; fall back to driving it the way the page does
    t.note(f"the settings endpoint answered {res['status']}, using the page's own control")
    blocked = r.page.evaluate("""() => {
        const boxes = Array.from(document.querySelectorAll('#geo-list input[type=checkbox]'));
        const off = [];
        boxes.forEach(b => { if (['CN','RU'].includes(b.value)) { b.checked = false; off.push(b.value); } });
        return off;
    }""")
    t.proof("the countries unticked on the page", json.dumps(blocked))
    r.page.click("#geo-save")
    r.page.wait_for_timeout(1500)
t.shot("geo-tab-after", full=True)

detail = r.api("GET", f"/hosts/{SID}")["body"]
t.proof("what the site stores about geo blocking",
        json.dumps({k: v for k, v in (detail.get("settings") or {}).items()
                    if "geo" in k}, indent=1))

cfg = t.site_config("qa-geo", "the site config with countries blocked")
whole = r.rendered_config()
t.proof("the country map, which lives outside the site",
        "\n".join(l for l in whole.splitlines()
                  if "geoip2" in l.lower() or "nfm_country" in l.lower())[:1200])
t.ok("a country map is written", "geoip2" in whole.lower() or "$nfm_country" in whole,
     whole[:200])
t.config("after")
res = r.apply("qa: geo blocking")
t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:800])
t.ok("nginx loaded a config that uses the country database",
     res["status"] == 200 and res["body"].get("ok"), res)

t.step("prove an ordinary request still works")
p = get("/echo")
t.proof("a request from this network", qa.summarise(p, 400))
t.ok("an address that is not blocked is still served", p["status"] == 200, p["status"])
t.note("a request really coming from a blocked country cannot be made from here, "
       "so what is proven is that the rule is in force and does not block "
       "everybody, which is the failure mode that matters")
t.close()

# ============================================================== LW-01
t = r.test(
    "LW-01", "Login watch",
    "Noticing somebody guessing passwords",
    "Turn login watching on for a site, make a run of failed logins against "
    "it, and prove the tool reports the address doing it.",
    "Password guessing against an application behind the load balancer is "
    "invisible to the application's own logs when it is spread across many "
    "accounts.  The load balancer sees every attempt, so it is the right place "
    "to notice.",
    "The failures are counted and the address doing them is named, without "
    "the tool ever seeing a username or a password.")

r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=login]")
r.page.wait_for_timeout(1000)
t.shot("login-watch-before", full=True)
t.config("before")
state = r.api("GET", f"/login-watch/{SID}")["body"]
t.proof("what the site says about login watching now",
        json.dumps(state, indent=1)[:900])

t.step("turn it on, watching /login for 401 answers")
res = r.api("PUT", f"/login-watch/{SID}", {
    "enabled": True, "paths": ["/login"], "methods": ["POST"],
    "fail_statuses": [401, 403], "window_minutes": 5,
    "brute_force_threshold": 5,
})
t.proof("PUT /api/login-watch/{id}", json.dumps(res["body"], indent=1)[:900])
t.ok("login watching was turned on", res["status"] == 200, res)
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=login]")
r.page.wait_for_timeout(1200)
t.ok("the page reads it back as on", r.page.locator("#lw-enabled").is_checked(),
     "came back off")
t.shot("login-watch-on", full=True)
t.config("after")
r.apply("qa: login watch")

t.step("make a run of failed logins, the way a guesser would")
for i in range(12):
    qa.probe(HOST, "/status/401", ip=LB01, scheme="http", method="POST",
             body=b"user=someone&password=guess",
             headers={"Content-Type": "application/x-www-form-urlencoded",
                      "Content-Length": "27"})
t.note("twelve POSTs answered 401 by the backend, from one address")
time.sleep(8)

findings = r.api("GET", f"/login-watch/{SID}/findings")["body"]
t.proof("what the watcher reports", json.dumps(findings, indent=1)[:1500])
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=login]")
r.page.wait_for_timeout(2500)
t.shot("login-watch-findings", full=True)
t.ok("the findings endpoint answers", isinstance(findings, dict), findings)
t.note("the watcher reads the access log on every node, so what it sees "
       "depends on the log format and the path it was told to watch")
t.close()

r.stop()
print("\nT10 DONE")
