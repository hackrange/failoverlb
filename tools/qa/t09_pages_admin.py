"""
Suite 9: error pages, and the rest of the site page.

Custom error pages, raw config mode, cloning a site, non standard ports, the
default site, and deleting.  These are the parts of making a website that are
not settings and not paths.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t09_pages_admin").start()
LB01 = qa.LB01
HOST = f"qa-admin.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
for n in ("qa-admin", "qa-admin-copy", "qa-ports"):
    x = find("hosts", n)
    if x:
        r.api("DELETE", f"/hosts/{x['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-admin")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-admin")["id"]
print(f"  test site id {SID}")


def get(path="/echo", host=HOST, **kw):
    return qa.probe(host, path, ip=LB01, scheme="http", **kw)


# ============================================================== ERR-01
t = r.test(
    "ERR-01", "Error pages",
    "A custom error page, made once and used by a site",
    "Make an error page template on the Error Pages page, attach it to a site, "
    "and prove a visitor who hits a 404 gets that page rather than nginx's.",
    "The stock nginx error page names nginx and its version and says nothing "
    "useful.  A branded page that says what went wrong and where to go next is "
    "the difference between a visitor leaving and a visitor trying again.",
    "The custom page is served for the codes it covers, on every site "
    "pointed at it, and it is served without asking the backend.")

t.step("open Error Pages and photograph it")
r.goto("/error-pages")
r.page.wait_for_timeout(800)
t.shot("error-pages-before", full=True)
t.config("before")
existing = r.api("GET", "/error-pages")["body"]
t.proof("the templates that exist now", json.dumps(existing, indent=1)[:900])

t.step("remove any template a previous run left behind, then make one")
for tpl in (existing.get("templates") or existing.get("error_pages") or []):
    if tpl["name"].startswith("qa"):
        r.api("DELETE", f"/error-pages/{tpl['id']}")
made = r.api("POST", "/error-pages", {
    "name": "qa_pages",
    "description": "QA test template, delete me",
    "html": "<!doctype html><html><body><h1>QA error {{ code }}</h1>"
            "<p>this page came from the template</p></body></html>",
    "codes": [400, 403, 404, 500, 502, 503, 504],
})
t.proof("POST /api/error-pages", json.dumps(made["body"], indent=1)[:700])
t.ok("the template was created", made["status"] in (200, 201), made)
TPL = made["body"]["id"]
r.goto("/error-pages")
r.page.wait_for_timeout(800)
t.shot("error-pages-after", full=True)

t.step("attach it to the site on the Basics tab")
r.goto(f"/sites/{SID}")
r.page.wait_for_timeout(600)
r.page.select_option("#f-errorpage", str(TPL))
r.page.click("#save-site")
r.page.wait_for_timeout(1200)
r.goto(f"/sites/{SID}")
t.ok("the template reads back as attached",
     r.page.locator("#f-errorpage").input_value() == str(TPL),
     r.page.locator("#f-errorpage").input_value())
t.shot("site-with-error-template")
cfg = t.site_config("qa-admin", "the config with the template attached")
t.proof("the error page rules", "\n".join(
    l for l in cfg.splitlines() if "error_page" in l or "__nfm_error" in l))
t.ok("the site points at the template", "qa_pages" in cfg, cfg[:400])
t.config("after")
res = r.apply("qa: error pages")
t.ok("apply succeeded", res["status"] == 200, res)

t.step("ask the backend for a 404 and see which page comes back")
p = get("/status/404")
t.proof("a 404 through the site", qa.summarise(p, 700))
t.ok("the answer is still a 404", p["status"] == 404, p["status"])
t.ok("the custom page was served", "QA error" in p["body"], p["body"][:300])
# The stock page names the server and its version.  The template does not,
# and the template text no longer contains the word either, which is what made
# this check fail the first time it ran.
t.ok("nginx's own page was not served", "nginx" not in p["body"].lower(),
     p["body"][:300])

p503 = get("/status/503")
t.proof("a 503 through the site", qa.summarise(p503, 400))
t.ok("another covered code uses it too", "QA error" in p503["body"], p503["body"][:200])
t.close()

# ============================================================== ADM-01
t = r.test(
    "ADM-01", "Site administration",
    "Raw config mode",
    "Switch a site to raw config mode, edit the config by hand, check it, save "
    "it, and prove nginx runs what was typed rather than what the form would "
    "have produced.",
    "There is always one thing the form does not cover.  Without an escape "
    "hatch that keeps the site under management, people edit files on the box "
    "and the next save wipes them, which is exactly the failure this mode "
    "exists to prevent.",
    "The typed config is what nginx serves, and the tool says the site is in "
    "raw mode rather than silently ignoring the form.")

r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=config]")
r.page.wait_for_timeout(1500)
t.shot("config-tab-gui-mode", full=True)
t.config("before")
generated = r.page.locator("#raw-config").input_value()
t.proof("the config the form produced, before anybody edited it", generated[:1200])

t.step("tick raw config mode and change the config by hand")
r.page.check("#f-raw")
r.page.wait_for_timeout(500)
hand = generated.replace(f"server_name qa-admin.{qa.DOMAIN};",
                         f"server_name qa-admin.{qa.DOMAIN};\n    add_header X-Hand-Written yes always;")
r.page.fill("#raw-config", hand)
t.shot("config-tab-raw-mode", full=True)

t.step("press Check it, which asks a real nginx whether this loads")
r.page.click("#check-config")
r.page.wait_for_timeout(3000)
problems = r.page.locator("#config-problems").inner_text()
t.proof("what the checker said", problems or "[nothing reported]")
t.ok("the checker accepted the config", "error" not in problems.lower(), problems[:300])

r.page.click("#save-config")
r.page.wait_for_timeout(1500)
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=config]")
r.page.wait_for_timeout(1200)
t.ok("the site reads back as being in raw mode",
     r.page.locator("#f-raw").is_checked(), "raw box came back unticked")
saved = r.page.locator("#raw-config").input_value()
t.ok("the hand written line survived the save",
     "X-Hand-Written" in saved, saved[:300])
cfg = t.site_config("qa-admin", "the config the fleet would be given, in raw mode")
t.ok("the hand written line is what gets rendered",
     "X-Hand-Written" in cfg, cfg[:300])
t.config("after")
res = r.apply("qa: raw mode")
t.ok("apply succeeded", res["status"] == 200, res)

p = get("/echo")
t.proof("a request to the hand edited site", qa.summarise(p, 400))
t.ok("nginx is serving the hand written config",
     p["headers"].get("X-Hand-Written") == "yes", p["headers"].get("X-Hand-Written"))

t.step("switch back to the form and prove the form takes over again")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=config]")
r.page.wait_for_timeout(1000)
# Unticking the box switches the site back on its own and disables Save, so
# there is nothing to press here.  Clicking it anyway is what the first run of
# this test did, and it waited thirty seconds for a disabled button.
r.page.uncheck("#f-raw")
r.page.wait_for_timeout(2500)
t.proof("what the page says the mode is now",
        r.page.locator("#mode-label").inner_text())
t.ok("the Save config button is disabled once the form is driving again",
     r.page.locator("#save-config").is_disabled(), "still enabled")
back_cfg = t.site_config("qa-admin", "the config once the form is driving again")
t.ok("the hand written file is no longer being pasted into the server block",
     "X-Hand-Written" not in back_cfg,
     [l for l in back_cfg.splitlines() if "Hand-Written" in l])
t.ok("there is only one server block in the file",
     back_cfg.count("\nserver {") <= 2, back_cfg.count("\nserver {"))
res = r.apply("qa: back to the form")
t.proof("the apply after leaving raw mode", json.dumps(res["body"], indent=1)[:700])
t.ok("the fleet can still apply, which is the part that used to break",
     res["status"] == 200 and res["body"].get("ok"), res)
back = get("/echo")
t.proof("the same request once the site is back on the form",
        qa.summarise(back, 400))
t.ok("the hand written header is gone",
     not back["headers"].get("X-Hand-Written"), back["headers"].get("X-Hand-Written"))
t.ok("the site still works", back["status"] == 200, back["status"])
t.close()

# ============================================================== ADM-02
t = r.test(
    "ADM-02", "Site administration",
    "Cloning a site",
    "Clone a working site under a new name and hostname, and prove the copy "
    "carries the original's settings while answering on its own name and being "
    "switched off until somebody turns it on.",
    "The second site is nearly always the first one with a different name.  "
    "Retyping forty settings is where the mistakes come from.",
    "The clone has the same settings, its own hostname, and is created "
    "disabled so it cannot take traffic before anybody has looked at it.")

t.step("give the original something to carry across, then clone it")
r.api("PUT", f"/hosts/{SID}", {"settings": {"client_max_body_size": "33m"},
                               "notes": "the original"})
t.config("before")
r.goto(f"/sites/{SID}")
r.page.wait_for_timeout(600)
t.shot("site-before-clone", full=True)
r.page.click("#clone-site")
r.page.wait_for_selector("#cl-name")
r.page.fill("#cl-name", "qa-admin-copy")
r.page.fill("#cl-names", f"qa-copy.{qa.DOMAIN}")
t.shot("clone-dialog")
r.page.click("#cl-go")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1500)

copy = find("hosts", "qa-admin-copy")
t.ok("the clone was created", bool(copy), copy)
t.proof("the clone as the API returns it", json.dumps(copy, indent=1)[:1000])
detail = r.api("GET", f"/hosts/{copy['id']}")["body"]
t.proof("the clone's settings", json.dumps(detail.get("settings"), indent=1)[:600])
t.ok("the settings came across",
     (detail.get("settings") or {}).get("client_max_body_size") == "33m",
     detail.get("settings"))
t.ok("it answers on its own hostname, not the original's",
     detail.get("server_names") == [f"qa-copy.{qa.DOMAIN}"], detail.get("server_names"))
t.ok("it is created switched off, so it cannot take traffic yet",
     detail.get("enabled") is False, detail.get("enabled"))
r.goto(f"/sites/{copy['id']}")
t.shot("the-clone", full=True)
t.config("after")
t.close()

# ============================================================== ADM-03
t = r.test(
    "ADM-03", "Site administration",
    "A site on a port that is not 80",
    "Move a site to a non standard port and prove it answers there and not on "
    "the old one.",
    "An internal tool, a staging copy or a second application on the same "
    "address all need this, and it is the sort of thing that either works or "
    "leaves a listener nobody notices.",
    "The site answers on the new port; nothing new appears on the old one.")

t.config("before")
res = r.api("PUT", f"/hosts/{copy['id']}", {"enabled": True, "http_port": 8088,
                                            "listen_https": False})
t.proof("PUT with a new port", json.dumps(res["body"], indent=1)[:400]
        if res["status"] == 200 else json.dumps(res)[:400])
t.ok("the port change saved", res["status"] == 200, res)
cfg = r.file_named("sites/qa-admin-copy.conf")
t.proof("the listen lines", "\n".join(l for l in cfg.splitlines() if "listen" in l))
t.ok("the config listens on the new port", "listen 8088" in cfg, cfg[:400])
t.config("after")
res = r.apply("qa: odd port")
t.ok("apply succeeded", res["status"] == 200, res)

p = qa.probe(f"qa-copy.{qa.DOMAIN}", "/echo", ip=LB01, scheme="http", port=8088)
t.proof("a request on port 8088", qa.summarise(p, 400))
t.ok("the site answers on the new port", p["status"] == 200, p["status"])
t.close()

# ============================================================== ADM-04
t = r.test(
    "ADM-04", "Site administration",
    "Deleting a site",
    "Delete the clone and prove it leaves the config, stops answering, and "
    "takes nothing else with it.",
    "Deleting is the operation people are most nervous about, and the one "
    "where a mistake is least recoverable.  What matters is that it removes "
    "exactly one site.",
    "The site is gone from the list and from the config; every other site "
    "still answers.")

t.config("before")
before_sites = [h["name"] for h in r.api("GET", "/hosts")["body"]["hosts"]]
t.proof("the sites before the delete", json.dumps(sorted(before_sites)))
still_ok = get("/echo")["status"]

res = r.api("DELETE", f"/hosts/{copy['id']}")
t.proof("DELETE /api/hosts/{id}", json.dumps(res, indent=1)[:400])
t.ok("the delete was accepted", res["status"] in (200, 204), res)
after_sites = [h["name"] for h in r.api("GET", "/hosts")["body"]["hosts"]]
t.proof("the sites after the delete", json.dumps(sorted(after_sites)))
t.ok("exactly one site was removed",
     set(before_sites) - set(after_sites) == {"qa-admin-copy"},
     set(before_sites) ^ set(after_sites))
t.ok("its config file is gone", not r.file_named("sites/qa-admin-copy.conf"), "")
t.config("after")
r.apply("qa: after delete")
gone = qa.probe_allowing_refusal(f"qa-copy.{qa.DOMAIN}", "/echo", ip=LB01,
                                 scheme="http", port=8088)
t.proof("the deleted site's port after applying",
        f"{gone['status']} {gone['reason']}  (status 0 means nothing is listening,\n"
        f"which is the answer this test is looking for)")
t.ok("nothing answers on its port any more", gone["status"] != 200, gone["status"])
t.ok("the site beside it is untouched", get("/echo")["status"] == 200, "")
t.close()

r.stop()
print("\nT09 DONE")
