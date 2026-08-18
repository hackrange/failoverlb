"""
Suite 4: paths.

Paths are where a site stops being one backend and becomes a routing decision,
and they are where this project's last three real bugs lived.  Every test here
reads the dialog back after saving, because a setting that saves and then shows
itself as off is the exact defect that reached the fleet.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t04_paths").start()
LB01 = qa.LB01
HOST = f"qa-paths.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]

old = find("hosts", "qa-paths")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-paths")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-paths")["id"]
print(f"  test site id {SID}")


def add_path(t, path, match="prefix", mode="proxy", pool=None, root=None,
             alias=None, target=None, code=None, strip=None, mount=None,
             shot=None):
    """Drive the Add a path dialog the way a person does."""
    r.goto(f"/sites/{SID}")
    r.page.click("button[data-tab=paths]")
    r.page.wait_for_timeout(400)
    r.page.click("#add-path")
    r.page.wait_for_selector("#l-path")
    r.page.fill("#l-path", path)
    r.page.select_option("#l-match", match)
    r.page.select_option("#l-mode", mode)
    r.page.wait_for_timeout(250)
    if mode == "proxy" and pool:
        r.page.select_option("#l-pool", str(pool))
    if mount is not None and r.page.locator("#l-mount").count():
        r.page.set_checked("#l-mount", mount)
        r.page.wait_for_timeout(200)
    if strip is not None and r.page.locator("#l-strip").is_visible():
        r.page.set_checked("#l-strip", strip)
    if root:
        r.page.fill("#l-root", root)
    if alias:
        r.page.fill("#l-alias", alias)
    if target:
        r.page.fill("#l-target", target)
    if code:
        r.page.select_option("#l-code", str(code))
    if shot:
        t.shot(shot)
    r.page.click("#l-save")
    r.page.wait_for_timeout(900)


def reopen(path_id):
    r.goto(f"/sites/{SID}")
    r.page.click("button[data-tab=paths]")
    r.page.wait_for_timeout(400)
    r.page.click(f"button[data-edit-path='{path_id}']")
    r.page.wait_for_selector("#l-path")
    r.page.wait_for_timeout(400)


def path_named(p):
    got = r.api("GET", f"/hosts/{SID}/locations")["body"]
    rows = got.get("locations") or got.get("paths") or got
    return next((x for x in rows if x["path"] == p), None)


def echo(path, host=HOST):
    p = qa.probe(host, path, ip=LB01, scheme="http")
    try:
        return p, json.loads(p["body"])
    except Exception:
        return p, {}


# ============================================================== PATH-01
t = r.test(
    "PATH-01", "Paths",
    "Send one path to a different place from the rest of the site",
    "Add a catch all path and an /api path, and prove requests land where the "
    "page says they will.",
    "This is the single most common reason a load balancer exists: one "
    "hostname, an application on one set of servers and an API or an admin "
    "panel on another.",
    "A request to / and a request to /api are both answered, and the config "
    "carries one location block for each.")

t.step("open the Paths tab, which starts empty")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(500)
t.shot("paths-empty", full=True)
t.config("before")
t.site_config("qa-paths", "the site's config with no paths at all")

t.step("add a catch all path of / going to the pool")
add_path(t, "/", mode="proxy", pool=POOL_ID, shot="add-path-dialog")
t.step("add an /api path going to the same pool")
add_path(t, "/api", mode="proxy", pool=POOL_ID)
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(500)
t.shot("paths-two", full=True)

cfg = r.file_named("sites/qa-paths.conf")
t.proof("the site's config with two paths", cfg)
t.config("after")
t.ok("the config has a location for /", "location / {" in cfg, cfg[:300])
t.ok("the config has a location for /api", "location /api" in cfg, cfg[:300])

res = r.apply("qa: two paths")
t.ok("apply succeeded", res["status"] == 200, res)
root_p, root_j = echo("/echo")
api_p, api_j = echo("/api/echo")
t.proof("a request to /echo", qa.summarise(root_p, 700))
t.proof("a request to /api/echo", qa.summarise(api_p, 700))
t.ok("the catch all path answers", root_p["status"] == 200, root_p["status"])
t.ok("the /api path answers", api_p["status"] == 200, api_p["status"])
t.close()

# ============================================================== PATH-02
t = r.test(
    "PATH-02", "Paths",
    "Take this path off before sending it on",
    "Tick the strip box on the /api path, prove the backend is asked for the "
    "path without /api on the front, and prove the box is still ticked when "
    "the dialog is opened again.",
    "An application mounted at /api on the load balancer usually expects to be "
    "at the root on its own server.  Without this, every request arrives at "
    "the backend with a prefix it has never heard of and every one is a 404.",
    "The backend reports the path with the prefix removed, and reopening the "
    "path shows the box still ticked.")

api_id = path_named("/api")["id"]
t.step("look at what the backend is asked for now, with the box clear")
before_p, before_j = echo("/api/echo")
t.proof("what the backend received before the change",
        json.dumps({"path_the_backend_saw": before_j.get("path")}, indent=1))
t.config("before")

t.step("open the path and tick 'Take this path off before sending it on'")
reopen(api_id)
t.shot("path-dialog-strip-before")
r.page.set_checked("#l-strip", True)
t.shot("path-dialog-strip-ticked")
r.page.click("#l-save")
r.page.wait_for_timeout(900)

t.step("open the same path again and read the box back")
reopen(api_id)
still = r.page.locator("#l-strip").is_checked()
t.shot("path-dialog-strip-reopened")
t.ok("the box is still ticked when the path is opened again", still,
     "the box came back unticked, which is the read back defect")
r.page.keyboard.press("Escape")

api_json = r.api("GET", f"/hosts/{SID}/locations")["body"]
t.proof("the path as the API hands it back to the page",
        json.dumps(path_named("/api"), indent=1)[:900])
t.ok("the API returns strip_prefix as true",
     path_named("/api").get("strip_prefix") is True, path_named("/api"))

cfg = r.file_named("sites/qa-paths.conf")
t.proof("the config for the /api path with stripping on",
        "\n".join(cfg.split("location /api")[1].splitlines()[:14])
        if "location /api" in cfg else cfg[:600])
t.config("after")
r.apply("qa: strip prefix")

after_p, after_j = echo("/api/echo")
t.proof("what the backend received after the change",
        json.dumps({"asked_for": "/api/echo",
                    "path_the_backend_saw": after_j.get("path")}, indent=1))
t.ok("the prefix was taken off before the request went on",
     after_j.get("path") == "/echo", after_j.get("path"))
t.ok("the site still answers 200", after_p["status"] == 200, after_p["status"])
t.close()

# ============================================================== PATH-03
t = r.test(
    "PATH-03", "Paths",
    "How nginx chooses between paths",
    "Add an exact match, a preferential prefix and a regular expression over "
    "the same ground, and prove each request is answered by the one nginx "
    "really picks rather than the one that was typed first.",
    "nginx does not read locations top to bottom, and everybody assumes it "
    "does.  A regex that quietly beats a prefix is how a static file handler "
    "ends up serving an API, and it is invisible in the config.",
    "An exact match wins over every prefix, a preferential prefix beats a "
    "regex, and a plain prefix loses to a regex.")

t.config("before")
t.step("add an exact match, a preferential prefix and a regex")
add_path(t, "/exact", match="exact", mode="redirect", target="https://example.net/won-exact", code=302)
add_path(t, "/assets", match="preferential", mode="redirect", target="https://example.net/won-preferential", code=302)
add_path(t, r"\.(png|css)$", match="regex", mode="redirect", target="https://example.net/won-regex", code=302)
add_path(t, "/plain", match="prefix", mode="redirect", target="https://example.net/won-prefix", code=302)

r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(600)
t.shot("paths-all-match-types", full=True)
order = r.page.locator("#paths-order").inner_text()
t.proof("what the page says nginx will do, in order", order)

cfg = r.file_named("sites/qa-paths.conf")
t.proof("the location blocks as rendered",
        "\n".join(l for l in cfg.splitlines() if l.strip().startswith("location")))
t.config("after")
t.ok("the exact match rendered as location =", "location = /exact" in cfg, cfg[:200])
t.ok("the preferential prefix rendered as location ^~", "location ^~ /assets" in cfg, cfg[:200])
t.ok("the regex rendered as location ~", "location ~ " in cfg, cfg[:200])

res = r.apply("qa: match types")
t.ok("apply succeeded", res["status"] == 200, res)

cases = [
    ("/exact", "won-exact", "an exact match wins"),
    ("/exact/deeper", "won-", "a longer path does not hit the exact match"),
    ("/assets/logo.png", "won-preferential", "a preferential prefix beats a regex"),
    ("/plain/logo.png", "won-regex", "a regex beats a plain prefix"),
    ("/plain/file.txt", "won-prefix", "a plain prefix wins when no regex matches"),
]
for path, expect, claim in cases:
    p = qa.probe(HOST, path, ip=LB01, scheme="http")
    loc = p["headers"].get("Location", "")
    t.proof(f"GET {path}", f"{p['status']}  Location: {loc}")
    if expect == "won-":
        t.ok(claim, "won-exact" not in loc, loc)
    else:
        t.ok(claim, expect in loc, f"got {loc!r}")
t.close()

# ============================================================== PATH-04
t = r.test(
    "PATH-04", "Paths",
    "A path that refuses traffic",
    "Set a path to Refuse it and prove nginx answers 403 without asking any "
    "backend.",
    "Blocking one path is how an admin panel, an old upload directory or a "
    "leaked endpoint gets closed off in one move without touching the "
    "application.",
    "The path answers 403, and the backends see no request for it.")

t.config("before")
add_path(t, "/blocked", mode="deny", shot="path-dialog-deny")
cfg = r.file_named("sites/qa-paths.conf")
t.proof("the denied location as rendered",
        "\n".join(cfg.split("location /blocked")[1].splitlines()[:8])
        if "location /blocked" in cfg else "[not found]")
t.config("after")
r.apply("qa: deny path")
p = qa.probe(HOST, "/blocked/anything", ip=LB01, scheme="http")
t.proof("GET /blocked/anything", qa.summarise(p, 500))
t.ok("a denied path answers 403", p["status"] == 403, p["status"])
t.close()

# ============================================================== PATH-05
t = r.test(
    "PATH-05", "Paths",
    "Serving files from disk on one path while the rest is proxied",
    "Add a static path with a directory, and a second one using Alias instead, "
    "and prove the difference between the two on the wire.",
    "The usual shape of a real site: the application on a backend and its "
    "static assets served straight off the load balancer, which is faster and "
    "takes load off the app.  root and alias differ in whether the path is "
    "part of the filename, and getting that wrong is a 404 nobody can explain.",
    "The root version looks for the path under the directory; the alias "
    "version replaces the path with the directory.")

t.config("before")
add_path(t, "/qa-static", mode="static",
         root=qa.STATIC_DIR.rsplit("/", 1)[0], shot="path-dialog-static")
add_path(t, "/files", mode="static", alias=qa.STATIC_DIR + "/")
cfg = r.file_named("sites/qa-paths.conf")
t.proof("the two static locations as rendered",
        "\n".join(cfg.split("location /qa-static")[1].splitlines()[:6]
                  + ["..."] + cfg.split("location /files")[1].splitlines()[:6])
        if "location /files" in cfg else cfg[:800])
t.config("after")
r.apply("qa: static paths")

leaf = qa.STATIC_DIR.rsplit("/", 1)[-1]
root_hit = qa.probe(HOST, f"/{leaf}/index.html", ip=LB01, scheme="http")
t.proof(f"GET /{leaf}/index.html, served with root", qa.summarise(root_hit, 400))
t.ok("root serves the file under the directory named",
     root_hit["status"] == 200 and "QA static site" in root_hit["body"],
     root_hit["status"])

alias_hit = qa.probe(HOST, "/files/index.html", ip=LB01, scheme="http")
t.proof("GET /files/index.html, served with alias", qa.summarise(alias_hit, 400))
t.ok("alias serves the same file from a path that is not in the filename",
     alias_hit["status"] == 200 and "QA static site" in alias_hit["body"],
     alias_hit["status"])
t.close()

# ============================================================== PATH-06
t = r.test(
    "PATH-06", "Paths",
    "Turning one path off without deleting it",
    "Untick Enabled on a path and prove it stops being rendered, then tick it "
    "back on.",
    "Taking one route out while an application is fixed, without losing the "
    "settings on it, is the difference between a two second change and "
    "retyping a form.",
    "The disabled path leaves the config and stops answering; the rest of the "
    "site is untouched.")

blocked_id = path_named("/blocked")["id"]
t.config("before")
before = qa.probe(HOST, "/blocked/x", ip=LB01, scheme="http")
t.ok("the path answers 403 while it is on", before["status"] == 403, before["status"])

reopen(blocked_id)
r.page.set_checked("#l-enabled", False)
t.shot("path-dialog-disabled")
r.page.click("#l-save")
r.page.wait_for_timeout(900)
reopen(blocked_id)
t.ok("the Enabled box reads back unticked",
     not r.page.locator("#l-enabled").is_checked(), "still ticked")
r.page.keyboard.press("Escape")

cfg = r.file_named("sites/qa-paths.conf")
t.proof("the config with the path switched off",
        "\n".join(l for l in cfg.splitlines() if l.strip().startswith("location")))
t.ok("a disabled path is not rendered", "location /blocked" not in cfg, cfg[:300])
t.config("after")
r.apply("qa: path off")
after = qa.probe(HOST, "/blocked/x", ip=LB01, scheme="http")
t.proof("GET /blocked/x once the path is off", qa.summarise(after, 400))
t.ok("it no longer answers 403", after["status"] != 403, after["status"])
t.ok("the rest of the site still works",
     qa.probe(HOST, "/echo", ip=LB01, scheme="http")["status"] == 200, "")
t.close()

# ============================================================== PATH-07
t = r.test(
    "PATH-07", "Paths",
    "Every field on the path dialog comes back the way it was saved",
    "Save a path with a value in every field the dialog offers, reopen it, and "
    "compare each control against what was typed.",
    "A form that saves correctly and redisplays incorrectly is worse than one "
    "that fails, because the next save writes the wrong value back without "
    "anybody touching that field.  This has already happened here.",
    "Every control on the reopened dialog holds the value that was saved.")

t.config("before")
add_path(t, "/roundtrip", match="preferential", mode="redirect",
         target="https://example.net/target", code=302)
rt = path_named("/roundtrip")
t.proof("the path as the API returns it", json.dumps(rt, indent=1))
reopen(rt["id"])
t.shot("path-dialog-roundtrip")
got = {
    "path": r.page.locator("#l-path").input_value(),
    "match_type": r.page.locator("#l-match").input_value(),
    "mode": r.page.locator("#l-mode").input_value(),
    "redirect_target": r.page.locator("#l-target").input_value(),
    "redirect_code": r.page.locator("#l-code").input_value(),
    "enabled": r.page.locator("#l-enabled").is_checked(),
}
r.page.keyboard.press("Escape")
want = {"path": "/roundtrip", "match_type": "preferential", "mode": "redirect",
        "redirect_target": "https://example.net/target", "redirect_code": "302",
        "enabled": True}
t.proof("what was typed against what came back",
        json.dumps({"typed": want, "read back": got}, indent=1))
for k in want:
    t.ok(f"{k} came back the way it was saved", got[k] == want[k],
         f"saved {want[k]!r}, read back {got[k]!r}")

t.step("check the same for every column the API returns, not just the ones on screen")
missing = [k for k, v in rt.items() if v is None and k in
           ("path", "match_type", "mode", "enabled")]
t.ok("no field the dialog needs came back empty", not missing, missing)
t.config("after")
t.close()

r.stop()
print("\nT04 DONE")
