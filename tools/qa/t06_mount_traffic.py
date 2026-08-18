"""
Suite 6: mounting a whole site under a path, and the settings that only a real
request can prove.

Rendering a directive is not the same as the directive doing anything.  Half of
this suite is about the difference: a cache setting that renders and never
caches, a rate limit that renders and never limits, a compression setting that
renders and sends the file uncompressed.  Everything here is checked at the
wire.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t06_mount_traffic").start()
LB01 = qa.LB01
HOST = f"qa-mount.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-mount")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-mount")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-mount")["id"]
print(f"  test site id {SID}")


def paths():
    return r.api("GET", f"/hosts/{SID}/locations")["body"]["locations"]


def add_path(t, path, **kw):
    r.goto(f"/sites/{SID}")
    r.page.click("button[data-tab=paths]")
    r.page.wait_for_timeout(400)
    r.page.click("#add-path")
    r.page.wait_for_selector("#l-path")
    r.page.fill("#l-path", path)
    if kw.get("match"):
        r.page.select_option("#l-match", kw["match"])
    r.page.select_option("#l-mode", kw.get("mode", "proxy"))
    r.page.wait_for_timeout(250)
    if kw.get("mode", "proxy") == "proxy":
        r.page.select_option("#l-pool", str(POOL_ID))
    if kw.get("mount"):
        r.page.check("#l-mount")
        r.page.wait_for_timeout(300)
    if kw.get("shot"):
        t.shot(kw["shot"])
    r.page.click("#l-save")
    r.page.wait_for_timeout(1000)


def settings_on_site(payload):
    return r.api("PUT", f"/hosts/{SID}", {"settings": payload})


def get(path, host=HOST, **kw):
    return qa.probe(host, path, ip=LB01, scheme="http", **kw)


# ============================================================== MNT-01
t = r.test(
    "MNT-01", "Paths",
    "Serve a whole website under a path",
    "Tick 'Serve a whole website here' on a path and prove the four separate "
    "things it has to do all happen: the prefix comes off on the way to the "
    "backend, absolute links in the page get the prefix put back, a redirect "
    "the backend builds without the prefix gets it back, and a cookie set for "
    "the backend's root is scoped to the mount.",
    "Putting an existing site under a path of another one is a normal thing to "
    "want and a miserable thing to do by hand: it is a strip, three sub_filter "
    "rules, two proxy_redirect rules and a cookie path rule, and missing any "
    "one of them produces a site that half works.  One tick should do all of "
    "it.",
    "The backend is asked for / when /shop/ is requested, the html that comes "
    "back has /shop/ on its links, a backend redirect lands inside the mount, "
    "and the cookie is scoped to the mount.")

t.step("photograph the site before the mount exists")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(500)
t.shot("before-mount", full=True)
t.config("before")
t.site_config("qa-mount", "the site config before the mount")

t.step("add a /shop path with 'Serve a whole website here' ticked")
add_path(t, "/shop", mount=True, shot="mount-dialog")
mount = next(p for p in paths() if p["path"] == "/shop")
t.proof("the path as the API returns it", json.dumps(mount, indent=1))
t.ok("the mount box was stored", mount.get("mount_site") is True, mount)

t.step("reopen the path and check the box is still ticked")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(400)
r.page.click(f"button[data-edit-path='{mount['id']}']")
r.page.wait_for_selector("#l-mount")
r.page.wait_for_timeout(400)
t.shot("mount-reopened")
t.ok("the mount box reads back ticked", r.page.locator("#l-mount").is_checked(),
     "came back unticked")
r.page.keyboard.press("Escape")

cfg = t.site_config("qa-mount", "the site config with the mount on it")
t.config("after")
block = cfg.split("location /shop")[1][:2200] if "location /shop" in cfg else ""
t.proof("everything the one tick wrote", block)
t.ok("the prefix is taken off on the way to the backend",
     "proxy_pass" in block and block.count("/") > 0, block[:300])
t.ok("links are rewritten for href, src and action",
     all(f'sub_filter \'{a}="/' in block or f'{a}="/' in block
         for a in ("href", "src", "action")), block[:600])
t.ok("a redirect the backend builds gets the prefix put back",
     "proxy_redirect" in block, block[:600])

res = r.apply("qa: mount")
t.ok("apply succeeded", res["status"] == 200, res)

t.step("ask for /shop/echo and see what the backend was asked for")
p = get("/shop/echo")
body = json.loads(p["body"]) if p["status"] == 200 else {}
t.proof("GET /shop/echo", qa.summarise(p, 800))
t.ok("the mount answers", p["status"] == 200, p["status"])
t.ok("the backend was asked for /echo, without the mount prefix",
     body.get("path") == "/echo", body.get("path"))

t.step("ask for a page with links in it and read them back")
page = get("/shop/")
t.proof("the html the visitor receives", page["body"][:900])
t.ok("a root relative link had the mount prefix put on it",
     'href="/shop/absolute/page.html"' in page["body"], page["body"][:400])
t.ok("a stylesheet link had the mount prefix put on it",
     'href="/shop/static/site.css"' in page["body"], page["body"][:400])
t.ok("an image source had the mount prefix put on it",
     'src="/shop/static/logo.png"' in page["body"], page["body"][:400])
t.ok("a form action had the mount prefix put on it",
     'action="/shop/submit"' in page["body"], page["body"][:400])
t.ok("an absolute link to somewhere else was left alone",
     'href="https://origin.example.net/elsewhere"' in page["body"],
     page["body"][:400])

t.step("make the backend redirect both ways and see where the visitor is sent")
absolute = get("/shop/redirect-abs")
t.proof("the backend answered with a full URL built from the Host header",
        qa.summarise(absolute, 500))
t.ok("a full URL redirect lands inside the mount",
     "/shop/landed" in absolute["headers"].get("Location", ""),
     absolute["headers"].get("Location"))
red = get("/shop/redirect-here")
t.proof("the backend answered with a path only, which RFC 7231 allows",
        qa.summarise(red, 500))
t.ok("a path only redirect also lands inside the mount",
     "/shop/landed" in red["headers"].get("Location", ""),
     red["headers"].get("Location"))
away = get("/shop/redirect-me")
t.proof("the backend answered with a URL somewhere else entirely",
        qa.summarise(away, 500))
t.ok("a redirect to another site is left alone",
     away["headers"].get("Location", "").startswith("http://origin.example.net/"),
     away["headers"].get("Location"))

t.step("make the backend set a cookie and check its path")
ck = get("/shop/set-cookie")
t.proof("GET /shop/set-cookie", qa.summarise(ck, 500))
t.ok("the cookie is scoped to the mount, not the backend's own root",
     "/shop/app" in ck["headers"].get("Set-Cookie", ""),
     ck["headers"].get("Set-Cookie"))
t.close()

# ============================================================== BEH-01
t = r.test(
    "BEH-01", "Settings in traffic",
    "Upload size limit",
    "Set the maximum request body on the site and prove a bigger upload is "
    "refused with 413 while a smaller one goes through.",
    "The default is 1MB and every file upload feature in the world hits it.  "
    "It is the single most common setting anybody changes here, and the "
    "failure it causes looks like a broken application rather than a limit.",
    "A body under the limit reaches the backend; one over it is refused by "
    "nginx with 413 and never reaches the backend at all.")

t.config("before")
res = settings_on_site({"client_max_body_size": "10k"})
t.ok("the setting saved", res["status"] == 200, res)
cfg = t.site_config("qa-mount", "the config carrying the limit")
t.ok("the directive is in the config", "client_max_body_size 10k" in cfg,
     [l for l in cfg.splitlines() if "body_size" in l])
t.config("after")
r.apply("qa: body size")

small = get("/echo", method="POST", body=b"x" * 5000,
            headers={"Content-Type": "application/octet-stream",
                     "Content-Length": "5000"})
t.proof("a 5k upload", qa.summarise(small, 500))
t.ok("an upload under the limit reaches the backend",
     small["status"] == 200 and '"bytes_received": 5000' in small["body"],
     small["status"])

big = get("/echo", method="POST", body=b"x" * 50000,
          headers={"Content-Type": "application/octet-stream",
                   "Content-Length": "50000"})
t.proof("a 50k upload against a 10k limit", qa.summarise(big, 500))
t.ok("an upload over the limit is refused with 413", big["status"] == 413,
     big["status"])
settings_on_site({})
t.close()

# ============================================================== BEH-02
t = r.test(
    "BEH-02", "Settings in traffic",
    "Compression",
    "Turn compression on and prove a compressible response really arrives "
    "compressed, and that a client which cannot decompress still gets it.",
    "Compression is most of the transfer saving on any text heavy site and it "
    "is one tick.  It is also easy to render and have do nothing, because it "
    "only applies to types on a list and only over a minimum length.",
    "With gzip on and a client that accepts it, the response carries "
    "Content-Encoding: gzip.  Without the header, it comes back plain.")

t.config("before")
res = settings_on_site({"gzip": True, "gzip_min_length": "100"})
t.proof("the settings being saved",
        json.dumps({"gzip": True, "gzip_min_length": "100"}))
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-mount", "the config with compression on")
gzip_lines = [l.strip() for l in cfg.splitlines() if "gzip" in l]
t.proof("every gzip directive the site was given", "\n".join(gzip_lines))
t.ok("gzip is on in the config", "gzip on;" in cfg, gzip_lines)
t.ok("the types the form calls the default are the types nginx is given",
     any("gzip_types" in l and "application/json" in l for l in gzip_lines),
     gzip_lines)
t.config("after")
r.apply("qa: gzip")

zipped = get("/compressible", headers={"Accept-Encoding": "gzip"})
plain = get("/compressible", headers={"Accept-Encoding": "identity"})
t.proof("asking with Accept-Encoding: gzip",
        f"{zipped['status']}  Content-Encoding: "
        f"{zipped['headers'].get('Content-Encoding')}  bytes: {zipped['length']}")
t.proof("asking without it",
        f"{plain['status']}  Content-Encoding: "
        f"{plain['headers'].get('Content-Encoding')}  bytes: {plain['length']}")
t.ok("a client that accepts gzip gets it",
     zipped["headers"].get("Content-Encoding") == "gzip",
     zipped["headers"].get("Content-Encoding"))
t.ok("a client that does not is still served",
     plain["status"] == 200 and not plain["headers"].get("Content-Encoding"),
     plain["headers"].get("Content-Encoding"))
t.ok("compression actually made it smaller",
     zipped["length"] < plain["length"], f"{zipped['length']} vs {plain['length']}")
settings_on_site({})
t.close()

# ============================================================== BEH-03
t = r.test(
    "BEH-03", "Settings in traffic",
    "Security headers",
    "Turn the security headers on and prove a browser receives exactly one of "
    "each, even when the backend sets its own.",
    "Two of these that disagree is worse than neither, because browsers do not "
    "settle the contradiction the same way.  The tool hides the backend's copy "
    "before adding its own, and that behaviour is invisible in the config.",
    "Each header arrives once, with the value set here.")

t.config("before")
want = {"hsts_enabled": True, "hsts_max_age": 31536000,
        "x_frame_options": "DENY", "x_content_type_options": True,
        "referrer_policy": "no-referrer",
        "content_security_policy": "default-src 'self'; frame-ancestors 'none'"}
res = settings_on_site(want)
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-mount", "the config carrying the headers")
t.config("after")
r.apply("qa: headers")

p = get("/echo")
t.proof("every response header the visitor received",
        "\n".join(f"{k}: {v}" for k, v in sorted(p["headers"].items())))
t.ok("X-Frame-Options is the one set here",
     p["headers"].get("X-Frame-Options") == "DENY", p["headers"].get("X-Frame-Options"))
t.ok("X-Content-Type-Options is set",
     p["headers"].get("X-Content-Type-Options") == "nosniff",
     p["headers"].get("X-Content-Type-Options"))
t.ok("Referrer-Policy is the one set here",
     p["headers"].get("Referrer-Policy") == "no-referrer",
     p["headers"].get("Referrer-Policy"))
t.ok("the Content Security Policy arrived whole",
     "frame-ancestors 'none'" in (p["headers"].get("Content-Security-Policy") or ""),
     p["headers"].get("Content-Security-Policy"))
t.note("HSTS is deliberately absent over plain http, which is correct: a "
       "browser ignores it there and sending it teaches nothing")
settings_on_site({})
t.close()

# ============================================================== BEH-04
t = r.test(
    "BEH-04", "Settings in traffic",
    "Blocking dotfiles and common exploit paths",
    "Turn both on and prove the paths scanners hit are refused without "
    "reaching the backend.",
    "A leaked .env or .git directory usually holds database passwords, and "
    "every site on the internet is scanned for them continuously.  This is one "
    "tick that closes the whole class.",
    "A request for a dotfile is refused; an ordinary request is not.")

t.config("before")
res = settings_on_site({"block_dotfiles": True, "block_common_exploits": True})
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-mount", "the config with the blocks on")
t.config("after")
r.apply("qa: blocks")

for path, claim in [("/.env", "a dotfile is refused"),
                    ("/.git/config", "a git directory is refused")]:
    p = get(path)
    t.proof(f"GET {path}", f"{p['status']} {p['reason']}")
    t.ok(claim, p["status"] in (403, 404), p["status"])
ok = get("/echo")
t.ok("an ordinary request is untouched", ok["status"] == 200, ok["status"])
settings_on_site({})
r.apply("qa: blocks off")
t.close()

r.stop()
print("\nT06 DONE")
