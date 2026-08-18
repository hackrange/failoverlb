"""
Suite 8: the rest of the settings that only traffic can prove.

Rewrites, content rewriting, redirect and cookie rewriting, websockets,
timeouts, CORS, custom headers and bandwidth limiting.  Each of these is a
setting somebody turns on expecting a visible change at the wire, so that is
where each is checked.
"""
import json
import socket
import ssl
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t08_behaviour2").start()
LB01 = qa.LB01
HOST = f"qa-beh.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-beh")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-beh")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-beh")["id"]
print(f"  test site id {SID}")


def sset(payload):
    return r.api("PUT", f"/hosts/{SID}", {"settings": payload})


def get(path="/echo", **kw):
    return qa.probe(HOST, path, ip=LB01, scheme="http", **kw)


def backend_saw(p):
    try:
        return json.loads(p["body"])
    except Exception:
        return {}


# ============================================================== BEH-05
t = r.test(
    "BEH-05", "Settings in traffic",
    "Rewrite rules",
    "Write a rewrite rule from the site's advanced settings and prove the "
    "backend is asked for the rewritten path.",
    "Rewrites are how an old URL keeps working after an application moves, and "
    "how an application that expects to live in a subdirectory is served from "
    "the root.  They also carry regular expressions, which the ordinary value "
    "checks would refuse, so they have their own handling and their own risk.",
    "A request for the old path arrives at the backend as the new one, with "
    "the visitor's address bar unchanged.")

t.step("read the config before the rule")
t.config("before")
t.site_config("qa-beh", "the site config before any rewrite")
before = get("/old/thing")
t.proof("what the backend saw before the rule",
        json.dumps({"asked for": "/old/thing",
                    "backend saw": backend_saw(get("/old/thing?x=1")).get("path")}, indent=1))

t.step("add a rewrite rule and save")
# Rewritten to /echo so the backend answers with the request it received
# rather than an html page.  The first version rewrote to /new/, which worked
# perfectly and which the test then failed to read, because the proof was in
# the page rather than in json.
res = sset({"rewrite_rules": ["^/old/(.*)$ /echo/$1 last"]})
t.proof("the rule being saved", json.dumps(["^/old/(.*)$ /echo/$1 last"]))
t.ok("the rule saved, backslashes and all", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the site config with the rewrite")
t.ok("the rewrite is in the config", "rewrite ^/old/(.*)$ /echo/$1 last" in cfg,
     [l for l in cfg.splitlines() if "rewrite" in l])
t.config("after")
r.apply("qa: rewrite")

p = get("/old/thing?x=1")
saw = backend_saw(p)
t.proof("GET /old/thing?x=1 through the rewrite", qa.summarise(p, 700))
t.ok("the backend was asked for the rewritten path",
     saw.get("path", "").startswith("/echo/thing"), saw.get("path"))
t.ok("the query string survived the rewrite",
     "x=1" in saw.get("path", ""), saw.get("path"))
t.ok("the visitor was not redirected", p["status"] == 200, p["status"])
sset({})
t.close()

# ============================================================== BEH-06
t = r.test(
    "BEH-06", "Settings in traffic",
    "Rewriting the content that comes back",
    "Add a sub_filter rule and prove the html the visitor receives has been "
    "changed on the way through.",
    "This is how a backend that writes its own hostname into pages is served "
    "under a different name without touching the application.  It is also the "
    "one with the trap that it does nothing at all unless the backend is asked "
    "not to compress, which the tool has to handle for you.",
    "The text the backend sent is not the text the visitor receives.")

t.config("before")
res = sset({"sub_filter_rules": ["'served by' 'delivered by'"]})
t.ok("the rule saved", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the config with content rewriting on")
t.proof("what the one rule wrote",
        "\n".join(l for l in cfg.splitlines()
                  if "sub_filter" in l or "Accept-Encoding" in l))
t.ok("the rule is in the config", "sub_filter 'served by'" in cfg, cfg[:400])
t.ok("the backend is asked not to compress, or there is nothing to replace",
     'proxy_set_header Accept-Encoding ""' in cfg, cfg[:400])
t.config("after")
r.apply("qa: sub filter")

p = get("/page.html")
t.proof("the html the visitor received", p["body"][:500])
t.ok("the replacement happened", "delivered by" in p["body"], p["body"][:300])
t.ok("the original text is gone", "served by" not in p["body"], p["body"][:300])
sset({})
t.close()

# ============================================================== BEH-07
t = r.test(
    "BEH-07", "Settings in traffic",
    "Rewriting a redirect and a cookie by hand",
    "Set proxy_redirect and proxy_cookie_path directly and prove both take "
    "effect, which is the manual version of what the mount tick does for you.",
    "A backend that lives under a different path from the one the visitor "
    "uses will send both a redirect and a cookie built for its own view of "
    "the world.  Somebody who does not want a full mount still needs these two "
    "individually.",
    "A redirect from the backend is rewritten, and a cookie the backend "
    "scopes to its own path is rescoped.")

t.config("before")
res = sset({"proxy_redirect": "/landed /moved-on",
            "proxy_cookie_path": "/app /application"})
t.ok("both settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the config with both rules")
t.proof("the two rules", "\n".join(
    l for l in cfg.splitlines() if "proxy_redirect" in l or "proxy_cookie_path" in l))
t.config("after")
r.apply("qa: redirect and cookie")

red = get("/redirect-here")
t.proof("a redirect from the backend", qa.summarise(red, 400))
# nginx resolves a path only Location against the server name, so the header
# that reaches the browser is absolute.  What matters is the path it points at.
t.ok("the redirect was rewritten",
     (red["headers"].get("Location") or "").endswith("/moved-on"),
     red["headers"].get("Location"))
ck = get("/set-cookie")
t.proof("a cookie from the backend", qa.summarise(ck, 400))
t.ok("the cookie path was rewritten",
     "/application" in ck["headers"].get("Set-Cookie", ""),
     ck["headers"].get("Set-Cookie"))
sset({})
t.close()

# ============================================================== BEH-08
t = r.test(
    "BEH-08", "Settings in traffic",
    "WebSockets",
    "Turn WebSockets on and prove a real upgrade handshake gets through to the "
    "backend with all three headers a websocket needs.",
    "Anything live in a browser is a websocket: chat, dashboards, terminals, "
    "notifications.  Without the upgrade headers the connection is refused or "
    "silently downgraded, and the failure looks like the application rather "
    "than the proxy.",
    "The backend receives Upgrade and Connection headers, and the long read "
    "timeout that stops the connection dying after a minute is set.")

t.config("before")
plain = get("/echo", headers={"Upgrade": "websocket", "Connection": "Upgrade"})
t.proof("an upgrade request with the setting off",
        json.dumps(backend_saw(plain).get("headers", {}), indent=1)[:700])
before_up = backend_saw(plain).get("headers", {}).get("upgrade")

res = sset({"websocket_enabled": True, "websocket_timeout": "3600s"})
t.ok("the setting saved", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the config with websockets on")
t.proof("what the setting wrote", "\n".join(
    l for l in cfg.splitlines()
    if "Upgrade" in l or "upgrade" in l or "read_timeout" in l))
t.ok("the upgrade header is passed on", "proxy_set_header Upgrade $http_upgrade" in cfg,
     cfg[:300])
t.ok("the connection header is set to upgrade",
     'proxy_set_header Connection "upgrade"' in cfg, cfg[:300])
t.ok("the long timeout is set", "proxy_read_timeout 3600s" in cfg, cfg[:300])
t.config("after")
r.apply("qa: websockets")

up = get("/echo", headers={"Upgrade": "websocket", "Connection": "Upgrade"})
saw = backend_saw(up).get("headers", {})
t.proof("what the backend received on an upgrade request",
        json.dumps(saw, indent=1)[:800])
t.ok("the backend was told this is an upgrade",
     saw.get("upgrade") == "websocket", saw.get("upgrade"))
t.ok("the connection header arrived as upgrade",
     (saw.get("connection") or "").lower() == "upgrade", saw.get("connection"))
sset({})
t.close()

# ============================================================== BEH-09
t = r.test(
    "BEH-09", "Settings in traffic",
    "A backend that takes too long",
    "Set a short read timeout and prove a slow backend produces a gateway "
    "timeout rather than holding the visitor forever.",
    "A backend that hangs will hold every worker connection nginx has until "
    "they run out, and then the whole load balancer stops answering for every "
    "site on it.  The timeout is what bounds one bad application's blast "
    "radius.",
    "A backend slower than the timeout gives 504.  A fast one is unaffected.")

t.config("before")
res = sset({"proxy_read_timeout": "2s"})
t.ok("the timeout saved", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the config with a two second read timeout")
t.ok("the timeout is in the config", "proxy_read_timeout 2s" in cfg,
     [l for l in cfg.splitlines() if "read_timeout" in l])
t.config("after")
r.apply("qa: read timeout")

fast = get("/echo")
t.ok("a fast request is unaffected", fast["status"] == 200, fast["status"])
slow = get("/slow/6", timeout=30)
t.proof("a request to a backend that takes six seconds", qa.summarise(slow, 400))
t.ok("a slow backend gives a gateway timeout", slow["status"] == 504, slow["status"])
sset({})
r.apply("qa: timeout back")
t.close()

# ============================================================== BEH-10
t = r.test(
    "BEH-10", "Settings in traffic",
    "CORS and custom response headers",
    "Turn CORS on for a named origin and add a header of our own, then prove "
    "both arrive and that the preflight request browsers send first is "
    "answered.",
    "A single page application on one name calling an API on another needs "
    "this and gets nothing but an unhelpful browser console message without "
    "it.  The preflight is the half people forget.",
    "The allow origin header arrives, an OPTIONS preflight is answered without "
    "reaching the backend, and the custom header is present.")

t.config("before")
res = sset({"cors_enabled": True,
            "cors_allow_origin": ["https://app.example.net"],
            "cors_allow_methods": ["GET", "POST", "OPTIONS"],
            "custom_response_headers": ["X-Served-By failover-lb"]})
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-beh", "the config with CORS and a custom header")
t.proof("what was written", "\n".join(
    l for l in cfg.splitlines() if "Access-Control" in l or "X-Served-By" in l))
t.config("after")
r.apply("qa: cors")

p = get("/echo", headers={"Origin": "https://app.example.net"})
t.proof("a cross origin request", "\n".join(
    f"{k}: {v}" for k, v in sorted(p["headers"].items())))
t.ok("the allow origin header arrived",
     "app.example.net" in (p["headers"].get("Access-Control-Allow-Origin") or ""),
     p["headers"].get("Access-Control-Allow-Origin"))
t.ok("the custom header arrived",
     p["headers"].get("X-Served-By") == "failover-lb", p["headers"].get("X-Served-By"))

pre = get("/echo", method="OPTIONS",
          headers={"Origin": "https://app.example.net",
                   "Access-Control-Request-Method": "POST"})
t.proof("the preflight a browser sends first", qa.summarise(pre, 500))
t.ok("the preflight is answered", pre["status"] in (200, 204), pre["status"])
t.ok("the preflight says which methods are allowed",
     "POST" in (pre["headers"].get("Access-Control-Allow-Methods") or ""),
     pre["headers"].get("Access-Control-Allow-Methods"))
sset({})
r.apply("qa: cors off")
t.close()

r.stop()
print("\nT08 DONE")
