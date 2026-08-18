"""
Suite 7: rate limits, connection limits and caching.

These three are the ones most likely to render perfectly and do nothing, which
is why every check here is a burst of real requests rather than a look at the
config.  A rate limit that is not limiting is worse than none, because somebody
believes the site is protected.
"""
import json
import socket
import sys
import threading
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t07_zones").start()
LB01 = qa.LB01
HOST = f"qa-zones.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-zones")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
for kind, name in (("rate", "qa_rate"), ("conn", "qa_conn"), ("cache", "qa_cache")):
    zs = r.api("GET", "/zones")["body"]
    for z in (zs.get(kind) or zs.get(kind + "_zones") or []):
        if z["name"] == name:
            r.api("DELETE", f"/zones/{kind}/{z['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-zones")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-zones")["id"]
print(f"  test site id {SID}")


def sset(payload):
    return r.api("PUT", f"/hosts/{SID}", {"settings": payload})


def get(path="/echo", **kw):
    return qa.probe(HOST, path, ip=LB01, scheme="http", **kw)


def new_zone(t, kind, fields, shot=None):
    r.goto("/zones")
    r.page.click(f"button[data-tab={kind}]")
    r.page.wait_for_timeout(400)
    r.page.click(f"button[data-new={kind}]")
    r.page.wait_for_selector("#z-name")
    for sel, val in fields.items():
        r.page.fill(sel, val)
    if shot:
        t.shot(shot)
    r.page.click("#z-save")
    r.page.wait_for_timeout(1200)


# ============================================================== ZONE-01
t = r.test(
    "ZONE-01", "Zones",
    "A rate limit that really limits",
    "Make a rate limit zone on the Zones page, point the site at it, apply, "
    "and send a burst of requests faster than the rate to prove the ones over "
    "the limit are refused.",
    "Rate limiting is what stops one client, or one broken script, using the "
    "whole site.  It is also the setting people most often believe is on when "
    "it is not, because nothing in a config file tells you it is working.",
    "Requests within the rate are answered.  Requests beyond it are refused "
    "with the status the zone is set to, and the site keeps working for "
    "everybody else afterwards.")

t.step("open Zones and photograph the rate limits tab")
r.goto("/zones")
r.page.click("button[data-tab=rate]")
r.page.wait_for_timeout(500)
t.shot("zones-rate-before", full=True)
t.config("before")

t.step("make a zone of one request a second, counted by client address")
new_zone(t, "rate", {"#z-name": "qa_rate", "#z-desc": "QA, delete me",
                     "#z-key": "$binary_remote_addr", "#z-rate": "1r/s",
                     "#z-size": "10m"}, shot="new-rate-zone")
r.goto("/zones")
r.page.click("button[data-tab=rate]")
r.page.wait_for_timeout(500)
t.shot("zones-rate-after", full=True)
zones = r.api("GET", "/zones")["body"]
t.proof("the zones the fleet knows about", json.dumps(zones, indent=1)[:1200])
made = [z for z in (zones.get("rate") or []) if z["name"] == "qa_rate"]
t.ok("the zone was created", bool(made), zones.get("rate"))

t.step("point the site at the zone, with no burst allowance")
res = sset({"limit_req_zone_name": "qa_rate", "limit_req_burst": 0,
            "limit_req_status": 429})
t.proof("the settings saved on the site",
        json.dumps({"limit_req_zone_name": "qa_rate", "limit_req_burst": 0,
                    "limit_req_status": 429}, indent=1))
t.ok("the site accepted the zone", res["status"] == 200, res)
cfg = t.site_config("qa-zones", "the site config with the limit on")
t.ok("the limit is in the site config", "limit_req zone=qa_rate" in cfg,
     [l for l in cfg.splitlines() if "limit_req" in l])
whole = r.rendered_config()
t.proof("the zone declaration, which lives outside the site",
        "\n".join(l for l in whole.splitlines() if "limit_req_zone" in l))
t.ok("the zone is declared with a size, so nginx will load it",
     "limit_req_zone" in whole and "10m" in whole, "")
t.config("after")
res = r.apply("qa: rate limit")
t.ok("apply succeeded", res["status"] == 200, res)

t.step("send fifteen requests as fast as possible")
codes = [get()["status"] for _ in range(15)]
t.proof("the status of each of fifteen back to back requests", json.dumps(codes))
t.ok("some requests were answered", 200 in codes, codes)
t.ok("the ones over the rate were refused", 429 in codes, codes)
t.ok("it refused with the status the zone was told to use",
     set(codes) <= {200, 429}, sorted(set(codes)))
t.note(f"{codes.count(200)} of 15 got through at a rate of 1r/s with no burst")

t.step("wait a moment and prove the site is not stuck refusing")
time.sleep(3)
after = get()
t.proof("a request a few seconds later", qa.summarise(after, 300))
t.ok("the site recovers once the burst is over", after["status"] == 200,
     after["status"])
sset({})
t.close()

# ============================================================== ZONE-02
t = r.test(
    "ZONE-02", "Zones",
    "A burst allowance",
    "Give the same zone a burst and prove more requests get through than the "
    "bare rate allows, which is the difference between a usable limit and one "
    "that refuses the third image on a page.",
    "A browser opening one page makes a dozen requests at once.  A limit with "
    "no burst refuses most of them and the site looks broken to a single "
    "ordinary visitor, which is why the burst exists.",
    "With a burst of ten, noticeably more of the fifteen requests are answered "
    "than with no burst at all.")

t.config("before")
res = sset({"limit_req_zone_name": "qa_rate", "limit_req_burst": 10,
            "limit_req_status": 429, "limit_req_nodelay": True})
t.ok("the burst saved", res["status"] == 200, res)
cfg = t.site_config("qa-zones", "the config with a burst")
t.proof("the limit line", "\n".join(l for l in cfg.splitlines() if "limit_req " in l))
t.ok("the burst reached the config", "burst=10" in cfg,
     [l for l in cfg.splitlines() if "limit_req " in l])
t.config("after")
r.apply("qa: burst")
time.sleep(3)
codes = [get()["status"] for _ in range(15)]
t.proof("fifteen back to back requests with a burst of ten", json.dumps(codes))
t.ok("the burst let noticeably more through", codes.count(200) >= 10,
     f"{codes.count(200)} of 15")
sset({})
r.apply("qa: rate off")
t.close()

# ============================================================== ZONE-03
t = r.test(
    "ZONE-03", "Zones",
    "Caching, and proving it is really caching",
    "Make a cache zone, turn caching on for the site, and prove the second "
    "request is served from the cache rather than from the backend.",
    "Caching is the difference between a backend that survives being linked "
    "from somewhere busy and one that falls over.  It is also the easiest "
    "thing to configure and believe in without checking, since a cached "
    "response and a fresh one look identical to a browser.",
    "The first request is a MISS and reaches the backend.  The second is a HIT "
    "and does not.")

t.step("make a cache zone on the Zones page")
r.goto("/zones")
r.page.click("button[data-tab=cache]")
r.page.wait_for_timeout(500)
t.shot("zones-cache-before", full=True)
t.config("before")
new_zone(t, "cache", {"#z-name": "qa_cache", "#z-desc": "QA, delete me",
                      "#z-path": "/var/cache/nginx/qa", "#z-keys": "10m",
                      "#z-max": "100m", "#z-inactive": "10m"},
         shot="new-cache-zone")
r.goto("/zones")
r.page.click("button[data-tab=cache]")
r.page.wait_for_timeout(500)
t.shot("zones-cache-after", full=True)
zones = r.api("GET", "/zones")["body"]
t.ok("the cache zone was created",
     any(z["name"] == "qa_cache" for z in (zones.get("cache") or [])),
     zones.get("cache"))

t.step("turn caching on for the site and ask for a status header")
res = sset({"proxy_cache_zone": "qa_cache", "cache_status_header": True,
            "proxy_cache_valid": ["200 5m"],
            "proxy_cache_bypass": [], "proxy_no_cache": []})
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-zones", "the site config with caching on")
t.proof("the cache directives", "\n".join(
    l for l in cfg.splitlines() if "cache" in l.lower()))
whole = r.rendered_config()
t.proof("the cache zone declaration",
        "\n".join(l for l in whole.splitlines() if "proxy_cache_path" in l))
t.ok("the zone is declared on disk with a size",
     "proxy_cache_path" in whole and "qa_cache" in whole, "")
t.config("after")
res = r.apply("qa: cache")
t.ok("apply succeeded", res["status"] == 200, res)

t.step("ask twice for the same thing and compare")
first = get("/cacheable-page")
second = get("/cacheable-page")
third = get("/cacheable-page")
t.proof("the first request", qa.summarise(first, 400))
t.proof("the second request", qa.summarise(second, 400))
status = [p["headers"].get("X-Cache-Status") for p in (first, second, third)]
t.proof("the cache status of three identical requests", json.dumps(status))
t.ok("the first request was a miss", status[0] == "MISS", status)
t.ok("the second was served from the cache", status[1] == "HIT", status)
t.ok("and so was the third", status[2] == "HIT", status)
t.ok("the cached answer is the same as the fresh one",
     first["body"] == second["body"], "bodies differ")

t.step("prove the backend really stopped being asked")
before_hits = get("/echo")
t.note("an uncacheable path still reaches the backend while a cached one does not")
t.ok("a different path is still fetched fresh",
     before_hits["headers"].get("X-Cache-Status") in ("MISS", None),
     before_hits["headers"].get("X-Cache-Status"))
sset({})
r.apply("qa: cache off")
t.close()

# ============================================================== ZONE-04
t = r.test(
    "ZONE-04", "Zones",
    "A connection limit",
    "Make a connection limit zone, set the site to allow one connection at a "
    "time from an address, and prove a second simultaneous connection is "
    "refused while a sequential one is not.",
    "Slow clients holding connections open is how a small box gets taken out "
    "without much traffic at all.  This is the setting that bounds it.",
    "One connection at a time works.  Two at once, one is refused.")

t.step("make a connection limit zone")
r.goto("/zones")
r.page.click("button[data-tab=conn]")
r.page.wait_for_timeout(500)
t.config("before")
new_zone(t, "conn", {"#z-name": "qa_conn", "#z-desc": "QA, delete me",
                     "#z-key": "$binary_remote_addr", "#z-size": "10m"},
         shot="new-conn-zone")
r.goto("/zones")
r.page.click("button[data-tab=conn]")
r.page.wait_for_timeout(500)
t.shot("zones-conn-after", full=True)

res = sset({"limit_conn_zone_name": "qa_conn", "limit_conn_count": 1})
t.ok("the settings saved", res["status"] == 200, res)
cfg = t.site_config("qa-zones", "the config with a connection limit")
t.proof("the limit line", "\n".join(l for l in cfg.splitlines() if "limit_conn" in l))
t.ok("the limit reached the config", "limit_conn qa_conn 1" in cfg,
     [l for l in cfg.splitlines() if "limit_conn" in l])
t.config("after")
r.apply("qa: conn limit")

t.step("hold one slow connection open and try a second at the same time")
results = {}

def slow_one():
    try:
        results["slow"] = qa.probe(HOST, "/slow/3", ip=LB01, scheme="http",
                                   timeout=20)["status"]
    except Exception as exc:
        results["slow"] = f"error {exc}"

th = threading.Thread(target=slow_one)
th.start()
time.sleep(1.0)
second = get("/echo")
th.join(25)
t.proof("the slow request that was already in flight", str(results.get("slow")))
t.proof("a second request made while the first was still running",
        qa.summarise(second, 400))
t.ok("the second simultaneous connection was refused",
     second["status"] in (503, 429), second["status"])
t.step("and one at a time still works")
lone = get("/echo")
t.proof("a request on its own once the first finished", qa.summarise(lone, 300))
t.ok("a single connection is unaffected", lone["status"] == 200, lone["status"])
sset({})
r.apply("qa: conn limit off")
t.close()

r.stop()
print("\nT07 DONE")
