"""
Suite 2: backend pools.

A pool is the thing a site proxies to, so everything after this depends on it.
Traffic is real: three echo backends on 9101, 9102 and 9103 that report the
request nginx actually made, which is the only way to tell a balanced pool from
a stuck one, or a failed over pool from one that is quietly serving errors.
"""
import json
import subprocess
import sys
import time
import urllib.request
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t02_pools").start()
NODE = qa.BACKEND_HOST
POOL = "qa_pool"
SITE_NAME = "qa-lb"
SITE_HOST = f"qa-lb.{qa.DOMAIN}"


def control(port, what):
    """Each backend has an always-on control port at data port + 100."""
    return urllib.request.urlopen(
        f"http://{NODE}:{port + 100}/{what}", timeout=10).read().decode()


def backends(state):
    """Take the two primary backends away, or give them back."""
    return [control(9101, state), control(9102, state)]


def hit(path="/echo", host=SITE_HOST, scheme="http", ip="127.0.0.1", n=1):
    out = []
    for _ in range(n):
        p = qa.probe(host, path, ip=ip, scheme=scheme)
        try:
            out.append(json.loads(p["body"])["backend"])
        except Exception:
            out.append(f"[{p['status']}]")
    return out


def find(kind, name):
    got = r.api("GET", f"/{kind}")
    body = got["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    for x in rows:
        if x["name"] == name:
            return x
    return None


# --------------------------------------------------------------- clean slate
for host in (find("hosts", SITE_NAME),):
    if host:
        r.api("DELETE", f"/hosts/{host['id']}")
        print("  removed leftover site")
for pool in (find("pools", POOL),):
    if pool:
        r.api("DELETE", f"/pools/{pool['id']}")
        print("  removed leftover pool")
backends("start")
time.sleep(1)

# ============================================================== POOL-01
t = r.test(
    "POOL-01", "Backend pools",
    "Create a pool from the Backend Pools page",
    "Press New pool, fill the dialog and prove the pool exists afterwards and "
    "is offered to a site.",
    "A pool is the list of servers behind one name.  It is the first thing "
    "anybody makes, and everything on the site form points at one.",
    "The pool appears in the list and is selectable when a site is created.")

t.step("open Backend Pools and photograph it as it is now")
r.goto("/pools")
t.shot("pools-before", full=True)
t.config("before")

t.step("press New pool, fill in the name, method and health check path")
r.page.click("#new-pool")
r.page.wait_for_selector("#p-name")
r.page.fill("#p-name", POOL)
r.page.fill("#p-desc", "QA test pool, delete me")
r.page.select_option("#p-lb", "round_robin")
r.page.fill("#p-path", "/health")
t.shot("new-pool-dialog")
r.page.click("#p-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(900)
t.shot("pools-after", full=True)

p = find("pools", POOL)
t.ok("the pool exists after the dialog was saved", bool(p), p)
t.proof("the pool as the API returns it", json.dumps(p, indent=1)[:1200])
POOL_ID = p["id"]
t.close()

# ============================================================== POOL-02
t = r.test(
    "POOL-02", "Backend pools",
    "Add backends to a pool",
    "Add two real servers through Add backend and prove they reach the "
    "rendered upstream block with the right address and port.",
    "A pool with no servers is a 502.  Adding servers is the most common thing "
    "done on this page.",
    "Both servers appear on the page and in the upstream block that a site's "
    "proxy_pass will point at.")

r.goto(f"/pools/{POOL_ID}")
t.shot("pool-detail-empty", full=True)
t.proof("the upstream file before any backends were added",
        r.file_named(f"upstreams/{POOL}.conf") or "[no upstream file yet]")
t.config("before")

t.step(f"add {NODE}:9101 and {NODE}:9102 through Add backend")
for port in (9101, 9102):
    r.page.click("#add-member")
    r.page.wait_for_selector("#nm-addr")
    r.page.fill("#nm-addr", NODE)
    r.page.fill("#nm-port", str(port))
    if port == 9101:
        t.shot("add-backend-dialog")
    r.page.click("#nm-save")
    r.page.wait_for_timeout(700)

r.goto(f"/pools/{POOL_ID}")
t.shot("pool-detail-two-members", full=True)
t.config("after")

members = r.api("GET", f"/pools/{POOL_ID}")["body"]["members"]
t.proof("the members as the API returns them", json.dumps(members, indent=1)[:1500])
t.ok("two backends are on the pool", len(members) == 2, len(members))

up = r.file_named(f"upstreams/{POOL}.conf")
t.proof("the upstream file after the two backends were added", up)
t.ok("the upstream names both servers",
     f"{NODE}:9101" in up and f"{NODE}:9102" in up, up[:400])
t.close()

# ============================================================== POOL-03
t = r.test(
    "POOL-03", "Backend pools",
    "A site in front of the pool, with traffic reaching both servers",
    "Create a site that proxies to the pool, apply for real, and send requests "
    "until both backends have answered.",
    "This is the whole point of a load balancer.  If requests only ever land "
    "on one server the second is decoration, and nobody finds out until the "
    "first one dies.",
    "nginx answers on port 80 for the site name and both backends take traffic.")

t.step("create the site through the New site dialog")
r.goto("/sites")
t.shot("sites-before", full=True)
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", SITE_NAME)
r.page.fill("#s-names", SITE_HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
t.shot("new-site-dialog")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
site = find("hosts", SITE_NAME)
t.ok("the site was created", bool(site), site)
SITE_ID = site["id"]
t.proof("the site as the API returns it", json.dumps(site, indent=1)[:1200])

t.step("photograph the site's nginx config tab before applying")
r.goto(f"/sites/{SITE_ID}")
r.page.click("button[data-tab=config]")
r.page.wait_for_timeout(1500)
t.shot("site-config-tab", full=True)
t.config("before")
t.proof("the site's config file as rendered", r.file_named(f"sites/{SITE_HOST}.conf"))

# Wait for the health checker to have seen the backends before applying.
#
# A pool whose members have not been checked yet is a pool with no healthy
# members, and the renderer leaves an empty upstream out on purpose, which
# takes the site with it.  So an apply run seconds after the pool was made
# renders a site that is not there, every request gets the default server's
# 404, and the suite reports a routing defect that is really its own hurry.
# That happened on 19 August: the pool was up thirty seconds later with
# everything passing.
t.step("wait for the health checker to have seen the backends")
_healthy_after = None
for _ in range(60):
    # The pool listing reports counts, not members: healthy, total and a
    # status.  Reading a members list off it gives an empty list every time,
    # so the wait never finished and reported the backends as never coming up
    # while they were sitting there healthy.
    _pool = find("pools", POOL) or {}
    if int(_pool.get("healthy") or 0) >= 2:
        _healthy_after = _
        break
    time.sleep(1)
t.proof("how long the pool took to report healthy",
        f"{_healthy_after} seconds" if _healthy_after is not None
        else "it never reported two healthy backends within 60 seconds")
t.ok("the pool has healthy backends before anything is applied",
     _healthy_after is not None,
     "the backends never came up, so what follows would be measuring an "
     "empty upstream rather than load balancing")

t.step("press Apply config, which stages and tests on every node before any applies")
res = r.apply("qa: pool and site")
t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:1200])
t.ok("apply reported success", res["status"] == 200 and res["body"].get("ok"), res)
t.ok("it applied to more than one node",
     len(res["body"].get("applied_to", [])) >= 1, res["body"].get("applied_to"))
t.config("after")

t.step("send twenty requests and record which backend answered each")
first = qa.probe(SITE_HOST, "/echo", ip="127.0.0.1", scheme="http")
t.proof("one request and its answer in full", qa.summarise(first, 900))
seen = hit(n=20)
t.proof("twenty requests, backend by backend", json.dumps(seen))
t.ok("the site answers over http", first["status"] == 200, first["status"])
t.ok("both backends took traffic", set(seen) == {"backend1", "backend2"}, sorted(set(seen)))
t.ok("round robin split it evenly",
     abs(seen.count("backend1") - seen.count("backend2")) <= 2,
     f"backend1={seen.count('backend1')} backend2={seen.count('backend2')}")

t.step("prove the standby node got the same config, not just this one")
lb02 = qa.probe(SITE_HOST, "/echo", ip=qa.LB02, scheme="http")
t.proof("the same request sent to lb02 instead of lb01", qa.summarise(lb02, 600))
t.ok("the standby serves the new site too", lb02["status"] == 200, lb02["status"])
t.close()

# ============================================================== POOL-04
t = r.test(
    "POOL-04", "Backend pools",
    "Weights",
    "Give one server three times the weight of the other and prove the split "
    "follows.",
    "Servers are rarely the same size.  A weight is how somebody puts a bigger "
    "box to work without replacing the smaller one.",
    "Over forty requests the weighted server takes roughly three times as many.")

r.goto(f"/pools/{POOL_ID}")
t.shot("members-before-weight")
t.proof("the upstream before the weight change", r.file_named(f"upstreams/{POOL}.conf"))
t.config("before")

t.step("set the first backend's weight to 3")
rows = r.api("GET", f"/pools/{POOL_ID}")["body"]["members"]
m1 = [m for m in rows if m["port"] == 9101][0]
r.api("PUT", f"/members/{m1['id']}", {"weight": 3})
r.goto(f"/pools/{POOL_ID}")
t.shot("members-after-weight")
up = r.file_named(f"upstreams/{POOL}.conf")
t.proof("the upstream after the weight change", up)
t.ok("the upstream carries weight=3", "weight=3" in up, up[:400])
t.config("after")

res = r.apply("qa: weight")
t.ok("apply succeeded", res["status"] == 200, res)
seen = hit(n=40)
c1, c2 = seen.count("backend1"), seen.count("backend2")
t.proof("forty requests, counted",
        f"backend1 (weight 3): {c1}\nbackend2 (weight 1): {c2}\n\n{json.dumps(seen)}")
t.ok("the weighted backend took about three times the traffic",
     c2 > 0 and 2.0 <= c1 / max(c2, 1) <= 4.5, f"{c1}:{c2}")

t.step("put the weight back to 1")
r.api("PUT", f"/members/{m1['id']}", {"weight": 1})
r.apply("qa: weight back")
t.close()

# ============================================================== POOL-05
t = r.test(
    "POOL-05", "Backend pools",
    "A backup server takes over only when the others are gone",
    "Add a third server marked Backup only, prove it gets nothing while the "
    "others are healthy, then stop both primaries and prove it takes over "
    "without the site going down.",
    "This is the standby web server everybody has and nobody tests.  Worth "
    "knowing it works before the day it is needed.",
    "Zero requests reach the backup while the primaries are up; every request "
    "reaches it once they are stopped, and the site keeps answering 200.")

t.step("add backend3 on 9103 as Backup only")
r.goto(f"/pools/{POOL_ID}")
r.page.click("#add-member")
r.page.wait_for_selector("#nm-addr")
r.page.fill("#nm-addr", NODE)
r.page.fill("#nm-port", "9103")
r.page.check("#nm-backup")
t.shot("add-backup-dialog")
r.page.click("#nm-save")
r.page.wait_for_timeout(900)
r.goto(f"/pools/{POOL_ID}")
t.shot("pool-with-backup", full=True)
up = r.file_named(f"upstreams/{POOL}.conf")
t.proof("the upstream with a backup server in it", up)
t.ok("the third server is marked backup", "9103" in up and "backup" in up, up[:600])
t.config("before")
res = r.apply("qa: backup member")
t.ok("apply succeeded", res["status"] == 200, res)
t.config("after")

t.step("with all three healthy, see who answers")
seen = hit(n=12)
t.proof("twelve requests while all three are up", json.dumps(seen))
t.ok("the backup took nothing while the primaries were up",
     "backend3" not in seen, sorted(set(seen)))

t.step("stop both primary backends, the way a real outage would")
t.proof("the two primaries taken away", str(backends("stop")))
time.sleep(2)
seen = hit(n=8)
t.proof("eight requests with both primaries stopped", json.dumps(seen))
t.ok("the backup took over", seen.count("backend3") >= 6, seen)
t.ok("the site never returned an error while failing over",
     all(s == "backend3" for s in seen), seen)

t.step("start the primaries again and confirm traffic comes back to them")
t.proof("the two primaries given back", str(backends("start")))
t.note("nginx will not retry a server it has marked failed until fail_timeout "
       "has passed, which is 10 seconds by default, so an immediate retry "
       "still lands on the backup and that is correct rather than a fault")
early = hit(n=4)
time.sleep(14)
seen = hit(n=12)
t.proof("four requests straight after the primaries came back, then twelve "
        "more once fail_timeout had passed",
        f"immediately: {json.dumps(early)}\nafter 14s:   {json.dumps(seen)}")
t.ok("traffic returned to the primaries once fail_timeout expired",
     "backend1" in seen or "backend2" in seen, seen)
t.ok("the backup stopped taking traffic once the primaries were back",
     seen.count("backend3") <= 1, seen)
t.close()

# ============================================================== POOL-06
t = r.test(
    "POOL-06", "Backend pools",
    "Active health checking marks a sick backend down",
    "Make one backend fail its health check on purpose and prove the manager "
    "notices, shows it, and takes it out of the config.",
    "nginx on its own only notices a backend is dead after it has already sent "
    "somebody's request to it.  Active checking is what stops a user being the "
    "one who finds out.",
    "The pool page shows the backend down within a few intervals, and the "
    "rendered upstream marks it down so no traffic goes there.")

t.step("open the pool's Active health checks tab")
r.goto(f"/pools/{POOL_ID}")
r.page.click("button[data-tab=health]")
r.page.wait_for_timeout(500)
t.shot("health-settings-before", full=True)
t.step("set the check to a fast interval so this does not take a minute")
r.page.fill("#h-interval", "3")
r.page.fill("#h-fall", "2")
r.page.fill("#h-rise", "2")
r.page.fill("#h-path", "/health")
r.page.click("#save-pool")
r.page.wait_for_timeout(1500)
r.goto(f"/pools/{POOL_ID}")
r.page.click("button[data-tab=health]")
r.page.wait_for_timeout(500)
t.shot("health-settings-after", full=True)
t.ok("the health check settings read back after saving",
     r.page.locator("#h-interval").input_value() == "3",
     r.page.locator("#h-interval").input_value())
t.config("before")

t.step("tell backend2 to start failing its health check")
before_state = r.api("GET", f"/pools/{POOL_ID}")["body"]["members"]
t.proof("member states while healthy",
        json.dumps([{k: m[k] for k in ("address", "port", "state", "enabled")}
                    for m in before_state], indent=1))
control(9102, "sick")

deadline = time.time() + 45
state = None
while time.time() < deadline:
    time.sleep(3)
    ms = r.api("GET", f"/pools/{POOL_ID}")["body"]["members"]
    state = {m["port"]: m["state"] for m in ms}
    if str(state.get(9102, "")).lower().endswith("down"):
        break
t.proof("member states after backend2 was made sick", json.dumps(state, indent=1))
r.goto(f"/pools/{POOL_ID}")
t.shot("pool-with-a-down-member", full=True)
t.ok("the manager noticed backend2 is down",
     "down" in str(state.get(9102, "")).lower(), state)

up = r.file_named(f"upstreams/{POOL}.conf")
t.proof("the upstream once the check had failed", up)
t.config("after")
t.ok("the down backend is marked down in the config",
     "9102" in up and "down" in up, up[:600])

t.step("apply, then prove no traffic reaches the sick backend")
r.apply("qa: health check down")
seen = hit(n=12)
t.proof("twelve requests with backend2 sick", json.dumps(seen))
t.ok("nothing reached the sick backend", "backend2" not in seen, seen)

t.step("make it well again and prove it comes back")
control(9102, "well")
deadline = time.time() + 45
while time.time() < deadline:
    time.sleep(3)
    ms = r.api("GET", f"/pools/{POOL_ID}")["body"]["members"]
    state = {m["port"]: m["state"] for m in ms}
    if "up" in str(state.get(9102, "")).lower():
        break
t.proof("member states after recovery", json.dumps(state, indent=1))
t.ok("the recovered backend came back up", "up" in str(state.get(9102, "")).lower(), state)
r.apply("qa: health check up")
seen = hit(n=12)
t.proof("twelve requests after recovery", json.dumps(seen))
t.ok("traffic went back to it", "backend2" in seen, seen)
t.close()

r.stop()
print("\nT02 DONE")
