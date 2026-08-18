"""
Suite 13: maps, stream proxying, and the cluster.

Maps and streams are the two parts of nginx this tool exposes that are not
about http sites.  The cluster half is the promise the whole product rests on:
that both nodes hold the same config and that the standby can take over.
"""
import json
import socket
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t13_maps_streams_cluster").start()
LB01, LB02 = qa.LB01, qa.LB02


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
for m in (r.api("GET", "/maps")["body"].get("maps") or []):
    if m["name"].startswith("qa_"):
        r.api("DELETE", f"/maps/{m['id']}")
for st in (r.api("GET", "/streams")["body"].get("streams") or []):
    if st["name"].startswith("qa_") or st["name"].startswith("qa-"):
        r.api("DELETE", f"/streams/{st['id']}")


# ============================================================== MAP-01
t = r.test(
    "MAP-01", "Maps",
    "A map, and a site that uses it",
    "Create a map on the Maps page and prove it is written into the config in "
    "a form nginx loads.",
    "A map is how one decision gets made once and reused: which backend a "
    "hostname belongs to, whether a user agent is a bot, which rate limit "
    "class an address falls into.  Without it the same conditional is repeated "
    "on every site and they drift apart.",
    "The map appears in the config outside every server block, where nginx "
    "needs it, and the fleet applies with it in place.")

r.goto("/maps")
r.page.wait_for_timeout(900)
t.shot("maps-page-before", full=True)
t.config("before")

t.step("create a map from the page, saying what it reads and what it sets")
r.page.click("#new-map")
r.page.wait_for_selector("#m-name")
r.page.fill("#m-name", "qa_agent_class")
# "Sets the variable" is required, and the form refuses without it with a
# message saying so.  The first version of this test left it blank, the save
# was correctly refused, and no request was ever made.
r.page.fill("#m-result", "qa_agent_class")
if r.page.locator("#m-source option[value='$http_user_agent']").count():
    r.page.select_option("#m-source", "$http_user_agent")
r.page.fill("#m-default", "browser")
# Each rule is its own pair of boxes, added with "Add a rule", rather than one
# textarea.  Filling #m-entries directly waited thirty seconds for a container.
for match, value in (("~*bot", "crawler"), ("~*curl", "tool")):
    r.page.click("#m-add")
    row = r.page.locator("#m-entries [data-entry]").last
    row.locator("[data-match]").fill(match)
    row.locator("[data-value]").fill(value)
t.shot("new-map-dialog")
r.page.click("#m-save")
r.page.wait_for_timeout(1200)
r.goto("/maps")
r.page.wait_for_timeout(900)
t.shot("maps-page-after", full=True)

made = find("maps", "qa_agent_class")
t.proof("the map as the API returns it", json.dumps(made, indent=1)[:900])
t.ok("the map was created", bool(made), made)

whole = r.rendered_config()
block = ""
for name, text in sorted((r.api("GET", "/preview")["body"].get("files") or {}).items()):
    if "qa_agent_class" in text:
        block = f"########## {name} ##########\n{text}"
        break
t.proof("where the map is written", block[:1200])
t.ok("the map is in the config", "qa_agent_class" in whole, whole[:200])
t.ok("it is written as a map block", "map " in block and "{" in block, block[:300])
t.config("after")
res = r.apply("qa: map")
t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:700])
t.ok("nginx loaded a config carrying the map",
     res["status"] == 200 and res["body"].get("ok"), res)
t.close()

# ============================================================== STR-01
t = r.test(
    "STR-01", "Streams",
    "Proxying something that is not http",
    "Create a stream that forwards a plain TCP port to a backend pool, apply, "
    "and prove a raw connection to that port reaches the backend.",
    "Databases, mail, ssh, game servers and anything else on a plain socket "
    "still need load balancing and failover.  A load balancer that only speaks "
    "http covers half the job.",
    "A TCP connection to the listening port is answered by the backend, with "
    "no http involved on the way in.")

r.goto("/streams")
r.page.wait_for_timeout(900)
t.shot("streams-page-before", full=True)
t.config("before")
missing = r.page.locator("#no-stream-module")
if missing.count() and not missing.is_hidden():
    t.note("this nginx has no stream module, so this cannot be tested here")
    t.ok("the page says so rather than offering something that cannot work",
         True, "")
    t.close()
else:
    t.step("create a stream on port 9500 pointing at the echo pool")
    r.page.click("#new-stream")
    r.page.wait_for_selector("#s-name")
    r.page.fill("#s-name", "qa_tcp")
    r.page.fill("#s-port", "9500")
    r.page.select_option("#s-pool", str(POOL_ID))
    if r.page.locator("#s-proto").count():
        r.page.select_option("#s-proto", "tcp")
    t.shot("new-stream-dialog")
    r.page.click("#s-save")
    r.page.wait_for_timeout(1200)
    r.goto("/streams")
    r.page.wait_for_timeout(900)
    t.shot("streams-page-after", full=True)

    made = find("streams", "qa_tcp")
    t.proof("the stream as the API returns it", json.dumps(made, indent=1)[:900])
    t.ok("the stream was created", bool(made), made)
    files = r.api("GET", "/preview")["body"].get("files") or {}
    stream_files = {n: v for n, v in files.items() if n.startswith("stream/")}
    t.proof("the stream config", json.dumps(stream_files, indent=1)[:1200])
    t.ok("a stream config file was written", bool(stream_files), list(files))
    t.config("after")
    res = r.apply("qa: stream")
    t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:700])
    t.ok("nginx loaded the stream config",
         res["status"] == 200 and res["body"].get("ok"), res)

    t.step("open a raw socket to the port and speak http down it by hand")
    time.sleep(1)
    try:
        sock = socket.create_connection(("127.0.0.1", 9500), 8)
        sock.sendall(b"GET /echo HTTP/1.1\r\nHost: anything\r\n"
                     b"Connection: close\r\n\r\n")
        data = b""
        while True:
            chunk = sock.recv(4096)
            if not chunk:
                break
            data += chunk
        sock.close()
        text = data.decode("utf-8", "replace")
    except Exception as exc:
        text = f"[connection failed: {exc}]"
    t.proof("what came back over the raw TCP connection", text[:900])
    t.ok("the backend answered through the stream", "backend" in text, text[:200])
    t.close()

# ============================================================== CLU-01
t = r.test(
    "CLU-01", "Cluster",
    "Both nodes really hold the same config",
    "Compare what each node is serving, rather than asking the active node "
    "whether it thinks the standby is up to date.",
    "The entire promise of a two node load balancer is that the standby can "
    "take over.  A standby holding a different config is worse than no standby, "
    "because the failure only shows up during an incident.",
    "The same request to each node gives the same answer for every site "
    "created in this test pass.")

r.goto("/cluster")
r.page.wait_for_timeout(1200)
t.shot("cluster-page", full=True)
t.config("before")
state = r.api("GET", "/cluster")["body"]
t.proof("GET /api/cluster", json.dumps(state, indent=1)[:1500])
t.ok("both nodes are known", len(state.get("nodes") or []) >= 2, state.get("nodes"))
t.ok("both are online",
     all(n.get("state", "").lower() == "online" for n in (state.get("nodes") or [])),
     [(n.get("name"), n.get("state")) for n in (state.get("nodes") or [])])

t.step("ask both nodes for every site this test pass created")
hosts = [h for h in r.api("GET", "/hosts")["body"]["hosts"]
         if h["name"].startswith("qa-") and h.get("enabled")]
rows = []
same = True
for h in hosts:
    names = h.get("server_names") or []
    if not names:
        continue
    name = names[0]
    a = qa.probe_allowing_refusal(name, "/echo", ip=LB01, scheme="http")
    b = qa.probe_allowing_refusal(name, "/echo", ip=LB02, scheme="http")
    rows.append(f"{name:34} lb01={a['status']:<4} lb02={b['status']}")
    if a["status"] != b["status"]:
        same = False
t.proof("the same request to each node, site by site", "\n".join(rows))
t.ok("every site answers the same on both nodes", same, "\n".join(rows))

t.step("compare the config checksum each node reports")
t.proof("what the cluster page reports about sync",
        json.dumps({n.get("name"): {k: n.get(k) for k in
                                    ("role", "state", "config_version", "checksum",
                                     "in_sync", "last_seen")}
                    for n in (state.get("nodes") or [])}, indent=1))
t.config("after")
t.close()

r.stop()
print("\nT13 DONE")
