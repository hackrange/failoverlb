"""
Remove everything this test pass created.

Through the API, the same way a person would, so anything that refuses to be
deleted refuses here too rather than being torn out of the database behind the
tool's back.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("cleanup").start()
removed, kept = [], []


def drop(kind, path, name):
    res = r.api("DELETE", path)
    if res["status"] in (200, 204):
        removed.append(f"{kind}: {name}")
    else:
        kept.append(f"{kind}: {name} -> {res['status']} {str(res['body'])[:120]}")


# sites first: pools and certificates cannot go while a site uses them
for h in r.api("GET", "/hosts")["body"]["hosts"]:
    if h["name"].startswith("qa-"):
        drop("site", f"/hosts/{h['id']}", h["name"])

for z in (r.api("GET", "/gslb/zones")["body"].get("zones") or []):
    if z["name"].startswith("qa-"):
        drop("gslb zone", f"/gslb/zones/{z['id']}", z["name"])

for m in (r.api("GET", "/maps")["body"].get("maps") or []):
    if m["name"].startswith("qa_") or m["name"].startswith("qa-"):
        drop("map", f"/maps/{m['id']}", m["name"])

for st in (r.api("GET", "/streams")["body"].get("streams") or []):
    if st["name"].startswith("qa_") or st["name"].startswith("qa-"):
        drop("stream", f"/streams/{st['id']}", st["name"])

zones = r.api("GET", "/zones")["body"]
for kind in ("rate", "conn", "cache"):
    for z in (zones.get(kind) or []):
        if z["name"].startswith("qa_") or z["name"].startswith("qa-"):
            drop(f"{kind} zone", f"/zones/{kind}/{z['id']}", z["name"])

for t in (r.api("GET", "/error-pages")["body"].get("templates") or []):
    if t["name"].startswith("qa_") or t["name"].startswith("qa-"):
        drop("error page template", f"/error-pages/{t['id']}", t["name"])

for p in r.api("GET", "/pools")["body"]["pools"]:
    if p["name"].startswith("qa_") or p["name"].startswith("qa-"):
        drop("pool", f"/pools/{p['id']}", p["name"])

for c in (r.api("GET", "/certs")["body"].get("certs") or []):
    if c["name"].startswith("qa-") or c["name"].startswith("qa_"):
        drop("certificate", f"/certs/{c['id']}", c["name"])

print("REMOVED:")
for line in removed:
    print("  ", line)
if kept:
    print("STILL THERE:")
    for line in kept:
        print("  ", line)

print("\napplying, so the nodes lose the config too")
res = r.apply("qa: removing the test objects")
print("  apply ->", res["status"], json.dumps(res["body"])[:200])

left = [h["name"] for h in r.api("GET", "/hosts")["body"]["hosts"]]
print("\nsites remaining on the fleet:", json.dumps(sorted(left)))
r.stop()
