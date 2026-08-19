"""
Suite 11: importing an existing config, and repairing one that will not load.

The config imported here is written for this test.  It carries, on purpose,
every shape that has caused a failed import on this project: a directive given
twice in one block, two locations with the same path, a limit_req referring to
a zone nobody declared, and an ssl directive in a block that cannot hold one.

Nothing here is anybody's real config.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t11_import_repair").start()
LB01 = qa.LB01

BROKEN = """
# An ordinary looking config that nginx will not load.
#
# The upstream carries the qa prefix for one reason: importing it makes a real
# pool on the fleet, and cleanup.py finds this pass's objects by that prefix.
# Called app_servers, which is what it was, the pool it created was recognised
# by nothing and was still on the fleet after the run.
upstream qa_app_servers {
    server %(backend)s:9101;
    server %(backend)s:9102;
    keepalive 32;
}

server {
    listen 80;
    server_name qa-import.%(domain)s;

    client_max_body_size 20m;
    client_max_body_size 50m;

    proxy_buffering off;

    location /monitoring {
        proxy_pass http://qa_app_servers;
        proxy_buffering off;
        proxy_buffering off;
    }

    location /monitoring {
        proxy_pass http://qa_app_servers;
    }

    location /api {
        limit_req zone=one burst=20 nodelay;
        limit_conn perip 5;
        proxy_pass http://qa_app_servers;
        proxy_buffering off;
    }

    location /static {
        root %(static)s;
        ssl_certificate /etc/ssl/nowhere.pem;
        ssl_certificate_key /etc/ssl/nowhere.key;
    }

    location / {
        proxy_pass http://qa_app_servers;
    }
}
""" % {"backend": qa.BACKEND_HOST, "domain": qa.DOMAIN,
       "static": qa.STATIC_DIR}


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


for n in ("qa-import", f"qa-import.{qa.DOMAIN}"):
    x = find("hosts", n)
    if x:
        r.api("DELETE", f"/hosts/{x['id']}")


# ============================================================== IMP-01
t = r.test(
    "IMP-01", "Importing",
    "Reading an existing nginx config and saying what it found",
    "Paste a real shaped config into the Import page, ask for a preview, and "
    "prove it reports the sites, the backends and the paths it can see before "
    "anything is written.",
    "Nobody starts with an empty load balancer.  The first thing anybody does "
    "with a tool like this is point it at the config they already have, and if "
    "that step is painful they stop there.",
    "The preview names the site, the upstream and every path, and it writes "
    "nothing until asked.")

t.step("open the Import page and paste the config")
r.goto("/import")
r.page.wait_for_timeout(800)
t.shot("import-page-empty", full=True)
t.config("before")
r.page.fill("#config", BROKEN)
t.proof("the config being imported", BROKEN)
t.shot("import-page-pasted", full=True)

t.step("ask for a preview")
prev = r.api("POST", "/import/preview", {"config": BROKEN})
t.proof("POST /api/import/preview", json.dumps(prev["body"], indent=1)[:2500])
t.ok("the preview was produced", prev["status"] == 200, prev)
body = prev["body"] if isinstance(prev["body"], dict) else {}
hosts = body.get("hosts") or body.get("sites") or []
pools = body.get("pools") or body.get("upstreams") or []
t.ok("it found the site", any("qa-import" in json.dumps(h) for h in hosts), hosts)
t.ok("it found the backends", bool(pools), pools)
paths = json.dumps(hosts)
for p in ("/monitoring", "/api", "/static", "/"):
    t.ok(f"it found the path {p}", f'"{p}"' in paths, paths[:400])
t.ok("nothing was written by a preview", not find("hosts", "qa-import"),
     "a site appeared before the import was confirmed")
t.close()

# ============================================================== IMP-02
t = r.test(
    "IMP-02", "Importing",
    "Importing a config that nginx would refuse",
    "Import the same config for real and prove the result is config nginx will "
    "load, with the duplicates and the dangling references dealt with rather "
    "than copied across.",
    "A config that has drifted over years is exactly the config people want to "
    "import, and it usually has a duplicate directive or a location written "
    "twice in it.  Copying those faithfully produces a fleet that cannot "
    "apply anything, which is the worst possible first impression.",
    "The import succeeds, the site exists, and the rendered config has no "
    "directive twice in one block and no path twice.")

t.step("press Import")
res = r.api("POST", "/import", {"config": BROKEN})
t.proof("POST /api/import", json.dumps(res["body"], indent=1)[:2000])
t.ok("the import was accepted", res["status"] == 200, res)
r.goto("/sites")
r.page.wait_for_timeout(1000)
t.shot("sites-after-import", full=True)

site = find("hosts", "qa-import") or find("hosts", f"qa-import.{qa.DOMAIN}")
t.ok("the site was created", bool(site), [h["name"] for h in r.api("GET", "/hosts")["body"]["hosts"]])
SID = site["id"]

t.step("switch it on, or there is no config to look at")
# A disabled site renders no file at all.  The first version of this test read
# that empty string and reported no duplicate directives and no duplicate
# paths, which is the "a pass that touched nothing" failure this project's
# own notes warn about.  Enable first, then look.
detail = r.api("GET", f"/hosts/{SID}")["body"]
t.proof("the imported site as the API returns it",
        json.dumps({k: detail.get(k) for k in
                    ("name", "enabled", "mode", "server_names", "pool")}, indent=1))
t.ok("an imported site is created switched off, so it cannot take traffic "
     "before anybody has looked at it", detail.get("enabled") is False,
     detail.get("enabled"))
r.goto(f"/sites/{SID}")
r.page.wait_for_timeout(900)
r.page.check("#f-enabled")
r.page.click("#save-site")
r.page.wait_for_timeout(1400)
cfg = t.site_config(site["name"], "the config the import produced")
t.config("after")

def dupes_in_blocks(text):
    """Any directive written twice inside the same block."""
    out, stack = [], [{}]
    for raw in text.splitlines():
        line = raw.split("#")[0].strip()
        if not line:
            continue
        if line.endswith("{"):
            stack.append({})
            continue
        if line == "}":
            if len(stack) > 1:
                stack.pop()
            continue
        if line.endswith(";"):
            name = line.split()[0]
            if name in ("add_header", "proxy_set_header", "server", "listen",
                        "sub_filter", "proxy_redirect", "error_page",
                        "proxy_hide_header", "limit_req", "ssl_conf_command",
                        "proxy_cache_valid", "gzip_types", "try_files",
                        "return", "rewrite", "allow", "deny", "include",
                        "set", "if", "more_clear_headers", "more_set_headers"):
                continue
            block = stack[-1]
            if line in block:
                continue
            if name in block:
                out.append(f"{name}: {block[name]!r} and {line!r}")
            block[name] = line
    return out

dup = dupes_in_blocks(cfg)
t.proof("directives written twice in the same block",
        "\n".join(dup) if dup else "none")
t.ok("no directive is written twice in one block", not dup, dup)

locs = [l.strip() for l in cfg.splitlines() if l.strip().startswith("location ")]
t.proof("every location block in the result", "\n".join(locs))
t.ok("no path is written twice", len(locs) == len(set(locs)), locs)

t.step("ask the fleet to load it, which is the only real test")
res = r.apply("qa: imported config")
t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:1200])
t.ok("nginx loaded the imported config",
     res["status"] == 200 and res["body"].get("ok"), res)

p = qa.probe(f"qa-import.{qa.DOMAIN}", "/echo", ip=LB01, scheme="http")
t.proof("a request to the imported site once it is switched on",
        qa.summarise(p, 500))
t.ok("the imported site answers", p["status"] == 200, p["status"])
t.close()

# ============================================================== REP-01
t = r.test(
    "REP-01", "Repair",
    "Finding and fixing a config nginx will not load",
    "Put a site into a state nginx refuses, press Check and repair, and prove "
    "it shows exactly what it would change before changing anything, then "
    "fixes it when told to.",
    "An apply that fails leaves a change stuck with an error naming a file and "
    "a line number.  Working back from that to the setting that caused it is "
    "the slowest thing anybody does with this tool.  A preview that names the "
    "lines is the difference between a minute and an afternoon.",
    "The preview lists the offending lines and changes nothing.  Confirming "
    "comments them out, and the fleet applies afterwards.")

t.step("break the site the way the real incident did")
# Not through the raw config editor: that one runs nginx -t before it saves and
# refuses anything nginx will not load, which is the right behaviour and means
# a broken config cannot be created that way.  This is the route the real
# failures took, a snippet naming a certificate that is not on disk.
BAD = ("ssl_certificate /etc/ssl/does-not-exist.pem;\n"
       "ssl_certificate_key /etc/ssl/does-not-exist.key;")
res = r.api("PUT", f"/hosts/{SID}", {"custom_config": BAD})
t.proof("the snippet that was added to the site", BAD)
t.ok("the tool stored it", res["status"] == 200, res)
t.note("a certificate that is not there, which nginx refuses at load")

t.step("prove the fleet refuses to apply it")
res = r.apply("qa: deliberately broken")
t.proof("POST /api/apply with the broken site",
        json.dumps(res["body"], indent=1)[:1200])
t.ok("the apply was refused rather than breaking the fleet",
     res["status"] != 200 or not res["body"].get("ok"), res)
t.ok("the refusal names the reason",
     "ssl" in json.dumps(res["body"]).lower()
     or "cannot load" in json.dumps(res["body"]).lower(),
     json.dumps(res["body"])[:400])
t.config("before")

t.step("open the Changes page and press Check and repair")
r.goto("/changes")
r.page.wait_for_timeout(1200)
t.shot("changes-page-broken", full=True)
preview = r.api("POST", "/repair", {})
t.proof("POST /api/repair with no confirmation, which is preview only",
        json.dumps(preview["body"], indent=1)[:1800])
t.ok("the preview was produced", preview["status"] == 200, preview)
changes = (preview["body"] or {}).get("changes") or []
t.ok("it found something to change", bool(changes), preview["body"])
t.ok("a preview changed nothing",
     "does-not-exist" in r.file_named(f"sites/{site['name']}.conf"),
     "the config changed before anybody confirmed the repair")

t.step("confirm the repair")
done = r.api("POST", "/repair", {"confirm": True})
t.proof("POST /api/repair with confirmation",
        json.dumps(done["body"], indent=1)[:1500])
t.ok("the repair was applied to the stored config", done["status"] == 200, done)
after = r.file_named(f"sites/{site['name']}.conf")
t.proof("the repaired config", after[:1800])
t.ok("the offending lines are commented out rather than deleted",
     "# ssl_certificate /etc/ssl/does-not-exist.pem" in after
     or "#ssl_certificate /etc/ssl/does-not-exist.pem" in after,
     [l for l in after.splitlines() if "does-not-exist" in l])
t.config("after")

t.step("and the fleet applies again")
# A moment's pause.  The repair commits its own transaction and SQLite takes
# one writer at a time, so an apply fired the same instant is refused by the
# driver rather than by us.  The endpoint now says so with a 503 instead of a
# bare 500, and this waits rather than racing it on purpose.
time.sleep(3)
res = r.apply("qa: after the repair")
t.proof("POST /api/apply after the repair", json.dumps(res["body"], indent=1)[:900])
t.ok("the fleet can apply again", res["status"] == 200 and res["body"].get("ok"), res)
p = qa.probe(f"qa-import.{qa.DOMAIN}", "/echo", ip=LB01, scheme="http")
t.ok("the site is serving again", p["status"] == 200, p["status"])
t.close()

# Leave nothing behind that stops the fleet applying.
#
# This suite deliberately creates a site whose config nginx will not load, and
# then repairs it.  When the repair does not complete, and on 19 August it did
# not because the agent took longer than sixty seconds to answer test_staging,
# the site is left **enabled** carrying a certificate path that does not
# exist.  Every apply after that is refused at prepare, correctly, and every
# suite that runs afterwards fails on something that has nothing to do with
# it: that day it took t12, t13 and t17 with it, 32 failures that were all one
# leftover.
#
# So the site is switched off whatever happened.  Off rather than deleted,
# because if the repair did fail the config is the evidence and somebody will
# want to look at it.
print("\n  making sure nothing is left that would stop the fleet applying")
_left = find("hosts", "qa-import") or find("hosts", f"qa-import.{qa.DOMAIN}")
if _left:
    _cfg = r.api("GET", f"/hosts/{_left['id']}")["body"]
    _still_broken = "does-not-exist" in json.dumps(_cfg)
    if _still_broken:
        print("   the repair did not finish, so the site is being switched off "
              "rather than left to refuse every apply on the fleet")
        res = r.api("PUT", f"/hosts/{_left['id']}", {"enabled": False})
        print("   disabled ->", res["status"])
        res = r.apply("qa: after switching the unrepaired site off")
        print("   apply ->", res["status"])
    else:
        print("   the repair finished, nothing to switch off")

r.stop()
print("\nT11 DONE")
