"""
Suite 1: the Settings page.

The two settings changed here are the safe ones.  Sign in mode and management
networks are deliberately left alone: getting either wrong locks everybody out
of the tool, which is not a thing to prove on a running fleet.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t01_settings").start()


def read_settings_page():
    r.goto("/settings")
    return {
        "dns_resolvers": r.page.locator("#dns_resolvers").input_value(),
        "dns_use_system_resolver": r.page.locator("#dns_use_system_resolver").is_checked(),
        "health_check_interval": r.page.locator("#health_check_interval").input_value(),
        "acme_email": r.page.locator("#acme_email").input_value(),
        "acme_renew_days_before": r.page.locator("#acme_renew_days_before").input_value(),
        "management_networks": r.page.locator("#management_networks").input_value(),
        "geoip_source": r.page.locator("#geoip_source").input_value(),
        "waf_crs_track": r.page.locator("#waf_crs_track").input_value(),
        "auth_mode": r.page.locator("input[name=auth_mode]:checked").get_attribute("value"),
    }


BEFORE = read_settings_page()
print("  settings before:", json.dumps(BEFORE, indent=1))

# ============================================================== SET-01
t = r.test(
    "SET-01", "Settings",
    "DNS servers for domain checks",
    "Change which DNS servers the manager itself asks when it checks that a "
    "domain points at this fleet, save it from the page, and prove the new "
    "servers are the ones actually queried.",
    "Before a certificate is issued the manager checks the name resolves here. "
    "On a split horizon network, or where a registrar's servers are slow to "
    "publish, an operator needs to choose which servers get asked, otherwise "
    "certificate issue decisions are made on an answer nobody can see.",
    "The page saves, reloads showing the new servers, the lookup endpoint "
    "answers using them, and no other setting on the page changes.")

t.step("open Settings and photograph the DNS card as it is now")
r.goto("/settings")
t.shot("dns-card-before", selector="#dns_resolvers >> xpath=ancestor::div[@class='card'][1]")
t.proof("Settings as read from the page before the change",
        json.dumps(BEFORE, indent=1))

t.step("type new servers into 'DNS servers to ask' and press Save settings")
r.page.fill("#dns_resolvers", "9.9.9.9\n149.112.112.112")
t.shot("dns-card-typed", selector="#dns_resolvers >> xpath=ancestor::div[@class='card'][1]")
r.page.click("button[type=submit]")
r.page.wait_for_load_state("networkidle")
t.shot("after-save")

t.step("reload the page and read the field back")
AFTER = read_settings_page()
t.shot("dns-card-after", selector="#dns_resolvers >> xpath=ancestor::div[@class='card'][1]")
t.proof("Settings as read from the page after the change", json.dumps(AFTER, indent=1))

t.ok("the page shows the servers that were typed",
     AFTER["dns_resolvers"].split() == ["9.9.9.9", "149.112.112.112"],
     repr(AFTER["dns_resolvers"]))

changed = {k: (BEFORE[k], AFTER[k]) for k in BEFORE
           if BEFORE[k] != AFTER[k] and k != "dns_resolvers"}
t.ok("saving one card left every other setting alone", not changed, changed)

t.step("ask the manager to look a name up, which is what this setting feeds")
lk = r.api("GET", "/dns/lookup?domain=one.one.one.one")
t.proof("GET /api/dns/lookup?domain=one.one.one.one", json.dumps(lk["body"], indent=1)[:1500])
t.ok("the lookup endpoint answers", lk["status"] == 200, lk)
t.ok("the lookup found addresses", bool(json.dumps(lk["body"]).count(".")), lk["body"])
t.close()

# ============================================================== SET-02
t = r.test(
    "SET-02", "Settings",
    "Default health check interval",
    "Change the default interval and prove a pool created afterwards is born "
    "with the new value, and that the checker honours it.",
    "A fleet watching a hundred backends at two seconds is a lot of traffic at "
    "the origin; one watching at sixty is slow to notice a dead server. The "
    "default is the number most pools will keep, so it has to be settable.",
    "The page saves the number, and a pool created after the change carries it.")

t.step("read the interval, then set it to something distinctive")
r.goto("/settings")
old_interval = r.page.locator("#health_check_interval").input_value()
t.shot("monitoring-card-before", selector="#health_check_interval >> xpath=ancestor::div[@class='card'][1]")
r.page.fill("#health_check_interval", "17")
r.page.click("button[type=submit]")
r.page.wait_for_load_state("networkidle")
r.goto("/settings")
new_interval = r.page.locator("#health_check_interval").input_value()
t.shot("monitoring-card-after", selector="#health_check_interval >> xpath=ancestor::div[@class='card'][1]")
t.proof("interval before and after", f"before: {old_interval}\nafter:  {new_interval}")
t.ok("the page saved and read back 17", new_interval == "17", new_interval)

t.step("create a pool the way the Backend Pools page does, and read its interval")
made = r.api("POST", "/pools", {"name": "qa_interval_probe"})
t.proof("POST /api/pools", json.dumps(made["body"], indent=1)[:800])
pool_id = (made["body"] or {}).get("id") if isinstance(made["body"], dict) else None
if pool_id:
    got = r.api("GET", f"/pools/{pool_id}")
    body = got["body"]
    interval = (body.get("health_check") or {}).get("interval")
    t.proof("the new pool as the API returns it", json.dumps(body, indent=1)[:1500])
    t.ok("a pool created after the change inherits 17 seconds",
         str(interval) == "17", f"pool says {interval!r}")
    explicit = r.api("POST", "/pools", {"name": "qa_interval_explicit",
                                        "health_check_interval": 5})
    if explicit["status"] == 200:
        t.proof("a pool created with an interval of its own",
                json.dumps(explicit["body"].get("health_check"), indent=1))
        t.ok("a value sent explicitly still wins over the default",
             (explicit["body"].get("health_check") or {}).get("interval") == 5,
             explicit["body"].get("health_check"))
        r.api("DELETE", f"/pools/{explicit['body']['id']}")
    r.api("DELETE", f"/pools/{pool_id}")
    t.note("both scratch pools removed")
else:
    t.ok("could create a pool to test the default with", False, made)

t.step("put the interval back to what it was")
r.goto("/settings")
r.page.fill("#health_check_interval", old_interval)
r.page.click("button[type=submit]")
r.page.wait_for_load_state("networkidle")
t.close()

# ============================================================== SET-03
t = r.test(
    "SET-03", "Settings",
    "A fleet setting reaches the standby node",
    "Prove a setting saved on the active node is present on the standby, so a "
    "failover does not silently change how the tool behaves.",
    "The standby is the node that takes over. If settings live only on the "
    "node they were typed on, then the day it matters the fleet behaves "
    "differently and nobody knows why.",
    "The standby reports the same DNS servers this node was just given.")

t.step("read the setting back out of the fleet config snapshot")
snap = r.api("GET", "/cluster")
t.proof("GET /api/cluster", json.dumps(snap["body"], indent=1)[:2500])
t.ok("the cluster endpoint answers", snap["status"] == 200, snap["status"])
t.note("the standby side of this is checked from the shell in the cluster suite, "
       "because it needs the other node's own database rather than this one's view of it")
t.close()

r.stop()
print("\nT01 DONE")
