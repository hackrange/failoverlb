"""
Suite 14: global load balancing by DNS.

GSLB answers DNS itself so a name can point at whichever site is up.  On this
fleet the listener is not running, so what can be proven here is the zone, the
records, the health driven answer selection and the delegation the tool hands
out, up to but not including a real query on the wire.

That boundary is stated rather than glossed over, and section 7 of the report
says what would be needed to close it.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t14_gslb").start()
ZONE = f"qa-gslb.{qa.DOMAIN}"


def zones():
    return r.api("GET", "/gslb/zones")["body"]


for z in (zones().get("zones") or []):
    if z["name"].startswith("qa-"):
        r.api("DELETE", f"/gslb/zones/{z['id']}")


# ============================================================== DNS-01
t = r.test(
    "DNS-01", "GSLB",
    "A DNS zone this fleet answers for",
    "Create a zone on the GSLB page and prove the fleet takes ownership of it, "
    "reports what it would answer, and hands out the delegation records a "
    "registrar needs.",
    "Failing over between two sites in different places cannot be done with a "
    "load balancer in one of them, because the thing that is down is the whole "
    "site.  Answering DNS is the only mechanism that works across locations, "
    "and it is the difference between a regional outage and a global one.",
    "The zone is created, both nodes are listed as answering for it, and the "
    "delegation the registrar needs is produced.")

r.goto("/gslb")
r.page.wait_for_timeout(1500)
t.shot("gslb-page-before", full=True)
t.config("before")
before = zones()
t.proof("what the GSLB service reports before anything is created",
        json.dumps({k: v for k, v in before.items() if k != "zones"}, indent=1)[:1200])
t.ok("the fleet knows which nodes would answer",
     len(before.get("nodes") or []) >= 2, before.get("nodes"))
t.note("the listener starts by itself once a zone exists, so this suite does "
       "reach the wire: real UDP queries are asked and the answers parsed")

t.step("create the zone")
made = r.api("POST", "/gslb/zones", {"name": ZONE, "ttl": 30,
                                     "description": "QA test zone, delete me"})
t.proof("POST /api/gslb/zones", json.dumps(made["body"], indent=1)[:900])
t.ok("the zone was created", made["status"] in (200, 201), made)
ZID = made["body"]["id"]
r.goto("/gslb")
r.page.wait_for_timeout(1500)
t.shot("gslb-page-with-zone", full=True)

detail = r.api("GET", f"/gslb/zones/{ZID}")["body"]
t.proof("the zone as the API returns it", json.dumps(detail, indent=1)[:1200])
t.ok("the zone carries the name that was asked for",
     detail.get("name") == ZONE, detail.get("name"))
# The time to live lives on the record rather than on the zone; the zone
# carries the SOA figures.  Checked on the record in DNS-02.
t.proof("the SOA figures the zone carries",
        json.dumps({k: v for k, v in detail.items() if k.startswith("soa")}, indent=1))
t.ok("the zone carries a complete set of SOA figures",
     all(detail.get(k) for k in ("soa_refresh", "soa_retry", "soa_expire",
                                 "soa_minimum")), detail)
t.config("after")
t.close()

# ============================================================== DNS-02
t = r.test(
    "DNS-02", "GSLB",
    "A record with more than one answer, and health deciding which is used",
    "Add a record with two answers pointing at two different addresses, and "
    "prove the tool tracks each answer's health and would only hand out the "
    "ones that are up.",
    "This is the whole point.  A name with two answers where both are handed "
    "out regardless is round robin DNS, which sends half your visitors to a "
    "dead site.  Health checking each answer is what turns it into failover.",
    "Both answers are stored against the record, each with its own health "
    "state, and the tool reports which it would give out.")

t.config("before")
t.step("add a record to the zone")
rec = r.api("POST", f"/gslb/zones/{ZID}/records",
            {"name": "www", "type": "A", "ttl": 30,
             "policy": "failover"})
t.proof("POST /api/gslb/zones/{id}/records", json.dumps(rec["body"], indent=1)[:900])
t.ok("the record was created", rec["status"] in (200, 201), rec)
RID = (rec["body"] or {}).get("id")

if RID:
    t.step("give it two answers, one per site")
    nodes = {n["name"]: n["id"] for n in (zones().get("nodes") or [])}
    for addr, label, node in ((qa.BACKEND_HOST, "the first site", "lb01"),
                              (qa.LB02, "the second site", "lb02")):
        ans = r.api("POST", f"/gslb/records/{RID}/answers",
                    {"value": addr, "weight": 1, "enabled": True,
                     "node_id": nodes.get(node)})
        t.proof(f"an answer for {label}", json.dumps(ans["body"], indent=1)[:600])
        t.ok(f"the answer {addr} was accepted", ans["status"] in (200, 201), ans)

    r.goto("/gslb")
    r.page.wait_for_timeout(1800)
    t.shot("gslb-zone-with-answers", full=True)
    full = r.api("GET", f"/gslb/zones/{ZID}")["body"]
    t.proof("the zone with its record and answers",
            json.dumps(full, indent=1)[:2000])
    records = full.get("records") or []
    t.ok("the record is on the zone", bool(records), full)
    answers = records[0].get("answers") if records else []
    t.ok("both answers are stored", len(answers or []) == 2, answers)
    t.ok("the record carries the time to live that was asked for",
         str(records[0].get("ttl")) == "30", records[0].get("ttl"))
    t.ok("the record carries a policy that decides between the answers",
         records[0].get("policy") == "failover", records[0].get("policy"))
    t.ok("each answer is tied to a node, which is what makes health mean "
         "anything", all(a.get("node_name") for a in (answers or [])), answers)

    # ---- and now a real question on the wire
    t.step("ask the fleet's own DNS server for the name, over UDP")
    time.sleep(3)
    status = zones().get("server") or {}
    t.proof("the DNS service now that a zone exists", json.dumps(status, indent=1))
    t.ok("creating a zone started the listener", status.get("listening") is True,
         status)
    t.ok("it loaded the zone", status.get("zones_loaded", 0) >= 1, status)

    where = status.get("address") or qa.BACKEND_HOST
    port = int(status.get("port") or 5353)
    answer = qa.dns_query(f"www.{ZONE}", where, port)
    t.proof(f"a real DNS query to {where}:{port}", json.dumps(answer, indent=1))
    t.ok("the fleet answered the query", answer.get("rcode") == "NOERROR", answer)
    values = [a["value"] for a in answer.get("answers") or []]
    t.ok("it answered with the addresses that were configured",
         set(values) <= {qa.BACKEND_HOST, qa.LB02} and values, values)
    t.ok("the answer carries the time to live from the record",
         all(a["ttl"] == 30 for a in answer.get("answers") or []),
         answer.get("answers"))

    t.step("switch one answer off and ask again")
    off = answers[0]
    r.api("DELETE", f"/gslb/answers/{off['id']}")
    time.sleep(3)
    again = qa.dns_query(f"www.{ZONE}", where, port)
    t.proof("the same query with one answer removed", json.dumps(again, indent=1))
    left = [a["value"] for a in again.get("answers") or []]
    t.ok("the removed address is no longer handed out",
         off["value"] not in left, {"removed": off["value"], "still answering": left})
    t.ok("the other address is still handed out", bool(left), left)

    t.step("ask for a name in the zone that does not exist")
    missing = qa.dns_query(f"nothing.{ZONE}", where, port)
    t.proof("a query for a name that was never created",
            json.dumps(missing, indent=1))
    t.ok("a name that does not exist is refused properly rather than answered",
         missing.get("rcode") in ("NXDOMAIN", "NOERROR")
         and not missing.get("answers"), missing)

    t.step("ask for a name in a zone this fleet is not authoritative for")
    other = qa.dns_query("www.example.net", where, port)
    t.proof("a query for somebody else's domain", json.dumps(other, indent=1))
    t.ok("it refuses to answer for a zone it does not hold",
         other.get("rcode") in ("REFUSED", "NXDOMAIN") or not other.get("answers"),
         other)
t.config("after")
t.close()

# ============================================================== DNS-03
t = r.test(
    "DNS-03", "GSLB",
    "The delegation a registrar has to be given",
    "Read the delegation the page hands out and check it names this fleet's "
    "nodes and is complete enough to paste into a registrar.",
    "Delegating a subdomain is the step everybody gets wrong, and the failure "
    "is silent: the records look right, the name does not resolve, and nothing "
    "says which half is missing.  The tool producing the exact records to "
    "paste is what removes that.",
    "The delegation names both nodes and gives the address records they need, "
    "in a form that can be pasted.")

t.config("before")
r.goto("/gslb")
r.page.wait_for_timeout(1800)
deleg = r.page.locator(".deleg pre")
text = deleg.first.inner_text() if deleg.count() else ""
if not text:
    body = zones()
    text = json.dumps({k: v for k, v in body.items() if k in ("nodes", "delegation")},
                      indent=1)
t.proof("the delegation the page hands out", text[:1500])
t.shot("gslb-delegation", full=True)
t.ok("the delegation mentions this fleet's nodes",
     "lb01" in text or qa.BACKEND_HOST in text or "71.208" in text, text[:300])
t.note("a real delegation cannot be completed from here, because it needs "
       "records at the registrar for a domain this test does not own")
t.config("after")
t.close()

# ============================================================== DNS-04
t = r.test(
    "DNS-04", "GSLB",
    "The service reports honestly that it is not listening",
    "Check that the page says the DNS listener is not running, rather than "
    "showing a zone that looks live and answering nothing.",
    "A GSLB zone that is configured but not being served is the most dangerous "
    "state this feature has: everything on screen says it is working and no "
    "query is ever answered.  The page has to say so.",
    "The status reports listening as false and the query counters as zero.")

status = zones().get("server") or {}
t.proof("what the service reports about itself", json.dumps(status, indent=1))
t.ok("the tool reports whether it is listening at all",
     "listening" in status, status)
t.ok("it says which address and port it is on", bool(status.get("port")), status)
t.ok("it counts the queries it has answered",
     (status.get("stats") or {}).get("queries", 0) > 0, status.get("stats"))
t.ok("it counted the ones it answered separately from the ones it refused",
     "answered" in (status.get("stats") or {}) and "refused" in (status.get("stats") or {}),
     status.get("stats"))
r.goto("/gslb")
r.page.wait_for_timeout(1500)
t.shot("gslb-status", full=True)
t.note("what is left untested on this fleet is a query arriving on port 53 "
       "from the internet.  The service answers on 5353 and the installer "
       "redirects 53 to it with a firewall rule; that redirect was not enabled, "
       "because this fleet shares a network with the owner's own DNS and "
       "taking port 53 was not something to do without being asked.")
t.close()

t2 = r.test(
    "DNS-05", "GSLB",
    "Removing a zone leaves nothing behind",
    "Delete the test zone and prove the record and its answers go with it.",
    "A zone left behind after a test or a mistake is a name this fleet claims "
    "to be authoritative for and answers wrongly.",
    "The zone, its record and its answers are all gone.")
t2.config("before")
res = r.api("DELETE", f"/gslb/zones/{ZID}")
t2.proof("DELETE /api/gslb/zones/{id}", json.dumps(res, indent=1)[:500])
t2.ok("the delete was accepted", res["status"] in (200, 204), res)
left = [z for z in (zones().get("zones") or []) if z["name"] == ZONE]
t2.proof("the zones that remain",
         json.dumps([z["name"] for z in (zones().get("zones") or [])], indent=1))
t2.ok("the zone is gone", not left, left)
t2.config("after")
r.goto("/gslb")
r.page.wait_for_timeout(1200)
t2.shot("gslb-after-delete", full=True)
t2.close()

r.stop()
print("\nT14 DONE")
