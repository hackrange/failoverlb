"""
Suite 17: access lists.

Held out of the first pass on purpose and given its own round, because an
access list is the one feature where a config that renders perfectly and does
nothing is not a cosmetic bug.  A rate limit that is not limiting costs you
some bandwidth.  An allow list that is not allowing, or worse is not denying,
is the door standing open while the page says it is shut.

So nothing here is judged by reading the config.  Every check is a real request
at real nginx from a real address, and the pass or fail is the status code that
comes back.

Two source addresses, which is what makes this suite possible at all:

  127.0.0.1   the loopback address, reaching nginx on the same box
  QA_LB01     the node's own LAN address, reaching the same nginx

Both are the same nginx and the same site.  They differ only in where the
request appears to come from, which is exactly the thing an access list decides
on, so a rule that discriminates between them is a rule that is really running.

What this cannot do, said out loud rather than faked: both of those addresses
are the node's own, and the roster puts every address a node has on the allow
list, so a rule that allows the management networks allows both of them.  This
suite can therefore never be an outsider.  Putting a spare address on the
loopback does not get round it either, because that just becomes another node
address and the fleet allowed it within the minute.

So the refusal half of the management rules is handed to
`t19_outside_address.py`, which runs from a container on a bridge network and
is a real outsider.  `ACL-15` leaves the site switched on and writes what t19
needs into `evidence/outside-handoff.json`.
"""
import json
import pathlib
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t17_access_lists").start()
LB01 = qa.LB01
LOOPBACK = "127.0.0.1"
HOST = f"qa-acl.{qa.DOMAIN}"
SITE = "qa-acl"
ACL = "qa_acl_list"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


def acls():
    return r.api("GET", "/zones")["body"].get("access_lists") or []


def find_acl(name):
    return next((a for a in acls() if a["name"] == name), None)


def set_acl(**fields):
    """
    Change the access list under test and give back what came out.

    Shouts if the save was refused.  An earlier version of this suite ignored
    the answer, so a save that came back 400 left the list on the previous
    test's settings and the next check measured the wrong thing while looking
    like it had measured the right one.
    """
    res = r.api("PUT", f"/access-lists/{ACL_ID}", fields)
    if res["status"] != 200:
        print(f"      !! the access list save was refused: {res['status']} "
              f"{str(res['body'])[:200]}", flush=True)
    return res


def get(ip, path="/", **kw):
    return qa.probe(HOST, path, ip=ip, scheme="http", **kw)


def both(t, title, expect_loopback, expect_lan, headers=None):
    """
    The same request from both addresses, which is the whole method.

    Recorded as one piece of evidence with both answers in it, because the
    interesting thing is never one status code, it is the difference between
    the two.
    """
    a = get(LOOPBACK, headers=headers)
    b = get(LB01, headers=headers)
    t.proof(f"{title}: from {LOOPBACK} then from {LB01}",
            f"from {LOOPBACK}:\n{qa.summarise(a)}\n\nfrom {LB01}:\n{qa.summarise(b)}")
    t.ok(f"{title}: {LOOPBACK} gets {expect_loopback}",
         a["status"] == expect_loopback, f"got {a['status']}")
    t.ok(f"{title}: {LB01} gets {expect_lan}",
         b["status"] == expect_lan, f"got {b['status']}")
    return a, b


# ---------------------------------------------------------------- setup

old = find("hosts", SITE)
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
stale = find_acl(ACL)
if stale:
    r.api("DELETE", f"/access-lists/{stale['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", SITE)
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "static")
r.page.fill("#s-root", qa.STATIC_DIR)
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", SITE)["id"]
print(f"  test site id {SID}")


# ---------------------------------------------------------------- ACL-01

t = r.test("ACL-01", "Access lists", "A site with no access list answers everybody",
           "Establish the baseline the rest of the suite measures against.",
           "Before you can prove a rule blocks somebody, you have to prove the "
           "site answered them in the first place.  Without this, every later "
           "403 could be a site that was never working.",
           "Both source addresses get 200 and the file off disk.")
t.step("apply the new static site with no access list on it")
res = r.apply("qa: access list baseline")
t.ok("apply succeeded", res["status"] == 200, res)
t.site_config(SITE, "the site config before any access list")
a, b = both(t, "no access list", 200, 200)
t.ok("and the body is the file off disk", "QA static site" in (a["body"] or ""),
     (a["body"] or "")[:200])
t.close()


# ---------------------------------------------------------------- ACL-02

t = r.test("ACL-02", "Access lists", "Making an access list on the Zones page",
           "Create an access list through the page a person uses, not the API.",
           "The first thing anybody does with this feature.  A list that "
           "cannot be made from the page is a list nobody has.",
           "The list is created, appears on the page, and can be attached to "
           "a site from the site's own settings.")
t.step("open Zones, go to the Access lists tab and press New")
r.goto("/zones")
r.page.click('button[data-tab="acl"]')
r.page.wait_for_timeout(400)
r.page.click('[data-new="acl"]')
r.page.wait_for_selector("#a-name")
r.page.fill("#a-name", ACL)
r.page.fill("#a-desc", "made by the access list round")
r.page.fill("#a-allow", "")
r.page.fill("#a-deny", "")
r.page.select_option("#a-default", "deny")
r.page.uncheck("#a-mgmt")
t.shot("the-new-access-list-dialog")
r.page.click("#z-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(900)
made = find_acl(ACL)
t.ok("the access list exists after saving", made is not None, acls())
ACL_ID = made["id"]
t.step("read it back and check every field survived the save")
t.proof("the access list as the API gives it back", json.dumps(made, indent=2))
t.ok("default action saved as deny", made.get("default_action") == "deny", made)
t.ok("include management saved as off", made.get("include_management") is False, made)
r.goto("/zones")
r.page.click('button[data-tab="acl"]')
r.page.wait_for_timeout(400)
t.shot("the-access-list-on-the-zones-page", full=True)
t.close()


# ---------------------------------------------------------------- ACL-03

t = r.test("ACL-03", "Access lists", "Default deny with nothing allowed shuts the site",
           "Attach a list that allows nobody and prove the site stops answering.",
           "The starting point for locking a site down: deny everything, then "
           "open it to the addresses you mean.  If this step does not bite, "
           "nothing built on top of it is real.",
           "Both addresses get 403 and the config carries deny all.")
t.step("attach the access list to the site and apply")
res = r.api("PUT", f"/hosts/{SID}", {"access_list_id": ACL_ID})
t.ok("the site accepted the access list", res["status"] == 200, res)
back = r.api("GET", f"/hosts/{SID}")["body"]
t.ok("and gives it back when asked", back.get("access_list_id") == ACL_ID, back.get("access_list_id"))
cfg = t.site_config(SITE, "the site config with a deny all list on it")
rules = qa.server_rules(cfg)
t.proof("the rules that apply to the whole server", rules or "[none]")
t.ok("the server denies everything", "deny all;" in rules, rules)
t.ok("and allows nothing", "allow " not in rules, rules)
res = r.apply("qa: default deny, nothing allowed")
t.ok("apply succeeded", res["status"] == 200, res)
both(t, "deny all", 403, 403)
t.close()


# ---------------------------------------------------------------- ACL-04

t = r.test("ACL-04", "Access lists", "An allow list that tells two addresses apart",
           "Allow one of the two source addresses and prove the other is still "
           "refused, then swap them over.",
           "This is the feature.  Somebody wants their office in and everybody "
           "else out.  Proving it both ways round is the difference between a "
           "rule that works and a rule that happens to be letting everybody in.",
           "Whichever address is on the list gets 200 and the other gets 403, "
           "and it follows the list when the list changes.")
t.step(f"allow {LOOPBACK} only")
set_acl(allow=[f"{LOOPBACK}/32"])
cfg = t.site_config(SITE, f"the config allowing {LOOPBACK} only")
t.ok(f"the server allows {LOOPBACK}", f"allow {LOOPBACK}/32;" in qa.server_rules(cfg), qa.server_rules(cfg))
r.apply("qa: allow loopback only")
both(t, f"only {LOOPBACK} allowed", 200, 403)

t.step(f"now swap it over and allow {LB01} only")
set_acl(allow=[f"{LB01}/32"])
cfg = t.site_config(SITE, f"the config allowing {LB01} only")
t.ok(f"the server allows {LB01}", f"allow {LB01}/32;" in qa.server_rules(cfg), qa.server_rules(cfg))
t.ok(f"and no longer allows {LOOPBACK}", f"allow {LOOPBACK}/32;" not in qa.server_rules(cfg), qa.server_rules(cfg))
r.apply("qa: allow the lan address only")
both(t, f"only {LB01} allowed", 403, 200)
t.shot("site-settings-with-the-access-list-attached")
t.close()


# ---------------------------------------------------------------- ACL-05

t = r.test("ACL-05", "Access lists", "Always allow the cluster nodes",
           "Turn on the management tick box and prove the allow lines are "
           "generated from the node roster rather than typed in.",
           "The requirement this feature was asked for: never let a rule meant "
           "for the public lock the fleet out of its own boxes, and never make "
           "somebody remember to add a node they installed last week.",
           "With it on, both addresses get through with no allow entries of "
           "our own, and every node in the roster appears in the config.")
t.step("clear the allow list and turn the management tick box on")
set_acl(allow=[], include_management=True)
cfg = t.site_config(SITE, "the config with the management tick box on")
nodes = [n["address"] for n in (r.api("GET", "/cluster")["body"].get("nodes") or [])]
t.proof("the node roster the config should have been built from", json.dumps(nodes, indent=2))
rules = qa.server_rules(cfg)
t.proof("the rules that apply to the whole server", rules or "[none]")
for address in nodes:
    t.ok(f"the roster address {address} is allowed", f"allow {address};" in rules,
         rules)
t.ok("and it still denies whatever is not matched", "deny all;" in qa.server_rules(cfg), qa.server_rules(cfg))
r.apply("qa: include management")
both(t, "management networks allowed", 200, 200)

t.step("turn it back off and prove the roster lines go away")
set_acl(include_management=False)
cfg = t.site_config(SITE, "the config with the management tick box off")
rules = qa.server_rules(cfg)
for address in nodes:
    t.ok(f"the roster address {address} is gone", f"allow {address};" not in rules,
         rules)
r.apply("qa: management off again")
both(t, "management networks not allowed", 403, 403)
t.close()


# ---------------------------------------------------------------- ACL-06

t = r.test("ACL-06", "Access lists", "Default allow with a deny list",
           "Turn the list the other way round: everybody in except the "
           "addresses named.",
           "The other half of the feature, and the one people reach for to "
           "block a scraper or a single bad address without listing the whole "
           "world they do want.",
           "The denied address gets 403 while the other still gets 200.")
t.step(f"default allow, deny {LB01}")
set_acl(default_action="allow", allow=[], deny=[f"{LB01}/32"])
cfg = t.site_config(SITE, "the config for default allow with one deny")
rules = qa.server_rules(cfg)
t.proof("the rules that apply to the whole server", rules or "[none]")
t.ok(f"the server denies {LB01}", f"deny {LB01}/32;" in rules, rules)
t.ok("and does not deny everything", "deny all;" not in rules, rules)
r.apply("qa: default allow with one deny")
both(t, "default allow, one address denied", 200, 403)

t.step("take the deny away again")
set_acl(deny=[])
r.apply("qa: default allow, nothing denied")
both(t, "default allow, nothing denied", 200, 200)
t.close()


# ---------------------------------------------------------------- ACL-07

t = r.test("ACL-07", "Access lists", "The same address allowed and denied",
           "Put one address in both lists and write down which one wins.",
           "Somebody will do this, by pasting a range into one box and an "
           "address into the other.  The answer has to be documented rather "
           "than discovered during an incident.",
           "nginx takes the first rule that matches and the tool writes the "
           "allows first, so the allow wins.  Whatever the answer, it is "
           "recorded here.")
t.step(f"allow and deny {LB01} at the same time")
set_acl(default_action="deny", allow=[f"{LB01}/32"], deny=[f"{LB01}/32"])
cfg = t.site_config(SITE, "the config with the same address in both lists")
allow_at = cfg.find(f"allow {LB01}/32;")
deny_at = cfg.find(f"deny {LB01}/32;")
t.ok("both lines are in the config", allow_at >= 0 and deny_at >= 0, qa.server_rules(cfg))
t.ok("the allow is written first, which is what decides it", allow_at < deny_at,
     f"allow at {allow_at}, deny at {deny_at}")
r.apply("qa: the same address in both lists")
a, b = both(t, "allowed and denied at once", 403, 200)
t.note(f"answer for the manual: the allow wins, {LB01} got {b['status']}")
t.close()


# ---------------------------------------------------------------- ACL-08

t = r.test("ACL-08", "Access lists", "A username and password on top of the address rules",
           "Turn basic auth on and prove the challenge, the refusal and the "
           "acceptance all really happen.",
           "A staging site somebody wants behind a password as well as an "
           "address rule.  This feature had never worked at all until it was "
           "fixed in an earlier round, so it gets checked properly.",
           "No credentials gets 401 with a realm, the wrong password gets 401, "
           "the right one gets 200.")
t.step("allow both addresses so the only thing in the way is the password")
set_acl(default_action="allow", allow=[], deny=[],
        basic_auth_enabled=True,
        add_user={"username": "qa-visitor", "password": "correct-horse-battery"})
back = find_acl(ACL)
t.proof("the access list with basic auth on", json.dumps(back, indent=2))
t.ok("basic auth reads back as on", back.get("basic_auth_enabled") is True, back)
t.ok("and the user is listed", "qa-visitor" in (back.get("basic_auth_users") or []), back)
cfg = t.site_config(SITE, "the config with basic auth on")
t.ok("the server asks for a password", "auth_basic " in qa.server_rules(cfg), qa.server_rules(cfg))
t.ok("and points at a password file", "auth_basic_user_file" in qa.server_rules(cfg), qa.server_rules(cfg))
r.apply("qa: basic auth on")

import base64 as _b64
none = get(LB01)
t.proof("no credentials", qa.summarise(none))
t.ok("no credentials gets 401", none["status"] == 401, none["status"])
t.ok("and the challenge carries a realm",
     "basic" in (none["headers"].get("WWW-Authenticate", "").lower()),
     none["headers"].get("WWW-Authenticate"))

def basic(user, password):
    raw = _b64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {raw}"}

wrong = get(LB01, headers=basic("qa-visitor", "not-the-password"))
t.proof("the wrong password", qa.summarise(wrong))
t.ok("the wrong password gets 401", wrong["status"] == 401, wrong["status"])

right = get(LB01, headers=basic("qa-visitor", "correct-horse-battery"))
t.proof("the right password", qa.summarise(right))
t.ok("the right password gets 200", right["status"] == 200, right["status"])
t.ok("and serves the real file", "QA static site" in (right["body"] or ""),
     (right["body"] or "")[:200])
t.close()


# ---------------------------------------------------------------- ACL-09

t = r.test("ACL-09", "Access lists", "The address rule is checked before the password",
           "With basic auth on and the address denied, prove the visitor is "
           "refused outright rather than asked for a password.",
           "It matters which comes first.  Being asked for a password by a site "
           "you are not allowed to reach tells an attacker the site is there "
           "and invites them to guess.",
           "A denied address gets 403 and never sees the password box, while "
           "the allowed address is still challenged.")
t.step(f"keep basic auth on, deny {LB01}, allow {LOOPBACK}")
set_acl(default_action="deny", allow=[f"{LOOPBACK}/32"], deny=[])
r.apply("qa: address rule and password together")
denied = get(LB01)
t.proof(f"a denied address with a password on the site ({LB01})", qa.summarise(denied))
t.ok("the denied address gets 403", denied["status"] == 403, denied["status"])
t.ok("and is never asked for a password",
     not denied["headers"].get("WWW-Authenticate"),
     denied["headers"].get("WWW-Authenticate"))
allowed = get(LOOPBACK)
t.proof(f"an allowed address with a password on the site ({LOOPBACK})", qa.summarise(allowed))
t.ok("the allowed address is asked for a password", allowed["status"] == 401,
     allowed["status"])
t.close()

set_acl(basic_auth_enabled=False)


# ---------------------------------------------------------------- ACL-10

t = r.test("ACL-10", "Access lists", "A forwarded address is believed from a proxy we named",
           "Turn on the forwarded address setting, name our own address as the "
           "trusted proxy, and prove the address in the header is the one the "
           "rules are applied to.",
           "Anybody running this behind a CDN or another balancer.  Without it "
           "every visitor arrives wearing the proxy's address and the allow "
           "list is meaningless.",
           "With the header set to an allowed address the request gets through, "
           "and without the header the same connection is refused.")
t.step(f"trust {LB01} as a proxy, allow only 203.0.113.7")
set_acl(default_action="deny", allow=["203.0.113.7/32"], deny=[],
        use_real_ip=True, real_ip_header="X-Forwarded-For",
        real_ip_from=[f"{LB01}/32"])
cfg = t.site_config(SITE, "the config that trusts a forwarded address")
t.ok("the config names the trusted proxy", f"set_real_ip_from {LB01}/32;" in cfg, qa.server_rules(cfg))
t.ok("and names the header it reads", "real_ip_header X-Forwarded-For;" in cfg, qa.server_rules(cfg))
t.ok("and reads the chain from our end", "real_ip_recursive on;" in cfg, qa.server_rules(cfg))
r.apply("qa: trusted forwarded address")

claimed = get(LB01, headers={"X-Forwarded-For": "203.0.113.7"})
t.proof("from the trusted proxy, claiming an allowed address", qa.summarise(claimed))
t.ok("the claimed address is the one that is judged", claimed["status"] == 200,
     claimed["status"])

bare = get(LB01)
t.proof("from the same trusted proxy with no header at all", qa.summarise(bare))
t.ok("with no header its own address is judged, and is not allowed",
     bare["status"] == 403, bare["status"])

wrong = get(LB01, headers={"X-Forwarded-For": "198.51.100.4"})
t.proof("from the trusted proxy, claiming an address that is not allowed",
        qa.summarise(wrong))
t.ok("a claimed address that is not on the list is still refused",
     wrong["status"] == 403, wrong["status"])
t.close()


# ---------------------------------------------------------------- ACL-11

t = r.test("ACL-11", "Access lists", "A forwarded address from a stranger is ignored",
           "Send the same header from an address that is not on the trusted "
           "proxy list, and prove it buys nothing.",
           "This is the one that matters.  Anybody can send X-Forwarded-For.  "
           "If it is believed from a stranger then the allow list can be walked "
           "straight past by typing a header, and the site is open while the "
           "page says it is shut.",
           "The header is ignored and the connection's own address is judged, "
           "so the request is refused.")
t.step(f"trust only {LOOPBACK} as a proxy, then send the header from {LB01}")
set_acl(real_ip_from=[f"{LOOPBACK}/32"])
cfg = t.site_config(SITE, "the config trusting only the loopback address")
t.ok(f"the config trusts {LOOPBACK} and not {LB01}",
     f"set_real_ip_from {LOOPBACK}/32;" in cfg and f"set_real_ip_from {LB01}/32;" not in cfg,
     qa.server_rules(cfg))
r.apply("qa: forwarded address from an untrusted source")

spoof = get(LB01, headers={"X-Forwarded-For": "203.0.113.7"})
t.proof("an untrusted source claiming an allowed address", qa.summarise(spoof))
t.ok("the spoofed header does not get in", spoof["status"] == 403, spoof["status"])

honest = get(LOOPBACK, headers={"X-Forwarded-For": "203.0.113.7"})
t.proof("the trusted source claiming the same address", qa.summarise(honest))
t.ok("and the trusted source with the same header still does", honest["status"] == 200,
     honest["status"])
t.note("the same header, the same claim, two different answers, decided only "
       "by whether the sender was named as a proxy")
t.close()


# ---------------------------------------------------------------- ACL-12

t = r.test("ACL-12", "Access lists", "Trusting every address, and what it costs",
           "Set the trusted proxy list to 0.0.0.0/0, which is what gets copied "
           "off the internet, and show what it does.",
           "This exact line is in a lot of configs, usually copied from a guide "
           "written for a box that could only ever be reached through a CDN.  "
           "On a box anybody can reach it hands the allow list to whoever asks.",
           "Any source can now claim any address and be believed, which is "
           "recorded here so the risk is written down rather than folklore.")
t.step("set the trusted proxy list to 0.0.0.0/0")
set_acl(real_ip_from=["0.0.0.0/0"])
cfg = t.site_config(SITE, "the config trusting every address")
t.ok("the config carries the wildcard", "set_real_ip_from 0.0.0.0/0;" in cfg, qa.server_rules(cfg))
r.apply("qa: the wildcard trusted proxy")
anyone = get(LB01, headers={"X-Forwarded-For": "203.0.113.7"})
t.proof("a source that was not named, claiming an allowed address", qa.summarise(anyone))
t.ok("with the wildcard, an unnamed source is believed", anyone["status"] == 200,
     anyone["status"])
t.note("this is the documented behaviour of the directive, not a defect.  It is "
       "here so that the answer to 'do I need set_real_ip_from 0.0.0.0/0' is a "
       "measurement rather than an opinion: it makes the allow list above it "
       "advisory for anybody who can reach the port.")
t.step("put the trusted proxy list back to something sane")
set_acl(real_ip_from=[f"{LB01}/32"])
r.apply("qa: back to a named proxy")
t.close()


# ---------------------------------------------------------------- ACL-13

t = r.test("ACL-13", "Access lists", "A chain of proxies, read from our end",
           "Send a header with more than one address in it and prove the tool "
           "reads it from the end its own proxy appends to.",
           "Real forwarded headers have several hops in them.  Reading from the "
           "wrong end takes whatever the client typed, and the client writes "
           "that end, so the whole feature turns into a spoof.",
           "With the trusted proxy list covering our address, the address to "
           "the left of ours is the one judged.")
t.step("send two addresses in the header, the allowed one first")
set_acl(real_ip_from=[f"{LB01}/32"], allow=["203.0.113.7/32"])
r.apply("qa: a chain of forwarded addresses")
chain = get(LB01, headers={"X-Forwarded-For": f"203.0.113.7, {LB01}"})
t.proof("a two hop chain ending at the trusted proxy", qa.summarise(chain))
t.ok("the hop before the trusted proxy is the one judged", chain["status"] == 200,
     chain["status"])
liar = get(LB01, headers={"X-Forwarded-For": f"198.51.100.4, 203.0.113.7"})
t.proof("a chain whose left hand end is the allowed address but whose last hop is not",
        qa.summarise(liar))
t.note(f"observed status {liar['status']} for a chain the client wrote entirely")
t.close()


# ---------------------------------------------------------------- ACL-14

t = r.test("ACL-14", "Access lists", "An access list on one path only",
           "Put the list on a path instead of the whole site and prove the "
           "rest of the site is untouched.",
           "The commonest real shape: a public site with an admin area, or a "
           "health check that has to stay reachable while everything else is "
           "locked down.",
           "The protected path is refused while the site root still answers.")
t.step("take the list off the site and give it to a path instead")
r.api("PUT", f"/hosts/{SID}", {"access_list_id": None})
set_acl(default_action="deny", allow=[f"{LOOPBACK}/32"], deny=[],
        use_real_ip=False, include_management=False)
res = r.api("POST", f"/hosts/{SID}/locations",
            {"path": "/sub", "match_type": "prefix", "mode": "static",
             "document_root": qa.STATIC_DIR, "access_list_id": ACL_ID})
t.ok("the path was created", res["status"] in (200, 201), res)
locs = r.api("GET", f"/hosts/{SID}/locations")["body"]
rows = locs.get("locations") or locs.get("paths") or []
mine = next((l for l in rows if l["path"] == "/sub"), None)
t.proof("the path as the API gives it back", json.dumps(mine, indent=2))
t.ok("the path kept the access list", mine and mine.get("access_list_id") == ACL_ID, mine)
cfg = t.site_config(SITE, "the site config with a list on one path only")
r.apply("qa: an access list on one path")

root_loop = get(LOOPBACK, "/")
root_lan = get(LB01, "/")
sub_loop = get(LOOPBACK, "/sub/page.html")
sub_lan = get(LB01, "/sub/page.html")
t.proof("the site root and the protected path, from both addresses",
        f"root from {LOOPBACK}:\n{qa.summarise(root_loop)}\n\n"
        f"root from {LB01}:\n{qa.summarise(root_lan)}\n\n"
        f"/sub from {LOOPBACK}:\n{qa.summarise(sub_loop)}\n\n"
        f"/sub from {LB01}:\n{qa.summarise(sub_lan)}")
t.ok("the site root still answers everybody", root_loop["status"] == 200
     and root_lan["status"] == 200, f"{root_loop['status']} {root_lan['status']}")
t.ok("the protected path answers the allowed address", sub_loop["status"] == 200,
     sub_loop["status"])
t.ok("and refuses the one that is not on the list", sub_lan["status"] == 403,
     sub_lan["status"])
t.close()


# ---------------------------------------------------------------- ACL-15

t = r.test("ACL-15", "Access lists", "A management only site",
           "Switch a site to management access only and prove the allow lines "
           "are built from the node roster with a deny on the end, and that "
           "the fleet's own addresses still get in.",
           "The tick box for a site nobody outside the fleet should ever see.  "
           "It is a different code path from an access list and does not use "
           "one at all.",
           "Every node and every management network is allowed, everything "
           "else is denied, and both of this suite's addresses get through.")
t.step("switch the site to management access only")
res = r.api("PUT", f"/hosts/{SID}", {"admin_only": True})
t.ok("the site accepted it", res["status"] == 200, res)
cfg = t.site_config(SITE, "the config for a management only site")
rules = qa.server_rules(cfg)
t.proof("the rules that apply to the whole server", rules or "[none]")
for address in nodes:
    t.ok(f"the roster address {address} is allowed", f"allow {address};" in rules, rules)
t.ok("and everything else is denied", "deny all;" in rules, rules)
r.apply("qa: management only site")
both(t, "management only site, from inside the management networks", 200, 200)

# The refusal half needs a source address outside every management network,
# and this suite has none.  It runs in the node's own network namespace, so
# every address it can use is one of the node's, and the roster puts every
# address a node has on the allow list.  Putting a spare address on the
# loopback does not help either: that just makes it another node address, and
# the fleet allowed it within a minute.  Found out the hard way.
#
# So the site is left switched on, and t19_outside_address.py finishes the
# test from a container on a bridge network, which is a genuine outsider.
# Everything it needs to judge its own answer goes in this file, the rules
# included, so it can prove it was not on the list before it believes a
# refusal.
# A control site alongside it, open to everybody, so the outsider can prove
# it reached this nginx at all.  Without one, a 403 from a single site could
# just as well be a name that resolves nowhere, a site that is down, or a
# container that cannot route to the node.
CONTROL = "qa-acl-open"
CONTROL_HOST = f"{CONTROL}.{qa.DOMAIN}"
old_control = find("hosts", CONTROL)
if old_control:
    r.api("DELETE", f"/hosts/{old_control['id']}")
res = r.api("POST", "/hosts",
            {"name": CONTROL, "server_names": [CONTROL_HOST], "mode": "static",
             "document_root": qa.STATIC_DIR, "listen_http": True,
             "listen_https": False, "force_https": False})
t.ok("the open control site was created", res["status"] in (200, 201), res)
r.apply("qa: the open control site next to the locked one")
t.proof("the open control site, asked from inside the fleet",
        qa.summarise(qa.probe(CONTROL_HOST, "/", ip=LB01, scheme="http")))

HANDOFF = pathlib.Path("/qa/evidence/outside-handoff.json")
HANDOFF.write_text(json.dumps({
    "site": SITE,
    "hostname": HOST,
    "node": LB01,
    "server_rules": rules,
    "expect": 403,
    "control_site": CONTROL,
    "control_hostname": CONTROL_HOST,
    "control_expect": 200,
    "why": "a site set to management access only, asked for by somebody who "
           "is not the management, with an open site beside it so the "
           "outsider can show it reached this nginx",
}, indent=2))
t.step("left switched on, with the rules handed to t19_outside_address.py")
t.note("the refusal half is measured by t19_outside_address.py, which runs "
       "from outside the node's own network.  This suite cannot be an "
       "outsider: every address it has is one of the node's, and every "
       "address a node has is on the roster, so it is always on the list.")
t.close()


# ---------------------------------------------------------------- ACL-16

t = r.test("ACL-16", "Access lists", "A list that is in use cannot be deleted",
           "Try to delete the access list while something is still pointing at "
           "it, and check what the tool says.",
           "Deleting a list out from under a site is how a site silently loses "
           "its protection.  The refusal has to name what is using it, or the "
           "person has to go and look through every site by hand.",
           "The delete is refused and the message names what is still using it.")
t.step("put the list back on the whole site as well as the path")
r.api("PUT", f"/hosts/{SID}", {"access_list_id": ACL_ID})
res = r.api("DELETE", f"/access-lists/{ACL_ID}")
t.proof("deleting a list that a site is using", json.dumps(res, indent=2))
t.ok("the delete is refused", res["status"] == 409, res)
t.ok("and the message names the site", SITE in str(res.get("body")), res.get("body"))

t.step("take it off the site, leaving only the path using it")
r.api("PUT", f"/hosts/{SID}", {"access_list_id": None})
res = r.api("DELETE", f"/access-lists/{ACL_ID}")
t.proof("deleting a list that only a path is using", json.dumps(res, indent=2))
if res["status"] in (200, 204):
    t.defect("A list still used by a path can be deleted",
             "The refusal only looks at sites.  A list attached to a path, or "
             "to a stream, is not counted, so the delete goes through and the "
             "path is left pointing at an access list that is not there any "
             "more.  Deleting from the site's own tab is the normal way people "
             "attach one, so this is reachable by anybody who protects a path "
             "rather than a whole site.",
             severity="medium")
    t.ok("a list used by a path is refused as well", False,
         f"it was deleted: {res}")
else:
    t.ok("a list used by a path is refused as well", res["status"] == 409, res)
    t.ok("and that message names the path too",
         "/sub" in str(res.get("body")) or SITE in str(res.get("body")),
         res.get("body"))
t.close()


# ---------------------------------------------------------------- ACL-17

t = r.test("ACL-17", "Access lists", "Trusting a forwarded address with nobody named",
           "Try to turn the forwarded address setting on without naming a "
           "single proxy, and check the tool refuses rather than saving "
           "something that does nothing.",
           "It is the easy half of the setting to fill in and the easy half to "
           "forget.  With nothing named, nginx trusts no source, so the header "
           "is ignored and every visitor is judged on the address the "
           "connection really came from.  The tick box says otherwise, and "
           "somebody puts a CDN in front and cannot work out why their allow "
           "list sees the CDN.",
           "The save is refused with a message naming the fix, and the list is "
           "left as it was.")
t.step("make a fresh list to try it on")
res = r.api("POST", "/access-lists",
            {"name": "qa_acl_inert", "allow": ["10.0.0.0/8"],
             "default_action": "deny", "include_management": False})
t.ok("the list was created", res["status"] in (200, 201), res)
INERT = res["body"]["id"]

t.step("turn the forwarded address setting on and name nobody")
res = r.api("PUT", f"/access-lists/{INERT}",
            {"use_real_ip": True, "real_ip_from": []})
t.proof("turning it on with an empty proxy list", json.dumps(res, indent=2)[:600])
t.ok("the save is refused", res["status"] == 400, res)
t.ok("and the message says what to do about it",
     "trusted proxy" in str(res.get("body")).lower(), res.get("body"))

t.step("and the same save with a proxy named is accepted")
res = r.api("PUT", f"/access-lists/{INERT}",
            {"use_real_ip": True, "real_ip_from": [f"{LB01}/32"]})
t.proof("the same save with a proxy named", json.dumps(res, indent=2)[:400])
t.ok("naming a proxy makes it acceptable", res["status"] == 200, res)

back = find_acl("qa_acl_inert")
t.ok("and it reads back on with the proxy stored",
     back.get("use_real_ip") is True and back.get("real_ip_from") == [f"{LB01}/32"],
     back)
r.api("DELETE", f"/access-lists/{INERT}")
t.close()


print("\nT17 DONE")
r.stop()
