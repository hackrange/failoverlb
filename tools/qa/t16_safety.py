"""
Suite 16: the guard that refuses a mass deletion.

A standby holds the rendered files but not the objects they were rendered
from.  A standby that gets promoted and renders therefore has nothing to
render, and the first version of this manager did exactly that: it produced a
config with every site missing, applied it to itself, and wiped its own
config.  Then it queued the same empty config for the node that was down,
which would have taken the live node with it when that node came back.

The guard is deliberately blunt.  Going from most sites to few is not a change
anybody makes on purpose, so an apply that removes more than half the site
files at once is refused until somebody says they really mean it.

This ran by hand on 18 August and was written up from what it printed.  That
is no longer good enough, because the apply path has changed twice since, so
it is a suite now: it makes its own sites, trips the guard with those, forces
the same apply through, and puts everything back.  Nothing it touches was
there before it ran.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t16_safety").start()
LB01, LB02 = qa.LB01, qa.LB02
PREFIX = "qa-wipe-"


def hosts():
    body = r.api("GET", "/hosts")["body"]
    return body.get("hosts") or body.get("sites") or []


def mine():
    return [h for h in hosts() if h["name"].startswith(PREFIX)]


def live_site_files():
    """The site files the fleet would write right now, which is what the guard
    measures against."""
    res = r.api("GET", "/preview")
    files = (res["body"] or {}).get("files") or {}
    return sorted(p for p in files if p.startswith("sites/"))


def force_apply(summary):
    """Apply the way the confirmation dialog does, with force set."""
    res = r.api("POST", "/apply", {"summary": summary, "force": True})
    time.sleep(3)
    return res


# ------------------------------------------------------------- make the sites

for h in mine():                                    # from an interrupted run
    r.api("DELETE", f"/hosts/{h['id']}")

before = live_site_files()
NEED = len(before) + 1          # so that switching mine off is over half
print(f"  the fleet renders {len(before)} site files, so this makes {NEED}")

for i in range(1, NEED + 1):
    name = f"{PREFIX}{i}"
    res = r.api("POST", "/hosts",
                {"name": name, "server_names": [f"{name}.{qa.DOMAIN}"],
                 "mode": "static", "document_root": qa.STATIC_DIR,
                 "listen_http": True, "listen_https": False,
                 "force_https": False})
    if res["status"] not in (200, 201):
        print(f"  !! could not create {name}: {res['status']} {res['body']}")
        sys.exit(1)

setup = r.apply("qa: sites for the mass deletion guard")
if setup["status"] != 200:
    print(f"  !! could not apply the test sites: {setup['status']} {setup['body']}")
    sys.exit(1)
FULL = live_site_files()
MINE = {h["name"]: h["id"] for h in mine()}
print(f"  {len(FULL)} site files live, {len(MINE)} of them this suite's")

WITNESS = next((p.split("/")[-1] for p in FULL
                if not p.split("/")[-1].startswith(PREFIX)), None)


def switch(state):
    for name, hid in MINE.items():
        r.api("PUT", f"/hosts/{hid}", {"enabled": state})


# ---------------------------------------------------------------- SAFE-01

t = r.test("SAFE-01", "Site administration",
           "An apply that would remove most of the sites is refused",
           f"Switch off {len(MINE)} of the fleet's {len(FULL)} sites, press "
           "Apply config, and prove the fleet refuses it and says why.",
           "A render that has lost most of its sites is far more often a node "
           "that cannot see them than somebody deleting their estate on "
           "purpose.  Applying that takes every one of those sites off the "
           "internet, and the difference between a bad afternoon and a "
           "disaster is whether anything stopped to ask.",
           "The apply is refused, naming how many files would go and which, "
           "and nothing on the fleet changes.")
switch(False)
staged = live_site_files()
t.ok(f"the staged config really does drop {len(MINE)} of {len(FULL)} sites",
     len(FULL) - len(staged) == len(MINE),
     f"{len(FULL)} live, {len(staged)} staged")

res = r.api("POST", "/apply", {"summary": "qa: a mass deletion"})
detail = res["body"] if isinstance(res["body"], dict) else {}
inner = detail.get("detail") if isinstance(detail.get("detail"), dict) else detail
message = str(inner.get("error") or detail.get("detail") or res["body"])
t.proof("POST /api/apply with most of the sites switched off",
        json.dumps(res["body"], indent=2)[:900])

t.ok("the apply is refused", res["status"] != 200 or inner.get("refused") is True,
     res["status"])
t.ok("and it is refused for this reason rather than some other failure",
     "remove" in message and "at once" in message, message[:200])
t.ok("the refusal counts what would go",
     f"{len(MINE)} of {len(FULL)}" in message, message[:200])
t.ok("and names files, so the person can see whether it is what they meant",
     PREFIX in message, message[:300])
t.ok("it says how to go ahead anyway",
     "force" in message.lower(), message[:300])
t.ok("and it explains the promoted standby case, which is the common one",
     "standby" in message.lower(), message[:400])

t.step("nothing was half done")
still = qa.probe(f"{PREFIX}1.{qa.DOMAIN}", "/", ip=LB01, scheme="http")
t.proof("one of the sites the refused apply would have removed",
        qa.summarise(still, body_chars=120))
t.ok("a site the refused apply would have removed is still being served",
     still["status"] == 200, still["status"])
if LB02:
    other = qa.probe(f"{PREFIX}1.{qa.DOMAIN}", "/", ip=LB02, scheme="http")
    t.ok("and on the other node too, so no node took it on its own",
         other["status"] == 200, other["status"])
t.close()


# ---------------------------------------------------------------- SAFE-02

t = r.test("SAFE-02", "Site administration",
           "The same apply goes through when somebody says they mean it",
           "Send the identical apply with force set and prove it is accepted "
           "and the files really go.",
           "A guard nobody can get past is a guard that gets taken out.  "
           "Somebody decommissioning an estate has to be able to finish, and "
           "the way through has to be one deliberate extra step rather than "
           "editing the config on the boxes by hand, which is how fleets stop "
           "matching each other.",
           "The forced apply is accepted and the sites stop answering.")
res = force_apply("qa: a mass deletion, and yes I mean it")
t.proof("the same apply with force set", json.dumps(res["body"], indent=2)[:500])
t.ok("the forced apply is accepted", res["status"] == 200, res)
t.ok("and it produced a new version",
     bool((res["body"] or {}).get("version")), res["body"])

gone = qa.probe_allowing_refusal(f"{PREFIX}1.{qa.DOMAIN}", "/", ip=LB01,
                                 scheme="http")
t.proof("the site afterwards", qa.summarise(gone, body_chars=120))
t.ok("the site really is gone rather than merely reported gone",
     gone["status"] != 200 or "QA static site" not in (gone["body"] or ""),
     gone["status"])
if WITNESS:
    t.ok(f"and a site that was not part of it is untouched: {WITNESS}",
         f"sites/{WITNESS}" in live_site_files(), WITNESS)
t.close()


# ---------------------------------------------------------------- SAFE-03

t = r.test("SAFE-03", "Site administration",
           "Ordinary changes are not touched by the guard",
           "Put the sites back, then delete one site on its own and apply, "
           "which is the change people actually make.",
           "A safety net that fires on normal work gets switched off within a "
           "week.  Removing one site is routine and has to stay routine, and "
           "the fleet has to come back from the forced deletion without "
           "anybody editing a box by hand.",
           "The sites come back on a normal apply, and deleting one is "
           "accepted with no refusal.")
t.step("put them back")
switch(True)
res = r.apply("qa: putting the sites back")
t.ok("adding them back is a normal apply and is accepted",
     res["status"] == 200, res)
back = qa.probe(f"{PREFIX}1.{qa.DOMAIN}", "/", ip=LB01, scheme="http")
t.proof("the site once it is back", qa.summarise(back, body_chars=120))
t.ok("and the site is being served again", back["status"] == 200, back["status"])

t.step("now delete one on its own")
one = sorted(MINE)[0]
r.api("DELETE", f"/hosts/{MINE[one]}")
res = r.apply("qa: removing one site the ordinary way")
t.proof("apply after deleting a single site",
        json.dumps(res["body"], indent=2)[:400])
t.ok("deleting one site at a time is not refused", res["status"] == 200, res)
MINE.pop(one)
t.close()


# ---------------------------------------------------------------- tidy up

for name, hid in MINE.items():
    r.api("DELETE", f"/hosts/{hid}")
res = force_apply("qa: removing the mass deletion guard's sites")
print("  tidy up apply:", res["status"])
left = [h["name"] for h in mine()]
print("  sites left behind:", left or "none")

print("\nT16 DONE")
r.stop()
