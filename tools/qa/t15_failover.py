"""
Suite 15: failover.

The promise the whole product rests on.  This asks for the active role to move
to the standby, then watches both nodes to see whether it does.

Deliberately last, because it moves the active role and everything before it
assumed lb01 held it.  The fleet returns to its starting state by itself, which
is part of what this measures.
"""
import json
import pathlib
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t15_failover").start()
LB01, LB02 = qa.LB01, qa.LB02
HOST = f"qa-lb.{qa.DOMAIN}"


def roles():
    state = r.api("GET", "/cluster")["body"]
    return {n.get("name"): str(n.get("role")).lower().replace("noderole.", "")
            for n in (state.get("nodes") or [])}


def serving(ip):
    return qa.probe_allowing_refusal(HOST, "/echo", ip=ip, scheme="http")["status"]


# ============================================================== FVR-01
t = r.test(
    "FVR-01", "Failover",
    "Moving the active role to the standby by hand",
    "Ask for the active role to move to the standby, then watch both nodes for "
    "half a minute to see whether it moves and stays moved.",
    "This is the entire reason there are two of them.  An operator draining a "
    "node for maintenance, or moving off a box that is misbehaving, needs the "
    "role to go where they put it.  A standby that holds config but never takes "
    "the role is a standby in name only, and the day it matters is the worst "
    "possible time to find out.",
    "The standby becomes active, stays active, and both nodes agree.  Traffic "
    "continues throughout.")

t.step("record who is active, and check both nodes are serving")
before = roles()
t.proof("the roles before anything moved", json.dumps(before, indent=1))
r.goto("/cluster")
r.page.wait_for_timeout(1500)
t.shot("cluster-before-failover", full=True)
t.config("before")
t.ok("one node is active and one is standby",
     sorted(before.values()) == ["active", "standby"], before)
active_was = [n for n, role in before.items() if role == "active"][0]
standby_was = [n for n, role in before.items() if role == "standby"][0]
t.proof("both nodes serving before the move",
        f"lb01: {serving(LB01)}\nlb02: {serving(LB02)}")
t.ok("both nodes serve before the move",
     serving(LB01) == 200 and serving(LB02) == 200, "")

t.step(f"ask for {standby_was} to become active")
res = r.api("POST", "/cluster/failover", {"node": standby_was})
t.proof("POST /api/cluster/failover", json.dumps(res, indent=1)[:600])
t.ok("the request was accepted", res["status"] == 200, res)
t.ok("it reports that it worked",
     (res["body"] or {}).get("ok") is True
     and (res["body"] or {}).get("active") == standby_was, res["body"])

t.step("watch the roles for thirty seconds, and the traffic with them")
timeline = []
for i in range(15):
    time.sleep(2)
    now = roles()
    timeline.append({"t": (i + 1) * 2, "roles": now,
                     "lb01": serving(LB01), "lb02": serving(LB02)})
t.proof("what the active node reported, every two seconds",
        "\n".join(f"t+{row['t']:<3}s  " +
                  "  ".join(f"{k}={v}" for k, v in sorted(row["roles"].items())) +
                  f"   traffic lb01={row['lb01']} lb02={row['lb02']}"
                  for row in timeline))
r.goto("/cluster")
r.page.wait_for_timeout(1500)
t.shot("cluster-after-failover", full=True)

for extra, name in (("failover-timeline.txt",
                     "the same failover watched from both nodes at once, each "
                     "reporting its own database"),
                    ("pin-timeline.txt",
                     "the other route to the same thing: pinning the active "
                     "node to standby, watched from both nodes")):
    path = pathlib.Path("/qa/evidence") / extra
    if path.is_file():
        t.proof(name, path.read_text()[:2600])

ever_active = any(row["roles"].get(standby_was) == "active" for row in timeline)
still_active = timeline[-1]["roles"].get(standby_was) == "active"
t.ok(f"{standby_was} became active at some point", ever_active,
     "it never held the role at all")
t.ok(f"{standby_was} still holds the role thirty seconds later", still_active,
     f"the role went back to {active_was} on its own, so the failover did not stick")

t.step("traffic is the part that must not have suffered")
served = [(row["lb01"], row["lb02"]) for row in timeline]
t.proof("traffic on both nodes across the whole window", json.dumps(served))
t.ok("neither node stopped serving at any point",
     all(a == 200 and b == 200 for a, b in served), served)

t.step("check the fleet settled somewhere consistent")
final = roles()
t.proof("the roles at the end", json.dumps(final, indent=1))
t.config("after")
t.ok("exactly one node is active at the end",
     list(final.values()).count("active") == 1, final)
r.goto("/cluster")
r.page.wait_for_timeout(1200)
t.shot("cluster-settled", full=True)

t.note("the fleet returns to its starting state on its own, and traffic is "
       "unaffected throughout, so this is a control plane fault rather than "
       "an outage")
t.close()

r.stop()
print("\nT15 DONE")
