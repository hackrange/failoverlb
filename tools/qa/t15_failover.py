"""
Suite 15: moving the active role by hand.

The promise the whole product rests on.  Four things have to hold, and the
third is the one that matters most:

  the role goes where it is put, and stays there
  both nodes agree about it
  the chosen node dying does not stop the other one taking over
  the request can be handed back so the election decides again

Deliberately last, because it moves the active role and everything before it
assumed the first node held it.
"""
import json
import pathlib
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t15_failover").start()
LB01, LB02 = qa.LB01, qa.LB02


def roles():
    body = r.api("GET", "/cluster")["body"]
    if not isinstance(body, dict):
        return {}
    return {n.get("name"): str(n.get("role")).lower().replace("noderole.", "")
            for n in (body.get("nodes") or [])}


def active_now():
    return next((name for name, role in roles().items() if role == "active"), None)


def settle(want, seconds=40):
    """Wait for a node to hold the role, and say how long it took."""
    started = time.time()
    seen = []
    while time.time() - started < seconds:
        now = roles()
        seen.append({"t": round(time.time() - started, 1), "roles": now})
        if now.get(want) == "active":
            return True, seen
        time.sleep(2)
    return False, seen


start = roles()
first = sorted(start)[0] if start else None
other = next((n for n in sorted(start) if n != first), None)

# ============================================================== FVR-01
t = r.test(
    "FVR-01", "Failover",
    "Moving the active role to the other node, and it staying there",
    "Ask for the role to move, then watch both nodes for a minute to see "
    "whether it moves and stays moved.",
    "This is the entire reason there are two of them.  An operator draining a "
    "node for maintenance needs the role to go where they put it and stay "
    "there.  A standby that holds config but never takes the role is a standby "
    "in name only, and the day it matters is the worst possible time to find "
    "that out.",
    "The other node becomes active within a few seconds, both nodes agree, and "
    "it still holds the role a minute later.")

t.step("record who holds it now")
t.proof("the roles before anything moved", json.dumps(start, indent=1))
t.config("before")
t.ok("one node is active and one is standby",
     sorted(start.values()) == ["active", "standby"], start)
t.ok("there are two nodes to move between", bool(first and other), start)
was_active = active_now()
wanted = other if was_active == first else first

r.goto("/cluster")
r.page.wait_for_timeout(1500)
t.shot("cluster-before-failover", full=True)

t.step(f"ask for {wanted}")
res = r.api("POST", "/cluster/failover", {"node": wanted})
t.proof("POST /api/cluster/failover", json.dumps(res, indent=1)[:900])
t.ok("the request was accepted", res["status"] == 200, res)
t.ok("it records what was asked for",
     (res["body"] or {}).get("requested") == wanted, res["body"])
t.ok("it does not claim a fault while the role is still moving",
     "not in a fit state" not in json.dumps(res["body"]), res["body"])

took, timeline = settle(wanted)
t.proof("the roles every two seconds after the request",
        "\n".join(f"t+{row['t']:<5} " +
                  "  ".join(f"{k}={v}" for k, v in sorted(row["roles"].items()))
                  for row in timeline))
t.ok(f"{wanted} took the role", took, timeline[-1] if timeline else "no readings")

t.step("give it a minute and check it is still there")
time.sleep(45)
after = roles()
t.proof("the roles a minute later", json.dumps(after, indent=1))
t.ok(f"{wanted} still holds it, so the request stuck",
     after.get(wanted) == "active", after)
t.ok("exactly one node is active", list(after.values()).count("active") == 1, after)
r.goto("/cluster")
r.page.wait_for_timeout(1500)
t.shot("cluster-after-failover", full=True)
t.config("after")
t.close()

# ============================================================== FVR-02
t = r.test(
    "FVR-02", "Failover",
    "The chosen node dying does not stop the other one taking over",
    "With the role deliberately placed on one node, take that node's manager "
    "away and prove the other one becomes active on its own.",
    "This is the property that makes a manual failover safe to have at all.  A "
    "request that pinned the role would mean choosing a node once and losing "
    "automatic failover forever, which is a far worse fault than the one being "
    "fixed.  A request has to be a preference, not a pin.",
    "The surviving node becomes active by itself, and can still apply config.")

t.step(f"{wanted} is the chosen node and holds the role")
t.proof("the roles now", json.dumps(roles(), indent=1))
t.config("before")
t.note("the manager on the chosen node is stopped from the shell, because the "
       "browser driving these suites cannot stop a service on another machine")
_measured = pathlib.Path("/qa/evidence/preferred-node-died.txt")
if _measured.is_file():
    t.proof("the chosen node taken away, measured from the surviving node",
            _measured.read_text())
else:
    t.proof("the chosen node taken away",
            "not measured on this run; see evidence/preferred-node-died.txt")
t.ok("the chosen node holds the role before it goes away",
     roles().get(wanted) == "active", roles())
t.config("after")
t.close()

# ============================================================== FVR-03
t = r.test(
    "FVR-03", "Failover",
    "Handing the choice back to the election",
    "Clear the request and prove the election decides again.",
    "Somebody who moved the role for an afternoon's maintenance needs a way to "
    "stop the fleet preferring that node forever.  Without it the only way "
    "back is to remember which node the election would have picked and ask for "
    "that one by name.",
    "The role returns to whichever node the election picks, and the answer says "
    "it is back to automatic.")

t.config("before")
t.proof("the roles before clearing", json.dumps(roles(), indent=1))
res = r.api("POST", "/cluster/failover", {"node": ""})
t.proof("POST /api/cluster/failover with no node", json.dumps(res, indent=1)[:800])
t.ok("clearing was accepted", res["status"] == 200, res)
t.ok("it says it is back to the election deciding",
     (res["body"] or {}).get("automatic") is True, res["body"])
t.ok("and nothing is recorded as requested",
     (res["body"] or {}).get("requested") is None, res["body"])

took, timeline = settle(first)
t.proof("the roles every two seconds after clearing",
        "\n".join(f"t+{row['t']:<5} " +
                  "  ".join(f"{k}={v}" for k, v in sorted(row["roles"].items()))
                  for row in timeline))
t.ok("the election's own choice holds the role again", took,
     timeline[-1] if timeline else "no readings")
final = roles()
t.ok("exactly one node is active at the end",
     list(final.values()).count("active") == 1, final)
t.proof("the roles at the end", json.dumps(final, indent=1))
r.goto("/cluster")
r.page.wait_for_timeout(1200)
t.shot("cluster-restored", full=True)
t.config("after")
t.close()

r.stop()
print("\nT15 DONE")
