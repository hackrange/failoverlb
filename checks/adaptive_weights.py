"""
Adaptive weights: the feature nothing was testing.

Found by the mutation harness rather than by reading: breaking the weight
calculation on purpose changed no check's answer, because no check and no suite
mentioned it.  A feature that quietly moves traffic between backends, with
nothing watching it, is one that can start doing the opposite of what it says
and nobody would know until a backend fell over under load it should never have
been sent.

The rules it is supposed to follow, each checked below:

  off unless somebody turned it on
  needs at least two healthy backends with a response time to compare
  left alone when everything is uniformly slow, because that is a downstream
    problem and shuffling weights just piles load on the least broken box
  left alone when the spread is small, because that is noise
  a faster backend gets more weight, within a floor and a ceiling
  and it moves one step at a time, or traffic sloshes back and forth every
    cycle

No database and no network: the method takes a pool and reads settings off it,
so the pool is a stand in and nothing is written anywhere.

    docker exec -i nginx-fleet-manager python < checks/adaptive_weights.py
"""
import sys

from app.core.health import HealthChecker
from app.models import MemberState

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {str(detail)[:300]}")
    return ok


class Member:
    def __init__(self, label, ms, weight=10, state=MemberState.UP, enabled=True):
        self.label = label
        self.avg_response_ms = ms
        self.weight = weight
        self.state = state
        self.enabled = enabled


class Pool:
    def __init__(self, members, **settings):
        self.name = "check-adaptive"
        self.members = members
        self._settings = {"adaptive_weight_enabled": True, **settings}

    def setting_map(self):
        return self._settings


checker = HealthChecker(node_name="check")


def weights(members, **settings):
    """Run one cycle and give back what the weights became."""
    pool = Pool(members, **settings)
    changed = checker.adjust_weights(None, pool)
    return changed, {m.label: m.weight for m in members}


print("\n  adaptive weights\n")

# ---- off unless asked for --------------------------------------------------
changed, after = weights([Member("a", 10), Member("b", 200)],
                         adaptive_weight_enabled=False)
check("it does nothing at all when it is switched off",
      changed is False and after == {"a": 10, "b": 10}, after)

# ---- needs something to compare -------------------------------------------
changed, after = weights([Member("a", 10)])
check("one backend is not a comparison, so nothing moves",
      changed is False and after == {"a": 10}, after)

changed, after = weights([Member("a", None), Member("b", None)])
check("backends with no timing yet are left alone",
      changed is False, after)

changed, after = weights([Member("a", 10),
                          Member("b", 200, state=MemberState.DOWN)])
check("a backend that is down is not weighed against a healthy one",
      changed is False, after)

# ---- uniformly slow is a downstream problem --------------------------------
changed, after = weights([Member("a", 4000), Member("b", 9000)],
                         adaptive_floor_ms=1000)
check("everything being slow is left alone rather than shuffled",
      changed is False and after == {"a": 10, "b": 10},
      "weights moved while every backend was slow, which piles load onto "
      "whichever one is least broken")

# ---- a small spread is noise ----------------------------------------------
changed, after = weights([Member("a", 100), Member("b", 110)])
check("a spread too small to mean anything is left alone",
      changed is False and after == {"a": 10, "b": 10}, after)

# ---- the real case ---------------------------------------------------------
fast, slow = Member("fast", 50), Member("slow", 400)
changed, after = weights([fast, slow])
check("a clear difference does move the weights", changed is True, after)
check("and it is the slow one that loses weight", after["slow"] < 10, after)
check("while the fast one is not pushed above where it started",
      after["fast"] <= 10, after)

# ---- one step at a time ----------------------------------------------------
check("it moves one step, not straight to the answer",
      after["slow"] == 9,
      f"the slow backend went from 10 to {after['slow']} in one cycle, which "
      f"is how traffic ends up sloshing between backends")

# and keeps going on later cycles rather than stopping after one
for _ in range(6):
    changed, after = weights([fast, slow])
check("repeated cycles keep walking it down towards the ideal",
      after["slow"] < 9, after)

# The other direction, which the first version of this check never exercised.
#
# Both moves are one step at a time and they are separate branches in the
# code.  Testing only the backend losing weight left the branch that gains it
# untested, and the mutation harness walked straight through: making a gaining
# backend jump to its ideal in one cycle changed nothing here.
riser = Member("riser", 50, weight=1)
plodder = Member("plodder", 400, weight=10)
changed, after = weights([riser, plodder], adaptive_max_weight=20)
check("a backend that deserves more weight gains it",
      after["riser"] > 1, after)
check("and gains it one step at a time, not in one jump",
      after["riser"] == 2,
      f"the fast backend went from 1 to {after['riser']} in a single cycle, "
      f"which is the sloshing this is supposed to avoid")

# ---- the floor and the ceiling --------------------------------------------
crawler = Member("crawler", 100000, weight=3)
quick = Member("quick", 10, weight=3)
for _ in range(30):
    weights([quick, crawler], adaptive_min_weight=2, adaptive_max_weight=5,
            adaptive_floor_ms=1000000)
check("a hopeless backend is never taken below the floor",
      crawler.weight >= 2, crawler.weight)
check("and a fast one is never taken above the ceiling",
      quick.weight <= 5, quick.weight)
check("a backend is never weighted to zero, which would take it out of "
      "rotation on timing alone", crawler.weight >= 1, crawler.weight)

failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: adaptive weights move carefully or not at all "
      f"({len(results)} checks)\n")
