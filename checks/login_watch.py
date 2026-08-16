"""
Spotting somebody working through a password list, and the shape that matters.

Two attacks, and only one of them is the reason this exists.

**Brute force** is one address trying many times.  Every lockout ever written
stops it, including this project's own, and any rate limit catches it too.

**Password spraying** is the opposite shape.  One password, tried once against
a hundred accounts, from a hundred addresses.  Each account sees a single
failed attempt so no per account lockout fires.  Each address makes a handful
of requests so no rate limit fires.  It is invisible to both of the defences
people already have, and that invisibility is the whole point of it.

So the assertions below are mostly about the spray rules, and specifically
about the two ways a detector like this fails in practice:

  * it cries wolf, somebody switches it off, and then it is worth nothing.  A
    busy login page has plenty of failures.  A big office has plenty of
    addresses.  Everybody typing their password wrong once is exactly "few per
    address".  Any one of those alone must not trip it.
  * it misses the slow version, because the attacker waited six minutes.

    docker exec -i nginx-fleet-manager python < checks/login_watch.py
"""
import sys
import types

from app.core.login_watch import judge

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"          {detail}")


def watch(**over):
    """The defaults a site starts with, with anything worth varying overridden."""
    base = dict(brute_threshold=10, spray_min_addresses=12,
                spray_min_failures=20, spray_max_per_address=3,
                slow_min_addresses=25, slow_min_failures=60)
    base.update(over)
    return types.SimpleNamespace(**base)


def addresses(spec):
    """[(count, how many addresses like that)] into what the judge reads."""
    out, n = [], 0
    for count, many in spec:
        for _ in range(many):
            n += 1
            out.append({"address": f"10.0.0.{n}", "count": count})
    return out


def kinds(found):
    return sorted(f["kind"] for f in found["findings"])


print("\n=== Watching a login for guessing ===\n")

print("  brute force, which is the easy one")

one_loud = addresses([(25, 1), (1, 3)])
check("one address over the threshold is called",
      "brute_force" in kinds(judge(one_loud, 28, watch(), 300)),
      "the shape every lockout already catches has to be caught here too")

check("an address under the threshold is not",
      "brute_force" not in kinds(judge(addresses([(9, 1)]), 9, watch(), 300)),
      "nine failures is somebody who forgot their password, and reporting it "
      "is how this gets switched off in week one")

check("brute force is not looked for in the slow window",
      "brute_force" not in kinds(judge(one_loud, 28, watch(), 21600, slow=True)),
      "twenty five failures from one address over six hours is a person with "
      "a saved password that changed, not an attack, and the short window has "
      "already had its say")


print()
print("  password spraying, which is the one nothing else sees")

spray = addresses([(2, 15)])          # 15 addresses, 2 tries each, 30 failures
check("many addresses trying a little each is called a spray",
      "spray" in kinds(judge(spray, 30, watch(), 300)),
      "this is the shape no per account lockout and no rate limit can see, "
      "and it is the whole reason for this feature")

check("and it is not also called brute force",
      "brute_force" not in kinds(judge(spray, 30, watch(), 300)),
      "two failures from one address is nothing on its own")


print()
print("  the three ways a detector cries wolf")

# Each of these has one of the three ingredients and must not fire.
check("plenty of failures from a few addresses is not a spray",
      "spray" not in kinds(judge(addresses([(2, 4)]), 40, watch(), 300)),
      "a busy login page behind one office NAT would report every morning")

check("plenty of addresses with almost no failures is not a spray",
      "spray" not in kinds(judge(addresses([(1, 14)]), 14, watch(), 300)),
      "fourteen people mistyping a password once is a Monday, not an attack")

check("plenty of failures from addresses that each tried hard is not a spray",
      "spray" not in kinds(judge(addresses([(20, 14)]), 280, watch(), 300)),
      "that is fourteen brute forces, which the brute force rule reports on "
      "its own with the address attached, and calling it a spray as well "
      "would double report the same thing")

check("exactly at the thresholds it does fire",
      "spray" in kinds(judge(addresses([(1, 12)]), 20, watch(), 300)),
      "a rule that needs one more than its stated threshold is a rule whose "
      "number on the page is a lie")


print()
print("  the slow version, which is what somebody does once they know")

slow = addresses([(2, 30)])           # 30 addresses over six hours
check("the same shape over hours is called, with its own thresholds",
      "slow_spray" in kinds(judge(slow, 60, watch(), 21600, slow=True)),
      "somebody who knows detectors use five minute windows waits six")

check("and the short window's thresholds do not apply to it",
      "slow_spray" not in kinds(judge(addresses([(2, 15)]), 30,
                                      watch(), 21600, slow=True)),
      "thirty failures over six hours is background noise on a public login, "
      "and using the five minute numbers over six hours reports it every day")

check("a spray in the short window is not labelled slow",
      kinds(judge(spray, 30, watch(), 300)) == ["spray"],
      "the label is what tells somebody how urgent it is")


print()
print("  nothing at all")

check("a quiet site produces no findings",
      not judge([], 0, watch(), 300)["findings"])
check("a site with only successful logins produces no findings",
      not judge([], 0, watch(), 300)["findings"],
      "successes are counted separately and are never evidence of anything")


print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed")
print()
print("  what this does not cover:")
print("    - reading a real access log, which is the agent's half")
print("    - whether the status codes somebody chose really mean a failure on")
print("      their application, which nothing but a person can know")
print("    - usernames, which this deliberately never sees")
print()
print("  RESULT:", "the rules hold" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
