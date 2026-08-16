"""
Watching a site's login for guessing, and the two shapes that takes.

**Brute force** is one address trying many times.  Every lockout ever written
stops it and it is the one everybody thinks of.

**Password spraying** is the opposite shape and is the reason this module
exists.  One password, tried once against a hundred accounts, from a hundred
addresses.  Each account sees a single failed attempt, so no per account
lockout fires.  Each address makes a handful of requests, so no rate limit
fires either.  It is invisible to both of the defences people already have, and
it is how accounts are actually taken now.

The signal only exists in the aggregate: many failures, spread thin across many
addresses, in a window.  Nothing looking at one account or one address can see
it, which is why this looks at the whole site at once.

## What it can and cannot see

It reads the access log, so it gets the address, the path, the method and the
status.  **It never sees a username or a password.**  So it cannot tell you
which accounts were targeted, only that the shape is there.  Making it see
usernames would mean reading request bodies, which is where the passwords are,
and that trade is not worth making for a detector.

## Both nodes, always

Whichever load balancer was serving is the one holding the evidence, and a
spray spread across a fleet is exactly the case where looking at one node halves
the signal and can put it under the threshold.
"""
import logging

from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.login")


async def fleet_failures(site: str, paths, methods, fail_statuses,
                         since=None) -> dict:
    """Every node's failed logins for one site, merged by address."""
    payload = {
        "site": site,
        "paths": list(paths or []),
        "methods": list(methods or ["POST"]),
        "fail_statuses": list(fail_statuses or [401, 403]),
    }
    if since is not None:
        payload["since"] = float(since)

    results = await ask_every_node("login_failures", payload)

    merged = {}
    nodes = {}
    failures = successes = 0
    partial = False

    for name, answer in results.items():
        nodes[name] = {
            "present": bool(answer.get("present")),
            "failures": answer.get("failures") or 0,
            "successes": answer.get("successes") or 0,
            "error": answer.get("error"),
        }
        if answer.get("truncated_read") or answer.get("capped_addresses"):
            partial = True

        for entry in answer.get("addresses") or []:
            address = entry.get("address")
            if not address:
                continue
            into = merged.setdefault(address, {
                "address": address, "count": 0, "paths": {},
                "first_seen": entry.get("first_seen"),
                "last_seen": entry.get("last_seen"),
                "nodes": [],
            })
            into["count"] += entry.get("count") or 0
            into["nodes"].append(name)
            for path, hits in (entry.get("paths") or []):
                into["paths"][path] = into["paths"].get(path, 0) + hits
            for field, pick in (("first_seen", min), ("last_seen", max)):
                mine, theirs = into.get(field), entry.get(field)
                if theirs is not None:
                    into[field] = theirs if mine is None else pick(mine, theirs)

        failures += answer.get("failures") or 0
        successes += answer.get("successes") or 0

    addresses = sorted(merged.values(), key=lambda a: a["count"], reverse=True)
    for entry in addresses:
        entry["paths"] = sorted(entry["paths"].items(),
                                key=lambda kv: kv[1], reverse=True)
        entry["nodes"] = sorted(set(entry["nodes"]))

    return {"site": site, "addresses": addresses, "failures": failures,
            "successes": successes, "nodes": nodes, "partial": partial}


def judge(addresses, failures, watch, window_seconds, slow=False) -> dict:
    """
    What the numbers mean, if anything.

    Three rules and each one exists because the other two miss something.

    **Brute force** is one address over a threshold.  Easy, and the only one of
    the three that a normal rate limit would also have caught.

    **A spray** needs all of: enough total failures to matter, spread across
    enough distinct addresses, with each address staying low.  All three
    together, because any one alone is an ordinary Monday morning.  A busy
    login page has plenty of failures; a big office has plenty of addresses;
    everybody typing their password wrong once is exactly "low per address".
    It is the combination that does not happen by accident.

    **The slow version** is the same test over hours rather than minutes,
    because an attacker who knows about five minute windows waits six.  It is
    the one most likely to be quietly missing from anybody else's detector.

    Returns findings rather than actions.  Deciding to refuse traffic on the
    strength of a pattern is a person's call: the addresses in a spray are
    usually a botnet, and they are sometimes a corporate NAT having a bad
    morning after a password policy change.
    """
    findings = []
    count = len(addresses)

    if not slow:
        loud = [a for a in addresses if a["count"] >= watch.brute_threshold]
        for entry in loud:
            findings.append({
                "kind": "brute_force",
                "address": entry["address"],
                "failures": entry["count"],
                "why": (f"{entry['count']} failed logins from one address in "
                        f"{window_seconds // 60} minutes, against a threshold "
                        f"of {watch.brute_threshold}"),
            })

    if slow:
        min_addresses = watch.slow_min_addresses
        min_failures = watch.slow_min_failures
    else:
        min_addresses = watch.spray_min_addresses
        min_failures = watch.spray_min_failures

    thin = [a for a in addresses if a["count"] <= watch.spray_max_per_address]
    if (failures >= min_failures
            and count >= min_addresses
            and len(thin) >= min_addresses):
        findings.append({
            "kind": "slow_spray" if slow else "spray",
            "address": None,
            "failures": failures,
            "addresses": len(thin),
            "why": (f"{failures} failed logins from {count} addresses in "
                    f"{window_seconds // 60} minutes, and {len(thin)} of them "
                    f"tried {watch.spray_max_per_address} times or fewer.  "
                    f"That is the shape of one password against many accounts, "
                    f"which no per account lockout and no rate limit will see."),
        })

    return {"findings": findings, "addresses_seen": count,
            "failures": failures, "window_seconds": window_seconds}
