"""
Watching a site's login for password guessing.

Brute force is one address trying many times; any lockout stops it.
Password spraying is the reverse: one password tried once against many
accounts from many addresses.  No per-account lockout or per-address rate
limit fires.  The signal only shows in aggregate (many failures spread thin
across many addresses in a window), so this looks at the whole site at once.

It reads the access log only: address, path, method, status.  It never sees
usernames or passwords, so it can report the pattern but not which accounts
were targeted.  Seeing usernames would mean reading request bodies, where
the passwords are.

It always reads every node.  Evidence lives on whichever load balancer served
the request, and looking at one node can halve a spray's signal and drop it
under the threshold.
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
    Turn failure counts into findings.

    Brute force: one address over a threshold.

    Spray: enough total failures, across enough distinct addresses, with each
    address staying low.  Each condition alone is normal traffic; only the
    combination is suspicious.

    Slow spray: the same test over hours instead of minutes, for attackers
    who wait out short windows.

    Returns findings, not actions.  Blocking is left to a person, since a
    "spray" is sometimes a corporate NAT after a password policy change.
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
