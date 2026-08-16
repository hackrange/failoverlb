"""
What the rules caught, gathered from every node and made into a decision.

Two jobs live here.  Collecting the hits, which is mostly merging what each
node saw, and deciding which of them somebody is allowed to whitelist, which is
the part that matters.

**The address filter is the safeguard, not a convenience.**  A firewall that
whitelists whatever fired while it was learning is a gift to anybody scanning
the site at the time: their probes become permanent exclusions, and nothing in
the interface would ever say so.  So a hit is only ever a candidate when it
came from an address somebody named as a tester **before** the traffic
happened.  Everything else is shown, because it is the more interesting half —
either a real attack or a real user meeting a false positive — and those need
different answers.
"""
import ipaddress
import logging

from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.waf.hits")


def parse_addresses(raw):
    """
    Turn what somebody typed into networks, and say what could not be read.

    Accepts one per line or comma separated, addresses or CIDRs, v4 or v6.  A
    bare address becomes a /32 or /128 so everything downstream compares the
    same way.

    What cannot be parsed is returned rather than dropped.  Silently ignoring a
    typo in a tester address means the page shows fewer candidates than
    expected and the reason is invisible, and somebody then widens the filter
    to compensate, which is exactly the wrong direction.
    """
    if isinstance(raw, str):
        parts = [p.strip() for p in raw.replace(",", "\n").splitlines()]
    else:
        parts = [str(p).strip() for p in (raw or [])]

    networks, bad = [], []
    for part in parts:
        if not part:
            continue
        try:
            networks.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            bad.append(part)
    return networks, bad


def address_matches(client, networks):
    """Whether one client address falls inside any tester network."""
    if not networks or not client:
        return False
    try:
        address = ipaddress.ip_address(str(client).strip())
    except ValueError:
        return False
    return any(address in net for net in networks)


async def fleet_hits(site: str, since=None) -> dict:
    """
    Every node's hits for one site, merged.

    Both nodes rather than the active one.  Whichever node was active while the
    testers were working is the one holding the evidence, and that is not
    necessarily the node somebody is looking at now — least of all after a
    failover, which is exactly when people go looking.
    """
    payload = {"site": site}
    if since is not None:
        payload["since"] = float(since)

    results = await ask_every_node("waf_hits", payload)

    merged = {}
    nodes = {}
    total = 0
    partial = False

    for name, answer in results.items():
        nodes[name] = {
            "present": bool(answer.get("present")),
            "transactions": answer.get("transactions") or 0,
            "bytes": answer.get("bytes") or 0,
            "error": answer.get("error"),
        }
        if answer.get("truncated_read") or answer.get("capped_groups"):
            partial = True

        for group in answer.get("groups") or []:
            key = (str(group.get("rule_id")), group.get("path") or "")
            into = merged.get(key)
            if into is None:
                into = merged[key] = {
                    "rule_id": key[0],
                    "path": key[1],
                    "message": group.get("message") or "",
                    "severity": group.get("severity") or "",
                    "count": 0,
                    "blocked": 0,
                    "clients": {},
                    "sample_uri": group.get("sample_uri") or "",
                    "first_seen": group.get("first_seen"),
                    "last_seen": group.get("last_seen"),
                    "nodes": [],
                }
            into["count"] += group.get("count") or 0
            into["blocked"] += group.get("blocked") or 0
            into["nodes"].append(name)
            for client, hits in (group.get("clients") or []):
                into["clients"][client] = into["clients"].get(client, 0) + hits
            for field, pick in (("first_seen", min), ("last_seen", max)):
                mine, theirs = into.get(field), group.get(field)
                if theirs is not None:
                    into[field] = theirs if mine is None else pick(mine, theirs)

        total += answer.get("transactions") or 0

    groups = sorted(merged.values(), key=lambda g: g["count"], reverse=True)
    for group in groups:
        group["clients"] = sorted(group["clients"].items(),
                                  key=lambda kv: kv[1], reverse=True)
        group["nodes"] = sorted(set(group["nodes"]))

    return {"site": site, "groups": groups, "transactions": total,
            "nodes": nodes, "partial": partial}


def split_by_tester(groups, networks):
    """
    Candidates and everything else, and never the two in one list.

    A group is a candidate only when **every** address that produced it is a
    tester.  Not "any", which is the tempting version and the wrong one: a
    group that a tester and a stranger both triggered is exactly the shape of
    an attack that happened to arrive during a test window, and whitelisting it
    on the strength of the tester's half is the failure this whole design
    exists to prevent.

    Mixed groups are called out as their own thing rather than quietly dropped
    into the other pile, because they are the ones worth a person's attention.
    """
    candidates, mixed, others = [], [], []

    for group in groups:
        clients = [c for c, _ in group.get("clients") or []]
        if not networks or not clients:
            others.append(group)
            continue

        inside = [c for c in clients if address_matches(c, networks)]
        if len(inside) == len(clients):
            candidates.append(group)
        elif inside:
            group = dict(group, tester_clients=inside,
                         other_clients=[c for c in clients if c not in inside])
            mixed.append(group)
        else:
            others.append(group)

    return {"candidates": candidates, "mixed": mixed, "others": others}


async def clear_fleet(site: str) -> dict:
    """Throw away what was learned, on every node, for one site."""
    results = await ask_every_node("waf_hits_clear", {"site": site})

    cleared = {name: r.get("cleared") or 0
               for name, r in results.items() if r.get("ok")}
    failed = {name: r.get("error") or "failed"
              for name, r in results.items() if not r.get("ok")}

    log.warning("cleared WAF hits for %s on %s%s", site,
                ", ".join(sorted(cleared)) or "nothing",
                f", failed on {failed}" if failed else "")
    return {"ok": not failed, "cleared": cleared, "failed": failed}


async def log_status() -> dict:
    """
    How much disk the audit logs are using, per node.

    Its own call because it is the answer to a different question from "what
    fired": a site under a scan in watching mode writes steadily, and filling
    the disk on a load balancer is a worse outage than anything the firewall
    prevents.
    """
    results = await ask_every_node("waf_log_status", {})

    nodes = {}
    for name, answer in results.items():
        nodes[name] = {
            "total": answer.get("total") or 0,
            "cap": answer.get("cap"),
            "free_bytes": answer.get("free_bytes"),
            "logs": answer.get("logs") or [],
            "error": answer.get("error"),
            "over": [l["site"] for l in (answer.get("logs") or []) if l.get("over_cap")],
        }
    return {"nodes": nodes,
            "any_over": any(n["over"] for n in nodes.values())}
