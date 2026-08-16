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
happened.  Everything else is shown, because it is the more interesting half.  It is either a real attack or
a real user meeting a false positive, and those need different answers.
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


async def fleet_hits(site: str, since=None, until=None) -> dict:
    """
    Every node's hits for one site, merged.

    Both nodes rather than the active one.  Whichever node was active while the
    testers were working is the one holding the evidence, and that is not
    necessarily the node somebody is looking at now, least of all after a
    failover, which is exactly when people go looking.

    `until` is what makes a finished session readable.  The window used to be
    open ended, so the only thing anybody could ask for was "since the running
    session started", and stopping a session therefore hid its own evidence.
    The hits were still in the log the whole time, which is the part that made
    it costly: somebody had exercised an application properly, stopped
    watching, and had no way back to the work they had just done.
    """
    payload = {"site": site}
    if since is not None:
        payload["since"] = float(since)
    if until is not None:
        payload["until"] = float(until)

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


async def fleet_surface(site: str, since=None, until=None) -> dict:
    """
    What the application is, as every node saw it, merged.

    The positive model's version of `fleet_hits`.  Both nodes rather than the
    active one, for the same reason: whichever node was active while the
    testers worked is the one holding the evidence, and after a failover that
    is not the node somebody is looking at.

    Merging on the templated path is what makes this useful.  Two nodes each
    saw a different half of the walk, and without merging somebody would save a
    surface that only covers the pages that happened to land on one box.
    """
    payload = {"site": site}
    if since is not None:
        payload["since"] = float(since)
    if until is not None:
        payload["until"] = float(until)

    results = await ask_every_node("waf_surface", payload)

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

        for entry in answer.get("entries") or []:
            key = entry.get("path") or ""
            into = merged.get(key)
            if into is None:
                into = merged[key] = {
                    "path": key,
                    "methods": {},
                    "count": 0,
                    "clients": {},
                    "sample_uri": entry.get("sample_uri") or "",
                    "first_seen": entry.get("first_seen"),
                    "last_seen": entry.get("last_seen"),
                    "nodes": [],
                }
            into["count"] += entry.get("count") or 0
            into["nodes"].append(name)
            for method, hits in (entry.get("methods") or []):
                into["methods"][method] = into["methods"].get(method, 0) + hits
            for client, hits in (entry.get("clients") or []):
                into["clients"][client] = into["clients"].get(client, 0) + hits
            for field, pick in (("first_seen", min), ("last_seen", max)):
                mine, theirs = into.get(field), entry.get(field)
                if theirs is not None:
                    into[field] = theirs if mine is None else pick(mine, theirs)

        total += answer.get("transactions") or 0

    entries = sorted(merged.values(), key=lambda e: e["path"])
    for entry in entries:
        entry["methods"] = sorted(entry["methods"].items(),
                                  key=lambda kv: kv[1], reverse=True)
        entry["clients"] = sorted(entry["clients"].items(),
                                  key=lambda kv: kv[1], reverse=True)
        entry["nodes"] = sorted(set(entry["nodes"]))

    return {"site": site, "entries": entries, "transactions": total,
            "nodes": nodes, "partial": partial}


def split_surface_by_tester(entries, networks):
    """
    What a tester reached, and what everybody else did, never in one list.

    Same safeguard as the exclusion side and it matters more here.  An
    exclusion learned from a stranger switches one rule off.  A surface entry
    learned from a stranger **permanently allows a path they found**, which on
    a positive model is the one thing the model exists to prevent.  Somebody
    scanning the site during a round would otherwise get every path they probed
    written into the allowed list as though a tester had walked it.
    """
    mine, mixed, theirs = [], [], []
    for entry in entries:
        clients = entry.get("clients") or []
        from_tester = [c for c, _ in clients if address_matches(c, networks)]
        from_others = [c for c, _ in clients if not address_matches(c, networks)]
        if from_tester and not from_others:
            mine.append(entry)
        elif from_tester and from_others:
            mixed.append(entry)
        else:
            theirs.append(entry)
    return {"candidates": mine, "mixed": mixed, "others": theirs}


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


async def rotate_logs() -> dict:
    """
    Rotate any audit log past its cap, on every node.

    Every node rather than the active one.  A standby quietly filling its disk
    is a standby that cannot be failed over to, and that is discovered at
    exactly the moment it was needed.

    Nothing here decides the cap or does the copying: the agent owns both,
    because it is the only part that can see the disk it is protecting.
    """
    results = await ask_every_node("waf_log_rotate", {})

    rotated = {}
    failed = {}
    for name, answer in results.items():
        if answer.get("ok"):
            done = answer.get("rotated") or []
            if done:
                rotated[name] = done
        else:
            failed[name] = answer.get("error") or "failed"

    if rotated or failed:
        log.warning("rotated WAF logs: %s%s", rotated or "nothing",
                    f", failed on {failed}" if failed else "")
    return {"ok": not failed, "rotated": rotated, "failed": failed}


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
