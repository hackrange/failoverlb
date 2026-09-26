"""
WAF hits gathered from every node, and which of them may be whitelisted.

The tester address filter is a safeguard, not a convenience.  Whitelisting
whatever fired during learning would turn anyone scanning the site at the
time into a permanent exclusion.  A hit is only a candidate when it came from
an address named as a tester before the traffic happened.  Everything else
is still shown: it is either a real attack or a real user hitting a false
positive, and those need different answers.
"""
import ipaddress
import logging

from app.core.fleet_verbs import ask_every_node

log = logging.getLogger("nfm.waf.hits")


def parse_addresses(raw):
    """
    Parse tester addresses (one per line or comma separated, v4 or v6,
    addresses or CIDRs).  Returns (networks, unparsed).

    Bad entries are returned, not dropped, so a typo is visible instead of
    tempting someone to widen the filter.
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

    All nodes, since the evidence is on whichever node was active during
    testing, which after a failover is not the one you are looking at.

    `until` lets a finished session be read back; without it, stopping a
    session hid its own hits.
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
    The positive model's version of `fleet_hits`: the application's paths
    as every node saw them, merged on the templated path.  Without merging,
    a saved surface would only cover pages that landed on one node.
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
    Split surface entries into tester-only, mixed, and others.

    Same safeguard as split_by_tester, and it matters more here: a surface
    entry learned from a stranger permanently allows a path they probed.
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
    Split hit groups into candidates, mixed, and others.

    A group is a candidate only when every client was a tester, not any.  A
    group triggered by both a tester and a stranger may be an attack that
    arrived during testing.  Mixed groups are listed separately because they
    deserve a person's attention.
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
    Rotate any audit log past its cap, on every node.  A standby with a full
    disk can't take over.  The agent owns the cap and the copying.
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
    Disk used by the audit logs, per node.  A scanned site in watching mode
    writes steadily, and a full disk on a load balancer is its own outage.
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
