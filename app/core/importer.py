"""
Turn a config somebody already has into sites and pools this system can manage.

This is the thing that decides whether anybody adopts the tool, because the
alternative is retyping a hundred server blocks by hand into a web page.

Two halves, deliberately separated.  `analyse` reads config text and works out
what it would become, touching nothing.  `apply_plan` takes the result of that
and writes it.  Nothing here decides on its own to change a running system, so
the preview can be run against production config by somebody who has not made
their mind up yet, which is the only way a careful person will ever try this.

## What it will not do

It refuses to guess.  Anything it cannot map to a real object goes into the
site's custom config box with a note saying so, and anything it cannot place at
all is reported as skipped with the reason.  Quietly dropping a directive
somebody depended on is the worst thing this could do: they would not find out
until the traffic did.

Certificates are noticed and never taken.  A `ssl_certificate` line points at a
file on a box this fleet does not manage, and copying that path into a site
would produce config that works until the file moves.  The path is reported so
the person can decide, and issuing a real certificate for those names is offered
as a separate step they choose.
"""
import logging
import re

from app.core.nginx_parser import (
    ParseError,
    extract_settings,
    extract_unknown,
    parse,
    serialize,
)
from app.models import Pool, PoolMember, VirtualHost, json_set

log = logging.getLogger("nfm.importer")

# nginx names are more permissive than ours.  Ours end up in filenames, so they
# get cleaned rather than rejected, and the original is kept in the notes.
SAFE_NAME = re.compile(r"[^A-Za-z0-9._-]+")


def _clean_name(raw: str, fallback: str) -> str:
    name = SAFE_NAME.sub("_", (raw or "").strip()).strip("_")
    return name or fallback


def _unquote(value: str) -> str:
    v = (value or "").strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "\"'":
        return v[1:-1]
    return v


def _args(directive):
    return [a for a in (directive.args or []) if a]


def _find_all(block, name: str) -> list:
    """Direct children of a block with this name.  Not recursive on purpose."""
    if not block.is_block:
        return []
    return [d for d in block.block if d.name == name]


def _first(block, name: str):
    found = _find_all(block, name)
    return found[0] if found else None


# ==============================================================================
# Reading upstreams
# ==============================================================================

def _read_upstream(block) -> dict:
    """One upstream block, as the pool it would become."""
    raw_name = _unquote(_args(block)[0]) if _args(block) else ""
    pool = {
        "raw_name": raw_name,
        "name": _clean_name(raw_name, "imported_pool"),
        "members": [],
        "lb_method": "round_robin",
        "keepalive": None,
        "notes": [],
    }

    if pool["name"] != raw_name:
        pool["notes"].append(
            f"renamed from {raw_name!r}, because names here end up in filenames"
        )

    for d in block.block if block.is_block else []:
        if d.name == "server":
            args = _args(d)
            if not args:
                continue
            target = _unquote(args[0])
            member = {"address": target, "port": 80, "weight": 1,
                      "backup": False, "max_fails": 3, "fail_timeout": 10,
                      "max_conns": 0}

            # host:port, or a bare host, or v6 in brackets
            if target.startswith("["):
                host, _, rest = target.partition("]")
                member["address"] = host.lstrip("[")
                if rest.startswith(":") and rest[1:].isdigit():
                    member["port"] = int(rest[1:])
            elif target.count(":") == 1:
                host, _, port = target.partition(":")
                member["address"] = host
                if port.isdigit():
                    member["port"] = int(port)

            for extra in args[1:]:
                if extra.startswith("weight="):
                    member["weight"] = int(extra.split("=", 1)[1] or 1)
                elif extra.startswith("max_fails="):
                    member["max_fails"] = int(extra.split("=", 1)[1] or 0)
                elif extra.startswith("max_conns="):
                    member["max_conns"] = int(extra.split("=", 1)[1] or 0)
                elif extra.startswith("fail_timeout="):
                    member["fail_timeout"] = int(
                        re.sub(r"[^0-9]", "", extra.split("=", 1)[1]) or 10
                    )
                elif extra == "backup":
                    member["backup"] = True
                elif extra == "down":
                    member["enabled"] = False

            pool["members"].append(member)

        elif d.name in ("least_conn", "ip_hash", "random"):
            pool["lb_method"] = d.name
        elif d.name == "hash":
            pool["lb_method"] = "hash"
            pool["hash_key"] = " ".join(_args(d))
        elif d.name == "keepalive":
            args = _args(d)
            if args and args[0].isdigit():
                pool["keepalive"] = int(args[0])

    # Every member on 443 almost certainly means the backend speaks https.  The
    # pool asks this question now, and answering it from what is there beats
    # making somebody work it out again after the import.
    if pool["members"] and all(m["port"] == 443 for m in pool["members"]):
        pool["backend_tls"] = True
        pool["notes"].append(
            "every backend is on 443, so this is set to talk to them over https"
        )

    return pool


# ==============================================================================
# Reading servers
# ==============================================================================

def _listen_info(block) -> dict:
    """What ports this server block listens on, and how."""
    info = {"http": False, "https": False, "http_port": 80, "https_port": 443,
            "default_server": False, "http2": False}

    for d in _find_all(block, "listen"):
        args = _args(d)
        if not args:
            continue
        spec = _unquote(args[0])
        ssl = "ssl" in args[1:] or "ssl" in spec.split()
        if "http2" in args[1:]:
            info["http2"] = True
        if "default_server" in args[1:]:
            info["default_server"] = True

        port = None
        bare = spec.rsplit("]", 1)[-1]
        if ":" in bare:
            tail = bare.rsplit(":", 1)[-1]
            if tail.isdigit():
                port = int(tail)
        elif bare.isdigit():
            port = int(bare)

        if ssl or port == 443:
            info["https"] = True
            if port:
                info["https_port"] = port
        else:
            info["http"] = True
            if port:
                info["http_port"] = port

    if not info["http"] and not info["https"]:
        info["http"] = True

    return info


def _looks_like_a_host(target: str) -> bool:
    """
    Is this a machine to talk to, or the name of an upstream declared elsewhere.

    A dot, a port, or brackets means a host.  A bare word means an upstream, and
    nginx itself works the same way round.  Guessing wrong in the host direction
    builds a pool pointing at something that will never resolve, so the bare
    word is treated as the upstream it almost certainly is.
    """
    bare = (target or "").split("/", 1)[0]
    return bool(bare) and ("." in bare or ":" in bare or bare.startswith("["))


def _read_server(block, pools_by_raw_name: dict, index: int) -> dict:
    """One server block, as the site it would become."""
    names = []
    for d in _find_all(block, "server_name"):
        names.extend(_unquote(a) for a in _args(d))
    names = [n for n in names if n and n != "_"]

    listen = _listen_info(block)
    primary = names[0] if names else f"imported_site_{index}"

    site = {
        "name": _clean_name(primary, f"imported_site_{index}"),
        "server_names": names,
        "listen_http": listen["http"],
        "listen_https": listen["https"],
        "http_port": listen["http_port"],
        "https_port": listen["https_port"],
        "default_server": listen["default_server"],
        "http2": listen["http2"],
        "force_https": False,
        "mode": "proxy",
        "pool": None,
        "document_root": None,
        "redirect_target": None,
        "redirect_code": 301,
        "settings": {},
        "custom_config": "",
        "cert_paths": [],
        "notes": [],
        "skipped": [],
    }

    if site["name"] != primary:
        site["notes"].append(f"renamed from {primary!r} to suit a filename")
    if not names:
        site["notes"].append(
            "this block had no server_name, so it was given a made up one"
        )

    # ---- certificates.  Noticed, never taken.
    for key in ("ssl_certificate", "ssl_certificate_key"):
        for d in _find_all(block, key):
            args = _args(d)
            if args:
                site["cert_paths"].append(_unquote(args[0]))
    if site["cert_paths"]:
        site["notes"].append(
            "this block points at certificate files on a box we do not manage, "
            "so no certificate was attached.  Issue one for these names, or "
            "upload the existing one, after the import."
        )

    # ---- what kind of site is it
    root = _first(block, "root")
    ret = _first(block, "return")

    if ret is not None:
        args = _args(ret)
        code = args[0] if args else "301"
        target = _unquote(args[1]) if len(args) > 1 else ""
        if code.isdigit() and target:
            site["mode"] = "redirect"
            site["redirect_code"] = int(code)
            site["redirect_target"] = target
        elif code.isdigit() and code in ("301", "302") and not target:
            site["skipped"].append(f"return {code} with nothing to return to")

    if site["mode"] != "redirect" and root is not None and _args(root):
        site["mode"] = "static"
        site["document_root"] = _unquote(_args(root)[0])

    # ---- locations
    #
    # The model has one pool per site and no location UI yet, so a config with
    # several is honest about it rather than silently serving only the first.
    locations = _find_all(block, "location")
    proxied = []
    for loc in locations:
        target = _first(loc, "proxy_pass")
        if target is None or not _args(target):
            continue
        path = " ".join(_unquote(a) for a in _args(loc)) or "/"
        proxied.append((path, _unquote(_args(target)[0]), loc))

    root_proxy = next((p for p in proxied if p[0].strip() in ("/", "= /")), None)
    chosen = root_proxy or (proxied[0] if proxied else None)

    # A root inside `location /` rather than on the server block.  This is at
    # least as common as the server level form, and missing it made a plain
    # static site look like a proxy with no backend, which then warned about a
    # problem that was not there.
    if site["mode"] != "redirect" and not chosen:
        for loc in locations:
            path = " ".join(_unquote(a) for a in _args(loc)).strip()
            if path not in ("/", "= /"):
                continue
            inner_root = _first(loc, "root")
            if inner_root is not None and _args(inner_root):
                site["mode"] = "static"
                site["document_root"] = _unquote(_args(inner_root)[0])
                break
            inner_return = _first(loc, "return")
            if inner_return is not None:
                args = _args(inner_return)
                code = args[0] if args else ""
                target = _unquote(args[1]) if len(args) > 1 else ""
                if code.isdigit() and target:
                    site["mode"] = "redirect"
                    site["redirect_code"] = int(code)
                    site["redirect_target"] = target
                break

    if chosen:
        path, target, loc = chosen
        site["mode"] = "proxy"
        upstream = target.split("://", 1)[-1].split("/", 1)[0]
        if upstream in pools_by_raw_name:
            site["pool"] = pools_by_raw_name[upstream]["name"]
        elif _looks_like_a_host(upstream):
            # proxy_pass straight at a host rather than an upstream.  Make a
            # pool for it, because everything downstream expects one.
            site["pool"] = None
            site["inline_backend"] = target
            site["notes"].append(
                f"proxy_pass points straight at {target}, so a pool was made for it"
            )
        else:
            # A bare word with no dot and no port is an upstream name, and if it
            # is not in what was pasted then it is declared in another file.
            # Inventing a pool with a backend called "gui_pool" would produce
            # something that looks right in the GUI and resolves to nothing at
            # all, which is a worse answer than saying what is missing.
            site["pool"] = None
            site["skipped"].append(
                f"the backend for this site is an upstream called {upstream!r}, "
                f"which is not in what you pasted.  Paste the file that declares "
                f"it as well, usually the one with the upstream blocks in, and "
                f"import again."
            )
        if target.startswith("https://"):
            site["backend_tls"] = True

        for extra_path, extra_target, _l in proxied:
            if (extra_path, extra_target) != (path, target):
                site["skipped"].append(
                    f"location {extra_path} proxying to {extra_target}, because a "
                    f"site here has one backend and there is no path routing UI yet"
                )

    for loc in locations:
        if loc in [c[2] for c in ([chosen] if chosen else [])]:
            continue
        if _is_acme_location(loc):
            # We write our own, on every node, whenever a certificate is issued.
            # Carrying somebody else's copy across would leave two.
            continue
        body = extract_unknown(loc)
        if body.strip():
            path = " ".join(_unquote(a) for a in _args(loc)) or "/"
            site["custom_config"] += f"\n# from location {path}\nlocation {path} {{\n{body}}}\n"

    # ---- settings we understand, and everything else kept verbatim
    site["settings"] = extract_settings(block) or {}
    leftover = extract_unknown(block)
    if leftover.strip():
        site["custom_config"] = (
            "# Kept from the imported config because there is no setting for it.\n"
            + leftover + site["custom_config"]
        )

    if site["custom_config"].strip():
        site["notes"].append(
            "some directives had no setting here, so they were kept as custom config"
        )

    # A plain http block that only redirects to https is how everybody writes
    # "force https", and we have a switch for exactly that.
    #
    # The acme-challenge location does not count against it.  Every config that
    # has ever renewed a certificate carries that block, and treating it as real
    # content meant these were never recognised, so each site came through twice,
    # once for each port, under one name.  The second one then collided with the
    # first and was dropped as already existing, which quietly lost the https
    # half of every site.
    real_locations = [l for l in locations if not _is_acme_location(l)]
    only_redirects = all(
        _first(l, "return") is not None for l in real_locations
    ) if real_locations else True

    if (site["mode"] == "redirect" and site["listen_http"] and not site["listen_https"]
            and only_redirects
            and (site["redirect_target"] or "").startswith("https://")):
        site["is_https_redirect_stub"] = True

    return site


def _is_acme_location(loc) -> bool:
    path = " ".join(_unquote(a) for a in _args(loc))
    return "acme-challenge" in path


# ==============================================================================
# The whole job
# ==============================================================================

def analyse(text: str) -> dict:
    """
    Read config text and work out what it would become.  Writes nothing.

    Gives back the sites and pools it would make, what it could not place and
    why, and anything worth a person's attention before they commit to it.
    """
    try:
        config = parse(text or "")
    except ParseError as exc:
        return {"ok": False, "error": f"that config would not parse: {exc}",
                "sites": [], "pools": [], "skipped": [], "warnings": []}

    # Walk into http {} if it is there, and cope with a fragment that is just a
    # server block, which is what people paste most often.
    scopes = [config]
    for top in config.directives:
        if top.name == "http" and top.is_block:
            scopes.append(top)

    upstream_blocks, server_blocks, skipped = [], [], []
    for scope in scopes:
        holder = scope.directives if hasattr(scope, "directives") else scope.block
        for d in holder or []:
            if d.name == "upstream" and d.is_block:
                upstream_blocks.append(d)
            elif d.name == "server" and d.is_block:
                server_blocks.append(d)
            elif d.name in ("stream", "mail") and d.is_block:
                skipped.append({
                    "what": f"the {d.name} block",
                    "why": f"{d.name} config is not imported yet.  It is left "
                           f"untouched wherever it is now.",
                })

    pools = [_read_upstream(b) for b in upstream_blocks]
    by_raw = {p["raw_name"]: p for p in pools if p["raw_name"]}

    sites = []
    for i, block in enumerate(server_blocks, start=1):
        sites.append(_read_server(block, by_raw, i))

    # One name, one site.
    #
    # Almost every real config writes a site as two server blocks, one on 80 and
    # one on 443 with the same server_name.  Here that is a single site with two
    # switches on it, so the two blocks have to be brought together.  Left alone
    # they both arrive under the same name, the second collides with the first,
    # and the https half, which is the half that matters, is the one dropped.
    folded = []
    for site in sites:
        twin = next((s for s in folded
                     if set(s["server_names"]) & set(site["server_names"])
                     and s["server_names"] and site["server_names"]), None)
        if twin is None:
            folded.append(site)
            continue

        plain, secure = (site, twin) if twin["listen_https"] else (twin, site)

        secure["listen_http"] = True
        secure["http_port"] = plain["http_port"]

        if plain.get("is_https_redirect_stub"):
            secure["force_https"] = True
            secure["notes"].append(
                "the plain http block for these names only redirected to https, "
                "so it became the force https switch rather than a second site"
            )
        else:
            secure["notes"].append(
                "there were two blocks for these names, one per port, and they "
                "were brought together into one site"
            )
            # Anything the http block did that the https one does not is worth
            # saying out loud rather than losing between the two.
            if plain["mode"] != secure["mode"]:
                secure["skipped"].append(
                    f"the http block served this as {plain['mode']} while the "
                    f"https block serves it as {secure['mode']}, and the https "
                    f"one was kept"
                )

        if secure is site and twin in folded:
            folded[folded.index(twin)] = secure

    # Backends that were written inline rather than as an upstream.
    for site in folded:
        target = site.pop("inline_backend", None)
        if not target:
            continue
        hostport = target.split("://", 1)[-1].split("/", 1)[0]
        host, _, port = hostport.partition(":")
        pool = {
            "raw_name": "",
            "name": _clean_name(f"{site['name']}_backend", "imported_pool"),
            "members": [{"address": host, "port": int(port) if port.isdigit() else
                         (443 if target.startswith("https://") else 80),
                         "weight": 1, "backup": False, "max_fails": 3,
                         "fail_timeout": 10, "max_conns": 0}],
            "lb_method": "round_robin",
            "keepalive": None,
            "backend_tls": target.startswith("https://"),
            "notes": ["made from a proxy_pass that named a host directly"],
        }
        pools.append(pool)
        site["pool"] = pool["name"]

    # A site proxying to https:// knows its backend speaks TLS, but that
    # setting lives on the pool.  Without carrying it across, an imported site
    # would talk plain http to a backend that only answers https, which fails at
    # the first request rather than at import time.
    pools_by_name = {p["name"]: p for p in pools}
    for site in folded:
        if not site.pop("backend_tls", False):
            continue
        pool = pools_by_name.get(site.get("pool") or "")
        if pool and not pool.get("backend_tls"):
            pool["backend_tls"] = True
            pool["notes"].append(
                f"{site['name']} proxies to it over https, so this is set to talk "
                f"to its backends over https too"
            )

    warnings = []
    if not folded and not pools:
        warnings.append(
            "nothing in that config looked like a server or upstream block.  If "
            "this is a whole nginx.conf, the sites are probably in the files it "
            "includes, and those need pasting in too."
        )
    for site in folded:
        if site["mode"] == "proxy" and not site["pool"]:
            warnings.append(
                f"{site['name']} looks like a proxy but no backend could be worked "
                f"out, so it will be made as a site with nothing behind it."
            )

    return {
        "ok": True,
        "sites": folded,
        "pools": pools,
        "skipped": skipped,
        "warnings": warnings,
    }


def apply_plan(session, plan: dict, chosen_sites=None, chosen_pools=None) -> dict:
    """
    Create what `analyse` worked out.

    Anything already there by that name is left alone rather than overwritten.
    An import that quietly replaced a site somebody is serving would be a very
    bad afternoon, and the report says clearly what was skipped for that reason.
    """
    made_pools, made_sites, existed = [], [], []

    want_pools = set(chosen_pools) if chosen_pools is not None else None
    want_sites = set(chosen_sites) if chosen_sites is not None else None

    pool_ids = {}
    for spec in plan.get("pools") or []:
        if want_pools is not None and spec["name"] not in want_pools:
            continue
        if session.query(Pool).filter(Pool.name == spec["name"]).first():
            existed.append(f"pool {spec['name']}")
            continue

        pool = Pool(
            name=spec["name"],
            description="imported",
            lb_method=spec.get("lb_method") or "round_robin",
            hash_key=spec.get("hash_key"),
            keepalive=spec.get("keepalive") or 32,
            backend_tls=bool(spec.get("backend_tls")),
            backend_tls_set=bool(spec.get("backend_tls")),
        )
        session.add(pool)
        session.flush()
        pool_ids[spec["name"]] = pool.id

        for m in spec.get("members") or []:
            session.add(PoolMember(
                pool_id=pool.id,
                address=m["address"],
                port=m.get("port") or 80,
                weight=m.get("weight") or 1,
                backup=bool(m.get("backup")),
                max_fails=m.get("max_fails", 3),
                fail_timeout=m.get("fail_timeout", 10),
                max_conns=m.get("max_conns", 0),
                enabled=m.get("enabled", True),
            ))
        made_pools.append(spec["name"])

    for spec in plan.get("sites") or []:
        if want_sites is not None and spec["name"] not in want_sites:
            continue
        if session.query(VirtualHost).filter(VirtualHost.name == spec["name"]).first():
            existed.append(f"site {spec['name']}")
            continue

        pool_id = None
        if spec.get("pool"):
            pool_id = pool_ids.get(spec["pool"])
            if pool_id is None:
                found = session.query(Pool).filter(Pool.name == spec["pool"]).first()
                pool_id = found.id if found else None

        host = VirtualHost(
            name=spec["name"],
            # Off, every time.  An import that started serving the moment it
            # finished would be a config change nobody reviewed.
            enabled=False,
            server_names=json_set(spec.get("server_names") or []),
            listen_http=bool(spec.get("listen_http", True)),
            listen_https=bool(spec.get("listen_https")),
            http_port=spec.get("http_port") or 80,
            https_port=spec.get("https_port") or 443,
            default_server=bool(spec.get("default_server")),
            http2=bool(spec.get("http2")),
            force_https=bool(spec.get("force_https")),
            mode=spec.get("mode") or "proxy",
            pool_id=pool_id,
            document_root=spec.get("document_root"),
            redirect_target=spec.get("redirect_target"),
            redirect_code=spec.get("redirect_code") or 301,
            settings=json_set(spec.get("settings") or {}),
            custom_config=spec.get("custom_config") or "",
        )
        session.add(host)
        made_sites.append(spec["name"])

    session.flush()
    log.warning("imported %d pools and %d sites, skipped %d that already existed",
                len(made_pools), len(made_sites), len(existed))

    return {"pools": made_pools, "sites": made_sites, "already_there": existed}
