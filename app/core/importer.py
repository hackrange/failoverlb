"""
Turn an existing nginx config into sites and pools this system can manage.

Two separate steps. `analyse` reads config text and reports what it would
create, touching nothing, so it is safe to run against production config.
`apply_plan` writes the result.

It doesn't guess. Anything that can't be mapped to a setting is kept in the
site's custom config with a note, and anything that can't be placed at all
is reported as skipped with a reason. Silently dropping a directive someone
depends on is the worst possible outcome.

Certificates are noted, never imported. An `ssl_certificate` path points at
a file on a box this fleet doesn't manage, so the path is reported and
issuing a certificate is offered as a separate step.
"""
import logging
import re
from functools import lru_cache

from app.core.nginx_parser import (
    ParseError,
    extract_settings,
    extract_unknown,
    parse,
    serialize,
)
from app.models import (ConnLimitZone, Location, Pool, PoolMember,
                        RateLimitZone, VirtualHost, json_set)

log = logging.getLogger("nfm.importer")

# nginx names are more permissive than ours, and ours end up in filenames,
# so they're cleaned rather than rejected. The original goes in the notes.
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
    """Direct children of a block with this name. Not recursive."""
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

    # Every member on 443 almost certainly means an HTTPS backend.
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

    # nginx 1.25.1 added a standalone `http2` directive. Both forms are in
    # common use, so check for it as well as the listen flag.
    for d in _find_all(block, "http2"):
        args = _args(d)
        if not args or args[0].lower() in ("on", "1", "true"):
            info["http2"] = True

    if not info["http"] and not info["https"]:
        info["http"] = True

    return info


# Directives we always generate ourselves, so copying them verbatim would
# duplicate them.
#
# Much shorter than the list `extract_unknown` drops, on purpose: that one is
# for reading back our own generated config. In a foreign config every one of
# those lines is someone's decision (error_page, allow, deny, add_header...)
# and must be kept.
ALWAYS_REGENERATED = {
    "listen", "server_name", "ssl_certificate", "ssl_certificate_key",
    "location",
}
# `if` is deliberately not in the list. We never generate one, and dropping
# them lost things like certbot's `if ($host = ...)` redirect and CORS
# preflight handlers. An `if` block is someone's logic; keep it.


def _verbatim(block, settings: dict, extra_drop=()) -> str:
    """
    Everything in this block we won't write ourselves. Directives that became
    settings are dropped (they render from the setting); everything else is
    kept exactly as written.
    """
    from app.core.nginx_parser import DIRECTIVE_TO_KEY

    if not block.is_block:
        return ""

    drop = set(ALWAYS_REGENERATED) | set(extra_drop)
    kept = []
    for d in block.block:
        if d.name in drop:
            continue
        # Became a setting, so it renders from there.
        key = DIRECTIVE_TO_KEY.get(d.name)
        if key and key in settings:
            continue
        kept.append(d)

    return serialize(kept) if kept else ""


@lru_cache(maxsize=1)
def _settable_on_a_path() -> frozenset:
    """
    Catalog keys a location block may hold. Imported lazily because the
    catalog is heavy and the parser tests read this module without it.
    """
    from app.catalog import all_features
    return frozenset(k for k, f in all_features().items()
                     if "location" in f.contexts)


def _commented(text: str, why: str) -> str:
    """
    Keep config we can't place, commented out, with the reason. Used where
    copying it in would clash with generated config; commented out it
    changes nothing but is still there to move by hand.
    """
    if not text.strip():
        return ""
    out = [f"\n# {why}"]
    out.extend("#   " + line for line in text.rstrip().splitlines())
    return "\n".join(out) + "\n"


def _looks_like_a_host(target: str) -> bool:
    """
    Is this a host, or the name of an upstream declared elsewhere? A dot, a
    port or brackets means a host; a bare word is an upstream, same as
    nginx. Guessing host for an upstream name would build a pool that never
    resolves.
    """
    bare = (target or "").split("/", 1)[0]
    return bool(bare) and ("." in bare or ":" in bare or bare.startswith("["))


LOCATION_PREFIXES = {"=": "exact", "^~": "preferential", "~": "regex", "~*": "regex_i"}


def _read_location(loc, pools_by_raw_name: dict, site: dict) -> dict:
    """
    One location block, as a path on the site. Anything we don't model stays
    in the path's own custom config.
    """
    args = [_unquote(a) for a in _args(loc)]
    if not args:
        return None

    match_type = "prefix"
    if args[0] in LOCATION_PREFIXES:
        match_type = LOCATION_PREFIXES[args[0]]
        args = args[1:]
    if not args:
        return None

    path = args[0]
    if path.startswith("@"):
        # A named location is a target for error_page/try_files, not a path.
        # Leave it in the site's custom config where it still works.
        return None

    spec = {"path": path, "match_type": match_type, "mode": "proxy",
            "pool": None, "document_root": None, "alias": None,
            "redirect_target": None, "redirect_code": 301,
            "custom_config": "", "enabled": True, "notes": []}

    target = _first(loc, "proxy_pass")
    root = _first(loc, "root")
    alias = _first(loc, "alias")
    ret = _first(loc, "return")

    if target is not None and _args(target):
        dest = _unquote(_args(target)[0])
        upstream = dest.split("://", 1)[-1].split("/", 1)[0]
        if upstream in pools_by_raw_name:
            spec["pool"] = pools_by_raw_name[upstream]["name"]
        elif _looks_like_a_host(upstream):
            spec["inline_backend"] = dest
        else:
            spec["notes"].append(
                f"proxies to an upstream called {upstream!r} that was not in "
                f"what you pasted"
            )
    elif ret is not None and _args(ret):
        rargs = _args(ret)
        code = rargs[0]
        dest = _unquote(rargs[1]) if len(rargs) > 1 else ""
        if code.isdigit() and dest:
            spec["mode"] = "redirect"
            spec["redirect_code"] = int(code)
            spec["redirect_target"] = dest
        else:
            spec["mode"] = "deny"
    elif alias is not None and _args(alias):
        spec["mode"] = "static"
        spec["alias"] = _unquote(_args(alias)[0])
    elif root is not None and _args(root):
        spec["mode"] = "static"
        spec["document_root"] = _unquote(_args(root)[0])
    else:
        spec["mode"] = "static"

    # Lift catalog modeled directives into the path's settings. Filter to
    # keys a path may hold: extract_settings doesn't know the block type, and
    # a server only setting on a path is rejected on the next save.
    lifted = {k: v for k, v in (extract_settings(loc) or {}).items()
              if k in _settable_on_a_path()}
    if lifted:
        spec["settings"] = lifted

    # Drop from the verbatim leftover anything that will be written into this
    # block anyway: the path's own settings and the site's, which the renderer
    # writes into every proxying path. Otherwise the directive appears twice
    # and nginx refuses duplicates like proxy_buffering outright.
    #
    # Nothing is lost: the path's values are in `lifted`, and a path setting
    # overrides the site's.
    already = dict((site or {}).get("settings") or {})
    already.update(lifted)

    leftover = _verbatim(loc, already, extra_drop=(
        "proxy_pass", "proxy_set_header", "proxy_http_version", "root", "alias",
        "return",
    ))
    if leftover.strip():
        spec["custom_config"] = leftover

    return spec


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

    # ---- certificates: noted, never imported.
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
    # Prefer the location that proxies / as the site's backend, else the
    # first proxying location.
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

    # Fold the chosen location into the site as its backend. Without this, a
    # site whose whole behavior was one `location / { proxy_pass ... }`
    # imported with no backend at all, or, with a `root` alongside, as a
    # static site serving the wrong content with no warning.
    if chosen is not None:
        dest = chosen[1]
        upstream = dest.split("://", 1)[-1].split("/", 1)[0]
        site["mode"] = "proxy"
        # A location proxying everything wins over a root; nginx would never
        # reach the root for those requests.
        site["document_root"] = None
        if upstream in pools_by_raw_name:
            site["pool"] = pools_by_raw_name[upstream]["name"]
        elif _looks_like_a_host(upstream):
            site["inline_backend"] = dest
        else:
            site["notes"].append(
                f"the main location proxies to an upstream called {upstream!r} "
                f"that was not in what you pasted, so no backend was attached"
            )

        # A path on the end of proxy_pass is a rewrite, which nginx doesn't
        # do for upstream names. Turn it into a rewrite rule, otherwise the
        # site proxies to the backend root and every page looks broken.
        suffix = dest.split("://", 1)[-1]
        suffix = suffix[len(upstream):] if suffix.startswith(upstream) else ""
        if suffix and suffix != "/":
            site["notes"].append(
                f"the backend is served under {suffix} rather than at its root.  "
                f"A rewrite rule was added for it, and the cookie and redirect "
                f"paths were set to match."
            )
            settings = site.setdefault("settings_seed", {})
            escaped = suffix.rstrip("/")
            settings["rewrite_rules"] = [
                r"^/(?!\.well-known/)(.*)$ %s/$1 break" % escaped
            ]
            settings["proxy_cookie_path"] = f"{suffix} /"
            settings["proxy_redirect"] = f"{suffix} /"

        # Keep whatever else that location did (WebSocket headers, buffering
        # and so on). Catalog modeled directives are lifted into settings
        # first so they're visible and editable, and aren't also copied
        # verbatim.
        lifted = extract_settings(chosen[2]) or {}
        if lifted:
            site.setdefault("settings_seed", {}).update(lifted)

        leftover = _verbatim(chosen[2], lifted, extra_drop=(
            "proxy_pass", "proxy_set_header", "proxy_http_version", "root",
            "alias", "return",
        ))
        if leftover.strip():
            site["custom_config"] += (
                "\n# From the location that serves this site, kept because "
                "there is no setting here for it.\n" + leftover
            )

    # Site settings must be known before reading the paths: the renderer
    # writes the site's proxy settings into every proxying path, and a path
    # needs to know that to avoid keeping a duplicate verbatim.
    site["settings"] = extract_settings(block) or {}

    # Settings inferred from the proxy_pass path. Never override settings
    # actually written in the config.
    for key, value in (site.pop("settings_seed", {}) or {}).items():
        site["settings"].setdefault(key, value)

    # Every meaningful location becomes a path on the site.
    real_locations = [l for l in locations if not _is_acme_location(l)]
    became_a_path = set()
    if len(real_locations) > 1:
        specs = []
        # nginx refuses two locations with the same path, and since applies
        # are all or nothing, one duplicate would block the whole fleet. Keep
        # the first and report the rest. Only for match types nginx treats as
        # duplicates; repeated regex locations are legal (first match wins).
        deduped = ("prefix", "exact", "preferential")
        seen_paths = {}
        for l in real_locations:
            spec = _read_location(l, pools_by_raw_name, site)
            if not spec:
                continue
            key = (spec.get("match_type") or "prefix", spec.get("path"))
            if key[0] in deduped and key in seen_paths:
                site["skipped"].append(
                    f"{spec.get('path')} appeared more than once, and nginx will "
                    f"not load a config with the same path twice.  The first one "
                    f"was kept and the rest were left out."
                )
                became_a_path.add(id(l))
                continue
            seen_paths[key] = spec
            specs.append(spec)
            became_a_path.add(id(l))
        site["locations"] = specs
        if site["locations"]:
            site["notes"].append(
                f"{len(site['locations'])} paths were brought over as paths on "
                f"this site, so each one keeps its own backend"
            )

    for loc in locations:
        if chosen is not None and loc is chosen[2]:
            continue
        if _is_acme_location(loc):
            # We write our own on every node when issuing. Don't keep a
            # second copy.
            continue
        if id(loc) in became_a_path:
            # Already a path on the site. Copying it here too would produce
            # a duplicate location, which nginx refuses.
            continue
        # The whole block as written, unfiltered. A location containing only
        # a root or an allow still does something.
        path = " ".join(_unquote(a) for a in _args(loc)) or "/"
        body = serialize(loc.block or [])
        site["custom_config"] += f"\n# kept from the imported config\nlocation {path} {{\n{body}}}\n"

    # ---- everything else kept verbatim
    # Site settings were already worked out above.
    extra = ["http2"]
    if site["mode"] == "static" and site["document_root"]:
        extra.append("root")
    if site["mode"] == "redirect":
        extra.append("return")
    leftover = _verbatim(block, site["settings"], extra_drop=extra)
    if leftover.strip():
        site["custom_config"] = (
            "# Kept from the imported config because there is no setting for it.\n"
            + leftover + site["custom_config"]
        )

    if site["custom_config"].strip():
        site["notes"].append(
            "some directives had no setting here, so they were kept as custom config"
        )

    # A plain http block that only redirects to https is "force https", which
    # we have a switch for. The acme-challenge location doesn't count against
    # it; otherwise nearly every real config came through as two sites under
    # one name and the https half was dropped as a duplicate.
    real_locations = [l for l in locations if not _is_acme_location(l)]
    only_redirects = all(
        _first(l, "return") is not None for l in real_locations
    ) if real_locations else True

    if (site["mode"] == "redirect" and site["listen_http"] and not site["listen_https"]
            and only_redirects
            and (site["redirect_target"] or "").startswith("https://")):
        site["is_https_redirect_stub"] = True

    return site


def _read_zone(d) -> dict:
    """
    A limit_req_zone or limit_conn_zone declaration, as a row to create.

        limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;

    The key is everything before `zone=`, since it can span several tokens.
    """
    args = [_unquote(a) for a in _args(d)]
    if not args:
        return None

    name = size = rate = None
    key_parts = []
    for arg in args:
        if arg.startswith("zone="):
            spec = arg[len("zone="):]
            name, _, size = spec.partition(":")
        elif arg.startswith("rate="):
            rate = arg[len("rate="):]
        else:
            key_parts.append(arg)

    if not name:
        return None

    return {
        "name": name,
        "key": " ".join(key_parts) or "$binary_remote_addr",
        "zone_size": size or "10m",
        "rate": rate or "10r/s",
    }


def _is_acme_location(loc) -> bool:
    path = " ".join(_unquote(a) for a in _args(loc))
    return "acme-challenge" in path


# ==============================================================================
# The whole job
# ==============================================================================

def analyse(text: str) -> dict:
    """
    Parse config text and report what it would become, without writing
    anything: sites and pools to create, what couldn't be placed and why,
    and warnings worth reading first.
    """
    try:
        config = parse(text or "")
    except ParseError as exc:
        return {"ok": False, "error": f"that config would not parse: {exc}",
                "sites": [], "pools": [], "skipped": [], "warnings": []}

    # Look inside http {} if present, and handle a bare server block, which
    # is what people paste most often.
    scopes = [config]
    for top in config.directives:
        if top.name == "http" and top.is_block:
            scopes.append(top)

    upstream_blocks, server_blocks, skipped = [], [], []
    zones = {"rate": [], "conn": []}
    for scope in scopes:
        holder = scope.directives if hasattr(scope, "directives") else scope.block
        for d in holder or []:
            if d.name == "upstream" and d.is_block:
                upstream_blocks.append(d)
            elif d.name == "server" and d.is_block:
                server_blocks.append(d)
            elif d.name in ("limit_req_zone", "limit_conn_zone"):
                # A limit_req is useless without its zone declaration, which
                # lives in http; nginx refuses the config otherwise. Bring the
                # declaration along when it's present.
                spec = _read_zone(d)
                if spec:
                    zones["rate" if d.name == "limit_req_zone" else "conn"].append(spec)
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

    # One name, one site. Real configs usually write a site as two server
    # blocks (80 and 443) with the same server_name. Here that's one site
    # with both listeners, so merge them; otherwise the second collides and
    # the https half gets dropped.
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
            # The stub is just a redirect for traffic, but it may carry
            # directives that matter. Keep them, commented out.
            if plain["custom_config"].strip():
                secure["custom_config"] += _commented(
                    plain["custom_config"],
                    "From the plain http block for these names, which became the "
                    "force https switch.  Kept in case any of it still matters.",
                )
        else:
            secure["notes"].append(
                "there were two blocks for these names, one per port, and they "
                "were brought together into one site"
            )
            # Report differences between the two blocks rather than losing
            # them silently.
            if plain["mode"] != secure["mode"]:
                secure["skipped"].append(
                    f"the http block served this as {plain['mode']} while the "
                    f"https block serves it as {secure['mode']}, and the https "
                    f"one was kept"
                )

        if secure is site and twin in folded:
            folded[folded.index(twin)] = secure

    # Backends written inline in proxy_pass rather than as an upstream, on
    # the site or any of its paths.
    def _pool_for(target, label):
        hostport = target.split("://", 1)[-1].split("/", 1)[0]
        host, _, port = hostport.partition(":")
        wanted_port = (int(port) if port.isdigit()
                       else (443 if target.startswith("https://") else 80))

        # Reuse an identical single member pool rather than creating one per
        # path under slightly different names.
        for existing in pools:
            members = existing.get("members") or []
            if (len(members) == 1 and members[0]["address"] == host
                    and members[0]["port"] == wanted_port
                    and bool(existing.get("backend_tls")) == target.startswith("https://")):
                return existing["name"]

        spec = {
            "raw_name": "",
            "name": _clean_name(label, "imported_pool"),
            "members": [{"address": host, "port": wanted_port, "weight": 1, "backup": False, "max_fails": 3,
                         "fail_timeout": 10, "max_conns": 0}],
            "lb_method": "round_robin",
            "keepalive": None,
            "backend_tls": target.startswith("https://"),
            "notes": ["made from a proxy_pass that named a host directly"],
        }
        pools.append(spec)
        return spec["name"]

    for site in folded:
        for loc in site.get("locations") or []:
            target = loc.pop("inline_backend", None)
            if target:
                label = f"{site['name']}{loc['path']}".replace("/", "_")
                loc["pool"] = _pool_for(target, label)

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

    # A site proxying to https:// needs backend TLS, but that setting lives
    # on the pool. Carry it over, or the site talks plain http to an HTTPS
    # only backend.
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

    # A limit_req naming an undeclared zone makes nginx refuse the config
    # ("zero size shared memory zone"). Common, since pasting a server block
    # leaves the http level declaration behind. Comment those lines out with
    # the reason so they can be restored once the zone exists.
    declared = {z["name"] for z in zones["rate"]} | {z["name"] for z in zones["conn"]}
    for site in folded:
        missing = _blank_dangling_zones(site, declared)
        for name in sorted(missing):
            warnings.append(
                f"{site['name']} rate limits against a zone called {name!r}, and "
                f"no limit_req_zone for it was in what you pasted.  Those lines "
                f"were commented out, because nginx will not load a config that "
                f"names a zone that does not exist.  Make the zone on the Zones "
                f"page and put them back if you want the limit."
            )

    return {
        "ok": True,
        "sites": folded,
        "pools": pools,
        "zones": zones,
        "skipped": skipped,
        "warnings": warnings,
    }


def _zone_named(bare: str):
    """
    The zone a limit_req or limit_conn line names, or None.

        limit_req  zone=one burst=10 nodelay;
        limit_conn perip 5;

    limit_req uses `zone=`; limit_conn takes it as the first argument,
    followed by a count. Read only the argument that holds the name, or the
    burst/connection count gets mistaken for a zone called "5".
    """
    parts = bare.rstrip(";").split()
    if not parts:
        return None
    if parts[0] == "limit_req":
        for token in parts[1:]:
            if token.startswith("zone="):
                # zone=one, or zone=one:10m on a declaration.
                return token[len("zone="):].split(":")[0] or None
        return None
    if parts[0] == "limit_conn":
        return parts[1] if len(parts) > 1 else None
    return None


def _blank_dangling_zones(site: dict, declared: set) -> set:
    """
    Comment out limit_req/limit_conn lines naming a zone that isn't being
    imported. Returns the zone names affected.
    """
    missing = set()

    def sweep(text):
        out = []
        for line in (text or "").splitlines():
            bare = line.strip()
            name = _zone_named(bare) if bare.startswith(
                ("limit_req ", "limit_conn ")) else None
            if name and name not in declared:
                missing.add(name)
                out.append(f"# {bare}")
                out.append(f"# ^ the zone {name!r} was not in what you "
                           f"pasted, and nginx will not load a config "
                           f"that names a zone that does not exist.")
                continue
            out.append(line)
        return "\n".join(out)

    site["custom_config"] = sweep(site.get("custom_config"))
    for loc in site.get("locations") or []:
        loc["custom_config"] = sweep(loc.get("custom_config"))
    return missing


def apply_plan(session, plan: dict, chosen_sites=None, chosen_pools=None) -> dict:
    """
    Create what `analyse` produced. Anything that already exists by name is
    left alone and reported, never overwritten.
    """
    made_pools, made_sites, existed = [], [], []

    want_pools = set(chosen_pools) if chosen_pools is not None else None
    want_sites = set(chosen_sites) if chosen_sites is not None else None

    # Zones first, since rate limited sites refer to them by name. Existing
    # zones are left alone, like pools and sites.
    for kind, model in (("rate", RateLimitZone), ("conn", ConnLimitZone)):
        for spec in (plan.get("zones") or {}).get(kind) or []:
            if session.query(model).filter(model.name == spec["name"]).first():
                existed.append(f"zone {spec['name']}")
                continue
            row = model(name=spec["name"], description="imported",
                        key=spec["key"], zone_size=spec["zone_size"])
            if kind == "rate":
                row.rate = spec["rate"]
            session.add(row)
    session.flush()

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
            # Always disabled; an import shouldn't start serving unreviewed.
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
        session.flush()

        for order, loc in enumerate(spec.get("locations") or [], start=1):
            loc_pool_id = None
            if loc.get("pool"):
                loc_pool_id = pool_ids.get(loc["pool"])
                if loc_pool_id is None:
                    found = session.query(Pool).filter(Pool.name == loc["pool"]).first()
                    loc_pool_id = found.id if found else None

            session.add(Location(
                host_id=host.id,
                path=loc["path"],
                match_type=loc.get("match_type") or "prefix",
                mode=loc.get("mode") or "proxy",
                pool_id=loc_pool_id,
                document_root=loc.get("document_root"),
                alias=loc.get("alias"),
                redirect_target=loc.get("redirect_target"),
                redirect_code=loc.get("redirect_code") or 301,
                custom_config=loc.get("custom_config") or "",
                # Settings lifted from the imported block. Without these the
                # values were dropped from verbatim and then lost.
                settings=json_set(loc.get("settings") or {}),
                enabled=True,
                sort_order=order * 10,
            ))

        made_sites.append(spec["name"])

    session.flush()
    log.warning("imported %d pools and %d sites, skipped %d that already existed",
                len(made_pools), len(made_sites), len(existed))

    return {"pools": made_pools, "sites": made_sites, "already_there": existed}
