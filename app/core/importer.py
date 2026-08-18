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

    # nginx 1.25.1 moved http2 off the listen line and made it its own
    # directive.  Both forms are current, plenty of real config uses the newer
    # one, and only reading the listen line left the switch off on a site that
    # had asked for it.
    for d in _find_all(block, "http2"):
        args = _args(d)
        if not args or args[0].lower() in ("on", "1", "true"):
            info["http2"] = True

    if not info["http"] and not info["https"]:
        info["http"] = True

    return info


# What we will write ourselves from the fields captured above, and so must not
# also copy verbatim or it would appear twice.
#
# Deliberately short.  `extract_unknown` in the parser drops a much longer list,
# and it is right to, because it exists for reading back config this system
# generated, where those directives really were ours.  A config from somewhere
# else is the opposite case: every one of those lines is somebody's decision,
# and dropping it loses behaviour they are relying on.  Importing a real world
# file is what showed this up, with error_page, allow, deny and add_header all
# quietly disappearing.
ALWAYS_REGENERATED = {
    "listen", "server_name", "ssl_certificate", "ssl_certificate_key",
    "location",
}
# `if` is not on that list, and putting it there was a mistake worth recording.
# We never generate one, so dropping them lost two different things at once: the
# certbot style `if ($host = ...)` redirect, and a CORS preflight handler living
# inside `location /` that carried five add_header lines with it.  An `if` block
# is somebody's logic and it gets kept like anything else.


def _verbatim(block, settings: dict, extra_drop=()) -> str:
    """
    Everything in this block we are not going to write ourselves.

    Anything that became a setting is dropped, because we will render it from
    the setting.  Everything else is kept exactly as it was written.
    """
    from app.core.nginx_parser import DIRECTIVE_TO_KEY

    if not block.is_block:
        return ""

    drop = set(ALWAYS_REGENERATED) | set(extra_drop)
    kept = []
    for d in block.block:
        if d.name in drop:
            continue
        # It became a setting, so it will be rendered from there.
        key = DIRECTIVE_TO_KEY.get(d.name)
        if key and key in settings:
            continue
        kept.append(d)

    return serialize(kept) if kept else ""


@lru_cache(maxsize=1)
def _settable_on_a_path() -> frozenset:
    """
    Catalog keys a location block is allowed to hold.

    Imported inside the function because the catalog pulls in a good deal and
    this module is also read by the parser tests, which have no need of it.
    """
    from app.catalog import all_features
    return frozenset(k for k, f in all_features().items()
                     if "location" in f.contexts)


def _commented(text: str, why: str) -> str:
    """
    Keep config we cannot place, commented out, with the reason.

    Used where copying it in as it stands would clash with something this system
    generates.  Commented out it changes nothing, and it is still there for
    somebody to move by hand, which beats both silently dropping it and
    producing config that will not load.
    """
    if not text.strip():
        return ""
    out = [f"\n# {why}"]
    out.extend("#   " + line for line in text.rstrip().splitlines())
    return "\n".join(out) + "\n"


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


LOCATION_PREFIXES = {"=": "exact", "^~": "preferential", "~": "regex", "~*": "regex_i"}


def _read_location(loc, pools_by_raw_name: dict, site: dict) -> dict:
    """
    One location block, as a path on the site.

    Anything it does that we do not model stays in the path's own custom config,
    the same bargain the site level makes.
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
        # A named location is a target for error_page and try_files, not a path
        # anybody browses to.  There is nowhere to put it, so it stays in the
        # site's custom config where it still works.
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

    # What this path does that the catalog models, lifted into its own settings
    # so it renders from there rather than being kept verbatim as well.
    #
    # Filtered to what a path may actually hold.  extract_settings reads a block
    # without knowing which kind it is, and a server only setting stored on a
    # path is refused the next time somebody saves that path.
    lifted = {k: v for k, v in (extract_settings(loc) or {}).items()
              if k in _settable_on_a_path()}
    if lifted:
        spec["settings"] = lifted

    # Drop from the verbatim leftover anything that is going to be written into
    # this block anyway: the path's own settings, and the site's, which the
    # renderer writes into every proxying path underneath it.
    #
    # This is what the empty dict here used to skip, and it is why an imported
    # config would not load.  The site lifted proxy_buffering into a setting,
    # the renderer wrote it into the path, and the path kept its own copy
    # verbatim as well, so the block held the directive twice.  nginx does not
    # take a duplicate of that one: it refuses the whole config, so the import
    # looked fine and the next apply failed on a file nobody had hand edited.
    #
    # Safe to drop rather than keep, because the value is not lost.  Anything of
    # the path's own is in `lifted` and renders from there, and a path's setting
    # beats the site's, so a path that disagreed with its site still wins.
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

    # The site's own backend, from the location that serves everything.
    #
    # This is the half that was missing and it lost whole sites.  `chosen` was
    # worked out here, used once below to keep it out of the custom config on
    # the grounds that it had been folded into the site, and then never
    # actually folded into anything.  With exactly one location the block was
    # excluded from the paths as well, since those only start at two, so a site
    # whose entire behaviour was one `location / { proxy_pass ... }` imported
    # with no backend, no path and nothing in its custom config.
    #
    # Worse than losing it: a config with a `root` alongside imported as a
    # static site serving that root, which is a site that answers, with the
    # wrong thing, and reported ok with no warnings.  The "looks like a proxy
    # but no backend" warning could not fire because the mode was no longer
    # proxy.
    if chosen is not None:
        dest = chosen[1]
        upstream = dest.split("://", 1)[-1].split("/", 1)[0]
        site["mode"] = "proxy"
        # A location that proxies everything beats a root.  nginx would never
        # reach the root for a request the location handles, so keeping static
        # describes a site that does not exist.
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

        # A path on the end of proxy_pass is a rewrite, and nginx does not do
        # it for you when the target is an upstream name.  Said rather than
        # dropped, because the site would otherwise proxy to the backend's root
        # and every page would be wrong in a way that looks like the backend's
        # fault.
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

        # Everything else that location did, which is where the WebSocket
        # headers and the buffering live.  Dropped, these come back as a
        # console that connects and dies, or a page that arrives in bursts.
        #
        # Anything the catalog models is lifted into the site's settings first,
        # so it lands as a setting somebody can see and change rather than as
        # opaque text.  Without this pass the same directive came out twice,
        # once as a setting and once verbatim, which nginx accepts and nobody
        # can reason about.
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

    # The site's own settings, worked out before the paths are read.
    #
    # Order matters here and it did not used to.  A path has to know what the
    # site will already write into it, because the renderer puts the site's
    # proxy settings into every path that proxies.  Read the paths first and
    # they cannot know, so a directive the site turned into a setting gets kept
    # verbatim on the path as well and the block ends up holding it twice.
    site["settings"] = extract_settings(block) or {}

    # The rewrite and cookie settings worked out from the main location's
    # proxy_pass path.  Merged after the block's own settings and never over
    # them, so anything actually written in the config wins over what we
    # inferred from a path.
    for key, value in (site.pop("settings_seed", {}) or {}).items():
        site["settings"].setdefault(key, value)

    # Every location that does something, as a path on the site.
    #
    # This used to keep one backend and report the rest as not brought over.
    # The first real config anybody imported had a restricted health endpoint on
    # its own path, so the very first file hit that wall.
    real_locations = [l for l in locations if not _is_acme_location(l)]
    became_a_path = set()
    if len(real_locations) > 1:
        specs = []
        # nginx refuses to start on two locations with the same path, so a
        # config that has one cannot be copied across faithfully: doing that
        # produced `duplicate location "/monitoring"` and, because an apply is
        # all or nothing, the whole fleet then could not apply anything.  A
        # config that has drifted over years is exactly the config people
        # import, and a path written twice is one of the commonest things in
        # one.
        #
        # Only for the match types nginx treats as duplicates.  Two regular
        # expression locations may repeat, and there the first one wins rather
        # than the config being refused, so those are left alone.
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
            # We write our own, on every node, whenever a certificate is issued.
            # Carrying somebody else's copy across would leave two.
            continue
        if id(loc) in became_a_path:
            # It is already a path on this site, so copying the block in here as
            # well would put two `location` blocks with the same path in one
            # server, and nginx refuses that outright.  This is the other half
            # of why an imported config would not load: the paths arrived
            # correctly and then every one of them was written a second time.
            continue
        # The whole block, as written.  Not filtered: a location whose body is
        # only a root, or only an allow, is still a location that does
        # something, and an earlier version dropped exactly those because every
        # directive in them was on the "we generate this" list.
        path = " ".join(_unquote(a) for a in _args(loc)) or "/"
        body = serialize(loc.block or [])
        site["custom_config"] += f"\n# kept from the imported config\nlocation {path} {{\n{body}}}\n"

    # ---- everything else kept verbatim
    # The settings themselves were worked out above, before the paths were read.
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


def _read_zone(d) -> dict:
    """
    A limit_req_zone or limit_conn_zone declaration, as a row we can make.

        limit_req_zone $binary_remote_addr zone=one:10m rate=5r/s;

    The key is everything before `zone=`, because it can be more than one token
    once somebody uses a map or a couple of variables.
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
    zones = {"rate": [], "conn": []}
    for scope in scopes:
        holder = scope.directives if hasattr(scope, "directives") else scope.block
        for d in holder or []:
            if d.name == "upstream" and d.is_block:
                upstream_blocks.append(d)
            elif d.name == "server" and d.is_block:
                server_blocks.append(d)
            elif d.name in ("limit_req_zone", "limit_conn_zone"):
                # The declaration lives in http, and a `limit_req` inside a
                # location is useless without it: nginx refuses the config with
                # "zero size shared memory zone".  Bringing the declaration over
                # is the only way the rule that referenced it still means
                # anything, and most people paste a server block on its own, so
                # the declaration is often not even here to bring.
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
            # It is only a redirect as far as traffic goes, but it can still
            # carry directives that were doing something, and folding it away
            # used to take those with it.
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

    # Backends that were written inline rather than as an upstream, on the site
    # itself or on any of its paths.
    def _pool_for(target, label):
        hostport = target.split("://", 1)[-1].split("/", 1)[0]
        host, _, port = hostport.partition(":")
        wanted_port = (int(port) if port.isdigit()
                       else (443 if target.startswith("https://") else 80))

        # Several paths on a site usually proxy to the same place, and making a
        # pool each would leave a list of identical backends under slightly
        # different names for somebody to maintain separately.
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

    # A rate limit rule that names a zone nobody declared is not config, it is a
    # config that will not load: nginx answers "zero size shared memory zone".
    #
    # It happens on almost every paste, because `limit_req` sits in the location
    # and `limit_req_zone` sits up in http, so pasting a server block brings the
    # rule and leaves the declaration behind.  Commented out with the reason
    # rather than dropped, so somebody can make the zone on the Zones page and
    # put the line back, and rather than left alone, which is the version that
    # takes the next apply down.
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

    The two directives do not agree on how to write it, which is worth being
    explicit about because reading them the same way is wrong in a way that
    looks right:

        limit_req  zone=one burst=10 nodelay;
        limit_conn perip 5;

    limit_req puts it in `zone=`, limit_conn makes it the first argument and
    follows it with a number.  Scanning every token for "something that is not
    a declared zone" finds the burst count or the connection count and blames
    that, so a line whose zone is perfectly fine gets commented out for naming
    a zone called "5".  Read the one argument that actually holds the name.
    """
    parts = bare.rstrip(";").split()
    if not parts:
        return None
    if parts[0] == "limit_req":
        for token in parts[1:]:
            if token.startswith("zone="):
                # zone=one, and on the declaration side zone=one:10m.
                return token[len("zone="):].split(":")[0] or None
        return None
    if parts[0] == "limit_conn":
        return parts[1] if len(parts) > 1 else None
    return None


def _blank_dangling_zones(site: dict, declared: set) -> set:
    """
    Comment out limit_req/limit_conn lines naming a zone that is not coming with
    them.  Gives back the zone names it had to do that for.
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
    Create what `analyse` worked out.

    Anything already there by that name is left alone rather than overwritten.
    An import that quietly replaced a site somebody is serving would be a very
    bad afternoon, and the report says clearly what was skipped for that reason.
    """
    made_pools, made_sites, existed = [], [], []

    want_pools = set(chosen_pools) if chosen_pools is not None else None
    want_sites = set(chosen_sites) if chosen_sites is not None else None

    # The shared memory zones first, because a site that rate limits refers to
    # one by name and the reference is worth nothing without the declaration.
    # Anything already there under that name is left alone, same bargain as
    # pools and sites: an import does not overwrite what somebody is running.
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
                # Lifted from the imported block.  Without this the path's own
                # settings were worked out, used to decide what not to keep
                # verbatim, and then thrown away, which loses the value instead
                # of moving it.
                settings=json_set(loc.get("settings") or {}),
                enabled=True,
                sort_order=order * 10,
            ))

        made_sites.append(spec["name"])

    session.flush()
    log.warning("imported %d pools and %d sites, skipped %d that already existed",
                len(made_pools), len(made_sites), len(existed))

    return {"pools": made_pools, "sites": made_sites, "already_there": existed}
