"""
Working out what this nginx can actually do.

We parse the configure line from nginx -V into a set of module names, and
the GUI only offers settings that will actually load.  The installer's module
list gets edited; if someone drops a module, its settings would otherwise
write config nginx refuses to start with.  Adding a module to the installer
makes its settings appear automatically.
"""

import logging
import re

log = logging.getLogger("nfm.caps")


# Modules compiled in by default.  Assumed present unless we see a
# matching --without- flag.
ALWAYS_ON = {
    "http_charset_module", "http_gzip_module", "http_ssi_module",
    "http_userid_module", "http_access_module", "http_auth_basic_module",
    "http_mirror_module", "http_autoindex_module", "http_geo_module",
    "http_map_module", "http_split_clients_module", "http_referer_module",
    "http_rewrite_module", "http_proxy_module", "http_fastcgi_module",
    "http_uwsgi_module", "http_scgi_module", "http_memcached_module",
    "http_limit_conn_module", "http_limit_req_module", "http_empty_gif_module",
    "http_browser_module", "http_upstream_hash_module",
    "http_upstream_ip_hash_module", "http_upstream_least_conn_module",
    "http_upstream_random_module", "http_upstream_keepalive_module",
    "http_upstream_zone_module", "http_headers_module", "http_log_module",
    "http_index_module", "http_core_module",
}


def parse_build_info(build_info: str) -> dict:
    """
    Parse nginx -V output into version, OpenSSL version, module set and the
    raw configure arguments.
    """
    result = {
        "nginx_version": None,
        "openssl_version": None,
        "modules": set(),
        "third_party": [],
        "configure_args": "",
        "has_stream": False,
        "has_mail": False,
        "has_http3": False,
    }

    if not build_info:
        return result

    m = re.search(r"nginx version:\s*nginx/(\S+)", build_info)
    if m:
        result["nginx_version"] = m.group(1)

    # Distro builds say "built with OpenSSL x", source builds against their
    # own OpenSSL say "running with".  Prefer "running with": that is what is
    # actually loaded.
    m = re.search(r"running with OpenSSL\s+(\S+)", build_info)
    if not m:
        m = re.search(r"built with OpenSSL\s+(\S+)", build_info)
    if m:
        result["openssl_version"] = m.group(1)

    m = re.search(r"configure arguments:(.*)", build_info, re.DOTALL)
    if not m:
        return result

    args = m.group(1)
    result["configure_args"] = args.strip()

    modules = set(ALWAYS_ON)

    # --with-http_ssl_module and friends
    for flag in re.findall(r"--with-([a-z0-9_]+_module)", args):
        modules.add(flag)

    # --without-http_gzip_module and friends
    for flag in re.findall(r"--without-([a-z0-9_]+_module)", args):
        modules.discard(flag)

    # Plain --with-stream and --with-mail have no _module on the end.
    if re.search(r"--with-stream(?![a-z_])", args):
        modules.add("stream")
        result["has_stream"] = True
    if re.search(r"--with-mail(?![a-z_])", args):
        modules.add("mail")
        result["has_mail"] = True

    if "http_v3_module" in modules:
        result["has_http3"] = True

    # Third party modules appear as --add-module=/some/path/name.  We key on
    # the folder name, so the installer clones each into a folder named after
    # the module.
    for path in re.findall(r"--add-(?:dynamic-)?module=(\S+)", args):
        name = path.rstrip("/").split("/")[-1]
        result["third_party"].append(name)
        modules.add(name)

        # Features can ask for either the folder name or the short alias.
        alias = THIRD_PARTY_ALIASES.get(name)
        if alias:
            modules.add(alias)

    result["modules"] = modules
    return result


# Installer folder names mapped to short names features can ask for.
THIRD_PARTY_ALIASES = {
    "headers-more-nginx-module": "headers_more",
    "lua-nginx-module": "lua",
    "echo-nginx-module": "echo",
    "ngx-fancyindex": "fancyindex",
    "ngx_cache_purge": "cache_purge",
    "nginx-dav-ext-module": "dav_ext",
    "ngx_http_substitutions_filter_module": "subs_filter",
    "subs-filter": "subs_filter",
    "nginx-upload-progress-module": "upload_progress",
    "upload-progress": "upload_progress",
    "ngx_http_auth_pam_module": "auth_pam",
    "auth-pam": "auth_pam",
    "ngx_http_geoip2_module": "geoip2",
    "geoip2": "geoip2",
    "modsecurity-nginx": "modsecurity",
    "ModSecurity-nginx": "modsecurity",
    # nchan was dropped from the build (see nginx-installer.sh), but nodes
    # not yet rebuilt still have it compiled in.
    "nchan": "nchan",
    "nginx-upstream-fair": "upstream_fair",
    "upstream-fair": "upstream_fair",
    "ngx_devel_kit": "ndk",
}


class Capabilities:
    """
    What one node's nginx can do.  Refreshed on each agent status reply.
    """

    def __init__(self, build_info: str = "", version: str = ""):
        parsed = parse_build_info(build_info)
        self.modules = parsed["modules"]
        self.nginx_version = parsed["nginx_version"] or version
        self.openssl_version = parsed["openssl_version"]
        self.third_party = parsed["third_party"]
        self.has_stream = parsed["has_stream"]
        self.has_mail = parsed["has_mail"]
        self.has_http3 = parsed["has_http3"]
        self.configure_args = parsed["configure_args"]
        self.raw = build_info

    @property
    def version_tuple(self) -> tuple:
        """The nginx version as numbers, for comparing against a minimum."""
        if not self.nginx_version:
            return None
        try:
            return tuple(int(p) for p in str(self.nginx_version).split(".")[:3])
        except (ValueError, AttributeError):
            return None

    def has(self, module: str) -> bool:
        if module in ("core", "", None):
            return True
        return module in self.modules

    def missing_for(self, features) -> list:
        """Which of these features this box cannot run."""
        return [f for f in features if not self.has(f.module)]

    def supports_post_quantum(self) -> bool:
        """
        Post quantum key exchange needs OpenSSL 3.5+.  The installer builds
        against 3.5; distro nginx builds usually won't have it.
        """
        if not self.openssl_version:
            return False
        m = re.match(r"(\d+)\.(\d+)", self.openssl_version)
        if not m:
            return False
        major, minor = int(m.group(1)), int(m.group(2))
        return (major, minor) >= (3, 5)

    def summary(self) -> dict:
        return {
            "nginx_version": self.nginx_version,
            "openssl_version": self.openssl_version,
            "module_count": len(self.modules),
            "third_party_count": len(self.third_party),
            "third_party": self.third_party,
            "has_stream": self.has_stream,
            "has_mail": self.has_mail,
            "has_http3": self.has_http3,
            "post_quantum": self.supports_post_quantum(),
        }


# This node's capabilities, set at startup and on every agent status call.
_local_caps = Capabilities()


def fleet_capabilities() -> Capabilities:
    """
    What every node in the fleet can do: what the GUI offers and what the
    renderer may emit.

    It is the intersection across nodes, since the config is identical
    everywhere and a setting missing on one box blocks the whole apply.

    Read from the per-node build info in the database, not a process global,
    so every worker and background job renders the same config.  A global is
    only set at startup, and a job in another context would render with no
    modules at all.

    Nodes that have never reported are ignored, so one box going down does
    not empty the set.
    """
    from app.db import session_scope
    from app.models import Node

    with session_scope() as session:
        infos = [
            n.nginx_build_info for n in session.query(Node).all()
            if n.nginx_build_info
        ]

    if not infos:
        # Nothing reported yet; fall back to this node's own view.
        return _local_caps

    common = common_capabilities(infos)

    # `nginx -V` shows what was compiled, not whether `load_module` was
    # written.  An unloaded module fails the config test, and since applies
    # are all or nothing that blocks the whole fleet.  So modsecurity is only
    # offered if every node that has reported says it is loaded.
    if "modsecurity" in common:
        with session_scope() as session:
            answered = [n.waf_module_loaded for n in session.query(Node).all()
                        if n.nginx_build_info and n.waf_module_loaded is not None]
        if answered and not all(answered):
            common = {m for m in common if m not in ("modsecurity", "modsecurity-nginx")}

    merged = Capabilities()
    merged.modules = common
    # nginx and OpenSSL versions also come from node reports rather than the
    # process global, which is empty outside the startup context and made the
    # post quantum check wrongly fail.
    parsed = [parse_build_info(i) for i in infos]
    versions_seen = [p["nginx_version"] for p in parsed if p["nginx_version"]]
    openssl_seen = [p["openssl_version"] for p in parsed if p["openssl_version"]]

    merged.nginx_version = min(versions_seen) if versions_seen else _local_caps.nginx_version
    # Oldest OpenSSL in the fleet.
    merged.openssl_version = (
        min(openssl_seen, key=_openssl_sort_key) if openssl_seen
        else _local_caps.openssl_version
    )
    merged.third_party = [t for t in _local_caps.third_party if t in common]
    merged.has_stream = "stream" in common
    merged.has_mail = "mail" in common
    merged.has_http3 = "http_v3_module" in common
    merged.configure_args = _local_caps.configure_args

    # The oldest nginx decides which directives can be used, since the same
    # config must work on every box.
    versions = []
    with session_scope() as session:
        for n in session.query(Node).all():
            if not n.nginx_version:
                continue
            try:
                versions.append(tuple(int(p) for p in str(n.nginx_version).split(".")[:3]))
            except ValueError:
                continue

    if versions:
        oldest = min(versions)
        merged.nginx_version = ".".join(str(p) for p in oldest)

    return merged


def _openssl_sort_key(version: str):
    """Numeric sort key for OpenSSL versions, so 3.10 sorts after 3.9."""
    parts = []
    for chunk in str(version).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def module_differences() -> dict:
    """
    Which nodes are missing which modules, for the cluster page.  A node
    built with a different module list otherwise goes unnoticed until a
    setting mysteriously won't apply.
    """
    from app.db import session_scope
    from app.models import Node

    with session_scope() as session:
        nodes = [
            (n.name, n.nginx_build_info, n.nginx_version)
            for n in session.query(Node).all() if n.nginx_build_info
        ]

    if len(nodes) < 2:
        return {"consistent": True, "nodes": {}, "missing": {}}

    per_node = {name: parse_build_info(info)["modules"] for name, info, _ in nodes}
    everything = set().union(*per_node.values())
    common = set.intersection(*per_node.values())

    missing = {}
    for name, mods in per_node.items():
        gap = everything - mods
        if gap:
            missing[name] = sorted(gap)

    return {
        "consistent": not missing,
        "nodes": {n: len(m) for n, m in per_node.items()},
        "versions": {name: ver for name, _, ver in nodes},
        "common_count": len(common),
        "missing": missing,
    }


def get_local_capabilities() -> Capabilities:
    return _local_caps


def set_local_capabilities(build_info: str, version: str = "") -> Capabilities:
    global _local_caps
    _local_caps = Capabilities(build_info, version)
    log.info(
        "nginx %s with %d modules, openssl %s",
        _local_caps.nginx_version,
        len(_local_caps.modules),
        _local_caps.openssl_version,
    )
    return _local_caps


def common_capabilities(node_build_infos: list) -> set:
    """
    The modules every node in the fleet has.  Only these are offered, since
    the config syncs everywhere and one node lacking a module rejects it.
    """
    if not node_build_infos:
        return set()

    sets = [parse_build_info(info)["modules"] for info in node_build_infos if info]
    if not sets:
        return set()

    common = sets[0]
    for s in sets[1:]:
        common &= s
    return common
