"""
Working out what this nginx can actually do.

We read the configure line back out of nginx -V and turn it into a set of
module names.  The GUI then only offers settings that will really load.

This matters more than it sounds.  The installer script builds nginx with a
specific list of modules, and people edit that list.  Somebody drops the image
filter module to speed up their build, and now every image filter setting in
the GUI writes config that makes nginx refuse to start.  Reading the real build
means that cannot happen.

It also means the GUI adapts on its own.  Add a module to the installer, rerun
it, and the settings for it just show up.
"""

import logging
import re

log = logging.getLogger("nfm.caps")


# Built in modules that are always compiled unless somebody went out of their
# way to turn them off.  These are the --without- ones, so we assume they are
# there and only drop them if we see them being disabled.
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
    Pull apart the output of nginx -V.

    Gives back the version, the OpenSSL version, the module set, and the raw
    configure arguments.
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

    # Two shapes show up here.  A distro build says "built with OpenSSL 3.0.2",
    # and a source build against its own OpenSSL says "running with".  Catch
    # both, and prefer the running one since that is what is actually loaded.
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

    # --without-http_gzip_module means it is not there, so take it back out.
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

    # Third party modules come in as --add-module=/some/path/name.  The folder
    # name is what we key on, which is why the installer clones each one into a
    # folder named after the module.
    for path in re.findall(r"--add-(?:dynamic-)?module=(\S+)", args):
        name = path.rstrip("/").split("/")[-1]
        result["third_party"].append(name)
        modules.add(name)

        # Map the folder names the installer uses onto friendlier names, so a
        # feature can ask for either one.
        alias = THIRD_PARTY_ALIASES.get(name)
        if alias:
            modules.add(alias)

    result["modules"] = modules
    return result


# The installer clones these into folders with these exact names.  Some of them
# are a mouthful, so features can ask for the short version instead.
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
    # nchan is no longer in the build, see the note in nginx-installer.sh.
    # This mapping stays because a node that has not been rebuilt yet still has
    # it compiled in, and its module list should still read properly.
    "nchan": "nchan",
    "nginx-upstream-fair": "upstream_fair",
    "upstream-fair": "upstream_fair",
    "ngx_devel_kit": "ndk",
}


class Capabilities:
    """
    What one node's nginx can do.

    Held in memory and refreshed whenever we get a status back from the agent.
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
        Does this build have the post quantum key exchange.

        Needs OpenSSL 3.5 or newer.  The installer builds against 3.5, so a box
        set up with it will say yes.  A distro nginx almost certainly will not.
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


# The capabilities of the node we are running on.  Filled in at startup and
# refreshed on every agent status call.
_local_caps = Capabilities()


def fleet_capabilities() -> Capabilities:
    """
    What every node in the fleet can do, as a set.

    This is what the GUI offers and what the renderer is allowed to emit, and
    it is the intersection rather than this node's own list.  Two reasons, and
    both have bitten:

      The config is identical on every node, because that is the whole point.
      Offer a setting that only three of your four boxes were built with, and
      the fourth refuses to start on the next apply.  The two phase apply
      catches it before anything goes live, so nothing breaks, but you are left
      with a change that will not go out and no obvious reason why.

      The module list is read back out of nginx -V and kept in the database
      against each node.  Reading it from there rather than a variable in this
      process means every worker, and every background job, renders exactly the
      same config.  A process global is only filled in by startup, so a job
      running in a different context would quietly render with no modules at
      all and drop every gated feature.

    A node we have never heard from is not counted.  It has told us nothing, so
    treating its silence as "supports nothing" would empty the set the moment a
    box went down.
    """
    from app.db import session_scope
    from app.models import Node

    with session_scope() as session:
        infos = [
            n.nginx_build_info for n in session.query(Node).all()
            if n.nginx_build_info
        ]

    if not infos:
        # Nothing known yet, so fall back to whatever this node worked out for
        # itself.  Better than claiming nothing is available.
        return _local_caps

    common = common_capabilities(infos)

    # Built is not loaded, and the gate has to ask for loaded.
    #
    # Everything above comes out of `nginx -V`, which reports what was compiled
    # in.  It cannot say whether a `load_module` line was ever written, and a
    # module nginx has not been told about is one that fails the config test
    # the first time anything uses it.  Since an apply is all or nothing, that
    # is not one broken site, it is a fleet that cannot apply anything.
    #
    # So modsecurity is dropped from what the fleet is offered unless every
    # node says it is loaded.  A node that has not said yet is not counted
    # against it, the same as everywhere else here: silence is not a no.
    if "modsecurity" in common:
        with session_scope() as session:
            answered = [n.waf_module_loaded for n in session.query(Node).all()
                        if n.nginx_build_info and n.waf_module_loaded is not None]
        if answered and not all(answered):
            common = {m for m in common if m not in ("modsecurity", "modsecurity-nginx")}

    # Version and OpenSSL come from this node, since they are only used for
    # display and for the post quantum check, which is per build anyway.
    merged = Capabilities()
    merged.modules = common
    # Both of these come from what the nodes reported, not from a variable in
    # this process.  A process global is only filled in by startup, so anything
    # running in another context saw no OpenSSL version at all and decided the
    # fleet could not do post quantum when it could.
    parsed = [parse_build_info(i) for i in infos]
    versions_seen = [p["nginx_version"] for p in parsed if p["nginx_version"]]
    openssl_seen = [p["openssl_version"] for p in parsed if p["openssl_version"]]

    merged.nginx_version = min(versions_seen) if versions_seen else _local_caps.nginx_version
    # The oldest OpenSSL in the fleet, for the same reason as the nginx version.
    merged.openssl_version = (
        min(openssl_seen, key=_openssl_sort_key) if openssl_seen
        else _local_caps.openssl_version
    )
    merged.third_party = [t for t in _local_caps.third_party if t in common]
    merged.has_stream = "stream" in common
    merged.has_mail = "mail" in common
    merged.has_http3 = "http_v3_module" in common
    merged.configure_args = _local_caps.configure_args

    # The oldest nginx in the fleet is what decides which directives can be
    # used, for the same reason as the module set: the config is identical
    # everywhere, so it has to work on the oldest box you have.
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
    """Sort OpenSSL versions numerically rather than as text, so 3.10 beats 3.9."""
    parts = []
    for chunk in str(version).split("."):
        digits = "".join(c for c in chunk if c.isdigit())
        parts.append(int(digits) if digits else 0)
    return tuple(parts)


def module_differences() -> dict:
    """
    Which nodes are missing which modules.

    Shown on the cluster page.  A node built from a different module list is
    the sort of thing that goes unnoticed until a setting mysteriously will not
    apply, so it is worth saying out loud.
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
    The modules every node in the fleet has.

    This is what the GUI actually offers.  A setting that works on three of your
    four boxes is worse than useless, because the config syncs everywhere and
    the fourth one refuses to start.  So we only offer the common set, and the
    cluster page points out any node that is the odd one out.
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
