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
