"""
Turning what is in the database into nginx config files.

Everything we generate lands under /etc/nginx/nginxmgr/ and a single include
line in conf.d pulls it in.  Keeping our files in one folder means we never have
to guess whether a file is ours, and wiping our own config never touches
anything a person wrote by hand.

The layout we write:

    nginxmgr/
      00-managed.conf     the log formats and other http level bits
      maps/*.conf         map blocks, including the sticky session routing
      limits/*.conf       rate limit and connection limit zones
      caches/*.conf       proxy cache zone definitions
      upstreams/*.conf    the backend pools
      sites/*.conf        one file per site
      streams/*.conf      plain TCP and UDP proxying
      certs/              cert bundles copied from whichever node got them

Order matters in one place.  Zones and maps have to be defined before anything
uses them, so the include lines are numbered and upstreams come before sites.
"""

import hashlib
import ipaddress
import json
import logging
import re

from app.catalog import get_feature
from app.core import error_pages
from app.models import MemberState

log = logging.getLogger("nfm.render")

# Where the country database lives.  One place, because it has to match what
# the agent writes and a path typed twice is a path that disagrees.
#
# Our own name rather than either source's, since the file can come from db-ip
# or from MaxMind and calling a db-ip database GeoLite2 would be a small lie
# that somebody eventually debugs.
GEOIP_DATABASE = "/usr/share/GeoIP/nfm-country.mmdb"

MANAGED_ROOT = "/etc/nginx/nginxmgr"

# Where the agent puts the firewall rule set.  Not under MANAGED_ROOT, because
# that folder is wiped and rewritten on every apply and these are installed by
# the agent on a schedule of their own.  One place, because it has to match
# what the agent writes and a path typed twice is a path that disagrees.
#
# It is the symlink rather than the versioned folder, so an update swaps what
# this points at without every site's rule file having to be rewritten.
CRS_ROOT = "/etc/nginx/modsecurity/crs"


def waf_path_to_regex(path: str) -> str:
    """
    Turn a path with `*` in it into a regular expression.

    Learning produces one exclusion per path it saw, and on anything with a
    path per object that is dozens of near identical rows: a git server gives
    `/trice/apache2.git/git-upload-pack`, `/trice/site.git/git-upload-pack`
    and so on for every repository that exists now or ever will.  Somebody
    reviewing that cannot see the shape, and a repository created tomorrow is
    not covered by any of them.

    So the stored path is a glob, which is what a person can read and edit,
    and the translation happens here on the way to nginx.  Storing the regex
    instead would mean the page shows somebody `^/trice/[^/]*\\.git/` and asks
    them to maintain it.

      *   anything except a slash, so one path segment
      **  anything at all, slashes included

    Everything outside a star is escaped, which matters more than it looks:
    `.git` has a dot in it, and an unescaped dot matches any character, so
    `/trice/*.git/` would quietly also match `/trice/anythingXgit/`.

    Not anchored at the end, on purpose.  These replace a `@beginsWith`, and
    an exclusion for a path is meant to cover what sits under it.
    """
    out = []
    i = 0
    while i < len(path):
        if path.startswith("**", i):
            out.append(".*")
            i += 2
        elif path[i] == "*":
            out.append("[^/]*")
            i += 1
        else:
            j = i
            while j < len(path) and path[j] != "*":
                j += 1
            out.append(re.escape(path[i:j]))
            i = j
    return "^" + "".join(out)


def _waf_path_match(path: str) -> str:
    """
    The ModSecurity operator for one exclusion's path.

    Plain paths keep `@beginsWith`, which is a string compare and cheaper than
    a regular expression on every request.  Only a path somebody has actually
    put a star in pays for `@rx`.
    """
    if "*" in path:
        return "@rx " + waf_path_to_regex(path)
    return "@beginsWith " + path
CERT_SYNC_DIR = f"{MANAGED_ROOT}/certs"
LE_LIVE_DIR = "/etc/letsencrypt/live"

# Where Debian and Ubuntu keep the public CA list.  nginx has no built in
# default, so verifying a backend certificate needs a file named out loud.
SYSTEM_CA_BUNDLE = "/etc/ssl/certs/ca-certificates.crt"

# The hybrid post quantum key exchange group, as OpenSSL 3.5 names it.
#
# Hybrid means it does the classic X25519 exchange and the quantum resistant
# ML-KEM one and mixes both results, so it is never weaker than what it
# replaces.  The older X25519Kyber768Draft00 name is gone in 3.5 and naming it
# stops nginx starting, so there is no point offering it as a fallback.
PQ_GROUP = "X25519MLKEM768"

# What we fall back through when post quantum is hybrid rather than required.
CLASSIC_GROUPS = ("X25519", "secp256r1", "secp384r1")

# What a site in SSL offload only mode forces, whatever is stored against it.
#
# The mode is one promise: this site terminates TLS and passes everything else
# through untouched.  Every key in here is a way the renderer would otherwise
# change a header, so the mode is exactly the list, and reading it is how you
# check what the promise covers.
#
# Forced at render time rather than by clearing the stored settings, because
# somebody who turns the mode off should get their site back rather than a site
# with every header setting wiped.  The GUI greys these out while it is on, so
# what is stored is whatever they were before and it is still there afterwards.
#
# Not in here, deliberately:
#
#   the pool token, which is the load balancer proving itself to the backend
#   rather than a rewrite of anything the backend sent.  Turning it off with a
#   checkbox on a different page would either break a backend that checks it or
#   quietly drop the check, and neither is something to do without being asked.
#
#   the WAF, CORS, geo blocking and the access list.  Those decide who gets
#   through, not what their headers say, they are off unless somebody turned
#   them on, and each has a tab of its own.
#
#   a backend path set on the pool, and the redirect rewriting that goes with
#   it.  That is how the request reaches the application at all, the same as
#   SNI.  Dropping it here would not pass headers through, it would 404.
OFFLOAD_ONLY_FORCES = {
    "hsts_enabled": False,
    "x_frame_options": "",
    "x_content_type_options": False,
    "referrer_policy": "",
    "content_security_policy": "",
    "permissions_policy": "",
    "custom_response_headers": [],
    "proxy_hide_headers": [],
    "proxy_redirect": "",
    "proxy_cookie_path": "",
    "sub_filter_rules": [],
    "server_header_mode": "default",
}

# Written into every generated file so nobody mistakes it for something they
# can safely edit by hand.
HEADER = """# Generated by Failover LB.  Do not edit this by hand.
#
# Anything you change here gets wiped the next time somebody saves in the GUI.
# To change it for real, edit the site in the manager, or switch that site to
# raw config mode and edit it there so your changes get stored.
#
# {detail}
"""


def esc(value) -> str:
    """
    Make a value safe to drop into a config file.

    The catalog already refuses semicolons, braces and newlines on the way in,
    so this is the second line of defense, not the first.  Anything odd gets
    quoted rather than passed through, because a value that closes a directive
    early can write whatever config it likes.
    """
    if value is None:
        return '""'
    text = str(value)
    if not text:
        return '""'

    # Already quoted and clean, leave it alone.
    if len(text) >= 2 and text[0] == text[-1] and text[0] in "\"'":
        inner = text[1:-1]
        if not re.search(r'[;{}\n\r\\]', inner):
            return text

    if re.search(r'[;{}\n\r\\]', text):
        raise ValueError(f"refusing to write a value with config syntax in it: {text!r}")

    # Spaces or a # need quoting or nginx reads them as more arguments.
    if re.search(r"[\s#]", text):
        return '"' + text.replace('"', '\\"') + '"'

    return text


def map_value(value) -> str:
    r"""
    A match or a result inside a map block.

    Not `esc`, and the difference is a backslash.  `esc` refuses them, which is
    right for a value going into an ordinary directive and wrong here: the whole
    point of a map is matching, most matching is regular expressions, and almost
    every regular expression worth writing has a backslash in it.  `~*google\.`
    made the render raise, and a render that raises stops every apply on every
    node until somebody works out which row of which map is to blame.

    Everything is quoted.  nginx keeps a backslash as written inside quotes, so
    a regular expression survives it, and quoting is what makes a value with a
    space in it work at all: unquoted, nginx counts the words and says "invalid
    number of the map parameters".

    Checked against real nginx rather than assumed, including the one case that
    breaks out: a value ending in a single backslash escapes our own closing
    quote and nginx reads to the end of the file looking for it.  A regular
    expression cannot legally end that way either, so refusing it costs nothing.
    """
    text = "" if value is None else str(value)

    # Older rows stored the two characters `""` to mean empty, from back when
    # the value was written pre-quoted.  Quoting that again gives a default of
    # two literal quote marks, which is a value no comparison will ever match.
    if text in ('""', "''"):
        text = ""

    if re.search(r"[;{}\n\r]", text):
        raise ValueError(
            f"a map entry cannot contain a semicolon, a brace or a newline: {text!r}")

    # An odd number of trailing backslashes would escape the closing quote.
    trailing = len(text) - len(text.rstrip("\\"))
    if trailing % 2:
        raise ValueError(
            f"a map entry cannot end in a single backslash: {text!r}")

    return '"' + text.replace('"', '\\"') + '"'


def directive_args(value, what: str) -> str:
    r"""
    A line of arguments written straight after a directive name.

    For the settings whose value *is* the rest of the directive: a rewrite rule
    is `^/old/(.*)$ /new/$1 last`, three arguments, and a sub_filter rule is two
    quoted strings.  They cannot go through `esc`, which quotes the lot into a
    single argument and refuses backslashes outright, and almost every rewrite
    worth writing has a backslash in it.  Same lesson as `map_value` in the maps
    work, one layer along.

    So it is written as typed, and what is refused is only what breaks out of
    the directive: a semicolon or a brace ends it early and starts writing
    config of somebody's choosing, a newline does the same, and a `#` turns the
    rest of the line into a comment, which silently drops half the rule.

    A trailing single backslash escapes whatever nginx reads next, so it goes
    too, the same as in a map value.
    """
    text = "" if value is None else str(value).strip()
    if not text:
        raise ValueError(f"an empty {what} is not a rule")

    if re.search(r"[;{}\n\r]", text):
        raise ValueError(
            f"a {what} cannot contain a semicolon, a brace or a newline: {text!r}")
    if "#" in text:
        raise ValueError(
            f"a {what} cannot contain a #, which nginx reads as the start of a "
            f"comment and would drop the rest of the rule: {text!r}")

    trailing = len(text) - len(text.rstrip("\\"))
    if trailing % 2:
        raise ValueError(f"a {what} cannot end in a single backslash: {text!r}")

    return text


def esc_header_value(value) -> str:
    """
    A response header value, which is allowed to contain semicolons.

    esc() refuses a semicolon because in most places it would end the directive
    early and let somebody write config of their own.  Inside a quoted argument
    it does no such thing, and a header value legitimately needs them: every
    Content-Security-Policy ever written is a list separated by semicolons, and
    so are Permissions-Policy and a Set-Cookie.

    Refusing them meant setting a CSP did not fail politely.  The render raised,
    so nothing could be applied anywhere until somebody worked out which setting
    on which site was responsible.

    So the value gets quoted rather than rejected, which is what nginx wants
    anyway.  A quote inside is escaped so it cannot close the string early.
    Newlines and carriage returns are still refused outright, because those end
    the directive whatever the quoting is, and a header value with a newline in
    it is header injection wearing a hat.
    """
    if value is None:
        return '""'
    text = str(value)
    if not text:
        return '""'

    if re.search(r"[\n\r]", text):
        raise ValueError(f"refusing to write a header value with a newline in it: {text!r}")

    return '"' + text.replace("\\", "\\\\").replace('"', '\\"') + '"'


def parse_size(value):
    """An nginx size like 16k or 1m as bytes.  None when it is not one."""
    m = re.fullmatch(r"(\d+)([kKmMgG]?)", str(value).strip())
    if not m:
        return None
    return int(m.group(1)) * {"": 1, "k": 1024, "m": 1024 ** 2, "g": 1024 ** 3}[
        m.group(2).lower()
    ]


def busy_buffers_for(buffer_size, buffers):
    """
    Work out a proxy_busy_buffers_size that nginx will accept.

    When you do not set it, nginx picks twice the larger of the header buffer
    and one body buffer, and then insists that figure fits inside everything
    except one buffer.  Raise proxy_buffer_size on its own and that sum stops
    working, and nginx complains about a directive you never touched:

        "proxy_busy_buffers_size" must be less than the size of all
        "proxy_buffers" minus one buffer

    Somebody raising the header buffer is nearly always doing it to fix a 502
    from a backend with big cookies.  Making them solve a second puzzle to get
    there is unkind, so we work out a value that fits and write it down.

    Gives back None when no sensible value exists, which means the buffers are
    genuinely too small and the person does have to change them.
    """
    head = parse_size(buffer_size)
    m = re.fullmatch(r"(\d+)\s+(\S+)", str(buffers).strip())
    if not head or not m:
        return None

    count = int(m.group(1))
    one = parse_size(m.group(2))
    if not one or count < 2:
        return None

    total = count * one
    ceiling = total - one
    floor = max(head, one)

    if floor > ceiling:
        return None
    return floor


def emit(feature, value) -> str:
    """
    Turn a setting into the text that follows its directive.

    Most settings are one value and get quoted if they contain anything odd.
    A few directives take several arguments instead, and those must not be
    quoted, because nginx counts arguments and one quoted string is one
    argument no matter how many spaces are inside it.

    Getting this wrong gives "invalid number of arguments", which does at least
    say what is wrong, but only after the config has failed to load.
    """
    if getattr(feature, "multi_arg", False):
        tokens = str(value).split()
        for token in tokens:
            if re.search(r'[;{}\n\r\\]', token):
                raise ValueError(f"refusing to write a value with config syntax in it: {token!r}")
        return " ".join(tokens)
    return esc(value)


class Renderer:
    """
    Builds the whole set of config files.

    Give it the objects, get back a dict of relative path to file contents.
    That dict goes to the agent, which stages it, tests it, and only then puts
    it live.  Nothing here writes to disk, which makes it easy to test and means
    a render that blows up half way cannot leave a broken file behind.
    """

    def __init__(self, capabilities=None, node_addresses=None, settings=None,
                 ignore_health=False, waf_profiles=None, waf_recording=None):
        self.caps = capabilities
        # Origin maps built while sites are rendered, written out at the end.
        # nginx sends one Access-Control-Allow-Origin and the page offers a
        # list, so the only way to honour a list is to look the caller's origin
        # up and answer with it when it is on the list.
        self._cors_maps = []
        # Same idea for the country blocking: the lookup is declared once at
        # the http level, and each site that blocks anything gets a map turning
        # a country code into a yes or no.
        self._geo_maps = []
        # Render as though every enabled backend were healthy.
        #
        # Only used to answer "has a person changed something since the last
        # apply".  Health state changes the config on its own, all day, as
        # backends flap, and the health checker applies those itself within
        # seconds.  Counting them as pending work puts a banner in front of
        # somebody about a change they did not make and cannot usefully apply,
        # and by the time they click it the checker has already done it.
        self.ignore_health = ignore_health
        # Every cluster node's address.  These go into the management allow list
        # so our own health checks never get blocked by an ACL somebody wrote.
        self.node_addresses = node_addresses or []
        self.settings = settings or {}
        # Tuned WAF profiles, as plain dictionaries rather than rows.  Read
        # once by whoever builds the renderer and passed in, so nothing here
        # touches a row after the session that loaded it has closed, which this
        # project has already been bitten by once.
        self.waf_profiles = waf_profiles or []
        # Site name to tester addresses, for sites recording their surface now.
        # A recording session switches full audit logging on for those
        # addresses and nobody else, so the log holds the shape of the
        # application instead of the shape of the attacks on it.  Read per
        # render rather than stored on the site, because it has to go off again
        # by itself when the session ends.
        self.waf_recording = waf_recording or {}
        # Which ports already have a QUIC listener carrying reuseport.  nginx
        # refuses to start if two server blocks both ask for it on the same
        # address and port, so the first site to want HTTP/3 on a port claims
        # it and the rest do without.  Per render, because the whole config is
        # written in one pass.
        self._quic_ports = set()
        # Access lists by id, filled in when sites are rendered.  A path can
        # carry its own, and the code that writes a path is too far down to be
        # handed the map.
        self.acl_by_id = {}
        self.files = {}

    def has_module(self, module: str) -> bool:
        if not self.caps:
            return True
        return self.caps.has(module)

    def supports(self, feature_key: str) -> bool:
        """
        Can the oldest node in the fleet handle this setting.

        Checked here as well as in the API, because config also gets rendered
        from places that never went through a form, like the health checker
        rewriting an upstream.  The renderer is the last gate before something
        reaches a config file.
        """
        if not self.caps:
            return True
        feature = get_feature(feature_key)
        if not feature:
            return True
        return feature.is_available(self.caps.modules, self.caps.version_tuple)

    # =========================================================================
    # The entry point
    # =========================================================================

    def render_all(self, hosts, pools, certs, access_lists, rate_zones,
                   conn_zones, cache_zones, maps, streams,
                   error_templates=None) -> dict:
        self.files = {}

        self._render_base()
        self._render_auth_files(access_lists)
        self._render_maps(maps, pools)
        self._render_limit_zones(rate_zones, conn_zones)
        self._render_cache_zones(cache_zones)
        self._render_upstreams(pools)
        self._render_error_pages(hosts, error_templates or [])
        self._render_sites(hosts, certs, access_lists, error_templates or [])
        self._render_streams(streams, certs, access_lists)

        # After the sites, because that is when they are built.  One file, so a
        # site with no cross site access adds nothing to the config at all.
        if self._cors_maps:
            self.files["maps/cors.conf"] = (
                HEADER.format(detail="Which origins each site answers to.")
                + "\n" + "\n".join(self._cors_maps))

        if self._geo_maps:
            # The lookup has to be at the http level, so it lives here rather
            # than in a server block, and it is only written when a site
            # actually blocks somewhere.  The database has to exist on every
            # node: without it nginx will not start, and the apply is refused
            # on the node that is missing it before anything goes live.
            self.files["maps/geoip.conf"] = (
                HEADER.format(detail="Country lookup, and who each site refuses.")
                + "\n"
                + "geoip2 " + GEOIP_DATABASE + " {\n"
                + "    auto_reload 5m;\n"
                + "    $nfm_geoip2_country country iso_code;\n"
                + "}\n\n"
                # While nginx is fetching one of our error pages the request is
                # an internal redirect back through the server rewrite phase,
                # so every site's country test would run a second time on the
                # page meant to explain the first refusal.  This says so, and
                # each site's map is keyed on it.
                + "map $uri $nfm_geo_scope {\n"
                + "    volatile;\n"
                + "    default \"\";\n"
                + f"    \"~^{error_pages.URI_PREFIX}/\" \"skip\";\n"
                + "}\n\n"
                + "\n".join(self._geo_maps))

        return self.files

    def checksum(self) -> str:
        """
        A fingerprint of everything we generated.

        Two nodes with the same checksum are serving the same config.  That is
        how the cluster page knows who is caught up without shipping whole
        files around to compare.
        """
        h = hashlib.sha256()
        for path in sorted(self.files):
            h.update(path.encode())
            h.update(b"\0")
            h.update(self.files[path].encode())
            h.update(b"\0")
        return h.hexdigest()

    # =========================================================================
    # Base config
    # =========================================================================

    def _render_base(self):
        """Log formats and the localhost only status endpoint."""
        lines = [HEADER.format(detail="Log formats and the stub_status endpoint.")]

        # The detailed format is the one worth having.  request_time is how long
        # the whole thing took, upstream_response_time is how long the backend
        # took.  The gap between them is nginx and the network.  Without both
        # numbers, "the site is slow" is a guess.
        lines.append('''
log_format nfm_main '$remote_addr - $remote_user [$time_local] '
                    '"$request" $status $body_bytes_sent '
                    '"$http_referer" "$http_user_agent"';

log_format nfm_detailed '$remote_addr - $remote_user [$time_local] '
                        '"$request" $status $body_bytes_sent '
                        '"$http_referer" "$http_user_agent" '
                        'rt=$request_time uct=$upstream_connect_time '
                        'uht=$upstream_header_time urt=$upstream_response_time '
                        'upstream=$upstream_addr cache=$upstream_cache_status '
                        'host=$host';
''')

        # JSON, for shipping to a log platform.  Note the escaping on the
        # request and user agent: those come straight from the client and can
        # contain quotes, which would produce broken JSON lines.
        lines.append('''
log_format nfm_json escape=json '{'
    '"time":"$time_iso8601",'
    '"remote_addr":"$remote_addr",'
    '"host":"$host",'
    '"request":"$request",'
    '"status":$status,'
    '"bytes":$body_bytes_sent,'
    '"referer":"$http_referer",'
    '"user_agent":"$http_user_agent",'
    '"request_time":$request_time,'
    '"upstream_addr":"$upstream_addr",'
    '"upstream_response_time":"$upstream_response_time",'
    '"cache_status":"$upstream_cache_status"'
'}';
''')

        # stub_status is what the dashboard reads for connection counts.  It is
        # bound to localhost only.  It is not sensitive exactly, but there is no
        # reason for the internet to see your connection counts.
        if self.has_module("http_stub_status_module"):
            lines.append('''
# Connection and request counters for the manager dashboard.  Localhost only,
# since nothing outside this box has any business reading it.
server {
    listen 127.0.0.1:7081;
    server_name _;

    access_log off;

    location = /nginx_status {
        stub_status;
        allow 127.0.0.1;
        deny all;
    }
}
''')

        self.files["00-managed.conf"] = "\n".join(lines)

    def _render_auth_files(self, access_lists):
        """
        Write the htpasswd files basic auth points at.

        The config names a file per access list.  Without this nothing creates
        it, nginx cannot open it, and every request to a site using basic auth
        gets a 500 while the error log says the file is missing.  Same shape of
        mistake as pointing at a certificate that is not there.
        """
        for acl in access_lists:
            if not acl.basic_auth_enabled:
                continue

            users = acl.auth_users()
            if not users:
                # Enabled with nobody in it would lock the site out completely,
                # since nginx would reject every request for want of a valid
                # user.  Leave the file out and the renderer below skips the
                # auth_basic line too.
                continue

            lines = [
                "# Generated by Failover LB.  Do not edit this by hand.",
                f"# Basic auth users for the {acl.name} access list.",
                "#",
                "# These are APR1 hashes, which is the format nginx reads.  It is a weak",
                "# hash by modern standards and that comes with the format, not from a",
                "# choice made here.  Basic auth is a speed bump on top of the address",
                "# rules, not the thing holding the door shut.",
            ]
            for user in users:
                if user.get("username") and user.get("hash"):
                    lines.append(f"{user['username']}:{user['hash']}")

            self.files[f"auth/{_safe_name(acl.name)}.htpasswd"] = "\n".join(lines) + "\n"

    # =========================================================================
    # Maps
    # =========================================================================

    def _render_maps(self, maps, pools):
        for m in maps:
            lines = [HEADER.format(detail=f"Map block: {m.name}")]

            args = f"{m.source_variable} ${m.result_variable.lstrip('$')}"
            lines.append(f"map {args} {{")
            if m.hostnames:
                lines.append("    hostnames;")
            if m.default_value:
                lines.append(f"    default {map_value(m.default_value)};")

            for entry in m.entry_list():
                match = entry.get("match", "")
                value = entry.get("value", "")
                if not match:
                    continue
                try:
                    lines.append(f"    {map_value(match)} {map_value(value)};")
                except ValueError as exc:
                    # One bad row loses that row, not the whole render.  Raising
                    # here would take out every unrelated change on every node,
                    # which is what the content security policy setting used to
                    # do and is the worst way for a typo to be reported.
                    log.warning("dropping an entry from the map %s: %s", m.name, exc)

            lines.append("}")
            self.files[f"maps/{_safe_name(m.name)}.conf"] = "\n".join(lines)

        # Sticky sessions need a map too.  This is our stand in for the paid
        # sticky cookie feature.  The map turns the route cookie into a value we
        # can hash the upstream on, and the site adds the cookie when a client
        # shows up without one.
        for pool in pools:
            cfg = pool.setting_map()
            if not cfg.get("sticky_enabled"):
                continue

            cookie = cfg.get("sticky_cookie_name", "nfm_route")
            max_age = int(cfg.get("sticky_cookie_max_age", 3600))
            var = _safe_var(pool.name)
            lines = [HEADER.format(detail=f"Sticky session routing for pool {pool.name}")]
            lines.append(f'''
# Stand in for the paid sticky cookie feature.  We hash on the route cookie so
# a client keeps landing on the same backend.  When they have no cookie yet the
# fallback is their address, which keeps them steady for that first request
# until the cookie is set.
map $cookie_{cookie} $sticky_{var} {{
    default $remote_addr;
    "" $remote_addr;
    ~. $cookie_{cookie};
}}

# Whether to hand this client a cookie, and what to put in it.
#
# Only when they do not already have one.  Setting it on every response is
# what this used to do, and it does not merely fail to be sticky, it actively
# rotates: the value written was the backend that just answered, the hash of
# that address lands on some other backend, and the next response writes that
# one instead.  A client walks round the pool one request at a time.
#
# The value has to be stable and does not have to mean anything, which is why
# it is a request id rather than an address.  What makes a client stick is the
# same string coming back every time, not what the string says.
#
# An empty value here writes no header at all, which is how the "only when they
# do not have one" half is done without an if block.
map $cookie_{cookie} $sticky_set_{var} {{
    ""      "{cookie}=$request_id; Path=/; Max-Age={max_age}; HttpOnly; SameSite=Lax";
    default "";
}}
''')
            self.files[f"maps/sticky-{_safe_name(pool.name)}.conf"] = "\n".join(lines)

    # =========================================================================
    # Rate and connection limit zones
    # =========================================================================

    def _render_limit_zones(self, rate_zones, conn_zones):
        if not rate_zones and not conn_zones:
            return

        lines = [HEADER.format(detail="Rate limit and connection limit zones.")]

        for z in rate_zones:
            lines.append(
                f"limit_req_zone {z.key} zone={_safe_name(z.name)}:{z.zone_size} rate={z.rate};"
            )

        for z in conn_zones:
            lines.append(
                f"limit_conn_zone {z.key} zone={_safe_name(z.name)}:{z.zone_size};"
            )

        # Log a rate limit hit at warn, not the default error.  A client getting
        # throttled is normal and expected.  Logging it as an error means the
        # error log fills with things that are working as designed, and then
        # people stop reading the error log.
        lines.append("")
        lines.append("limit_req_log_level warn;")
        lines.append("limit_conn_log_level warn;")

        self.files["limits/zones.conf"] = "\n".join(lines)

    # =========================================================================
    # Cache zones
    # =========================================================================

    def _render_cache_zones(self, cache_zones):
        if not cache_zones:
            return

        lines = [HEADER.format(detail="Proxy cache zones.")]

        for z in cache_zones:
            parts = [
                f"proxy_cache_path {z.path}",
                f"levels={z.levels}",
                f"keys_zone={_safe_name(z.name)}:{z.keys_zone_size}",
                f"max_size={z.max_size}",
                f"inactive={z.inactive}",
                f"use_temp_path={'on' if z.use_temp_path else 'off'}",
            ]
            lines.append(" ".join(parts) + ";")

        # use_temp_path=off is the default we set on the model and it is worth
        # knowing why.  With it on, nginx writes the file to a temp folder and
        # then moves it into the cache.  If those are different filesystems that
        # move is a full copy of every cached response.
        self.files["caches/zones.conf"] = "\n".join(lines)

    # =========================================================================
    # Upstreams
    # =========================================================================

    def _pool_has_servers(self, pool) -> bool:
        """
        Will this pool actually produce a server line.

        nginx refuses an upstream block with nothing in it, and refusing means
        the config does not load, which means the apply fails on every node and
        no unrelated change can go out either.  One pool somebody emptied while
        tidying up should not be able to freeze the fleet.

        Enabled is the test, not healthy.  A pool whose members are all failing
        their checks still writes them, marked down or put back by the safety
        net above, so it still loads.
        """
        return any(m.enabled for m in getattr(pool, "members", []) or [])

    def _render_upstreams(self, pools):
        for pool in pools:
            if not self._pool_has_servers(pool):
                # No file at all.  The include is a glob, so a missing file is
                # fine, where an empty upstream block is fatal.
                log.warning(
                    "pool %s has no backends, leaving its upstream out and sending "
                    "the sites that use it to 503",
                    pool.name,
                )
                continue
            self.files[f"upstreams/{_safe_name(pool.name)}.conf"] = self._render_pool(pool)

    def _render_pool(self, pool, stream=False) -> str:
        """
        One upstream block.

        `stream` renders the same pool for the stream context, which takes a
        smaller set of directives than http does.  Checked against real nginx
        rather than assumed: ip_hash, keepalive and fair are all refused there,
        while zone, least_conn, hash, random and random two least_conn are
        fine.  Writing an http upstream into a stream block gets "directive is
        not allowed here", which stops the whole config loading over a setting
        somebody made on a page that never mentioned streams.
        """
        cfg = pool.setting_map()
        # The stream copy goes inside a file that already carries the header,
        # and repeating the whole "do not edit this" preamble once per pool
        # buries the config it is supposed to be introducing.
        lines = [] if stream else [HEADER.format(detail=f"Backend pool: {pool.name}")]
        if stream:
            lines.append(f"# Backend pool: {pool.name}")

        if pool.description:
            lines.append(f"# {pool.description}")

        lines.append(f"upstream {_safe_name(pool.name)} {{")

        # The shared memory zone matters more than it looks.  Without it every
        # worker process keeps its own idea of which backends are up, so with 16
        # workers a backend can be marked down in one and fine in another.
        if pool.zone_size:
            # A different name for the stream copy, and it has to be different.
            # nginx keeps one shared memory zone namespace for the whole
            # config, not one per block, so a pool used by a site and by a
            # stream declares the same zone twice for different uses and nginx
            # refuses the lot: "already declared for a different use".  That is
            # every apply on every node failing because somebody pointed a
            # stream at a pool a site was already using, which is the ordinary
            # thing to do.
            suffix = "_stream_zone" if stream else "_zone"
            lines.append(
                f"    zone {_safe_name(pool.name)}{suffix} {pool.zone_size};")

        # Load balancing method.  Only the ones the free version actually has.
        method = pool.lb_method
        if cfg.get("sticky_enabled") and stream:
            # Sticky hashes on a variable a map block sets, and maps live in
            # http.  A stream cannot see it, so this falls back rather than
            # writing a hash on a variable that is always empty, which would
            # send every connection to the same backend and look like the load
            # balancing had broken.
            lines.append("    # Sticky sessions need a cookie, and there are no")
            lines.append("    # cookies on a raw socket.  Balancing on the client")
            lines.append("    # address instead, which is the nearest thing.")
            lines.append("    hash $remote_addr consistent;")
        elif cfg.get("sticky_enabled"):
            var = f"$sticky_{_safe_var(pool.name)}"
            consistent = " consistent" if cfg.get("sticky_consistent", True) else ""
            lines.append(f"    hash {var}{consistent};")
        elif method == "least_conn":
            lines.append("    least_conn;")
        elif method == "ip_hash" and stream:
            # Same intent, different spelling.  stream has no ip_hash and would
            # refuse the config outright.
            lines.append("    hash $remote_addr consistent;")
        elif method == "ip_hash":
            lines.append("    ip_hash;")
        elif method == "hash" and stream and "$" in (pool.hash_key or "$request_uri") \
                and not _stream_has_variable(pool.hash_key or "$request_uri"):
            # The key names something only http knows about, like $request_uri.
            # There is no request here to take it from.
            lines.append(f"    # {pool.hash_key} means nothing on a raw socket, so")
            lines.append("    # this balances on the client address instead.")
            lines.append("    hash $remote_addr consistent;")
        elif method == "hash":
            key = pool.hash_key or "$request_uri"
            consistent = " consistent" if pool.hash_consistent else ""
            lines.append(f"    hash {esc(key)}{consistent};")
        elif method == "random":
            lines.append("    random;")
        elif method == "random_two":
            lines.append("    random two least_conn;")
        elif method == "fair" and stream:
            lines.append("    # fair is an http only module, so this is round robin.")
        elif method == "fair" and self.has_module("upstream_fair"):
            lines.append("    fair;")
        # round_robin is the default and takes no directive.

        lines.append("")

        # The members.  This is where health check results turn into config.
        any_up = False
        for m in pool.members:
            line = self._render_member(pool, m)
            if line:
                lines.append(line)
                if not line.strip().endswith("down;"):
                    any_up = True

        # Safety net.  If every member would be marked down we put them all back
        # in instead.  A pool serving errors is bad.  A pool serving nothing at
        # all, because a network blip failed every check at once, is worse, and
        # it is a failure mode we can just refuse to have.
        if not any_up and pool.members:
            log.warning(
                "pool %s would have had every member down, leaving them in instead",
                pool.name,
            )
            lines = [ln for ln in lines if not ln.strip().startswith("server ")]
            lines.append(
                "    # Every member failed its health check.  Rather than serve nothing\n"
                "    # we left them all in.  Something bigger is wrong, go look at the\n"
                "    # network or the backends themselves."
            )
            for m in pool.members:
                if m.enabled:
                    lines.append(self._render_member(pool, m, force_up=True))

        # keepalive is http only.  nginx refuses it in a stream upstream, and
        # it would mean nothing there anyway: a stream connection is the thing
        # being proxied, not a request on a pooled one.
        if pool.keepalive and not stream:
            lines.append("")
            lines.append(f"    keepalive {pool.keepalive};")
            if pool.keepalive_requests:
                lines.append(f"    keepalive_requests {pool.keepalive_requests};")
            if pool.keepalive_timeout:
                lines.append(f"    keepalive_timeout {pool.keepalive_timeout};")

        lines.append("}")
        return "\n".join(lines)

    def _render_member(self, pool, member, force_up=False) -> str:
        if not member.enabled:
            return f"    # {member.label} is disabled in the manager"

        parts = [f"server {member.address}:{member.port}"]

        # Slow start stand in.  A member that just came back gets a low weight
        # that climbs over the ramp window.  The health checker sets
        # ramp_weight, we just write whatever it decided.
        weight = member.weight
        node_state = {} if self.ignore_health else member.node_states()
        ramp = node_state.get("ramp_weight")
        if ramp is not None and ramp < weight:
            parts.append(f"weight={ramp}")
        elif weight and weight != 1:
            parts.append(f"weight={weight}")

        if member.max_fails is not None:
            parts.append(f"max_fails={member.max_fails}")
        if member.fail_timeout:
            parts.append(f"fail_timeout={member.fail_timeout}")
        if member.max_conns:
            parts.append(f"max_conns={member.max_conns}")
        if member.backup:
            parts.append("backup")

        state = MemberState.UP if self.ignore_health else member.effective_state
        if not force_up and state in (MemberState.DOWN, MemberState.MAINTENANCE):
            parts.append("down")

        line = "    " + " ".join(parts) + ";"

        # A short note on the end so somebody reading the file knows why a
        # server is marked down without having to go and open the GUI.
        if state == MemberState.MAINTENANCE:
            line += "   # taken out by an admin"
        elif state == MemberState.DOWN:
            # down_reason and not last_error, deliberately.  last_error is
            # rewritten by every failing check, so the wording could change
            # while the member's state did not, and this comment would change
            # the rendered file with it.  That makes the checksum an apply
            # compares against unstable, and the next unrelated apply reloads
            # nginx for a difference nobody made.  down_reason is captured once
            # when the member goes down and left alone until it comes back.
            reason = member.down_reason or member.last_error or "no reason recorded"
            line += f"   # failing health checks: {reason[:60]}"
        elif state == MemberState.DRAINING:
            line += "   # draining, will go down once connections finish"

        return line

    # =========================================================================
    # Sites
    # =========================================================================

    def _render_error_pages(self, hosts, error_templates):
        """
        Write out the pages, but only the ones a live site actually points at.

        Rendering every template whether or not anything uses it would put a
        half finished page somebody is still working on into the live config on
        every node, and grow the bundle that goes round the fleet on every
        apply for no reason.

        A template that will not render drops out and the sites using it fall
        back to nginx's own pages.  That is the same rule certificates follow
        and for the same reason: one object nobody can serve must never be able
        to stop every other change on every node.
        """
        wanted = set()
        for host in hosts:
            if not host.enabled:
                continue
            wanted.add(host.error_page_template_id)
            # A path can ask for a different one from the rest of its site, and
            # missing those here would write the directives with no files
            # behind them.
            for loc in (host.locations or []):
                if loc.enabled:
                    wanted.add(getattr(loc, "error_page_template_id", None))
        wanted.discard(None)

        for template in error_templates:
            if template.id not in wanted:
                continue
            try:
                self.files.update(error_pages.rendered_files(template))
            except Exception as exc:
                log.warning(
                    "leaving the error page template %s out of the config: %s",
                    template.name, exc,
                )

    def _render_sites(self, hosts, certs, access_lists, error_templates=None):
        cert_by_id = {c.id: c for c in certs}
        acl_by_id = {a.id: a for a in access_lists}
        # Kept on the renderer as well, because a path's own access list is
        # written several calls down from here and had no way to reach this.
        self.acl_by_id = acl_by_id
        error_by_id = {t.id: t for t in (error_templates or [])}

        for host in hosts:
            if not host.enabled:
                continue
            text = self._render_site(host, cert_by_id, acl_by_id, error_by_id)
            self.files[f"sites/{_safe_name(host.name)}.conf"] = text

    def _error_page_choice(self, obj, error_by_id):
        """
        The error page template one site or one path is really going to get.

        Gives back None rather than raising, always.  A template with a status
        code nginx would not take is one bad row, and letting that throw makes
        the whole render fail, which stops every unrelated change on every node
        until somebody works out which template is to blame.  Falling back to
        nginx's own pages is a page looking plain instead.

        Checking the pages are really in the bundle is not belt and braces
        either.  nginx handles an error_page pointing at a file that is not
        there by falling back and keeping the real status, so it is harmless,
        but writing directives for files nobody rendered means the config and
        the bundle disagree and the next person has to work out which is right.
        """
        template = error_by_id.get(getattr(obj, "error_page_template_id", None))
        if template is None:
            return None

        folder = f"{error_pages.PAGES_DIR}/{error_pages._folder_name(template.name)}"
        try:
            wanted = error_pages.valid_codes(template.code_list())
        except Exception as exc:
            log.warning("no error pages from the template %s: %s", template.name, exc)
            return None

        codes = [c for c in wanted if f"{folder}/{c}.html" in self.files]
        if not codes:
            return None

        return {"template": template, "folder": folder, "codes": codes}

    def _error_page_rules(self, choice, indent=4, extra=None) -> list:
        """
        The error_page lines for one block, newest choice winning per code.

        `extra` is what this block would have inherited.  It is spelled out
        rather than left to nginx because of a rule that catches everybody:
        nginx inherits error_page from the server into a location only when the
        location has no error_page of its own, and one rule in a location throws
        away *all* of them.  So a path with a template covering 404 and 500,
        inside a site whose template also covers 502, would silently serve the
        stock 502 page on that path only.  Writing the full set means what a
        path shows never depends on which codes somebody happened to tick.
        """
        pad = " " * indent
        by_code = {}
        for source in (extra, choice):
            if not source:
                continue
            for code in source["codes"]:
                by_code[code] = source

        if not by_code:
            return []

        names = sorted({s["template"].name for s in by_code.values()})
        lines = [f"{pad}# Custom error pages from: {', '.join(names)}."]
        for code in sorted(by_code):
            source = by_code[code]
            lines.append(
                f"{pad}error_page {code} "
                f"{error_pages.URI_PREFIX}/{_safe_name(source['template'].name)}/{code}.html;"
            )
        return lines

    def _error_page_locations(self, choices) -> list:
        """
        The blocks that actually serve the pages, one per template in use.

        One per template and named after it, because a site can now use more
        than one: its own for most of it and a different one on a path.  They
        would collide on a single shared prefix and the second would never be
        reached.

        internal means the only way in is one of our own error_page lines.
        Without it these are ordinary files anybody can fetch, which would let
        somebody pull the 500 page off a site that is perfectly well.

        ^~ so it beats any regex location the site has.  A site with a regex
        that happens to match this path would otherwise send the error page off
        to a backend.

        Nothing goes in these blocks except reading the file and stepping out
        of the way of the site's own gate.  Each is a leaf that reads one file
        off the disk, so there is no proxying and nothing in here that can see
        the rest of the config.
        """
        lines = []
        for folder, name in sorted({(c["folder"], c["template"].name)
                                    for c in choices if c}):
            lines.append(f"    location ^~ {error_pages.URI_PREFIX}/{_safe_name(name)}/ {{")
            lines.append("        internal;")
            # The site's own gate must not be applied to the page that explains
            # the gate.  Fetching an error page is an internal redirect, and an
            # internal redirect runs the access phase again, so a visitor
            # refused by the allow list was refused a second time on the way to
            # being told why.  nginx will not recurse into an error page, so it
            # gave up and served its own: a site with a template applied showed
            # the stock grey 403 to exactly the people the template was written
            # for.  Same again for a password prompt and its 401.
            #
            # Proved on a real nginx, and the tell is in the log: "access
            # forbidden by rule" twice for one request, the second one for the
            # error page.
            #
            # Safe because of the line above.  internal means the only way in
            # is one of our own error_page rules, so opening this location up
            # exposes nothing: a request straight off the wire for this path
            # gets a 404 whatever these two lines say.  Access directives are
            # inherited only when the location sets none of its own, so naming
            # one here replaces the site's list rather than adding to it.
            lines.append("        allow all;")
            lines.append("        auth_basic off;")
            lines.append(f"        alias {MANAGED_ROOT}/{folder}/;")
            lines.append("        default_type text/html;")
            lines.append("    }")
        if lines:
            lines.append("")
        return lines

    @staticmethod
    def _offload_only(host) -> bool:
        """Is this site in SSL offload only mode?"""
        return bool(getattr(host, "tls_offload_only", False))

    def _offload_cfg(self, cfg, host) -> dict:
        """
        The settings to render with, once offload only mode has had its say.

        Applied everywhere a cfg is finalised rather than once at the top,
        because a path's own settings are merged over the site's and would
        otherwise put back the very thing the mode exists to prevent.  A site
        promising to pass headers through, with one path quietly rewriting
        them, is the failure this mode is meant to make impossible.
        """
        if not self._offload_only(host):
            return cfg
        return {**cfg, **OFFLOAD_ONLY_FORCES}

    def _render_site(self, host, cert_by_id, acl_by_id, error_by_id=None) -> str:
        # Raw mode.  The person is driving, we just write out what they typed.
        # It still goes through nginx -t on every node before it goes live, so
        # "I am driving" does not mean "I can take the fleet down".
        if getattr(host, "config_mode", "gui") == "raw" and host.custom_config:
            return (
                HEADER.format(detail=f"Site {host.name}, in raw config mode.")
                + "\n" + host.custom_config
            )

        cfg = self._offload_cfg(host.setting_map(), host)
        all_names = host.name_list()

        # Picking one name and sending the rest to it.
        #
        # The first name wins, so the direction is set by ordering rather than
        # by a second switch: put example.com first to pull the www in, put
        # www.example.com first to push it out.
        #
        # The names being redirected come out of the main server block
        # entirely.  Leaving them on would mean nginx matching them there
        # first, and the redirect block would never be reached.
        redirecting = bool(getattr(host, "redirect_to_primary", False)) \
            and len(all_names) > 1
        served = all_names[:1] if redirecting else all_names
        moved = all_names[1:] if redirecting else []

        names = " ".join(esc(n) for n in served)
        cert = cert_by_id.get(host.cert_id)
        acl = acl_by_id.get(host.access_list_id)

        # Worked out before anything is written, because both blocks need it.
        usable = cert is not None and getattr(cert, "usable", True)

        # Error pages, for the site and for any path that wants a different one.
        #
        # Both server blocks get them, and they have to, because a site that
        # answers on http as well as https can produce an error on either one.
        # Doing it once here rather than once per block also means the two
        # cannot end up pointing at different pages.
        error_by_id = error_by_id or {}
        site_error = self._error_page_choice(host, error_by_id)
        loc_errors = {}
        for loc in (host.locations or []):
            if not loc.enabled:
                continue
            choice = self._error_page_choice(loc, error_by_id)
            if choice:
                loc_errors[loc.id] = choice

        error_lines = self._error_page_rules(site_error)
        error_lines += self._error_page_locations(
            [site_error] + list(loc_errors.values()))

        # A custom error page in front of a backend does nothing until nginx is
        # told to look at what the backend sent.  error_page only fires on
        # errors nginx produced itself, so on a proxy site the backend's own 404
        # goes straight through and the template somebody just attached is
        # never reached.  Nothing fails, nothing is logged, the config is
        # exactly what they asked for, and it simply does not work.
        #
        # So attaching a template turns interception on.  It is not as blunt as
        # it sounds: nginx only intercepts codes that have an error_page rule,
        # which is the list they ticked and nothing else.  Anybody who does want
        # the backend's own pages can set it off on the site or on one location,
        # and that still wins, because this only fills in a value nobody set.
        if site_error and "proxy_intercept_errors" not in cfg:
            cfg["proxy_intercept_errors"] = True

        lines = [HEADER.format(detail=f"Site: {host.name}")]
        if host.notes:
            for note_line in str(host.notes).splitlines()[:5]:
                lines.append(f"# {note_line}")
            lines.append("")

        # ---- the names being sent somewhere else ----------------------------
        if moved:
            lines.append(self._render_canonical_redirect(
                host, moved, served[0], cert if usable else None, cfg))

        # ---- the plain http server ------------------------------------------
        if host.listen_http:
            lines.append(self._render_http_block(host, names, cfg,
                                                 cert if usable else None,
                                                 acl,
                                                 error_lines=error_lines,
                                                 site_error=site_error,
                                                 loc_errors=loc_errors))

        # ---- the https server -----------------------------------------------
        if host.listen_https and usable:
            lines.append(self._render_https_block(host, names, cfg, cert, acl,
                                                   error_lines=error_lines,
                                                   site_error=site_error,
                                                   loc_errors=loc_errors))
        elif host.listen_https and not cert:
            lines.append(
                f"# No certificate is attached to {host.name} yet, so the https server\n"
                f"# block was left out.  nginx will not start with an ssl listener that\n"
                f"# has no cert, so writing it anyway would take the whole box down."
            )
        elif host.listen_https and cert and not usable:
            reason = ("it has never been issued" if not cert.not_after
                      else "its files are not on this node")
            lines.append(
                f"# The certificate {cert.name} is attached to {host.name} but {reason},\n"
                f"# so the https server block was left out.  Pointing nginx at a\n"
                f"# certificate file that is not there stops it starting at all, which\n"
                f"# would take down every other site on this box as well.\n"
                f"#\n"
                f"# Issue or re-issue it from the Certificates page and apply again."
            )

        return "\n".join(lines)

    def _tls_policy_lines(self, cfg, indent="    ", session_zone="SSL",
                          default_protocols=None) -> list:
        """
        The TLS settings themselves: versions, ciphers, session, key exchange.

        Every server block that terminates TLS needs these, and that includes
        the redirect block, which for a long time did not get them.  It listens
        on 443 with a certificate, so it is a real TLS endpoint, and a version
        list applied only to the site block left the apex name answering on
        whatever the default was.  A scan of the bare name then reports a
        version the site page says is switched off, and the setting looks
        broken when what is broken is its reach.

        Everything here is derived from cfg alone, so every caller gets the same
        answer for the same settings by construction rather than by keeping
        several copies in step.

        `indent` because stream nests a level deeper than http does.

        `session_zone` because nginx keeps one shared memory zone namespace for
        the whole config rather than one per block, the same trap the pool
        zones already work around.  http and stream both asking for `SSL` is
        two different uses of one name, and nginx refuses the whole config
        rather than picking one.

        `default_protocols` for what to write when nothing is set.  http says
        1.3, which is what makes the post quantum exchange the normal case for
        a new site.  A stream cannot say that yet: its settings have never
        carried a version list, so every existing one would read as unset and
        move to 1.3 on the next apply.  On a raw socket that surfaces as a
        client that simply stops connecting, with no status code anywhere to
        say why, so the stream caller keeps today's pair until somebody sets
        one deliberately.
        """
        # Built without the indent and prefixed on the way out, so a blank
        # separator stays genuinely blank rather than becoming a line of
        # trailing spaces.
        out = []

        # 1.3 only, because that is what makes the post quantum key exchange
        # the normal case: X25519MLKEM768 is a 1.3 group, and a client that
        # prefers 1.2 never reaches it.  Existing sites are unaffected, because their
        # versions were written down explicitly before this moved, so this
        # fallback only ever applies to something new.
        proto = list(cfg.get("ssl_protocols")
                     or default_protocols or ["TLSv1.3"])

        # Post quantum only.  This one overrules the version list on purpose,
        # because the two cannot disagree and both be honoured: the quantum
        # resistant exchange only exists in TLS 1.3, so leaving 1.2 switched on
        # would quietly hand any client that asks for it a connection with none
        # of the protection the setting was turned on for.  Better to move the
        # version list and say so in the file than to serve a promise we are not
        # keeping.
        pq_only = bool(
            cfg.get("ssl_post_quantum_only")
            and self.caps and self.caps.supports_post_quantum()
            and self.supports("ssl_post_quantum_only")
        )
        if pq_only:
            proto = ["TLSv1.3"]

        out.append(f"ssl_protocols {' '.join(proto)};")

        # Ciphers are per version and the two lists are not interchangeable.
        # ssl_ciphers is TLS 1.2 and older only, and TLS 1.3 ignores it
        # completely, so writing it into a 1.3 only site is a line that looks
        # like it is doing something and is not.  The 1.3 list is its own
        # directive and has to go through ssl_conf_command.
        legacy = [p for p in proto if p in ("TLSv1", "TLSv1.1", "TLSv1.2")]

        if legacy:
            ciphers = self._catalog_default(cfg, "ssl_ciphers")
            if ciphers:
                out.append(f"ssl_ciphers {ciphers};")
            out.append("ssl_prefer_server_ciphers off;")
        elif cfg.get("ssl_ciphers"):
            out.append("# Cipher list left out.  TLS 1.3 is the only version enabled")
            out.append("# here and it ignores ssl_ciphers, so writing it would only")
            out.append("# look like it was doing something.")

        if "TLSv1.3" in proto:
            suites = self._catalog_default(cfg, "ssl_ciphersuites")
            if suites:
                out.append(f"ssl_conf_command Ciphersuites {esc(suites)};")

        out.append(f"ssl_session_cache shared:{session_zone}:10m;")
        out.append(f"ssl_session_timeout {cfg.get('ssl_session_timeout', '1d')};")
        out.append(
            f"ssl_session_tickets {'on' if cfg.get('ssl_session_tickets') else 'off'};"
        )

        # Post quantum key exchange.  Only offered when the box was built
        # against OpenSSL 3.5 or newer, which the installer does.  On anything
        # older this directive makes nginx refuse to start.
        if pq_only:
            out.append("")
            out.append("# Post quantum only.  One group and no classic fallback, so a")
            out.append("# client that cannot do it does not connect at all.  That is")
            out.append("# the point of the setting, and it is why TLS 1.2 is off above:")
            out.append("# this exchange only exists in 1.3, so leaving 1.2 on would let")
            out.append("# a client opt straight back out of it.")
            out.append(f"ssl_conf_command Groups {PQ_GROUP};")
        elif (cfg.get("ssl_post_quantum", True) and self.caps
                and self.caps.supports_post_quantum()
                and self.supports("ssl_post_quantum")):
            out.append("")
            out.append("# Hybrid post quantum key exchange, from OpenSSL 3.5.  Clients")
            out.append("# that do not know it fall back to a normal curve on their own.")
            out.append(
                f"ssl_conf_command Groups {PQ_GROUP}:{':'.join(CLASSIC_GROUPS)};"
            )

        return [f"{indent}{line}" if line else "" for line in out]

    def _render_canonical_redirect(self, host, moved, primary, cert, cfg=None) -> str:
        """
        A server block whose only job is to send these names to the real one.

        It listens on the same ports as the site, including https, and that
        part matters: a browser asked for https://www.example.com does the TLS
        handshake before it ever sees a redirect, so without a certificate here
        the visitor gets a warning and never reaches the 301.  The certificate
        has to cover the names being moved, which is exactly what the warning
        on the site page is about.

        The challenge location is repeated here on purpose.  These names still
        need to be validated at renewal time, and a redirect on that path means
        renewing a certificate that has already expired becomes impossible: the
        redirect leads to https the validation server will no longer trust.

        301 rather than 302.  This is a decision about which name the site has,
        not a temporary arrangement, and a 302 leaves both names in search
        results forever, which is the thing being fixed.
        """
        names = " ".join(esc(n) for n in moved)
        usable = cert is not None and getattr(cert, "usable", True)

        lines = [f"# {', '.join(moved)} are served from {primary}."]
        lines.append("server {")
        tls_lines = []
        if host.listen_http:
            lines.append(f"    listen {host.http_port or 80};")
            lines.append(f"    listen [::]:{host.http_port or 80};")
        if host.listen_https and usable:
            cert_dir = self._cert_path(cert)
            listen = f"    listen {host.https_port or 443} ssl"
            if host.http2:
                lines.append(listen + ";")
                lines.append(f"    listen [::]:{host.https_port or 443} ssl;")
                lines.append("    http2 on;")
            else:
                lines.append(listen + ";")
                lines.append(f"    listen [::]:{host.https_port or 443} ssl;")
            tls_lines.append(f"    ssl_certificate     {cert_dir}/fullchain.pem;")
            tls_lines.append(f"    ssl_certificate_key {cert_dir}/privkey.pem;")
            # The same TLS settings the site itself gets.  This block terminates
            # TLS in its own right, so a version list left off here is not
            # inherited from the site block next to it: the name answers on
            # whatever the default server offers instead.  That is how a site
            # switched to 1.3 only kept answering 1.2 on its bare name, which is
            # the one name a scanner is most likely to be pointed at.
            tls_lines.extend(self._tls_policy_lines(cfg or {}))
        lines.append(f"    server_name {names};")
        if tls_lines:
            lines.append("")
            lines.extend(tls_lines)
        lines.append("")
        lines.append("    # Still has to answer a challenge, or these names can")
        lines.append("    # never be renewed on the certificate.")
        lines.append("    location ^~ /.well-known/acme-challenge/ {")
        lines.append("        root /var/www/certbot;")
        lines.append('        default_type "text/plain";')
        lines.append("        try_files $uri =404;")
        lines.append("    }")
        lines.append("")
        scheme = "https" if (host.listen_https and usable) else "$scheme"
        # Inside a location, not at the server level, and that is not a style
        # choice.  A `return` written at the server level runs in the rewrite
        # phase, which happens before nginx picks a location, so it beats the
        # challenge block above and every request for a token gets a 301
        # instead.  The certificate covering these names could then never be
        # renewed, which is the exact failure the comment above is about, and
        # writing it the obvious way produced it.
        lines.append("    location / {")
        lines.append(f"        return 301 {scheme}://{primary}$request_uri;")
        lines.append("    }")
        lines.append("}")
        return "\n".join(lines)

    def _render_http_block(self, host, names, cfg, cert=None, acl=None,
                           error_lines=None, site_error=None,
                           loc_errors=None) -> str:
        """
        The plain http server.

        The access list belongs here just as much as it does on the https
        block, and for a long time it was only passed to that one.  A site
        serving over http with an access list on it rendered every rule the
        page showed on 443 and none of them on 80, so the list looked applied
        and the site answered anybody who asked for it without the s.  Worse
        where there is no certificate at all, because then http is the only
        way in and the whole list was doing nothing.
        """
        default = " default_server" if host.default_server else ""
        lines = [
            "server {",
            f"    listen {host.http_port}{default};",
            f"    listen [::]:{host.http_port}{default};",
            f"    server_name {names};",
            "",
        ]

        # The acme challenge always has to work over plain http, even when
        # everything else redirects.  Lets Encrypt does follow redirects to
        # https, but if the cert has expired that redirect leads somewhere the
        # validation server will not trust, and then you cannot renew the very
        # cert you need.  So this location comes first and is never redirected.
        lines.append("    # Certificate validation.  Never redirect this, or renewing a")
        lines.append("    # cert that has already expired becomes impossible.")
        lines.append("    location ^~ /.well-known/acme-challenge/ {")
        lines.append("        root /var/www/certbot;")
        lines.append('        default_type "text/plain";')
        # And never let an access list shut it either.  The rules below apply
        # to the whole server block, so a site allowing one office would
        # otherwise refuse the certificate authority and stop being able to
        # renew.  Same reason the internal error page location says this.
        lines.append("        allow all;")
        lines.append("        try_files $uri =404;")
        lines.append("    }")
        lines.append("")

        # Only redirect to https if there is going to be an https server to
        # land on.  A site set to force https with no certificate attached has
        # no https block at all, because nginx refuses to start with an ssl
        # listener and no certificate.  Redirecting anyway sends every visitor
        # to a port nothing is listening on, and the site is simply down with
        # no error in any log to explain it.
        #
        # Without a certificate we serve over http instead and say so in the
        # config, which is the least surprising thing to do while somebody is
        # still in the middle of setting the site up.
        if host.force_https and host.listen_https and cert:
            # A redirect only block never reaches _render_body, so the rules
            # are written here instead.  An address the site does not accept
            # has no business being told where the site really lives, and it
            # would be refused by the https block a moment later anyway.
            acl_lines = self._access_control(acl, host)
            if acl_lines:
                lines.extend(acl_lines)
                lines.append("")
            lines.append("    location / {")
            lines.append("        return 301 https://$host$request_uri;")
            lines.append("    }")
        else:
            if host.force_https and host.listen_https and not cert:
                lines.append("    # Set to redirect to https, but no certificate is attached yet, so")
                lines.append("    # there is no https server to redirect to.  Serving over http until")
                lines.append("    # one is issued, rather than sending everybody to a dead port.")
                lines.append("")
            lines.extend(self._render_body(host, cfg, tls=False, acl=acl,
                                           error_lines=error_lines,
                                           site_error=site_error,
                                           loc_errors=loc_errors))

        lines.append("}")
        return "\n".join(lines)

    def _catalog_default(self, cfg, key):
        """
        A setting, falling back to what the catalog says the default is.

        Leaving one of these unset does not mean "no preference", it means
        nginx uses its own built in value, which is not the one the page calls
        the default.  So a site nobody touched behaved differently from what
        the GUI said, and the only way to get the advertised behaviour was to
        open the field and save it unchanged.

        Writing the catalog default when nothing is set makes the page honest:
        what it shows is what the file gets.

        It was written for the cipher lists, where the built in list is older
        and looser than the advertised one.  gzip_types is the same trap and
        cost more: nginx compresses only text/html on its own, so every site
        that had never opened the field served its css, javascript, json and
        svg uncompressed while the form listed all eleven types as the default.
        """
        value = cfg.get(key)
        if value:
            return value
        feature = get_feature(key)
        if not feature or not self.supports(key):
            return None
        return feature.default

    def _render_https_block(self, host, names, cfg, cert, acl, error_lines=None,
                            site_error=None, loc_errors=None) -> str:
        default = " default_server" if host.default_server else ""
        http2 = ""
        lines = ["server {"]

        # nginx 1.25.1 moved http2 from a listen parameter to its own directive.
        # Using the old form on a new nginx logs a deprecation warning on every
        # start, and the new form on an old one fails outright.  So we check.
        version = getattr(self.caps, "nginx_version", None) if self.caps else None
        use_new_http2 = _version_at_least(version, (1, 25, 1))

        if host.http2 and not use_new_http2:
            http2 = " http2"

        lines.append(f"    listen {host.https_port} ssl{http2}{default};")
        lines.append(f"    listen [::]:{host.https_port} ssl{http2}{default};")
        if host.http2 and use_new_http2:
            lines.append("    http2 on;")
        lines.extend(self._http3_lines(cfg, host))
        lines.append(f"    server_name {names};")
        lines.append("")

        # ---- certificate ----
        cert_dir = self._cert_path(cert)
        lines.append(f"    ssl_certificate     {cert_dir}/fullchain.pem;")
        lines.append(f"    ssl_certificate_key {cert_dir}/privkey.pem;")

        lines.extend(self._tls_policy_lines(cfg))

        # Staple only when the certificate names a responder to staple from.
        #
        # This used to key off the certificate having come from Lets Encrypt,
        # which was right when they ran an OCSP responder and is now exactly
        # backwards: they have moved to published revocation lists and their
        # certificates name no responder at all.  nginx does not treat that as
        # an error, it just ignores the setting and says so on every reload:
        #
        #   "ssl_stapling" ignored, no OCSP responder URL in the certificate
        #
        # Reading what the certificate actually says keeps this right whoever
        # issued it, and whatever they decide to do next.
        if cfg.get("ssl_stapling", True) and getattr(cert, "ocsp_url", None):
            lines.append("")
            lines.append("    ssl_stapling on;")
            lines.append("    ssl_stapling_verify on;")
            lines.append(f"    ssl_trusted_certificate {cert_dir}/chain.pem;")

        verify = cfg.get("ssl_verify_client", "off")
        if verify and verify != "off":
            lines.append("")
            lines.append(f"    ssl_verify_client {verify};")
            client_ca = cfg.get("ssl_client_certificate")
            if client_ca:
                lines.append(f"    ssl_client_certificate {esc(client_ca)};")
            lines.append(f"    ssl_verify_depth {int(cfg.get('ssl_verify_depth', 2))};")

        lines.append("")
        lines.extend(self._render_body(host, cfg, tls=True, acl=acl,
                                       error_lines=error_lines,
                                       site_error=site_error,
                                       loc_errors=loc_errors))
        lines.append("}")
        return "\n".join(lines)

    def _cert_path(self, cert) -> str:
        """
        Where this cert's files live.  Same answer on every node, on purpose.

        This used to point at /etc/letsencrypt/live on whichever node certbot
        got the cert on, and at our synced folder everywhere else.  That reads
        as correct and cannot work, because the config is rendered once on the
        active node and the exact same bytes are shipped to the rest of the
        fleet.  So every node got the issuing node's path, and any node that did
        not issue the cert failed its test with "cannot load certificate", which
        blocked the apply for the whole fleet.  Every https site hit this, so
        nothing could be applied at all.

        Now every node reads the cert from its own synced folder, including the
        node that issued it, so one rendered config is true everywhere.  Certbot
        still owns /etc/letsencrypt and we still never write into it.  We copy
        out of it, which is what the other nodes were already doing.
        """
        return f"{CERT_SYNC_DIR}/{cert.name}"

    # =========================================================================
    # The shared body of a server block
    # =========================================================================

    def _render_body(self, host, cfg, tls=False, acl=None, error_lines=None,
                     site_error=None, loc_errors=None) -> list:
        lines = []

        # ---- logging ----
        if cfg.get("access_log_enabled", True):
            fmt = {"main": "nfm_main", "detailed": "nfm_detailed", "json": "nfm_json"}.get(
                cfg.get("access_log_format", "main"), "nfm_main"
            )
            lines.append(
                f"    access_log /var/log/nginx/{_safe_name(host.name)}.access.log {fmt};"
            )
        else:
            lines.append("    access_log off;")

        level = cfg.get("error_log_level", "warn")
        lines.append(f"    error_log /var/log/nginx/{_safe_name(host.name)}.error.log {level};")
        lines.append("")

        # ---- limits ----
        for key in ("client_max_body_size", "client_body_buffer_size",
                    "client_body_timeout", "client_header_timeout",
                    "send_timeout", "keepalive_timeout", "keepalive_requests",
                    "large_client_header_buffers"):
            value = cfg.get(key)
            if value not in (None, ""):
                feature = get_feature(key)
                if feature and "server" in feature.contexts:
                    lines.append(f"    {feature.directive} {emit(feature, value)};")

        # Rate and connection limits set on the site itself.
        #
        # These were only ever written inside location blocks, so a site with no
        # explicit locations, which is most of them, silently got no limiting at
        # all.  You set a limit, saved, applied, and nothing happened.
        #
        # limit_req and limit_conn are perfectly valid in a server block, and a
        # limit set on the site should cover the whole site.
        lines.extend(self._limit_lines(cfg, indent=4))

        lines.extend(self._serving_lines(cfg, indent=4))

        # Bandwidth and expiry, which are offered on the site and were only
        # ever written inside a path.
        #
        # A site with no paths, which is most of them, could have a rate limit
        # set and shown on its own page and serve at full speed.  The catalog
        # has always listed these for the server context; only the location
        # renderer wrote them.
        #
        # Found by checks/wiring.py on its first run against a fleet whose
        # first site happens to have no paths, which is exactly the case that
        # hides it.
        for key in ("limit_rate", "limit_rate_after", "expires"):
            value = cfg.get(key)
            if value in (None, ""):
                continue
            feature = get_feature(key)
            if feature:
                lines.append(f"    {feature.directive} {emit(feature, value)};")
        lines.extend(self._cors_lines(cfg, indent=4, name=host.name))
        lines.extend(self._geo_block_lines(cfg, indent=4, name=host.name))
        lines.extend(self._waf_lines(cfg, indent=4, name=host.name))
        lines.extend(self._exploit_lines(cfg, indent=4))
        lines.extend(self._purge_lines(cfg, indent=4))

        # Which resolver nginx uses when it has to look a name up while it is
        # running.  Several arguments, so it goes through the same writer as a
        # rewrite rule: esc would quote the lot into one and nginx would read
        # "1.1.1.1 8.8.8.8 valid=300s" as a single nameserver.
        resolver = (cfg.get("resolver") or "").strip()
        if resolver:
            try:
                lines.append(f"    resolver {directive_args(resolver, 'resolver')};")
            except ValueError as exc:
                log.warning("dropping the resolver setting: %s", exc)
                lines.append(f"    # resolver left out, {exc}")

        # Rewrites and text replacement, both set on the site.
        #
        # A rewrite at this level runs before nginx picks a location, which is
        # what somebody typing one at the site level means by it.
        lines.extend(self._rewrite_lines(cfg, indent=4))
        lines.extend(self._sub_filter_lines(
            cfg, indent=4, proxying=(host.mode == "proxy" and host.pool is not None)))

        if cfg.get("server_tokens") is not None:
            lines.append(f"    server_tokens {'on' if cfg.get('server_tokens') else 'off'};")

        # The Server header itself.
        #
        # server_tokens above only takes the version off, leaving "Server: nginx".
        # Getting rid of it altogether needs headers-more, so this only appears
        # when the module is actually compiled in.
        mode = cfg.get("server_header_mode", "suppress")
        if mode != "default" and self.has_module("headers_more"):
            if mode == "custom" and cfg.get("server_header_value"):
                lines.append(
                    f"    more_set_headers \"Server: {esc(cfg['server_header_value']).strip(chr(34))}\";"
                )
            else:
                lines.append("    more_clear_headers Server;")
        elif mode != "default" and not self.has_module("headers_more"):
            lines.append(
                "    # Cannot remove the Server header: this nginx was built without\n"
                "    # the headers-more module.  server_tokens off above still hides\n"
                "    # the version number."
            )

        lines.append("")

        # ---- security headers ----
        header_lines = self._security_headers(cfg, tls)
        if header_lines:
            lines.extend(header_lines)
            lines.append("")

        # ---- access control ----
        acl_lines = self._access_control(acl, host)
        if acl_lines:
            lines.extend(acl_lines)
            lines.append("")

        # ---- hidden files ----
        if cfg.get("block_dotfiles", True):
            lines.append("    # Block .git, .env and friends.  Scanners hit these constantly")
            lines.append("    # and a leaked .env usually has database passwords in it.")
            lines.append("    location ~ /\\. {")
            lines.append("        deny all;")
            lines.append("        access_log off;")
            lines.append("        log_not_found off;")
            lines.append("    }")
            lines.append("")

        # ---- error pages ----
        # The template first, then anything hand written, because nginx takes
        # the last error_page it reads for a given code.  So a rule somebody
        # typed themselves beats the template, which is the way round people
        # expect: the specific thing you wrote wins over the shared default.
        lines.extend(error_lines or [])

        for rule in cfg.get("error_pages", []) or []:
            lines.append(f"    error_page {rule};")

        # ---- compression ----
        gzip_lines = self._gzip(cfg)
        if gzip_lines:
            lines.extend(gzip_lines)
            lines.append("")

        # ---- the locations ----
        enabled_locations = [loc for loc in sorted(host.locations,
                                                   key=lambda x: x.sort_order)
                             if loc.enabled]
        for loc in enabled_locations:
            lines.extend(self._render_location(
                loc, cfg, host,
                error_choice=(loc_errors or {}).get(loc.id),
                site_error=site_error))
            lines.append("")

        # The site's own mode covers whatever the paths above do not.
        #
        # This used to be an else, so adding a single path to a site threw the
        # site's own behaviour away.  A site set to redirect, with one path on
        # it, rendered no redirect at all and nothing that answered for the
        # root.  nginx then fell back to its own compiled in root and served
        # the "Welcome to nginx" page.
        #
        # Everything about that looks fine on the way past.  The site page says
        # redirect, the config is valid, nginx accepts it and reloads, and the
        # only sign is a visitor getting a page nobody wrote.
        #
        # A prefix location of / already answers for everything, so in that
        # case the site's mode genuinely has nothing left to cover.
        covers_root = any(loc.path == "/" and loc.match_type == "prefix"
                          for loc in enabled_locations)
        if not covers_root:
            lines.extend(self._render_root_behavior(host, cfg))

        # ---- anything hand written ----
        #
        # This goes **inside** the server block, so it has to be a snippet.  A
        # whole file gets refused rather than pasted, because a `server` block
        # nested in a `server` block is config nginx will not load, and an
        # apply is all or nothing: one site like this stops the entire fleet
        # applying anything.  The API clears it when a site leaves raw mode,
        # and this is the second line of defence, for a value that arrived some
        # other way.
        if host.custom_config:
            if re.search(r"(?m)^\s*server\s*\{", host.custom_config):
                lines.append("    # Hand written config left out on purpose: it is a whole")
                lines.append("    # file rather than a snippet, and a server block cannot")
                lines.append("    # go inside a server block.  Switch the site to raw")
                lines.append("    # config mode to use it, or trim it to the directives")
                lines.append("    # that belong in here.")
                log.warning("left out the hand written config on %s: it is a whole "
                            "file rather than a snippet", host.name)
            else:
                lines.append("    # Custom config from the manager")
                for line in host.custom_config.splitlines():
                    lines.append(f"    {line}")

        return lines

    # A short list of things scanners try, in one place so the pattern can be
    # read and argued with rather than being buried in a format string.
    #
    # Deliberately narrow.  Every entry here is something no ordinary request
    # contains, because a pattern that catches real traffic gets turned off
    # after the first complaint and then protects nothing.  The catalog says
    # plainly this is a speed bump and not a firewall, and the entries are the
    # ones its own example names plus the two that everybody scans for.
    #
    # No dollar sign in here, and that is not an oversight.  nginx unescapes
    # \$ inside a quoted string before the regex ever sees it, so a pattern
    # written to match a literal ${jndi: reaches PCRE as ${jndi:, where the
    # dollar is an end of string anchor and the whole branch can never match.
    # It looked right in the config file and let the probe straight through,
    # which a real request found and reading never would.  Matching jndi: on
    # its own catches the same thing and cannot be got wrong.
    EXPLOIT_PATTERN = (
        r"(\.\./|\.\.%2[fF]|<script|%3[cC]script|"
        r"union[[:space:]%+]+select|/etc/passwd|jndi:)"
    )

    def _exploit_lines(self, cfg, indent=4) -> list:
        """The scanner speed bump, when somebody asks for it."""
        if not cfg.get("block_common_exploits"):
            return []
        pad = " " * indent
        return [
            f"{pad}# Obvious attack patterns in the path or the query string.",
            f"{pad}# A speed bump for scanners, not a firewall: it stops the",
            f"{pad}# noisy ones and nobody who is actually trying.  Watch the",
            f"{pad}# logs after turning it on, since an app that puts odd",
            f"{pad}# things in a query string will be caught by it too.",
            f'{pad}if ($request_uri ~* "{self.EXPLOIT_PATTERN}") {{',
            f"{pad}    return 403;",
            f"{pad}}}",
        ]

    def _purge_lines(self, cfg, indent=4) -> list:
        """
        The PURGE endpoint, locked to the management network.

        Only rendered when there is a cache to purge.  proxy_cache_purge names
        a zone, so writing it without one is a config nginx refuses, and the
        setting is on a site that may have no cache at all.

        The allow list is not optional.  A purge anybody can reach is a way to
        push every request through to the backend on demand, which is a denial
        of service with fewer steps than usual.
        """
        if not cfg.get("cache_purge_enabled"):
            return []

        pad = " " * indent
        zone = cfg.get("proxy_cache_zone")
        if not zone:
            return [
                f"{pad}# Cache purging is switched on and this site has no cache",
                f"{pad}# zone, so there is nothing to purge.  Pick a cache on the",
                f"{pad}# site first.",
            ]

        if not self.has_module("ngx_cache_purge"):
            return [
                f"{pad}# Cache purging is switched on and this nginx was built",
                f"{pad}# without the purge module, so it cannot be written.",
            ]

        lines = [
            f"{pad}# Drop one cached page on demand:  curl -X PURGE https://.../path",
            f"{pad}# Management network only, on purpose.",
            f"{pad}location ~ ^/purge(/.*)$ {{",
        ]
        for addr in self.node_addresses:
            lines.append(f"{pad}    allow {addr};")
        for cidr in self.settings.get("management_networks", []):
            lines.append(f"{pad}    allow {cidr};")
        lines.append(f"{pad}    deny all;")
        lines.append(f"{pad}    proxy_cache_purge {_safe_name(zone)} "
                     f"$scheme$host$1;")
        lines.append(f"{pad}}}")
        return lines

    def _http3_lines(self, cfg, host) -> list:
        """
        A QUIC listener for this site, and the header that advertises it.

        HTTP/3 is not something a browser tries first.  It connects over TCP
        like always, and only moves to QUIC because the response told it to
        with an Alt-Svc header.  Write the listener without the header and
        nothing ever uses it, which is the quiet failure worth naming: the
        config is right, the port is open, and every request is still HTTP/2.

        **reuseport goes on exactly one listener in the whole config.**  nginx
        refuses to start with "duplicate listen options" if two server blocks
        both ask for it on the same address and port, so a second site turning
        HTTP/3 on would take the fleet's config down rather than just its own.
        The first QUIC site in a render claims it and the rest do without,
        which is all nginx wants: the option belongs to the socket, not to the
        site.
        """
        if not cfg.get("http3_enabled"):
            return []

        # nginx will not parse a quic listener without the module, so this
        # degrades to a comment rather than failing the apply for every site on
        # the node.
        if not self.has_module("http_v3_module"):
            return [
                "    # HTTP/3 is switched on for this site and this nginx was",
                "    # built without the http_v3 module, so it cannot be written.",
            ]

        port = host.https_port or 443
        first = port not in self._quic_ports
        self._quic_ports.add(port)
        reuseport = " reuseport" if first else ""

        return [
            f"    listen {port} quic{reuseport};",
            f"    listen [::]:{port} quic;",
            "    http3 on;",
            # Without this a browser never tries QUIC at all.  always, so it is
            # sent on error responses too, since a client that only ever sees a
            # 404 should still learn the site speaks HTTP/3.
            f"    add_header Alt-Svc 'h3=\":{port}\"; ma=86400' always;",
        ]

    def _waf_lines(self, cfg, indent=4, name="site") -> list:
        """
        Point this site at the firewall, and write the rules it will read.

        Two lines in the server block and a file beside it.  The file is where
        everything interesting is, because ModSecurity takes its whole
        configuration from rule files rather than from nginx directives.

        Deliberately in the **server** block and not a location.  A location
        that sets modsecurity replaces the server's setting for requests that
        reach it rather than adding to it, which is the same trap this project
        has already met with add_header, with error_page and with a server
        level if.  Setting it per site means every request gets checked, and a
        location that wanted to opt out would have to say so itself.
        """
        mode = (cfg.get("waf_mode") or "off").strip()
        if mode in ("", "off"):
            return []

        pad = " " * indent

        if not self.has_module("modsecurity"):
            return [
                f"{pad}# The firewall is set to {mode} and this nginx was built",
                f"{pad}# without the modsecurity module, so it cannot be written.",
                f"{pad}# Rebuild nginx with the firewall module from the build page.",
            ]

        safe = _safe_name(name)
        rules_path = f"{MANAGED_ROOT}/waf/{safe}.conf"
        self.files[f"waf/{safe}.conf"] = self._waf_rules_file(cfg, mode, safe, name)

        return [
            f"{pad}modsecurity on;",
            f"{pad}modsecurity_rules_file {rules_path};",
        ]

    def _waf_rules_file(self, cfg, mode: str, safe: str, name: str = "") -> str:
        """
        The rule file for one site.

        Order is not a style choice here.  The engine settings come first, then
        the rule set's own defaults, then our overrides, then the rules
        themselves.  Set a variable after the rules have already been included
        and it is read too late to change anything, which fails silently: the
        config tests clean and the setting does nothing.
        """
        # Strictness is a level, or the name of a tuned profile.  A profile
        # runs at level 1 and gets its strictness from the exclusions somebody
        # proved were wrong, which is the whole argument for having them: a
        # tuned level 1 catches more real attacks than an untuned level 3 that
        # somebody switched off after a bad afternoon.
        chosen = (cfg.get("waf_paranoia") or "1").strip()
        paranoia = "1" if chosen.startswith("custom:") else chosen
        if paranoia not in ("1", "2", "3", "4"):
            paranoia = "1"

        # DetectionOnly logs what it would have refused and refuses nothing.
        engine = "DetectionOnly" if mode == "watching" else "On"

        # Block known malicious is a locked preset, so it ignores the site's
        # strictness.  Pinning paranoia to 1 is the whole of what makes "safe
        # to turn on without tuning" true, since 1 is the level CRS keeps
        # deployable.  Somebody who has raised strictness has taken on the
        # tuning that goes with it, and this mode is for the people who have
        # not.
        if mode == "block_known":
            paranoia = "1"

        # The bar a request has to clear before it is refused, and it is CRS's
        # own number rather than one of ours.
        #
        # It was 15 for a day, chosen because it sounded conservative, and the
        # first two real probes showed what that cost: CRS scores critical 5,
        # error 4, warning 3, so 15 means three critical rules, and a
        # libinjection confirmed SQL injection scores exactly 5.  Block known
        # malicious would have waved through the most obvious attack there is
        # while catching a path traversal that scored 30.
        #
        # 5 is what crs-setup ships, which means one critical rule is enough.
        # Every number we invent here is one we have to defend later with
        # nothing behind it, and this setting has already been bitten once by
        # exactly that.
        threshold = "5"

        return "\n".join([
            f"# Written by the fleet manager for {safe}.  Do not edit.",
            f"# Mode: {mode}.  Paranoia level {paranoia}.",
            "",
            f"SecRuleEngine {engine}",
            "SecRequestBodyAccess On",
            "",
            "# Inspect a body up to this size and refuse anything larger rather",
            "# than waving it through unchecked.  A firewall that stops looking",
            "# past a size an attacker chooses is not one.",
            "SecRequestBodyLimit 13107200",
            "SecRequestBodyNoFilesLimit 131072",
            "SecRequestBodyLimitAction Reject",
            "SecPcreMatchLimit 10000",
            "SecPcreMatchLimitRecursion 10000",
            "",
            "# The audit log, which is what the hits page reads.",
            "#",
            "# The parts are chosen to leave request and response bodies out.",
            "# A body is where passwords and card numbers are, and a firewall",
            "# that writes them to a log has created a worse problem than the",
            "# one it was fitted to solve.  A, B, F, H and Z are the headers",
            "# and the outcome, which is what identifying a false positive",
            "# actually needs.",
            "SecAuditEngine RelevantOnly",
            "SecAuditLogParts ABFHZ",
            "SecAuditLogType Serial",
            "SecAuditLogFormat JSON",
            f"SecAuditLog /var/log/nginx/waf-{safe}.log",
            "",
            "# The rule set's own defaults, then ours on top.",
            f"Include {CRS_ROOT}/crs-setup.conf.example",
            "",
            "# Rule ids in the 900000 block are the rule set's own setup range.",
            "# These two are the ones it leaves commented out for exactly this.",
            f'SecAction "id:900000,phase:1,nolog,pass,t:none,'
            f'setvar:tx.blocking_paranoia_level={paranoia}"',
            f'SecAction "id:900110,phase:1,nolog,pass,t:none,'
            f'setvar:tx.inbound_anomaly_score_threshold={threshold},'
            f'setvar:tx.outbound_anomaly_score_threshold=4"',
            "",
            f"Include {CRS_ROOT}/rules/*.conf",
            "",
        ] + self._block_known_lines(mode)
          + self._waf_recorder_lines(name)
          + self._waf_exclusion_lines(cfg)
          + self._waf_surface_lines(cfg))

    # Rules that block known malicious deliberately does not enforce.
    #
    # Every one of these is CRITICAL in the rule set, which scores 5, which is
    # the whole threshold.  So one of them refuses a request on its own.  That
    # is right for a rule that catches an exploit, and wrong for these, because
    # these do not catch exploitation.  They catch a *shape*: a path that looks
    # like a system file, a file extension somebody decided is nobody's
    # business, a dotfile.  Plenty of honest applications are made of exactly
    # those shapes.
    #
    # Measured on real traffic before this list existed, not guessed:
    #
    #   A git hosting site: 282 requests reached the firewall and **282 were
    #   refused**.  278 of them, 98%, tripped nothing but these rules.  It
    #   serves repositories, so it serves .gitignore and files whose extension
    #   is on a restricted list, and the firewall called every one an attack.
    #
    #   A documentation site about nginx: searching its own help for
    #   "/etc/nginx/nginx.conf" was refused, and so was "/var/log/nginx/
    #   error.log".  930120 fired alone and reached the threshold on its own.
    #   A site whose subject is system administration cannot let people ask
    #   about system paths.
    #
    # None of that is the rule set misbehaving.  It is what these rules are
    # for, at a threshold where one of them is enough.  The mistake was ours:
    # this mode is offered as safe to turn on without tuning, and with these
    # in it that claim is false for any site that serves files or talks about
    # servers.
    #
    # So block known malicious now means what its name says.  Injection, cross
    # site scripting, remote code execution, path traversal and file inclusion
    # are all still enforced, which is checked by test rather than asserted
    # here.  These four are left out of this mode only.
    POLICY_RULES = (
        ("920440", "URL file extension is restricted by policy"),
        ("920500", "Attempt to access a backup or working file"),
        ("930120", "OS File Access Attempt"),
        ("930130", "Restricted File Access Attempt"),
    )

    def _block_known_lines(self, mode: str) -> list:
        """The policy rules, turned down to logging, for one mode only."""
        if mode != "block_known":
            return []

        lines = [
            "",
            "# Block known malicious: the rules it deliberately does not run.",
            "#",
            "# Watching still runs the whole set, so a learning round sees",
            "# these firing and anybody who wants them enforced has 'block",
            "# what the rules say' one setting along.  They are only left out",
            "# of the mode that promises to be safe without tuning.",
            "#",
            "# SecRuleRemoveById, after the include, is the same directive the",
            "# tuned exclusions use for a whole site.  Before the include it",
            "# would name rules that do not exist yet, which is not an error",
            "# and does nothing at all.",
        ]
        for rule_id, why in self.POLICY_RULES:
            lines.append(f"# {rule_id}  {why}")
        for rule_id, _why in self.POLICY_RULES:
            lines.append(f"SecRuleRemoveById {rule_id}")
        lines.append("")
        return lines

    def _waf_recorder_lines(self, name: str) -> list:
        """
        Full audit logging, for the tester addresses, while a round is running.

        The log normally holds only transactions where a rule fired, which is
        what tuning a negative model needs and is no use at all for building a
        positive one: it describes the attacks rather than the application.  So
        a recording round switches the audit engine on, for the named addresses
        and nobody else.

        **For nobody else** is the whole safeguard and the reason this is not
        simply left on.  Logging every request to a busy site fills a disk, and
        it writes the paths every visitor asked for into a file, which is a
        privacy problem nobody asked for.  Bodies stay out either way: the
        parts written here are set above and do not include them.

        It goes off on its own when the round ends, because this is rendered
        from the running session rather than from a setting somebody has to
        remember to turn back.
        """
        addresses = self.waf_recording.get(name) or []
        if not addresses:
            return []

        # ipMatch takes a comma separated list and understands CIDR.  Anything
        # with a quote or a space in it would end the directive early, so the
        # list is filtered to what an address can actually look like rather
        # than trusted because it came from our own database.
        safe = [a for a in (str(x).strip() for x in addresses)
                if re.fullmatch(r"[0-9a-fA-F:.]{2,45}(?:/\d{1,3})?", a)]
        if not safe:
            return []

        return [
            "",
            "# Recording the surface for a learning round.",
            "#",
            "# Full audit logging, for the tester addresses only, so the log",
            "# holds what the application is rather than what was attacked.",
            "# This disappears when the round ends.",
            f'SecRule REMOTE_ADDR "@ipMatch {",".join(safe)}" '
            f'"id:19000,phase:1,pass,nolog,ctl:auditEngine=On"',
            "",
        ]

    def _waf_surface_lines(self, cfg) -> list:
        """
        The positive model: this is the application, refuse everything else.

        Written last, after the rule set and after the exclusions, because it
        is a different question from everything above it.  The rules ask
        whether a request looks like an attack.  This asks whether the request
        is part of the application at all, and a request that is not gets no
        further whatever the rules think of it.

        Two modes and the difference matters more than anything else on this
        page.  **report** logs what it would have refused and refuses nothing,
        which is the only safe way to find out how complete the surface is.
        **enforce** refuses.  Going straight to enforce means every page the
        testers did not open returns 403 to real users, and the first anybody
        hears of it is a phone call.

        Every rule matches on REQUEST_FILENAME, which was checked against a
        real ModSecurity rather than assumed: it is the path with the query
        string already off, so /search?q=a and /search?q=b are one entry rather
        than two, and no rule here has to think about query strings at all.
        """
        wanted = (cfg.get("waf_positive") or "off").strip()
        if wanted not in ("report", "enforce"):
            return []

        profile = self._waf_profile(cfg)
        entries = (profile or {}).get("surface") or []
        if not entries:
            # A default deny with nothing allowed refuses the entire site, so
            # this refuses to write itself instead and says why in the config
            # where somebody reading it will find it.
            return [
                "",
                "# A positive model is switched on for this site and the profile",
                "# it points at has no surface in it.  Writing it would refuse",
                "# every request, so it is left out.  Record a round on the",
                "# site's WAF tab and save what it found.",
                "",
            ]

        deny = ('log,auditlog,deny,status:403' if wanted == "enforce"
                else 'log,auditlog,pass')
        verb = ("outside the allowed surface" if wanted == "enforce"
                else "outside the allowed surface, and would have been refused")

        lines = [
            "",
            f"# The allowed surface, {len(entries)} "
            f"{'path' if len(entries) == 1 else 'paths'}, in {wanted} mode.",
            "# Nothing reaches the application unless a rule below allows it.",
            'SecAction "id:20000,phase:2,nolog,pass,setvar:tx.fw_allowed=0"',
            "",
        ]

        rule_id = 20001
        for entry in entries:
            path = str(entry.get("path") or "").strip()
            if not path:
                continue
            methods = [str(m).strip().upper() for m in (entry.get("methods") or [])
                       if re.fullmatch(r"[A-Z]{3,10}", str(m).strip().upper())]

            # A trailing slash is not a different page.  nginx hands back both
            # forms depending on how somebody linked it, and a model that
            # allowed /about and refused /about/ would be reported as broken
            # within the hour.
            path_rx = waf_path_to_regex(path.rstrip("/") or "/") + "/?$"

            if methods:
                method_rx = "^(?:" + "|".join(sorted(set(methods))) + ")$"
                lines.append(f'SecRule REQUEST_FILENAME "@rx {path_rx}" '
                             f'"id:{rule_id},phase:2,chain,nolog,pass"')
                lines.append(f'    SecRule REQUEST_METHOD "@rx {method_rx}" '
                             f'"t:none,setvar:tx.fw_allowed=1"')
            else:
                # No methods means any method, which somebody chose on purpose.
                lines.append(f'SecRule REQUEST_FILENAME "@rx {path_rx}" '
                             f'"id:{rule_id},phase:2,nolog,pass,'
                             f'setvar:tx.fw_allowed=1"')
            rule_id += 1

        lines += [
            "",
            f"SecRule TX:fw_allowed \"@eq 0\" "
            f"\"id:29999,phase:2,{deny},msg:'{verb}',"
            f"logdata:'%{{REQUEST_METHOD}} %{{REQUEST_FILENAME}}'\"",
            "",
        ]
        return lines

    def _waf_exclusion_lines(self, cfg) -> list:
        """
        The site's tuned exclusions, from the profile it is pointed at.

        **Where these go is not a style choice and getting it wrong is
        silent.**  ModSecurity has two ways to switch a rule off and they live
        at opposite ends of the file:

          * `SecRuleRemoveById` is read while the config loads, so the rule has
            to already exist.  It goes *after* the rules are included.  Put it
            before and it is a directive about a rule nobody has defined yet,
            which is not an error, it simply does nothing.
          * `ctl:ruleRemoveById` inside a phase 1 rule happens at request time,
            which is how an exclusion is scoped to one path.

        Both are written here, after the include, which is correct for the
        first and harmless for the second.  A config with either in the wrong
        place tests clean and quietly keeps refusing the traffic somebody
        thought they had allowed, which is the worst outcome this feature has:
        the page says the exclusion is saved and the site still breaks.
        """
        profile = self._waf_profile(cfg)
        if not profile:
            return []

        lines = ["", f"# Exclusions from the profile {profile['name']}.",
                 "# Written by the fleet manager.  Do not edit."]

        # Our own rule ids, well below the 900000 block the rule set uses for
        # its own setup, so nothing here can collide with a CRS rule.
        next_id = 10000

        for item in profile["exclusions"]:
            rule_id = int(item["rule_id"])
            path = (item.get("path") or "").strip()
            why = (item.get("message") or "").replace("\n", " ")[:120]

            if path:
                lines.append(f"# {rule_id} off for {path}: {why}")
                lines.append(
                    f'SecRule REQUEST_URI "{_waf_path_match(path)}" '
                    f'"id:{next_id},phase:1,pass,nolog,'
                    f'ctl:ruleRemoveById={rule_id}"'
                )
                next_id += 1
            else:
                lines.append(f"# {rule_id} off for the whole site: {why}")
                lines.append(f"SecRuleRemoveById {rule_id}")

        lines.append("")
        return lines

    def _waf_profile(self, cfg):
        """
        The profile a site is pointed at, as plain data.

        Read through the same objects everything else here uses, and returned
        as dictionaries so the renderer never holds a row past the session that
        loaded it.  A row read after its session closes is a 500, and this
        project has already met that one.
        """
        chosen = (cfg.get("waf_paranoia") or "").strip()
        if not chosen.startswith("custom:"):
            return None

        name = chosen.split(":", 1)[1]
        for profile in (self.waf_profiles or []):
            if profile["name"] == name:
                return profile
        return None

    def _geo_block_lines(self, cfg, indent=4, name="site") -> list:
        """
        Refusing a list of countries, which takes a database and two blocks.

        The lookup itself lives in the http level file, once, because the
        geoip2 block cannot go in a server.  What is written here is the map
        that turns a country code into a yes or no for this site, and the test.

        Worth knowing what this costs: the database has to be on every node.
        Without it nginx will not start at all, so the apply is refused on the
        node that is missing it and nothing goes live, which is the two phase
        apply doing its job rather than a fleet going dark.
        """
        codes = [str(c).strip().upper() for c in (cfg.get("geoip2_country_block") or [])
                 if str(c).strip()]
        if not codes:
            return []

        if not self.has_module("geoip2"):
            pad = " " * indent
            return [
                f"{pad}# Country blocking is set and this nginx was built without",
                f"{pad}# the geoip2 module, so it cannot be written.",
            ]

        bad = [c for c in codes if not re.fullmatch(r"[A-Z]{2}", c)]
        codes = [c for c in codes if re.fullmatch(r"[A-Z]{2}", c)]
        pad = " " * indent
        lines = []
        for code in bad:
            log.warning("dropping a country code that is not two letters: %r", code)
            lines.append(f"{pad}# {code!r} is not a two letter country code, left out")
        if not codes:
            return lines

        var = f"nfm_geo_{_safe_var(name)}"
        # Keyed on the scope and the country together, not the country alone.
        #
        # A 403 with an error page on it is an internal redirect, and nginx
        # restarts an internal request at the server rewrite phase, which is
        # where this test lives.  So the error page request was tested again,
        # refused again, and nginx, which will not recurse into an error page,
        # gave up and served its own stock 403 instead of the site's template.
        # Somebody with a template applied saw the plain nginx page and nothing
        # in the log to say why.
        #
        # The scope map answers "skip" while nginx is fetching one of our error
        # pages, so the key becomes skipCN, which matches nothing here and
        # leaves the page to be served.  Cheaper than an if, and it cannot be
        # got at from outside: the error locations are internal.
        #
        # volatile, or none of that works.  nginx remembers what a map came out
        # as for the rest of the request, and the whole point here is that the
        # answer has to be different the second time round.
        entries = ["    volatile;", "    default 0;"] + [f"    {code} 1;" for code in codes]
        self._geo_maps.append(
            f"map \"$nfm_geo_scope$nfm_geoip2_country\" ${var} {{\n"
            + "\n".join(entries) + "\n}\n")

        lines.append(f"{pad}# Refused: {', '.join(codes)}.  A VPN defeats this in one")
        lines.append(f"{pad}# click, so it is for cutting scanner noise and meeting a")
        lines.append(f"{pad}# rule about where a site may be served, not for security.")
        lines.append(f"{pad}if (${var}) {{")
        lines.append(f"{pad}    return 403;")
        lines.append(f"{pad}}}")
        return lines

    def _cors_lines(self, cfg, indent=4, name="site") -> list:
        """
        Cross site access, which is five settings and one feature.

        All five have been on the page since the catalog was written and none
        of them has ever put a header anywhere.  Turning it on, listing your
        frontend and applying left the browser refusing the call exactly as
        before, with nothing to say why.

        Three things make this more than an add_header:

        **A list of origins cannot be one header.**  nginx sends a single
        Access-Control-Allow-Origin, so the only honest way to honour a list is
        to look the caller's origin up and answer with it when it is on the
        list, and with nothing when it is not.  That is a map, generated here
        and written to maps/cors.conf, and it is why Vary: Origin goes out with
        it: the answer depends on who asked, and a cache that misses that
        serves one origin's answer to another.

        **The preflight is most of the work.**  A browser sends OPTIONS before
        anything interesting and expects the headers back on that, not on the
        real request.  Sending them only on the real request is the classic way
        to have CORS configured and not working, so OPTIONS is answered here
        with 204 and never reaches the backend.

        The `if` holds nothing but the `return`, which is not tidiness: real
        nginx refuses `add_header` inside an `if` at the server level, with
        "directive is not allowed here", and the headers set above it apply to
        the 204 anyway because they are set in the same block.

        **Credentials and `*` cannot go together**, which the help text says and
        the browser enforces.  It is refused on the way in now, and if a saved
        setting from before still has both, the credentials header is left out
        rather than writing a combination no browser will use.
        """
        if not cfg.get("cors_enabled"):
            return []

        pad = " " * indent
        origins = [str(o).strip() for o in (cfg.get("cors_allow_origin") or ["*"])
                   if str(o).strip()]
        methods = [str(m).strip() for m in (cfg.get("cors_allow_methods")
                                            or ["GET", "POST", "OPTIONS"])]
        headers = [str(h).strip() for h in (cfg.get("cors_allow_headers")
                                            or ["Authorization", "Content-Type"])]
        credentials = bool(cfg.get("cors_allow_credentials"))

        if not origins:
            origins = ["*"]

        # OPTIONS has to be allowed or the preflight the browser sends is not
        # on the list it is being told about, which reads as a server that
        # cannot make up its mind.
        if "OPTIONS" not in [m.upper() for m in methods]:
            methods = methods + ["OPTIONS"]

        lines = []
        wildcard = origins == ["*"]

        if wildcard and credentials:
            credentials = False
            log.warning("cors: %s allows any origin and credentials, which no "
                        "browser will use, so credentials are left out", name)
            lines.append(f"{pad}# Credentials are left out here: they were set "
                         f"along with an allowed")
            lines.append(f"{pad}# origin of *, and browsers refuse that pair on "
                         f"purpose.  List the")
            lines.append(f"{pad}# real origins to use credentials.")

        if wildcard:
            origin_value = '"*"'
        else:
            var = f"nfm_cors_{_safe_var(name)}"
            entries = [f'    default "";']
            for origin in origins:
                entries.append(f"    {map_value(origin)} $http_origin;")
            self._cors_maps.append(
                f"map $http_origin ${var} {{\n" + "\n".join(entries) + "\n}\n")
            origin_value = f"${var}"

        header_lines = [
            f"{pad}add_header Access-Control-Allow-Origin {origin_value} always;",
            f"{pad}add_header Access-Control-Allow-Methods "
            f"{esc_header_value(', '.join(methods))} always;",
            f"{pad}add_header Access-Control-Allow-Headers "
            f"{esc_header_value(', '.join(headers))} always;",
        ]
        if credentials:
            header_lines.append(
                f'{pad}add_header Access-Control-Allow-Credentials "true" always;')
        if not wildcard:
            header_lines.append(f"{pad}add_header Vary Origin always;")

        # Only the preflight uses this one.  A browser ignores it on an
        # ordinary response, and putting it here rather than inside the block
        # below is what keeps that block to a single return.
        header_lines.append(f"{pad}add_header Access-Control-Max-Age 86400 always;")
        lines.extend(header_lines)

        # The preflight, answered here rather than at the backend.
        inner = " " * (indent + 4)
        lines.append(f"{pad}if ($request_method = OPTIONS) {{")
        lines.append(f"{inner}return 204;")
        lines.append(f"{pad}}}")
        return lines

    def _serving_lines(self, cfg, indent=4) -> list:
        """
        The three switches about how files are served, wherever they are set.

        All present in the catalog for years and none of them ever written, so
        turning any of them on did nothing at all.  They are one line each,
        except the file cache, which is three: nginx has no `open_file_cache
        on`, it wants a size, and the two that go with it are what make the
        cache safe to have.
        """
        pad = " " * indent
        lines = []

        if cfg.get("sendfile") is not None:
            lines.append(f"{pad}sendfile {'on' if cfg.get('sendfile') else 'off'};")

        if cfg.get("log_not_found") is not None:
            lines.append(
                f"{pad}log_not_found {'on' if cfg.get('log_not_found') else 'off'};")

        if cfg.get("open_file_cache") is not None:
            if cfg.get("open_file_cache"):
                # The numbers the catalog's own example gives, since the setting
                # is a switch and nginx wants a size.  Short validity on
                # purpose: the trap with this cache is a deploy that puts new
                # files down while nginx keeps serving the old ones.
                lines.append(f"{pad}open_file_cache max=10000 inactive=20s;")
                lines.append(f"{pad}open_file_cache_valid 30s;")
                lines.append(f"{pad}open_file_cache_min_uses 2;")
                lines.append(f"{pad}open_file_cache_errors on;")
            else:
                lines.append(f"{pad}open_file_cache off;")

        return lines

    def _rewrite_lines(self, cfg, indent=4) -> list:
        """
        The rewrite rules somebody typed, written out.

        A rule that is wrong is left out with a comment naming it, rather than
        raising.  A raise here stops the whole render, which stops every
        unrelated change on every node until somebody works out which rule on
        which site is to blame: the same failure the Content-Security-Policy
        setting and the first real map both caused.
        """
        pad = " " * indent
        rules = cfg.get("rewrite_rules") or []
        if not rules:
            return []

        lines = []

        # Step around the certificate challenge, at server level only.
        #
        # nginx runs server level rewrites in the rewrite phase, which is
        # before it picks a location.  So a rule like ^/(.*)$ /app/$1 rewrites
        # /.well-known/acme-challenge/TOKEN into /app/.well-known/... and the
        # ^~ location that serves the challenge never matches it any more.  The
        # request then falls through to whatever else is there, which on a site
        # blocking dotfiles is a 403.
        #
        # That is a very expensive way to find out.  Issuing a certificate
        # fails with "Invalid response ... 403" and nothing in the site looks
        # wrong, and worse, a site that already has a certificate keeps working
        # until it silently fails to renew sixty days later, unattended, at
        # whatever hour the timer runs.
        #
        # break here stops the rewrite module for this request only, so the
        # rules below never see the challenge and everything else is untouched.
        if indent == 4:
            lines.append(f"{pad}# Keep the certificate challenge out of the rewrites below.")
            lines.append(f"{pad}if ($request_uri ~ ^/\\.well-known/acme-challenge/) {{")
            lines.append(f"{pad}    break;")
            lines.append(f"{pad}}}")

            # And keep our own error pages out of them, for the same reason in
            # a different disguise.
            #
            # Serving an error page is an internal redirect, and nginx restarts
            # an internal redirect at the server rewrite phase, so the rules
            # below run a second time on the page meant to explain the first
            # error.  A rule like ^/(.*)$ /app/$1 turns /__nfm_error/x/404.html
            # into /app/__nfm_error/x/404.html, the internal location that
            # serves the page stops matching, and nginx, which will not recurse
            # into an error page, gives up and serves its own stock page.
            #
            # Same defect the country test had, and it reads the same way from
            # the outside: the template is applied, the config looks right, and
            # the visitor gets the plain nginx page with nothing in the log
            # naming the rewrite that did it.
            #
            # $uri, not $request_uri.  During an internal redirect $request_uri
            # still holds what the client asked for, so a $request_uri test
            # never sees the error page path at all and this guard would do
            # nothing.  That is the whole reason it is written differently from
            # the challenge guard above.
            lines.append(f"{pad}# Same for our own error pages, which arrive here "
                         "as an internal redirect.")
            lines.append(f"{pad}if ($uri ~ ^{error_pages.URI_PREFIX}/) {{")
            lines.append(f"{pad}    break;")
            lines.append(f"{pad}}}")

        for rule in rules:
            try:
                lines.append(f"{pad}rewrite {directive_args(rule, 'rewrite rule')};")
            except ValueError as exc:
                log.warning("dropping a rewrite rule: %s", exc)
                lines.append(f"{pad}# rewrite rule left out, {exc}")
        return lines

    def _sub_filter_lines(self, cfg, indent=4, proxying=False) -> list:
        """
        Text replacement on the way out, and the two things that make it work.

        `sub_filter` on its own replaces the first match in a text/html response
        and nothing else, which is not what anybody means by find and replace,
        so `sub_filter_once off` goes with it.

        The one that actually decides whether this works at all is
        Accept-Encoding.  A backend that gzips its answer, which most do, sends
        bytes nginx cannot search, and the filter quietly does nothing: the
        setting is on, the config is valid, and the page comes through
        unchanged.  So when the traffic is proxied we ask the backend for plain
        text.  It costs bandwidth between here and the backend and it is the
        only way the feature is honest.
        """
        pad = " " * indent
        rules = cfg.get("sub_filter_rules") or []
        if not rules:
            return []

        # The module has to be in the build.  It is in ours, but a fleet is
        # entitled to an nginx without it, and writing sub_filter there is a
        # config that will not load: every site down, because of one setting on
        # one of them.  Saying so in the file beats that by a mile.
        if not self.has_module("http_sub_module"):
            log.warning("sub_filter rules set but this nginx has no sub module")
            return [f"{pad}# Text replacement is set on this site, and this "
                    f"nginx was built without",
                    f"{pad}# the sub module, so it cannot be written."]

        lines = []
        for rule in rules:
            try:
                lines.append(f"{pad}sub_filter {directive_args(rule, 'replacement rule')};")
            except ValueError as exc:
                log.warning("dropping a sub_filter rule: %s", exc)
                lines.append(f"{pad}# replacement rule left out, {exc}")

        if not any(ln.strip().startswith("sub_filter ") for ln in lines):
            return lines            # nothing usable, so nothing to set up for

        lines.append(f"{pad}sub_filter_once off;")
        if proxying:
            lines.append(f"{pad}# Ask the backend not to compress, or there is")
            lines.append(f"{pad}# nothing readable here to replace.")
            lines.append(f'{pad}proxy_set_header Accept-Encoding "";')
        return lines

    # The attributes a page uses to point at itself.  Only these three, because
    # these are the ones a site writes from the root, and each extra rule costs
    # a pass over every byte of HTML that goes out.
    #
    # Deliberately not `url(`, which needs `sub_filter_types` widened to reach a
    # stylesheet and comes in three quoting styles.  A site that needs it can say
    # so in Response text replacement on the path, which is a field now.
    MOUNT_ATTRIBUTES = ("href", "src", "action")

    def _mount_settings(self, loc_only, mount_prefix) -> dict:
        """
        The rewrite rules a mounted site needs, added to whatever it already has.

        A site mounted under /shop still writes `href="/basket/"`, and under the
        mount that resolves against the hosting site, misses this location and is
        answered by whatever owns its root.  So the page comes through unstyled
        and every link walks off the mount, which reads as the mount being broken
        rather than as the links being absolute.

        The prefix is the path, so there is nothing to ask anybody.

        These go in front of any hand written rule, because a rule somebody wrote
        for this path is the more specific statement and should see the result of
        the general ones.  Note that nginx's sub module replaces in a single pass
        rather than cascading, so a rule cannot re-match what an earlier rule
        produced, and a prefix cannot be added twice.

        That single pass is also the limit of this: a backend that already knows
        it lives under the prefix writes `href="/shop/basket/"` itself, and these
        rules would make it `/shop/shop/basket/`.  Such a backend does not want a
        mount, it wants the plain proxy, which is what the checkbox says.
        """
        out = dict(loc_only)
        existing = list(out.get("sub_filter_rules") or [])
        generated = [f"""'{attr}="/' '{attr}="{mount_prefix}'"""
                     for attr in self.MOUNT_ATTRIBUTES]
        out["sub_filter_rules"] = generated + [r for r in existing
                                               if r not in generated]

        # The cookie half, which the links and the redirects do not cover.
        #
        # A backend at its own root sets `Path=/` or `Path=/app`, and a browser
        # then sends that cookie only for that path on the hosting site.  The
        # application is at /shop/app, so the cookie never comes back and the
        # first thing that breaks is signing in: the login works, the next
        # request arrives with no session, and it looks like the application is
        # broken rather than the mount.
        #
        # Only when nobody has set one by hand.  A rule somebody wrote for this
        # path is the more specific statement, the same rule the sub_filter and
        # redirect halves already follow.
        if not (out.get("proxy_cookie_path") or "").strip():
            out["proxy_cookie_path"] = f"/ {mount_prefix}"
        return out

    def _mount_redirect_lines(self, mount_prefix, already_set=False,
                              indent=8) -> list:
        """
        Put the prefix back on a redirect the backend built without it.

        A backend answers a URL missing its trailing slash with a redirect, and
        it builds that from the Host header, which carries no prefix.  So asking
        for /shop/basket gets `Location: http://www.example.com/basket/` and the
        visitor leaves the mount on the first such URL and does not come back.

        Both schemes, because which one the backend names depends on whether it
        has been told there is TLS in front of it, and being wrong here is
        invisible until somebody types a URL without the slash.

        nginx takes the first proxy_redirect that matches, so a rule set by hand
        on this path is written before these and keeps winning.
        """
        pad = " " * indent
        if already_set:
            lines = [f"{pad}# Redirect rewriting is set on this path, and it is",
                     f"{pad}# written above, so it is tried before these."]
        else:
            lines = []
        lines.append(f"{pad}# The backend builds redirects from the Host header,")
        lines.append(f"{pad}# which carries no prefix.  Put it back on.")
        for scheme in ("http", "https"):
            lines.append(f"{pad}proxy_redirect {scheme}://$host/ {mount_prefix};")

        # And the other shape, which is just as common and was missed.  Plenty
        # of applications answer with `Location: /basket/` rather than a full
        # URL, and RFC 7231 has allowed that since 2014.  That one does not
        # start with a scheme, so neither rule above touches it, and the
        # visitor is sent to /basket/ on the hosting site: straight out of the
        # mount on the first redirect.
        #
        # A regular expression rather than `proxy_redirect / {mount_prefix}`,
        # because a plain prefix would also catch a protocol relative
        # `//other.example.net/x` and turn it into a path on this site.  The
        # (?!/) refuses that one and leaves it alone.
        lines.append(f"{pad}# Some backends answer with a path rather than a full")
        lines.append(f"{pad}# URL.  Same problem, and it needs its own rule.")
        lines.append(f"{pad}proxy_redirect ~^/(?!/)(.*)$ {mount_prefix}$1;")
        return lines

    def _limit_lines(self, cfg, indent=4) -> list:
        """
        The limit_req and limit_conn lines for whatever level we are at.

        Shared between the server block and each location, because the settings
        are the same in both and writing them twice invites them to drift.
        """
        pad = " " * indent
        lines = []

        zone = cfg.get("limit_req_zone_name")
        if zone:
            burst = int(cfg.get("limit_req_burst", 0) or 0)
            parts = [f"limit_req zone={_safe_name(zone)}"]
            if burst:
                parts.append(f"burst={burst}")
            if cfg.get("limit_req_nodelay", True):
                parts.append("nodelay")
            lines.append(pad + " ".join(parts) + ";")

            status = cfg.get("limit_req_status")
            if status:
                lines.append(f"{pad}limit_req_status {int(status)};")

        conn_zone = cfg.get("limit_conn_zone_name")
        if conn_zone:
            count = int(cfg.get("limit_conn_count", 10) or 10)
            lines.append(f"{pad}limit_conn {_safe_name(conn_zone)} {count};")
            status = cfg.get("limit_conn_status")
            if status:
                lines.append(f"{pad}limit_conn_status {int(status)};")

        return lines

    def _security_headers(self, cfg, tls) -> list:
        lines = []
        add = []

        if tls and cfg.get("hsts_enabled", True):
            age = int(cfg.get("hsts_max_age", 31536000))
            value = f"max-age={age}"
            if cfg.get("hsts_include_subdomains"):
                value += "; includeSubDomains"
            add.append(("Strict-Transport-Security", value))

        # These two fall back to nothing, and the catalog default is written
        # into the settings blob when a site is created instead.
        #
        # They are dropdowns whose "do not send the header" option is the empty
        # string, and the GUI does not send an empty value: it treats it as the
        # setting having been cleared and leaves the key out.  With a default
        # here, leaving the key out meant SAMEORIGIN, so choosing not to send
        # the header stored nothing, rendered the default, and the header came
        # back on the next apply.  There was no way to turn either of them off
        # at all, and nothing said so.
        #
        # An absent key now means what the person asked for.  Sites that
        # predate this got the value they were already serving written down by
        # pin_existing_security_headers, so nothing they serve changes.
        xfo = cfg.get("x_frame_options", "")
        if xfo:
            add.append(("X-Frame-Options", xfo))

        if cfg.get("x_content_type_options", True):
            add.append(("X-Content-Type-Options", "nosniff"))

        ref = cfg.get("referrer_policy", "")
        if ref:
            add.append(("Referrer-Policy", ref))

        csp = cfg.get("content_security_policy")
        if csp:
            name = "Content-Security-Policy-Report-Only" if cfg.get("csp_report_only") \
                else "Content-Security-Policy"
            add.append((name, csp))

        perms = cfg.get("permissions_policy")
        if perms:
            add.append(("Permissions-Policy", perms))

        for raw in cfg.get("custom_response_headers", []) or []:
            name, _, value = str(raw).partition(" ")
            if name and value:
                add.append((name.strip(), value.strip()))

        if add:
            # Drop the backend's copy of anything we are about to set.
            #
            # add_header appends, it does not replace.  Proxy to a backend that
            # already sets these and the browser gets two of each, and two of
            # these do not agree: a backend saying X-Frame-Options DENY next to
            # our SAMEORIGIN.  Browsers do not settle that the same way, and
            # several treat a contradictory pair as no answer at all, so a
            # header we added to harden the site ends up removing the
            # protection the backend already had.
            #
            # Hiding first means exactly one of each goes out and it is the one
            # configured here.  That is the trade: this page decides, so a
            # backend asking for something stricter gets overruled.  It is the
            # only version that is predictable, since the alternative is a
            # header whose value depends on what the backend happened to send,
            # and the setting is right here for anybody who wants DENY.
            lines.append("    # The backend may set these too, and add_header appends rather")
            lines.append("    # than replaces, so we drop its copy first.  Two of these that")
            lines.append("    # disagree is worse than either one on its own.")
            for name, _value in add:
                lines.append(f"    proxy_hide_header {name};")
            lines.append("")

            lines.append("    # Security headers.  The 'always' on the end matters: without it")
            lines.append("    # these are left off error responses, which is exactly when a")
            lines.append("    # browser is most likely to do something you did not intend.")
            for name, value in add:
                lines.append(f"    add_header {name} {esc_header_value(value)} always;")

        return lines

    def _access_control(self, acl, host) -> list:
        lines = []

        # The management allow list.  This is the bit that makes sure the boxes
        # you manage from never get locked out by a rule meant for the public.
        # It is generated from the cluster roster, so adding a node later lands
        # here on its own without anybody remembering to update a list.
        if host.admin_only or (acl and acl.include_management):
            lines.append("    # Cluster nodes and the management network.  Generated from the")
            lines.append("    # node roster, so a new node lands here on its own.")
            for addr in self.node_addresses:
                lines.append(f"    allow {addr};")
            for cidr in self.settings.get("management_networks", []):
                lines.append(f"    allow {cidr};")

        if host.admin_only:
            lines.append("    # This site is set to management access only.")
            lines.append("    deny all;")
            return lines

        if not acl:
            return lines

        if acl.use_real_ip:
            lines.append("")
            lines.append("    # Trust the forwarded address, but only from these proxies.")
            lines.append("    # Listing the proxies is not optional.  Without it anybody can")
            lines.append("    # send the header themselves and claim to be any address at all,")
            lines.append("    # which would walk straight through the rules below.")
            for proxy in acl.trusted_proxies():
                lines.append(f"    set_real_ip_from {proxy};")
            lines.append(f"    real_ip_header {acl.real_ip_header};")
            lines.append("    real_ip_recursive on;")
            lines.append("")

        for cidr in acl.allows():
            lines.append(f"    allow {cidr};")
        for cidr in acl.denies():
            lines.append(f"    deny {cidr};")

        if acl.default_action == "deny" and (acl.allows() or self.node_addresses):
            lines.append("    deny all;")

        if acl.basic_auth_enabled:
            if acl.auth_users():
                lines.append("")
                lines.append(f"    auth_basic {esc(acl.basic_auth_realm)};")
                lines.append(
                    f"    auth_basic_user_file {MANAGED_ROOT}/auth/"
                    f"{_safe_name(acl.name)}.htpasswd;"
                )
            else:
                lines.append("")
                lines.append("    # Basic auth is turned on for this access list but it has no")
                lines.append("    # users in it.  Left out rather than written, because nginx")
                lines.append("    # would then reject every request for want of a valid user and")
                lines.append("    # the site would be completely unreachable.")

        return lines

    def _gzip(self, cfg) -> list:
        if not cfg.get("gzip", True):
            return ["    gzip off;"]

        lines = [
            "    gzip on;",
            f"    gzip_comp_level {int(cfg.get('gzip_comp_level', 5))};",
            f"    gzip_min_length {esc(cfg.get('gzip_min_length', '1024'))};",
            f"    gzip_vary {'on' if cfg.get('gzip_vary', True) else 'off'};",
        ]

        # The one people get caught by.  On a proxy site every response came
        # from a backend, and the default for this is off, so gzip appears to do
        # nothing at all until you set it.
        proxied = cfg.get("gzip_proxied", "any")
        lines.append(f"    gzip_proxied {proxied};")

        # Not cfg.get on its own.  nginx's own default is text/html and
        # nothing else, so leaving this alone meant css, javascript, json and
        # svg went out uncompressed on every site, while the form showed a list
        # of eleven types and called it the default.  Every other directive in
        # this block already falls back to the catalog; this one did not.
        types = cfg.get("gzip_types") or self._catalog_default(cfg, "gzip_types")
        if types:
            lines.append(f"    gzip_types {' '.join(types)};")

        if cfg.get("gzip_static") and self.has_module("http_gzip_static_module"):
            lines.append("    gzip_static on;")

        return lines

    def _render_root_behavior(self, host, cfg) -> list:
        """A site with no separate locations, so one behavior for everything."""
        lines = ["    location / {"]

        if host.mode == "proxy" and host.pool:
            lines.extend(self._proxy_lines(host.pool, cfg, indent=8,
                                           offload_only=self._offload_only(host)))
        elif host.mode == "static":
            root = host.document_root or "/var/www/html"
            lines.append(f"        root {esc(root)};")
            lines.append(f"        index {cfg.get('index_files', 'index.html index.htm')};")
            try_files = cfg.get("try_files")
            if try_files:
                lines.append(f"        try_files {try_files};")
            else:
                lines.append("        try_files $uri $uri/ =404;")
        elif host.mode == "redirect":
            target = host.redirect_target or "/"
            code = host.redirect_code or 301
            lines.append(f"        return {code} {esc(target)}$request_uri;")
        else:
            lines.append("        return 404;")

        lines.append("    }")
        return lines

    def _render_location(self, loc, host_cfg, host, error_choice=None,
                         site_error=None) -> list:
        cfg = self._offload_cfg({**host_cfg, **loc.setting_map()}, host)

        prefix = {
            "exact": "= ",
            "prefix": "",
            "preferential": "^~ ",
            "regex": "~ ",
            "regex_i": "~* ",
        }.get(loc.match_type, "")

        # Taking the prefix off only works if the location ends in a slash.
        #
        # nginx swaps the matched part of the path for the one on proxy_pass.
        # With `location /lb` and `proxy_pass http://x/`, the request /lb/login
        # matches /lb, the rest is /login, and it goes on as //login with two
        # slashes, which backends answer 404 to.  With `location /lb/` the rest
        # is login and it goes on as /login, which is the point.
        #
        # So the slash is added here rather than asked of whoever typed the
        # path.  That leaves the bare /lb matching nothing, so it gets the one
        # line redirect anybody would write by hand.  Both halves are needed
        # and forgetting the second is why the bare path 404s while every link
        # under it works.
        #
        # Mounting a whole site is strip_prefix plus the repairs that go with it,
        # so it turns the strip on rather than being a second way to ask for it.
        # Offload only mode turns a mount off, because a mount is nothing but
        # rewriting: the links in the HTML, the cookie paths and the redirects.
        # Honoured here rather than by refusing to save the checkbox, so that
        # taking the mode off gives the mount back exactly as it was.
        mount = (bool(getattr(loc, "mount_site", False))
                 and (loc.path or "").strip("/") != ""
                 and not self._offload_only(host))
        strip = bool(getattr(loc, "strip_prefix", False)) or mount

        # The trailing slash is optional for a plain strip and it is not optional
        # for a mount, so a mount gets it on `preferential` too.  Without it the
        # doubled slash goes upstream on every request, and whether that works at
        # all is up to the backend: Apache tolerates it, plenty of things do not.
        # Widening the guard is safe because a mount is new, so there is no
        # existing config whose rendering this changes.
        slashable = loc.match_type == "prefix" or (mount and loc.match_type == "preferential")

        path = loc.path
        lines = []
        if strip and slashable and not path.endswith("/"):
            lines.append(f"    location = {path} {{")
            lines.append(f"        return 301 {path}/;")
            lines.append("    }")
            lines.append("")
            path = path + "/"

        lines.append(f"    location {prefix}{path} {{")

        # Who may reach this path, if it has a list of its own.
        #
        # This was stored, offered in the API and never written.  A path could
        # be given an access list, the page would show it set, the config would
        # test clean, and every address on earth could still reach it.  For an
        # admin login behind an allow list that is the worst possible shape of
        # bug: it looks locked and is open.
        #
        # nginx does not inherit allow and deny into a location that has any of
        # its own, so a path list replaces the site's rather than adding to it.
        # The management allow list is written again here for that reason,
        # which _access_control already does, or the people running this would
        # lock themselves out of the very path they were protecting.
        if getattr(loc, "access_list_id", None):
            loc_acl = (self.acl_by_id or {}).get(loc.access_list_id)
            if loc_acl is not None:
                for line in self._access_control(loc_acl, host):
                    # _access_control writes at server indent; a location is one
                    # level deeper.
                    lines.append("    " + line if line.strip() else line)

        # This path's own error pages, if somebody gave it different ones.
        #
        # The site's rules are written in again underneath, for any code this
        # path's template does not cover.  nginx inherits error_page from the
        # server only when the location has none of its own, and a single rule
        # here throws away every inherited one, so without that a path with a
        # template covering 404 would silently serve the stock 502 page while
        # the rest of the site served a proper one.
        loc_only = loc.setting_map()

        # A mount's own rewrite rules go in here, next to any the person wrote,
        # so `_sub_filter_lines` renders the lot in one place and writes
        # `sub_filter_once off` and the Accept-Encoding line exactly once.  Doing
        # it any other way means either duplicating those two or forgetting them,
        # and forgetting them is the failure that leaves the config valid and the
        # filter doing nothing.
        if mount:
            mount_prefix = path if path.endswith("/") else path + "/"
            loc_only = self._mount_settings(loc_only, mount_prefix)
            # And into cfg, which is what the proxy half of the render reads.
            # The cookie rule is written by _proxy_lines from cfg, so putting it
            # only in loc_only left it out of the file entirely and the mount
            # shipped without it.
            cfg = {**cfg, **{k: v for k, v in loc_only.items()
                             if k == "proxy_cookie_path"}}

        if error_choice:
            lines.extend(self._error_page_rules(
                error_choice, indent=8, extra=site_error))

            # Same reasoning as on the site, one level down.  A template on a
            # path is a more specific statement than a switch on the whole
            # site, so it turns interception on for this path even if the site
            # turned it off, and only something set on this path itself wins.
            if "proxy_intercept_errors" not in loc_only:
                cfg["proxy_intercept_errors"] = True

        # Per location limits
        for key in ("client_max_body_size", "client_body_timeout",
                    "limit_rate", "limit_rate_after", "expires"):
            value = cfg.get(key)
            if value not in (None, ""):
                feature = get_feature(key)
                if feature:
                    lines.append(f"        {feature.directive} {emit(feature, value)};")

        # Limits for this path.  A location only needs its own if it differs
        # from the site, since nginx inherits the server block's otherwise.
        if loc_only.get("limit_req_zone_name") or loc_only.get("limit_conn_zone_name"):
            lines.extend(self._limit_lines(cfg, indent=8))

        lines.extend(self._serving_lines(loc_only, indent=8))

        # Cross site access is not written per path, and the reason is nginx
        # rather than laziness.  add_header is not inherited into a block that
        # has any of its own, so a path with CORS headers silently loses the
        # site's security headers, HSTS included: watched it happen, the path
        # answered with its CORS headers and no X-Frame-Options.  And the
        # preflight cannot work there anyway, because the site's `if` returns
        # in the rewrite phase, before nginx has picked a location at all.
        #
        # So the setting is offered on the site only, and the catalog says so.
        if loc_only.get("cors_enabled"):
            log.warning("cors on path %s of %s is set on the site instead",
                        loc.path, host.name)
            lines.append("        # Cross site access is set for the whole "
                         "site rather than per path.")

        # Only this path's own rules.  Everything else in cfg is inherited from
        # the site, and nginx already inherits those into the location on its
        # own: writing them again here would run each rule twice.
        lines.extend(self._rewrite_lines(loc_only, indent=8))
        lines.extend(self._sub_filter_lines(
            loc_only, indent=8, proxying=(loc.mode == "proxy" and loc.pool is not None)))

        if loc.mode == "proxy" and loc.pool:
            # `strip`, not the column, or a mount would get the location's
            # trailing slash and not the one on proxy_pass that does the work.
            lines.extend(self._proxy_lines(
                loc.pool, cfg, indent=8, strip_prefix=strip,
                regex_location=loc.match_type in ("regex", "regex_i"),
                offload_only=self._offload_only(host)))
            if mount:
                lines.extend(self._mount_redirect_lines(
                    path if path.endswith("/") else path + "/",
                    already_set=bool((cfg.get("proxy_redirect") or "").strip()),
                    indent=8))
        elif loc.mode == "static":
            if loc.alias:
                lines.append(f"        alias {esc(loc.alias)};")
            else:
                lines.append(f"        root {esc(loc.document_root or '/var/www/html')};")
            try_files = cfg.get("try_files")
            if try_files:
                lines.append(f"        try_files {try_files};")
            if cfg.get("autoindex"):
                lines.append("        autoindex on;")
                lines.append("        autoindex_exact_size off;")
                lines.append("        autoindex_localtime on;")
            if cfg.get("fancyindex") and self.has_module("fancyindex"):
                lines.append("        fancyindex on;")
                lines.append("        fancyindex_exact_size off;")
        elif loc.mode == "redirect":
            lines.append(f"        return {loc.redirect_code or 301} {esc(loc.redirect_target or '/')};")
        elif loc.mode == "deny":
            lines.append("        deny all;")

        if loc.custom_config:
            for line in loc.custom_config.splitlines():
                lines.append(f"        {line}")

        lines.append("    }")
        return lines

    def _empty_pool_lines(self, pool, indent=8) -> list:
        """
        What a location does when its pool has nothing in it.

        503 rather than pointing at an upstream we did not write.  A proxy_pass
        at a name with no upstream block is the same fatal error as the empty
        block, so this has to change wherever the block goes missing.

        The site keeps working everywhere else, and every other site on the box
        is untouched, which is the whole point.  Same trade the renderer already
        makes for a certificate whose files are not there.
        """
        pad = " " * indent
        return [
            f"{pad}# The pool {pool.name} has no backends, so there is nowhere to send",
            f"{pad}# this.  Returning 503 rather than naming an upstream that is not",
            f"{pad}# there, which stops nginx loading and takes every site on the box",
            f"{pad}# down with it.  Add a backend to the pool and apply again.",
            f"{pad}return 503;",
        ]

    @staticmethod
    def _backend_path(cfg) -> str:
        """
        Where the application sits on the backend, tidied up, or empty.

        Always a leading and a trailing slash.  The trailing one is what makes
        nginx swap the matched part of the path rather than glue the two
        together, and asking somebody to remember it is asking for the bug the
        strip prefix checkbox already exists to avoid.
        """
        value = (cfg.get("backend_path") or "").strip()
        if not value:
            return ""
        if not value.startswith("/"):
            value = "/" + value
        if not value.endswith("/"):
            value += "/"
        return value

    def _backend_path_redirect_lines(self, backend_path, already_set, indent=8) -> list:
        """
        Put the backend's own path back off the redirects it sends.

        A backend that thinks it lives at /shop/ redirects to /shop/basket/,
        and without this the visitor's address bar grows a path that is none of
        their business and that the site does not answer on.

        Four rules, because a backend can say where it sent you four ways: an
        absolute URL with our name on it in either scheme, a plain path, or an
        absolute URL with something else in the host part.

        That last one is not a corner case and it is why the catch all is here.
        A backend listening on a port of its own answers with that port in the
        Location, so a rule scoped to $host alone reads
        http://site:8080/shop/thing, does not match, and the path stays on.
        Watched it do exactly that on a real nginx while this was being built,
        which is the only reason it is written this way.

        The catch all is last on purpose.  nginx takes the first rule that
        matches, so the three scoped ones answer first when they apply, and the
        pattern only gets a look when the host is not one we named.

        Worth knowing about the catch all: it matches any host with this path
        on it, so a backend redirecting to somebody else's site that happens to
        use the same path would have that turned into a local path.  With a
        distinctive path that cannot happen, and with a plain one like /shop/
        it is possible but needs the other site to share the path.  A rule set
        by hand is written above all of these and wins outright, which is the
        way out if it ever does happen.
        """
        pad = " " * indent
        lines = []
        if already_set:
            lines.append(f"{pad}# Redirect rewriting is set here too, and it is written")
            lines.append(f"{pad}# above, so it is tried before these.")
        lines.append(f"{pad}# The backend builds redirects from the path it thinks it")
        lines.append(f"{pad}# is under.  Take it back off.")
        for scheme in ("http", "https"):
            lines.append(f"{pad}proxy_redirect {scheme}://$host{backend_path} /;")
        lines.append(f"{pad}proxy_redirect {backend_path} /;")
        lines.append(f"{pad}# And when the backend names itself, or its own port, in the")
        lines.append(f"{pad}# Location.  Last, so the three above answer first.")
        lines.append(f"{pad}proxy_redirect "
                     f"~^https?://[^/]+{backend_path}(.*)$ /$1;")
        return lines

    def _proxy_lines(self, pool, cfg, indent=8, strip_prefix=False,
                     regex_location=False, offload_only=False) -> list:
        if not self._pool_has_servers(pool):
            return self._empty_pool_lines(pool, indent)

        pad = " " * indent
        scheme = "https" if getattr(pool, "uses_backend_tls", False) else "http"

        # A trailing slash on proxy_pass is what takes the location's path off
        # the front before the request goes on.  It is one character and it
        # changes the meaning completely, which is why it is a checkbox on the
        # location rather than something anybody has to remember.
        #
        # /lb/thing reaches the backend as /thing.  Without it the backend gets
        # /lb/thing and answers 404, which reads like the backend being broken
        # rather than the path being passed on whole.
        tail = "/" if strip_prefix else ""

        # The backend sitting under a path of its own.
        #
        # This is the other half of the strip above and it goes in the same
        # place, on proxy_pass, for one reason worth writing down: a rewrite
        # rule that does this has to be written at the site level, where it
        # runs before nginx has picked a location, so it rewrites the
        # certificate challenge and the error pages along with everything else.
        # People then carve those back out by hand and the site works until the
        # next thing that needs carving out.  Watched it happen on a live
        # fleet, twice, for the same site.
        #
        # A URI on proxy_pass is the content phase, inside one location, so
        # nothing else on the site can see it.
        # Set on the pool, because it is a fact about the backend rather than
        # about any one site pointed at it, and overridden on a site or a path
        # for the case where the same backend is reached two ways.  The pool is
        # also simply where people look: the first attempt at setting this was
        # typing the path onto a member's address, which is host and port, and
        # being told the port was not valid.
        backend_path = self._backend_path(cfg)
        if not backend_path:
            try:
                backend_path = self._backend_path(pool.setting_map())
            except Exception:  # a pool with no settings blob at all
                backend_path = ""
        lines = []
        if backend_path and regex_location:
            # nginx refuses a URI on proxy_pass in a regex location, and would
            # refuse the whole config with it, which takes every site on the
            # node down and not just this one.  A rewrite inside the location
            # does the same job and is still confined to the location, so it
            # cannot reach the challenge or the error pages.
            lines.append(f"{pad}# This path is matched by a pattern, and nginx will not take a")
            lines.append(f"{pad}# path on proxy_pass in one.  Same result, written the way")
            lines.append(f"{pad}# nginx allows here, and still only inside this block.")
            lines.append(f"{pad}rewrite ^(.*)$ {backend_path.rstrip('/')}$1 break;")
            lines.append(f"{pad}proxy_pass {scheme}://{_safe_name(pool.name)};")
        elif backend_path:
            lines.append(f"{pad}proxy_pass {scheme}://{_safe_name(pool.name)}{backend_path};")
        else:
            lines.append(f"{pad}proxy_pass {scheme}://{_safe_name(pool.name)}{tail};")

        backend_name = getattr(pool, "backend_name", "") or ""

        # The pool saying it is somebody else's website is what swaps the Host
        # header for the backend's own name and rewrites its redirects back at
        # us.  Both are rewriting, so offload only mode does neither, and the
        # backend gets the name the visitor typed.
        #
        # `backend_name` itself is left alone above, because SNI is not a
        # rewrite of anything: it is the only way to reach a backend that serves
        # more than one certificate, and dropping it would turn this mode into a
        # handshake failure on exactly the backends that need it most.
        is_site = (getattr(pool, "backend_kind", "servers") == "site"
                   and not offload_only)

        if scheme == "https":
            # nginx sends no SNI at all unless you ask, and plenty of backends
            # answer the wrong certificate or hang up without it.  The name it
            # would use by default is the upstream block's name, which is not a
            # hostname anybody has a certificate for, so we always say which
            # name we mean.
            if backend_name:
                lines.append(f"{pad}proxy_ssl_server_name on;")
                lines.append(f"{pad}proxy_ssl_name {esc(backend_name)};")
            else:
                # Every member is a bare address.  SNI takes a name, so there is
                # nothing honest to send, and asking nginx to send one anyway
                # gets the upstream block's name put on the wire.
                lines.append(f"{pad}proxy_ssl_server_name off;")

            if getattr(pool, "backend_tls_verify", False):
                # nginx ships no trusted certificate list of its own, so turning
                # verification on without naming one fails every request instead
                # of checking anything.  Blank means the system bundle, which is
                # what a certificate from a public CA needs.
                bundle = (getattr(pool, "backend_tls_ca", None) or "").strip() or SYSTEM_CA_BUNDLE
                lines.append(f"{pad}proxy_ssl_verify on;")
                lines.append(f"{pad}proxy_ssl_verify_depth 3;")
                lines.append(f"{pad}proxy_ssl_trusted_certificate {esc(bundle)};")
            else:
                lines.append(f"{pad}proxy_ssl_verify off;")

        version = cfg.get("proxy_http_version", "1.1")
        lines.append(f"{pad}proxy_http_version {version};")

        # These four are what your backend needs to know who actually asked.
        # Without them every request looks like it came from the load balancer,
        # and the app logs your own address a million times.
        #
        # Which Host to send is the one that is not obvious.  Servers running
        # your app want the name the visitor typed, so they serve the right site
        # and build the right links.  Somebody else's website only answers to
        # its own name, and sending it yours gets you their default site, or a
        # 404, or a redirect somewhere strange.  Nothing about that failure says
        # "wrong Host header", which is why it is a choice on the pool rather
        # than something to work out from a 404.
        if is_site and backend_name:
            lines.append(f"{pad}proxy_set_header Host {esc(backend_name)};")
        else:
            lines.append(f"{pad}proxy_set_header Host $host;")
        lines.append(f"{pad}proxy_set_header X-Real-IP $remote_addr;")
        lines.append(f"{pad}proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;")
        lines.append(f"{pad}proxy_set_header X-Forwarded-Proto $scheme;")
        lines.append(f"{pad}proxy_set_header X-Forwarded-Host $host;")
        lines.append(f"{pad}proxy_set_header X-Forwarded-Port $server_port;")

        # Anything set by hand goes first, because nginx takes the first
        # proxy_redirect that matches and stops looking.
        #
        # It used to be written after the two generated below, which meant that
        # on a pool with a backend name a hand written rule could never fire:
        # the generated rule matched, nginx stopped, and the setting somebody
        # had filled in did nothing at all.  The mount path already knew to put
        # the hand written one first.  This one did not.
        #
        # Two arguments, so it goes through the same writer as a rewrite rule
        # rather than being quoted whole, which would turn "/guacamole/ /" into
        # a single nonsense argument.
        hand_redirect = (cfg.get("proxy_redirect") or "").strip()
        if hand_redirect:
            try:
                lines.append(f"{pad}proxy_redirect "
                             f"{directive_args(hand_redirect, 'proxy_redirect')};")
            except ValueError as exc:
                log.warning("dropping proxy_redirect: %s", exc)
                lines.append(f"{pad}# proxy_redirect left out, {exc}")
                hand_redirect = ""

        if backend_path:
            lines.extend(self._backend_path_redirect_lines(
                backend_path, already_set=bool(hand_redirect), indent=indent))

        if is_site and backend_name:
            # Their redirects point at their own name.  Left alone, the first
            # redirect walks your visitor off your site and onto the backend's
            # address, which then works, so it reads as fine right up until
            # somebody notices the address bar.
            #
            # Rewriting to a path rather than to our own name means this holds
            # for every site pointed at this pool, and for http and https alike,
            # without the renderer having to know which site it is writing.
            lines.append(f"{pad}proxy_redirect https://{backend_name}/ /;")
            lines.append(f"{pad}proxy_redirect http://{backend_name}/ /;")

        # The pool token, if this pool has one.  The backend checks it and turns
        # away anything that did not come through us.
        #
        # Two things stop a client from forging this.  We set the header rather
        # than adding to it, so whatever the client sent is replaced.  And we
        # clear it on the way back so the value never reaches a browser.
        if pool is not None and getattr(pool, "token_active", False):
            token = pool.token
            if token:
                header = _safe_header(pool.token_header or "X-Fleet-Token")
                lines.append("")
                lines.append(f"{pad}# Proves to the backend that this came through the fleet.")
                lines.append(f"{pad}# Rotate it from the pool page, never by hand editing here.")
                lines.append(f"{pad}proxy_set_header {header} {esc(token)};")
                lines.append(f"{pad}proxy_hide_header {header};")

        if cfg.get("websocket_enabled"):
            timeout = cfg.get("websocket_timeout", "3600s")
            lines.append("")
            lines.append(f"{pad}# WebSocket upgrade.  All three of these are needed, and the long")
            lines.append(f"{pad}# timeout is what stops the connection dying after a minute.")
            lines.append(f"{pad}proxy_set_header Upgrade $http_upgrade;")
            lines.append(f'{pad}proxy_set_header Connection "upgrade";')
            lines.append(f"{pad}proxy_read_timeout {esc(timeout)};")
            lines.append(f"{pad}proxy_send_timeout {esc(timeout)};")
        elif version == "1.1":
            # Clearing Connection is what lets keepalive to the backend work.
            # Leave it set and every request opens a fresh connection, which
            # quietly undoes the keepalive setting on the pool.
            lines.append(f'{pad}proxy_set_header Connection "";')

        # If the header buffer has been raised, pin the busy buffer size to
        # something that fits rather than letting nginx work out a number that
        # does not.  See busy_buffers_for.
        head = cfg.get("proxy_buffer_size")
        bufs = cfg.get("proxy_buffers", "8 4k")
        if head:
            busy = busy_buffers_for(head, bufs)
            if busy:
                lines.append(f"{pad}proxy_busy_buffers_size {busy // 1024}k;")

        for key in ("proxy_connect_timeout", "proxy_send_timeout", "proxy_read_timeout",
                    "proxy_buffer_size", "proxy_buffers", "proxy_next_upstream_tries",
                    "proxy_next_upstream_timeout"):
            if cfg.get("websocket_enabled") and key in ("proxy_read_timeout", "proxy_send_timeout"):
                continue
            value = cfg.get(key)
            if value not in (None, ""):
                feature = get_feature(key)
                text = emit(feature, value) if feature else esc(value)
                lines.append(f"{pad}{key} {text};")

        # proxy_cookie_path, since the redirect half of this pair has already
        # been written further up where the order matters.
        value = (cfg.get("proxy_cookie_path") or "").strip()
        if value:
            try:
                lines.append(f"{pad}proxy_cookie_path "
                             f"{directive_args(value, 'proxy_cookie_path')};")
            except ValueError as exc:
                log.warning("dropping proxy_cookie_path: %s", exc)
                lines.append(f"{pad}# proxy_cookie_path left out, {exc}")

        for key in ("proxy_buffering", "proxy_request_buffering", "proxy_intercept_errors",
                    "proxy_ssl_verify", "proxy_ssl_server_name"):
            # The pool already settled the two TLS ones, and writing them twice
            # leaves nginx taking whichever came last, which is a bad way to
            # find out that two pages disagree.  The pool page is the one that
            # knows about the trusted certificate, so it wins.
            if scheme == "https" and key in ("proxy_ssl_verify", "proxy_ssl_server_name"):
                continue
            value = cfg.get(key)
            if value is not None:
                lines.append(f"{pad}{key} {'on' if value else 'off'};")

        retry = cfg.get("proxy_next_upstream")
        if retry:
            lines.append(f"{pad}proxy_next_upstream {' '.join(retry)};")

        for header in cfg.get("proxy_hide_headers", []) or []:
            lines.append(f"{pad}proxy_hide_header {esc(header)};")

        # Caching
        cache = cfg.get("proxy_cache_zone")
        if cache:
            lines.append("")
            lines.append(f"{pad}proxy_cache {_safe_name(cache)};")
            for rule in cfg.get("proxy_cache_valid", []) or []:
                lines.append(f"{pad}proxy_cache_valid {rule};")
            key = cfg.get("proxy_cache_key")
            if key:
                lines.append(f"{pad}proxy_cache_key {esc(key)};")
            bypass = cfg.get("proxy_cache_bypass") or []
            if bypass:
                lines.append(f"{pad}proxy_cache_bypass {' '.join(bypass)};")
            no_cache = cfg.get("proxy_no_cache") or []
            if no_cache:
                lines.append(f"{pad}proxy_no_cache {' '.join(no_cache)};")
            stale = cfg.get("proxy_cache_use_stale") or []
            if stale:
                lines.append(f"{pad}proxy_cache_use_stale {' '.join(stale)};")
            if cfg.get("proxy_cache_background_update", True):
                lines.append(f"{pad}proxy_cache_background_update on;")
            if cfg.get("proxy_cache_lock", True):
                lines.append(f"{pad}proxy_cache_lock on;")
                lines.append(f"{pad}proxy_cache_lock_timeout 5s;")
            min_uses = cfg.get("proxy_cache_min_uses")
            if min_uses and int(min_uses) > 1:
                lines.append(f"{pad}proxy_cache_min_uses {int(min_uses)};")
            if cfg.get("cache_status_header", True):
                lines.append(f"{pad}add_header X-Cache-Status $upstream_cache_status always;")

        # Sticky sessions, our stand in for the paid feature.  The map handles
        # reading the cookie, this sets it when the client does not have one.
        pool_cfg = pool.setting_map()
        if pool_cfg.get("sticky_enabled"):
            lines.append("")
            lines.append(f"{pad}# Sticky sessions.  The map decides whether this client needs a")
            lines.append(f"{pad}# cookie, and hands back nothing when they already have one, so")
            lines.append(f"{pad}# no header is written and their existing route survives.")
            lines.append(
                f"{pad}add_header Set-Cookie $sticky_set_{_safe_var(pool.name)} always;"
            )

        return lines

    # =========================================================================
    # Stream, for plain TCP and UDP
    # =========================================================================

    def _render_streams(self, streams, certs, access_lists):
        """
        TCP and UDP proxying, as one file holding the whole stream block.

        Everything else we generate goes inside http, and stream is a sibling
        of http rather than something in it, so this is the one thing that
        cannot be another include in that list.  nginx.conf gets a second
        include at the top level, and that include points here.

        The whole block in one file, rather than a folder of pieces included
        from a `stream { }` written into nginx.conf.  Two reasons.  A block with
        nothing in it still has to be accepted by nginx on a fleet that uses no
        streams, and the agent's tidy up of an out of date include list only
        knows how to remove include lines, so a brace it had written into
        nginx.conf would be left behind on its own and nothing would load at
        all.  Here the braces live in a generated file that is replaced whole.

        The upstreams are written in here too, and they have to be.  http and
        stream keep separate upstream namespaces, so a pool declared for the
        sites is not visible to a stream: nginx says `no port in upstream`,
        which reads like the pool is malformed rather than like it is in the
        wrong half of the config.  The same name in both places is fine and is
        what happens when one pool serves a site and a stream.
        """
        if not self.has_module("stream"):
            if streams:
                log.warning(
                    "this nginx has no stream module, leaving %s stream(s) out",
                    len(streams))
            return

        live = [s for s in (streams or []) if s.enabled]
        if not live:
            return

        cert_by_id = {c.id: c for c in certs}
        acl_by_id = {a.id: a for a in access_lists}

        bodies = []
        pools_used = {}

        for s in live:
            # A pool with nothing in it is fatal here in a way it is not for a
            # site.  A site can answer 503 and say why; a raw socket has no
            # status code to send, so there is nothing to degrade to.  The
            # stream comes out entirely rather than naming an upstream that is
            # not there, which would stop nginx loading and take the whole
            # fleet's config with it.
            if s.pool and not self._pool_has_servers(s.pool):
                log.warning(
                    "stream %s uses pool %s which has no backends, leaving the "
                    "stream out", s.name, s.pool.name)
                continue
            if not s.pool and not s.custom_config:
                log.warning("stream %s has no pool and nothing hand written, "
                            "leaving it out", s.name)
                continue

            if s.pool:
                pools_used[s.pool.id] = s.pool

            bodies.append(self._render_stream_server(s, cert_by_id, acl_by_id))

        if not bodies:
            return

        lines = [HEADER.format(detail="TCP and UDP proxying.")]
        lines.append("stream {")
        lines.append("")
        lines.append("    # Upstreams again, because stream cannot see the ones")
        lines.append("    # declared for http.  Same pools, separate namespace.")
        for pool in sorted(pools_used.values(), key=lambda p: p.name):
            for line in self._render_pool(pool, stream=True).splitlines():
                lines.append(f"    {line}" if line else "")
            lines.append("")

        lines.extend(bodies)
        lines.append("}")

        self.files["stream/nfm-stream.conf"] = "\n".join(lines)

    def _render_stream_server(self, s, cert_by_id, acl_by_id) -> list:
        lines = [f"    # {s.name}", "    server {"]

        listen = f"        listen {s.listen_address}:{s.listen_port}"
        # udp is on the listen line, and the protocol column says the same
        # thing, so either one being set means udp.  They drifted apart once
        # already because the page wrote one and the renderer read the other.
        if s.udp or s.protocol == "udp":
            listen += " udp"
        if s.proxy_protocol:
            listen += " proxy_protocol"
        lines.append(listen + ";")

        cfg = s.setting_map()

        if s.ssl_enabled and s.cert_id in cert_by_id:
            cert = cert_by_id[s.cert_id]
            usable = getattr(cert, "usable", True)
            if usable:
                cert_dir = self._cert_path(cert)
                lines.append("        ssl_preread off;")
                lines.append(f"        ssl_certificate     {cert_dir}/fullchain.pem;")
                lines.append(f"        ssl_certificate_key {cert_dir}/privkey.pem;")
                # The same settings a site gets, rather than a version pair
                # written into the renderer.  Hard coding it here meant a stream
                # ignored the version list on its own page and got no post
                # quantum exchange at all, however the fleet was configured.
                #
                # Its own session zone: nginx has one shared memory namespace
                # for the whole config, so http and stream both naming `SSL`
                # is two uses of one name and nginx refuses the lot.
                lines.extend(self._tls_policy_lines(
                    cfg,
                    indent="        ",
                    session_zone="SSL_STREAM",
                    default_protocols=["TLSv1.2", "TLSv1.3"],
                ))
            else:
                # Same rule as a site: never point nginx at certificate files
                # that are not there.  It refuses to load and then nothing can
                # be applied anywhere.
                lines.append("        # The certificate for this stream is not on")
                lines.append("        # this node, so it is carrying plain tcp until")
                lines.append("        # the files turn up.")

        # Who is allowed to connect.  The stream module has allow and deny of
        # its own, with the same first match wins rule as http.
        acl = acl_by_id.get(getattr(s, "access_list_id", None))
        if acl is not None:
            for entry in acl.allows():
                lines.append(f"        allow {entry};")
            for entry in acl.denies():
                lines.append(f"        deny {entry};")
            if acl.default_action == "deny":
                lines.append("        deny all;")

        if s.pool:
            lines.append(f"        proxy_pass {_safe_name(s.pool.name)};")

        for key in ("proxy_timeout", "proxy_connect_timeout"):
            if cfg.get(key):
                lines.append(f"        {key} {esc(cfg[key])};")

        if s.custom_config:
            for line in s.custom_config.splitlines():
                lines.append(f"        {line}")

        lines.append("    }")
        lines.append("")
        return "\n".join(lines)


# ==============================================================================
# Helpers
# ==============================================================================

def _is_bare_address(value: str) -> bool:
    """
    Is this an IP address rather than a hostname.

    A member can be either, and it changes what we can send as SNI.  Brackets
    come off first because that is how an IPv6 member is written.
    """
    candidate = str(value).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False


# The handful of nginx variables that exist in both http and stream.  A hash
# key naming anything else is an http variable, and in a stream it is simply
# empty, which quietly sends every connection to one backend.
_STREAM_VARIABLES = (
    "$remote_addr", "$remote_port", "$binary_remote_addr",
    "$server_addr", "$server_port", "$proxy_protocol_addr",
    "$proxy_protocol_port", "$ssl_preread_server_name",
    "$hostname", "$time_iso8601", "$time_local",
)


def _stream_has_variable(key: str) -> bool:
    """Is every variable in this hash key one a stream actually has."""
    used = re.findall(r"\$[A-Za-z0-9_]+", str(key))
    return bool(used) and all(v in _STREAM_VARIABLES for v in used)


def _safe_name(name: str) -> str:
    """
    Make a name safe to use as a filename and as an nginx identifier.

    Names come from people typing in a form, so they can hold anything.  This
    one gets used as a filename and as an upstream name, and both of those would
    be bad places for a slash or a semicolon to turn up.
    """
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
    return cleaned[:64] or "unnamed"


def _safe_var(name: str) -> str:
    """Same idea, but for an nginx variable name, where only word chars work."""
    cleaned = re.sub(r"[^A-Za-z0-9_]", "_", str(name))
    return cleaned[:48] or "unnamed"


# The API asks the same question when somebody names or renames something:
# would this collide with what is already there.  It has to be these two
# functions and not a copy of them, because a copy that drifts turns a refusal
# into a config where one object quietly overwrites another.
safe_name = _safe_name
safe_var = _safe_var


def _safe_header(name: str) -> str:
    """
    Make an HTTP header name safe to write into a directive.

    Header names are letters, digits and dashes, so anything else is somebody
    either making a mistake or trying something.  We strip rather than quote
    because a quoted header name is not a header name nginx will accept.
    """
    cleaned = re.sub(r"[^A-Za-z0-9-]", "", str(name))
    return cleaned[:64] or "X-Fleet-Token"


def _version_at_least(version: str, target: tuple) -> bool:
    """Is this nginx version at least the given one."""
    if not version:
        # Assume new.  The current form is what a fresh build wants, and the
        # installer pins something recent.
        return True
    try:
        parts = tuple(int(p) for p in version.split(".")[:3])
    except (ValueError, AttributeError):
        return True
    return parts >= target
