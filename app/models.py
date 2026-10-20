"""
Database models.

Feature settings live in JSON columns rather than a column per setting, since
there are a couple hundred directives and each new one would otherwise need a
migration. The catalog in app/catalog/ defines the legal keys and validates
them.

Config versions are tracked in ConfigVersion; a node compares its
applied_version against the latest to know whether it is behind.
"""

import enum
import ipaddress
import json
from datetime import datetime, timedelta, timezone

from sqlalchemy import (
    Boolean,
    Column,
    DateTime,
    Enum,
    Float,
    ForeignKey,
    Index,
    Integer,
    String,
    Text,
    UniqueConstraint,
)
from sqlalchemy.orm import DeclarativeBase, relationship


class Base(DeclarativeBase):
    pass


def utcnow():
    return datetime.now(timezone.utc)


class JSONColumn(Text):
    """JSON stored as text. Read with json_get, which handles NULL."""


def json_get(raw, default=None):
    if not raw:
        return default if default is not None else {}
    try:
        return json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return default if default is not None else {}


def json_set(value):
    return json.dumps(value, separators=(",", ":"), sort_keys=True)


# ==============================================================================
# Enums
# ==============================================================================

class NodeRole(str, enum.Enum):
    ACTIVE = "active"        # takes the writes
    STANDBY = "standby"      # stays in sync, ready to take over
    UNKNOWN = "unknown"      # have not heard from it yet


class NodeState(str, enum.Enum):
    ONLINE = "online"
    OFFLINE = "offline"
    DEGRADED = "degraded"    # reachable, but nginx is unhealthy
    SYNCING = "syncing"      # catching up on queued changes
    JOINING = "joining"      # brand new, still getting its first sync


class MemberState(str, enum.Enum):
    UP = "up"                  # health checks pass, taking traffic
    DOWN = "down"              # health checks fail, nginx marked it down
    DRAINING = "draining"      # finishing what it has, no new connections
    MAINTENANCE = "maintenance"  # a person took it out on purpose
    UNKNOWN = "unknown"        # not checked yet


class UserRole(str, enum.Enum):
    ADMIN = "admin"        # everything, including users and cluster trust
    OPERATOR = "operator"  # config and certs, but not users or trust
    VIEWER = "viewer"      # read only


class AuthSource(str, enum.Enum):
    LOCAL = "local"
    OIDC = "oidc"


class ChangeState(str, enum.Enum):
    PENDING = "pending"      # waiting to go out
    PREPARED = "prepared"    # staged and tested on the node, not live yet
    APPLIED = "applied"
    FAILED = "failed"
    ROLLED_BACK = "rolled_back"


# ==============================================================================
# Cluster
# ==============================================================================

class Node(Base):
    """An nginx node. Each node keeps rows for itself and all its peers."""

    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    address = Column(String(255), nullable=False)
    peer_port = Column(Integer, default=8444)
    gui_port = Column(Integer, default=8443)

    # Higher wins the election; ties break on name.
    priority = Column(Integer, default=100)

    role = Column(Enum(NodeRole), default=NodeRole.UNKNOWN)
    state = Column(Enum(NodeState), default=NodeState.JOINING)

    # Admin pinned this node to standby (e.g. for patching); never elected.
    forced_standby = Column(Boolean, default=False)

    # The HMAC key signs each message on top of mTLS, so we know which node
    # sent it, not just that some cluster member did.
    cert_fingerprint = Column(String(128))
    hmac_key_encrypted = Column(Text)

    # What we know about the box itself
    public_ip = Column(String(45))
    public_ip_checked_at = Column(DateTime)
    local_addresses = Column(Text)      # json list
    nginx_version = Column(String(64))
    nginx_build_info = Column(Text)     # the whole nginx -V line
    agent_version = Column(String(32))
    os_info = Column(String(255))

    # Sync tracking.
    applied_version = Column(Integer, default=0)
    applied_checksum = Column(String(64))
    last_heartbeat = Column(DateTime)
    last_sync_at = Column(DateTime)
    last_error = Column(Text)

    # Health of the nginx service on that box
    nginx_active = Column(Boolean, default=False)
    nginx_config_ok = Column(Boolean, default=False)

    # Whether the node's public listener actually answered a request.
    # nginx_active only reflects systemctl, and a wedged nginx still counts
    # as active: on August 24, 2026 workers hung on a shared memory lock held
    # by a dead worker, handshakes completed, and clients got silence for 73
    # minutes while GSLB kept handing out the node.
    #
    # None means not reported yet. Never withdraw a node from DNS for None,
    # or a fleet mid-upgrade would drop off one node at a time.
    nginx_serving = Column(Boolean, default=None)
    nginx_serving_detail = Column(String(255))

    # Whether nginx has a load_module line for the WAF module. The module
    # list comes from `nginx -V`, which shows what was compiled in, not what
    # is loaded; an unloaded module fails nginx -t with `unknown directive`
    # and so blocks the fleet wide apply. None means not reported yet.
    waf_module_loaded = Column(Boolean, default=None)
    load_average = Column(Float)
    disk_free_bytes = Column(Integer)

    is_self = Column(Boolean, default=False)
    joined_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def local_address_list(self):
        return json_get(self.local_addresses, [])

    @property
    def is_healthy(self):
        return self.state == NodeState.ONLINE and self.nginx_active

    @property
    def seconds_since_heartbeat(self):
        if not self.last_heartbeat:
            return None
        hb = self.last_heartbeat
        if hb.tzinfo is None:
            hb = hb.replace(tzinfo=timezone.utc)
        return (utcnow() - hb).total_seconds()


class JoinToken(Base):
    """Single use, short lived token for joining a node. Hash only."""

    __tablename__ = "join_tokens"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False)
    created_by = Column(String(64))
    created_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)
    used_at = Column(DateTime)
    used_by_node = Column(String(64))
    note = Column(String(255))

    @property
    def is_valid(self):
        exp = self.expires_at
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return self.used_at is None and exp > utcnow()


class ConfigVersion(Base):
    """A numbered full snapshot of the config (not a diff).

    Catching up a node means sending it the newest one; no replaying edits.
    """

    __tablename__ = "config_versions"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, unique=True, nullable=False, index=True)

    # sha256 of the rendered files.
    checksum = Column(String(64), nullable=False)

    # Checksum of the same render with every enabled backend treated as
    # healthy. checksum answers "same bytes on every node?"; this answers
    # "has a person changed anything since the last apply?", which health
    # flaps (applied by the health checker itself) should not trigger.
    user_checksum = Column(String(64))

    snapshot = Column(Text, nullable=False)      # json of every object
    rendered = Column(Text)                      # json of path to file contents

    author = Column(String(64))
    summary = Column(String(500))
    created_at = Column(DateTime, default=utcnow, index=True)

    # Authoring node, to tell versions apart after a split brain.
    origin_node = Column(String(64))

    applied = Column(Boolean, default=False)
    applied_at = Column(DateTime)


class PendingChange(Base):
    """A version queued for a node that was unreachable during an apply.

    When the node returns the sync worker pushes the newest version and
    clears its whole backlog.
    """

    __tablename__ = "pending_changes"

    id = Column(Integer, primary_key=True)
    node_name = Column(String(64), nullable=False, index=True)
    version = Column(Integer, nullable=False)

    state = Column(Enum(ChangeState), default=ChangeState.PENDING)
    attempts = Column(Integer, default=0)
    last_attempt_at = Column(DateTime)
    last_error = Column(Text)

    queued_at = Column(DateTime, default=utcnow)
    completed_at = Column(DateTime)

    __table_args__ = (
        UniqueConstraint("node_name", "version", name="uq_pending_node_version"),
        Index("ix_pending_state", "state", "node_name"),
    )


# ==============================================================================
# Sites and routing
# ==============================================================================

class VirtualHost(Base):
    """A site, rendered as a server block.

    settings holds the catalog options (limits, timeouts, headers, etc.);
    see app/catalog/ for the keys.
    """

    __tablename__ = "virtual_hosts"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, default=True)

    # server_name values, as a JSON list.
    server_names = Column(Text, nullable=False, default='["_"]')

    listen_http = Column(Boolean, default=True)
    listen_https = Column(Boolean, default=True)
    http_port = Column(Integer, default=80)
    https_port = Column(Integer, default=443)
    default_server = Column(Boolean, default=False)

    # http2 defaults on with TLS. http3 needs a build flag the installer does
    # not set, so the GUI hides it unless the build supports it.
    http2 = Column(Boolean, default=True)

    force_https = Column(Boolean, default=True)

    # 301 every other server name to the first one, to pick a canonical
    # host. Order server_names to choose www to bare or bare to www.
    redirect_to_primary = Column(Boolean, default=False)

    cert_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"))
    cert = relationship("Certificate", back_populates="hosts")

    # proxy (to a pool), static (files), redirect, or php (fastcgi).
    mode = Column(String(20), default="proxy")

    pool_id = Column(Integer, ForeignKey("pools.id", ondelete="SET NULL"))
    pool = relationship("Pool", back_populates="hosts")

    document_root = Column(String(500))
    redirect_target = Column(String(500))
    redirect_code = Column(Integer, default=301)

    settings = Column(Text, default="{}")

    # Access list for this site. It must never block the management host.
    access_list_id = Column(Integer, ForeignKey("access_lists.id", ondelete="SET NULL"))
    access_list = relationship("AccessList")

    # Custom error page. SET NULL so a deleted template falls back to the
    # stock nginx page instead of breaking the render.
    error_page_template_id = Column(
        Integer, ForeignKey("error_page_templates.id", ondelete="SET NULL")
    )
    error_page_template = relationship("ErrorPageTemplate")

    # Restrict the whole site to the management allow list (staging sites,
    # admin panels).
    admin_only = Column(Boolean, default=False)

    # Terminate TLS and otherwise pass the application's responses through
    # untouched. Replaces a dozen settings whose defaults suit a site you own
    # but not one you only front. The renderer forces the settings listed in
    # OFFLOAD_ONLY_FORCES rather than clearing them, so turning this off
    # restores what the site had.
    tls_offload_only = Column(Boolean, default=False)

    # Raw nginx appended to the server block. Still checked by nginx -t.
    custom_config = Column(Text)

    # "gui": built from the settings above plus custom_config.
    # "raw": the user writes the whole server block and it is used verbatim.
    # Raw still goes through the two phase apply and nginx -t on every node.
    config_mode = Column(String(10), default="gui")

    notes = Column(Text)
    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))

    locations = relationship(
        "Location",
        back_populates="host",
        cascade="all, delete-orphan",
        order_by="Location.sort_order",
    )

    def name_list(self):
        return json_get(self.server_names, ["_"])

    def setting_map(self):
        return json_get(self.settings, {})


class Location(Base):
    """A location block inside a site, e.g. /api to another pool."""

    __tablename__ = "locations"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"), nullable=False)
    host = relationship("VirtualHost", back_populates="locations")

    path = Column(String(500), nullable=False, default="/")

    # exact (=), prefix, preferential (^~), regex (~), regex_i (~*)
    match_type = Column(String(20), default="prefix")

    # Explicit order; do not rely on database row order.
    sort_order = Column(Integer, default=100)

    mode = Column(String(20), default="proxy")

    pool_id = Column(Integer, ForeignKey("pools.id", ondelete="SET NULL"))
    pool = relationship("Pool")

    document_root = Column(String(500))
    alias = Column(String(500))
    redirect_target = Column(String(500))
    redirect_code = Column(Integer, default=301)

    settings = Column(Text, default="{}")

    access_list_id = Column(Integer, ForeignKey("access_lists.id", ondelete="SET NULL"))
    access_list = relationship("AccessList")

    # Per-path error page override, typically so a health check path is
    # excluded. Empty inherits the site's page.
    error_page_template_id = Column(
        Integer, ForeignKey("error_page_templates.id", ondelete="SET NULL")
    )
    error_page_template = relationship("ErrorPageTemplate")

    custom_config = Column(Text)
    enabled = Column(Boolean, default=True)

    # Strip the location path before proxying, for backends mounted under a
    # prefix they do not know about. Off by default.
    strip_prefix = Column(Boolean, default=False)

    # Serve a site that expects to live at / under this path. On top of
    # strip_prefix this rewrites root-relative links and redirects so they
    # stay under the mount; see _mount_settings in the renderer. Kept
    # separate from strip_prefix, which is enough on its own for APIs.
    mount_site = Column(Boolean, default=False)

    def setting_map(self):
        return json_get(self.settings, {})


# ==============================================================================
# Backend pools
# ==============================================================================

class Pool(Base):
    """A group of backends, rendered as an upstream block.

    nginx does passive checks (max_fails, fail_timeout). The manager adds
    active checks on a schedule and, when a backend fails, rewrites the
    upstream with it marked down and reloads.
    """

    __tablename__ = "pools"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # round_robin, least_conn, ip_hash, hash, random, random_two, fair.
    # least_time is NGINX Plus only; the catalog suggests alternatives.
    lb_method = Column(String(32), default="round_robin")

    # Only used when lb_method is hash, e.g. $request_uri.
    hash_key = Column(String(255))
    hash_consistent = Column(Boolean, default=False)

    # Upstream keepalive; saves a handshake per request, especially over TLS.
    keepalive = Column(Integer, default=32)
    keepalive_requests = Column(Integer, default=1000)
    keepalive_timeout = Column(String(20), default="60s")

    # Shared memory zone so workers share up/down state.
    zone_size = Column(String(20), default="64k")

    # ---- talking to the backend over TLS ------------------------------------
    # Proxy with https instead of http. Plain http to a TLS port gets a 400
    # that does not mention the scheme, hence the port-based guess below.
    backend_tls = Column(Boolean, default=False)

    # True once a user has set backend_tls explicitly, so we stop guessing
    # from the port and never override a deliberate "off".
    backend_tls_set = Column(Boolean, default=False)

    # servers: your app servers. Host is passed through and their redirects
    #          already point at your site.
    # site:    a third party site on its own name. Host is set to that name
    #          and its redirects are rewritten back to ours.
    # Getting this wrong fails quietly (backend default site, or visitors
    # bounced to the backend's own address).
    backend_kind = Column(String(20), default="servers")   # servers, site

    # Verify the backend certificate. On by default.
    backend_tls_verify = Column(Boolean, default=True)

    # CA file for verification; blank means the system bundle. nginx has no
    # default CA, so verification fails if none is configured.
    backend_tls_ca = Column(String(500))

    # Name for SNI and certificate verification. nginx would otherwise use
    # the proxy_pass host, which for us is the upstream name (e.g.
    # "websec_pool"). Blank derives it from the members; see backend_name.
    backend_tls_name = Column(String(255))

    # Active health checks, run by the manager
    health_check_enabled = Column(Boolean, default=True)
    health_check_type = Column(String(20), default="http")   # http, https, tcp
    health_check_path = Column(String(500), default="/")
    health_check_method = Column(String(10), default="GET")
    health_check_host_header = Column(String(255))
    health_check_expect_status = Column(String(100), default="200-399")
    health_check_expect_body = Column(String(500))
    health_check_interval = Column(Integer, default=10)
    health_check_timeout = Column(Integer, default=5)
    health_check_rise = Column(Integer, default=2)    # good checks before up
    health_check_fall = Column(Integer, default=3)    # bad checks before down
    health_check_verify_tls = Column(Boolean, default=False)
    health_check_port = Column(Integer)               # blank means the member's port

    # If marking members down would leave fewer than this up, leave them all
    # in and warn instead, so a bad check cannot empty the pool.
    min_healthy_members = Column(Integer, default=1)

    # ---- backend trust ------------------------------------------------------
    # Shared secret header sent on every proxied request so backends can
    # reject direct access. It is a bearer secret: use TLS on untrusted hops,
    # and treat it as a complement to a firewall, not a replacement.
    #
    # Rotation takes two steps since nginx sends one value:
    #   1. Stage: nginx keeps sending the current token; add the new one to
    #      the backends so they accept either.
    #   2. Activate: nginx sends the new one; the old one moves to previous
    #      so you know what to remove.
    token_enabled = Column(Boolean, default=False)
    token_header = Column(String(64), default="X-Fleet-Token")
    token_encrypted = Column(Text)            # what nginx sends right now
    token_next_encrypted = Column(Text)       # staged, not sent yet
    token_previous_encrypted = Column(Text)   # what it was before the last swap
    token_rotated_at = Column(DateTime)

    settings = Column(Text, default="{}")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    members = relationship(
        "PoolMember",
        back_populates="pool",
        cascade="all, delete-orphan",
        order_by="PoolMember.id",
    )
    hosts = relationship("VirtualHost", back_populates="pool")

    def setting_map(self):
        return json_get(self.settings, {})

    # ---- backend trust helpers ----------------------------------------------
    # Decrypt on access so plaintext is never stored on the model where it
    # could be logged by accident.

    def _read_token(self, column_value):
        if not column_value:
            return None
        from app.core.crypto import decrypt
        try:
            return decrypt(column_value)
        except Exception:
            # The secret key changed. None leaves the header off, which fails
            # closed: the backend rejects requests and someone notices.
            return None

    @property
    def token(self):
        """The value nginx should be sending right now."""
        return self._read_token(self.token_encrypted)

    @property
    def token_next(self):
        """Staged token; add it to backends before activating."""
        return self._read_token(self.token_next_encrypted)

    @property
    def token_previous(self):
        """Token sent before the last activate; safe to remove."""
        return self._read_token(self.token_previous_encrypted)

    @property
    def token_active(self):
        """True if the pool is enabled for a token and has one."""
        return bool(self.token_enabled and self.token_encrypted)

    @property
    def token_rotation_pending(self):
        return bool(self.token_next_encrypted)

    @property
    def uses_backend_tls(self):
        """Whether to proxy to these backends over https.

        Once the user has set it explicitly, that wins. Until then, guess
        from the port: any enabled member on 443 means TLS.
        """
        if self.backend_tls_set:
            return bool(self.backend_tls)
        return any(m.enabled and m.port == 443 for m in self.members)

    @property
    def backend_name(self):
        """The backend hostname for SNI, cert checks and (for "site") Host.

        backend_tls_name if set, else the first enabled member given as a
        hostname rather than an IP.
        """
        explicit = (self.backend_tls_name or "").strip()
        if explicit:
            return explicit
        for member in sorted(self.members, key=lambda m: m.id or 0):
            if not member.enabled:
                continue
            address = (member.address or "").strip()
            if address and not _looks_like_address(address):
                return address
        return ""

    @property
    def effective_health_check_type(self):
        """Health check protocol, upgraded from http to https for TLS pools.

        An http check against a TLS backend would mark every member down.
        Only the http default is changed; tcp and https are left alone.
        """
        if self.health_check_type == "http" and self.uses_backend_tls:
            return "https"
        return self.health_check_type or "http"

    @property
    def healthy_count(self):
        return sum(1 for m in self.members if m.state == MemberState.UP and m.enabled)

    @property
    def total_count(self):
        return sum(1 for m in self.members if m.enabled)

    @property
    def status_summary(self):
        if not self.members:
            return "empty"
        if self.healthy_count == 0:
            return "down"
        if self.healthy_count < self.total_count:
            return "degraded"
        return "healthy"


class PoolMember(Base):
    """One backend server in a pool."""

    __tablename__ = "pool_members"

    id = Column(Integer, primary_key=True)
    pool_id = Column(Integer, ForeignKey("pools.id", ondelete="CASCADE"), nullable=False)
    pool = relationship("Pool", back_populates="members")

    address = Column(String(255), nullable=False)   # ip or hostname
    port = Column(Integer, nullable=False, default=80)
    weight = Column(Integer, default=1)

    # Idle until every normal member is down, e.g. a "sorry" page server.
    backup = Column(Boolean, default=False)

    # Passive checks, done by nginx while serving real traffic
    max_fails = Column(Integer, default=3)
    fail_timeout = Column(String(20), default="10s")
    max_conns = Column(Integer, default=0)   # 0 means no limit

    enabled = Column(Boolean, default=True)

    # up, down, draining or maintenance, set by an admin. Kept separate from
    # the health check state so a passing check cannot undo it.
    admin_state = Column(String(20), default="up")

    # What the checks say
    state = Column(Enum(MemberState), default=MemberState.UNKNOWN)
    consecutive_ok = Column(Integer, default=0)
    consecutive_fail = Column(Integer, default=0)
    last_check_at = Column(DateTime)
    last_state_change = Column(DateTime)
    last_error = Column(Text)

    # Reason captured when the member went down, kept until it comes back.
    # Rendered as a comment in the upstream; last_error changes on every
    # check and would make the config checksum churn and trigger reloads.
    down_reason = Column(String(255))

    last_response_ms = Column(Float)

    # Rolling stats so the GUI can show a backend slowing down
    avg_response_ms = Column(Float)
    check_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)

    # Health check results per node. A backend reachable from one node but
    # not another often explains an intermittent site.
    per_node_state = Column(Text, default="{}")

    notes = Column(String(500))
    created_at = Column(DateTime, default=utcnow)

    __table_args__ = (
        UniqueConstraint("pool_id", "address", "port", name="uq_member_addr"),
    )

    @property
    def label(self):
        return f"{self.address}:{self.port}"

    @property
    def effective_state(self):
        """State to render; admin_state overrides the health check."""
        if not self.enabled:
            return MemberState.MAINTENANCE
        if self.admin_state == "maintenance":
            return MemberState.MAINTENANCE
        if self.admin_state == "draining":
            return MemberState.DRAINING
        if self.admin_state == "down":
            return MemberState.DOWN
        return self.state

    def node_states(self):
        return json_get(self.per_node_state, {})


# ==============================================================================
# Shared bits sites point at
# ==============================================================================

class AccessList(Base):
    """A reusable allow/deny list.

    include_management adds every cluster node's address automatically,
    including nodes added later.
    """

    __tablename__ = "access_lists"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(500))

    # json lists of CIDRs
    allow_entries = Column(Text, default="[]")
    deny_entries = Column(Text, default="[]")

    # allow or deny for anything not matched above
    default_action = Column(String(10), default="deny")

    include_management = Column(Boolean, default=True)

    # Basic auth on top of the IP rules, if you want both
    basic_auth_enabled = Column(Boolean, default=False)
    basic_auth_realm = Column(String(255), default="Restricted")
    basic_auth_users = Column(Text, default="[]")   # json of user and hash

    # Use the client address from a header. Only enable behind a trusted
    # proxy; clients can forge the header.
    use_real_ip = Column(Boolean, default=False)
    real_ip_header = Column(String(50), default="X-Forwarded-For")
    real_ip_from = Column(Text, default="[]")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    def allows(self):
        return json_get(self.allow_entries, [])

    def denies(self):
        return json_get(self.deny_entries, [])

    def trusted_proxies(self):
        return json_get(self.real_ip_from, [])

    def auth_users(self):
        return json_get(self.basic_auth_users, [])


class ErrorPageTemplate(Base):
    """A custom error page shared by any number of sites.

    One template covers many status codes; the code and its description are
    substituted at render time, so there is no page per code per site.
    """

    __tablename__ = "error_page_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # User supplied HTML with placeholders. Filled by plain string
    # replacement, never a template engine, since this comes from a form and
    # an engine would allow code execution. The placeholders are in render.py.
    html = Column(Text, nullable=False, default="")

    # Status codes this template covers, as a JSON list of ints.
    codes = Column(Text, default="[]")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))

    images = relationship(
        "ErrorPageImage",
        back_populates="template",
        cascade="all, delete-orphan",
    )

    def code_list(self):
        return json_get(self.codes, [])


class ErrorPageImage(Base):
    """An image for an error page, stored in the database.

    Inlined as a data URI at render time, so the page has nothing to fetch
    while the site is failing, uploads replicate with the config, and there
    is no upload directory to serve (or traverse). Uploads are size capped.
    """

    __tablename__ = "error_page_images"

    id = Column(Integer, primary_key=True)
    template_id = Column(
        Integer,
        ForeignKey("error_page_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    template = relationship("ErrorPageTemplate", back_populates="images")

    # Referenced from the template as {{image:name}}.
    name = Column(String(128), nullable=False)

    # Detected from the file's magic bytes, not the browser's claim.
    content_type = Column(String(60), nullable=False)

    # base64, so it fits in the JSON snapshot.
    data = Column(Text, nullable=False)
    size_bytes = Column(Integer, default=0)

    created_at = Column(DateTime, default=utcnow)


class GslbZone(Base):
    """A DNS zone the fleet is authoritative for (GSLB).

    This is what moves traffic on failover, as opposed to moving which node
    manages config: answer only with healthy targets, on a short TTL.

    Usually a delegated subzone, e.g. keep example.com elsewhere, delegate
    gslb.example.com to these nodes with NS records, and CNAME public names
    into it, so an outage here only affects those names.
    """

    __tablename__ = "gslb_zones"

    id = Column(Integer, primary_key=True)
    # Zone apex, without the trailing dot; matched case insensitively.
    name = Column(String(253), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, default=True)
    description = Column(String(500))

    # SOA fields. soa_minimum is the negative caching TTL.
    soa_primary = Column(String(253))        # blank means the first nameserver
    soa_contact = Column(String(253), default="hostmaster")
    soa_refresh = Column(Integer, default=3600)
    soa_retry = Column(Integer, default=600)
    soa_expire = Column(Integer, default=604800)
    soa_minimum = Column(Integer, default=30)
    soa_serial = Column(Integer, default=1)

    # JSON list of NS names. Must match the parent zone's delegation or
    # resolvers get inconsistent answers.
    nameservers = Column(Text, default="[]")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    records = relationship("GslbRecord", back_populates="zone",
                           cascade="all, delete-orphan")

    def nameserver_list(self):
        return json_get(self.nameservers, [])


class GslbRecord(Base):
    """A name in a zone. Unhealthy answers are left out of the reply."""

    __tablename__ = "gslb_records"

    id = Column(Integer, primary_key=True)
    zone_id = Column(Integer, ForeignKey("gslb_zones.id", ondelete="CASCADE"),
                     nullable=False)
    zone = relationship("GslbZone", back_populates="records")

    # Label within the zone: "@" is the apex, "*" a wildcard.
    name = Column(String(253), nullable=False, default="@")
    enabled = Column(Boolean, default=True)
    description = Column(String(500))

    # A, AAAA or CNAME. CNAMEs are not health checked.
    record_type = Column(String(10), default="A")

    # Short so answers can change. Resolvers may clamp low TTLs and some
    # clients cache longer; 30s moves most clients within a minute or two.
    ttl = Column(Integer, default=30)

    # all      every healthy answer (round robin)
    # failover only the healthy answer with the lowest priority number
    policy = Column(String(20), default="all")

    # Behavior when no answer is healthy. serve_all is usually better than
    # an empty answer, which looks to visitors like the site does not exist.
    when_all_down = Column(String(20), default="serve_all")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    answers = relationship("GslbAnswer", back_populates="record",
                           cascade="all, delete-orphan",
                           order_by="GslbAnswer.priority")

    def fqdn(self, zone_name=None) -> str:
        zone_name = zone_name or (self.zone.name if self.zone else "")
        label = (self.name or "@").strip()
        if label in ("@", ""):
            return zone_name
        return f"{label}.{zone_name}"


class GslbAnswer(Base):
    """One possible answer for a record.

    Usually tied to a cluster node, whose health we already track. An answer
    with no node is always treated as healthy.
    """

    __tablename__ = "gslb_answers"

    id = Column(Integer, primary_key=True)
    record_id = Column(Integer, ForeignKey("gslb_records.id", ondelete="CASCADE"),
                       nullable=False)
    record = relationship("GslbRecord", back_populates="answers")

    # An address for A/AAAA, the target name for CNAME.
    value = Column(String(253), nullable=False)

    # Node whose health gates this answer; NULL means always served.
    node_id = Column(Integer, ForeignKey("nodes.id", ondelete="SET NULL"))

    # The node by name. Use this, not node_id, after replication: node rows
    # are per database and not replicated, so the same id can mean a
    # different node elsewhere. On a pair the ids came out mirrored, and the
    # survivor of a failure served the dead node's address. Names are unique
    # fleet wide.
    node_name = Column(String(64))
    node = relationship("Node")

    # Lower wins under the failover policy; ignored otherwise.
    priority = Column(Integer, default=10)
    enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=utcnow)


class RateLimitZone(Base):
    """A named limit_req zone, declared at http level and shareable."""

    __tablename__ = "rate_limit_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    # $binary_remote_addr is per client IP and much smaller in memory than
    # $remote_addr.
    key = Column(String(255), default="$binary_remote_addr")

    zone_size = Column(String(20), default="10m")

    # Requests per second or per minute
    rate = Column(String(20), default="10r/s")

    created_at = Column(DateTime, default=utcnow)


class ConnLimitZone(Base):
    """A named limit_conn zone for concurrent connections."""

    __tablename__ = "conn_limit_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))
    key = Column(String(255), default="$binary_remote_addr")
    zone_size = Column(String(20), default="10m")
    created_at = Column(DateTime, default=utcnow)


class CacheZone(Base):
    """A proxy cache zone.

    The directory must exist and be writable before nginx starts, so the
    manager creates it through the agent on save.
    """

    __tablename__ = "cache_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    path = Column(String(500), nullable=False, default="/var/cache/nginx/proxy")

    # Directory levels, e.g. 1:2, so no single directory gets huge.
    levels = Column(String(20), default="1:2")

    # Key index memory; 1m holds roughly 8000 keys.
    keys_zone_size = Column(String(20), default="10m")

    # Disk cap for cached bodies
    max_size = Column(String(20), default="1g")

    # Evict entries unused for this long, even if there is room
    inactive = Column(String(20), default="60m")

    use_temp_path = Column(Boolean, default=False)

    created_at = Column(DateTime, default=utcnow)


class StreamServer(Base):
    """TCP/UDP proxying via the stream module (databases, mail, syslog).

    ssl_preread is available for routing by SNI without decrypting.
    """

    __tablename__ = "stream_servers"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    enabled = Column(Boolean, default=True)

    listen_port = Column(Integer, nullable=False)
    listen_address = Column(String(64), default="0.0.0.0")
    protocol = Column(String(10), default="tcp")   # tcp or udp

    udp = Column(Boolean, default=False)
    proxy_protocol = Column(Boolean, default=False)

    pool_id = Column(Integer, ForeignKey("pools.id", ondelete="SET NULL"))
    pool = relationship("Pool")

    ssl_enabled = Column(Boolean, default=False)
    cert_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"))
    cert = relationship("Certificate")

    settings = Column(Text, default="{}")
    access_list_id = Column(Integer, ForeignKey("access_lists.id", ondelete="SET NULL"))
    access_list = relationship("AccessList")

    custom_config = Column(Text)
    created_at = Column(DateTime, default=utcnow)

    def setting_map(self):
        return json_get(self.settings, {})


class MapBlock(Base):
    """An nginx map block, the usual alternative to if statements."""

    __tablename__ = "map_blocks"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    source_variable = Column(String(255), nullable=False, default="$http_user_agent")
    result_variable = Column(String(64), nullable=False)
    # Store the raw value; the renderer quotes it. (Storing `""` here once
    # produced a default of two literal quote marks.)
    default_value = Column(String(255), default="")

    entries = Column(Text, default="[]")   # json list of match and value
    hostnames = Column(Boolean, default=False)

    created_at = Column(DateTime, default=utcnow)

    def entry_list(self):
        return json_get(self.entries, [])


# ==============================================================================
# Certificates
# ==============================================================================

class TunnelNetwork(Base):
    """The fleet's single WireGuard network.

    Every node and every enrolled workload gets an address, so backends
    reached through the tunnel stay reachable after failover. The operator
    picks the range since only they know what is already in use.
    """
    __tablename__ = "tunnel_networks"

    id = Column(Integer, primary_key=True)
    # Must be RFC 1918.
    cidr = Column(String(64), nullable=False, default="10.77.0.0/24")
    listen_port = Column(Integer, default=51820)
    enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    # Highest address allocated so far. Allocation counts upward so a
    # removed workload's address is not reused right away, which would send
    # traffic from stale pool members to a different machine. Gaps are
    # reused once the top of the range is reached.
    address_high_water = Column(Integer, default=0)

    peers = relationship("TunnelPeer", back_populates="network",
                         cascade="all, delete-orphan")


class TunnelNodeKey(Base):
    """A node's WireGuard public key. Per node, never replicated.

    The private key is generated by the agent and never leaves the node.
    """
    __tablename__ = "tunnel_node_keys"

    id = Column(Integer, primary_key=True)
    node_name = Column(String(64), unique=True, nullable=False, index=True)
    public_key = Column(String(64), nullable=False)
    address = Column(String(64), nullable=False)     # this node's tunnel address
    endpoint = Column(String(255))
    # Operator override for the endpoint workloads dial. A hostname is often
    # better than an address: wg resolves it at interface up, so a dual stack
    # name lets each workload use the address family it has.
    endpoint_override = Column(String(255))                   # what a workload dials
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class TunnelPeer(Base):
    """An enrolled workload. Its key pair is generated on the workload."""
    __tablename__ = "tunnel_peers"

    id = Column(Integer, primary_key=True)
    network_id = Column(Integer, ForeignKey("tunnel_networks.id", ondelete="CASCADE"),
                        nullable=False)
    network = relationship("TunnelNetwork", back_populates="peers")

    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    address = Column(String(64), nullable=False, index=True)
    public_key = Column(String(64))

    # WireGuard pre-shared key, mixed into the handshake so that breaking
    # Curve25519 alone (e.g. harvest now, decrypt later) is not enough. It
    # is not post quantum in the ML-KEM sense, but it is what WireGuard
    # offers. Encrypted at rest. Both ends must match or the handshake
    # fails, so it is never added to a working peer without asking.
    psk_encrypted = Column(Text)

    # One time token for installing the PSK on an already enrolled workload.
    # Separate from enrollment so the workload keeps its address and key.
    psk_token_hash = Column(String(128), index=True)
    psk_expires_at = Column(DateTime)
    psk_applied_at = Column(DateTime)

    # Enrollment token: hash only, single use, short lived, like the join
    # token. Anyone holding it can put a machine on the tunnel.
    enrol_token_hash = Column(String(128), index=True)
    enrol_expires_at = Column(DateTime)
    enrolled_at = Column(DateTime)

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    def is_enrolled(self):
        return bool(self.public_key and self.enrolled_at)

    @property
    def has_psk(self):
        return bool(self.psk_encrypted)

    @property
    def enrol_is_valid(self):
        """Whether the enrollment token is still valid.

        sqlite returns naive datetimes; comparing with the aware utcnow()
        would raise, hence the tzinfo fix.
        """
        if not self.enrol_token_hash:
            return False
        exp = self.enrol_expires_at
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp is None or exp > utcnow()


class MetricSample(Base):
    """One persisted telemetry bucket for one node.

    The in memory history (15s detail for two hours) is lost on restart;
    this keeps the long view. One minute rows are kept for 48 hours and
    rolled up into five minute rows kept for 30 days, sized for what a chart
    can draw (all tiers are under 35 MB for four nodes). Buckets store min,
    mean and max rather than a sample so spikes are not lost.
    """

    __tablename__ = "metric_samples"

    id = Column(Integer, primary_key=True)

    node = Column(String(64), nullable=False, index=True)

    # Bucket start in epoch seconds; integer for easy range arithmetic.
    at = Column(Integer, nullable=False, index=True)

    # "1m" or "5m".
    resolution = Column(String(4), nullable=False, default="1m")

    # {"cpu_percent": {"min": 3, "avg": 7, "max": 41}, ...}
    # JSON so new metrics do not need a migration.
    values = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint("node", "at", "resolution", name="uq_metric_bucket"),
    )

    def value_map(self):
        return json_get(self.values, {})


class WafProfile(Base):
    """A named WAF tuning (rule exclusions) shared by any number of sites.

    Exclusions take real effort to tune, so they are reusable across sites
    running the same application. Editing a profile affects every site using
    it, so the page lists those sites before saving.
    """

    __tablename__ = "waf_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # Provenance, so exclusions can be explained and safely removed later.
    learned_from_site = Column(String(255))
    learned_from_addresses = Column(Text, default="[]")
    learned_at = Column(DateTime)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))

    exclusions = relationship(
        "WafExclusion",
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="WafExclusion.rule_id",
    )

    # Exclusions tune the negative model (rules describe attacks). The
    # surface is a positive model: known paths and methods, everything else
    # refused. Both belong to one profile since they form one policy, and the
    # positive model still runs the rules underneath.
    surface = relationship(
        "WafSurfaceEntry",
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="WafSurfaceEntry.path",
    )

    def address_list(self):
        return json_get(self.learned_from_addresses, [])


class WafExclusion(Base):
    """A rule disabled by this profile.

    A blank path disables it site wide; a path limits it to that path, which
    is usually the right fix for a false positive.
    """

    __tablename__ = "waf_exclusions"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("waf_profiles.id", ondelete="CASCADE"),
                        nullable=False)
    profile = relationship("WafProfile", back_populates="exclusions")

    rule_id = Column(Integer, nullable=False)
    path = Column(String(500))

    # Evidence behind the decision, for later review.
    message = Column(String(300))
    learned_from_ip = Column(String(64))
    sample_uri = Column(String(500))
    hits = Column(Integer, default=0)

    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String(64))

    __table_args__ = (
        UniqueConstraint("profile_id", "rule_id", "path", name="uq_waf_exclusion"),
    )


class LoginWatch(Base):
    """Login attack detection for one site.

    Detects brute force (one address, many attempts) and password spraying
    (many addresses, few attempts each), which slips past per account
    lockouts and per address rate limits and is only visible in aggregate.

    Works from the access log, so it sees address, path, method and status
    but never usernames; it cannot say which accounts were targeted.
    """

    __tablename__ = "login_watches"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"),
                     unique=True, nullable=False)

    enabled = Column(Boolean, default=True)

    # Login paths as a JSON list (form, API token endpoint, etc.).
    paths = Column(Text, default='[]')
    methods = Column(Text, default='["POST"]')

    # Statuses that mean a failed login. Application specific: a form may
    # return 200 on failure and 302 on success, an API 401. The page asks
    # rather than guessing.
    fail_statuses = Column(Text, default='[401, 403]')

    # Short window. A slow spray will not trip it; see the slow window.
    window_seconds = Column(Integer, default=300)

    # One address, many tries.
    brute_threshold = Column(Integer, default=10)

    # Many addresses, few tries each. All three must hold, so ordinary busy
    # traffic does not trigger it.
    spray_min_addresses = Column(Integer, default=12)
    spray_min_failures = Column(Integer, default=20)
    spray_max_per_address = Column(Integer, default=3)

    # Slow spray detection over hours rather than minutes.
    slow_window_seconds = Column(Integer, default=21600)
    slow_min_addresses = Column(Integer, default=25)
    slow_min_failures = Column(Integer, default=60)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))

    def path_list(self):
        return json_get(self.paths, [])

    def method_list(self):
        return json_get(self.methods, ["POST"])

    def fail_status_list(self):
        return json_get(self.fail_statuses, [401, 403])


class WafSurfaceEntry(Base):
    """An allowed path and its methods in the positive model.

    Requests not matching any entry are refused. Paths are templates
    (e.g. /user/*/profile) so learned per-object paths generalize; they are
    converted to regexes at render time, like exclusion paths. Methods are
    enforced too, so a POST to a GET-only page is refused.
    """

    __tablename__ = "waf_surface_entries"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("waf_profiles.id", ondelete="CASCADE"),
                        nullable=False)
    profile = relationship("WafProfile", back_populates="surface")

    # The template, with * for one path segment and ** for any number.
    path = Column(String(500), nullable=False)

    # JSON list of methods. Empty means any method, which must be chosen
    # deliberately.
    methods = Column(Text, default='["GET"]')

    # Evidence for review, as with exclusions.
    sample_uri = Column(String(500))
    learned_from_ip = Column(String(64))
    hits = Column(Integer, default=0)
    note = Column(String(300))

    created_at = Column(DateTime, default=utcnow)
    created_by = Column(String(64))

    __table_args__ = (
        UniqueConstraint("profile_id", "path", name="uq_waf_surface"),
    )

    def method_list(self):
        return json_get(self.methods, [])


class WafSession(Base):
    """A WAF learning session and the tester addresses it trusts.

    Only traffic from these addresses is learned from, so a scanner hitting
    the site during learning cannot turn its probes into exclusions.
    Sessions are time bounded on purpose.
    """

    __tablename__ = "waf_sessions"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    host = relationship("VirtualHost")

    # IPs and CIDRs, as a JSON list.
    addresses = Column(Text, nullable=False, default="[]")

    # WAF mode before the session, restored when it stops.
    previous_mode = Column(String(20))

    started_at = Column(DateTime, default=utcnow)
    started_by = Column(String(64))
    ended_at = Column(DateTime)
    ended_by = Column(String(64))

    note = Column(String(500))

    def address_list(self):
        return json_get(self.addresses, [])

    @property
    def running(self):
        return self.ended_at is None


class CertificateAuthority(Base):
    """A commercial ACME certificate authority and its credentials.

    Let's Encrypt is not stored here; it is the default when a certificate
    names no authority. One row per ACME directory, since some CAs have
    separate directories for DV and OV (e.g. "DigiCert OV").
    """
    __tablename__ = "certificate_authorities"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # The ACME directory the authority gave you.
    directory_url = Column(String(500), nullable=False)

    # External account binding credentials, required by paid CAs to
    # register an account.
    eab_kid = Column(String(512))
    eab_hmac_key_encrypted = Column(Text)

    # Preferred chain name, if the CA needs one. Usually empty.
    preferred_chain = Column(String(128))

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    # Result of the last credential test, so bad credentials show up now
    # rather than at the first renewal months later.
    last_tested_at = Column(DateTime)
    last_test_ok = Column(Boolean)
    last_test_error = Column(Text)

    certificates = relationship("Certificate", back_populates="authority")

    def has_credentials(self):
        return bool(self.eab_kid and self.eab_hmac_key_encrypted)


class Certificate(Base):
    """A TLS certificate served by the fleet.

    Only the node that owns the address in DNS can answer an http-01
    challenge, so that node is determined at each renewal (it can change),
    issues the cert, and the files are copied to the other nodes.
    """

    __tablename__ = "certificates"

    id = Column(Integer, primary_key=True)
    name = Column(String(253), unique=True, nullable=False, index=True)

    domains = Column(Text, nullable=False, default="[]")   # json list

    # letsencrypt, uploaded, or self_signed
    source = Column(String(20), default="letsencrypt")

    challenge_type = Column(String(20), default="http-01")
    dns_plugin = Column(String(40))
    dns_credentials_encrypted = Column(Text)

    # Issuing CA, empty for Let's Encrypt. Renewal uses the same CA.
    authority_id = Column(Integer, ForeignKey("certificate_authorities.id",
                                              ondelete="RESTRICT"))
    authority = relationship("CertificateAuthority", back_populates="certificates")
    dns_propagation_seconds = Column(Integer, default=60)

    key_type = Column(String(10), default="ecdsa")

    not_before = Column(DateTime)
    not_after = Column(DateTime)
    issuer = Column(String(255))
    serial = Column(String(128))
    fingerprint = Column(String(128))

    # OCSP responder URL from the cert, read at issue time. Stapling is only
    # configured when present; Let's Encrypt has dropped OCSP, and nginx
    # warns on every reload if stapling is set without a responder.
    ocsp_url = Column(String(255))

    # Which node issued it and what DNS said then, for troubleshooting.
    issued_by_node = Column(String(64))
    issued_from_ip = Column(String(45))
    resolved_ips = Column(Text)          # json list of what DNS returned

    auto_renew = Column(Boolean, default=True)
    renew_days_before = Column(Integer, default=30)

    last_renewal_attempt = Column(DateTime)
    last_renewal_success = Column(DateTime)
    last_renewal_error = Column(Text)
    renewal_failures = Column(Integer, default=0)

    # JSON of node name to checksum of the copy it holds.
    synced_nodes = Column(Text, default="{}")

    # Whether the cert files were on disk at the last check. A node restored
    # from an old backup or rebuilt without /etc/letsencrypt can have the
    # row but not the files, and nginx will not load a config pointing at
    # missing files.
    files_present = Column(Boolean, default=True)
    files_checked_at = Column(DateTime)

    # Whether DNS points at one of our nodes. If not, http-01 renewal will
    # fail later, so warn now while the cert is still valid.
    dns_ok = Column(Boolean, default=True)
    dns_warning = Column(Text)
    dns_checked_at = Column(DateTime)

    # Uploaded cert material, so every node can serve it. The key is
    # encrypted with the node secret.
    uploaded_fullchain = Column(Text)
    uploaded_privkey_encrypted = Column(Text)

    # Pending CSR awaiting the CA. The private key is already in
    # uploaded_privkey_encrypted. With no not_after yet, `usable` is False
    # and the renderer skips it.
    csr_pem = Column(Text)
    csr_created_at = Column(DateTime)

    def has_material(self) -> bool:
        """True if the cert and key are stored in the database.

        Uploaded, self signed and completed CSR certs can be rewritten to
        any node from the database. Let's Encrypt certs live in certbot's
        directory on the issuing node and cannot.
        """
        return bool(self.uploaded_fullchain and self.uploaded_privkey_encrypted)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    hosts = relationship("VirtualHost", back_populates="cert")

    def domain_list(self):
        return json_get(self.domains, [])

    def sync_map(self):
        return json_get(self.synced_nodes, {})

    def resolved_ip_list(self):
        return json_get(self.resolved_ips, [])

    @property
    def usable(self) -> bool:
        """Safe to reference from nginx: issued and files present.

        Otherwise the https block is omitted rather than rendered with
        missing paths.
        """
        return bool(self.not_after) and self.files_present is not False

    @property
    def days_left(self):
        if not self.not_after:
            return None
        na = self.not_after
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        return (na - utcnow()).days

    @property
    def needs_renewal(self):
        if not self.auto_renew or self.source != "letsencrypt":
            return False
        if not self.not_after:
            return False
        na = self.not_after
        if na.tzinfo is None:
            na = na.replace(tzinfo=timezone.utc)
        # Compare the exact time left, the way certbot does.  days_left drops
        # the hours, so 30 days and 5 hours counted as due here while certbot
        # said "not yet due" and kept the old certificate.
        return na - utcnow() <= timedelta(days=self.renew_days_before or 30)

    @property
    def status(self):
        left = self.days_left
        if left is None:
            return "unknown"
        if left < 0:
            return "expired"
        if left <= 7:
            return "critical"
        if left <= (self.renew_days_before or 30):
            return "expiring"
        return "valid"


# ==============================================================================
# People and what they did
# ==============================================================================

class User(Base):
    """A user account.

    Local accounts are the break glass path for when the identity provider
    is down, and always require TOTP.
    """

    __tablename__ = "users"

    id = Column(Integer, primary_key=True)
    username = Column(String(64), unique=True, nullable=False, index=True)
    email = Column(String(255))
    full_name = Column(String(255))

    source = Column(Enum(AuthSource), default=AuthSource.LOCAL)
    role = Column(Enum(UserRole), default=UserRole.VIEWER)

    password_hash = Column(String(255))
    totp_secret_encrypted = Column(Text)

    # Last TOTP time step accepted. Codes at or below it are rejected, so a
    # code cannot be replayed within its validity window (RFC 6238 5.2).
    totp_last_step = Column(Integer)
    totp_enrolled = Column(Boolean, default=False)

    # Hashed, single use recovery codes.
    recovery_codes = Column(Text, default="[]")

    enabled = Column(Boolean, default=True)
    must_change_password = Column(Boolean, default=False)

    failed_attempts = Column(Integer, default=0)
    locked_until = Column(DateTime)
    last_login_at = Column(DateTime)
    last_login_ip = Column(String(45))

    oidc_subject = Column(String(255), index=True)

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    created_by = Column(String(64))

    @property
    def is_locked(self):
        if not self.locked_until:
            return False
        lu = self.locked_until
        if lu.tzinfo is None:
            lu = lu.replace(tzinfo=timezone.utc)
        return lu > utcnow()

    def can_write(self):
        return self.role in (UserRole.ADMIN, UserRole.OPERATOR)

    def is_admin(self):
        return self.role == UserRole.ADMIN


class Session(Base):
    """A browser session, stored server side so it can be revoked."""

    __tablename__ = "sessions"

    id = Column(Integer, primary_key=True)
    token_hash = Column(String(64), unique=True, nullable=False, index=True)
    user_id = Column(Integer, ForeignKey("users.id", ondelete="CASCADE"), nullable=False)
    user = relationship("User")

    created_at = Column(DateTime, default=utcnow)
    last_seen_at = Column(DateTime, default=utcnow)
    expires_at = Column(DateTime, nullable=False)

    ip_address = Column(String(45))
    user_agent = Column(String(500))

    revoked = Column(Boolean, default=False)
    revoked_reason = Column(String(255))

    @property
    def is_valid(self):
        exp = self.expires_at
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return not self.revoked and exp > utcnow()


class AuditLog(Base):
    """Who did what, when, and from where. Append only."""

    __tablename__ = "audit_log"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)

    username = Column(String(64), index=True)
    user_role = Column(String(20))
    source_ip = Column(String(45))
    node_name = Column(String(64))

    action = Column(String(64), nullable=False, index=True)
    object_type = Column(String(64))
    object_name = Column(String(255))

    # JSON with before and after values.
    changes = Column(Text)

    result = Column(String(20), default="success")
    detail = Column(Text)

    config_version = Column(Integer)

    def change_map(self):
        return json_get(self.changes, {})


class SystemSetting(Base):
    """Settings editable from the GUI, stored in the database."""

    __tablename__ = "system_settings"

    key = Column(String(128), primary_key=True)
    value = Column(Text)
    encrypted = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))


class HealthEvent(Base):
    """A backend state change.

    Kept out of the audit log so high volume machine events do not bury
    user actions.
    """

    __tablename__ = "health_events"

    id = Column(Integer, primary_key=True)
    timestamp = Column(DateTime, default=utcnow, index=True)

    pool_name = Column(String(128), index=True)
    member_address = Column(String(255))
    node_name = Column(String(64))

    old_state = Column(String(20))
    new_state = Column(String(20))
    reason = Column(Text)
    response_ms = Column(Float)

    __table_args__ = (
        Index("ix_health_pool_time", "pool_name", "timestamp"),
    )


def _looks_like_address(value: str) -> bool:
    """True for an IP address (IPv6 may be bracketed), False for a name."""
    candidate = str(value).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False
