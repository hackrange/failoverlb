"""
The database tables.

A few things worth knowing before you read this:

Feature settings live in JSON columns, not in a column per setting.  There are
a couple hundred nginx directives we can turn on, and a table with 200 mostly
empty columns would be miserable to work with and would need a migration every
time somebody wants one more option.  The catalog in app/catalog/ is what says
which keys are legal and how to check them, so the JSON is not a free for all.

Every table that ends up as nginx config has a config_version stamped on it.
That is how a node knows whether it is caught up, and it is what the pending
change queue counts against.
"""

import enum
import json
from datetime import datetime, timezone

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
    """
    JSON in a text column.

    SQLAlchemy has a JSON type, but sqlite handles it as text anyway and this
    version gives us a spot to put a sane default when a row has null in it.
    """


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
    DEGRADED = "degraded"    # answers us, but its nginx is unhappy
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
    """
    One nginx box in the fleet.

    Every node has a row for itself and a row for each of its peers.  They all
    keep their own copy, which is why losing one does not lose the roster.
    """

    __tablename__ = "nodes"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False, index=True)
    address = Column(String(255), nullable=False)
    peer_port = Column(Integer, default=8444)
    gui_port = Column(Integer, default=8443)

    # Higher number wins the election.  Ties break on name so the answer is
    # always the same one, never random.
    priority = Column(Integer, default=100)

    role = Column(Enum(NodeRole), default=NodeRole.UNKNOWN)
    state = Column(Enum(NodeState), default=NodeState.JOINING)

    # Set when an admin pins this node out of the running.  A node in standby
    # on purpose never gets elected, which is what you want while you patch it.
    forced_standby = Column(Boolean, default=False)

    # Trust.  The fingerprint is what we check the peer cert against, and the
    # hmac key signs each message on top of the TLS, so we know which node sent
    # it and not just that some cluster member did.
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

    # Sync tracking.  applied_version against the cluster's current version is
    # what tells you a node is behind.
    applied_version = Column(Integer, default=0)
    applied_checksum = Column(String(64))
    last_heartbeat = Column(DateTime)
    last_sync_at = Column(DateTime)
    last_error = Column(Text)

    # Health of the nginx service on that box
    nginx_active = Column(Boolean, default=False)
    nginx_config_ok = Column(Boolean, default=False)
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
    """
    A one time ticket that lets a new box into the cluster.

    Short lived and single use.  Anybody holding one of these can get a signed
    peer cert, so they are as good as a password.  We keep only the hash, the
    same as we do for passwords.
    """

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
    """
    A numbered snapshot of the whole config.

    Every change bumps the number.  The snapshot is the full state, not a diff,
    which makes catching a node up simple: hand it the newest snapshot and it
    is done, no replaying a chain of edits in the right order.
    """

    __tablename__ = "config_versions"

    id = Column(Integer, primary_key=True)
    version = Column(Integer, unique=True, nullable=False, index=True)

    # sha256 of the rendered files.  Two nodes with the same checksum are
    # serving the same config, full stop.
    checksum = Column(String(64), nullable=False)

    snapshot = Column(Text, nullable=False)      # json of every object
    rendered = Column(Text)                      # json of path to file contents

    author = Column(String(64))
    summary = Column(String(500))
    created_at = Column(DateTime, default=utcnow, index=True)

    # Which node authored it, so a split brain merge can tell them apart.
    origin_node = Column(String(64))

    applied = Column(Boolean, default=False)
    applied_at = Column(DateTime)


class PendingChange(Base):
    """
    A change that has not made it to a node yet.

    This is what happens when a box is down during an apply.  Instead of
    refusing the change or quietly letting that node drift, we write the target
    version here.  When the node comes back the sync worker walks the queue,
    pushes the newest version, and clears the whole backlog at once.
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
    """
    One site.  Turns into a server block.

    The settings column holds everything from the catalog: body size limits,
    rate limits, timeouts, headers, all of it.  See app/catalog/ for the keys
    and what each one does.
    """

    __tablename__ = "virtual_hosts"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, default=True)

    # server_name.  A json list, since a site usually answers to more than one.
    server_names = Column(Text, nullable=False, default='["_"]')

    listen_http = Column(Boolean, default=True)
    listen_https = Column(Boolean, default=True)
    http_port = Column(Integer, default=80)
    https_port = Column(Integer, default=443)
    default_server = Column(Boolean, default=False)

    # http2 is on by default when TLS is on.  http3 needs a build flag the
    # installer does not use right now, so the GUI hides it unless we see it.
    http2 = Column(Boolean, default=True)

    force_https = Column(Boolean, default=True)

    cert_id = Column(Integer, ForeignKey("certificates.id", ondelete="SET NULL"))
    cert = relationship("Certificate", back_populates="hosts")

    # What this site does.  proxy sends to a pool, static serves files,
    # redirect just bounces, php goes to fastcgi.
    mode = Column(String(20), default="proxy")

    pool_id = Column(Integer, ForeignKey("pools.id", ondelete="SET NULL"))
    pool = relationship("Pool", back_populates="hosts")

    document_root = Column(String(500))
    redirect_target = Column(String(500))
    redirect_code = Column(Integer, default=301)

    settings = Column(Text, default="{}")

    # Which access list guards this site.  Straight from the ask: the box you
    # manage from should never get blocked by an ACL you wrote for the public.
    access_list_id = Column(Integer, ForeignKey("access_lists.id", ondelete="SET NULL"))
    access_list = relationship("AccessList")

    # Lock the whole site down to the management allow list.  Handy for a
    # staging site or an admin panel that should never face the internet.
    admin_only = Column(Boolean, default=False)

    # Free text nginx that goes in the server block.  We still run nginx -t on
    # it, so a typo cannot take the fleet down, but it is your rope.
    custom_config = Column(Text)

    # gui or raw.
    #
    # gui means this site is built from the settings above and the custom_config
    # is appended to it.  raw means the person is writing the whole server block
    # themselves and we write out exactly what they typed.
    #
    # Raw still goes through the same two phase apply, so "I am driving" does
    # not mean "I can take the fleet down".  Every node still has to pass
    # nginx -t on it before any node applies it.
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
    """
    A location block inside a site.

    Most sites are fine with just the one at /.  You add more when part of the
    site goes somewhere else: /api to one pool, /static off the disk, /ws to a
    websocket backend with a much longer timeout.
    """

    __tablename__ = "locations"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"), nullable=False)
    host = relationship("VirtualHost", back_populates="locations")

    path = Column(String(500), nullable=False, default="/")

    # exact (=), prefix, preferential (^~), regex (~), regex_i (~*)
    match_type = Column(String(20), default="prefix")

    # Order matters for prefix matches in nginx, so we keep it explicit rather
    # than hoping the database hands rows back the same way twice.
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

    custom_config = Column(Text)
    enabled = Column(Boolean, default=True)

    def setting_map(self):
        return json_get(self.settings, {})


# ==============================================================================
# Backend pools
# ==============================================================================

class Pool(Base):
    """
    A group of backends.  Turns into an upstream block.

    Two different things watch these servers and it helps to keep them straight:

      nginx itself does passive checks.  It notices a request failed and stops
      sending traffic there for a while.  That is max_fails and fail_timeout,
      and it is all the free version gives you.

      We do active checks on top.  The manager reaches out to every backend on
      a schedule whether or not anybody is browsing the site.  When one goes
      bad we rewrite the upstream with that server marked down and reload.
      That is how you get real health checking without paying for Plus.
    """

    __tablename__ = "pools"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # round_robin, least_conn, ip_hash, hash, random, random_two, fair
    #
    # least_time and its random variant are Plus only, so they are not here.
    # The catalog explains what to use instead.
    lb_method = Column(String(32), default="round_robin")

    # Only read when lb_method is hash.  Something like $request_uri.
    hash_key = Column(String(255))
    hash_consistent = Column(Boolean, default=False)

    # Keeping connections open to the backend is one of the biggest easy wins
    # there is, especially over TLS where you skip the handshake every time.
    keepalive = Column(Integer, default=32)
    keepalive_requests = Column(Integer, default=1000)
    keepalive_timeout = Column(String(20), default="60s")

    # Shared memory so all the workers agree on what is up and what is down.
    # Without this each worker keeps its own count and they disagree.
    zone_size = Column(String(20), default="64k")

    # Active checks, our own
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

    # Do not let a bad check take the whole pool out.  If applying the downs
    # would leave fewer than this many servers up, we leave them all in and
    # shout instead.  A pool serving errors beats a pool serving nothing.
    min_healthy_members = Column(Integer, default=1)

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

    # Backup servers sit idle until every normal one is down.  This is the free
    # version's answer to priority groups.  Good for a static "sorry we are
    # down" box that only shows up when the real ones are gone.
    backup = Column(Boolean, default=False)

    # Passive checks, done by nginx while serving real traffic
    max_fails = Column(Integer, default=3)
    fail_timeout = Column(String(20), default="10s")
    max_conns = Column(Integer, default=0)   # 0 means no limit

    enabled = Column(Boolean, default=True)

    # Where the admin put it: up, down, draining, maintenance.  Separate from
    # what the health check thinks, since a person taking a box out for patching
    # should not get undone by a check that happens to pass.
    admin_state = Column(String(20), default="up")

    # What the checks say
    state = Column(Enum(MemberState), default=MemberState.UNKNOWN)
    consecutive_ok = Column(Integer, default=0)
    consecutive_fail = Column(Integer, default=0)
    last_check_at = Column(DateTime)
    last_state_change = Column(DateTime)
    last_error = Column(Text)
    last_response_ms = Column(Float)

    # Rolling numbers so the GUI can show whether a backend is getting slower
    avg_response_ms = Column(Float)
    check_count = Column(Integer, default=0)
    fail_count = Column(Integer, default=0)

    # Which pool member health checks came from which node.  A backend can be
    # reachable from one load balancer and not another, and knowing that is
    # usually the whole answer to why a site is flaky.
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
        """
        What we actually tell nginx.

        An admin saying a box is out beats a health check saying it is fine.
        People take servers out for a reason, and a check that passes anyway
        should not put it back in the rotation behind their back.
        """
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
    """
    A named allow and deny list you can reuse across sites.

    Straight out of the requirement about whitelisting the management box.  The
    include_management flag is the important one: turn it on and every cluster
    node's address gets folded in automatically.  Add a node later and it lands
    in the list without anybody remembering to go update it.
    """

    __tablename__ = "access_lists"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False)
    description = Column(String(500))

    # json lists of CIDRs
    allow_entries = Column(Text, default="[]")
    deny_entries = Column(Text, default="[]")

    # Whether to allow or deny anything not matched above
    default_action = Column(String(10), default="deny")

    include_management = Column(Boolean, default=True)

    # Basic auth on top of the IP rules, if you want both
    basic_auth_enabled = Column(Boolean, default=False)
    basic_auth_realm = Column(String(255), default="Restricted")
    basic_auth_users = Column(Text, default="[]")   # json of user and hash

    # Look at the real client address instead of the proxy in front of us.
    # Turn this on only when something you trust is actually in front, since a
    # client can send this header itself and lie about who it is.
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


class RateLimitZone(Base):
    """
    A named rate limit that sites can point at.

    nginx wants these declared once at the http level and then used down in the
    server or location blocks.  Keeping them as their own objects means a
    handful of sites can share one bucket, which is usually what you want for
    something like a login endpoint.
    """

    __tablename__ = "rate_limit_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    # What we count per.  $binary_remote_addr is by client IP and is the usual
    # pick.  It is the packed form of the address, so it takes way less memory
    # than $remote_addr, which matters when the zone holds a million of them.
    key = Column(String(255), default="$binary_remote_addr")

    zone_size = Column(String(20), default="10m")

    # Requests per second or per minute
    rate = Column(String(20), default="10r/s")

    created_at = Column(DateTime, default=utcnow)


class ConnLimitZone(Base):
    """Same idea as a rate limit zone, but counting connections open at once."""

    __tablename__ = "conn_limit_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))
    key = Column(String(255), default="$binary_remote_addr")
    zone_size = Column(String(20), default="10m")
    created_at = Column(DateTime, default=utcnow)


class CacheZone(Base):
    """
    A proxy cache.

    Caching in front of a slow backend is the single biggest speedup most sites
    can get.  The catch is that the folder has to exist and be writable before
    nginx starts, so the manager makes it through the agent when you save this.
    """

    __tablename__ = "cache_zones"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    path = Column(String(500), nullable=False, default="/var/cache/nginx/proxy")

    # How the folder tree gets laid out.  1:2 means one character, then two.
    # Spreading files out keeps any single folder from getting huge and slow.
    levels = Column(String(20), default="1:2")

    # Memory for the key index, not the cached files themselves.  1m of keys is
    # roughly 8000 entries.
    keys_zone_size = Column(String(20), default="10m")

    # Cap on disk used by the actual cached bodies
    max_size = Column(String(20), default="1g")

    # Throw out anything not touched in this long, even if there is room
    inactive = Column(String(20), default="60m")

    use_temp_path = Column(Boolean, default=False)

    created_at = Column(DateTime, default=utcnow)


class StreamServer(Base):
    """
    Plain TCP or UDP proxying.  No http involved.

    The installer builds --with-stream, so this works.  Use it for a database
    port, a mail server, a syslog collector, anything that is not a web
    request.  ssl_preread is in there too, which lets you route by the TLS
    name without decrypting anything.
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
    """
    A map block.

    This is nginx's lookup table.  You give it an input variable and a list of
    matches, and it sets an output variable.  It is how you do conditional
    things without piling up if statements, which nginx handles badly inside
    location blocks.
    """

    __tablename__ = "map_blocks"

    id = Column(Integer, primary_key=True)
    name = Column(String(64), unique=True, nullable=False)
    description = Column(String(500))

    source_variable = Column(String(255), nullable=False, default="$http_user_agent")
    result_variable = Column(String(64), nullable=False)
    default_value = Column(String(255), default='""')

    entries = Column(Text, default="[]")   # json list of match and value
    hostnames = Column(Boolean, default=False)

    created_at = Column(DateTime, default=utcnow)

    def entry_list(self):
        return json_get(self.entries, [])


# ==============================================================================
# Certificates
# ==============================================================================

class Certificate(Base):
    """
    A TLS cert the fleet serves.

    The tricky part this whole thing exists to solve: only the node that owns
    the public address in DNS can answer an http-01 challenge.  So we work out
    which node that is at renewal time, not once at the start, because it moves.
    Then that node gets the cert and we copy the files to everybody else.
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
    dns_propagation_seconds = Column(Integer, default=60)

    key_type = Column(String(10), default="ecdsa")

    not_before = Column(DateTime)
    not_after = Column(DateTime)
    issuer = Column(String(255))
    serial = Column(String(128))
    fingerprint = Column(String(128))

    # Which node got the cert last time, and what DNS said at that moment.
    # Keeping both means you can look back and see why it picked that box.
    issued_by_node = Column(String(64))
    issued_from_ip = Column(String(45))
    resolved_ips = Column(Text)          # json list of what DNS returned

    auto_renew = Column(Boolean, default=True)
    renew_days_before = Column(Integer, default=30)

    last_renewal_attempt = Column(DateTime)
    last_renewal_success = Column(DateTime)
    last_renewal_error = Column(Text)
    renewal_failures = Column(Integer, default=0)

    # Which nodes have the current copy.  json of node name to checksum.
    synced_nodes = Column(Text, default="{}")

    # Whether the files were actually there last time we looked, and when.
    #
    # The database saying a certificate exists is not the same as the files
    # being on disk.  A node restored from a backup that predates the
    # certificate, or rebuilt without /etc/letsencrypt, has the row and not the
    # files.  Rendering a config that points at files which are not there means
    # nginx refuses to load, and then nothing can be applied anywhere until
    # somebody works out why.
    files_present = Column(Boolean, default=True)
    files_checked_at = Column(DateTime)

    # For an uploaded cert, we keep the material here so the fleet can serve it
    # everywhere.  The key is encrypted with the node secret.
    uploaded_fullchain = Column(Text)
    uploaded_privkey_encrypted = Column(Text)

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
        """
        Is this certificate safe to point nginx at.

        Needs both an issue date, meaning it was actually obtained, and the
        files still being there.  Either missing and the https block gets left
        out rather than written with paths that do not resolve.
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
        left = self.days_left
        return left is not None and left <= (self.renew_days_before or 30)

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
    """
    An account.

    Local accounts are the break glass path.  They keep working when the
    identity provider is down, which is the entire reason they exist.  They
    have to have TOTP on, no exceptions, because a local account with just a
    password is the weakest way into this thing.
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
    totp_enrolled = Column(Boolean, default=False)

    # One time codes for when somebody loses their phone.  Hashed, single use.
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
    """
    A logged in browser.

    Kept in the database, not just signed in a cookie, so an admin can kick
    somebody out right now.  A signed cookie you cannot revoke is fine until
    the day you need to revoke one.
    """

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
    """
    Who did what, when, from where.

    Append only.  Nothing in the app updates or deletes these rows.  When
    somebody asks why the site went down at 2am, this is the answer.
    """

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

    # What changed.  json with before and after.
    changes = Column(Text)

    result = Column(String(20), default="success")
    detail = Column(Text)

    config_version = Column(Integer)

    def change_map(self):
        return json_get(self.changes, {})


class SystemSetting(Base):
    """
    Settings that live in the database instead of the environment.

    Anything an admin should be able to change from the GUI without editing a
    file and restarting a container goes here.
    """

    __tablename__ = "system_settings"

    key = Column(String(128), primary_key=True)
    value = Column(Text)
    encrypted = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)
    updated_by = Column(String(64))


class HealthEvent(Base):
    """
    A backend changed state.

    Separate from the audit log because these are machine generated and there
    are a lot more of them.  Mixing them in would bury the human actions.
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
