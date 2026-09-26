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
import ipaddress
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

    # Whether that node's own public listener actually answered a request.
    #
    # Not the same question as nginx_active, and the difference is the whole
    # reason this column exists.  nginx_active is `systemctl is-active nginx`,
    # which says the service is running.  A wedged nginx is running: on
    # 24 August 2026 the master held its listening sockets while every worker
    # sat blocked on a shared memory lock left locked by one that had died, so
    # systemd said `active`, the kernel completed handshakes, and clients got
    # silence for 73 minutes.  The GSLB went on handing that node out because
    # the only signal it had was the one that could not see this.
    #
    # None means the node has not said yet, which is not the same as no.  A
    # node is never withdrawn from a DNS answer for having stayed quiet about
    # this, or a fleet part way through an upgrade would take itself off the
    # internet one node at a time.
    nginx_serving = Column(Boolean, default=None)
    nginx_serving_detail = Column(String(255))

    # Whether nginx on that node has actually been told the WAF module exists.
    #
    # Separate from the module list, and it has to be.  The module list is read
    # out of `nginx -V`, which says what was **compiled in**.  It says nothing
    # about whether a load_module line was ever written, and a module that is
    # built but not loaded is not a module nginx knows about: the first thing
    # that uses it fails the config test with `unknown directive`, and an apply
    # is all or nothing, so that is the whole fleet.
    #
    # None means the node has not said yet, which is not the same as no.
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

    # The same render, but with every enabled backend treated as healthy.
    #
    # There are two because they answer different questions.  The one above
    # answers "are these nodes serving the same bytes", which has to include
    # health, since a backend marked down really is different config.  This one
    # answers "has a person changed something since the last apply", and health
    # has no business in that: backends flap on their own all day, the health
    # checker applies those changes itself, and counting them as somebody's
    # unfinished work puts a banner in front of them about a change they did not
    # make and cannot usefully apply.
    user_checksum = Column(String(64))

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

    # Send every other name to the first one with a 301.
    #
    # Serving two names is not the same as choosing one.  A site answering on
    # both example.com and www.example.com has two of every page as far as a
    # search engine is concerned, and people expect to pick a canonical one.
    # The first name in server_names is the one kept, so the direction is
    # decided by putting the winner first, which means one switch does both
    # www to bare and bare to www.
    redirect_to_primary = Column(Boolean, default=False)

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

    # Which custom error page this site shows.  SET NULL rather than a refusal,
    # because a template going missing has to drop the site back to the stock
    # nginx page and not stop the site rendering at all.
    error_page_template_id = Column(
        Integer, ForeignKey("error_page_templates.id", ondelete="SET NULL")
    )
    error_page_template = relationship("ErrorPageTemplate")

    # Lock the whole site down to the management allow list.  Handy for a
    # staging site or an admin panel that should never face the internet.
    admin_only = Column(Boolean, default=False)

    # Terminate TLS and change nothing else.
    #
    # The job people actually arrive with: a site that already works, in front
    # of which they want a load balancer holding the certificate, with the
    # application's own headers reaching the browser exactly as it sent them.
    # Without this it is a dozen settings across three pages, every one of them
    # a default that is right for a site you own and wrong for one you are only
    # carrying traffic for, and the way you find out you missed one is a
    # Content-Security-Policy that no longer matches the application.
    #
    # One switch instead, and the renderer forces the lot.  What it covers is
    # OFFLOAD_ONLY_FORCES in the renderer, next to the reasons for what it
    # leaves alone.  It forces rather than clears, so turning it off gives the
    # site back the settings it had.
    tls_offload_only = Column(Boolean, default=False)

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

    # A different error page for this path than the rest of the site gets.
    #
    # "The whole site except the health check" is the normal ask, and the health
    # check is the thing that breaks first when somebody forgets it.  Empty
    # means this path shows whatever the site shows.
    error_page_template_id = Column(
        Integer, ForeignKey("error_page_templates.id", ondelete="SET NULL")
    )
    error_page_template = relationship("ErrorPageTemplate")

    custom_config = Column(Text)
    enabled = Column(Boolean, default=True)

    # Take this location's path off the front before sending the request on.
    # Off by default, because passing the path through whole is what most
    # backends expect.  Turn it on when a backend is being mounted under a
    # prefix it knows nothing about, which is the usual reason for a location
    # like /lb in the first place.
    strip_prefix = Column(Boolean, default=False)

    # Serve a whole site that thinks it lives at its own root under this path.
    #
    # This is strip_prefix and then everything else that turns out to be needed,
    # which is the part nobody expects.  A site mounted under /shop still writes
    # its own links from the root, so the page arrives styled by a stylesheet at
    # /assets that this site does not serve, and every link leaves the mount.
    # Its redirects name the host without the prefix, so the first URL missing a
    # trailing slash sends the visitor off the mount for good.
    #
    # Every one of those repairs is derivable from the path, so none of them is a
    # question worth asking.  The renderer builds them in _mount_settings.
    #
    # Separate from strip_prefix rather than replacing it, because taking the
    # path off is still right on its own for an API or a health check, where
    # there is no HTML and nothing to rewrite.
    mount_site = Column(Boolean, default=False)

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

    # ---- talking to the backend over TLS ------------------------------------
    # Off means we proxy with plain http, which is right for a backend on a
    # network you trust.  On means https, for a backend that only speaks TLS or
    # one you reach across something you do not trust.
    #
    # Sending plain http at a TLS port does not fail in a way anybody enjoys.
    # The backend answers 400 and the error says nothing about the scheme.
    backend_tls = Column(Boolean, default=False)

    # Has anybody actually chosen, or are we still guessing from the port.
    # Without this we could not tell "off because they left it alone" from "off
    # because they turned it off", and we would keep switching it back on under
    # somebody who meant it.
    backend_tls_set = Column(Boolean, default=False)

    # What is on the other end, which decides a handful of fiddly things that
    # nobody should have to set one at a time.
    #
    #   servers: boxes running your app.  They answer to whatever name the
    #            visitor asked for, so the Host header is passed straight
    #            through and their redirects already point at your site.
    #   site:    somebody else's website, on its own name.  It only answers to
    #            that name, so the Host header has to be that name, and its
    #            redirects point at itself and have to be pointed back.
    #
    # Getting this wrong does not fail loudly.  It serves the backend's default
    # site, or bounces your visitor onto the backend's own address, and both
    # look like the proxy working.
    backend_kind = Column(String(20), default="servers")   # servers, site

    # Encrypting the hop and checking who is on the far end of it are two
    # different things.  On by default, because a proxy that would talk to
    # anybody holding any certificate is not doing the job people assume it is.
    backend_tls_verify = Column(Boolean, default=True)

    # Blank means the system CA bundle, which is what a public certificate
    # needs.  Point it at your own CA file for an internal one.  nginx ships no
    # default here, so leaving it out makes verification fail rather than pass.
    backend_tls_ca = Column(String(500))

    # Which name to put in SNI and check the backend's certificate against.
    #
    # This needs saying because nginx's default is wrong for us.  It sends the
    # host from proxy_pass, and ours is the upstream block's name, so a pool
    # called websec_pool would offer "websec_pool" as the server name.  No
    # backend has a certificate for that.
    #
    # Blank means work it out from the members, which is right nearly always,
    # since the members of a pool serve the same site and present the same
    # certificate.  Set it when they do not.
    backend_tls_name = Column(String(255))

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

    # ---- backend trust ------------------------------------------------------
    # A shared secret nginx puts on every request it proxies to this pool.  The
    # backend checks it and refuses anything without it, so somebody who finds
    # the app server's address cannot just talk to it directly.
    #
    # This is a bearer secret.  Anybody holding it can pretend to be the fleet,
    # so if the hop to the backend crosses anything you do not trust, run that
    # hop over TLS as well.  It is not a replacement for a firewall, it is the
    # thing that catches what the firewall missed.
    #
    # Three slots, because rotating a shared secret safely takes two steps.  You
    # cannot change both ends at once, and nginx can only send one value:
    #
    #   1. Stage a new one.  nginx keeps sending the old one, so nothing breaks.
    #      Add the new one to your backends so they accept either.
    #   2. Activate.  nginx starts sending the new one, which the backends
    #      already take.  The old one moves to previous so you know what to go
    #      and delete.
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
    # These decrypt on the way out.  Everything that renders config or sends a
    # health check goes through here, so the plaintext is never sitting on the
    # model waiting to be logged by accident.

    def _read_token(self, column_value):
        if not column_value:
            return None
        from app.core.crypto import decrypt
        try:
            return decrypt(column_value)
        except Exception:
            # A token we cannot decrypt means the secret key changed under us.
            # Returning None makes the renderer leave the header off, which
            # fails closed: the backend rejects us and somebody notices, rather
            # than us shipping a garbage header and calling it fine.
            return None

    @property
    def token(self):
        """The value nginx should be sending right now."""
        return self._read_token(self.token_encrypted)

    @property
    def token_next(self):
        """Staged but not live yet.  Put this on your backends before you activate."""
        return self._read_token(self.token_next_encrypted)

    @property
    def token_previous(self):
        """What we sent before the last activate.  Safe to delete from backends."""
        return self._read_token(self.token_previous_encrypted)

    @property
    def token_active(self):
        """Is this pool actually sending a token?  Both halves have to be true."""
        return bool(self.token_enabled and self.token_encrypted)

    @property
    def token_rotation_pending(self):
        return bool(self.token_next_encrypted)

    @property
    def uses_backend_tls(self):
        """
        Are we talking to these backends over https.

        Until somebody says otherwise we go by the port.  A member on 443 is
        speaking TLS in every setup anybody actually runs, and sending plain
        http at it gets a 400 whose message says nothing about the scheme, so
        the person who added the member gets to debug a made up problem.

        The moment anybody touches the switch we stop guessing and do what they
        said, forever, including turning it off with a 443 member sitting there.
        Guessing is for the setup nobody has thought about yet.
        """
        if self.backend_tls_set:
            return bool(self.backend_tls)
        return any(m.enabled and m.port == 443 for m in self.members)

    @property
    def backend_name(self):
        """
        The backend's own hostname, when it has one.

        Used for SNI, for checking its certificate, and for the Host header when
        this pool is somebody else's site.  What was typed wins, otherwise the
        first enabled member that is a name rather than an address, since the
        members of a pool answer to the same name.
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
        """
        What the health checker should really speak.

        An http check against a TLS backend fails every time, which marks every
        member down and takes the pool out.  Defaulting the traffic to https and
        leaving the check on http would hand somebody a pool that goes dark the
        moment they add a backend, so the check follows the same guess.

        Only the plain http default moves.  Somebody who picked tcp or https
        picked it on purpose and we leave it be.
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

    # Why this member was marked down, captured at the moment it went down and
    # then left alone until it comes back up.
    #
    # Separate from last_error, which is rewritten by every failing check.  The
    # rendered upstream carries this reason as a comment, so using last_error
    # there meant the config changed whenever the wording of the error changed,
    # even though nothing about the member had.  That defeats the "nothing
    # actually changed" test an apply does before reloading nginx, and turns an
    # unrelated apply into a reload nobody asked for.
    down_reason = Column(String(255))

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


class ErrorPageTemplate(Base):
    """
    A custom error page, written once and pointed at by any number of sites.

    The status code is not part of the template.  One template answers for 404,
    500, 502 and the rest, with the code and its description dropped in where
    the template asks for them.  That is the whole reason these are their own
    objects: without it you are back to a page per code per site, which is how
    they drift apart, and a page owned by one site has to be copied by hand for
    every other site that wants the same look.
    """

    __tablename__ = "error_page_templates"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # The HTML somebody wrote, with our placeholders still in it.
    #
    # Placeholders are filled in by plain string swaps at render time and never
    # by a template engine.  This text comes out of a form on a page, and an
    # engine that can evaluate an expression turns that form into a way of
    # reading the manager's own process.  There are four swaps, they are listed
    # in render.py, and nothing else in the text means anything.
    html = Column(Text, nullable=False, default="")

    # Which status codes this template answers for.  A json list of ints.
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
    """
    A picture an error page uses, kept here rather than as a file on disk.

    It goes into the HTML as a data URI when the page is rendered, so the
    finished page carries its own pictures and there is nothing else to fetch.

    That is deliberate and it settles three problems at once.  An error page
    that references a picture which is not there is a broken page at exactly
    the moment the site is already in trouble.  A folder of uploads is a second
    thing that has to replicate to every node and stay in step with the config.
    And serving uploads means a location with a path in it, which is a path
    somebody can try to walk out of.  Inlining has none of that.

    The cost is size, which is why uploads are capped.  A logo is a few
    kilobytes and base64 makes it a third bigger again, which is nothing next
    to being unable to fail.
    """

    __tablename__ = "error_page_images"

    id = Column(Integer, primary_key=True)
    template_id = Column(
        Integer,
        ForeignKey("error_page_templates.id", ondelete="CASCADE"),
        nullable=False,
    )
    template = relationship("ErrorPageTemplate", back_populates="images")

    # What the template calls it, in {{image:name}}.
    name = Column(String(128), nullable=False)

    # Worked out from the file's own first bytes, not from what the browser
    # claimed, because the browser is repeating whatever the uploader named it.
    content_type = Column(String(60), nullable=False)

    # base64, so the row travels through the same json the rest of a snapshot
    # goes through without anybody needing a binary path.
    data = Column(Text, nullable=False)
    size_bytes = Column(Integer, default=0)

    created_at = Column(DateTime, default=utcnow)


class GslbZone(Base):
    """
    A DNS zone this fleet answers for, so a name can follow the healthy nodes.

    This is the piece that makes traffic failover possible rather than only
    manager failover.  Everything else here can move which node is in charge of
    writing config, and none of it can move where the traffic goes, because
    that is decided by whatever the client resolved before it connected.

    The industry word is GSLB, global server load balancing.  F5 sell it as
    GTM, Citrix and most others call it GSLB.  The technique is the same
    everywhere: be authoritative for a name, know which things behind it are
    up, and answer with only those on a short TTL.

    Normally a child of a zone somebody already owns.  You keep example.com at
    your registrar or at Route 53, delegate `gslb.example.com` down to these
    boxes with NS records, and point the public names at it with CNAMEs.  That
    way a load balancer being unreachable costs you the names deliberately put
    behind it and not the whole domain.
    """

    __tablename__ = "gslb_zones"

    id = Column(Integer, primary_key=True)
    # The zone apex, stored without a trailing dot and matched case blind.
    name = Column(String(253), unique=True, nullable=False, index=True)
    enabled = Column(Boolean, default=True)
    description = Column(String(500))

    # The SOA.  A zone with no SOA is not a zone, and resolvers do read these:
    # the last field is how long a negative answer may be cached, which is what
    # decides how long a name that does not exist keeps not existing.
    soa_primary = Column(String(253))        # blank means the first nameserver
    soa_contact = Column(String(253), default="hostmaster")
    soa_refresh = Column(Integer, default=3600)
    soa_retry = Column(Integer, default=600)
    soa_expire = Column(Integer, default=604800)
    soa_minimum = Column(Integer, default=30)
    soa_serial = Column(Integer, default=1)

    # The nameservers this zone claims, as a json list of names.  These have to
    # match the NS records the parent zone delegates to, or resolvers get a
    # different answer depending on who they ask, which is a bad afternoon.
    nameservers = Column(Text, default="[]")

    created_at = Column(DateTime, default=utcnow)
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)

    records = relationship("GslbRecord", back_populates="zone",
                           cascade="all, delete-orphan")

    def nameserver_list(self):
        return json_get(self.nameservers, [])


class GslbRecord(Base):
    """
    One name inside a zone, and how to decide what to answer for it.

    The answers are not a fixed list.  Each one is tied to something whose
    health is known, and the ones that are not healthy are left out of the
    reply.  That is the whole feature: a client that resolves during an outage
    is told about the boxes that are actually up.
    """

    __tablename__ = "gslb_records"

    id = Column(Integer, primary_key=True)
    zone_id = Column(Integer, ForeignKey("gslb_zones.id", ondelete="CASCADE"),
                     nullable=False)
    zone = relationship("GslbZone", back_populates="records")

    # The label inside the zone.  "@" is the zone itself, "www" is
    # www.<zone>, and "*" is a wildcard.
    name = Column(String(253), nullable=False, default="@")
    enabled = Column(Boolean, default=True)
    description = Column(String(500))

    # A, AAAA or CNAME.  CNAME has no health behind it and is here because a
    # zone usually needs one or two.
    record_type = Column(String(10), default="A")

    # How long a resolver may keep the answer.  Short, because the whole point
    # is changing it.  Worth knowing that this is a request and not a rule:
    # resolvers clamp very low values, browsers cache separately, and some
    # runtimes cache for the life of the process.  Thirty seconds buys most
    # clients moving within a minute or two, and a tail that is worse.
    ttl = Column(Integer, default=30)

    # all      every healthy answer, which is round robin across what is up
    # failover the healthy answer with the lowest priority number, and only
    #          that one, so traffic sits on the primary until it goes away
    policy = Column(String(20), default="all")

    # What to do when nothing behind it is healthy.  Answering with everything
    # is usually right: a name that resolves to a broken box gives the visitor
    # an error they can retell, and a name that resolves to nothing looks to
    # them like the whole company has vanished.
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
    """
    One address this name could be answered with, and how we know it is alive.

    Tied to a cluster node by preference, because then the health is something
    this system already tracks minute by minute.  A plain address with no node
    behind it is allowed and is always treated as healthy, which is right for
    something outside the fleet that we have no way to check.
    """

    __tablename__ = "gslb_answers"

    id = Column(Integer, primary_key=True)
    record_id = Column(Integer, ForeignKey("gslb_records.id", ondelete="CASCADE"),
                       nullable=False)
    record = relationship("GslbRecord", back_populates="answers")

    # For an A or AAAA this is an address.  For a CNAME it is the target name.
    value = Column(String(253), nullable=False)

    # Which node's health decides whether this answer is given out.  Null means
    # nothing is watching it, and it is always handed out.
    node_id = Column(Integer, ForeignKey("nodes.id", ondelete="SET NULL"))

    # Which node this answer belongs to, by name.
    #
    # node_id above cannot be trusted once this row has travelled.  Node rows
    # are deliberately not replicated, because each box keeps its own view of
    # the cluster, so the ids are only meaningful in the database that issued
    # them.  This row is config and does replicate, and on the other node the
    # same id is a different machine.
    #
    # On a two node cluster the two mappings come out as exact mirror images:
    # every answer points at the other node.  The result is that when one node
    # dies, the survivor drops itself from the answer and keeps handing out the
    # address of the box that is down.  That is worse than having no failover
    # at all, and it only shows up during the failure it exists to handle.
    #
    # Names are unique across the fleet and mean the same thing everywhere.
    node_name = Column(String(64))
    node = relationship("Node")

    # Lower goes first under the failover policy.  Ignored by the others.
    priority = Column(Integer, default=10)
    enabled = Column(Boolean, default=True)

    created_at = Column(DateTime, default=utcnow)


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
    # Empty means empty.  This used to hold the two characters `""`, on the
    # reasoning that it was already written the way nginx wants, and the
    # renderer then quoted it again and the default became a literal pair of
    # quote marks.  Store the value, let the renderer do the quoting.
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
    """
    The one WireGuard network this fleet offers, and the range it lives in.

    One per fleet rather than one per workload.  Every node holds an address in
    it and every enrolled workload holds one, so a pool member reached through
    the tunnel is reachable from whichever node is serving.  A tunnel that only
    the active node could use would go dark at the first failover and look like
    the backend had died.

    The range is chosen by whoever runs this, because they are the only ones who
    know what is already in use on their network.  A range that collides with
    something they already run is the failure they cannot debug from here.
    """
    __tablename__ = "tunnel_networks"

    id = Column(Integer, primary_key=True)
    # RFC1918, and refused otherwise.  A tunnel handing out public addresses is
    # a routing accident waiting to happen.
    cidr = Column(String(64), nullable=False, default="10.77.0.0/24")
    listen_port = Column(Integer, default=51820)
    enabled = Column(Boolean, default=False)
    created_at = Column(DateTime, default=utcnow)

    # How far up the range addresses have been handed out.
    #
    # Kept so an address is not given to a second workload the moment the first
    # one is removed.  A pool member still pointing at it would then send
    # production traffic to a different machine, silently, and the only sign is
    # somebody remembering which workload used to be there.  Counting upward
    # costs a /24 nothing: 250 workloads before it matters, and the gaps are
    # still available once the top is reached.
    address_high_water = Column(Integer, default=0)

    peers = relationship("TunnelPeer", back_populates="network",
                         cascade="all, delete-orphan")


class TunnelNodeKey(Base):
    """
    One node's own key pair for the tunnel.

    Per node, never replicated.  The private half is generated on the box by the
    agent and never leaves it, which is the same rule the cluster's own keys
    follow.  Only the public half is shared, and only so a workload can be told
    who it is talking to.
    """
    __tablename__ = "tunnel_node_keys"

    id = Column(Integer, primary_key=True)
    node_name = Column(String(64), unique=True, nullable=False, index=True)
    public_key = Column(String(64), nullable=False)
    address = Column(String(64), nullable=False)     # this node's tunnel address
    endpoint = Column(String(255))
    # What an operator says workloads should dial, when the address we worked
    # out is not the one that works.  A name belongs here more often than an
    # address: wg resolves it when the interface comes up, so a dual stack
    # name lets each workload pick the family it actually has, which one
    # address never can.
    endpoint_override = Column(String(255))                   # what a workload dials
    updated_at = Column(DateTime, default=utcnow, onupdate=utcnow)


class TunnelPeer(Base):
    """
    One enrolled workload.

    It holds an address in the tunnel range and a public key it generated
    itself.  The private half never leaves the workload, which is why the script
    generates it there rather than this end handing one out.
    """
    __tablename__ = "tunnel_peers"

    id = Column(Integer, primary_key=True)
    network_id = Column(Integer, ForeignKey("tunnel_networks.id", ondelete="CASCADE"),
                        nullable=False)
    network = relationship("TunnelNetwork", back_populates="peers")

    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    address = Column(String(64), nullable=False, index=True)
    public_key = Column(String(64))

    # A WireGuard pre-shared key, and the only post quantum story WireGuard
    # has.
    #
    # The handshake is Curve25519, which a quantum computer breaks, and traffic
    # captured today is decrypted whenever one arrives.  That is the same
    # harvest now, decrypt later argument the TLS side makes, and it applies
    # harder here: this carries backend traffic rather than public pages.
    #
    # WireGuard's own answer is this key.  It is 32 random bytes mixed into the
    # handshake as an extra symmetric input, so an attacker who breaks
    # Curve25519 still has to have taken this as well, and it is never sent
    # over the wire by either end.  It does not make the tunnel post quantum in
    # the sense that ML-KEM does; it makes breaking Curve25519 insufficient on
    # its own, which is what is available.
    #
    # Encrypted at rest with the node's own key, like a pool token, and both
    # ends have to hold the same value or the handshake fails.  That last part
    # is why it is never added to a peer that already works without asking.
    psk_encrypted = Column(Text)

    # A ticket for the one command that puts the key on an existing workload.
    # Separate from the enrolment ticket because a workload being upgraded is
    # already enrolled and must not be re-enrolled: it keeps its address, its
    # own private key and its place in every pool that points at it.
    psk_token_hash = Column(String(128), index=True)
    psk_expires_at = Column(DateTime)
    psk_applied_at = Column(DateTime)

    # The enrolment ticket.  Only the hash is kept, it works once, and it is
    # short lived, exactly like the cluster join token.  Anybody holding one can
    # put a machine on the tunnel.
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
        """
        Whether the enrolment ticket is still good.

        The tzinfo dance is not decoration.  utcnow() is timezone aware and
        sqlite hands the column back naive, so comparing them raises rather
        than returning False, and the caller sees a 500 instead of an expired
        link.  The join token has the same property for the same reason.
        """
        if not self.enrol_token_hash:
            return False
        exp = self.enrol_expires_at
        if exp and exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        return exp is None or exp > utcnow()


class MetricSample(Base):
    """
    One bucket of telemetry for one node, written down so it outlives a restart.

    The in memory history is fifteen second detail for two hours, which answers
    "what is happening now" and loses everything the moment the manager
    restarts.  This is the other question: what did last Tuesday look like.

    **Two resolutions, and the reason is what a chart can usefully draw.**  An
    hour long window built from five minute buckets is twelve points, which is
    a sketch.  A thirty day window at one minute is 43,200 points per node,
    which is more than a chart can draw and more than anybody can read.  So one
    minute rows are kept for 48 hours and rolled up into five minute rows kept
    for thirty days.

    Storage is not the constraint anybody expected.  All tiers together are
    under 35 MB for four nodes, which is why the resolution was chosen for the
    charts rather than for the disk.

    **Min, mean and max, never a sample.**  A five minute bucket holding one
    reading throws away the spike that was the reason somebody is looking, and
    it throws it away at exactly the zoom level where nobody can check.
    """

    __tablename__ = "metric_samples"

    id = Column(Integer, primary_key=True)

    node = Column(String(64), nullable=False, index=True)

    # Bucket start, epoch seconds.  An integer rather than a DateTime because
    # every read is a range scan and every write is a bucket boundary, and both
    # are arithmetic.
    at = Column(Integer, nullable=False, index=True)

    # "1m" or "5m".
    resolution = Column(String(4), nullable=False, default="1m")

    # {"cpu_percent": {"min": 3, "avg": 7, "max": 41}, ...}
    #
    # Json rather than a column per metric, because the set of things worth
    # charting has already changed twice and a migration per metric is how a
    # feature like this stops being extended.
    values = Column(Text, nullable=False, default="{}")

    __table_args__ = (
        UniqueConstraint("node", "at", "resolution", name="uq_metric_bucket"),
    )

    def value_map(self):
        return json_get(self.values, {})


class WafProfile(Base):
    """
    A tuned rule set, named, and applied to any number of sites.

    The exclusions are the expensive part of running a WAF: somebody exercised
    an application, watched what the rules said about it, and decided which of
    those were wrong.  Tying that to one site would mean doing it again for
    every site that runs the same application, which is how a firewall ends up
    switched off on nineteen of twenty sites.

    So it is an object with a name, like an access list or an error page
    template, and a site points at it.  Editing one changes every site using
    it, which is the point and is also why the page has to show that list
    before somebody saves.
    """

    __tablename__ = "waf_profiles"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # Where it came from, kept because an exclusion nobody can explain is one
    # nobody will dare remove, and a WAF full of those checks nothing.
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

    # The other half of a profile, and the opposite idea.
    #
    # Exclusions are a negative model with holes cut in it: the rules describe
    # attacks, and an exclusion says one of them is wrong about this
    # application.  Everything the rules do not recognise is allowed.
    #
    # The surface is a positive model.  It lists what the application actually
    # is, and everything not on the list is refused.  The two live on one
    # profile because they are one policy for one application, and because a
    # positive model still wants the rules underneath it: knowing a path exists
    # does not mean an attack against that path is welcome.
    surface = relationship(
        "WafSurfaceEntry",
        back_populates="profile",
        cascade="all, delete-orphan",
        order_by="WafSurfaceEntry.path",
    )

    def address_list(self):
        return json_get(self.learned_from_addresses, [])


class WafExclusion(Base):
    """
    One rule this profile tells the firewall not to apply, and why.

    A blank path means the rule is off for the whole site.  A path means it is
    off only there, which is nearly always what a false positive deserves: a
    rule that is wrong about the upload form is usually right everywhere else,
    and turning it off site wide to fix one page is how a WAF quietly stops
    checking anything.
    """

    __tablename__ = "waf_exclusions"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("waf_profiles.id", ondelete="CASCADE"),
                        nullable=False)
    profile = relationship("WafProfile", back_populates="exclusions")

    rule_id = Column(Integer, nullable=False)
    path = Column(String(500))

    # What it looked like when somebody decided.  Not decoration: this is the
    # evidence for the decision, and without it a review a year later is
    # somebody guessing.
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
    """
    Watching one site's login for guessing, and the two shapes it takes.

    **Brute force** is one address trying many times.  Every lockout ever
    written stops it, including ours, and it is the one everybody thinks of.

    **Password spraying** is the opposite shape and is the reason this exists.
    One password, tried once against a hundred accounts, from a hundred
    addresses.  Each account sees a single failed attempt, so no per account
    lockout ever fires, and each address makes a handful of requests, so no
    rate limit does either.  It is invisible to both of the defences people
    already have, and it is how accounts are actually taken these days.

    The signal is only visible in the aggregate: a lot of failures, spread thin
    across a lot of addresses, in a short window.  Nothing looking at one
    account or one address can see it, which is exactly why it needs its own
    thing looking at the whole site at once.

    What this reads is the site's access log, so it sees the address, the path,
    the method and the status and never a username or a password.  That is a
    real limit, not a design flourish: it cannot tell you which accounts were
    targeted.  It can tell you the shape is there, which is the part that
    decides whether somebody should be woken up.
    """

    __tablename__ = "login_watches"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"),
                     unique=True, nullable=False)

    enabled = Column(Boolean, default=True)

    # Where the login is.  A json list, because an application often has more
    # than one: a form, an API token endpoint, a mobile path.
    paths = Column(Text, default='[]')
    methods = Column(Text, default='["POST"]')

    # **What a failure looks like, and this is per application.**
    #
    # There is no universal answer and pretending otherwise is how a detector
    # ends up reporting every successful login as an attack.  A form that
    # re-renders itself with "wrong password" answers 200, and the same
    # application answers 302 when the login worked, so for that one a 200 is
    # the failure and the redirect is the success.  An API answers 401.  The
    # page says this plainly and asks rather than guessing.
    fail_statuses = Column(Text, default='[401, 403]')

    # How far back a burst is measured over.  Five minutes is short enough that
    # a slow spray spread over a day will not trip it, which is a real gap and
    # is written down rather than hidden: see the long window below.
    window_seconds = Column(Integer, default=300)

    # One address, many tries.
    brute_threshold = Column(Integer, default=10)

    # Many addresses, few tries each.  All three have to hold at once or a busy
    # login page on a Monday morning is an incident.
    spray_min_addresses = Column(Integer, default=12)
    spray_min_failures = Column(Integer, default=20)
    spray_max_per_address = Column(Integer, default=3)

    # The slow version of the same attack, measured over hours rather than
    # minutes, because an attacker who knows about five minute windows simply
    # waits six.
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
    """
    One path this application is allowed to have, and the methods it answers.

    This is the positive model, and it is the opposite of an exclusion.  An
    exclusion says "the rules are wrong about this one thing".  A surface entry
    says "this is part of the application", and the rule written from the whole
    set says everything else is refused.

    **The path is a template, and it has to be.**  Learning sees what somebody
    exercised, so a site with a path per object gives back
    /user/12345/profile and /user/12346/profile and nothing at all about the
    user created tomorrow.  Stored with `*` in it, translated to a regular
    expression at render time, the same as an exclusion path, so what somebody
    reviews is what somebody edits.

    Methods matter as much as the path.  Nearly every application answers GET
    on a page and nothing else, and the whole point of a positive model is that
    a POST to a page that only ever served GET is refused before the
    application sees it.
    """

    __tablename__ = "waf_surface_entries"

    id = Column(Integer, primary_key=True)
    profile_id = Column(Integer, ForeignKey("waf_profiles.id", ondelete="CASCADE"),
                        nullable=False)
    profile = relationship("WafProfile", back_populates="surface")

    # The template, with * for one path segment and ** for any number.
    path = Column(String(500), nullable=False)

    # A json list, because one path usually answers more than one.  Empty means
    # any method, which is a decision somebody has to make on purpose.
    methods = Column(Text, default='["GET"]')

    # The evidence.  Same reasoning as an exclusion: a rule nobody can explain
    # is one nobody dares change, and on a positive model that matters more,
    # because the thing nobody dares change is refusing traffic.
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
    """
    One round of watching, with the addresses that count as testers.

    The addresses are the whole safeguard.  A WAF that whitelists whatever
    fired while it was learning is a gift to anybody scanning the site at the
    time: their probes become permanent exclusions and nothing in the interface
    ever says so.  Naming who counts, before the traffic happens, is what turns
    "it fired a lot" into "somebody vouched for this".

    Bounded on purpose.  Evidence that never expires becomes a whitelist nobody
    remembers agreeing to.
    """

    __tablename__ = "waf_sessions"

    id = Column(Integer, primary_key=True)
    host_id = Column(Integer, ForeignKey("virtual_hosts.id", ondelete="CASCADE"),
                     nullable=False, index=True)
    host = relationship("VirtualHost")

    # IPs and CIDRs, as a json list.  A testing round rarely comes from one
    # address: an office, a VPN, a build runner, somebody's laptop.
    addresses = Column(Text, nullable=False, default="[]")

    # What the site was enforcing before this started, so stopping can put it
    # back rather than leaving a site in whatever the session needed.
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
    """
    One authority you buy certificates from, and how to talk to it.

    A profile rather than a global setting, because a company can buy from more
    than one, and because a setting that silently changes where every
    certificate comes from is the wrong shape.  Lets Encrypt is not in here: it
    needs no credentials and it is the default when a certificate names no
    authority.

    One row per directory rather than per company.  Several authorities publish
    separate addresses for domain validated and organisation validated
    certificates, so "DigiCert OV" is a sensible name for one of these and
    "DigiCert" is not.
    """
    __tablename__ = "certificate_authorities"

    id = Column(Integer, primary_key=True)
    name = Column(String(128), unique=True, nullable=False, index=True)
    description = Column(String(500))

    # The ACME directory the authority gave you.
    directory_url = Column(String(500), nullable=False)

    # External account binding.  A paid authority does not let anybody register
    # an account, so it hands out these two with the entitlement and the client
    # presents them at registration.  Without them the registration is refused
    # and the error talks about the account rather than about these being
    # missing.
    eab_kid = Column(String(512))
    eab_hmac_key_encrypted = Column(Text)

    # A chain this authority needs asked for by name, if it needs one.  Empty
    # for almost everybody.
    preferred_chain = Column(String(128))

    enabled = Column(Boolean, default=True)
    created_at = Column(DateTime, default=utcnow)

    # When somebody last proved the credentials work, and what happened.  Paid
    # credentials are wrong in a way that only shows at first use, which is at
    # renewal, months later, at whatever hour the timer runs.
    last_tested_at = Column(DateTime)
    last_test_ok = Column(Boolean)
    last_test_error = Column(Text)

    certificates = relationship("Certificate", back_populates="authority")

    def has_credentials(self):
        return bool(self.eab_kid and self.eab_hmac_key_encrypted)


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

    # Which paid authority issued this, or empty for Lets Encrypt.
    #
    # Renewal reads this.  A certificate bought from one authority that quietly
    # renews from another is a change nobody asked for and nobody sees until a
    # browser complains about the issuer.
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

    # The OCSP responder named in the certificate, or empty when it names
    # none.  Read at issue time so the renderer does not have to open the file.
    #
    # This decides whether stapling is worth configuring.  Authorities have
    # started dropping OCSP for published revocation lists, and Lets Encrypt
    # has, so their certificates carry no responder and nginx warns once per
    # reload that it is ignoring the setting.
    ocsp_url = Column(String(255))

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

    # Whether this domain points at addresses we actually answer on.
    #
    # A renewal is only possible from a node the certificate authority can
    # reach, and it reaches whatever DNS says.  So a domain pointing somewhere
    # no node owns is a renewal that will fail, ninety days from now, quietly,
    # long after whoever changed the record has forgotten.  Worth saying out
    # loud while the certificate is still fine.
    dns_ok = Column(Boolean, default=True)
    dns_warning = Column(Text)
    dns_checked_at = Column(DateTime)

    # For an uploaded cert, we keep the material here so the fleet can serve it
    # everywhere.  The key is encrypted with the node secret.
    uploaded_fullchain = Column(Text)
    uploaded_privkey_encrypted = Column(Text)

    # The signing request somebody is waiting on an authority to answer.
    #
    # The key is already in uploaded_privkey_encrypted and never goes anywhere:
    # that is the whole point of a signing request, they sign a statement about
    # the public half and never see the private one.  A row in this state has no
    # not_after, so `usable` is False and the renderer leaves it out, which is
    # exactly right for a certificate that does not exist yet.
    csr_pem = Column(Text)
    csr_created_at = Column(DateTime)

    def has_material(self) -> bool:
        """
        Do we hold the certificate itself, rather than only a row about one.

        True for anything uploaded, self signed, or a completed signing
        request.  Those can be written to any node from the database alone,
        which is what makes them recover on their own when a node turns up
        without the files.  A Lets Encrypt certificate lives in certbot's
        folder on whichever node issued it and cannot.
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

    # The last time step this account successfully used.
    #
    # A TOTP code is valid for a window, not an instant, so without this the
    # same six digits authenticate as many times as somebody cares to submit
    # them.  RFC 6238 section 5.2 says the verifier must not accept a code it
    # has already accepted, and the reason is the obvious one: a code seen once
    # over a shoulder, through a phishing proxy that relays a real login, or in
    # a screen share, is otherwise good for another minute and a half.
    #
    # Stored as the counter rather than a timestamp because that is what the
    # comparison needs, and because it makes the rule simple: anything at or
    # below this has been used.
    totp_last_step = Column(Integer)
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


def _looks_like_address(value: str) -> bool:
    """
    Is this an IP address rather than a hostname.

    Brackets come off first, since that is how an IPv6 member is written.  It
    changes what we can send as SNI and what we can put in a Host header, and
    both want a name.
    """
    candidate = str(value).strip()
    if candidate.startswith("[") and candidate.endswith("]"):
        candidate = candidate[1:-1]
    try:
        ipaddress.ip_address(candidate)
        return True
    except ValueError:
        return False
