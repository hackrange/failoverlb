"""
Starting the manager.

Two separate listeners, on two ports, on purpose:

  7443 is the web GUI.  A normal https server with a server certificate.

  7444 is node to node.  It demands a client certificate signed by this
  cluster's own CA, and nothing else is trusted, so a browser pointed at it does
  not even complete the handshake.  On top of that every message is signed with
  a key only the sending node has.

Keeping them apart matters.  On one port with a path check, one routing mistake
puts a peer endpoint on the public side.  Two listeners means the isolation is
in the TLS layer, where a bug in our code cannot undo it.
"""

import asyncio
import logging
import os
import ssl
import sys
from contextlib import asynccontextmanager
from pathlib import Path

import uvicorn
from apscheduler.schedulers.asyncio import AsyncIOScheduler
from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles

from app import __version__
from app.config import get_settings
from app.core.agent_client import AgentError, get_agent
from app.core.capabilities import set_local_capabilities
from app.core.cluster import get_cluster
from app.core.crypto import ClusterCA
from app.db import init_db, session_scope
from app.models import Node, NodeRole, NodeState, utcnow

log = logging.getLogger("nfm")

scheduler = AsyncIOScheduler()


# ==============================================================================
# Logging
# ==============================================================================

def setup_logging():
    settings = get_settings()
    level = getattr(logging, settings.log_level.upper(), logging.INFO)

    logging.basicConfig(
        level=level,
        format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
        stream=sys.stdout,
    )

    # These two are chatty at info and say nothing we want.  httpx logs a line
    # for every health check, which on a fleet with 20 backends buries anything
    # useful within seconds.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


# ==============================================================================
# Startup
# ==============================================================================

async def register_self():
    """
    Make sure this node has a row for itself and it is current.

    Runs on every start.  A container that got a new address, or a box that had
    nginx rebuilt with different modules, needs that picked up.
    """
    settings = get_settings()

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == settings.node_name).first()

        if not node:
            node = Node(
                name=settings.node_name,
                address=settings.node_address,
                is_self=True,
                state=NodeState.ONLINE,
                # A single node cluster is active from the start.  Waiting for an
                # election with nobody to elect would leave it read only and the
                # first thing anybody tries would be refused.
                role=NodeRole.ACTIVE,
            )
            session.add(node)
            log.info("registered this node as %s", settings.node_name)

        node.address = settings.node_address
        node.peer_port = settings.peer_port
        node.gui_port = settings.gui_port
        node.priority = settings.cluster_priority
        node.is_self = True
        node.state = NodeState.ONLINE
        node.last_heartbeat = utcnow()
        session.commit()


async def refresh_local_state():
    """
    Ask the agent what nginx looks like on this box.

    This is where the module list comes from, and the module list is what
    decides which settings the GUI even shows.  Without it we would be guessing,
    and guessing wrong means offering a setting that makes nginx refuse to start.
    """
    settings = get_settings()
    agent = get_agent()

    try:
        status = await agent.status()
    except AgentError as exc:
        log.warning("cannot reach the host agent: %s", exc)
        log.warning("the GUI will come up, but nothing can be applied until it is back")
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == settings.node_name).first()
            if node:
                node.nginx_active = False
                node.last_error = str(exc)[:500]
                session.commit()
        return

    caps = set_local_capabilities(
        status.get("build_info", ""),
        status.get("version_banner", ""),
    )

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == settings.node_name).first()
        if node:
            node.nginx_version = caps.nginx_version
            node.nginx_build_info = status.get("build_info", "")[:65536]
            node.agent_version = status.get("agent_version")
            node.nginx_active = status.get("service_active") in ("active", "no-systemd")
            node.load_average = (status.get("load_average") or [None])[0]
            node.disk_free_bytes = status.get("disk_free")
            node.last_heartbeat = utcnow()
            session.commit()

    # Our own addresses, so the management allow list can include them and the
    # cert code can spot a floating VIP sitting on this box.
    try:
        addrs = await agent.local_addresses()
        import json

        with session_scope() as session:
            node = session.query(Node).filter(Node.name == settings.node_name).first()
            if node:
                node.local_addresses = json.dumps(addrs.get("addresses", []))
                session.commit()
    except AgentError:
        pass


async def refresh_public_ip():
    """
    Work out our public address.

    This is the number that decides which node gets to answer a certificate
    challenge, so it is worth getting right and worth refreshing.  A box behind
    NAT that fails over has a different answer than it did an hour ago.
    """
    settings = get_settings()
    try:
        result = await get_agent().public_ip()
    except AgentError:
        return

    if not result.get("ok"):
        return

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == settings.node_name).first()
        if node:
            old = node.public_ip
            node.public_ip = result["public_ip"]
            node.public_ip_checked_at = utcnow()
            session.commit()
            if old and old != result["public_ip"]:
                log.warning(
                    "our public address changed from %s to %s.  Certificate "
                    "issuing may move to a different node.",
                    old, result["public_ip"],
                )


def ensure_pki():
    """
    Make sure this node has its cluster identity.

    A brand new single node makes its own CA and signs itself.  A node that is
    going to join an existing cluster gets its cert during the join, so it does
    not make a CA here.  We can tell the difference by whether there are peers
    on the roster.
    """
    settings = get_settings()
    ca = ClusterCA()

    with session_scope() as session:
        peer_count = session.query(Node).filter(Node.name != settings.node_name).count()

    if not ca.exists():
        if peer_count > 0:
            log.warning(
                "there are peers on the roster but no cluster CA here.  "
                "This node needs to rejoin the cluster."
            )
            return
        log.info("no cluster CA yet, making one.  This node starts the cluster.")
        ca.create(cluster_name=settings.node_name)

    if not ca.has_node_cert():
        if not ca.ca_key_path.is_file():
            log.warning("no node certificate and no CA key, this node has to rejoin")
            return
        log.info("signing a certificate for this node")
        _, csr = ca.create_node_csr(settings.node_name, [settings.node_address])
        ca.save_node_cert(ca.sign_node_csr(csr, settings.node_name))

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == settings.node_name).first()
        if node:
            node.cert_fingerprint = ca.node_fingerprint()
            session.commit()

    expires = ca.node_cert_expires()
    if expires:
        days = (expires - utcnow()).days
        if days < 30:
            log.warning("this node's cluster certificate expires in %s days", days)


# ==============================================================================
# Background jobs
# ==============================================================================

def start_scheduler():
    settings = get_settings()

    from app.core.acme import get_cert_manager
    from app.core.health import HealthChecker
    from app.web.routes_api import apply_current_config

    cluster = get_cluster()

    checker = HealthChecker(
        node_name=settings.node_name,
        on_change=lambda reason: apply_current_config(
            author="health check", summary=reason
        ),
    )

    async def start_checker():
        await checker.start()

    asyncio.get_event_loop().create_task(start_checker())

    # The health loop ticks often and cheaply.  Each pool has its own interval
    # and the checker skips any pool that is not due yet, so a fast tick costs
    # almost nothing and means a pool asking for a 3 second check actually gets
    # one.  Ticking at the slowest interval instead would quietly round every
    # pool up to that.
    scheduler.add_job(
        checker.run_cycle,
        "interval",
        seconds=2,
        id="health",
        max_instances=1,       # never let two cycles overlap
        coalesce=True,         # a run that was missed does not queue up
    )

    scheduler.add_job(
        cluster.send_heartbeats,
        "interval",
        seconds=settings.heartbeat_interval,
        id="heartbeat",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        cluster.run_election,
        "interval",
        seconds=settings.heartbeat_interval * 2,
        id="election",
        max_instances=1,
        coalesce=True,
    )

    # Catching up nodes that were offline.  Runs often, does nothing when the
    # queue is empty, which is nearly always.
    scheduler.add_job(
        cluster.drain_pending,
        "interval",
        seconds=30,
        id="drain",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        get_cert_manager().check_renewals,
        "interval",
        seconds=settings.cert_check_interval,
        id="certs",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(refresh_local_state, "interval", seconds=60, id="local_state",
                      max_instances=1, coalesce=True)

    # The public address does not move often, so once an hour is plenty and it
    # keeps us from hammering the services that tell us.
    scheduler.add_job(refresh_public_ip, "interval", seconds=3600, id="public_ip",
                      max_instances=1, coalesce=True)

    scheduler.add_job(cleanup_old_rows, "interval", seconds=86400, id="cleanup",
                      max_instances=1, coalesce=True)

    scheduler.start()
    log.info("background jobs started")


async def cleanup_old_rows():
    """
    Throw away old health events and expired sessions.

    Health events pile up fast.  A fleet with 30 backends flapping generates
    thousands a day, and none of them matter after a couple of weeks.  The audit
    log is deliberately not touched here, that is kept.
    """
    from datetime import timedelta

    from app.auth.service import cleanup_expired
    from app.models import HealthEvent

    cutoff = utcnow() - timedelta(days=14)
    with session_scope() as session:
        removed = session.query(HealthEvent).filter(
            HealthEvent.timestamp < cutoff
        ).delete()
        sessions_gone = cleanup_expired(session)
        session.commit()

    if removed or sessions_gone:
        log.info("cleanup removed %s health events and %s old sessions",
                 removed, sessions_gone)


# ==============================================================================
# The apps
# ==============================================================================

@asynccontextmanager
async def lifespan(app: FastAPI):
    settings = get_settings()

    log.info("=" * 70)
    log.info("NGINX Fleet Manager %s", __version__)
    log.info("  node:     %s (%s)", settings.node_name, settings.node_address)
    log.info("  gui:      https://%s:%s", settings.bind_address, settings.gui_port)
    log.info("  peers:    https://%s:%s (client cert required)",
             settings.bind_address, settings.peer_port)
    log.info("=" * 70)

    init_db()

    from app.auth.service import ensure_bootstrap_admin

    with session_scope() as session:
        ensure_bootstrap_admin(session)

    await register_self()
    ensure_pki()
    await refresh_local_state()

    # Kick this off in the background.  It reaches out to the internet and can
    # take a few seconds, and blocking startup on it means a box with no route
    # out sits there looking hung.
    asyncio.create_task(refresh_public_ip())

    start_scheduler()

    if not settings.admin_networks:
        log.warning("")
        log.warning("NFM_ADMIN_ALLOWLIST is empty, so anybody who can reach port")
        log.warning("%s gets the login page.  Set it.", settings.gui_port)
        log.warning("")

    yield

    log.info("shutting down")
    if scheduler.running:
        scheduler.shutdown(wait=False)


def create_gui_app() -> FastAPI:
    from app.web.routes_api import router as api_router
    from app.web.routes_pages import router as pages_router
    from app.web.security import (
        AdminAllowlistMiddleware,
        RateLimitMiddleware,
        SecurityHeadersMiddleware,
    )

    settings = get_settings()

    app = FastAPI(
        title="NGINX Fleet Manager",
        version=__version__,
        lifespan=lifespan,
        # Tells FastAPI it is being served under a prefix, so it does not get
        # confused about its own paths.  The templates do the rest.
        root_path=settings.root_path.rstrip("/"),
        # No interactive docs.  They are handy in development and they are a
        # map of every endpoint for anybody who gets this far in production.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Order matters and it is the reverse of what you might expect.  Starlette
    # runs the last one added first, so the allow list ends up outermost and
    # turns people away before anything else does any work.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AdminAllowlistMiddleware)

    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(pages_router)
    app.include_router(api_router, prefix="/api")

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        # Deliberately says almost nothing.  This is reachable without logging
        # in, so the version number and node name stay out of it.
        return {"status": "ok"}

    return app


def create_peer_app() -> FastAPI:
    """
    The node to node app.

    No session cookies, no CSRF, no HTML.  Every route checks the signature on
    the message before it does anything.  There is no login here because the
    client certificate is the login.
    """
    from app.web.routes_peer import router as peer_router

    app = FastAPI(
        title="NGINX Fleet Manager peer API",
        version=__version__,
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )
    app.include_router(peer_router)
    return app


# ==============================================================================
# TLS
# ==============================================================================

def gui_ssl_context(settings) -> dict:
    """
    The certificate for the web GUI.

    Self signed, generated on first start.  Your browser will complain and that
    is expected for a management tool on a private network.  You can point this
    at a real certificate in Settings once you have one.

    A self signed certificate here is still worth a lot.  It stops anybody on
    the network reading your session cookie, which is the actual risk.  The
    warning is about identity, not encryption.
    """
    cert_path = settings.pki_dir / "gui.crt"
    key_path = settings.pki_dir / "gui.key"

    if not cert_path.is_file() or not key_path.is_file():
        _make_gui_cert(settings, cert_path, key_path)

    return {
        "ssl_certfile": str(cert_path),
        "ssl_keyfile": str(key_path),
    }


def _make_gui_cert(settings, cert_path: Path, key_path: Path):
    import datetime
    import ipaddress as ipmod

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    log.info("making a self signed certificate for the GUI")

    settings.pki_dir.mkdir(parents=True, exist_ok=True)
    key = ec.generate_private_key(ec.SECP256R1())
    now = datetime.datetime.now(datetime.timezone.utc)

    san = [x509.DNSName(settings.node_name), x509.DNSName("localhost")]
    try:
        san.append(x509.IPAddress(ipmod.ip_address(settings.node_address)))
    except ValueError:
        san.append(x509.DNSName(settings.node_address))
    san.append(x509.IPAddress(ipmod.ip_address("127.0.0.1")))

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, settings.node_name),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "NGINX Fleet Manager"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=825))
        .add_extension(x509.SubjectAlternativeName(san), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .sign(key, hashes.SHA256())
    )

    fd = os.open(str(key_path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))

    cert_path.write_bytes(cert.public_bytes(serialization.Encoding.PEM))


def peer_ssl_config(settings) -> dict:
    """
    TLS for the peer port.

    CERT_OPTIONAL, not CERT_REQUIRED, and the reason is worth writing down
    because CERT_REQUIRED looks stricter and is the obvious thing to reach for.

    A node that is joining does not have a cluster certificate yet.  Getting one
    is the entire point of the join.  With CERT_REQUIRED the handshake fails
    before the joiner can ask, so joining is impossible and the error looks like
    a network problem.  That is a chicken and egg you cannot code your way out
    of on one port.

    CERT_OPTIONAL still verifies a certificate when one is presented, so a
    forged or expired one is rejected exactly as before.  It only allows a
    connection with no certificate at all through to the application.

    That is safe because the certificate was never the only gate.  Every peer
    route verifies an HMAC signature made with a key only that node holds, with
    a timestamp and a nonce so a captured request cannot be replayed, and it
    checks the source address against the node roster.  The one route that does
    not is /peer/join, and that one demands a single use join token instead.

    So a caller with no certificate can open a connection and get told no by
    every route except the one designed to be reached that way.
    """
    ca = ClusterCA()

    if not ca.has_node_cert():
        return {}

    return {
        "ssl_certfile": str(ca.node_cert_path),
        "ssl_keyfile": str(ca.node_key_path),
        "ssl_ca_certs": str(ca.ca_cert_path),
        "ssl_cert_reqs": ssl.CERT_OPTIONAL,
    }


# ==============================================================================
# Running
# ==============================================================================

async def serve():
    settings = get_settings()

    # Set up the database and this node's certificate before we build the
    # listeners, not inside the app's startup hook.
    #
    # uvicorn reads the TLS settings when the Config object is built, which
    # happens before the app has started and therefore before any startup hook
    # has run.  Doing the certificate work in the hook meant a brand new node
    # had no certificate at the moment we decided whether to open the peer
    # port, so it silently came up without one and could not be joined until
    # somebody restarted it.  It worked on the second boot, which made it a
    # confusing thing to chase.
    #
    # Both of these are safe to call twice, and the startup hook still calls
    # them, so ordering is the only thing that changed here.
    init_db()
    ensure_pki()

    gui = create_gui_app()
    peer = create_peer_app()

    gui_config = uvicorn.Config(
        gui,
        host=settings.bind_address,
        port=settings.gui_port,
        log_level=settings.log_level,
        access_log=False,
        server_header=False,   # no need to tell anybody what we run on
        date_header=True,
        **gui_ssl_context(settings),
    )

    peer_tls = peer_ssl_config(settings)
    servers = [uvicorn.Server(gui_config)]

    if peer_tls:
        peer_config = uvicorn.Config(
            peer,
            host=settings.bind_address,
            port=settings.peer_port,
            log_level="warning",
            access_log=False,
            server_header=False,
            **peer_tls,
        )
        servers.append(uvicorn.Server(peer_config))
    else:
        log.warning(
            "no cluster certificate yet, so the peer port is not listening.  "
            "It starts once this node has joined or started a cluster."
        )

    await asyncio.gather(*[s.serve() for s in servers])


def main():
    setup_logging()
    settings = get_settings()

    if not settings.secret_key:
        log.error("")
        log.error("NFM_SECRET_KEY is not set, so refusing to start.")
        log.error("")
        log.error("Make one with:  openssl rand -base64 48")
        log.error("Then put it in .env as NFM_SECRET_KEY")
        log.error("")
        log.error("We do not make one up at startup on purpose.  A key that")
        log.error("changes every restart means every stored secret becomes")
        log.error("unreadable and everybody gets logged out.")
        sys.exit(1)

    try:
        asyncio.run(serve())
    except KeyboardInterrupt:
        log.info("interrupted")


if __name__ == "__main__":
    main()
