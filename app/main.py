"""
Manager entry point.

Two listeners on two ports, on purpose. 7443 is the web GUI, a normal HTTPS
server. 7444 is node to node: it only trusts client certificates signed by
this cluster's CA, and every message is also signed with the sender's key.

Keeping them apart puts the isolation in the TLS layer. With one port and a
path check, a single routing mistake would expose a peer endpoint publicly.
"""

import asyncio
import datetime as _dt
import logging
import os
import ssl
import sys
import time
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
from app.core.frontend_probe import get_probe, get_watchdog
from app.core import gslb
from app.core.metrics import get_collector
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

    # Chatty at info. httpx logs every health check, which buries anything
    # useful on a fleet with a few dozen backends.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    logging.getLogger("httpcore").setLevel(logging.WARNING)
    logging.getLogger("apscheduler").setLevel(logging.WARNING)


# ==============================================================================
# Startup
# ==============================================================================

async def register_self():
    """
    Make sure this node has a current row for itself. Runs on every start
    so a new address or a rebuilt nginx gets picked up.
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
                # A single node cluster is active from the start. Waiting
                # for an election with nobody to elect leaves it read only.
                role=NodeRole.ACTIVE,
            )
            session.add(node)
            log.info("registered this node as %s", settings.node_name)

        else:
            # Don't assume we're still active. A node that has been away
            # usually lost the role to its peer, and coming back as active
            # would show two active nodes until the next election. Standing
            # down is cheap: the election runs within seconds, and a cluster
            # of one elects itself immediately.
            peers = session.query(Node).filter(Node.name != settings.node_name).count()
            if peers and node.role == NodeRole.ACTIVE:
                log.info("starting up as standby until an election says otherwise")
                node.role = NodeRole.STANDBY

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
    Ask the agent what nginx looks like on this box. The module list decides
    which settings the GUI offers, and offering an unsupported one would
    stop nginx from starting.
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

            # The agent answered, so clear any earlier error. Leaving a stale
            # timeout message next to a fresh heartbeat teaches people to
            # ignore errors.
            node.last_error = None
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

    # If the fleet wants the WAF module and it is built but not loaded, load
    # it. The upgrade path now does this, but older nodes can be stuck with
    # the .so present and no load_module line; this recovers them without a
    # rebuild.
    #
    # Only ever loads. Unloading is a rebuild decision, and doing it here on
    # a manager restart could pull the module out from under a live site.
    # The agent verb refuses if the .so is missing and rolls back if the
    # nginx test fails.
    try:
        from app.core.settings_store import get as _setting

        status = await agent.call("waf_module_status")

        if _setting("waf_module") and status.get("built") and not status.get("loaded"):
            log.warning("this fleet wants the WAF module and nginx has not "
                        "been told about it, loading it now")
            await agent.call("waf_module", enabled=True)
            status = await agent.call("waf_module_status")

        # Record whether the module is actually loaded. `nginx -V` only shows
        # what was compiled in, and gating the GUI on that let a built but
        # unloaded node offer the WAF and fail the apply fleet wide.
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == settings.node_name).first()
            if node:
                node.waf_module_loaded = bool(status.get("loaded"))
                session.commit()
    except AgentError as exc:
        log.warning("could not check the WAF module: %s", exc)
    except Exception:
        log.exception("could not check the WAF module")


async def refresh_frontend_state():
    """
    Probe this node's own listener and record the result.

    This is the signal GSLB withdraws a node on, and the record TTL is
    seconds, so it runs much more often than refresh_local_state. Kept
    separate so a slow agent cannot delay it.
    """
    settings = get_settings()
    probe = get_probe()

    # Empty means use the configured node address, which is the one GSLB
    # hands out for this node.
    host = settings.frontend_probe_host.strip() or settings.node_address

    try:
        verdict = await probe.run_cycle(
            host,
            settings.frontend_probe_port,
            settings.frontend_probe_server_name,
            settings.frontend_probe_timeout,
            settings.frontend_probe_fail_after,
            settings.frontend_probe_pass_after,
        )
    except Exception:
        # A broken probe must never mark a node down. Keep the last verdict
        # so a bug here can't take a working node off the internet.
        log.exception("the frontend probe blew up, leaving the last verdict alone")
        return

    if verdict is None:
        return

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == settings.node_name).first()
        if node and (node.nginx_serving is not verdict
                     or node.nginx_serving_detail != probe.detail):
            node.nginx_serving = verdict
            node.nginx_serving_detail = probe.detail[:255]
            session.commit()

    # DNS withdrawal routes around the problem; this tries to fix it. Runs
    # after the write above so the node is already leaving the answer
    # before its listener drops for a restart.
    if verdict is False and settings.frontend_watchdog:
        await get_watchdog().repair(
            time.time(),
            settings.frontend_watchdog_cooldown,
            settings.frontend_watchdog_max_per_day,
            detail=probe.detail,
        )


async def refresh_public_ip():
    """
    Refresh our public address. It decides which node answers certificate
    challenges, and a box behind NAT can change it on failover.
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

    A new single node creates its own CA and signs itself. A node about to
    join gets its certificate during the join, so we don't create a CA when
    peers are already on the roster.
    """
    settings = get_settings()
    ca = ClusterCA()

    with session_scope() as session:
        peer_count = session.query(Node).filter(Node.name != settings.node_name).count()

    # has_identity, not exists. Only the founding node holds the CA key;
    # joined nodes get the CA certificate only, so checking for the key
    # would tell every healthy joined node to rejoin.
    if not ca.has_identity():
        if peer_count > 0:
            log.warning(
                "there are peers on the roster but this node has no cluster "
                "identity: no CA certificate, or no certificate and key of its "
                "own.  It cannot prove who it is to the others.  This node "
                "needs to rejoin the cluster."
            )
            return
        log.info("no cluster CA yet, making one.  This node starts the cluster.")
        ca.create(cluster_name=settings.node_name)
    elif not ca.exists():
        # A member that cannot sign, which is what joining is meant to produce.
        log.info("this node joined the cluster rather than starting it, so it "
                 "holds the CA certificate and not the CA key")

    # A CA whose cert and key don't match can't sign anything the fleet will
    # accept. Say so loudly instead of letting peer connections fail
    # mysteriously later. Not auto repaired: a new CA would invalidate every
    # node certificate, and that is a decision for a person. Only checked
    # where the key exists, which is the founding node.
    if ca.exists() and not ca.ca_pair_ok():
        log.error("=" * 70)
        log.error("The cluster CA certificate and its key do not match.")
        log.error("")
        log.error("Nothing this node signs will be trusted by the others, and")
        log.error("joining will not work.  This is not repaired automatically,")
        log.error("because a new CA would invalidate every node certificate in")
        log.error("the cluster and they would all have to rejoin.")
        log.error("")
        log.error("If this is the only node, the clean fix is to stop it, remove")
        log.error("%s, and start again.", ca.dir)
        log.error("If there are other nodes, take the CA files from a healthy one.")
        log.error("=" * 70)

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

    # Tick often. Each pool has its own interval and the checker skips pools
    # that aren't due, so a fast tick is cheap and a 3 second check really
    # runs every 3 seconds.
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

    # GeoIP database, if configured. The job decides whether an update is
    # due, so schedule changes take effect without a restart.
    async def _geoip():
        from app.core import geoip

        await geoip.refresh_if_due()

    scheduler.add_job(
        _geoip,
        "interval",
        minutes=60,
        id="geoip",
        max_instances=1,
        coalesce=True,
    )

    # WAF rule set, same pattern. A separate job so one unreachable source
    # doesn't stop both.
    async def _waf_rules():
        from app.core import waf_rules

        await waf_rules.refresh_if_due()

    scheduler.add_job(
        _waf_rules,
        "interval",
        minutes=60,
        id="waf_rules",
        max_instances=1,
        coalesce=True,
    )

    # Rotate WAF audit logs every 15 minutes on every node. A scan in
    # watching mode writes steadily, and a standby with a full disk can't be
    # failed over to. Cheap when there's nothing to do.
    async def _waf_logs():
        from app.core import waf_hits

        await waf_hits.rotate_logs()

    scheduler.add_job(
        _waf_logs,
        "interval",
        minutes=15,
        id="waf_logs",
        max_instances=1,
        coalesce=True,
    )

    # Catch up nodes that were offline. Usually a no-op.
    scheduler.add_job(
        cluster.drain_pending,
        "interval",
        seconds=30,
        id="drain",
        max_instances=1,
        coalesce=True,
    )

    # DNS zones and accounts converge on their own. The push after a change
    # is the fast path; this covers pushes that could not be delivered, so
    # an account removed while a peer was down stays removed. Zones render
    # no nginx config and never travel with an apply, so without this a
    # standby would have no zones and DNS would die with the active node.
    # Both are no-ops on a standby.
    scheduler.add_job(
        cluster.replicate_gslb,
        "interval",
        seconds=60,
        id="gslb-zones",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(
        cluster.replicate_accounts,
        "interval",
        seconds=60,
        id="accounts",
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

    # Start the DNS listener if anything is configured. Failure is logged,
    # not raised: port 53 may be held by the distro's resolver, and that
    # shouldn't take the whole GUI down.
    try:
        gslb.refresh()
        if gslb.get_server().data.zones:
            gslb.get_server().start()
            # Scheduled because this function isn't async and the redirect
            # needs the agent. A few seconds in, so the listener is up
            # before traffic is pointed at it.
            scheduler.add_job(
                gslb.ensure_redirect,
                "date",
                run_date=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=5),
                id="gslb_redirect",
            )
    except Exception as exc:
        log.error("the dns listener did not start, so gslb is off: %s", exc)

    # Keep DNS answers in step with which nodes are serving, and the
    # listener in step with whether there's anything to serve. Ten seconds
    # to stay well inside the short TTL.
    #
    # reconcile rather than refresh: the block above only starts the
    # listener if zones exist at boot, and a joining node gets its zones a
    # few seconds later.
    scheduler.add_job(
        gslb.reconcile,
        "interval",
        seconds=10,
        id="gslb_zones",
        max_instances=1,
        coalesce=True,
    )

    # Connection counters for the dashboard. The useful number is the rate
    # between readings; 15s is a balance between hiding spikes and noise
    # from our own health checks.
    scheduler.add_job(
        get_collector().collect,
        "interval",
        seconds=15,
        id="nginx_metrics",
        max_instances=1,
        coalesce=True,
    )

    # Persist telemetry every minute on every node: fold the last minute,
    # roll data past 48 hours into 5 minute buckets, prune past 30 days.
    def _store_metrics():
        from app.core import metrics_store

        metrics_store.tick()

    scheduler.add_job(
        _store_metrics,
        "interval",
        seconds=60,
        id="metrics_store",
        max_instances=1,
        coalesce=True,
    )

    # Backend self-reported metrics. Slower than our own because these are
    # someone else's servers and CPU/memory don't need 15s resolution.
    scheduler.add_job(
        get_collector().collect_members,
        "interval",
        seconds=30,
        id="member_metrics",
        max_instances=1,
        coalesce=True,
    )

    # Notice a certificate whose files have gone before it stops every apply.
    scheduler.add_job(
        get_cert_manager().verify_files,
        "interval",
        seconds=300,
        id="cert_files",
        max_instances=1,
        coalesce=True,
    )

    # Catch a domain that stopped pointing at us while its certificate is
    # still valid. Hourly is plenty.
    scheduler.add_job(
        get_cert_manager().check_dns,
        "interval",
        seconds=3600,
        id="cert_dns",
        max_instances=1,
        coalesce=True,
    )

    scheduler.add_job(refresh_local_state, "interval", seconds=60, id="local_state",
                      max_instances=1, coalesce=True)

    # More often than local_state: this takes a wedged node out of DNS, and
    # the record TTL is typically 30 seconds.
    scheduler.add_job(refresh_frontend_state, "interval",
                      seconds=get_settings().frontend_probe_interval,
                      id="frontend_probe", max_instances=1, coalesce=True)

    # The public address rarely changes; hourly avoids hammering the lookup
    # services.
    scheduler.add_job(refresh_public_ip, "interval", seconds=3600, id="public_ip",
                      max_instances=1, coalesce=True)

    scheduler.add_job(cleanup_old_rows, "interval", seconds=86400, id="cleanup",
                      max_instances=1, coalesce=True)

    scheduler.start()
    log.info("background jobs started")


async def cleanup_old_rows():
    """
    Delete old health events and expired sessions. Health events pile up
    fast and are useless after a couple of weeks. The audit log is kept.
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
    log.info("Failover LB %s", __version__)
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

    # In the background: it reaches out to the internet, and blocking on it
    # makes a box with no outbound route look hung.
    asyncio.create_task(refresh_public_ip())

    # Install the certbot hooks now instead of discovering they're missing
    # halfway through an issue.
    async def _hooks():
        from app.core import acme_hooks

        await acme_hooks.ensure_hooks()

    asyncio.create_task(_hooks())

    # Check certificate files now rather than in five minutes, so a node
    # that came back without them reports it right away.
    async def _certs():
        from app.core.acme import get_cert_manager

        await asyncio.sleep(5)
        await get_cert_manager().verify_files()

    asyncio.create_task(_certs())

    start_scheduler()

    # Run an election now instead of waiting a full interval. register_self
    # stands a returning node down, and until an election runs the node
    # refuses config changes, which used to mean a window after every
    # restart where there was no active node at all.
    #
    # Heartbeat first so the election judges peers on fresh data rather
    # than last_heartbeat values from before this node went down. In the
    # background so an unreachable peer doesn't stall startup.
    async def _settle_role():
        cluster = get_cluster()
        began = time.monotonic()
        try:
            await cluster.send_heartbeats()
        except Exception as exc:
            log.info("could not reach the peers before the first election: %s", exc)
        try:
            await cluster.run_election()
        except Exception as exc:
            log.warning("the first election did not run: %s", exc)

        # Log how long it took. This is the window where the node refuses
        # config changes after a restart, and it's easy to miss otherwise.
        with session_scope() as session:
            me = cluster.self_node(session)
            role = me.role.value if me else "not in the roster"
        log.info("roles settled %.1f seconds after startup, this node is %s",
                 time.monotonic() - began, role)

    asyncio.create_task(_settle_role())

    if not settings.admin_networks:
        log.warning("")
        log.warning("NFM_ADMIN_ALLOWLIST is empty, so anybody who can reach port")
        log.warning("%s gets the login page.  Set it.", settings.gui_port)
        log.warning("")

    yield

    log.info("shutting down")
    if scheduler.running:
        scheduler.shutdown(wait=False)

    # Remove the port 53 redirect before exiting. The nftables rule lives on
    # the host and outlives the container; left behind, it points at a port
    # with nothing listening, and resolvers wait for a timeout instead of
    # moving to the other nameserver. See clear_redirect.
    #
    # Best effort with a timeout so shutdown can't hang. The agent also
    # clears stale rules on its own.
    try:
        from app.core import gslb

        server = gslb.get_server()
        if server._running:
            await asyncio.wait_for(gslb.clear_redirect(server), timeout=10)
            server.stop()
            log.info("gave port 53 back and stopped the dns listener")
    except Exception as exc:                      # noqa: BLE001
        log.warning("could not give port 53 back on the way out: %s", exc)


def create_gui_app() -> FastAPI:
    from app.web.routes_account import router as account_router
    from app.web.routes_backup import router as backup_router
    from app.web.routes_tunnel import router as tunnel_router
    from app.web.routes_api import router as api_router
    from app.web.routes_pages import router as pages_router
    from app.web.security import (
        AdminAllowlistMiddleware,
        RateLimitMiddleware,
        SecurityHeadersMiddleware,
    )

    settings = get_settings()

    app = FastAPI(
        title="Failover LB",
        version=__version__,
        lifespan=lifespan,
        # Tells FastAPI it is served under a prefix. The templates handle
        # the rest.
        root_path=settings.root_path.rstrip("/"),
        # No interactive docs; in production they're just a map of every
        # endpoint.
        docs_url=None,
        redoc_url=None,
        openapi_url=None,
    )

    # Starlette runs the last added middleware first, so the allow list is
    # outermost and rejects requests before anything else does work.
    app.add_middleware(SecurityHeadersMiddleware)
    app.add_middleware(RateLimitMiddleware)
    app.add_middleware(AdminAllowlistMiddleware)

    static_dir = Path(__file__).parent / "web" / "static"
    if static_dir.is_dir():
        app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")

    app.include_router(pages_router)
    app.include_router(account_router)
    app.include_router(api_router, prefix="/api")
    # The tunnel router carries its own paths: the managed half under /api
    # and enrollment under /tunnel, which must be reachable by workloads
    # outside the admin allow list. GUI listener only; workloads never have
    # a peer client certificate.
    app.include_router(tunnel_router)
    app.include_router(backup_router)

    @app.get("/healthz", include_in_schema=False)
    async def healthz():
        # Says almost nothing: this is reachable without logging in.
        return {"status": "ok"}

    return app


def create_peer_app() -> FastAPI:
    """
    The node to node app. No cookies, CSRF or HTML. Every route checks the
    message signature first; the client certificate is the login.
    """
    from app.web.routes_peer import router as peer_router

    app = FastAPI(
        title="Failover LB peer API",
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
    Certificate for the web GUI. Self signed on first start and can be
    replaced with a real one in Settings. Browsers will warn, but it still
    protects the session cookie on the wire, which is the real risk.
    """
    cert_path = settings.pki_dir / "gui.crt"
    key_path = settings.pki_dir / "gui.key"

    # Check that the pair actually matches, not just that both files exist.
    # A mismatched pair (from an interrupted write) made uvicorn fail before
    # listening and docker restart it into the same failure forever. It's a
    # throwaway self signed cert, so regenerating is always safe.
    remake = not cert_path.is_file() or not key_path.is_file()

    if not remake:
        try:
            from app.core.crypto import key_matches_cert

            if not key_matches_cert(cert_path.read_text(), key_path.read_text()):
                log.warning(
                    "the GUI certificate and key do not go together, making a new "
                    "pair.  This usually means a previous start was interrupted "
                    "part way through writing them."
                )
                remake = True
        except Exception as exc:
            log.warning("could not read the GUI certificate (%s), making a new pair", exc)
            remake = True

    if remake:
        cert_path.unlink(missing_ok=True)
        key_path.unlink(missing_ok=True)
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
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Failover LB"),
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

    # Write both to temp files and then rename into place. Two renames still
    # leave a small window; the match check in gui_ssl_context is what
    # actually recovers from a mismatched pair.
    key_tmp = key_path.with_suffix(".key.tmp")
    cert_tmp = cert_path.with_suffix(".crt.tmp")

    fd = os.open(str(key_tmp), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "wb") as fh:
        fh.write(key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ))
        fh.flush()
        os.fsync(fh.fileno())

    cert_tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))

    os.replace(str(key_tmp), str(key_path))
    os.replace(str(cert_tmp), str(cert_path))


def peer_ssl_config(settings) -> dict:
    """
    TLS for the peer port.

    CERT_OPTIONAL, not CERT_REQUIRED. A joining node has no cluster
    certificate yet (getting one is the point of the join), so CERT_REQUIRED
    would fail the handshake and joining would look like a network problem.

    A presented certificate is still verified, so forged or expired ones are
    rejected. The certificate was never the only gate: every peer route
    checks an HMAC signature with a timestamp and nonce, plus the source
    address against the roster. The one exception is /peer/join, which
    requires a single use join token.
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

    # Set up the database and node certificate before building the
    # listeners, not in the startup hook. uvicorn reads TLS settings when the
    # Config is built, before any hook runs, so a brand new node used to come
    # up without a peer port until it was restarted. Both calls are
    # idempotent and the hook still makes them.
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
