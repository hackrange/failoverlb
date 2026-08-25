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

        else:
            # Do not assume we are still active because we were when we stopped.
            #
            # A node that has been away has no idea what happened while it was
            # gone, and the usual answer is that the other node took over.
            # Coming back still believing it is active means its own roster says
            # two nodes are active until the first election tidies up, which is
            # a handful of seconds of the GUI telling two different people they
            # are both on the node that takes writes.
            #
            # Standing down and waiting to be elected costs nothing.  The
            # election runs within seconds, and if this node should be active it
            # will be, by the same rule everybody else is using.  A cluster of
            # one elects itself immediately, so nothing is stuck read only.
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

            # The agent answered, so whatever it said last time it did not is
            # over.  This was never cleared, so one slow reply left "the agent
            # did not answer status within 30s" sitting on the node for good,
            # next to a module count and a heartbeat from a second ago that
            # proved the opposite.  An error that does not go away when the
            # problem does is worse than no error, because people stop believing
            # any of them.
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

    # If this fleet asked for the WAF module, make sure nginx has been told it
    # exists.
    #
    # Building the module and loading it are two different things, and only the
    # first used to happen: the .so landed in the modules directory, the fleet
    # recorded that it wanted the WAF, and nothing ever wrote the load_module
    # line.  The upgrade walk now does it as part of the build, which is the
    # right place.  This is the way back for a node that is already in that
    # state, so recovering does not mean rebuilding nginx from source again.
    #
    # Only ever loads, never unloads.  Turning the module off is a rebuild
    # decision and belongs with the rebuild; quietly unloading it here because
    # a setting says false could take the module out from under a site that is
    # using it, at the worst possible moment, which is a manager restart.
    #
    # The verb refuses when the .so is not there, tests nginx afterwards and
    # puts the old state back if the test fails, so the worst case here is a
    # line in the log.
    try:
        from app.core.settings_store import get as _setting

        status = await agent.call("waf_module_status")

        if _setting("waf_module") and status.get("built") and not status.get("loaded"):
            log.warning("this fleet wants the WAF module and nginx has not "
                        "been told about it, loading it now")
            await agent.call("waf_module", enabled=True)
            status = await agent.call("waf_module_status")

        # Write down whether nginx here has actually been told about the
        # module, because `nginx -V` cannot say.  It reports what was compiled
        # in, and built is not loaded: the gate that decides whether the GUI
        # offers the WAF used to be satisfied by the build alone, so a node
        # that was built and not loaded passed it, the setting was offered, and
        # the apply failed fleet wide with a raw emerg.
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
    Put a request through this node's own listener and write down the answer.

    Runs far more often than refresh_local_state, because this is the signal
    the GSLB withdraws a node on and the record's TTL is measured in seconds.
    Checking it once a minute would mean a minute of handing out a black hole
    before DNS even began to move.

    Kept out of refresh_local_state on purpose.  That function talks to the
    host agent and does a lot of other work, so a slow agent would delay this,
    and this is the one thing here that has to stay quick.
    """
    settings = get_settings()
    probe = get_probe()

    # Empty means ask on the address this node was configured with, which is
    # the one a gslb answer hands out for it.  Nothing about the address is
    # hard coded here: a fleet that renumbers changes NFM_NODE_ADDRESS and this
    # follows it.
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
        # Never let a broken probe be the thing that decides a node is down.
        # Leaving the last verdict alone is the safe failure here: a bug in
        # this code should not be able to take a working node off the internet.
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

    # Withdrawing from DNS routes around the problem.  This is the part that
    # fixes it.  Deliberately after the write above, so the node is already on
    # its way out of the answer before its listener drops for a restart.
    if verdict is False and settings.frontend_watchdog:
        await get_watchdog().repair(
            time.time(),
            settings.frontend_watchdog_cooldown,
            settings.frontend_watchdog_max_per_day,
            detail=probe.detail,
        )


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

    # Three states, and only one of them is a problem.
    #
    # This used to ask ca.exists(), which is "can this node sign for the
    # cluster", and report a false answer as "this node is not in the cluster".
    # Only the founding node holds the CA key; every node that joined is given
    # the CA certificate and never the key, on purpose.  So every joined node
    # in every fleet printed "This node needs to rejoin the cluster" at every
    # startup while it was working perfectly, and rejoining on that advice is
    # disruptive for no reason.
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

    # A CA whose certificate and key do not match cannot sign anything the rest
    # of the fleet will accept.  Say so here, plainly, rather than letting it
    # surface later as peer connections failing for no visible reason.
    #
    # Not repaired automatically on purpose.  Every node certificate out there
    # was signed by this CA, so replacing it would quietly invalidate all of
    # them and every node would have to rejoin.  That is a decision for a person.
    # Only meaningful where there is a key to match against the certificate,
    # which is the founding node.  Asking it anywhere else compares a
    # certificate with a key that is not supposed to be there.
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

    # The country database, if anybody asked for one.  Hourly ticks, and the
    # job itself decides whether anything is due, so changing the schedule from
    # monthly to daily takes effect without a restart.
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

    # The WAF rule set, on the same hourly tick and for the same reasons.  Its
    # own job rather than sharing the country database's, so a source that is
    # unreachable stops one of them and not both.
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

    # Rotating the firewall's audit logs.  Every fifteen minutes rather than
    # hourly, and from every node rather than the active one.
    #
    # A site being scanned in watching mode writes steadily, and nobody looks
    # at the disk on a load balancer until it is full.  An hour of a determined
    # scan is a lot of JSON, and a standby that filled its own disk is a
    # standby that cannot be failed over to, which is found out at the worst
    # possible moment.  The job itself is cheap when there is nothing to do,
    # which is nearly every tick.
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

    # Accounts, converging on their own.
    #
    # The push after a change is the fast path.  This is what makes the fleet
    # agree again when that push could not be delivered, which is exactly the
    # case that matters: an account taken away while the other box was down must
    # not come back when it returns.  Does nothing on a standby, and nothing on
    # the active node when the accounts already match.
    # DNS zones, converging the same way and for a sharper reason.  A zone
    # renders no nginx config at all, so it never travelled with a config
    # apply, and a standby with no zones runs no listener.  Losing the active
    # node then took the whole fleet's DNS with it, which is the one thing this
    # feature exists to survive.  Does nothing on a standby.
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

    # Bring the dns listener up, if anything is configured to be served.
    #
    # A failure here is logged and stepped over rather than raised.  Port 53
    # may be taken by a resolver the distribution installed, and a manager that
    # refuses to start because of that would take the whole GUI away over a
    # feature most fleets will never turn on.
    try:
        gslb.refresh()
        if gslb.get_server().data.zones:
            gslb.get_server().start()
            # Scheduled rather than awaited, because this function is not async
            # and the redirect wants the agent, which is.  Once, a few seconds
            # in, so the listener is certainly up before anything is pointed at
            # it: a rule with nothing behind it answers no queries at all,
            # which looks exactly like the box being down.
            scheduler.add_job(
                gslb.ensure_redirect,
                "date",
                run_date=_dt.datetime.now(_dt.timezone.utc) + _dt.timedelta(seconds=5),
                id="gslb_redirect",
            )
    except Exception as exc:
        log.error("the dns listener did not start, so gslb is off: %s", exc)

    # Keep the dns answers in step with which nodes are actually serving, and
    # the listener in step with whether there is anything to serve.
    #
    # Ten seconds because the whole point of this feature is a short TTL, and a
    # snapshot that lags the TTL would hand out an address for a box that has
    # been down since before the answer was cached.
    #
    # reconcile rather than refresh, because the block above only starts the
    # listener if a zone is already in the database at boot.  A node joining an
    # existing cluster is empty at that moment and gets its config seconds
    # later, so it lost that race every time and never looked again.
    scheduler.add_job(
        gslb.reconcile,
        "interval",
        seconds=10,
        id="gslb_zones",
        max_instances=1,
        coalesce=True,
    )

    # Connection numbers, so the dashboard has something moving on it.
    #
    # Fifteen seconds because these are counters and the useful thing is the
    # rate between two readings.  Too far apart and a spike is averaged away,
    # too close and it is all noise from the manager's own health checks.
    scheduler.add_job(
        get_collector().collect,
        "interval",
        seconds=15,
        id="nginx_metrics",
        max_instances=1,
        coalesce=True,
    )

    # Telemetry written down, so it survives a restart.
    #
    # Every minute, and on every node.  The job folds the completed minute out
    # of memory, rolls anything past 48 hours into five minute buckets, and
    # prunes past thirty days.  All three are cheap and two of them usually do
    # nothing, which is what lets this run on a timer rather than being
    # something somebody has to remember.
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

    # What the backends say about themselves, for anything publishing it.
    #
    # Slower than our own numbers on purpose.  This reaches out to somebody
    # else's servers, cpu and memory do not need fifteen second resolution to
    # be useful, and being a polite visitor to a box we do not own matters more
    # than the extra detail.
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

    # Notice a domain that stopped pointing at us, while the certificate it
    # belongs to is still valid and there is time to do something about it.
    # Hourly is plenty: DNS moves when a person moves it, not on its own.
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

    # Much more often than local_state, because this is what takes a wedged
    # node out of DNS and the record's TTL is 30 seconds on a normal setup.
    scheduler.add_job(refresh_frontend_state, "interval",
                      seconds=get_settings().frontend_probe_interval,
                      id="frontend_probe", max_instances=1, coalesce=True)

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

    # Kick this off in the background.  It reaches out to the internet and can
    # take a few seconds, and blocking startup on it means a box with no route
    # out sits there looking hung.
    asyncio.create_task(refresh_public_ip())

    # Put the certbot hooks on the host now rather than waiting for the first
    # certificate.  Finding out they are missing halfway through an issue is a
    # bad time to find out.
    async def _hooks():
        from app.core import acme_hooks

        await acme_hooks.ensure_hooks()

    asyncio.create_task(_hooks())

    # Check the certificate files now rather than waiting five minutes.  A node
    # that just came back without them would otherwise spend that time unable
    # to apply anything, with an error about a file rather than about the
    # certificate.
    async def _certs():
        from app.core.acme import get_cert_manager

        await asyncio.sleep(5)
        await get_cert_manager().verify_files()

    asyncio.create_task(_certs())

    start_scheduler()

    # Settle who is active now, rather than up to one election interval from
    # now.
    #
    # register_self stands a returning node down to standby on purpose, and
    # until an election has run this node refuses config changes.  The election
    # job is on an interval and an interval job does not fire until one whole
    # interval has passed, so that refusal lasts about twice the heartbeat
    # every time the container restarts, which is every upgrade.  Somebody
    # applying in that window used to be told to go and use the active node,
    # and there was no active node to go to.
    #
    # A heartbeat first, then the election.  The other way round the election
    # judges the peers on last_heartbeat values written before this node went
    # down, so a node that has been away a while sees a peer that is alive and
    # serving as dead and can take the role off it for a couple of seconds.
    # Asking the peers first costs one round trip and means the first election
    # runs on better information than the periodic ones do.
    #
    # In the background, because it talks to the network and a node with an
    # unreachable peer must not sit in startup waiting for a timeout.
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

        # Worth a line of its own.  This is the window in which the node
        # refuses config changes after a restart, and until it was measured
        # nobody knew it was there at all: it was filed as a node that
        # "briefly believed it was a standby" with no cause.  Saying how long
        # it took, every time, means the next person can see it rather than
        # deduce it.
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

    # Give port 53 back before going away.
    #
    # The redirect lives on the host, in nftables, and outlives this container
    # completely.  Stopping the manager left the rule behind pointing at a port
    # with nothing listening on it, so the box went on accepting DNS on 53 and
    # answering none of it.
    #
    # That is worse than the box being down, and clear_redirect's own docstring
    # says why: a resolver that gets silence sits there until it times out,
    # while a resolver that cannot reach the address at all moves on to the
    # other nameserver immediately.  On a two node fleet it looks like DNS has
    # failed everywhere when one node's container was stopped.
    #
    # Best effort and time limited.  A node that cannot reach its agent on the
    # way out must not hang the shutdown; the agent clears a stale rule on its
    # own as well.
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
    app.include_router(account_router)
    app.include_router(api_router, prefix="/api")
    # The tunnel carries its own full paths: the managed half under /api and
    # the enrolment half at /tunnel, which has to be reachable by a workload
    # that is not on the management allow list.  On the GUI listener, never the
    # peer one, which demands a client certificate no workload will ever have.
    app.include_router(tunnel_router)
    app.include_router(backup_router)

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

    # Both there is not the same as both good.
    #
    # This used to check only that the files existed.  A pair that does not go
    # together, which is what you get if a run was interrupted between writing
    # the key and writing the certificate, passed that check happily.  uvicorn
    # then refused to build an SSL context, the process died before it listened
    # on anything, and docker restarted it into the same wall forever.  A crash
    # loop with no way out, over two files we can simply make again.
    #
    # So check they actually match, and rebuild them if they do not.  There is
    # nothing to lose by regenerating: it is a self signed certificate for a
    # management GUI, not something anybody has pinned.
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

    # Write both to one side first, then move them into place together.
    #
    # These were written straight over the top, key first and certificate
    # second.  Dying in the gap between the two left a new key beside the old
    # certificate, which do not match, and the app would not start again.
    #
    # Two renames are still two operations, so this narrows the window rather
    # than closing it.  What actually closes it is gui_ssl_context checking that
    # the pair matches and rebuilding them when it does not.  Both, because a
    # window this cheap to shrink is worth shrinking.
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
