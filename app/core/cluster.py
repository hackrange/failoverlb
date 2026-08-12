"""
The cluster.

Every nginx box runs the same container and they form a trust group.  One node
is ACTIVE and takes the writes.  The rest are STANDBY, stay in sync, and are
ready to take over.  This is how an F5 device group behaves and it is a shape
people already understand.

Why not let every node take writes?  Because two admins editing the same site on
two nodes at the same time gives you two different answers and no way to tell
which one is right.  Load balancer config is not something you want to merge and
hope.  One writer means there is always exactly one truth.

The three things in here that matter most:

  Two phase apply.  Nothing goes live anywhere until every reachable node has
  staged it and run nginx -t on it.  If any node says no, nobody applies.  That
  is the difference between one bad config breaking one box and one bad config
  breaking your whole edge.

  The pending queue.  A node that was down during a change is not forgotten and
  is not left to drift.  The change gets written down against that node, and
  when it comes back the sync worker catches it up.

  Peer auth.  The peer port is not the web GUI and it is not open.  Getting in
  takes a client certificate signed by this cluster's own CA, a source address
  on the roster, and a signature on the message from a key only that node has.
"""

import asyncio
import hashlib
import json
import logging
import ssl
import time
from datetime import datetime, timedelta, timezone

import httpx

from app.config import get_settings
from app.core.crypto import ClusterCA, decrypt, encrypt, new_token, sign_payload, verify_payload
from app.db import session_scope
from app.models import (
    ChangeState,
    ConfigVersion,
    Node,
    NodeRole,
    NodeState,
    PendingChange,
    utcnow,
)

log = logging.getLogger("nfm.cluster")

# How long a peer request gets before we call the node unreachable.
PEER_TIMEOUT = 15
PEER_PREPARE_TIMEOUT = 60

# A signed peer message older than this is refused.  Stops somebody who captured
# a request from replaying it later.
MAX_CLOCK_SKEW_SECONDS = 60

# Nonces we have already seen, so a replay inside the skew window still fails.
# Trimmed as it goes so it cannot grow without limit.
_seen_nonces = {}


class ClusterError(Exception):
    pass


class NodeUnreachable(ClusterError):
    """
    Could not talk to a node.

    Its own type because it is the one failure that does not stop an apply.
    Unreachable nodes get queued.  A node that answered and said no is a
    different matter and stops everything.
    """


# ==============================================================================
# Talking to peers
# ==============================================================================

class PeerClient:
    """
    Calls another node.

    Three separate checks have to pass, on purpose.  Any one of them alone has a
    way to be wrong:

      mTLS proves the caller holds a cert from our cluster CA.  On its own it
      does not say which node, and a stolen node cert would work.

      The source address has to be on the roster.  On its own that is spoofable,
      and it breaks on NAT.

      The HMAC proves this exact message came from the node that claims to have
      sent it, and the timestamp and nonce inside the signature stop a captured
      message being replayed.

    Together they are hard to get around without having actually compromised a
    cluster member, at which point you have bigger problems.
    """

    def __init__(self, node: Node, ca: ClusterCA = None):
        self.node = node
        self.ca = ca or ClusterCA()
        self.settings = get_settings()

    def _ssl_context(self) -> ssl.SSLContext:
        """
        TLS that only trusts our own CA.

        load_verify_locations with just the cluster CA replaces the normal trust
        store rather than adding to it.  That is what we want.  A certificate
        from a real public CA is worth nothing here, which is the whole point of
        having our own.
        """
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_verify_locations(cafile=str(self.ca.ca_cert_path))
        ctx.load_cert_chain(
            certfile=str(self.ca.node_cert_path),
            keyfile=str(self.ca.node_key_path),
        )
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Node certs carry the node name and its addresses in the SAN, and we
        # connect by address, so hostname checking does work here.  Leave it on.
        ctx.check_hostname = True
        ctx.minimum_version = ssl.TLSVersion.TLSv1_2
        return ctx

    async def call(self, path: str, payload: dict = None, timeout: int = PEER_TIMEOUT) -> dict:
        url = f"https://{self.node.address}:{self.node.peer_port}{path}"
        body = json.dumps(payload or {}).encode()

        hmac_key = decrypt(self.node.hmac_key_encrypted)
        if not hmac_key:
            raise ClusterError(f"no shared key for node {self.node.name}, it needs to rejoin")

        timestamp = str(int(time.time()))
        nonce = new_token(16)
        signature = sign_payload(
            hmac_key, self.settings.node_name, timestamp, nonce, body
        )

        headers = {
            "Content-Type": "application/json",
            "X-NFM-Node": self.settings.node_name,
            "X-NFM-Timestamp": timestamp,
            "X-NFM-Nonce": nonce,
            "X-NFM-Signature": signature,
        }

        try:
            async with httpx.AsyncClient(
                verify=self._ssl_context(),
                timeout=timeout,
            ) as client:
                response = await client.post(url, content=body, headers=headers)
        except (httpx.ConnectError, httpx.ConnectTimeout) as exc:
            raise NodeUnreachable(f"{self.node.name} is not answering: {exc}")
        except httpx.TimeoutException:
            raise NodeUnreachable(f"{self.node.name} timed out after {timeout}s")
        except ssl.SSLError as exc:
            # Worth its own message.  This almost always means the node's cert
            # expired or somebody rebuilt a box and it needs to rejoin, and that
            # is a very different fix from a network problem.
            raise ClusterError(
                f"TLS to {self.node.name} failed, its cert is probably expired "
                f"or it needs to rejoin the cluster: {exc}"
            )
        except httpx.HTTPError as exc:
            raise NodeUnreachable(f"could not reach {self.node.name}: {exc}")

        if response.status_code == 401:
            raise ClusterError(f"{self.node.name} rejected our credentials, it may need to rejoin")
        if response.status_code >= 400:
            raise ClusterError(
                f"{self.node.name} answered {response.status_code}: {response.text[:300]}"
            )

        try:
            return response.json()
        except json.JSONDecodeError:
            raise ClusterError(f"{self.node.name} sent back something that was not json")


def verify_peer_request(node_name: str, timestamp: str, nonce: str,
                        body: bytes, signature: str, source_ip: str) -> Node:
    """
    Check a request that came in on the peer port.

    Called before any peer route runs.  Everything has to line up or we refuse.
    """
    if not all([node_name, timestamp, nonce, signature]):
        raise ClusterError("that request is missing its signature headers")

    # Freshness.  Reject anything too old or too far in the future, so a
    # captured request cannot be replayed tomorrow.
    try:
        sent_at = int(timestamp)
    except ValueError:
        raise ClusterError("bad timestamp")

    drift = abs(time.time() - sent_at)
    if drift > MAX_CLOCK_SKEW_SECONDS:
        raise ClusterError(
            f"that message is {int(drift)}s out of date.  Check the clocks on your nodes."
        )

    # Replay inside the window.  Same nonce twice is not allowed.
    now = time.time()
    for old_nonce, seen_at in list(_seen_nonces.items()):
        if now - seen_at > MAX_CLOCK_SKEW_SECONDS * 2:
            _seen_nonces.pop(old_nonce, None)

    key = f"{node_name}:{nonce}"
    if key in _seen_nonces:
        raise ClusterError("that message has already been used once")

    with session_scope() as session:
        node = session.query(Node).filter(Node.name == node_name).first()
        if not node:
            raise ClusterError(f"{node_name} is not a member of this cluster")

        # The source address has to be one this node is known to use.  Belt and
        # braces on top of the cert, and it catches a cert that walked off a
        # decommissioned box onto something else.
        known = {node.address} | {
            a.get("address") for a in node.local_address_list() if a.get("address")
        }
        if source_ip not in known and source_ip not in ("127.0.0.1", "::1"):
            log.warning(
                "%s called us from %s, which is not an address we have for it",
                node_name, source_ip,
            )
            raise ClusterError(f"{node_name} is not expected to call from {source_ip}")

        hmac_key = decrypt(node.hmac_key_encrypted)
        if not hmac_key:
            raise ClusterError(f"no shared key on file for {node_name}")

        if not verify_payload(hmac_key, node_name, timestamp, nonce, body, signature):
            raise ClusterError("the signature on that message does not check out")

        _seen_nonces[key] = now
        return node


# ==============================================================================
# The cluster manager
# ==============================================================================

class ClusterManager:
    def __init__(self):
        self.settings = get_settings()
        self.ca = ClusterCA()
        self.node_name = self.settings.node_name
        self._apply_lock = asyncio.Lock()

    # ---- who we are ---------------------------------------------------------

    def self_node(self, session) -> Node:
        return session.query(Node).filter(Node.name == self.node_name).first()

    def peers(self, session):
        return session.query(Node).filter(Node.name != self.node_name).all()

    def is_active(self, session) -> bool:
        me = self.self_node(session)
        return bool(me and me.role == NodeRole.ACTIVE)

    # =========================================================================
    # Election
    # =========================================================================

    async def run_election(self):
        """
        Work out who should be active.

        Deliberately simple.  Highest priority among healthy nodes wins, and a
        tie breaks on node name so the answer is the same every time no matter
        who is asking.

        This is not Raft and does not pretend to be.  Raft would give stronger
        guarantees at the cost of a lot more code and a lot more ways to go
        subtly wrong.  What we do have is the one protection that matters: a
        node will not make itself active unless it can see more than half the
        cluster.  Two halves of a split network cannot both elect themselves.
        """
        with session_scope() as session:
            nodes = session.query(Node).all()
            if not nodes:
                return

            total = len(nodes)
            me = self.self_node(session)
            if not me:
                return

            healthy = [
                n for n in nodes
                if not n.forced_standby
                and (n.is_self or _recently_seen(n, self.settings.node_dead_after))
            ]

            # Quorum.  With no majority we do not get to be active, even if
            # everybody we can see agrees.  In a network split the smaller side
            # has to stand down, or both sides start writing config and you get
            # two different edges serving two different things.
            #
            # Two nodes are the exception, and it has to be, because a pair can
            # never reach a majority when one of them is down.  One out of two
            # is not more than half, so the strict rule meant an HA pair lost
            # the ability to change anything the moment either node died, which
            # is the exact moment you need it.  A load balancer you cannot
            # reconfigure during an outage is not much of a load balancer.
            #
            # So for a pair the survivor takes over.  The risk that buys is a
            # split where both sides think they are alone and both go active.
            # That is a real risk and worth understanding: config written on one
            # side during the split gets overwritten when they meet again.  It
            # is still the better trade, because a split between two boxes is
            # rarer than one box rebooting, and the damage is a lost edit rather
            # than an outage.  Three or more nodes keep the strict rule, where
            # majority actually means something.
            pair = (total == 2)
            if total > 1 and not pair and len(healthy) <= total / 2:
                if me.role == NodeRole.ACTIVE:
                    log.warning(
                        "only %s of %s nodes are visible, that is not a majority, "
                        "so stepping down to standby",
                        len(healthy), total,
                    )
                    me.role = NodeRole.STANDBY
                    session.commit()
                return

            if not healthy:
                return

            winner = sorted(healthy, key=lambda n: (-n.priority, n.name))[0]

            for node in nodes:
                should_be = NodeRole.ACTIVE if node.name == winner.name else NodeRole.STANDBY
                if node.role != should_be:
                    log.info("%s is now %s", node.name, should_be.value)
                    node.role = should_be

            session.commit()

    async def failover_to(self, target_name: str, actor: str = "system"):
        """Hand active over to a specific node, by hand."""
        with session_scope() as session:
            target = session.query(Node).filter(Node.name == target_name).first()
            if not target:
                raise ClusterError(f"there is no node called {target_name}")
            if target.forced_standby:
                raise ClusterError(f"{target_name} is pinned to standby, unpin it first")
            if not _recently_seen(target, self.settings.node_dead_after) and not target.is_self:
                raise ClusterError(f"{target_name} is not answering, so it cannot take over")

            for node in session.query(Node).all():
                node.role = NodeRole.ACTIVE if node.name == target_name else NodeRole.STANDBY

            session.commit()
            log.warning("%s made %s the active node", actor, target_name)

    # =========================================================================
    # Two phase apply
    # =========================================================================

    async def apply_config(self, rendered: dict, checksum: str, summary: str,
                           author: str, snapshot: dict) -> dict:
        """
        Push a config change out to the whole fleet, safely.

        Phase one, prepare.  Every reachable node stages the files and runs
        nginx -t on them.  Nothing is live yet.  A node that fails the test
        stops the whole thing right here, and since nothing was applied
        anywhere, there is nothing to undo.

        Phase two, commit.  Every node that prepared cleanly swaps the config in
        and reloads.  If a node fails at this point, every node that already
        committed gets rolled back, so the fleet ends up consistent either way.

        Nodes that were unreachable during phase one get the version written
        into their pending queue and are caught up when they return.

        The important promise: you never end up with half your load balancers on
        one config and half on another.
        """
        async with self._apply_lock:
            return await self._apply_config_locked(
                rendered, checksum, summary, author, snapshot
            )

    async def _apply_config_locked(self, rendered, checksum, summary, author, snapshot):
        started = time.monotonic()

        with session_scope() as session:
            if not self.is_active(session):
                raise ClusterError(
                    "this node is a standby, so it does not take config changes.  "
                    "Make your change on the active node."
                )

            # Nothing to do.  Saying so beats a pointless reload of every box.
            latest = session.query(ConfigVersion).order_by(
                ConfigVersion.version.desc()
            ).first()
            if latest and latest.checksum == checksum:
                return {
                    "ok": True,
                    "unchanged": True,
                    "version": latest.version,
                    "message": "nothing actually changed, so nothing was reloaded",
                }

            next_version = (latest.version if latest else 0) + 1

            version_row = ConfigVersion(
                version=next_version,
                checksum=checksum,
                snapshot=json.dumps(snapshot),
                rendered=json.dumps(rendered),
                author=author,
                summary=summary[:500] if summary else None,
                origin_node=self.node_name,
            )
            session.add(version_row)
            session.commit()

            peers = self.peers(session)
            peer_info = [
                {"name": p.name, "address": p.address, "port": p.peer_port}
                for p in peers
            ]

        # ---- pre-flight ------------------------------------------------------
        # Before touching anything, check the fleet is in a state worth changing.
        # Pushing config onto a farm that is already half broken is how a small
        # problem becomes an outage.
        preflight = await self._preflight_check()

        # ---- phase one, prepare ---------------------------------------------
        prepared = []
        unreachable = []
        failed = []

        local_result = await self._prepare_local(rendered)
        if not local_result["ok"]:
            with session_scope() as session:
                session.query(ConfigVersion).filter(
                    ConfigVersion.version == next_version
                ).delete()
                session.commit()
            return {
                "ok": False,
                "phase": "prepare",
                "node": self.node_name,
                "error": local_result.get("output", "the config test failed on this node"),
                "preflight": preflight,
            }
        prepared.append(self.node_name)

        for info in peer_info:
            try:
                result = await self._prepare_peer(info, rendered, next_version, checksum)
                if result.get("ok"):
                    prepared.append(info["name"])
                else:
                    failed.append({
                        "node": info["name"],
                        "error": result.get("output", "the config test failed there"),
                    })
            except NodeUnreachable as exc:
                log.warning("%s is unreachable, queueing the change: %s", info["name"], exc)
                unreachable.append(info["name"])
            except ClusterError as exc:
                failed.append({"node": info["name"], "error": str(exc)})

        # Any node that answered and said the config is bad stops everything.
        # Nothing has gone live, so there is nothing to unwind.
        if failed:
            log.error("prepare failed on %s, so nothing was applied anywhere", failed)
            with session_scope() as session:
                session.query(ConfigVersion).filter(
                    ConfigVersion.version == next_version
                ).delete()
                session.commit()
            return {
                "ok": False,
                "phase": "prepare",
                "failed": failed,
                "prepared": prepared,
                "unreachable": unreachable,
                "error": "the config did not pass its test on every node, so nothing changed",
                "preflight": preflight,
            }

        # ---- phase two, commit ----------------------------------------------
        committed = []
        commit_failed = []

        local_commit = await self._commit_local(next_version)
        if not local_commit.get("ok"):
            with session_scope() as session:
                session.query(ConfigVersion).filter(
                    ConfigVersion.version == next_version
                ).delete()
                session.commit()
            return {
                "ok": False,
                "phase": "commit",
                "node": self.node_name,
                "error": local_commit.get("output", "the local apply failed"),
                "preflight": preflight,
            }
        committed.append(self.node_name)

        for info in peer_info:
            if info["name"] not in prepared:
                continue
            try:
                result = await self._commit_peer(info, next_version)
                if result.get("ok"):
                    committed.append(info["name"])
                else:
                    commit_failed.append({
                        "node": info["name"],
                        "error": result.get("output", "the commit failed there"),
                    })
            except (NodeUnreachable, ClusterError) as exc:
                # A node that dropped out between prepare and commit.  Rare, but
                # it happens, and it is exactly why the queue exists.
                commit_failed.append({"node": info["name"], "error": str(exc)})

        if commit_failed:
            log.error("commit failed on %s, rolling the whole fleet back", commit_failed)
            await self._rollback_everywhere(committed)
            with session_scope() as session:
                session.query(ConfigVersion).filter(
                    ConfigVersion.version == next_version
                ).delete()
                session.commit()
            return {
                "ok": False,
                "phase": "commit",
                "failed": commit_failed,
                "rolled_back": committed,
                "error": "a node failed to apply, so the whole fleet was put back",
                "preflight": preflight,
            }

        # ---- record what happened -------------------------------------------
        with session_scope() as session:
            row = session.query(ConfigVersion).filter(
                ConfigVersion.version == next_version
            ).first()
            if row:
                row.applied = True
                row.applied_at = utcnow()

            for name in committed:
                node = session.query(Node).filter(Node.name == name).first()
                if node:
                    node.applied_version = next_version
                    node.applied_checksum = checksum
                    node.last_sync_at = utcnow()
                    node.last_error = None

            # Anybody we could not reach gets queued rather than forgotten.
            for name in unreachable:
                self._queue_change(session, name, next_version)
                node = session.query(Node).filter(Node.name == name).first()
                if node:
                    node.state = NodeState.OFFLINE
                    node.last_error = "was not reachable during the last change"

            session.commit()

        elapsed = round(time.monotonic() - started, 2)
        log.info(
            "applied version %s to %s in %ss, %s queued",
            next_version, committed, elapsed, len(unreachable),
        )

        return {
            "ok": True,
            "version": next_version,
            "checksum": checksum,
            "applied_to": committed,
            "queued_for": unreachable,
            "seconds": elapsed,
            "preflight": preflight,
        }

    # ---- pre-flight ---------------------------------------------------------

    async def _preflight_check(self) -> dict:
        """
        Look at the fleet before changing anything.

        This does not block the change.  It is information, gathered and handed
        back so the GUI can warn you.  Blocking every change whenever one pool
        is degraded would mean you cannot fix the degraded pool, which is
        exactly backwards.

        What it flags is worth knowing before you hit apply:
          - nodes we cannot see right now
          - nodes whose nginx is not running
          - pools with no healthy members left
        """
        from app.models import Pool

        warnings = []
        with session_scope() as session:
            nodes = session.query(Node).all()
            for node in nodes:
                if node.is_self:
                    continue
                if not _recently_seen(node, self.settings.node_dead_after):
                    warnings.append({
                        "level": "warning",
                        "message": (
                            f"{node.name} has not checked in, so this change will be "
                            f"queued for it and applied when it comes back"
                        ),
                    })
                elif not node.nginx_active:
                    warnings.append({
                        "level": "warning",
                        "message": f"nginx is not running on {node.name}",
                    })

            for pool in session.query(Pool).all():
                if pool.members and pool.healthy_count == 0:
                    warnings.append({
                        "level": "critical",
                        "message": (
                            f"pool {pool.name} has no healthy backends at all, "
                            f"so it is already serving errors"
                        ),
                    })
                elif pool.members and pool.healthy_count < (pool.min_healthy_members or 1):
                    warnings.append({
                        "level": "warning",
                        "message": (
                            f"pool {pool.name} is down to {pool.healthy_count} healthy "
                            f"backends, below the {pool.min_healthy_members} you asked for"
                        ),
                    })

        return {"warnings": warnings, "safe": not any(
            w["level"] == "critical" for w in warnings
        )}

    # ---- prepare and commit, locally ---------------------------------------

    async def _prepare_local(self, rendered: dict) -> dict:
        from app.core.agent_client import AgentError, get_agent

        agent = get_agent()
        try:
            await agent.write_staging(rendered)
            return await agent.test_staging()
        except AgentError as exc:
            return {"ok": False, "output": str(exc)}

    async def _commit_local(self, version: int) -> dict:
        from app.core.agent_client import AgentError, get_agent

        agent = get_agent()
        try:
            return await agent.apply(reload=True, label=f"v{version}")
        except AgentError as exc:
            return {"ok": False, "output": str(exc)}

    # ---- prepare and commit, on a peer -------------------------------------

    async def _prepare_peer(self, info, rendered, version, checksum) -> dict:
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == info["name"]).first()
            if not node:
                raise ClusterError(f"{info['name']} is not on the roster")
            client = PeerClient(node, self.ca)

        return await client.call(
            "/peer/config/prepare",
            {"version": version, "checksum": checksum, "files": rendered},
            timeout=PEER_PREPARE_TIMEOUT,
        )

    async def _commit_peer(self, info, version) -> dict:
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == info["name"]).first()
            if not node:
                raise ClusterError(f"{info['name']} is not on the roster")
            client = PeerClient(node, self.ca)

        return await client.call(
            "/peer/config/commit", {"version": version}, timeout=PEER_PREPARE_TIMEOUT
        )

    async def _rollback_everywhere(self, node_names):
        """Put every node that committed back where it was."""
        from app.core.agent_client import get_agent

        for name in node_names:
            try:
                if name == self.node_name:
                    await get_agent().rollback()
                else:
                    with session_scope() as session:
                        node = session.query(Node).filter(Node.name == name).first()
                        if node:
                            client = PeerClient(node, self.ca)
                            await client.call("/peer/config/rollback", {})
            except Exception:
                # Keep going.  One node refusing to roll back is bad, but
                # stopping here would leave the rest on the broken config too.
                log.exception("could not roll back %s", name)

    # =========================================================================
    # The pending change queue
    # =========================================================================

    def _queue_change(self, session, node_name: str, version: int):
        existing = session.query(PendingChange).filter(
            PendingChange.node_name == node_name,
            PendingChange.version == version,
        ).first()
        if existing:
            return

        session.add(PendingChange(
            node_name=node_name,
            version=version,
            state=ChangeState.PENDING,
        ))
        log.info("queued version %s for %s", version, node_name)

    async def drain_pending(self):
        """
        Catch up any node that has queued changes waiting.

        The trick here is that we do not replay the queue one version at a time.
        A node that missed twelve changes does not need to apply all twelve, it
        needs to end up on the newest one.  So we push the latest version, and
        if it lands, the whole backlog for that node clears at once.

        Doing it the other way would mean a node that was down over a weekend
        reloading nginx a hundred times to catch up, running through config
        states nobody is interested in.
        """
        with session_scope() as session:
            pending_nodes = {
                row.node_name for row in
                session.query(PendingChange).filter(
                    PendingChange.state == ChangeState.PENDING
                ).all()
            }
            if not pending_nodes:
                return

            latest = session.query(ConfigVersion).filter(
                ConfigVersion.applied == True  # noqa: E712
            ).order_by(ConfigVersion.version.desc()).first()
            if not latest:
                return

            target_version = latest.version
            rendered = json.loads(latest.rendered or "{}")
            checksum = latest.checksum

            node_rows = {
                n.name: n for n in
                session.query(Node).filter(Node.name.in_(pending_nodes)).all()
            }

        for name in pending_nodes:
            node = node_rows.get(name)
            if not node:
                continue

            try:
                info = {"name": node.name, "address": node.address, "port": node.peer_port}
                result = await self._prepare_peer(info, rendered, target_version, checksum)
                if not result.get("ok"):
                    raise ClusterError(result.get("output", "the config test failed there"))

                result = await self._commit_peer(info, target_version)
                if not result.get("ok"):
                    raise ClusterError(result.get("output", "the commit failed there"))

            except NodeUnreachable:
                # Still down.  Leave the queue alone and try again next time.
                continue
            except Exception as exc:
                log.error("could not catch %s up: %s", name, exc)
                with session_scope() as session:
                    for row in session.query(PendingChange).filter(
                        PendingChange.node_name == name,
                        PendingChange.state == ChangeState.PENDING,
                    ).all():
                        row.attempts = (row.attempts or 0) + 1
                        row.last_attempt_at = utcnow()
                        row.last_error = str(exc)[:1000]
                    session.commit()
                continue

            # It worked, so the whole backlog for this node is done.
            with session_scope() as session:
                rows = session.query(PendingChange).filter(
                    PendingChange.node_name == name,
                    PendingChange.state == ChangeState.PENDING,
                    PendingChange.version <= target_version,
                ).all()
                for row in rows:
                    row.state = ChangeState.APPLIED
                    row.completed_at = utcnow()

                node_row = session.query(Node).filter(Node.name == name).first()
                if node_row:
                    node_row.applied_version = target_version
                    node_row.applied_checksum = checksum
                    node_row.last_sync_at = utcnow()
                    node_row.state = NodeState.ONLINE
                    node_row.last_error = None
                session.commit()

            log.info("caught %s up to version %s, cleared %s queued changes",
                     name, target_version, len(rows))

    def pending_summary(self, session) -> dict:
        """What the GUI shows about who is behind."""
        rows = session.query(PendingChange).filter(
            PendingChange.state == ChangeState.PENDING
        ).all()

        by_node = {}
        for row in rows:
            entry = by_node.setdefault(row.node_name, {
                "count": 0, "oldest": None, "last_error": None,
            })
            entry["count"] += 1
            if entry["oldest"] is None or row.queued_at < entry["oldest"]:
                entry["oldest"] = row.queued_at
            if row.last_error:
                entry["last_error"] = row.last_error

        return by_node

    # =========================================================================
    # Heartbeats
    # =========================================================================

    async def send_heartbeats(self):
        """
        Tell every peer we are alive and ask how they are doing.

        This is also how the roster stays fresh.  Each answer carries the
        node's nginx state, its applied version and its public address, so the
        cluster page is never guessing.
        """
        with session_scope() as session:
            me = self.self_node(session)
            payload = {
                "node": self.node_name,
                "role": me.role.value if me else "unknown",
                "priority": self.settings.cluster_priority,
                "applied_version": me.applied_version if me else 0,
                "nginx_active": me.nginx_active if me else False,
                "timestamp": time.time(),
            }
            peers = [
                {"id": p.id, "name": p.name, "address": p.address, "port": p.peer_port}
                for p in self.peers(session)
            ]

        for info in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    client = PeerClient(node, self.ca)

                answer = await client.call("/peer/heartbeat", payload, timeout=PEER_TIMEOUT)

                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    node.last_heartbeat = utcnow()
                    node.state = NodeState.ONLINE
                    node.last_error = None
                    node.applied_version = answer.get("applied_version", node.applied_version)
                    node.nginx_active = answer.get("nginx_active", False)
                    node.nginx_config_ok = answer.get("nginx_config_ok", False)
                    node.nginx_version = answer.get("nginx_version") or node.nginx_version
                    if answer.get("nginx_build_info"):
                        node.nginx_build_info = answer["nginx_build_info"][:65536]
                    node.load_average = answer.get("load_average")
                    node.disk_free_bytes = answer.get("disk_free")
                    if answer.get("public_ip"):
                        node.public_ip = answer["public_ip"]
                        node.public_ip_checked_at = utcnow()
                    if answer.get("local_addresses"):
                        node.local_addresses = json.dumps(answer["local_addresses"])
                    if answer.get("role"):
                        try:
                            node.role = NodeRole(answer["role"])
                        except ValueError:
                            pass
                    session.commit()

            except NodeUnreachable as exc:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if node:
                        if _recently_seen(node, self.settings.node_dead_after):
                            # Not dead yet, just missed one.  Do not panic and
                            # do not start an election over a single lost packet.
                            pass
                        else:
                            if node.state != NodeState.OFFLINE:
                                log.warning("%s has gone quiet: %s", node.name, exc)
                            node.state = NodeState.OFFLINE
                        node.last_error = str(exc)[:500]
                        session.commit()
            except ClusterError as exc:
                log.error("heartbeat to %s was refused: %s", info["name"], exc)
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if node:
                        node.state = NodeState.DEGRADED
                        node.last_error = str(exc)[:500]
                        session.commit()

    # =========================================================================
    # Joining
    # =========================================================================

    def create_join_token(self, session, created_by: str, note: str = "",
                          hours: int = 2) -> str:
        """
        Make a ticket that lets one new box into the cluster.

        Short lived and single use.  Anybody holding one of these can get a
        signed cluster cert, so treat it exactly like a password.  We store only
        the hash, so a stolen database does not hand over working tokens.
        """
        from app.core.crypto import hash_token
        from app.models import JoinToken

        token = new_token(32)
        session.add(JoinToken(
            token_hash=hash_token(token),
            created_by=created_by,
            expires_at=utcnow() + timedelta(hours=hours),
            note=note[:255] if note else None,
        ))
        session.commit()
        return token


# ==============================================================================
# Helpers
# ==============================================================================

def _recently_seen(node: Node, dead_after: int) -> bool:
    if node.is_self:
        return True
    seconds = node.seconds_since_heartbeat
    if seconds is None:
        return False
    return seconds < dead_after


_manager = None


def get_cluster() -> ClusterManager:
    global _manager
    if _manager is None:
        _manager = ClusterManager()
    return _manager
