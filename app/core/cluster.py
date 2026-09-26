"""
Cluster membership, elections and config distribution.

Every nginx box runs the same container. One node is ACTIVE and takes writes;
the rest are STANDBY and stay in sync, like an F5 device group. A single
writer avoids having to merge conflicting edits made on two nodes.

Two phase apply: nothing goes live until every reachable node has staged the
config and passed nginx -t. If any node refuses, nobody applies.

Pending queue: changes for a node that was down are recorded against it and
the sync worker catches it up when it returns.

Peer auth: the peer port requires a client cert from the cluster CA, a source
address on the roster, and an HMAC signature with that node's key.
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

# Signed peer messages older than this are refused, to limit replay.
MAX_CLOCK_SKEW_SECONDS = 60

# Nonces seen inside the skew window, so a replay there still fails.
# Pruned as it goes.
_seen_nonces = {}


def adopt_peer_role(session, peer, claimed, self_name: str):
    """Record a peer's claimed role without ever recording two actives.

    A peer claiming active while we are active is normal mid-failover. We
    stand down: being wrongly standby costs one election cycle, while being
    wrongly active means two writers.
    """
    if claimed != NodeRole.ACTIVE:
        peer.role = claimed
        return

    me = session.query(Node).filter(Node.name == self_name).first()
    if me and me.role == NodeRole.ACTIVE:
        log.warning("%s says it is active as well, standing down until the "
                    "election settles it", peer.name)
        me.role = NodeRole.STANDBY

    peer.role = claimed


def choose_winner(healthy, all_nodes, wanted):
    """Pick the active node. Pure function, so it is testable alone.

    Returns (winner, reason); reason is empty unless the requested node was
    passed over. The requested node wins if it is healthy, otherwise the
    highest priority healthy node, ties broken by name so every node reaches
    the same answer. An unfit request is ignored so failover still works.
    """
    if not healthy:
        return None, ""

    winner = sorted(healthy, key=lambda n: (-n.priority, n.name))[0]
    if not wanted:
        return winner, ""

    choice = next((n for n in healthy if n.name == wanted), None)
    if choice is not None:
        return choice, ""

    if any(n.name == wanted for n in all_nodes):
        return winner, (f"{wanted} was asked to be the active node and is not "
                        f"in a fit state, so {winner.name} takes it until that "
                        f"changes")
    return winner, (f"{wanted} was asked to be the active node and there is no "
                    f"such node, so {winner.name} takes it")


def preferred_active():
    """(name, timestamp) of the requested active node.

    An empty name means no request; the election uses priority.
    """
    from app.core import settings_store

    name = (settings_store.get("preferred_active_node") or "").strip()
    try:
        at = float(settings_store.get("preferred_active_at") or 0)
    except (TypeError, ValueError):
        at = 0.0
    return name, at


def set_preferred_active(name, actor: str = "system") -> float:
    """Record that somebody asked for a node, or cleared the request."""
    from app.core import settings_store

    at = time.time()
    settings_store.set("preferred_active_node", (name or "").strip(), actor)
    settings_store.set("preferred_active_at", repr(at), actor)
    return at


def adopt_preferred_active(name, at) -> bool:
    """Adopt a peer's preferred active node if theirs is newer.

    Last write wins, which is fine for one value set by a button press.
    Strictly newer, so equal timestamps do not flip back and forth.
    """
    from app.core import settings_store

    try:
        their_at = float(at or 0)
    except (TypeError, ValueError):
        return False

    mine, my_at = preferred_active()
    if their_at <= my_at:
        return False

    theirs = (name or "").strip()
    settings_store.set("preferred_active_node", theirs, "peer")
    settings_store.set("preferred_active_at", repr(their_at), "peer")
    if theirs != mine:
        log.warning("the other node says %s is the one to be active",
                    theirs or "nobody in particular")
    return theirs != mine


def looks_like_a_wipe(previous: dict, incoming: dict) -> str:
    """Reason string if applying this would drop most served sites, else "".

    A promoted standby has the rendered files but not the objects behind
    them, so rendering there once produced an empty config that wiped
    itself and was queued for the other node. Going to zero sites, or losing
    more than half at once, is flagged. Deleting a last site then needs
    confirming twice, which is an acceptable cost. A first apply is exempt.
    """
    def sites(files):
        return {p for p in files if p.startswith("sites/")}

    was, now = sites(previous), sites(incoming)

    if not was:
        return ""                       # nothing was being served, nothing to lose

    if not now:
        return (
            f"this would remove all {len(was)} site files and leave nothing being "
            f"served.  A config that renders no sites usually means the objects "
            f"they come from are missing rather than that somebody deleted every "
            f"site, which is what happens on a node that was promoted from standby."
        )

    gone = was - now
    if len(gone) > len(was) / 2:
        return (
            f"this would remove {len(gone)} of {len(was)} site files at once: "
            f"{', '.join(sorted(p.split('/')[-1] for p in gone)[:5])}"
        )

    return ""


class ClusterError(Exception):
    pass


class RoleNotSettled(ClusterError):
    """No node is active yet, e.g. for a few seconds after a restart.

    Separate from an ordinary refusal because the right answer is "retry",
    not "use the other node". Callers map it to a 503 with Retry-After
    instead of a 409.
    """


class NodeUnreachable(ClusterError):
    """Could not reach a node.

    Unlike other errors this does not abort an apply; the node is queued.
    A node that answers and refuses does abort it.
    """


# ==============================================================================
# Talking to peers
# ==============================================================================

class PeerClient:
    """Client for calls to another node.

    Requests are checked three ways, since each alone is weak: mTLS against
    the cluster CA (does not identify which node), source address on the
    roster (spoofable), and an HMAC over the message with a timestamp and
    nonce (identifies the sender and prevents replay).
    """

    def __init__(self, node: Node, ca: ClusterCA = None):
        self.node = node
        self.ca = ca or ClusterCA()
        self.settings = get_settings()

    def _ssl_context(self) -> ssl.SSLContext:
        """TLS context that trusts only the cluster CA, not public CAs."""
        ctx = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
        ctx.load_verify_locations(cafile=str(self.ca.ca_cert_path))
        ctx.load_cert_chain(
            certfile=str(self.ca.node_cert_path),
            keyfile=str(self.ca.node_key_path),
        )
        ctx.verify_mode = ssl.CERT_REQUIRED

        # Node certs list their addresses in the SAN, so this works.
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
            # Usually an expired cert or a rebuilt node that must rejoin,
            # which is a different fix from a network problem.
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
    """Authenticate a peer port request before any peer route runs."""
    if not all([node_name, timestamp, nonce, signature]):
        raise ClusterError("that request is missing its signature headers")

    # Reject messages too far in the past or future.
    try:
        sent_at = int(timestamp)
    except ValueError:
        raise ClusterError("bad timestamp")

    drift = abs(time.time() - sent_at)
    if drift > MAX_CLOCK_SKEW_SECONDS:
        raise ClusterError(
            f"that message is {int(drift)}s out of date.  Check the clocks on your nodes."
        )

    # Reject a reused nonce inside the window.
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

        # Source address must be one we know for this node. Extra to the cert
        # check; catches a cert copied off a decommissioned box.
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

    def not_active_error(self, session) -> ClusterError:
        """Build the error to raise when this node is not active.

        If another node is active, name it and give its address. If no node
        is active yet, or this node has no roster row (both normal just after
        a restart, since register_self stands down to wait for an election),
        return RoleNotSettled so the caller says to retry.
        """
        me = self.self_node(session)
        holder = (
            session.query(Node)
            .filter(Node.name != self.node_name, Node.role == NodeRole.ACTIVE)
            .first()
        )

        if holder:
            # Only call ourselves a standby if the roster says so; a fresh
            # row starts UNKNOWN.
            if me is not None and me.role == NodeRole.STANDBY:
                opening = "this node is a standby, so it does not take config changes."
            else:
                opening = ("this node does not hold the active role, so it does "
                           "not take config changes.")

            where = ""
            if holder.address:
                where = f"  It is at https://{holder.address}:{holder.gui_port or 7443}"
            return ClusterError(
                f"{opening}  Make your change on {holder.name}, which is the "
                f"active node.{where}"
            )

        if me is None:
            return RoleNotSettled(
                "this node is not in the roster yet, so it does not take config "
                "changes.  That happens for a moment while a node starts up.  "
                "Try again in a few seconds."
            )

        return RoleNotSettled(
            "no node in this fleet holds the active role at the moment, so "
            "there is nowhere to make this change yet.  That is normal for a "
            "few seconds after a restart, while the nodes settle which of them "
            "takes writes.  Try again in a few seconds."
        )

    async def replicate_gslb(self) -> dict:
        """Send this node's DNS zones to every online peer.

        Zones render no nginx config, so the config snapshot (which only moves
        when rendered config changes) never carried them, and a standby had no
        zones to serve after failover. Only the active node sends, to avoid
        two nodes flapping over the zone list.
        """
        from app.core import snapshot as snapshot_store

        with session_scope() as session:
            if not self.is_active(session):
                return {"skipped": "not the active node"}

            tables = snapshot_store.capture_gslb(session)
            # Lets the receiver tell "last zone deleted" from "blank node".
            has_config = not snapshot_store.is_empty(session)
            targets = [
                (p.name, PeerClient(p, self.ca))
                for p in self.peers(session)
                if p.state == NodeState.ONLINE
            ]

        if not targets:
            return {"sent_to": [], "failed": {}}

        sent, failed = [], {}
        for name, client in targets:
            try:
                await client.call("/peer/gslb", {"tables": tables,
                                                "sender_has_config": has_config})
                sent.append(name)
            except (NodeUnreachable, ClusterError) as exc:
                # The timer retries, so an unreachable node catches up.
                failed[name] = str(exc)
                log.warning("could not send the dns zones to %s: %s", name, exc)
        return {"sent_to": sent, "failed": failed}

    async def replicate_accounts(self) -> dict:
        """Send this node's accounts to every online peer.

        Accounts also ride the config snapshot, but that only moves when the
        rendered nginx config changes. Without this, a password change or a
        revoked account would sit on one node until an unrelated site edit.

        Called after account changes and on a timer. Only the active node
        sends, to avoid two nodes flapping over the account list.
        """
        from app.core import snapshot as snapshot_store

        with session_scope() as session:
            if not self.is_active(session):
                return {"skipped": "not the active node"}

            rows = snapshot_store.capture_users(session)
            targets = [
                (p.name, PeerClient(p, self.ca))
                for p in self.peers(session)
                if p.state == NodeState.ONLINE
            ]

        if not targets:
            return {"sent_to": [], "failed": {}}

        sent, failed = [], {}
        for name, client in targets:
            try:
                await client.call("/peer/accounts", {"users": rows})
                sent.append(name)
            except (NodeUnreachable, ClusterError) as exc:
                # Do not fail the account change; the timer retries.
                failed[name] = str(exc)
                log.warning("could not send accounts to %s: %s", name, exc)

        if sent:
            log.info("sent %d accounts to %s", len(rows), ", ".join(sent))
        return {"sent_to": sent, "failed": failed}

    # =========================================================================
    # Election
    # =========================================================================

    async def run_election(self):
        """Decide which node should be active.

        Deliberately simple, not Raft: see choose_winner for the rule. The
        one protection is quorum, so both halves of a split cannot elect
        themselves (with an exception for two node clusters, below).
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

            # Quorum: without a majority we stand down, so a split cannot
            # produce two writers.
            #
            # Two node clusters are exempt, since a pair can never have a
            # majority with one node down and would be unmanageable during
            # exactly the outage that matters. The cost is that in a true
            # split both go active, and edits made on one side are overwritten
            # when they rejoin. Three or more nodes keep the strict rule.
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

            # Honor a manual failover request while the requested node is
            # healthy; otherwise the election would hand the role straight
            # back on priority. It is a preference, not a pin (forced_standby
            # is the pin), so if that node dies failover still happens.
            wanted, _asked_at = preferred_active()
            winner, passed_over = choose_winner(healthy, nodes, wanted)
            if winner is None:
                return
            if passed_over:
                log.warning("%s", passed_over)

            promoted = False
            for node in nodes:
                should_be = NodeRole.ACTIVE if node.name == winner.name else NodeRole.STANDBY
                if node.role != should_be:
                    log.info("%s is now %s", node.name, should_be.value)
                    if node.is_self and should_be == NodeRole.ACTIVE:
                        promoted = True
                    node.role = should_be

            session.commit()

        # A promoted standby has rendered files but no config objects, so it
        # could serve but not edit. Restore them from the latest snapshot.
        # Done outside the session above so the restore gets its own
        # transaction.
        if promoted:
            await self._restore_config_if_empty()

    async def _restore_config_if_empty(self):
        """Restore config objects from the newest snapshot, if we have none.

        Never overwrites existing objects with an older snapshot. Errors are
        logged, not raised: the node still serves what it has, and an
        exception here would kill the election loop.
        """
        from app.core import snapshot as snapshot_store

        try:
            with session_scope() as session:
                if not snapshot_store.is_empty(session):
                    return

                newest = session.query(ConfigVersion).order_by(
                    ConfigVersion.version.desc()
                ).first()
                if not newest or not newest.snapshot:
                    log.warning(
                        "promoted to active with no config and no snapshot to put "
                        "back, so this node can serve what it has but not change it"
                    )
                    return

                data = json.loads(newest.snapshot)
                if not data.get("tables"):
                    # Older snapshot format with counts only.
                    log.warning(
                        "the newest snapshot here predates config replication, so "
                        "there is nothing to restore from"
                    )
                    return

                written = snapshot_store.restore(session, data)
                log.warning(
                    "promoted to active and put the config back from version %s: %s",
                    newest.version,
                    ", ".join(f"{k}={v}" for k, v in written.items() if v),
                )
        except Exception as exc:
            log.error("could not restore the config after being promoted: %s", exc)

    async def failover_to(self, target_name: str, actor: str = "system"):
        """Manually make a node active. An empty target clears the request.

        Records the preference and runs an election rather than setting roles
        directly, so the election stays the only thing deciding roles.

        The preference persists across reboots. If the chosen node becomes
        unfit, the election fails over anyway, and the node takes the role
        back when it returns. Clear the request to stop that.
        """
        wanted = (target_name or "").strip()

        if wanted:
            with session_scope() as session:
                target = session.query(Node).filter(Node.name == wanted).first()
                if not target:
                    raise ClusterError(f"there is no node called {wanted}")
                if target.forced_standby:
                    raise ClusterError(
                        f"{wanted} is pinned to standby, unpin it first")
                if (not _recently_seen(target, self.settings.node_dead_after)
                        and not target.is_self):
                    raise ClusterError(
                        f"{wanted} is not answering, so it cannot take over")

        set_preferred_active(wanted, actor)
        log.warning("%s asked for %s to be the active node", actor,
                    wanted or "whichever the election picks")

        # Not strictly needed, the loops would get there; this just makes
        # the change take effect immediately.
        await self.run_election()
        try:
            await self.send_heartbeats()
        except Exception as exc:
            log.warning("could not tell the other nodes straight away: %s", exc)

    # =========================================================================
    # Two phase apply
    # =========================================================================

    async def apply_config(self, rendered: dict, checksum: str, summary: str,
                           author: str, snapshot: dict,
                           user_checksum: str = None, force: bool = False) -> dict:
        """Push a config change to the whole fleet with a two phase apply.

        Prepare: every reachable node stages the files and runs nginx -t.
        Any failure stops the apply with nothing to undo.

        Commit: prepared nodes swap in the config and reload. If one fails,
        nodes that already committed are rolled back.

        Unreachable nodes get the version queued and catch up on return.
        """
        async with self._apply_lock:
            return await self._apply_config_locked(
                rendered, checksum, summary, author, snapshot, user_checksum, force
            )

    async def _apply_config_locked(self, rendered, checksum, summary, author, snapshot,
                                   user_checksum=None, force=False):
        started = time.monotonic()

        with session_scope() as session:
            if not self.is_active(session):
                raise self.not_active_error(session)

            latest = session.query(ConfigVersion).order_by(
                ConfigVersion.version.desc()
            ).first()

            # Refuse a render that drops (most of) the served sites; see
            # looks_like_a_wipe. Checked before the version row is written.
            # Compare against the files on disk, not version history, which a
            # promoted standby may not have or may have recorded as empty.
            if not force:
                reason = looks_like_a_wipe(await self._live_config_files(), rendered)
                if reason:
                    log.error("refusing to apply: %s", reason)
                    return {
                        "ok": False,
                        "phase": "refused",
                        "error": (
                            f"Refused, because {reason}\n\n"
                            f"If this node was just promoted from standby, it does not "
                            f"have the sites and pools, only the files it was given, and "
                            f"it should carry on serving those.\n\n"
                            f"If you really did mean to remove them, apply again with "
                            f"force set."
                        ),
                        "refused": True,
                    }

            # Skip the reload if nothing changed, unless forced. Force is
            # needed to push to a node that is behind, and for changes that
            # alter no rendered file (DNS zone edits) but must still reach
            # the other nodes.
            if latest and latest.checksum == checksum and not force:
                return {
                    "ok": True,
                    "unchanged": True,
                    "version": latest.version,
                    "message": "nothing actually changed, so nothing was reloaded",
                }

            # Continue from the highest version anywhere in the fleet (known
            # from heartbeats), not just this node's. A promoted standby has
            # written none, and restarting at 1 would reuse numbers for
            # different configs. Only monotonic increase is relied on.
            highest = latest.version if latest else 0
            for node in session.query(Node).all():
                highest = max(highest, node.applied_version or 0)

            next_version = highest + 1

            version_row = ConfigVersion(
                version=next_version,
                checksum=checksum,
                user_checksum=user_checksum,
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
                result = await self._prepare_peer(info, rendered, next_version, checksum,
                                                  force, snapshot)
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

        # Any refusal stops the apply. Nothing is live yet, so no unwinding.
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
                # Node dropped out between prepare and commit.
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

            # Queue the version for nodes we could not reach.
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
        """Collect fleet warnings for the GUI before an apply.

        Informational only, never blocking; blocking on a degraded pool would
        stop you fixing that pool. Flags unseen nodes, stopped nginx, the WAF
        module not loaded, unhealthy pools, and country blocking (which needs
        a GeoIP database we cannot check for).
        """
        from app.core.render import GEOIP_DATABASE
        from app.models import Pool, VirtualHost

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

            # WAF sites on a fleet where some node has not loaded the module.
            # Otherwise the only symptom is a confusing `unknown directive
            # "modsecurity"` from the config test.
            wafers = [h.name for h in session.query(VirtualHost).all()
                      if h.enabled
                      and (h.setting_map().get("waf_mode") or "off") != "off"]
            if wafers:
                unloaded = [n.name for n in nodes if n.waf_module_loaded is False]
                if unloaded:
                    warnings.append({
                        "level": "critical",
                        "message": (
                            f"{', '.join(wafers)} run the WAF, and nginx on "
                            f"{', '.join(unloaded)} has not been told the "
                            f"module exists.  The apply will be refused on "
                            f"that node with an unknown directive.  Rebuild it "
                            f"from the NGINX Build page, or restart its "
                            f"manager, which loads the module if it is there."
                        ),
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

            # Country blocking needs the MMDB file on every node, which we
            # cannot check from here. Without it the apply fails with an
            # error that does not mention the setting responsible.
            blocking = [h.name for h in session.query(VirtualHost).all()
                        if h.enabled and h.setting_map().get("geoip2_country_block")]
            if blocking:
                warnings.append({
                    "level": "warning",
                    "message": (
                        f"country blocking is set on {', '.join(sorted(blocking))}, "
                        f"which needs {GEOIP_DATABASE} on every node.  Without it "
                        f"nginx will not start and this change will be refused"
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

    async def _live_config_files(self) -> dict:
        """The site files live on this node, read from disk via the agent.

        Disk rather than database, since a mismatch between them is exactly
        what the wipe check should catch. If the agent does not answer this
        returns {} and the wipe check is skipped, rather than blocking every
        apply while the agent is briefly down.
        """
        from app.core.agent_client import get_agent
        from app.core.render import MANAGED_ROOT

        try:
            listing = await get_agent().list_dir(f"{MANAGED_ROOT}/sites")
        except Exception as exc:
            log.debug("cannot list the live sites, skipping the wipe check: %s", exc)
            return {}

        return {
            f"sites/{entry['name']}": ""
            for entry in listing.get("entries", [])
            if str(entry.get("name", "")).endswith(".conf")
        }

    async def _prepare_peer(self, info, rendered, version, checksum, force=False,
                            snapshot=None) -> dict:
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == info["name"]).first()
            if not node:
                raise ClusterError(f"{info['name']} is not on the roster")
            client = PeerClient(node, self.ca)

        return await client.call(
            "/peer/config/prepare",
            {"version": version, "checksum": checksum, "files": rendered,
             "force": bool(force), "snapshot": snapshot},
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
                # Keep going so the other nodes still roll back.
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
        """Catch up nodes with queued changes.

        Pushes only the latest applied version rather than replaying each
        one; if it lands, the node's whole backlog is cleared.
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

            # Send the config objects too. Otherwise the node keeps stale
            # objects and, if later promoted, re-renders from them and
            # silently reverts every change made while it was away.
            snapshot = json.loads(latest.snapshot or "{}")

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
                result = await self._prepare_peer(info, rendered, target_version, checksum,
                                                  snapshot=snapshot)
                if not result.get("ok"):
                    raise ClusterError(result.get("output", "the config test failed there"))

                result = await self._commit_peer(info, target_version)
                if not result.get("ok"):
                    raise ClusterError(result.get("output", "the commit failed there"))

            except NodeUnreachable:
                # Still down; retry next time.
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

            # Success clears this node's whole backlog.
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
        """Heartbeat every peer and refresh the roster from their answers."""
        _wanted, _wanted_at = preferred_active()
        with session_scope() as session:
            me = self.self_node(session)
            payload = {
                "node": self.node_name,
                "role": me.role.value if me else "unknown",
                "priority": self.settings.cluster_priority,
                "applied_version": me.applied_version if me else 0,
                "nginx_active": me.nginx_active if me else False,
                # Result of our self probe. Must stay None until there is a
                # verdict: peers withdraw us from DNS on False.
                "nginx_serving": me.nginx_serving if me else None,
                "nginx_serving_detail": me.nginx_serving_detail if me else None,
                # Sent on every heartbeat because each node runs its own
                # election; a node that did not know would keep undoing it.
                "preferred_active": _wanted,
                "preferred_active_at": _wanted_at,
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
                    # Older managers do not send this. Do not read its
                    # absence as a failure and pull the node from DNS.
                    if "nginx_serving" in answer:
                        node.nginx_serving = answer["nginx_serving"]
                        node.nginx_serving_detail = (answer.get("nginx_serving_detail") or "")[:255]
                    if "waf_module_loaded" in answer:
                        node.waf_module_loaded = answer["waf_module_loaded"]
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
                            adopt_peer_role(session, node, NodeRole(answer["role"]),
                                            self.settings.node_name)
                        except ValueError:
                            pass
                    session.commit()

                if "preferred_active_at" in answer:
                    adopt_preferred_active(answer.get("preferred_active"),
                                           answer.get("preferred_active_at"))

            except NodeUnreachable as exc:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if node:
                        if _recently_seen(node, self.settings.node_dead_after):
                            # Missed one heartbeat; not dead yet.
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
        """Create a single use join token for one new node.

        Anyone holding it can get a cluster cert, so treat it as a password.
        Only its hash is stored.
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
