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


def adopt_peer_role(session, peer, claimed, self_name: str):
    """
    Record what a peer says it is, without ever writing down two active nodes.

    A peer claiming to be active while we also think we are is not somebody
    lying, it is the ordinary shape of a failover in progress: one side promoted
    itself while the other was away, and the other has not run an election yet.
    Writing both down and waiting for the election to tidy up means the roster
    says two nodes take writes, and the GUI says so to whoever is looking.

    Standing down here is the safe direction.  Believing we are a standby when
    we are really the active node costs one election cycle.  Believing we are
    active when another node is means two nodes taking writes, which is the
    thing the whole design exists to prevent.
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
    """
    Which node should be active, given who is fit and what was asked for.

    Pulled out of the election so it can be tested without a cluster.  No
    database, no clock, no side effects: a list of the nodes that are fit, the
    full roster, and the name somebody asked for.

    Gives back the winner and a reason, where the reason is empty unless a
    request had to be passed over.

    The rule, in order:

      Whoever was asked for, if they are fit to take it.
      Otherwise the highest priority among the fit, ties broken on name so
      every node works out the same answer without having to agree first.

    A request that cannot be honoured is passed over rather than obeyed, which
    is what keeps automatic failover working: the node somebody chose dying
    must not stop the other one taking over.
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
    """
    Which node somebody asked to be active, and when they asked.

    Empty name means nobody asked, and the election falls back to priority the
    way it always did.
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
    """
    Take a peer's copy of the request when theirs is the newer one.

    Both nodes hold the same single value and the newest instruction wins.
    That is enough here: it is one scalar set by a person pressing a button,
    not something two nodes race to write, so last one in is the right answer
    and there is nothing to agree about beyond which came last.

    Strictly newer, so two nodes with the same timestamp do not swap it back
    and forth forever.
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
    """
    Would applying this throw away most of what is already being served.

    Gives back a reason when it would, and an empty string when it is a normal
    change.

    This exists because of a real one.  A standby holds the rendered files but
    not the objects they were rendered from, so a standby that gets promoted and
    renders has nothing to render.  It produced a config with every site missing,
    applied it to itself, and wiped its own config.  Then it queued the same
    empty config for the node that was down, which would have taken the live
    node with it when that node came back.

    The rule is deliberately blunt.  Going from some sites to none is not a
    change anybody makes on purpose, and the cost of being wrong is that
    somebody deleting their last site has to say so twice.  The cost of not
    having it is both load balancers serving nothing.

    Deleting sites one at a time is untouched, and so is a first apply, since
    there is nothing to lose when nothing is there yet.
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
    """
    Not the active node, and nobody else is either.

    Its own type because the answer is "try again in a moment", not "go and do
    it on the other box".  A node that has just restarted stands itself down on
    purpose and waits to be elected, so for a few seconds after every upgrade
    the honest answer to "why was that refused" is that the fleet has not
    decided yet.  Telling somebody to make their change on the active node in
    that window sends them to a node that is standing down for the same reason.

    The caller turns this into a 503 with a retry in it, the same as a busy
    database, rather than the 409 an ordinary refusal gets.
    """


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

    def not_active_error(self, session) -> ClusterError:
        """
        The right refusal for a node that is not active.

        `is_active` gives back false for three different situations and they do
        not deserve the same sentence:

          another node holds the role, so go and do it there
          nobody holds it yet, so wait a few seconds and do it here
          this node has no row for itself yet, so it is not in a fleet at all

        Only the first of those means "make your change on the active node",
        and that was what every refusal used to say.  The other two are the
        seconds after a restart, when `register_self` has deliberately stood
        this node down to wait for an election, and following that advice sends
        somebody to a node that is standing down as well.  Both of them are
        worth retrying, so they come back as `RoleNotSettled`.

        Where another node does hold the role, say which one and where it is.
        "The active node" is not an instruction on a fleet where somebody has
        to go and look up which node that is today.
        """
        me = self.self_node(session)
        holder = (
            session.query(Node)
            .filter(Node.name != self.node_name, Node.role == NodeRole.ACTIVE)
            .first()
        )

        if holder:
            # Say what this node actually is.  A fresh row starts UNKNOWN and a
            # node that has just stood down is not a standby by anybody's
            # choosing, so "this node is a standby" is only true when the
            # roster says so.
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
        """
        Send this node's DNS zones to every peer.

        Same shape as replicate_accounts below, and for a sharper reason.  A
        zone renders no nginx config, so it never rode the config snapshot,
        which only moves when the rendered config changes.  A zone therefore
        lived on whichever node it was created on and nowhere else.

        The standby starts its listener from the zones in its own database, so
        with none it started nothing and answered nothing.  Losing the active
        node took the fleet's DNS with it, which is precisely the failure the
        feature exists to survive.

        Only the active node sends, for the same reason it is the only one that
        sends accounts: two nodes pushing different ideas of the zone list at
        each other is a flap, and the active node is the one that owns config.
        """
        from app.core import snapshot as snapshot_store

        with session_scope() as session:
            if not self.is_active(session):
                return {"skipped": "not the active node"}

            tables = snapshot_store.capture_gslb(session)
            # So the far end can tell "the last zone was deleted" from "a
            # blank node is pushing its emptiness at me".
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
                # Not worth raising over, same as accounts: the timer tries
                # again, and a node that was unreachable catches up when it
                # comes back without anybody doing anything.
                failed[name] = str(exc)
                log.warning("could not send the dns zones to %s: %s", name, exc)
        return {"sent_to": sent, "failed": failed}

    async def replicate_accounts(self) -> dict:
        """
        Send this node's accounts to every peer.

        Accounts are in the config snapshot as well, which covers a node being
        promoted or catching up after being away.  That is not enough on its own:
        a snapshot only moves when the rendered nginx config changes, and none of
        the things people do to accounts change a line of nginx config.  Changing
        a password, enrolling a second factor, or taking somebody's access away
        would otherwise sit on one node until an unrelated site edit carried it
        across, which for the last of those is a security hole with a wait on it.

        Called after an account changes, and again on a timer so a node that was
        unreachable at the time catches up without anybody doing anything.

        Only the active node sends.  Two nodes pushing different ideas of the
        account list at each other is how you get a flap, and the active node is
        already the one that owns config.
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
                # Not worth raising over.  The timer will try again, and an
                # account change must not fail because one box is having a
                # moment.
                failed[name] = str(exc)
                log.warning("could not send accounts to %s: %s", name, exc)

        if sent:
            log.info("sent %d accounts to %s", len(rows), ", ".join(sent))
        return {"sent_to": sent, "failed": failed}

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

            # Priority decides it, unless somebody has said which node they
            # want and that node is in a fit state to take it.
            #
            # Without this the failover button could not work at all.  It wrote
            # the roles down and answered success, and then this election ran a
            # few seconds later, sorted on priority and broke the tie on name,
            # and handed the role straight back.  On an ordinary pair with equal
            # priorities the first name always won, so the role could never be
            # moved by hand, and the button said it had worked.
            #
            # The important half is the fallback.  A request only counts while
            # the node it names is healthy, so if that node dies the election
            # picks the ordinary winner and the fleet fails over on its own,
            # exactly as it did before.  A request is a preference, never a pin:
            # pinning is what forced_standby is for, and it is checked above.
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

        # Put the config back, if this node has just been promoted and has none.
        #
        # A standby holds the rendered files and not the objects behind them, so
        # without this it can serve what it was given and change none of it,
        # which is the half of a failover nobody thinks about until they need to
        # fix something during one.
        #
        # Outside the session above on purpose.  Restoring rewrites most of the
        # config tables and wants a transaction of its own, not one that is
        # already holding the node rows.
        if promoted:
            await self._restore_config_if_empty()

    async def _restore_config_if_empty(self):
        """
        Rebuild this node's config objects from the newest snapshot it has.

        Only when it has none of its own.  A node that already has sites and
        pools is either the one that has been holding them all along or has
        already done this, and overwriting a real config with an older snapshot
        would be its own outage.

        Failing here is logged and not raised.  A promotion that cannot restore
        still leaves a node serving what it has, which is the important half,
        and an exception thrown out of an election loop stops the elections.
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
                    # A snapshot from before these carried objects.  It holds
                    # counts and nothing else, so there is nothing to restore.
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
        """
        Hand active over to a specific node, by hand.

        An empty target means go back to letting the election decide.

        This records what was asked for and then runs an election, rather than
        writing the roles itself.  Writing them itself is what it used to do,
        and the next election overwrote them a few seconds later, so the button
        reported success and the role went straight back where it came from.
        One place decides who is active, and this tells it what somebody wants.

        The request outlives a reboot and outlives the node going away, and
        that is deliberate: it is a statement about how the fleet should run,
        not a nudge.  Failover away from the chosen node still happens on its
        own when that node is not fit, because the election treats the request
        as a preference and drops it the moment it cannot be honoured.  Coming
        back is the other half of the same rule, so a node that was chosen and
        then rebooted takes the role again when it returns.  Clear the request
        to stop that.
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

        # Settle it here rather than waiting up to a full election interval,
        # and tell the other node at once rather than waiting for the next
        # heartbeat.  Both are only about how quickly it happens; the loops
        # would get there on their own.
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

            # Refuse to serve nothing.  A render that has lost every site is
            # almost always a node that cannot see the objects rather than
            # somebody deleting their whole estate, and applying it takes the
            # fleet down.  Checked before the version row is written so a
            # refused apply leaves no trace to clean up.
            #
            # Compared against what is on disk, not against this node's version
            # history.  A promoted standby has no history worth trusting: it
            # either has none at all, or it has the empty version it wrote the
            # last time this happened, and comparing an empty render against an
            # empty record says everything is fine.  The files being served are
            # the only honest answer to what would be lost.
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

            # Nothing to do.  Saying so beats a pointless reload of every box.
            #
            # Unless somebody asked for it anyway, which force did not used to
            # cover: it only skipped the safety checks above, so an apply with
            # force set still stopped dead here and reported "unchanged".  That
            # is the wrong answer for the two cases force exists for.  One is a
            # node that is behind and needs the current config pushed at it
            # regardless.  The other is a change that moves with an apply but
            # does not alter a single rendered file, which is exactly what a DNS
            # zone edit is: the renderer is right that nothing changed, and the
            # zones still have to reach the other nodes.
            if latest and latest.checksum == checksum and not force:
                return {
                    "ok": True,
                    "unchanged": True,
                    "version": latest.version,
                    "message": "nothing actually changed, so nothing was reloaded",
                }

            # Carry on from the highest number anybody in the fleet has reached,
            # not just the highest this node happens to have written.
            #
            # Version numbers are meant to describe the fleet's config, and a
            # node that has been a standby all its life has written none of them.
            # Promote it and it would start again at 1 while the other node was
            # at sixty, so the same number would mean two different configs, the
            # pending queue would be full of versions lower than what the node it
            # is for already has, and anybody reading either during an incident
            # would draw the wrong conclusion.
            #
            # Every node knows what the others have applied, from the heartbeat,
            # so the highest number in the fleet is knowable without anybody
            # coordinating.  Taking the maximum keeps them going up, which is the
            # only property anything here relies on.
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
          - country blocking, which needs a database this cannot see
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

            # A site running the WAF, on a fleet where some node has the
            # module built but never loaded.
            #
            # Said here, before the apply, because the alternative is what
            # happened in the field: the first anybody heard was `unknown
            # directive "modsecurity"` out of a config test, which reads like a
            # config error and is not one.  Nothing here is wrong with the
            # config; one box was never told the module exists.
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

            # Country blocking needs a database file on every node, and
            # nothing here can see a node's filesystem.  Without it nginx does
            # not start, so the apply is refused on that node and the error is
            # about opening an MMDB file, which says nothing about which
            # setting asked for it.  One sentence here beats that.
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
        """
        What this node is serving right now, as a file map.

        Read off disk through the agent rather than out of the database, because
        the question is what applying would take away, and the answer to that is
        whatever is live.  A node whose database and disk disagree is exactly the
        case worth catching.

        An agent that will not answer gives back nothing, which makes the wipe
        check stand aside.  Guessing that a node has no sites when we simply
        cannot see is the wrong way to be wrong: it would block every apply on a
        node whose agent is briefly down.
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

            # The objects behind those files travel with them here too.
            #
            # Missing this is how a node that was down came back, took the files
            # and served them correctly, and kept its own older objects.  It
            # then became active, rendered from what it still had, and undid
            # every change made while it was away, silently, because from its
            # point of view nothing had changed.
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
        _wanted, _wanted_at = preferred_active()
        with session_scope() as session:
            me = self.self_node(session)
            payload = {
                "node": self.node_name,
                "role": me.role.value if me else "unknown",
                "priority": self.settings.cluster_priority,
                "applied_version": me.applied_version if me else 0,
                "nginx_active": me.nginx_active if me else False,
                # Whether our own listener answered a real request just now.
                # None if we have not got a verdict yet, and it has to stay
                # None rather than becoming False: the other node withdraws us
                # from DNS on a False, and "has not said" is not "is down".
                "nginx_serving": me.nginx_serving if me else None,
                "nginx_serving_detail": me.nginx_serving_detail if me else None,
                # Who somebody asked to be active, and when.  This rides the
                # heartbeat because it has to reach the other node in seconds:
                # both nodes run their own election from their own database, so
                # a request only one of them knows about is a request the other
                # one keeps undoing.
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
                    # Absent means an older manager that does not probe itself,
                    # so leave what we have rather than reading the silence as
                    # a failure and taking that node out of DNS.
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
