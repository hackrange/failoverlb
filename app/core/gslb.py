"""
Authoritative DNS for names that should follow the healthy nodes.

Moving the active role around doesn't move a single connection; where traffic
goes is decided by what the client resolved. This decides that.

DNS failover is bounded by things outside this box. The TTL is a request:
resolvers clamp low values, browsers cache, some runtimes cache for the life
of the process. A 30 second TTL moves most clients within a minute or two,
with a longer tail. It's the right tool when nodes are in different places
with different addresses, where a floating IP can't work.

Answers are built per query from live health rather than written to a zone
file and reloaded, so there is nothing to reload and nothing to fall behind.

Deliberately not supported:
- Recursion. Anything outside our zones gets REFUSED; an open resolver is an
  amplification attack waiting to happen.
- DNSSEC. Doing it badly makes names fail to resolve everywhere, which is a
  worse outage than the one this feature exists to prevent.
"""
import json
import logging
import socket
import struct
import threading
import time

import dns.flags
import dns.message
import dns.name
import dns.rcode
import dns.rdataclass
import dns.rdatatype
import dns.rrset

log = logging.getLogger("nfm.gslb")

# Without EDNS a client only has to accept 512 bytes. Going over that without
# setting TC gives answers that silently vanish for some clients.
UDP_SAFE_BYTES = 512
UDP_MAX_BYTES = 4096

# Anything longer than this is someone probing.
MAX_QUERY_BYTES = 4096


class ZoneData:
    """
    Everything needed to answer, with no database in the query path. Built
    on a timer and swapped in whole, so a busy database can't turn into
    timeouts for every visitor.
    """

    def __init__(self):
        self.zones = {}          # zone name, lowered, no trailing dot -> dict
        self.built_at = 0.0

    def zone_for(self, qname: str):
        """
        The most specific zone covering this name. Walks upward from the
        full name so a child zone wins over its parent.
        """
        parts = qname.strip(".").lower().split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self.zones:
                return self.zones[candidate]
        return None


# How long the serving loops block before rechecking the stop flag. Closing a
# socket from another thread doesn't reliably wake a thread blocked in
# recvfrom/accept on Linux, so without a timeout the old threads kept the
# port and the next start failed with "Address already in use".
POLL_SECONDS = 0.5

# How long stop() waits for those threads. Generous, so a thread mid answer
# can finish.
STOP_TIMEOUT_SECONDS = 5.0


class GslbServer:
    """
    Listens on UDP and TCP and answers from the snapshot. TCP is required:
    replies too big for UDP get TC set and the resolver retries over TCP.
    """

    def __init__(self, address=None, port=None):
        self.address = address or _own_address()
        # Bind the node's own address, not 0.0.0.0, which collides with the
        # stub resolver on 127.0.0.53 on most distros. An authoritative
        # server has no business answering on loopback anyway.
        #
        # High port on purpose. The container runs unprivileged with
        # no-new-privileges, so file capabilities are ignored and 53 can't be
        # bound here. The agent installs a DNAT from 53 to this port, which
        # also preserves the client address.
        self.port = int(port or 5353)
        self.data = ZoneData()
        self._udp = None
        self._tcp = None
        self._threads = []
        self._running = False
        self.stats = {"queries": 0, "answered": 0, "refused": 0,
                      "nxdomain": 0, "errors": 0, "started_at": None,
                      "last_error": None}

    # ------------------------------------------------------------------ life
    def start(self):
        if self._running:
            return
        self._running = True

        # Threads left over from a previous run would hold the port and make
        # the bind below fail. Log it so that failure is explainable.
        alive = [t for t in self._threads if t.is_alive()]
        if alive:
            log.error("%s serving thread(s) from the last run are still going, "
                      "so this bind will probably fail", len(alive))
        self._threads = []

        try:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp.bind((self.address, self.port))
            self._udp.settimeout(POLL_SECONDS)

            self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp.bind((self.address, self.port))
            self._tcp.listen(64)
            self._tcp.settimeout(POLL_SECONDS)
        except OSError as exc:
            self._running = False
            self.stats["last_error"] = str(exc)
            self._close()
            raise

        self.stats["started_at"] = time.time()
        for target in (self._serve_udp, self._serve_tcp):
            thread = threading.Thread(target=target, daemon=True)
            thread.start()
            self._threads.append(thread)
        log.info("gslb listening on %s:%s udp and tcp", self.address, self.port)

    def stop(self):
        """
        Stop serving and wait for the threads to exit. Order matters: drop
        the flag, join the threads, then close the sockets. Closing first
        can leave threads blocked on a dead socket still holding the port.
        """
        self._running = False

        for thread in self._threads:
            if thread is threading.current_thread():
                continue
            thread.join(timeout=STOP_TIMEOUT_SECONDS)

        stuck = [t for t in self._threads
                 if t.is_alive() and t is not threading.current_thread()]
        if stuck:
            # This is the state that used to wedge the port. If it shows up,
            # start here.
            log.error("%s serving thread(s) would not stop within %.0f seconds, "
                      "so the port may not come free", len(stuck),
                      STOP_TIMEOUT_SECONDS)

        self._threads = []
        self._close()
        self.stats["started_at"] = None

    def _close(self):
        for sock in (self._udp, self._tcp):
            try:
                if sock:
                    sock.close()
            except OSError:
                pass
        self._udp = self._tcp = None

    # --------------------------------------------------------------- serving
    def _serve_udp(self):
        while self._running:
            try:
                raw, peer = self._udp.recvfrom(UDP_MAX_BYTES)
            except socket.timeout:
                # Poll timeout: loop and recheck the flag. Must be caught
                # before OSError, since socket.timeout is an OSError and the
                # branch below would end the thread.
                continue
            except (OSError, AttributeError):
                # Socket closed or gone; nothing left to serve on.
                if self._running:
                    log.debug("udp socket closed")
                return
            try:
                reply = self.handle(raw, peer[0], over_tcp=False)
                if reply:
                    self._udp.sendto(reply, peer)
            except Exception as exc:
                self.stats["errors"] += 1
                log.warning("udp query from %s blew up: %s", peer[0], exc)

    def _serve_tcp(self):
        while self._running:
            try:
                conn, peer = self._tcp.accept()
            except socket.timeout:
                # Same as UDP: must be caught before OSError.
                continue
            except (OSError, AttributeError):
                if self._running:
                    log.debug("tcp socket closed")
                return

            # accept() on a socket with a timeout returns a connection that
            # inherits it. Clear it explicitly; the handler sets its own.
            conn.settimeout(None)
            threading.Thread(target=self._handle_tcp, args=(conn, peer),
                             daemon=True).start()

    def _handle_tcp(self, conn, peer):
        # DNS over TCP prefixes every message with a two byte length, in
        # both directions.
        try:
            conn.settimeout(5)
            header = self._read_exactly(conn, 2)
            if not header:
                return
            (length,) = struct.unpack("!H", header)
            if length > MAX_QUERY_BYTES:
                return
            raw = self._read_exactly(conn, length)
            if not raw:
                return
            reply = self.handle(raw, peer[0], over_tcp=True)
            if reply:
                conn.sendall(struct.pack("!H", len(reply)) + reply)
        except (OSError, struct.error):
            pass
        except Exception as exc:
            self.stats["errors"] += 1
            log.warning("tcp query from %s blew up: %s", peer[0], exc)
        finally:
            try:
                conn.close()
            except OSError:
                pass

    @staticmethod
    def _read_exactly(conn, count):
        buf = b""
        while len(buf) < count:
            chunk = conn.recv(count - len(buf))
            if not chunk:
                return None
            buf += chunk
        return buf

    # -------------------------------------------------------------- answering
    def handle(self, raw: bytes, client: str, over_tcp=False):
        """
        Turn one query into one reply. Never raises: a malformed packet is
        someone scanning, and a server that crashes on one can be turned off
        by anyone.
        """
        self.stats["queries"] += 1
        try:
            query = dns.message.from_wire(raw)
        except Exception:
            # Can't even find the message id, so there is nothing to reply.
            return None

        try:
            reply = dns.message.make_response(query)
            reply.flags |= dns.flags.AA
            reply.flags &= ~dns.flags.RA        # we do not recurse, so say so

            if not query.question:
                reply.set_rcode(dns.rcode.FORMERR)
                return reply.to_wire()

            question = query.question[0]
            qname = question.name.to_text(omit_final_dot=True).lower()
            qtype = question.rdtype

            zone = self.data.zone_for(qname)
            if zone is None:
                # Not ours. REFUSED, never a lookup: this is what keeps us
                # from being an open resolver.
                self.stats["refused"] += 1
                reply.set_rcode(dns.rcode.REFUSED)
                reply.flags &= ~dns.flags.AA
                return self._finish(reply, query, over_tcp)

            self._answer_from_zone(reply, zone, qname, qtype)
            return self._finish(reply, query, over_tcp)
        except Exception as exc:
            self.stats["errors"] += 1
            self.stats["last_error"] = str(exc)
            log.warning("could not answer %s for %s: %s", raw[:40], client, exc)
            try:
                reply = dns.message.make_response(query)
                reply.set_rcode(dns.rcode.SERVFAIL)
                return reply.to_wire()
            except Exception:
                return None

    def _finish(self, reply, query, over_tcp):
        """
        Serialize, setting TC if it won't fit over UDP. The client's limit
        comes from its EDNS record, or 512 without one.
        """
        if over_tcp:
            return reply.to_wire()

        limit = UDP_SAFE_BYTES
        if query.edns >= 0:
            reply.use_edns(edns=0, payload=min(query.payload or 512, UDP_MAX_BYTES))
            limit = min(query.payload or UDP_SAFE_BYTES, UDP_MAX_BYTES)

        wire = reply.to_wire()
        if len(wire) <= limit:
            return wire

        # Too big: send the header with TC so the resolver retries over TCP.
        reply.answer = []
        reply.additional = []
        reply.flags |= dns.flags.TC
        return reply.to_wire()

    def _answer_from_zone(self, reply, zone, qname, qtype):
        apex = zone["name"]
        wanted = dns.rdatatype.to_text(qtype)

        # SOA and NS at the apex come from the zone settings, so they always
        # exist without anyone having to add them.
        if qname == apex and wanted == "SOA":
            reply.answer.append(self._soa_rrset(zone))
            self.stats["answered"] += 1
            return
        if qname == apex and wanted == "NS":
            ns = self._ns_rrset(zone)
            if ns:
                reply.answer.append(ns)
                self.stats["answered"] += 1
                return

        found = zone["records"].get(qname)
        if found is None:
            found = self._wildcard_for(zone, qname)

        if found is None:
            # NXDOMAIN with the SOA in authority; resolvers read the negative
            # cache time from it.
            self.stats["nxdomain"] += 1
            reply.set_rcode(dns.rcode.NXDOMAIN)
            reply.authority.append(self._soa_rrset(zone))
            return

        # A CNAME answers every query type.
        cname = found.get("CNAME")
        if cname and wanted != "CNAME":
            reply.answer.append(dns.rrset.from_text(
                qname + ".", cname["ttl"], "IN", "CNAME",
                cname["values"][0] if cname["values"] else "."))
            self.stats["answered"] += 1
            return

        entry = found.get(wanted)
        if entry is None or not entry["values"]:
            # Name exists but not this type: NOERROR/NODATA, which resolvers
            # treat differently from NXDOMAIN.
            reply.authority.append(self._soa_rrset(zone))
            return

        reply.answer.append(dns.rrset.from_text_list(
            qname + ".", entry["ttl"], "IN", wanted, entry["values"]))
        self.stats["answered"] += 1

    @staticmethod
    def _wildcard_for(zone, qname):
        """
        A wildcard covers exactly one label and only where nothing more
        specific exists. `*.example.com` matches `a.example.com`, not
        `a.b.example.com` or `example.com`.
        """
        apex = zone["name"]
        if not qname.endswith("." + apex):
            return None
        head = qname[: -(len(apex) + 1)]
        if not head or "." in head:
            return None
        return zone["records"].get("*." + apex)

    def _soa_rrset(self, zone):
        primary = zone["soa_primary"] or (zone["nameservers"][0]
                                          if zone["nameservers"] else zone["name"])
        contact = zone["soa_contact"] or "hostmaster"
        if "@" in contact:
            # The SOA contact is a name with the @ replaced by a dot.
            local, _, domain = contact.partition("@")
            contact = f"{local.replace('.', '\\\\.')}.{domain}"
        return dns.rrset.from_text(
            zone["name"] + ".", zone["soa_minimum"], "IN", "SOA",
            f"{primary}. {contact}. {zone['soa_serial']} {zone['soa_refresh']} "
            f"{zone['soa_retry']} {zone['soa_expire']} {zone['soa_minimum']}")

    def _ns_rrset(self, zone):
        if not zone["nameservers"]:
            return None
        return dns.rrset.from_text_list(
            zone["name"] + ".", 3600, "IN", "NS",
            [n if n.endswith(".") else n + "." for n in zone["nameservers"]])


def build_zone_data(session, healthy_nodes) -> ZoneData:
    """
    Flatten the database into what queries are answered from.
    `healthy_nodes` comes from the caller so the health rule lives in one
    place.
    """
    from app.models import GslbZone

    data = ZoneData()
    for zone in session.query(GslbZone).all():
        if not zone.enabled:
            continue

        zone_name = (zone.name or "").strip(".").lower()
        if not zone_name:
            continue

        records = {}
        for record in zone.records:
            if not record.enabled:
                continue

            values = _live_values(record, healthy_nodes)
            if not values:
                continue

            fqdn = record.fqdn(zone_name).lower()
            records.setdefault(fqdn, {})[record.record_type] = {
                "ttl": max(1, int(record.ttl or 30)),
                "values": values,
            }

        data.zones[zone_name] = {
            "name": zone_name,
            "soa_primary": (zone.soa_primary or "").strip("."),
            "soa_contact": zone.soa_contact or "hostmaster",
            "soa_refresh": int(zone.soa_refresh or 3600),
            "soa_retry": int(zone.soa_retry or 600),
            "soa_expire": int(zone.soa_expire or 604800),
            "soa_minimum": int(zone.soa_minimum or 30),
            "soa_serial": int(zone.soa_serial or 1),
            "nameservers": [n.strip(".") for n in zone.nameserver_list() if n],
            "records": records,
        }

    data.built_at = time.time()
    return data


def _answer_node(answer):
    """
    The node name an answer is tied to, or None.

    By name, since ids on replicated rows differ between databases. node_id
    is a fallback for rows written before names were stored; it is correct
    on the node that wrote them.
    """
    name = (getattr(answer, "node_name", None) or "").strip()
    if name:
        return name
    node = getattr(answer, "node", None)
    return node.name if node is not None else None


def _live_values(record, healthy_nodes):
    """
    Which of a record's answers to hand out right now. Node-tied answers
    are only given while the node is healthy; what happens when none are is
    the record's when_all_down setting.
    """
    enabled = [a for a in record.answers if a.enabled]
    if not enabled:
        return []

    if record.record_type == "CNAME":
        # Nothing to health check, and only one CNAME is legal.
        return [_as_target(enabled[0].value)]

    healthy = [a for a in enabled
               if _answer_node(a) is None or _answer_node(a) in healthy_nodes]

    if not healthy:
        if record.when_all_down == "serve_all":
            # A name pointing at a broken box gives the visitor an error
            # they can report. A name resolving to nothing looks like DNS
            # itself is broken.
            healthy = enabled
        else:
            return []

    if record.policy == "failover":
        best = min(a.priority if a.priority is not None else 10 for a in healthy)
        healthy = [a for a in healthy
                   if (a.priority if a.priority is not None else 10) == best]

    seen, values = set(), []
    for answer in healthy:
        value = (answer.value or "").strip()
        if value and value not in seen:
            seen.add(value)
            values.append(value)
    return values


def _as_target(value: str) -> str:
    value = (value or "").strip()
    return value if value.endswith(".") else value + "."


def _own_address() -> str:
    """
    This node's configured address. Falls back to 0.0.0.0 only when nothing
    is configured, i.e. a fresh install with no zones to serve.
    """
    try:
        from app.config import get_settings
        addr = (get_settings().node_address or "").strip()
        if addr:
            return addr
    except Exception:
        pass
    return "0.0.0.0"


def node_addresses(session) -> dict:
    """
    Every address each node is known by, keyed by node name: the cluster
    address, the discovered public IP and its interface addresses. Behind
    NAT the first two differ, so all of them count.
    """
    from app.models import Node

    out = {}
    for node in session.query(Node).all():
        known = set()
        for value in (node.address, node.public_ip):
            if value and str(value).strip():
                known.add(str(value).strip())
        # Entries are dicts (one per interface); older rows may be plain
        # strings, so handle both.
        try:
            for entry in json.loads(node.local_addresses or "[]"):
                value = entry.get("address") if isinstance(entry, dict) else entry
                if value and str(value).strip():
                    known.add(str(value).strip())
        except Exception:                       # noqa: BLE001
            pass
        out[node.name] = known
    return out


def _worth_naming(addresses) -> list:
    """
    Addresses worth showing in a message. Matching still uses all of them;
    this just leaves out loopback and link local so the text stays readable.
    """
    out = []
    for value in sorted(addresses):
        low = value.lower()
        if low.startswith(("127.", "fe80:", "::1")) or low == "0.0.0.0":
            continue
        out.append(value)
    return out


def answer_address_warnings(session) -> list:
    """
    Answers that hand out an address their own node doesn't hold.

    Catches typos that are otherwise invisible: an answer one digit off from
    its node's real address looks fine while the other node carries the
    traffic, and only fails once that node is gone.

    A warning, never a refusal. Floating addresses and services in front of a
    node are legitimate. Answers not tied to a node are skipped since there
    is nothing to compare them to.
    """
    from app.models import GslbAnswer, GslbRecord, GslbZone

    known = node_addresses(session)
    out = []
    for zone in session.query(GslbZone).all():
        for record in zone.records:
            for answer in record.answers:
                name = _answer_node(answer)
                if not name:
                    continue
                if name not in known:
                    out.append({
                        "zone": zone.name,
                        "record": record.fqdn(zone.name),
                        "answer_id": answer.id,
                        "value": answer.value,
                        "node": name,
                        "problem": "no node of that name",
                        "detail": (
                            f"this answer is tied to a node called {name}, and "
                            f"there is no node of that name in the fleet.  It "
                            f"will never be handed out while that stays true."
                        ),
                    })
                    continue
                value = (answer.value or "").strip()
                if value and value not in known[name]:
                    out.append({
                        "zone": zone.name,
                        "record": record.fqdn(zone.name),
                        "answer_id": answer.id,
                        "value": value,
                        "node": name,
                        "problem": "address is not one that node holds",
                        "detail": (
                            f"{name} is reachable on "
                            f"{', '.join(_worth_naming(known[name])) or 'no address this fleet knows'}, "
                            f"and this answer hands out {value}.  If that is "
                            f"deliberate, a floating address for instance, "
                            f"nothing is wrong.  If it is a typo, nobody finds "
                            f"out until the other node is gone and this is the "
                            f"only answer left."
                        ),
                    })
    return out


def healthy_node_names(session) -> set:
    """
    Nodes healthy enough to hand out in a DNS answer, by name.

    Stricter than "online" on the cluster page. What matters is whether
    nginx is actually serving, not whether the manager is up. Three gates:
    node online, nginx active, and nginx_serving not False. The third exists
    because on August 24, 2026 a wedged nginx passed the first two for 73
    minutes while serving nobody. nginx_serving comes from a real request
    through the node's own listener; see app/core/frontend_probe.py.

    Only an explicit False withdraws a node. None means nothing has reported
    yet, e.g. an older manager during a rolling upgrade, and treating that as
    a failure would withdraw each node in turn.
    """
    from app.models import Node, NodeState

    out = set()
    for node in session.query(Node).all():
        if node.state != NodeState.ONLINE:
            continue
        if not node.nginx_active:
            continue
        if node.nginx_serving is False:
            continue
        out.add(node.name)
    return out


# Old name kept for existing callers. It returns names now, not ids.
healthy_node_ids = healthy_node_names


async def ensure_redirect(server=None):
    """
    Point port 53 at our listener via the agent. Only called once the
    listener is up: a redirect with nothing behind it answers nothing, which
    looks like the box being down.
    """
    from app.core.agent_client import get_agent

    server = server or get_server()
    if not server._running:
        return {"installed": False, "note": "the listener is not up"}
    try:
        return await get_agent().call("dns_redirect", timeout=30,
                                      address=server.address, port=server.port)
    except Exception as exc:
        log.error("could not install the dns redirect, so port 53 is not ours: %s", exc)
        return {"installed": False, "error": str(exc)}


async def clear_redirect(server=None):
    """
    Remove the port 53 redirect. A redirect to a stopped listener is worse
    than none: clients get silence instead of moving to another nameserver.
    """
    from app.core.agent_client import get_agent

    try:
        return await get_agent().call("dns_redirect_clear", timeout=30)
    except Exception as exc:
        log.error("could not take the dns redirect off: %s", exc)
        return {"cleared": False, "error": str(exc)}


async def reconcile(server=None):
    """
    Make the listener match the zones.

    Starting only at boot missed the important case: a joining node is empty
    at boot and gets its zones seconds later, so the standby, whose whole job
    is to keep answering after the active node dies, never answered at all.
    Running on the refresh timer brings the listener up within seconds of a
    zone appearing and gives port 53 back when the last one is removed.
    """
    server = server or get_server()
    data = refresh(server)
    wanted = bool(data.zones)

    if wanted and not server._running:
        try:
            server.start()
        except Exception as exc:
            log.error("the dns listener would not start: %s", exc)
            return
        log.info("a zone turned up, so the dns listener is coming up now")
        await ensure_redirect(server)
        return

    if not wanted and server._running:
        log.info("no zones left here, stopping the dns listener")
        await clear_redirect(server)
        server.stop()
        return

    if wanted and server._running:
        # Re-assert the redirect if something cleared it (a reboot, an
        # nftables flush). Check status first: rewriting drops and rebuilds
        # the table, and doing that every few seconds leaves brief gaps.
        from app.core.agent_client import get_agent
        try:
            status = await get_agent().call("dns_redirect_status", timeout=15)
            # Check both that the rule exists and that it points where we
            # want. A mismatched status key once made this rebuild the table
            # every ten seconds, exactly what the check above is meant to
            # avoid.
            want = f"{server.address}:{server.port}"
            wrong_target = status.get("target") not in (None, want)
            if not status.get("installed"):
                log.info("the dns redirect had gone, putting it back")
                await ensure_redirect(server)
            elif wrong_target:
                log.info("the dns redirect points at %s rather than %s, "
                         "rewriting it", status.get("target"), want)
                await ensure_redirect(server)
            elif not status.get("matches_all_local", True):
                # A rule from an older agent that only matched one address,
                # leaving the node's other addresses without a redirect.
                log.info("the dns redirect only matches one address, rewriting "
                         "it to cover every address this node holds")
                await ensure_redirect(server)
        except Exception as exc:
            log.debug("could not check the dns redirect: %s", exc)


def refresh(server=None):
    """
    Rebuild the snapshot the server answers from. On a timer because health
    changes constantly with no single place to hook; a few seconds of lag is
    well inside any sensible TTL.
    """
    from app.db import session_scope

    server = server or get_server()
    try:
        with session_scope() as session:
            data = build_zone_data(session, healthy_node_names(session))
        server.data = data
        return data
    except Exception as exc:
        # Keep the last good snapshot. A database hiccup shouldn't take a
        # name off the internet, and health rarely changes that fast.
        log.error("could not rebuild the gslb zones, keeping the last set: %s", exc)
        return server.data


_server = None


def get_server():
    global _server
    if _server is None:
        _server = GslbServer()
    return _server
