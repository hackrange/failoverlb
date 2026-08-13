"""
Answering DNS for names that should follow the healthy nodes.

This is the half of high availability everything else here was missing.  The
cluster can already move which node is in charge, and none of that moves a
single connection, because where the traffic goes was decided by whatever the
client resolved before it connected.  This decides that.

The trade nobody should be sold past
------------------------------------

DNS failover is bounded by things outside this box.  The TTL is a request, not
a rule.  Resolvers clamp very low values, browsers keep their own cache, and
some runtimes cache a lookup for the life of the process.  Thirty seconds gets
most clients moving inside a minute or two and leaves a tail that is much
worse.  Anybody promised instant failover has been promised something DNS
cannot do.

Where it is the right tool is when the nodes are in different places with
different addresses, which is exactly when nothing else works: two boxes on one
network can share a floating address and fail over in a second, and two boxes
in different buildings cannot.

Why the answers are computed rather than written to a file
----------------------------------------------------------

The obvious build is to generate a zone file and reload a real DNS server.
That falls apart at the first requirement: the answer has to change the moment
health changes, and reloading bind every few seconds to publish a health change
is not a system anybody wants to run.  So the reply is assembled per query out
of live health, and there is nothing to reload and nothing to fall behind.

What this deliberately does not do
----------------------------------

No recursion, ever.  This answers only for zones it is authoritative for and
refuses everything else.  An open resolver on the internet is a gift to
somebody running an amplification attack, and the difference between an
authoritative server and an open resolver is exactly this refusal.

No DNSSEC.  Signing wants key management, key rollover and a chain to the
parent, and doing it badly is worse than not doing it: a broken signature makes
a name fail to resolve everywhere, which is a harder outage than the one this
feature exists to prevent.
"""
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

# A DNS message over UDP is capped unless the client says otherwise with EDNS.
# 512 is what a client with no EDNS is required to cope with, and going over it
# without setting the truncated bit is how you get answers that vanish for some
# people and work for everybody you tested with.
UDP_SAFE_BYTES = 512
UDP_MAX_BYTES = 4096

# A query nobody could reasonably send.  Anything longer is somebody probing.
MAX_QUERY_BYTES = 4096


class ZoneData:
    """
    A snapshot of everything needed to answer, with no database in the path.

    Built on a timer and swapped in whole.  A query is not the place to open a
    session: an answer has to be quick, and a database that is briefly busy
    would turn into timeouts for every visitor rather than a slow page for one.
    """

    def __init__(self):
        self.zones = {}          # zone name, lowered, no trailing dot -> dict
        self.built_at = 0.0

    def zone_for(self, qname: str):
        """
        The most specific zone we hold that covers this name.

        Walked from the full name upward so a delegation inside a zone we also
        hold answers from the child, which is what a resolver expects.
        """
        parts = qname.strip(".").lower().split(".")
        for i in range(len(parts)):
            candidate = ".".join(parts[i:])
            if candidate in self.zones:
                return self.zones[candidate]
        return None


class GslbServer:
    """
    Listens on UDP and TCP and answers out of the snapshot.

    Both, because TCP is not optional.  A reply too big for UDP gets the
    truncated bit and the resolver asks again over TCP, and a server that only
    speaks UDP simply fails for those names.
    """

    def __init__(self, address="0.0.0.0", port=53):
        self.address = address
        self.port = port
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

        try:
            self._udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self._udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._udp.bind((self.address, self.port))

            self._tcp = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._tcp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._tcp.bind((self.address, self.port))
            self._tcp.listen(64)
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
        self._running = False
        self._close()

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
            except OSError:
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
            except OSError:
                if self._running:
                    log.debug("tcp socket closed")
                return
            threading.Thread(target=self._handle_tcp, args=(conn, peer),
                             daemon=True).start()

    def _handle_tcp(self, conn, peer):
        # DNS over TCP puts a two byte length in front of every message, both
        # ways.  Forgetting it on the reply looks like the server answering
        # garbage.
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
        Turn one query into one reply.

        Never raises out.  A malformed query is somebody scanning, not an
        emergency, and a server that falls over on a bad packet is a server
        anybody can turn off from the internet.
        """
        self.stats["queries"] += 1
        try:
            query = dns.message.from_wire(raw)
        except Exception:
            # Not a DNS message we can read.  There is no useful reply to a
            # packet we cannot even find the id in.
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
                # Not ours.  REFUSED rather than an attempt to look it up, and
                # that refusal is the line between an authoritative server and
                # an open resolver somebody else can point at a victim.
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
        Serialise, and set the truncated bit if it will not fit over UDP.

        The size a client can take comes from its own EDNS record when it sends
        one, and is 512 when it does not.  Guessing high and hoping is how you
        get a name that works for most people and silently fails for the rest.
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

        # Too big.  Answer with the header and the truncated bit, which tells
        # the resolver to ask again over TCP.
        reply.answer = []
        reply.additional = []
        reply.flags |= dns.flags.TC
        return reply.to_wire()

    def _answer_from_zone(self, reply, zone, qname, qtype):
        apex = zone["name"]
        wanted = dns.rdatatype.to_text(qtype)

        # SOA and NS for the zone itself are answered from the zone, not from
        # a record somebody had to remember to add.  A zone that cannot answer
        # its own SOA is one every checking tool will complain about.
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
            # The name does not exist here.  NXDOMAIN with the SOA in the
            # authority section, because that is where a resolver reads how
            # long it may remember that it does not exist.
            self.stats["nxdomain"] += 1
            reply.set_rcode(dns.rcode.NXDOMAIN)
            reply.authority.append(self._soa_rrset(zone))
            return

        # A CNAME answers every type, which is the rule that surprises people.
        cname = found.get("CNAME")
        if cname and wanted != "CNAME":
            reply.answer.append(dns.rrset.from_text(
                qname + ".", cname["ttl"], "IN", "CNAME",
                cname["values"][0] if cname["values"] else "."))
            self.stats["answered"] += 1
            return

        entry = found.get(wanted)
        if entry is None or not entry["values"]:
            # The name exists, this type does not.  NOERROR with nothing in the
            # answer, which is not the same as NXDOMAIN and resolvers treat the
            # two differently.
            reply.authority.append(self._soa_rrset(zone))
            return

        reply.answer.append(dns.rrset.from_text_list(
            qname + ".", entry["ttl"], "IN", wanted, entry["values"]))
        self.stats["answered"] += 1

    @staticmethod
    def _wildcard_for(zone, qname):
        """
        A wildcard covers one level and only where nothing more specific is.

        `*.example.com` answers for `a.example.com` and not for `a.b.example.com`
        and not for `example.com` itself, which is the same one label rule a
        wildcard certificate follows.
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
            # The contact is written as a name, with the at sign replaced by a
            # dot, which is one of the odder corners of the format.
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


def build_zone_data(session, healthy_node_ids) -> ZoneData:
    """
    Turn the database into the flat thing a query can be answered from.

    `healthy_node_ids` is decided by the caller and handed in rather than
    worked out here, so the rule about what counts as healthy lives in one
    place and this stays a lookup.
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

            values = _live_values(record, healthy_node_ids)
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


def _live_values(record, healthy_node_ids):
    """
    Which of a record's answers should be handed out right now.

    The whole feature is in here.  An answer tied to a node is only given when
    that node is healthy, and what happens when none of them are is a choice
    the person made when they set the record up.
    """
    enabled = [a for a in record.answers if a.enabled]
    if not enabled:
        return []

    if record.record_type == "CNAME":
        # Nothing to health check about a name, and only one is legal.
        return [_as_target(enabled[0].value)]

    healthy = [a for a in enabled
               if a.node_id is None or a.node_id in healthy_node_ids]

    if not healthy:
        if record.when_all_down == "serve_all":
            # A name that resolves to a broken box gives the visitor an error
            # they can describe.  A name that resolves to nothing looks to them
            # like the company has gone, and to us like DNS is broken.
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


def healthy_node_ids(session) -> set:
    """
    Which nodes are well enough to be handed out in a DNS answer.

    Stricter than the cluster page's idea of online, and deliberately so.  A
    node whose manager is answering but whose nginx is stopped will accept a
    connection on port 80 from nobody, so sending traffic there is worse than
    leaving it out.  What matters for an answer is whether the thing that
    serves the site is running, not whether the thing that manages it is.
    """
    from app.models import Node, NodeState

    out = set()
    for node in session.query(Node).all():
        if node.state != NodeState.ONLINE:
            continue
        if not node.nginx_active:
            continue
        out.add(node.id)
    return out


def refresh(server=None):
    """
    Rebuild the snapshot the server answers from.

    Runs on a timer rather than on a change, because health changes on its own
    all day and there is no single place a change lands.  A few seconds of
    staleness is well inside the TTL anybody would set, so nothing is gained by
    being cleverer.
    """
    from app.db import session_scope

    server = server or get_server()
    try:
        with session_scope() as session:
            data = build_zone_data(session, healthy_node_ids(session))
        server.data = data
        return data
    except Exception as exc:
        # Keep serving the last good snapshot.  A database hiccup should not
        # take a name off the internet, and the old answers are still broadly
        # right: health does not change that fast.
        log.error("could not rebuild the gslb zones, keeping the last set: %s", exc)
        return server.data


_server = None


def get_server():
    global _server
    if _server is None:
        _server = GslbServer()
    return _server
