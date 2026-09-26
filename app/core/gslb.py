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


# How long a serving loop waits for a packet before looking up to see whether
# it has been asked to stop.
#
# The loops used to block forever waiting for a query.  Closing the socket from
# another thread does not reliably wake a thread that is already inside
# recvfrom or accept on Linux, so those threads stayed alive holding the port
# open, and the next start could never bind: "Address already in use", with the
# operating system's own socket list showing the port free, and no way back
# except restarting the manager.  Waking twice a second costs nothing and means
# the threads end when they are told to.
POLL_SECONDS = 0.5

# How long stop() waits for those threads before giving up on them.  Generous
# next to the poll interval, because a thread that is mid answer should be
# allowed to finish.
STOP_TIMEOUT_SECONDS = 5.0


class GslbServer:
    """
    Listens on UDP and TCP and answers out of the snapshot.

    Both, because TCP is not optional.  A reply too big for UDP gets the
    truncated bit and the resolver asks again over TCP, and a server that only
    speaks UDP simply fails for those names.
    """

    def __init__(self, address=None, port=None):
        self.address = address or _own_address()
        # The node's own address rather than everything, and that is not a
        # detail.  Ubuntu and most others run a stub resolver on 127.0.0.53,
        # so binding 0.0.0.0 collides with it and the listener never starts.
        # Binding the address the world reaches this box on sidesteps that
        # entirely, and is what an authoritative server should be answering on
        # anyway: nothing should be asking it over loopback.
        # A port anybody may bind, and the agent puts a redirect in front of it.
        #
        # Port 53 cannot be bound from in here and that is by design, not an
        # oversight to work around.  The container runs unprivileged with
        # no-new-privileges set, which makes the kernel ignore file
        # capabilities outright, so the usual setcap trick is inert.  Turning
        # that hardening off for a chart of a feature would be trading the
        # thing that protects the most exposed component in the system.
        #
        # So this listens high and asks the agent, which is the root part and
        # exists for exactly this, to redirect 53 to it.  A destination NAT
        # rewrites where the packet is going and leaves who it came from alone,
        # so the client address survives, which the capability route also gave
        # us and the alternative of proxying through nginx did not.
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

        # Nothing should be left from a previous life, but say so rather than
        # assume it: a thread still running here is the fault this timeout and
        # the join in stop() exist to prevent, and it would otherwise show up
        # as an unexplainable bind failure.
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
        Stop serving, and do not come back until the threads have really gone.

        The order matters.  The flag goes down first, then we wait for the
        loops to notice and end, and only then are the sockets closed.  Closing
        them first is what the old version did, and it left threads blocked
        inside a call on a socket that had been taken away, still holding the
        port, so the next start could never bind and only a restart of the
        manager cleared it.
        """
        self._running = False

        for thread in self._threads:
            if thread is threading.current_thread():
                continue
            thread.join(timeout=STOP_TIMEOUT_SECONDS)

        stuck = [t for t in self._threads
                 if t.is_alive() and t is not threading.current_thread()]
        if stuck:
            # Worth shouting about.  Carrying on and closing underneath them is
            # exactly the state that used to wedge the port, so if this ever
            # appears it is the thing to look at.
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
                # Nothing arrived in the poll interval.  Go round again and
                # look at the flag, which is the whole point of the timeout.
                #
                # This has to be caught before OSError, because a timeout is a
                # kind of OSError, and the branch below reads one as the socket
                # having been closed and ends the thread.  Getting that order
                # wrong stops the server answering anything at all.
                continue
            except (OSError, AttributeError):
                # Closed under us, or gone entirely.  Either way there is
                # nothing left to serve on.
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
                # Same as the udp side: a timeout is how this loop gets to look
                # at the flag, and it must be caught before OSError.
                continue
            except (OSError, AttributeError):
                if self._running:
                    log.debug("tcp socket closed")
                return

            # accept() on a socket with a timeout hands back a connection that
            # has one too.  The handler sets its own, but say so here rather
            # than leaving it to be inherited by accident.
            conn.settimeout(None)
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


def build_zone_data(session, healthy_nodes) -> ZoneData:
    """
    Turn the database into the flat thing a query can be answered from.

    `healthy_nodes` is a set of node names decided by the caller rather than
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
    The node an answer belongs to, as a name, or None if it is not tied to one.

    By name because an id on a replicated row means whatever the receiving
    database happens to have under that number, which is a different machine.
    node_id is still read as a fallback for rows written before names were
    stored, and on the node that authored those rows it is correct.
    """
    name = (getattr(answer, "node_name", None) or "").strip()
    if name:
        return name
    node = getattr(answer, "node", None)
    return node.name if node is not None else None


def _live_values(record, healthy_nodes):
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
               if _answer_node(a) is None or _answer_node(a) in healthy_nodes]

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


def _own_address() -> str:
    """
    This node's address, as the cluster knows it.

    Falls back to everything only when there is nothing configured, which is a
    fresh install that has no zones to serve either.
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
    Every address each node is known by, keyed by node name.

    Three places hold one: the address the cluster talks to it on, the public
    address it discovered by asking the internet what it goes out as, and the
    list of addresses its own interfaces hold.  A node behind NAT has a
    different answer in the first two, which is exactly why all three count.
    """
    from app.models import Node

    out = {}
    for node in session.query(Node).all():
        known = set()
        for value in (node.address, node.public_ip):
            if value and str(value).strip():
                known.add(str(value).strip())
        # local_addresses is a list of objects, one per interface, not a list
        # of strings.  Storing str(entry) put a whole json object into the set
        # and into the message a person reads.  Older rows may still be plain
        # strings, so both shapes are handled.
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
    The addresses worth showing somebody, in a sentence.

    Every address counts when deciding whether an answer matches, including
    loopback and link local: an answer pointing at one of those is held by the
    node and is still almost certainly a mistake, and that is a different
    conversation.  Printing them all makes the message unreadable, so the list
    a person sees leaves out the ones nobody would ever mean to publish.
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
    Answers that hand out an address their own node does not hold.

    Reported from the field, and it cost a real outage to find.  An answer was
    tied to the second node and pointed at an address one digit away from that
    node's real one.  Everything looked right: both nodes answered, the record
    resolved, the page showed two healthy answers.

    It only showed when the other node was taken away, because until then the
    other node's answer was the one being used.  Then the name resolved solely
    to an address that belonged to nobody, and it read as DNS having failed.

    A warning and never a refusal.  Pointing an answer at something other than
    the node itself is a real thing people do: a floating address that moves
    between machines, or a service in front of the node.  The product cannot
    tell that apart from a typo, but it can say "this does not look like that
    node" and let somebody who knows decide.

    Answers not tied to a node are left alone entirely.  There is nothing to
    compare them against, which is the whole meaning of not tying them.
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
    Which nodes are well enough to be handed out in a DNS answer, by name.

    Stricter than the cluster page's idea of online, and deliberately so.  A
    node whose manager is answering but whose nginx is stopped will accept a
    connection on port 80 from nobody, so sending traffic there is worse than
    leaving it out.  What matters for an answer is whether the thing that
    serves the site is running, not whether the thing that manages it is.

    Three gates, and the third one is here because the first two were not
    enough.  On 24 August 2026 a node passed both for 73 minutes while serving
    nobody: its manager was online and answering, and `systemctl is-active
    nginx` said `active`, because a wedged nginx is still a running one.  Half
    of every DNS answer pointed at it the whole time.

    So `nginx_serving` is the answer to a different question, asked by putting
    a real request through that node's own listener.  See
    app/core/frontend_probe.py.

    Only an explicit False withdraws a node.  None means nothing has reported
    yet, and a node is not taken off the internet for having been quiet: during
    a rolling upgrade the node running the older manager never sets this, and
    treating that as a failure would withdraw each node in turn as it was
    upgraded.
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


# The old name, kept so nothing calling it breaks quietly.  It returns names
# now, which is the whole point of the change, so the name would be a lie.
healthy_node_ids = healthy_node_names


async def ensure_redirect(server=None):
    """
    Ask the agent to point port 53 at wherever we are listening.

    Called after the listener is up rather than before, so a rule never exists
    with nothing behind it.  A box with a redirect and no listener answers
    nothing at all, which looks exactly like the machine being down.
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
    Give port 53 back, for when there is nothing left to answer for.

    A redirect pointing at a listener that has stopped is worse than no
    redirect: the box takes port 53 and then answers nothing on it, so anything
    still asking gets silence rather than moving on to another nameserver.
    """
    from app.core.agent_client import get_agent

    try:
        return await get_agent().call("dns_redirect_clear", timeout=30)
    except Exception as exc:
        log.error("could not take the dns redirect off: %s", exc)
        return {"cleared": False, "error": str(exc)}


async def reconcile(server=None):
    """
    Make the listener match the zones, whenever either one changes.

    Starting the listener used to happen once, at boot, and only if a zone was
    already in the database.  That is the wrong moment for the case that
    matters most.  A node joining an existing cluster comes up empty and gets
    its config a few seconds later, so it always lost that race and then never
    looked again: it would sit there, part of the cluster, healthy in every
    view, and never answer a single DNS query until somebody restarted it.

    The node that stays quiet is the standby, which is the one whose whole job
    is to keep answering after the other one dies.  So the fleet looks like it
    has two nameservers and has one, and finds out which at the worst moment.

    Running it on the same timer as the refresh means a zone added on any node
    brings that node's listener up within a few seconds, and the last zone
    being deleted hands port 53 back.
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
        # Re-assert the firewall rule if something else cleared it, which a
        # reboot or anybody flushing nftables will do.  Asked about first
        # rather than just rewritten, because writing it means dropping the
        # table and rebuilding it, and doing that every few seconds would put a
        # small hole in the one thing this is here to keep up.
        from app.core.agent_client import get_agent
        try:
            status = await get_agent().call("dns_redirect_status", timeout=15)
            # Ask about the rule, and about whether it is the rule we want.
            #
            # This read `installed`, which the agent never sent: it answered
            # `present`.  So the check was false every time and this rebuilt
            # the nftables table every ten seconds for the life of the node,
            # each rebuild being a delete followed by a write with a gap in
            # between.  The comment above says why that is the one thing not
            # to do here, and it was being done on a timer.
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
                # An older agent's rule, left behind by an upgrade.  It matches
                # one address, so every other address this node answers on has
                # no redirect at all.
                log.info("the dns redirect only matches one address, rewriting "
                         "it to cover every address this node holds")
                await ensure_redirect(server)
        except Exception as exc:
            log.debug("could not check the dns redirect: %s", exc)


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
            data = build_zone_data(session, healthy_node_names(session))
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
