"""
Certificates.

This is the part that solves the problem that makes clustered nginx annoying.

Lets Encrypt proves you own a domain by connecting to whatever address that
domain points at.  In a two node setup only one of those boxes is on the end of
that address at any given moment.  Run certbot on the other one and the
challenge fails, every single time, and the failure looks like a DNS problem
even though DNS is fine.

Worse, the node holding that address is not fixed.  Failover moves it.  A cert
issued from lb-01 three months ago may need to renew from lb-02 today.  So we
work out who owns the address at renewal time, every time, and never assume the
node that got it last time can get it again.

Two things make this reliable:

  Pick the issuer fresh.  Look up the domain, ask each node what its public
  address is, and give the job to whichever node matches.

  Answer from everywhere.  When certbot asks for a token, we push it to every
  node before telling Lets Encrypt to go look.  Round robin DNS, an address
  that just moved, a stale cache, none of it matters if every box can answer.

Once a cert is issued it gets copied to every node, because they all have to
serve it.
"""

import asyncio
import json
import logging
import re
from datetime import datetime, timezone

import dns.asyncresolver
import dns.resolver

from app.config import get_settings
from app.core.agent_client import AgentError, get_agent
from app.core.cluster import NodeUnreachable, PeerClient, get_cluster
from app.core.crypto import decrypt, parse_certificate
from app.db import session_scope
from app.models import Certificate, Node, NodeState, utcnow

log = logging.getLogger("nfm.acme")

# Where to look a domain up, when nobody has said otherwise.
#
# Public resolvers on purpose, not the box's own.  An internal resolver very
# often has a split horizon answer pointing at a private address, and that is
# not what the certificate authority will see.  We want the public answer,
# because that is the one that decides which node can answer the challenge.
#
# This is only the default.  Plenty of places cannot reach these at all, or run
# their own resolvers they would rather use, so it is a setting.  See
# dns_resolvers on the settings page.
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def configured_resolvers() -> list:
    """
    Which DNS servers to ask.

    Falls back to the public ones when nothing is set, which is right for a box
    on the internet and wrong for one that is not, hence the setting.
    """
    from app.core import settings_store

    chosen = settings_store.get("dns_resolvers") or []
    chosen = [r.strip() for r in chosen if r and r.strip()]
    return chosen or DEFAULT_RESOLVERS

DNS_TIMEOUT = 8


class AcmeError(Exception):
    pass


# ==============================================================================
# Working out who should get the cert
# ==============================================================================

async def resolve_domain(domain: str) -> dict:
    """
    Look a domain up the way Lets Encrypt will.

    We ask more than one public resolver and merge the answers.  DNS changes
    take time to spread, so during a failover different resolvers legitimately
    give different answers for a while.  Taking the union means we consider
    every node that any resolver currently points at, which is the safe way
    round.
    """
    found_v4 = set()
    found_v6 = set()
    errors = []

    resolvers = list(configured_resolvers())

    # Optionally ask this box's own resolver too.  Useful on a split horizon
    # network where the internal answer is the one that matters, and harmless
    # elsewhere because we merge the answers rather than trusting one.
    from app.core import settings_store

    if settings_store.get("dns_use_system_resolver"):
        try:
            system = dns.resolver.Resolver()
            resolvers.extend(str(ns) for ns in system.nameservers)
        except Exception:
            pass

    for server in resolvers:
        resolver = dns.asyncresolver.Resolver(configure=False)
        resolver.nameservers = [server]
        resolver.timeout = DNS_TIMEOUT
        resolver.lifetime = DNS_TIMEOUT

        for rdtype, bucket in (("A", found_v4), ("AAAA", found_v6)):
            try:
                answer = await resolver.resolve(domain, rdtype)
                for record in answer:
                    bucket.add(str(record))
            except dns.resolver.NoAnswer:
                continue
            except dns.resolver.NXDOMAIN:
                errors.append(f"{server} says {domain} does not exist")
                break
            except Exception as exc:
                errors.append(f"{server}: {type(exc).__name__}")

    return {
        "domain": domain,
        "a": sorted(found_v4),
        "aaaa": sorted(found_v6),
        "all": sorted(found_v4 | found_v6),
        "errors": errors,
        "resolved": bool(found_v4 or found_v6),
    }


async def pick_issuing_node(domain: str) -> dict:
    """
    Decide which node should ask for this cert.

    In order of preference:

      1. A node whose detected public address is one the domain resolves to.
         This is the right answer and it is the one that will actually work.
      2. A node that has that address on one of its own interfaces.  Covers a
         floating VIP, where the address is on the box but its outbound path
         goes somewhere else.
      3. The active node, as a last resort, with a warning.  Better to try and
         get a clear error than to refuse and do nothing.
    """
    dns_result = await resolve_domain(domain)

    with session_scope() as session:
        nodes = session.query(Node).all()
        online = [n for n in nodes if n.state == NodeState.ONLINE or n.is_self]

        if not dns_result["resolved"]:
            active = next((n for n in online if n.role.value == "active"), None)
            return {
                "node": active.name if active else None,
                "reason": "dns_failed",
                "confidence": "none",
                "dns": dns_result,
                "warning": (
                    f"{domain} does not resolve at all right now.  Check the DNS "
                    f"record exists and has spread before trying again."
                ),
            }

        wanted = set(dns_result["all"])

        # Best case, a node's public address is one the domain points at.
        for node in online:
            if node.public_ip and node.public_ip in wanted:
                return {
                    "node": node.name,
                    "reason": "public_ip_match",
                    "confidence": "high",
                    "matched_ip": node.public_ip,
                    "dns": dns_result,
                }

        # Next, the address is sitting on one of its interfaces.  This is the
        # floating VIP case, where the box holds the address but its own traffic
        # goes out through something else, so its detected public address does
        # not match even though it is the right box.
        for node in online:
            local = {a.get("address") for a in node.local_address_list()}
            overlap = local & wanted
            if overlap:
                return {
                    "node": node.name,
                    "reason": "local_interface_match",
                    "confidence": "high",
                    "matched_ip": sorted(overlap)[0],
                    "dns": dns_result,
                }

        # Nothing matched.  Usually means the domain points at something in
        # front, like a cloud load balancer or a CDN, and the challenge will
        # never reach any of these boxes over http.
        active = next((n for n in online if n.role.value == "active"), None)
        return {
            "node": active.name if active else (online[0].name if online else None),
            "reason": "no_match",
            "confidence": "low",
            "dns": dns_result,
            "warning": (
                f"{domain} points at {', '.join(dns_result['all'])}, and none of "
                f"your nodes report that address.  If there is a load balancer or "
                f"a CDN in front, an http-01 challenge cannot work.  Use dns-01 "
                f"for this one."
            ),
        }


# ==============================================================================
# Answering the challenge on every node
# ==============================================================================

class ChallengeCoordinator:
    """
    Puts the challenge token on every node, not just the one asking.

    This is what makes issuance reliable rather than lucky.  Lets Encrypt picks
    which address to connect to and does not tell us in advance.  With round
    robin DNS, or an address that just moved, or a resolver holding a stale
    answer, the request can easily land on a node that is not the one running
    certbot.  If only that node had the file, the challenge fails and the error
    tells you nothing useful.

    Put the token everywhere and it does not matter which one they hit.
    """

    def __init__(self):
        self.cluster = get_cluster()
        self.settings = get_settings()

    async def publish(self, token: str, key_auth: str) -> dict:
        results = {"ok": [], "failed": []}

        try:
            await get_agent().acme_token_write(token=token, value=key_auth)
            results["ok"].append(self.settings.node_name)
        except AgentError as exc:
            results["failed"].append({"node": self.settings.node_name, "error": str(exc)})

        with session_scope() as session:
            peers = [
                {"id": p.id, "name": p.name}
                for p in self.cluster.peers(session)
                if p.state == NodeState.ONLINE
            ]

        for info in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    client = PeerClient(node, self.cluster.ca)
                await client.call(
                    "/peer/acme/token",
                    {"action": "write", "token": token, "value": key_auth},
                )
                results["ok"].append(info["name"])
            except Exception as exc:
                # One node failing is not fatal.  As long as the node the
                # validation server actually hits has the file, it works.
                log.warning("could not put the token on %s: %s", info["name"], exc)
                results["failed"].append({"node": info["name"], "error": str(exc)})

        log.info("challenge token is on %s of %s nodes",
                 len(results["ok"]), len(results["ok"]) + len(results["failed"]))
        return results

    async def cleanup(self, token: str):
        try:
            await get_agent().acme_token_delete(token=token)
        except AgentError:
            pass

        with session_scope() as session:
            peers = [
                {"id": p.id, "name": p.name}
                for p in self.cluster.peers(session)
                if p.state == NodeState.ONLINE
            ]

        for info in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    client = PeerClient(node, self.cluster.ca)
                await client.call("/peer/acme/token", {"action": "delete", "token": token})
            except Exception:
                # A leftover token file is harmless.  It is a random name in a
                # folder that only serves challenge files.
                pass


# ==============================================================================
# The certificate manager
# ==============================================================================

class CertificateManager:
    def __init__(self):
        self.settings = get_settings()
        self.cluster = get_cluster()
        self.challenges = ChallengeCoordinator()

    # -------------------------------------------------------------------------

    async def issue(self, cert_id: int, force: bool = False, actor: str = "system") -> dict:
        """
        Get or renew a certificate, from whichever node can actually do it.

        Every time.  Not from whoever did it last time.  That is the whole
        point, because the node that owns the public address moves.
        """
        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if not cert:
                raise AcmeError("no such certificate")
            if cert.source != "letsencrypt":
                raise AcmeError("that certificate was uploaded, so there is nothing to renew")

            domains = cert.domain_list()
            challenge_type = cert.challenge_type
            dns_plugin = cert.dns_plugin
            dns_creds = decrypt(cert.dns_credentials_encrypted) if cert.dns_credentials_encrypted else None
            key_type = cert.key_type
            cert_name = cert.name
            propagation = cert.dns_propagation_seconds

            # Which authority, read off the certificate rather than off a
            # setting.
            #
            # This is what makes a renewal go back to whoever issued it.  A
            # certificate bought from one authority that quietly renews from
            # another is a change nobody asked for, and the first sign of it is
            # a browser complaining about an issuer somebody did not choose.
            #
            # Read here, inside the session, with everything else this function
            # needs.  Reaching for cert.authority further down is a lazy load on
            # a row whose session has closed, which is a DetachedInstanceError
            # and a 500 on the page: every Lets Encrypt request on this fleet
            # failed that way, including the ones that have no authority at all.
            authority = cert.authority
            if authority is not None:
                if not authority.enabled:
                    raise AcmeError(
                        f"the authority {authority.name} is turned off, so this "
                        f"certificate cannot be renewed from it.  Turn it back on, "
                        f"or point the certificate at another one.")
                issuer_settings = {
                    "directory": (authority.directory_url or "").strip(),
                    "eab_kid": (authority.eab_kid or "").strip(),
                    "eab_hmac": (decrypt(authority.eab_hmac_key_encrypted) or ""
                                 if authority.eab_hmac_key_encrypted else ""),
                    "preferred_chain": (authority.preferred_chain or "").strip(),
                }
            else:
                issuer_settings = None

            cert.last_renewal_attempt = utcnow()
            session.commit()

        if not domains:
            raise AcmeError("that certificate has no domains on it")

        # Whatever an admin put in Settings, falling back to the environment.
        # Blank is fine, see settings_store.acme_email for why.
        from app.core import settings_store

        email = settings_store.acme_email()
        staging = settings_store.get("acme_staging", self.settings.acme_staging)

        # ---- pick the node ---------------------------------------------------
        if challenge_type == "dns-01":
            # dns-01 does not need any inbound connection, so any node can do
            # it.  Use the active one and keep it simple.
            with session_scope() as session:
                me = self.cluster.self_node(session)
                issuer = self.settings.node_name if me and me.role.value == "active" else None
            selection = {"node": issuer or self.settings.node_name,
                         "reason": "dns01_any_node", "confidence": "high"}
        else:
            selection = await pick_issuing_node(domains[0])

        issuing_node = selection.get("node")
        if not issuing_node:
            raise AcmeError("could not work out which node should ask for this cert")

        log.info(
            "issuing %s from %s (%s, confidence %s)",
            cert_name, issuing_node, selection.get("reason"), selection.get("confidence"),
        )

        # ---- run it ----------------------------------------------------------
        ca_bundle = settings_store.get("acme_ca_bundle")

        if issuer_settings is not None:
            directory = issuer_settings["directory"]
            eab_kid = issuer_settings["eab_kid"]
            eab_hmac = issuer_settings["eab_hmac"]
            preferred_chain = issuer_settings["preferred_chain"]
        else:
            # Lets Encrypt, which needs no credentials and is the default.
            directory = (settings_store.get("acme_directory_url") or "").strip()
            eab_kid = ""
            eab_hmac = ""
            preferred_chain = ""

        request = {
            "domains": domains,
            # Send our own name for it, so certbot files it under the same name
            # we will look it up by afterwards.
            "cert_name": cert_name,
            "email": email,
            "staging": staging,
            "acme_server": directory or None,
            "ca_bundle": ca_bundle or None,
            "eab_kid": eab_kid or None,
            "eab_hmac_key": eab_hmac or None,
            "preferred_chain": preferred_chain or None,
            "challenge": challenge_type,
            "key_type": key_type,
            "force_renewal": force,
        }
        if challenge_type == "dns-01":
            request["dns_plugin"] = dns_plugin
            request["dns_credentials"] = dns_creds
            request["dns_propagation"] = propagation
        else:
            # The hooks are what make the token land on every node.  certbot
            # calls them, they call our local API, and that pushes the token out
            # to the cluster before certbot tells Lets Encrypt to go and look.
            #
            # Write them first, every time.  A node that was rebuilt will not
            # have them, and the failure without this is "hook ... is not a file
            # on this box", which says what is wrong but nothing about why or
            # what to do about it.
            from app.core import acme_hooks

            written = await acme_hooks.ensure_hooks()
            if not written.get("ok"):
                raise AcmeError(
                    f"could not put the certbot hooks on this node: {written.get('error')}.  "
                    f"Without them only the node running certbot can answer the challenge."
                )

            request["auth_hook"] = acme_hooks.AUTH_HOOK
            request["cleanup_hook"] = acme_hooks.CLEANUP_HOOK

        try:
            if issuing_node == self.settings.node_name:
                result = await get_agent().certbot(**request)
            else:
                result = await self._issue_on_peer(issuing_node, request)
        except (AgentError, NodeUnreachable) as exc:
            self._record_failure(cert_id, str(exc))
            raise AcmeError(f"the certificate request failed: {exc}")

        if not result.get("ok"):
            output = result.get("output", "")
            self._record_failure(cert_id, output)
            raise AcmeError(_explain_certbot_error(output))

        # ---- record it and copy it around -----------------------------------
        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            cert.issued_by_node = issuing_node
            cert.issued_from_ip = selection.get("matched_ip")
            cert.resolved_ips = json.dumps(selection.get("dns", {}).get("all", []))
            cert.last_renewal_success = utcnow()
            cert.last_renewal_error = None
            cert.renewal_failures = 0
            session.commit()

        await self.refresh_metadata(cert_id, issuing_node)
        sync = await self.replicate(cert_id)

        return {
            "ok": True,
            "issued_by": issuing_node,
            "selection": selection,
            "synced_to": sync.get("ok", []),
            "sync_failed": sync.get("failed", []),
        }

    async def _issue_on_peer(self, node_name: str, request: dict) -> dict:
        with session_scope() as session:
            node = session.query(Node).filter(Node.name == node_name).first()
            if not node:
                raise AcmeError(f"{node_name} is not on the roster")
            client = PeerClient(node, self.cluster.ca)

        # Long timeout.  Waiting on Lets Encrypt plus DNS propagation on a
        # dns-01 challenge can genuinely take minutes.
        return await client.call("/peer/acme/issue", request, timeout=600)

    # -------------------------------------------------------------------------

    async def replicate(self, cert_id: int) -> dict:
        """
        Copy a cert to every other node.

        They all serve the same sites, so they all need the same cert.  Only one
        of them could get it, so the rest have to be handed a copy.

        The private key goes over the wire here.  That is unavoidable and it is
        fine: the channel is mutual TLS between two nodes that already hold
        certificates from the same private CA, and the key lands at 0600 owned
        by root on the far side.
        """
        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if not cert:
                raise AcmeError("no such certificate")
            name = cert.name
            source_node = cert.issued_by_node
            peers = [
                {"id": p.id, "name": p.name}
                for p in self.cluster.peers(session)
            ]

        # Get the files from whichever node holds them.
        if source_node == self.settings.node_name or not source_node:
            try:
                export = await get_agent().cert_export(name=name)
            except AgentError as exc:
                raise AcmeError(f"could not read the cert files: {exc}")
        else:
            with session_scope() as session:
                node = session.query(Node).filter(Node.name == source_node).first()
                if not node:
                    raise AcmeError(f"{source_node} is not on the roster")
                client = PeerClient(node, self.cluster.ca)
            export = await client.call("/peer/cert/export", {"name": name}, timeout=60)

        bundle = export.get("bundle", {})
        if "fullchain.pem" not in bundle:
            raise AcmeError("the exported cert is missing its chain")

        import hashlib
        checksum = hashlib.sha256(bundle["fullchain.pem"].encode()).hexdigest()[:16]

        results = {"ok": [], "failed": []}

        # Put a copy in this node's synced folder, even when this is the node
        # certbot wrote the real files on.  Having the files somewhere is not
        # enough, they have to be at the path the rendered config names, and
        # that path is now the synced folder on every node.  Skipping this on
        # the issuing node left it as the only node without a copy where the
        # config looks, which is the one node everybody assumes is fine.
        try:
            await get_agent().cert_import(name=name, bundle=bundle)
            await _reload_for_new_cert(name)
            results["ok"].append(self.settings.node_name)
        except AgentError as exc:
            results["failed"].append({"node": self.settings.node_name, "error": str(exc)})

        # Push to every peer, the node the files came from included.  It has the
        # certbot copy, which is not the copy the config reads, and sending the
        # same bytes back costs one write and removes a way for that node to sit
        # there looking fine while nginx cannot find its certificate.
        for info in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    client = PeerClient(node, self.cluster.ca)
                await client.call(
                    "/peer/cert/import", {"name": name, "bundle": bundle}, timeout=60
                )
                results["ok"].append(info["name"])
            except Exception as exc:
                log.error("could not copy %s to %s: %s", name, info["name"], exc)
                results["failed"].append({"node": info["name"], "error": str(exc)})

        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if cert:
                sync_map = {n: checksum for n in results["ok"]}
                cert.synced_nodes = json.dumps(sync_map)
                session.commit()

        log.info("copied %s to %s of %s nodes",
                 name, len(results["ok"]), len(results["ok"]) + len(results["failed"]))
        return results

    # -------------------------------------------------------------------------

    async def refresh_metadata(self, cert_id: int, node_name: str = None) -> dict:
        """Read the dates and names back off the real file."""
        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if not cert:
                raise AcmeError("no such certificate")
            name = cert.name
            holder = node_name or cert.issued_by_node or self.settings.node_name

        try:
            if holder == self.settings.node_name:
                export = await get_agent().cert_export(name=name)
            else:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.name == holder).first()
                    if not node:
                        return {}
                    client = PeerClient(node, self.cluster.ca)
                export = await client.call("/peer/cert/export", {"name": name}, timeout=60)
        except Exception as exc:
            log.warning("could not read the cert files for %s: %s", name, exc)
            return {}

        try:
            info = parse_certificate(export["bundle"]["fullchain.pem"])
        except Exception as exc:
            log.warning("could not parse the cert for %s: %s", name, exc)
            return {}

        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if cert:
                cert.not_before = info["not_before"]
                cert.not_after = info["not_after"]
                cert.issuer = info["issuer"][:255]
                cert.serial = info["serial"][:128]
                cert.fingerprint = info["fingerprint"]
                # Empty when the authority publishes no responder, which is
                # now the normal case rather than the exception.
                cert.ocsp_url = (info.get("ocsp_url") or "")[:255] or None
                if info.get("domains"):
                    cert.domains = json.dumps(info["domains"])
                session.commit()

        return info

    # -------------------------------------------------------------------------

    async def place_material(self, cert_id: int) -> dict:
        """
        Write a certificate we hold ourselves to every node.

        Uploaded, self signed and completed signing requests all keep the
        material in the database, so this needs no source node and no export
        from anywhere: it reads the row and writes the files.

        That is a real difference from a Lets Encrypt certificate, not an
        implementation detail.  Those live in certbot's folder on whichever node
        issued them, so a node that never had them has to be handed a copy by a
        node that did, and if no such node is up there is nothing to be done.
        These can be rebuilt on any node from the database, which the snapshot
        already carries everywhere, so they come back on their own.
        """
        from app.core.crypto import decrypt

        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if not cert:
                raise AcmeError("no such certificate")
            if not cert.has_material():
                raise AcmeError(f"{cert.name} has no stored certificate to write")
            name = cert.name
            fullchain = cert.uploaded_fullchain
            privkey = decrypt(cert.uploaded_privkey_encrypted)
            peers = [{"id": p.id, "name": p.name} for p in self.cluster.peers(session)]

        if not privkey:
            # The key is sealed with this node's secret.  Failing to open it
            # means NFM_SECRET_KEY changed, and writing the certificate without
            # a key would leave nginx pointed at half a pair.
            raise AcmeError(
                f"the stored private key for {name} will not decrypt.  That "
                f"happens when NFM_SECRET_KEY changed on this node.  Upload the "
                f"certificate again."
            )

        bundle = {"fullchain.pem": fullchain, "privkey.pem": privkey}
        results = {"ok": [], "failed": []}

        try:
            await get_agent().cert_import(name=name, bundle=bundle)
            await _reload_for_new_cert(name)
            results["ok"].append(self.settings.node_name)
        except AgentError as exc:
            results["failed"].append({"node": self.settings.node_name, "error": str(exc)})

        for info in peers:
            try:
                with session_scope() as session:
                    node = session.query(Node).filter(Node.id == info["id"]).first()
                    if not node:
                        continue
                    client = PeerClient(node, self.cluster.ca)
                await client.call("/peer/cert/import",
                                  {"name": name, "bundle": bundle}, timeout=60)
                results["ok"].append(info["name"])
            except Exception as exc:
                log.error("could not copy %s to %s: %s", name, info["name"], exc)
                results["failed"].append({"node": info["name"], "error": str(exc)})

        # Record which nodes got it, the same way issuing does.
        #
        # This is what the "copied to" count on the page reads.  Writing the
        # files without writing this leaves a certificate that really is on
        # every node reading as 0 of 2 forever, with a "copy to all" button that
        # never stops being offered.  A column that is wrong is worse than no
        # column, because somebody acts on it.
        import hashlib
        checksum = hashlib.sha256(fullchain.encode()).hexdigest()[:16]

        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if cert:
                cert.synced_nodes = json.dumps({n: checksum for n in results["ok"]})
                cert.files_present = self.settings.node_name in results["ok"]
                cert.files_checked_at = utcnow()
                session.commit()

        log.info("wrote %s to %s of %s nodes", name, len(results["ok"]),
                 len(results["ok"]) + len(results["failed"]))
        return results

    async def verify_files(self):
        """
        Check the certificates we think exist are really on disk.

        The database and the filesystem drift apart more easily than you would
        expect.  A node restored from a backup older than the certificate, a
        rebuilt box, somebody clearing /etc/letsencrypt to free space.  The row
        stays, the files do not.

        It matters because the renderer points nginx at those paths.  A missing
        file means nginx will not start, which means the config cannot be
        applied anywhere, which means one stale certificate row blocks every
        change you try to make until somebody works out why.

        So we look, and mark the ones that are not there.  The renderer then
        leaves their https block out and says so, which keeps the rest of the
        fleet working while you sort the certificate out.
        """
        from app.core.render import CERT_SYNC_DIR

        agent = get_agent()

        with session_scope() as session:
            certs = [
                (c.id, c.name, bool(c.not_after))
                for c in session.query(Certificate).all()
            ]

        for cert_id, name, was_issued in certs:
            if not was_issued:
                continue

            # Check the path the config actually names, which is the synced
            # folder on every node now.  Checking certbot's folder on the
            # issuing node made that node report the certificate present while
            # the file nginx was told to open was somewhere else entirely.
            path = f"{CERT_SYNC_DIR}/{name}/fullchain.pem"

            present = True
            try:
                await agent.read_file(path)
            except AgentError as exc:
                # Only a missing file counts.  The agent being unreachable tells
                # us nothing about whether the certificate is there, and marking
                # it missing on that basis would drop https from every site the
                # moment the agent restarted.
                if getattr(exc, "code", "") in ("not_found", "denied"):
                    present = False
                else:
                    continue

            # Anything we hold the material for can put itself back.
            #
            # This is the case a promoted standby lands in: the snapshot brought
            # the row, so the certificate is right there in the database, and
            # the only thing missing is a file.  Waiting for a person to notice
            # and press something would mean the site serves plain http until
            # they do, when nothing was actually lost.
            if not present:
                with session_scope() as session:
                    cert = session.query(Certificate).filter(
                        Certificate.id == cert_id).first()
                    can_rebuild = bool(cert and cert.has_material())
                if can_rebuild:
                    try:
                        await self.place_material(cert_id)
                        log.info("wrote %s back to disk from what we hold", name)
                        continue
                    except Exception as exc:
                        log.error("could not write %s back to disk: %s", name, exc)

            with session_scope() as session:
                cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
                if not cert:
                    continue
                if cert.files_present != present:
                    if present:
                        log.info("certificate %s is back on disk", name)
                    else:
                        log.error(
                            "certificate %s is in the database but its files are not on "
                            "this node.  Leaving its https block out so the rest of the "
                            "config still applies.  Re-issue it.",
                            name,
                        )
                    cert.files_present = present
                cert.files_checked_at = utcnow()
                session.commit()

    async def check_dns(self):
        """
        Check each certificate's domains still point at this fleet.

        Renewal works by the certificate authority connecting to whatever the
        domain resolves to.  Point it somewhere no node answers and the renewal
        fails, but not today: today the certificate is still valid and every
        page says so.  It fails in ninety days, on a schedule nobody is watching,
        long after whoever moved the record has stopped thinking about it.

        So we compare what the domain resolves to against every address the
        fleet knows it has, and say so while there is still time to fix it.

        A resolver that will not answer is not a mismatch.  DNS being down tells
        us nothing about where the record points, and marking every certificate
        broken because a resolver timed out would be worse than saying nothing.
        """
        with session_scope() as session:
            certs = [
                (c.id, c.name, json.loads(c.domains or "[]"))
                for c in session.query(Certificate).all()
            ]
            ours = set()
            for node in session.query(Node).all():
                if node.public_ip:
                    ours.add(node.public_ip)
                for entry in node.local_address_list():
                    if entry.get("scope") == "global" and entry.get("address"):
                        ours.add(entry["address"])

        if not ours:
            log.debug("no node addresses known yet, skipping the dns check")
            return

        for cert_id, name, domains in certs:
            unowned, owned, failed = [], [], []

            # Resolve once and keep both halves.  Looking it up twice invites
            # two different answers, which is exactly the sort of thing that
            # makes a warning appear and vanish for no visible reason.
            for domain in domains or [name]:
                result = await resolve_domain(domain)
                if not result["resolved"]:
                    failed.append(domain)
                    continue
                for address in result["all"]:
                    (owned if address in ours else unowned).append(address)

            if not owned and not unowned:
                # Every lookup failed.  Say nothing rather than cry wolf.
                if failed:
                    log.warning("could not resolve %s to check its dns", ", ".join(failed))
                continue

            ok, warning = True, None

            if unowned and not owned:
                ok = False
                warning = (
                    f"{name} resolves to {', '.join(sorted(set(unowned)))}, and no node in "
                    f"this fleet answers on any of those.  A renewal has to be answered by "
                    f"the node the record points at, so this one will fail when it comes "
                    f"due.  Point the record at a node, or issue from wherever it points."
                )
            elif unowned:
                warning = (
                    f"{name} also resolves to {', '.join(sorted(set(unowned)))}, which no "
                    f"node here owns.  Renewal still works through the addresses we do "
                    f"answer on, but a certificate authority may try that one first, and "
                    f"anybody reaching it goes nowhere.  Usually a stale record."
                )

            with session_scope() as session:
                cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
                if not cert:
                    continue
                if cert.dns_warning != warning:
                    if warning:
                        log.warning("dns check on %s: %s", name, warning)
                    else:
                        log.info("dns for %s points at this fleet again", name)
                cert.dns_ok = ok
                cert.dns_warning = warning
                cert.dns_checked_at = utcnow()
                session.commit()

    async def check_renewals(self):
        """
        Renew anything that is getting close to expiry.

        This is the manager's own scheduler, and it replaces the certbot timer
        on purpose.  The stock timer runs on every box, and on a node that does
        not own the public address the renewal fails every time it fires.  You
        end up with a mailbox full of failures from two of your three nodes and
        the real problem buried in there somewhere.

        Doing it here means the decision about which node runs certbot gets made
        fresh each time, with current DNS.

        install.sh turns certbot.timer off for exactly this reason.
        """
        with session_scope() as session:
            if not self.cluster.is_active(session):
                # Only the active node drives renewals.  Otherwise every node
                # tries at once and they race each other into the rate limits.
                return

            due = [
                c.id for c in session.query(Certificate).filter(
                    Certificate.source == "letsencrypt",
                    Certificate.auto_renew == True,  # noqa: E712
                ).all()
                if c.needs_renewal
            ]

        for cert_id in due:
            try:
                log.info("renewing certificate %s", cert_id)
                await self.issue(cert_id)
            except AcmeError as exc:
                log.error("renewal of cert %s failed: %s", cert_id, exc)
            # Space them out.  Lets Encrypt rate limits are real, and hammering
            # them with ten renewals at once is a good way to get blocked for a
            # week, which is much worse than these taking a couple of minutes.
            await asyncio.sleep(5)

    def _record_failure(self, cert_id: int, error: str):
        with session_scope() as session:
            cert = session.query(Certificate).filter(Certificate.id == cert_id).first()
            if cert:
                cert.last_renewal_error = error[:2000]
                cert.renewal_failures = (cert.renewal_failures or 0) + 1
                session.commit()


# ==============================================================================
# Making certbot errors readable
# ==============================================================================

def _explain_certbot_error(output: str) -> str:
    """
    Turn certbot's output into something you can act on.

    certbot's errors are accurate and almost useless if you have not seen them
    before.  These are the ones that actually come up, with what to do about
    them.
    """
    text = (output or "").lower()

    if "too many certificates" in text or "rate limit" in text:
        return (
            "Lets Encrypt rate limited you.  There is a cap of 5 certificates per "
            "week for the same set of domains.  Wait it out, and use the staging "
            "setting while you are testing so this does not happen again.\n\n"
            + output[-1500:]
        )

    if "timeout during connect" in text or "connection refused" in text:
        return (
            "Lets Encrypt could not reach your server on port 80.  Check that port "
            "80 is open from the internet, that DNS points at one of your nodes, "
            "and that nothing in front is blocking /.well-known/acme-challenge/.\n\n"
            "Note that port 80 has to stay open even for an https only site, "
            "because that is where the challenge happens.\n\n"
            + output[-1500:]
        )

    if "nxdomain" in text or "dns problem" in text:
        return (
            "DNS lookup failed for that domain.  Check the record exists and has "
            "had time to spread.  A record added in the last few minutes may not "
            "be visible to Lets Encrypt yet.\n\n"
            + output[-1500:]
        )

    if "unauthorized" in text and "challenge" in text:
        # Dig the address the CA actually connected to out of the output.  It
        # is the single most useful thing in there and it is buried in a wall
        # of text, so pull it to the front.
        import re as _re

        hit_ip = None
        m = _re.search(r"Detail:\s*([0-9a-fA-F:.]+):\s*Invalid response", output or "")
        if m:
            hit_ip = m.group(1)

        # If the hook reported success, the token really was written.  That
        # changes the diagnosis completely: this is not a distribution problem,
        # it is a reachability one, and saying so saves somebody an hour of
        # looking at the wrong half.
        hook_worked = '"ok":true' in (output or "") or '"ok": true' in (output or "")

        # The hook printing an error instead of ok means the token was never
        # written anywhere, and every other explanation below is a red herring.
        # The CA's 404 is then just the symptom.  Worth catching, because
        # sending somebody to look at port 80 when their hook is broken wastes
        # a lot of time.
        hook_error = None
        m_hook = _re.search(
            r"Hook '--manual-auth-hook'[^\n]*ran with output:\s*(.+)", output or ""
        )
        if m_hook and not hook_worked:
            hook_error = m_hook.group(1).strip()[:200]

        lines = []
        if hook_error:
            lines.append(
                "The hook that publishes the challenge token failed, so the file "
                "was never written and there was nothing for the certificate "
                "authority to fetch.  Fix this first, the 404 below is only the "
                "symptom."
            )
            lines.append(f"\nThe hook said:  {hook_error}")

            if "not found" in hook_error.lower():
                lines.append(
                    "\n\"not found\" from the hook means the manager refused the "
                    "call rather than the URL being wrong.  The hook runs on the "
                    "host and posts to 127.0.0.1, and the manager only accepts "
                    "that from a loopback address.  Check the manager log for "
                    "\"acme hook called from\", which names the address it saw:\n"
                    "\n"
                    "  docker compose logs | grep 'acme hook'"
                )
            elif "connection" in hook_error.lower() or "refused" in hook_error.lower():
                lines.append(
                    "\nThe hook could not reach the manager at all.  Check the "
                    "container is running and listening on the GUI port."
                )
            return "\n".join(lines)

        if hook_worked:
            lines.append(
                "The challenge token was written to every node, the hook says so, "
                "so the cluster side worked.  What failed is the certificate "
                "authority reaching it."
            )
        else:
            lines.append("The challenge file was not served correctly.")

        if hit_ip:
            lines.append(
                f"\nThe certificate authority connected to {hit_ip} and got a 404.  "
                f"So something is answering port 80 for this domain, but it is not "
                f"the nginx this manager is driving."
            )

        lines.append(
            "\nThe usual causes, in the order worth checking:\n"
            "\n"
            "  Something else owns port 80 on that address.  Another nginx, a "
            "cloud load balancer, a CDN.  The manager can only answer on the "
            "boxes it runs on.\n"
            "\n"
            "  The domain points somewhere other than these nodes.  Check the "
            "certificate's placement, which shows what DNS says next to what "
            "each node reports its own address to be.\n"
            "\n"
            "  The http site is redirecting /.well-known/acme-challenge/ to "
            "https.  The generated config never does this, but a hand written "
            "server block in front might.\n"
            "\n"
            "If the domain genuinely points at something else and always will, "
            "use a dns-01 challenge instead.  It needs no inbound connection at "
            "all, and it is the only way to get a wildcard."
        )

        return "\n".join(lines) + "\n\n" + output[-1200:]

    if "account" in text and "not found" in text:
        return (
            "The certificate authority does not recognise the account this node "
            "registered with.\n\n"
            "certbot keeps its account details in /etc/letsencrypt/accounts, and "
            "the authority has to have a matching record.  They can fall out of "
            "step when the account was deactivated at their end, or when the box "
            "was restored from a backup taken before it registered, or when you "
            "are pointed at a test server that has been restarted.\n\n"
            "The fix is to let it register again:\n"
            "  rm -rf /etc/letsencrypt/accounts/<the server>\n\n"
            "Nothing else is lost by doing that.  Existing certificates keep "
            "working, it only affects how the next renewal authenticates.\n\n"
            + output[-1000:]
        )

    if "invalid contact" in text or "invalid email" in text:
        return "Lets Encrypt did not accept the contact email.  Check it in Settings."

    return output[-2000:] if output else "certbot failed and said nothing useful"


_manager = None


def get_cert_manager() -> CertificateManager:
    global _manager
    if _manager is None:
        _manager = CertificateManager()
    return _manager


async def _reload_for_new_cert(name: str):
    """
    Make nginx pick up a certificate that just landed on this node.

    nginx reads certificate files once, when it loads, and holds them in memory.
    New bytes on disk change nothing until it is told to look again.

    Without this a renewal is invisible.  The files are replaced 30 days before
    expiry, every page in the GUI says the certificate is current, and nginx
    goes on serving the old one until something unrelated reloads it.  If
    nothing does, it serves an expired certificate with a valid one sitting
    right there on disk, which is a miserable thing to debug at the point it
    starts costing you visitors.

    A reload that fails is logged and swallowed.  The copy did work, the files
    are correct, and throwing here would report a replication failure for
    something that replicated fine.  The usual reason is that nginx is already
    unhappy about unrelated config, and that is its own alarm.
    """
    try:
        await get_agent().reload()
        log.info("reloaded nginx so it picks up the new %s certificate", name)
    except Exception as exc:
        log.error(
            "copied %s but could not reload nginx, so it is still serving the old "
            "certificate on this node: %s", name, exc,
        )


async def test_authority_credentials(authority) -> dict:
    """
    Prove an authority's credentials work, without issuing anything.

    Registers an account against the directory with the external account
    binding it was given, and throws the account away.  No certificate is asked
    for, so nothing is spent and no rate limit is touched that matters.

    This exists because these credentials fail in a particular way.  A key id
    with a character missing is accepted by every box on the screen and refused
    by the authority at registration, and registration happens at issue time.
    For a renewal that is months later, unattended, at whatever hour the timer
    runs.  Somebody finds out when a browser complains.
    """
    from app.core.agent_client import get_agent
    from app.core.crypto import decrypt

    if not authority.directory_url:
        return {"ok": False, "error": "this authority has no directory address"}

    hmac_key = ""
    if authority.eab_hmac_key_encrypted:
        hmac_key = decrypt(authority.eab_hmac_key_encrypted) or ""

    if bool(authority.eab_kid) != bool(hmac_key):
        return {"ok": False,
                "error": ("external account binding needs both the key id and "
                          "the key.  One without the other is refused at "
                          "registration.")}

    try:
        result = await get_agent().call(
            "acme_register_test", timeout=120,
            acme_server=authority.directory_url,
            eab_kid=authority.eab_kid or None,
            eab_hmac_key=hmac_key or None,
        )
    except Exception as exc:
        return {"ok": False, "error": str(exc)[:2000]}

    data = result.get("data") if isinstance(result, dict) else None
    if isinstance(data, dict):
        return {"ok": bool(data.get("ok")), "error": data.get("error")}
    return {"ok": bool(result.get("ok")), "error": result.get("error")}
