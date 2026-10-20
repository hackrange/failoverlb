"""
Certificate issuance and distribution across the cluster.

An http-01 challenge is answered by whatever address the domain points at,
and in a cluster only one node sits behind that address at a time, which
failover moves. Run certbot on the wrong node and the challenge fails with
an error that looks like a DNS problem.

So the issuing node is picked fresh every time by matching DNS against each
node's addresses, and the challenge token is pushed to every node before the
CA is told to look, so it doesn't matter which one it reaches. Issued
certificates are then copied to every node, since they all serve them.
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

# Default resolvers when none are configured (see dns_resolvers in
# settings). Public on purpose: an internal resolver often has a split
# horizon answer, and what matters is what the CA will see.
DEFAULT_RESOLVERS = ["1.1.1.1", "8.8.8.8", "9.9.9.9"]


def configured_resolvers() -> list:
    """DNS servers to ask; the public defaults if none are set."""
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
    Look a domain up the way the CA will. Several resolvers are queried and
    the answers merged, since during a DNS change they legitimately disagree
    and the union covers every node any of them points at.
    """
    found_v4 = set()
    found_v6 = set()
    errors = []

    resolvers = list(configured_resolvers())

    # Optionally include the system resolver, for split horizon networks.
    # Harmless elsewhere since the answers are merged.
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
    Decide which node should request this certificate, in order:

      1. A node whose public address is one the domain resolves to.
      2. A node holding that address on an interface (a floating VIP whose
         outbound traffic leaves some other way).
      3. The active node, with a warning. A clear error beats doing nothing.
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

        # Best case: a node's public address matches.
        for node in online:
            if node.public_ip and node.public_ip in wanted:
                return {
                    "node": node.name,
                    "reason": "public_ip_match",
                    "confidence": "high",
                    "matched_ip": node.public_ip,
                    "dns": dns_result,
                }

        # Floating VIP: the address is on an interface even though outbound
        # traffic makes the public address look different.
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

        # No match. Usually a cloud load balancer or CDN in front, which an
        # http-01 challenge can never get through.
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
    Puts the challenge token on every node, not just the one running
    certbot. The CA picks the address it connects to, and round robin DNS,
    a recently moved address or a stale cache can send it to any node.
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
                # Not fatal; only the node the CA actually reaches needs it.
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
                # A leftover token file is harmless: a random name in a
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
        Issue or renew a certificate from whichever node can do it right
        now, never assuming the previous issuer still can.
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

            # Use the authority recorded on the certificate, so a renewal
            # goes back to whoever issued it rather than silently switching
            # issuers.
            #
            # Read it here, inside the session. Touching cert.authority after
            # the session closes is a lazy load on a detached row and raises
            # DetachedInstanceError.
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

        # From Settings, falling back to the environment. Blank is allowed;
        # see settings_store.acme_email.
        from app.core import settings_store

        email = settings_store.acme_email()
        staging = settings_store.get("acme_staging", self.settings.acme_staging)

        # ---- pick the node ---------------------------------------------------
        if challenge_type == "dns-01":
            # dns-01 needs no inbound connection, so any node works. Use the
            # active one.
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
            # Let's Encrypt: the default, and needs no credentials.
            directory = (settings_store.get("acme_directory_url") or "").strip()
            eab_kid = ""
            eab_hmac = ""
            preferred_chain = ""

        request = {
            "domains": domains,
            # Our own name, so certbot files it where we'll look for it.
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
            # The hooks push the token to every node before certbot tells the
            # CA to look. Written every time, since a rebuilt node won't have
            # them and the resulting certbot error is unhelpful.
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

        # certbot exits 0 when it decides the certificate is not due and keeps
        # the old one.  Counting that as a renewal recorded a success, copied
        # the old files around and reloaded nginx, hiding that nothing changed.
        if "not yet due for renewal" in result.get("output", "").lower():
            log.info("certbot on %s says %s is not yet due for renewal; nothing changed",
                     issuing_node, cert_name)
            return {
                "ok": True,
                "renewed": False,
                "issued_by": issuing_node,
                "selection": selection,
                "message": f"{issuing_node} says this certificate is not yet due for "
                           f"renewal, so the existing one was kept.",
            }

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
            "renewed": True,
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

        # Long timeout: the CA plus dns-01 propagation can take minutes.
        return await client.call("/peer/acme/issue", request, timeout=600)

    # -------------------------------------------------------------------------

    async def replicate(self, cert_id: int) -> dict:
        """
        Copy a certificate to every node, since only one could obtain it.

        The private key crosses the wire here. That's acceptable: the channel
        is mutual TLS between nodes with certificates from the cluster CA,
        and the key lands 0600 root on the far side.
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

        # Fetch the files from whichever node holds them.
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

        # Import into this node's synced folder too, even if certbot ran
        # here. The rendered config points at the synced folder on every
        # node, not at certbot's copy.
        try:
            await get_agent().cert_import(name=name, bundle=bundle)
            await _reload_for_new_cert(name)
            results["ok"].append(self.settings.node_name)
        except AgentError as exc:
            results["failed"].append({"node": self.settings.node_name, "error": str(exc)})

        # Push to every peer, including the one the files came from; its
        # certbot copy isn't the path the config reads.
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
        """Read the dates and names back from the actual certificate."""
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
                # Empty when the CA publishes no OCSP responder, which is
                # now common.
                cert.ocsp_url = (info.get("ocsp_url") or "")[:255] or None
                if info.get("domains"):
                    cert.domains = json.dumps(info["domains"])
                session.commit()

        return info

    # -------------------------------------------------------------------------

    async def place_material(self, cert_id: int) -> dict:
        """
        Write a certificate whose material we store (uploaded, self signed
        or completed CSR) to every node.

        Unlike Let's Encrypt certificates, which live in certbot's folder on
        the issuing node, these can be rebuilt on any node from the
        database, so no source node is needed.
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
            # The key is encrypted with this node's secret. Failure means
            # NFM_SECRET_KEY changed; don't write a cert without its key.
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

        # Record which nodes got it, like issue() does. The page's "copied
        # to" count reads this, and without it the cert shows 0 of N forever.
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
        Check that certificates we think exist are actually on disk.

        The database and filesystem drift: restores from older backups,
        rebuilt boxes, someone clearing /etc/letsencrypt. A missing file
        stops nginx from loading, which blocks every apply. Missing ones are
        marked so the renderer drops their https block and the rest of the
        config still applies.
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

            # Check the path the config names: the synced folder on every
            # node, not certbot's folder on the issuer.
            path = f"{CERT_SYNC_DIR}/{name}/fullchain.pem"

            present = True
            try:
                await agent.read_file(path)
            except AgentError as exc:
                # Only a missing file counts. An unreachable agent says
                # nothing about the file, and treating it as missing would
                # drop https everywhere on an agent restart.
                if getattr(exc, "code", "") in ("not_found", "denied"):
                    present = False
                else:
                    continue

            # If we hold the material, write it back. Typical for a promoted
            # standby: the row came with the snapshot and only the file is
            # missing, so there's no reason to serve plain http meanwhile.
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

        If a record is moved away, renewal will fail when it comes due, long
        after anyone remembers the change. Warn while there's time.

        A resolver that doesn't answer is not a mismatch; we don't flag
        certificates just because DNS timed out.
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

            # Resolve once and use both halves, so the warning can't flicker
            # between two different answers.
            for domain in domains or [name]:
                result = await resolve_domain(domain)
                if not result["resolved"]:
                    failed.append(domain)
                    continue
                for address in result["all"]:
                    (owned if address in ours else unowned).append(address)

            if not owned and not unowned:
                # Every lookup failed. Don't cry wolf.
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
        Renew anything close to expiry.

        Replaces the stock certbot timer, which runs on every box and fails
        on every node that doesn't own the public address. Here the issuing
        node is chosen fresh each time. install.sh disables certbot.timer
        for this reason.
        """
        with session_scope() as session:
            if not self.cluster.is_active(session):
                # Only the active node renews, or nodes race each other into
                # the rate limits.
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
            # Space them out. Hitting rate limits can get you blocked for a
            # week.
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
    Turn certbot's output into something actionable, covering the errors
    that actually come up.
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
        # Pull out the address the CA actually connected to; it's the most
        # useful detail and it's buried in the output.
        import re as _re

        hit_ip = None
        m = _re.search(r"Detail:\s*([0-9a-fA-F:.]+):\s*Invalid response", output or "")
        if m:
            hit_ip = m.group(1)

        # If the hook reported success the token was written, so this is a
        # reachability problem, not a distribution one.
        hook_worked = '"ok":true' in (output or "") or '"ok": true' in (output or "")

        # A hook error means the token was never written and the CA's 404 is
        # just the symptom. Catch this first so nobody goes chasing port 80.
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
    Reload nginx so it picks up a certificate that just landed.

    nginx reads certificate files at load time. Without a reload a renewal
    is invisible: the GUI shows the new certificate while nginx keeps
    serving the old one until it expires.

    Failures are logged, not raised. The files were copied correctly, and a
    failing reload usually means nginx is unhappy about something else.
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
    Check an authority's credentials by registering a throwaway account with
    the given external account binding. No certificate is requested.

    A mistyped EAB key id is otherwise only rejected at registration, which
    for a renewal happens months later, unattended.
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
