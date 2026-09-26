"""
Exporting the whole configuration from this fleet and restoring it on
another.

Unlike a snapshot, which moves between nodes that share a secret key over
mutual TLS, a backup must survive a laptop, an email and a year in a drawer,
then rebuild an unrelated fleet.  So secrets are decrypted on export and
re-encrypted with the new fleet's key on restore, and the archive itself is
encrypted since it holds private keys.

Encryption is AES-256 via pyzipper.  ZipCrypto is broken, and a zip of PEM
files offers plenty of known plaintext.  Tools too old for AES refuse the
file rather than misread it.

The password is the operator's login password.  Zip AES uses PBKDF2 with
only 1000 iterations, so the archive is only as strong as that password
against an offline attacker, and it can't be rotated separately.  Store the
file somewhere trusted or wrap it in proper encryption.

Machine identity (node names, cluster membership, join tokens, this node's
identity) is left out: it belongs to the hardware, and carrying it over
would confuse the new fleet about who it is.
"""
import io
import json
import logging
from datetime import timezone

import pyzipper

from app.core import snapshot
from app.core.crypto import decrypt, encrypt
from app.models import SystemSetting, utcnow

log = logging.getLogger("nfm.backup")

# Bump on incompatible changes.  Readers refuse unknown versions.
FORMAT_VERSION = 1

MANIFEST = "backup.json"
CERT_DIR = "certificates"
README = "README.txt"

# Per-box settings, never exported.
SETTINGS_SKIP_PREFIXES = ("totp_pending",)

# Exported but not restored.  management_networks limits where the GUI can
# be reached from; restoring the old list could lock you out of the fleet you
# are rebuilding.
SETTINGS_SKIP_KEYS = {"management_networks"}

READ_ME = """\
This is a configuration backup from Failover LB.

It is encrypted with AES-256 and the password is the login password of whoever
took it.  Any current zip tool will open it with that password.

It contains private keys.  Treat it the way you would treat the keys
themselves: it is enough on its own to serve every site this fleet serves.

Restore it from the GUI, under Backup, on the fleet you want it on.  Restoring
replaces the configuration that is there.
"""


# =============================================================================
# Taking one
# =============================================================================

def _capture_settings(session) -> list:
    """
    Settings from the database, with encrypted values decrypted (the key
    belongs to this fleet).  Values that won't decrypt are left out rather
    than exported as unreadable bytes.
    """
    out = []
    for row in session.query(SystemSetting).all():
        if any(row.key.startswith(p) for p in SETTINGS_SKIP_PREFIXES):
            continue

        value = row.value
        if row.encrypted and value:
            value = decrypt(value)
            if value is None:
                log.warning("could not read the setting %s, leaving it out", row.key)
                continue

        out.append({"key": row.key, "value": value, "encrypted": bool(row.encrypted)})
    return out


async def _capture_cert_files(session) -> dict:
    """
    Certificate files that are not in the database.

    Uploaded and self signed certs are already in the tables.  Let's Encrypt
    certs live in certbot's folder on the issuing node, and a new fleet can't
    reissue until it serves those names, which it can't do without a cert.
    So they are read from disk.  Unreadable ones are reported, not skipped
    silently.
    """
    from app.core.agent_client import get_agent
    from app.models import Certificate

    bundles, missing = {}, []
    with_material = session.query(Certificate).all()

    for cert in with_material:
        if cert.has_material():
            continue          # already in the tables, in full

        try:
            answer = await get_agent().cert_export(name=cert.name)
            bundle = (answer.get("data") or answer).get("bundle") or answer
            if isinstance(bundle, dict) and bundle.get("fullchain.pem"):
                bundles[cert.name] = bundle
            else:
                missing.append(cert.name)
        except Exception as exc:
            log.info("no files on this node for %s: %s", cert.name, exc)
            missing.append(cert.name)

    return {"bundles": bundles, "missing": missing}


async def build(session, password: str, node_name: str = "") -> tuple:
    """
    The whole configuration as one encrypted archive.  Returns the bytes
    and a summary of what went in.
    """
    if not password:
        raise ValueError("a backup needs a password")

    data = snapshot.capture(session)
    data["format"] = FORMAT_VERSION
    data["settings"] = _capture_settings(session)
    data["taken_at"] = utcnow().replace(tzinfo=timezone.utc).isoformat()
    data["taken_from"] = node_name

    # Old node names and addresses, for reference only (not restored as
    # cluster identity).
    from app.models import Node
    data["nodes_seen"] = [
        {"name": n.name, "address": n.address, "public_ip": n.public_ip}
        for n in session.query(Node).all()
    ]

    certs = await _capture_cert_files(session)
    data["certificates_without_files"] = certs["missing"]

    counts = {name: len(rows) for name, rows in data["tables"].items() if rows}
    counts["users"] = len(data.get("users") or [])
    counts["settings"] = len(data["settings"])
    counts["certificate files"] = len(certs["bundles"])

    buf = io.BytesIO()
    with pyzipper.AESZipFile(buf, "w", compression=pyzipper.ZIP_DEFLATED,
                             encryption=pyzipper.WZ_AES) as zf:
        zf.setpassword(password.encode("utf-8"))
        zf.setencryption(pyzipper.WZ_AES, nbits=256)
        zf.writestr(README, READ_ME)
        zf.writestr(MANIFEST, json.dumps(data, indent=2, default=str))
        for name, bundle in certs["bundles"].items():
            for fname, text in bundle.items():
                zf.writestr(f"{CERT_DIR}/{name}/{fname}", text)

    return buf.getvalue(), {"counts": counts, "missing_files": certs["missing"]}


# =============================================================================
# Reading one
# =============================================================================

class BadArchive(Exception):
    """Not a backup, or not one this can read, or the wrong password."""


def read_archive(blob: bytes, password: str) -> dict:
    """
    Open an archive and return its contents.

    Distinguishes a wrong password from a corrupt file, which the zip layer
    reports the same way, so nobody throws away a good backup over a typo.
    """
    if not password:
        raise BadArchive("give the password this backup was made with")

    try:
        zf = pyzipper.AESZipFile(io.BytesIO(blob))
    except Exception as exc:
        raise BadArchive(f"this is not a zip file ({exc})")

    with zf:
        names = zf.namelist()
        if MANIFEST not in names:
            raise BadArchive(
                "this zip has no backup in it.  A backup from here always "
                f"contains {MANIFEST}.")

        zf.setpassword(password.encode("utf-8"))
        try:
            raw = zf.read(MANIFEST)
        except RuntimeError as exc:
            if "password" in str(exc).lower():
                raise BadArchive("that password does not open this backup")
            raise BadArchive(f"could not read this backup ({exc})")
        except Exception as exc:
            raise BadArchive(f"could not read this backup ({exc})")

        try:
            data = json.loads(raw)
        except ValueError:
            # With some files a wrong password yields garbage instead of an
            # error.
            raise BadArchive("that password does not open this backup")

        version = data.get("format")
        if version != FORMAT_VERSION:
            raise BadArchive(
                f"this backup is format {version}, and this system reads "
                f"format {FORMAT_VERSION}.  Restore it on a matching version.")

        # Rebuild the certificate bundles.
        bundles = {}
        for entry in names:
            if not entry.startswith(CERT_DIR + "/"):
                continue
            parts = entry.split("/")
            if len(parts) != 3:
                continue
            _, cert_name, fname = parts
            try:
                bundles.setdefault(cert_name, {})[fname] = \
                    zf.read(entry).decode("utf-8")
            except Exception as exc:
                raise BadArchive(f"could not read {entry} ({exc})")

        data["cert_bundles"] = bundles

    return data


# =============================================================================
# Putting one back
# =============================================================================

def _restore_settings(session, rows) -> int:
    """Restore settings, re-encrypting secrets with this fleet's key."""
    done, skipped = 0, []
    for row in rows or []:
        key = row.get("key")
        if not key or any(key.startswith(p) for p in SETTINGS_SKIP_PREFIXES):
            continue
        if key in SETTINGS_SKIP_KEYS:
            skipped.append(key)
            continue

        value = row.get("value")
        if row.get("encrypted") and value:
            value = encrypt(value)

        existing = session.query(SystemSetting).filter(
            SystemSetting.key == key).first()
        if existing is None:
            existing = SystemSetting(key=key)
            session.add(existing)
        existing.value = value
        existing.encrypted = bool(row.get("encrypted"))
        done += 1
    return {"restored": done, "left_alone": skipped}


def _family(value: str) -> int:
    import ipaddress
    try:
        return ipaddress.ip_address(str(value).strip()).version
    except ValueError:
        return 0        # a hostname, nothing to rewrite


def _node_addresses(node) -> dict:
    """This node's addresses, keyed by IP version."""
    import ipaddress
    found = {}
    for candidate in (node.public_ip, node.address):
        if not candidate:
            continue
        try:
            addr = ipaddress.ip_address(str(candidate).strip())
        except ValueError:
            continue
        found.setdefault(addr.version, str(addr))
    return found


def _retarget_gslb(session) -> dict:
    """
    Point GSLB answers at this fleet's machines.

    GSLB answers are literal addresses.  Restored unchanged onto a new fleet,
    they would send every visitor to the old boxes while everything looks
    healthy.

    Each answer names its node, so where a node of that name exists here the
    address is replaced with its address of the same family (A stays IPv4,
    AAAA stays IPv6).  Anything unmatched is left as is and reported rather
    than guessed.
    """
    from app.models import GslbAnswer, Node

    nodes = {n.name: _node_addresses(n) for n in session.query(Node).all()}
    changed, unmatched, kept = [], [], 0

    for answer in session.query(GslbAnswer).all():
        version = _family(answer.value)
        if not version:
            kept += 1                       # CNAME target, travels fine
            continue

        if not answer.node_name:
            kept += 1                       # not tied to a node
            continue

        addresses = nodes.get(answer.node_name)
        if not addresses:
            unmatched.append({"answer": answer.value, "node": answer.node_name,
                              "why": "no node of that name here"})
            continue

        replacement = addresses.get(version)
        if not replacement:
            unmatched.append({
                "answer": answer.value, "node": answer.node_name,
                "why": f"{answer.node_name} has no IPv{version} address here"})
            continue

        if replacement != answer.value:
            changed.append({"node": answer.node_name,
                            "was": answer.value, "now": replacement})
            answer.value = replacement
        else:
            kept += 1

    return {"changed": changed, "unmatched": unmatched, "unchanged": kept}


async def restore_all(data: dict, author: str = "restore") -> dict:
    """
    Restore a backup across the whole fleet.

    Restoring only the local node would leave the fleet split.  So this
    writes the database, sends settings and certificate files to every node,
    applies the rendered config through the normal path, and rebuilds the
    tunnel if it was enabled.  Every step reports its result.
    """
    from app.core.tunnel import apply_to_fleet
    from app.db import session_scope
    from app.models import Certificate, TunnelNetwork
    from app.web.routes_api import apply_current_config

    result = {"tables": {}, "users": {}, "settings": 0,
              "certificates": {"written": [], "failed": []},
              "applied": None, "tunnel": None}

    # 1. The configuration itself.
    with session_scope() as session:
        result["tables"] = snapshot.restore(session, data)
        result["users"] = snapshot.restore_users(session, data.get("users") or [])
        result["settings"] = _restore_settings(session, data.get("settings"))
        result["dns"] = _retarget_gslb(session)
        session.commit()

    # 1b. Settings to every other node.  They are node local, and a standby
    # without the ACME email or resolvers would look ready but behave
    # differently once promoted.
    result["settings_to_peers"] = {"ok": [], "failed": {}}
    try:
        from app.core.cluster import PeerClient, get_cluster
        cluster = get_cluster()
        with session_scope() as session:
            rows = _capture_settings(session)
            peers = [(p.name, PeerClient(p, cluster.ca)) for p in cluster.peers(session)]
        for node_name, client in peers:
            try:
                await client.call("/peer/settings", {"settings": rows})
                result["settings_to_peers"]["ok"].append(node_name)
            except Exception as exc:
                result["settings_to_peers"]["failed"][node_name] = str(exc)
    except Exception as exc:
        result["settings_to_peers"]["failed"]["*"] = str(exc)

    # 2. Certificate files not in the tables, onto this node first so they
    #    can be replicated.
    from app.core.agent_client import get_agent

    for name, bundle in (data.get("cert_bundles") or {}).items():
        try:
            await get_agent().cert_import(name=name, bundle=bundle)
            result["certificates"]["written"].append(name)
        except Exception as exc:
            result["certificates"]["failed"].append({"name": name, "error": str(exc)})

    # 3. Every certificate to every other node, via the normal replicate
    #    path.
    try:
        from app.core.acme import AcmeManager
        manager = AcmeManager()
        with session_scope() as session:
            cert_ids = [c.id for c in session.query(Certificate).all()]
        for cert_id in cert_ids:
            try:
                await manager.replicate(cert_id)
            except Exception as exc:
                log.info("could not copy certificate %s to the peers: %s",
                         cert_id, exc)
    except Exception as exc:
        log.warning("could not copy certificates to the peers: %s", exc)

    # 4. Rendered config to the whole fleet, through the normal apply.
    try:
        result["applied"] = await apply_current_config(
            author=author, summary="restored from a backup")
    except Exception as exc:
        result["applied"] = {"ok": False, "error": str(exc)}

    # 5. The tunnel, if the backup had it enabled.
    try:
        with session_scope() as session:
            network = session.query(TunnelNetwork).first()
            wanted = bool(network and network.enabled)
        if wanted:
            result["tunnel"] = await apply_to_fleet()
    except Exception as exc:
        result["tunnel"] = {"ok": False, "error": str(exc)}

    return result
