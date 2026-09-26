"""
Taking the whole configuration off this fleet, and putting it on another one.

Not the same job as a snapshot.  A snapshot travels between nodes that already
trust each other, over mutual TLS, and lands on a box that holds the same
secret key.  This has to survive somebody's laptop, an email, and a year in a
drawer, and then rebuild a fleet that has nothing in common with this one.

So two things are different.  Secrets are unsealed on the way out and sealed
again with the new fleet's key on the way in, because the key that protects
them here does not exist there.  And the archive is encrypted, because in
between those two moments it is a file full of private keys.

On the encryption
-----------------
AES-256, through pyzipper.  The zip format's own scheme, ZipCrypto, is broken:
a few known plaintext bytes recover the stream, and a zip full of PEM files
hands an attacker more known plaintext than they need.  Anything that opens a
modern zip opens this, and anything too old to know AES will say so rather than
open it wrongly.

The password is the operator's own login password, which is the part worth
being honest about.  Zip AES derives its key with PBKDF2 at 1000 iterations,
which is not much, so the archive is exactly as strong as that password is
against somebody who has the file and time to spend.  It is not a passphrase
chosen for this job and it cannot be rotated without changing the login.  For
an archive that will sit somewhere untrusted, put it in something that does its
own key derivation properly, and treat this file as the sensitive thing it is.

What is in it
-------------
Everything the fleet is configured to do, and nothing about the box it came
from.  Node names, cluster membership, join tokens and this node's identity are
all left behind on purpose: they belong to the machines, not the configuration,
and carrying them across would leave the new fleet arguing with itself about
who it is.
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

# Bumped when the shape changes in a way an older reader would get wrong.  A
# reader that meets a number it does not know refuses rather than guessing.
FORMAT_VERSION = 1

MANIFEST = "backup.json"
CERT_DIR = "certificates"
README = "README.txt"

# Settings that describe this box rather than the configuration.  A restore
# somewhere else should keep its own.
SETTINGS_SKIP_PREFIXES = ("totp_pending",)

# Left where they are on a restore, because they describe the machines rather
# than the configuration.
#
# management_networks is the one that matters.  It is the list of places the
# GUI may be reached from, and the new fleet is being administered from
# wherever somebody is standing right now, which is not necessarily anywhere on
# the old fleet's list.  Restoring it is a decent way to lock yourself out of
# the system you are in the middle of rebuilding, from inside the operation
# that was meant to save you.
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


# ==============================================================================
# Taking one
# ==============================================================================

def _capture_settings(session) -> list:
    """
    The settings kept in the database.

    Encrypted values are unsealed here, for the same reason the other secrets
    are: the key that reads them belongs to this fleet.  A value that will not
    decrypt is left out rather than carried across as bytes the far end will
    store and never be able to read.
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
    The certificate material that is not in the database.

    Anything uploaded or self signed is already in the tables, keys included,
    so it travels with them.  A Lets Encrypt certificate is not: it lives in
    certbot's folder on whichever node issued it, and a restore somewhere else
    would have nothing to serve until it managed to issue again.  Issuing again
    needs the new fleet to already be answering for those names, which is
    exactly the thing it cannot do without a certificate.

    So they are read off disk and carried too.  A certificate that cannot be
    read is reported rather than skipped in silence: finding out at restore
    time that a site has no certificate is worse than being told now.
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
    The whole configuration, as one encrypted archive.

    Returns the bytes and a short summary of what went in, so the page can say
    what was taken rather than only that something was.
    """
    if not password:
        raise ValueError("a backup needs a password")

    data = snapshot.capture(session)
    data["format"] = FORMAT_VERSION
    data["settings"] = _capture_settings(session)
    data["taken_at"] = utcnow().replace(tzinfo=timezone.utc).isoformat()
    data["taken_from"] = node_name

    # What the nodes were, and what addresses they answered on.  Not restored
    # as cluster identity, which belongs to the machines.  It is here so a
    # restore can say what the old addresses were when it rewrites them, and
    # so somebody reading the archive later can tell where it came from.
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


# ==============================================================================
# Reading one
# ==============================================================================

class BadArchive(Exception):
    """Not a backup, or not one this can read, or the wrong password."""


def read_archive(blob: bytes, password: str) -> dict:
    """
    Open an archive and hand back what is in it.

    A wrong password and a corrupt file both come out of the zip layer as the
    same unhelpful error, so they are separated here.  Telling somebody the
    file is damaged when they simply mistyped is the kind of thing that gets a
    good backup thrown away.
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
            # The zip layer will happily hand back rubbish for a wrong password
            # on some files rather than raising, so this is the same mistake
            # arriving by a different route.
            raise BadArchive("that password does not open this backup")

        version = data.get("format")
        if version != FORMAT_VERSION:
            raise BadArchive(
                f"this backup is format {version}, and this system reads "
                f"format {FORMAT_VERSION}.  Restore it on a matching version.")

        # The certificate files, back into the shape they went in as.
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


# ==============================================================================
# Putting one back
# ==============================================================================

def _restore_settings(session, rows) -> int:
    """Settings back in, sealed again with this fleet's key."""
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
        return 0        # a name, not an address, so nothing to rewrite


def _node_addresses(node) -> dict:
    """Every address this node is known by, sorted into families."""
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
    Point the DNS answers at the machines that are actually here.

    This is the one part of a backup that is about hardware rather than
    configuration, and it is the part that does real damage if it is carried
    across unchanged.  A gslb answer is a literal address, and its whole job is
    to be handed out to the internet.  Restore a backup onto a new fleet and
    those addresses still name the old boxes: the new load balancers come up,
    say they are healthy, and send every visitor to machines that are not
    theirs.  Everything looks right on both ends.

    An answer says which node it belongs to, by name, so where the new fleet
    has a node of that name the address is replaced with that node's own, of
    the same family.  An A record gets IPv4 and an AAAA gets IPv6, because
    swapping one for the other produces a record that is valid, wrong, and
    silent about it.

    Anything that cannot be matched is left exactly as it was and reported.
    Guessing at which new machine replaces which old one is not something to
    do quietly with a DNS record.
    """
    from app.models import GslbAnswer, Node

    nodes = {n.name: _node_addresses(n) for n in session.query(Node).all()}
    changed, unmatched, kept = [], [], 0

    for answer in session.query(GslbAnswer).all():
        version = _family(answer.value)
        if not version:
            kept += 1                       # a CNAME target, which travels fine
            continue

        if not answer.node_name:
            kept += 1                       # not ours to move, always handed out
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
    Put a backup back, everywhere.

    A restore that only landed on the node somebody happened to be logged into
    would leave the fleet split, which is the one state the whole two phase
    apply exists to prevent.  So this finishes the job: the configuration goes
    into the database, the certificate files go to every node, the rendered
    config is pushed to every node through the same path a normal save uses,
    and the tunnel is rebuilt if it was on.

    Nothing here is quiet about failing.  Every step reports, because a restore
    that half worked and said nothing is worse than one that refused.
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

    # 1b. The settings, out to every other node.
    #
    # These have always been node local, which is survivable while somebody
    # sets them on the box in front of them, and not survivable after a
    # restore: a standby with no acme email and no resolvers looks ready and
    # behaves differently the moment it is promoted.  A restore is supposed to
    # leave every node able to do the job.
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

    # 2. The certificate files that were not in the tables, onto this node
    #    first so there is something for the rest of the fleet to be given.
    from app.core.agent_client import get_agent

    for name, bundle in (data.get("cert_bundles") or {}).items():
        try:
            await get_agent().cert_import(name=name, bundle=bundle)
            result["certificates"]["written"].append(name)
        except Exception as exc:
            result["certificates"]["failed"].append({"name": name, "error": str(exc)})

    # 3. Every certificate out to every other node.  replicate is the path the
    #    rest of the system already uses for this, so a restored fleet ends up
    #    in the same state as one that issued the certificates itself.
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

    # 4. The rendered config, to the whole fleet, through the normal path.
    try:
        result["applied"] = await apply_current_config(
            author=author, summary="restored from a backup")
    except Exception as exc:
        result["applied"] = {"ok": False, "error": str(exc)}

    # 5. The tunnel, if the backup had one turned on.
    try:
        with session_scope() as session:
            network = session.query(TunnelNetwork).first()
            wanted = bool(network and network.enabled)
        if wanted:
            result["tunnel"] = await apply_to_fleet()
    except Exception as exc:
        result["tunnel"] = {"ok": False, "error": str(exc)}

    return result
