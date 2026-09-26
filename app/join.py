"""
Joining an existing cluster.

Run this on a new box after the container is up:

    docker exec nfm-gui python -m app.join <sponsor-address>:<port> <token>

What happens, in order:

  1. We make a key pair here and a signing request.  The key never leaves.
  2. The request goes to the sponsor along with the join token.
  3. The sponsor checks the token, signs the request, and sends back our
     certificate, the cluster CA, and a shared key for signing messages.
  4. We save all that, then ask the sponsor for the rest of the roster so we
     know about every other node, not just the one we joined through.

The token is the only thing standing between somebody and a cluster
certificate, which is why it is single use and short lived.

This talks to the sponsor over TLS but cannot check its certificate yet, since
we do not have the CA at that point.  That is unavoidable in any join flow and
it is why the token matters.  We pin what we got afterwards, so this one moment
is the only window.
"""

import asyncio
import json
import logging
import ssl
import sys

import httpx

from app.config import get_settings
from app.core.crypto import ClusterCA, encrypt
from app.db import init_db, session_scope
from app.models import Node, NodeRole, NodeState, utcnow

log = logging.getLogger("nfm.join")


class JoinError(Exception):
    pass


async def join_cluster(sponsor: str, token: str) -> dict:
    settings = get_settings()

    if ":" in sponsor:
        host, _, port = sponsor.rpartition(":")
        port = int(port)
    else:
        host, port = sponsor, settings.peer_port

    ca = ClusterCA()

    # A node makes itself a CA the first time it starts, before anybody has had
    # a chance to join it anywhere.  So "do you have a CA" is the wrong question
    # to ask here, and asking it would mean you could never join a node that had
    # ever been switched on.
    #
    # The real question is whether this node is already somebody's cluster: does
    # it have peers, or config anybody is relying on.  If not, the CA it made
    # for itself is worth nothing and we can throw it away.
    if ca.exists() and ca.ca_key_path.is_file():
        init_db()
        with session_scope() as session:
            peer_count = session.query(Node).filter(
                Node.name != settings.node_name
            ).count()
            from app.models import ConfigVersion

            version_count = session.query(ConfigVersion).count()

        if peer_count > 0 or version_count > 0:
            raise JoinError(
                f"this node is already running a cluster of its own: "
                f"{peer_count} peer(s) and {version_count} config version(s).  "
                f"Joining would throw that away.  If you really mean to, clear "
                f"out its data volume first."
            )

        log.info("discarding the CA this node made for itself, it has never been used")
        ca.ca_key_path.unlink(missing_ok=True)
        ca.ca_cert_path.unlink(missing_ok=True)
        ca.node_cert_path.unlink(missing_ok=True)
        ca.node_key_path.unlink(missing_ok=True)

    log.info("making a key pair and a signing request for %s", settings.node_name)
    _, csr = ca.create_node_csr(settings.node_name, [settings.node_address])

    payload = {
        "token": token,
        "node_name": settings.node_name,
        "address": settings.node_address,
        "csr": csr,
        "priority": settings.cluster_priority,
        "peer_port": settings.peer_port,
        "gui_port": settings.gui_port,
    }

    # We cannot verify the sponsor yet, because the whole point of this call is
    # to get the CA that would let us.  Every join protocol has this moment.
    # The token is what makes it safe enough: it is single use, it expires in a
    # couple of hours, and it only ever goes to an address you typed yourself.
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    url = f"https://{host}:{port}/peer/join"
    log.info("asking %s to let us in", url)

    try:
        async with httpx.AsyncClient(verify=context, timeout=30) as client:
            response = await client.post(url, json=payload)
    except httpx.HTTPError as exc:
        raise JoinError(
            f"could not reach {host}:{port}.  Check the address, that the "
            f"manager is running there, and that the firewall lets this box "
            f"through on that port.  ({exc})"
        )

    if response.status_code == 401:
        raise JoinError(
            "that join token was refused.  They are single use and they expire "
            "after two hours, so make a fresh one on the cluster page."
        )
    if response.status_code >= 400:
        raise JoinError(f"the sponsor said no: {response.status_code} {response.text[:300]}")

    result = response.json()

    for field in ("certificate", "ca_certificate", "hmac_key"):
        if not result.get(field):
            raise JoinError(f"the answer was missing {field}, so we cannot join")

    log.info("got a signed certificate, saving it")
    ca.import_ca_cert(result["ca_certificate"])
    ca.save_node_cert(result["certificate"])

    # Save the roster.  The sponsor's own entry carries the shared key we use to
    # sign messages to it.
    cluster = result.get("cluster", {})
    sponsor_name = cluster.get("sponsor")

    init_db()
    with session_scope() as session:
        for entry in cluster.get("peers", []):
            name = entry.get("name")
            if not name or name == settings.node_name:
                continue

            node = session.query(Node).filter(Node.name == name).first()
            if not node:
                node = Node(name=name)
                session.add(node)

            node.address = entry.get("address", "")
            node.peer_port = entry.get("peer_port", 7444)
            node.gui_port = entry.get("gui_port", 7443)
            node.priority = entry.get("priority", 100)
            node.state = NodeState.OFFLINE
            node.role = NodeRole.STANDBY
            node.is_self = False

            # Only the sponsor's key comes back on a join.  For the others we
            # learn the key when they talk to us, or on the next roster swap.
            if entry.get("hmac_key"):
                node.hmac_key_encrypted = encrypt(entry["hmac_key"])

        # The key the sponsor gave us is the one we use to talk to the sponsor.
        if sponsor_name:
            sponsor_node = session.query(Node).filter(Node.name == sponsor_name).first()
            if sponsor_node:
                sponsor_node.hmac_key_encrypted = encrypt(result["hmac_key"])

        me = session.query(Node).filter(Node.name == settings.node_name).first()
        if not me:
            me = Node(name=settings.node_name, is_self=True)
            session.add(me)
        me.address = settings.node_address
        me.peer_port = settings.peer_port
        me.gui_port = settings.gui_port
        me.priority = settings.cluster_priority
        me.is_self = True
        me.state = NodeState.ONLINE
        # A node that just joined is a standby.  It has no config yet, so making
        # it active would mean the cluster's newest and emptiest member is the
        # one taking changes.
        me.role = NodeRole.STANDBY
        me.cert_fingerprint = ca.node_fingerprint()
        me.joined_at = utcnow()

        session.commit()

    log.info("joined the cluster that %s is in", sponsor_name)
    return {
        "ok": True,
        "sponsor": sponsor_name,
        "peers": [p.get("name") for p in cluster.get("peers", [])],
    }


def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s %(levelname)-7s [%(name)s] %(message)s",
        stream=sys.stdout,
    )

    if len(sys.argv) < 3:
        print("usage: python -m app.join <sponsor-address>[:port] <join-token>")
        print()
        print("Make a token on the cluster page of a node that is already up.")
        sys.exit(1)

    try:
        result = asyncio.run(join_cluster(sys.argv[1], sys.argv[2]))
    except JoinError as exc:
        print(f"\njoin failed: {exc}\n")
        sys.exit(1)

    print()
    print(f"joined through {result['sponsor']}")
    print("Restart this container so it starts its peer listener and syncs up.")
    print()


if __name__ == "__main__":
    main()
