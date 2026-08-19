"""
Crypto helpers: secrets at rest, the cluster CA, and peer certificates.

Two separate jobs live in here.

First, encrypting things we have to store but must not store in the clear.  The
OIDC client secret, DNS provider tokens, TOTP seeds, peer HMAC keys.  If
somebody walks off with the database file, none of that should be readable.

Second, the cluster's own certificate authority.  Nodes prove who they are to
each other with certs this CA signs.  Nobody else's CA counts, including the
public ones, so a valid cert from a real CA on the internet gets you nowhere.
"""

import base64
import datetime
import hashlib
import hmac
import ipaddress
import logging
import os
import secrets
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from app.config import get_settings

log = logging.getLogger("nfm.crypto")

# How long a node cert is good for.  Long enough that renewals are not a chore,
# short enough that a cert stolen off a decommissioned box eventually dies.
NODE_CERT_DAYS = 825
CA_CERT_DAYS = 3650


# ==============================================================================
# Encrypting things we store
# ==============================================================================

def _aead():
    """
    Build the cipher from the node secret key.

    AES-GCM, so anybody tampering with the stored value makes decryption fail
    instead of quietly handing back different bytes.
    """
    settings = get_settings()
    key = hashlib.sha256(settings.secret_key.encode()).digest()
    return AESGCM(key)


def encrypt(plaintext: str) -> str:
    """
    Encrypt a string for storage.

    A fresh random nonce every time, tacked on the front.  Reusing a nonce with
    GCM is the one mistake that breaks it wide open, so we never derive one and
    never keep a counter.
    """
    if plaintext is None:
        return None
    if not isinstance(plaintext, str):
        plaintext = str(plaintext)

    nonce = os.urandom(12)
    blob = _aead().encrypt(nonce, plaintext.encode(), None)
    return base64.b64encode(nonce + blob).decode()


def decrypt(ciphertext: str) -> str:
    """
    Turn it back.  Returns None if it will not decrypt.

    Most likely reason for a failure is the secret key changed, which happens
    when somebody rebuilds a node and generates a new one.  We log it and hand
    back None so the caller can prompt for the value again, instead of throwing
    and taking the whole page down.
    """
    if not ciphertext:
        return None
    try:
        raw = base64.b64decode(ciphertext)
        nonce, blob = raw[:12], raw[12:]
        return _aead().decrypt(nonce, blob, None).decode()
    except Exception:
        log.warning("could not decrypt a stored secret, the node key probably changed")
        return None


def hash_token(token: str) -> str:
    """
    sha256 of a token, for storing in the database.

    Used for session tokens and join tokens.  These are long random strings, so
    a plain hash is fine.  Passwords are different and go through argon2, since
    people pick guessable ones and a fast hash lets you try billions of them.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """
    Compare without leaking how much matched through timing.

    A normal == bails at the first different byte, so how long it takes tells
    an attacker how much of their guess was right.  Do that in a loop and they
    can walk a token out one character at a time.
    """
    return hmac.compare_digest(a.encode(), b.encode())


def new_token(length: int = 32) -> str:
    """A random token, url safe so it can go in a header or a link."""
    return secrets.token_urlsafe(length)


# ==============================================================================
# Signing messages between nodes
# ==============================================================================

def sign_payload(hmac_key: str, node_name: str, timestamp: str,
                 nonce: str, body: bytes) -> str:
    """
    Sign a peer request.

    mTLS already proves the connection came from a node holding a cluster cert.
    This proves which node, and that this exact body is what they sent.  We put
    the timestamp and nonce inside the signed part, so replaying a captured
    request fails the freshness check instead of sailing through.
    """
    mac = hmac.new(hmac_key.encode(), digestmod=hashlib.sha256)
    mac.update(node_name.encode())
    mac.update(b"\x00")
    mac.update(timestamp.encode())
    mac.update(b"\x00")
    mac.update(nonce.encode())
    mac.update(b"\x00")
    mac.update(hashlib.sha256(body).digest())
    return base64.b64encode(mac.digest()).decode()


def verify_payload(hmac_key: str, node_name: str, timestamp: str,
                   nonce: str, body: bytes, signature: str) -> bool:
    expected = sign_payload(hmac_key, node_name, timestamp, nonce, body)
    return hmac.compare_digest(expected, signature)


# ==============================================================================
# The cluster CA
# ==============================================================================

class ClusterCA:
    """
    The certificate authority the fleet trusts.

    The first node makes it.  Every node that joins gets a cert signed by it.
    Peer connections require a cert from this CA and nothing else, so being a
    member of the cluster is the same thing as holding one of these.

    The CA key never leaves the node that made it.  Joining nodes send a signing
    request in and get a cert back, they never get the key itself.
    """

    def __init__(self, pki_dir: Path = None):
        settings = get_settings()
        self.dir = pki_dir or settings.pki_dir
        self.dir.mkdir(parents=True, exist_ok=True)
        os.chmod(self.dir, 0o700)

        self.ca_key_path = self.dir / "cluster-ca.key"
        self.ca_cert_path = self.dir / "cluster-ca.crt"
        self.node_key_path = self.dir / "node.key"
        self.node_cert_path = self.dir / "node.crt"

        # Where a key waits while we are asking somebody to sign it.
        #
        # Joining makes a new key and then asks the sponsor for a certificate.
        # That request can fail, and often does: a spent token, a firewall, a
        # sponsor that is not up yet.  If the new key has already replaced the
        # live one by then, this node is left with a key and a certificate that
        # do not match, the peer listener will not start, and it crash loops
        # with no way back.  A failed join has to leave the node exactly as it
        # was, so the new key sits here until a certificate for it turns up.
        self.node_key_pending_path = self.dir / "node.key.pending"

    # ---- the CA itself ------------------------------------------------------

    def exists(self) -> bool:
        """
        Can this node sign for the cluster: it holds the CA key as well as the
        certificate.

        True only on the node that founded the cluster.  A node that joined is
        given the CA **certificate**, so it can verify its peers, and never the
        CA key, because only one machine should be able to mint new members.

        That is why this is not the question "is this node part of a cluster".
        Asking this one and reporting the answer as cluster membership told
        every joined node in every fleet that it needed to rejoin, at every
        startup, while it was working perfectly.  Use has_identity for
        membership.
        """
        return self.ca_cert_path.is_file() and self.ca_key_path.is_file()

    def has_identity(self) -> bool:
        """
        Is this node a member of a cluster: it can prove who it is and check
        who its peers are.

        The CA certificate to verify peers, and its own certificate and key to
        answer them with.  A joined node has exactly these three and no CA key,
        which is the normal and correct state for every node but one.
        """
        return (self.ca_cert_path.is_file()
                and self.node_cert_path.is_file()
                and self.node_key_path.is_file())

    def ca_pair_ok(self) -> bool:
        """
        Does the CA certificate actually go with the CA key.

        Deliberately separate from exists(), and deliberately not something that
        regenerates on its own.  A GUI certificate that does not match its key
        can be thrown away and remade, because nobody has ever relied on it.  A
        CA is the opposite: every node certificate in the cluster was signed by
        it, so making a new one silently would invalidate all of them and every
        node would have to rejoin.

        So this reports, and the caller says something useful.  Losing a cluster
        because a check quietly did the tidy looking thing is not a trade worth
        making.
        """
        if not self.exists():
            return False
        try:
            return key_matches_cert(
                self.ca_cert_path.read_text(), self.ca_key_path.read_text()
            )
        except Exception:
            return False

    def create(self, cluster_name: str = "nginx-fleet") -> None:
        """
        Make a brand new CA.  Only the first node in a cluster does this.

        P-256 instead of RSA.  Smaller keys, faster handshakes, and every peer
        here is something we control, so there is no ancient client to worry
        about not understanding it.
        """
        if self.exists():
            log.info("cluster CA is already here, leaving it alone")
            return

        key = ec.generate_private_key(ec.SECP256R1())
        now = datetime.datetime.now(datetime.timezone.utc)

        subject = x509.Name([
            x509.NameAttribute(NameOID.COMMON_NAME, f"{cluster_name} cluster CA"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Failover LB"),
        ])

        cert = (
            x509.CertificateBuilder()
            .subject_name(subject)
            .issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=CA_CERT_DAYS))
            .add_extension(
                # path_length 0 means this CA signs end certs only.  A node cert
                # cannot turn around and sign more certs, so one stolen node key
                # cannot mint new cluster members.
                x509.BasicConstraints(ca=True, path_length=0),
                critical=True,
            )
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=False, data_encipherment=False,
                    key_agreement=False, key_cert_sign=True, crl_sign=True,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                x509.SubjectKeyIdentifier.from_public_key(key.public_key()),
                critical=False,
            )
            .sign(key, hashes.SHA256())
        )

        # Both to one side, then move them in.  Written straight over the top,
        # dying between the two leaves a CA whose certificate and key do not
        # match, and that takes the whole cluster's trust with it.
        key_tmp = self.ca_key_path.with_suffix(".key.tmp")
        cert_tmp = self.ca_cert_path.with_suffix(".crt.tmp")

        self._write_key(key_tmp, key)
        cert_tmp.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
        os.chmod(cert_tmp, 0o644)

        os.replace(str(key_tmp), str(self.ca_key_path))
        os.replace(str(cert_tmp), str(self.ca_cert_path))

        log.info("made a new cluster CA at %s", self.ca_cert_path)

    def load_ca_cert(self) -> x509.Certificate:
        return x509.load_pem_x509_certificate(self.ca_cert_path.read_bytes())

    def load_ca_key(self):
        return serialization.load_pem_private_key(
            self.ca_key_path.read_bytes(), password=None
        )

    def ca_pem(self) -> str:
        return self.ca_cert_path.read_text()

    def import_ca_cert(self, pem: str) -> None:
        """
        Save the CA cert we got when joining an existing cluster.

        Cert only, no key.  A joining node needs the cert so it can check the
        peers it talks to.  It never needs to sign anything, so it never gets
        the key.
        """
        x509.load_pem_x509_certificate(pem.encode())   # blow up now if it is junk
        self.ca_cert_path.write_text(pem)
        os.chmod(self.ca_cert_path, 0o644)

    # ---- node certs ---------------------------------------------------------

    def create_node_csr(self, node_name: str, addresses: list) -> tuple:
        """
        Make this node a key and a signing request.

        The key stays here.  Only the request goes over the wire, and a request
        is public information, so it does not matter who sees it.
        """
        key = ec.generate_private_key(ec.SECP256R1())

        san = [x509.DNSName(node_name)]
        for addr in addresses:
            try:
                san.append(x509.IPAddress(ipaddress.ip_address(addr)))
            except ValueError:
                san.append(x509.DNSName(addr))

        csr = (
            x509.CertificateSigningRequestBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, node_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Failover LB"),
            ]))
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .sign(key, hashes.SHA256())
        )

        # Deliberately not node_key_path.  See node_key_pending_path.
        self._write_key(self.node_key_pending_path, key)
        return key, csr.public_bytes(serialization.Encoding.PEM).decode()

    def sign_node_csr(self, csr_pem: str, node_name: str) -> str:
        """
        Sign a joining node's request.

        Runs on whichever node holds the CA key.  We do not just sign whatever
        subject they asked for.  The common name gets overwritten with the node
        name the cluster agreed on, so a node cannot request a cert claiming to
        be a different node and then use it to impersonate one.
        """
        if not self.ca_key_path.is_file():
            raise RuntimeError("this node does not hold the CA key, so it cannot sign")

        csr = x509.load_pem_x509_csr(csr_pem.encode())
        if not csr.is_signature_valid:
            raise ValueError("that signing request is not properly signed")

        ca_cert = self.load_ca_cert()
        ca_key = self.load_ca_key()
        now = datetime.datetime.now(datetime.timezone.utc)

        try:
            san_ext = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName)
            san = san_ext.value
        except x509.ExtensionNotFound:
            san = x509.SubjectAlternativeName([x509.DNSName(node_name)])

        cert = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([
                x509.NameAttribute(NameOID.COMMON_NAME, node_name),
                x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Failover LB"),
            ]))
            .issuer_name(ca_cert.subject)
            .public_key(csr.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=NODE_CERT_DAYS))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(san, critical=False)
            .add_extension(
                x509.KeyUsage(
                    digital_signature=True, content_commitment=False,
                    key_encipherment=True, data_encipherment=False,
                    key_agreement=False, key_cert_sign=False, crl_sign=False,
                    encipher_only=False, decipher_only=False,
                ),
                critical=True,
            )
            .add_extension(
                # Both, because every node is a server to its peers and a client
                # when it calls them.  Leave out client auth and mTLS fails in a
                # way that takes an hour to work out.
                x509.ExtendedKeyUsage([
                    ExtendedKeyUsageOID.SERVER_AUTH,
                    ExtendedKeyUsageOID.CLIENT_AUTH,
                ]),
                critical=False,
            )
            .add_extension(
                x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                critical=False,
            )
            .sign(ca_key, hashes.SHA256())
        )

        return cert.public_bytes(serialization.Encoding.PEM).decode()

    def save_node_cert(self, cert_pem: str) -> None:
        """
        Take delivery of a signed certificate, and promote the key that goes
        with it.

        This is the only place the live node key changes, and it only changes
        once we are holding the certificate that matches it.  Up to this point a
        failure leaves the node running on whatever it had before.
        """
        x509.load_pem_x509_certificate(cert_pem.encode())

        tmp = self.node_cert_path.with_suffix(".crt.tmp")
        tmp.write_text(cert_pem)
        os.chmod(tmp, 0o644)

        # Key first.  A key with no certificate is caught and regenerated on the
        # next start.  A certificate with the wrong key is what we are trying to
        # avoid.
        if self.node_key_pending_path.is_file():
            os.replace(str(self.node_key_pending_path), str(self.node_key_path))
        os.replace(str(tmp), str(self.node_cert_path))

    def has_node_cert(self) -> bool:
        """
        Do we have a usable certificate for this node.

        Both files being present is not enough.  They have to be a pair.  This
        used to check only that they existed, so a mismatched pair counted as
        having a certificate, nothing regenerated it, and the peer listener
        failed to start for good.
        """
        if not (self.node_cert_path.is_file() and self.node_key_path.is_file()):
            return False
        try:
            return key_matches_cert(
                self.node_cert_path.read_text(), self.node_key_path.read_text()
            )
        except Exception:
            return False

    def node_fingerprint(self) -> str:
        if not self.node_cert_path.is_file():
            return None
        cert = x509.load_pem_x509_certificate(self.node_cert_path.read_bytes())
        return cert.fingerprint(hashes.SHA256()).hex()

    def cert_fingerprint(self, pem: str) -> str:
        cert = x509.load_pem_x509_certificate(pem.encode())
        return cert.fingerprint(hashes.SHA256()).hex()

    def node_cert_expires(self):
        if not self.node_cert_path.is_file():
            return None
        cert = x509.load_pem_x509_certificate(self.node_cert_path.read_bytes())
        return cert.not_valid_after_utc

    @staticmethod
    def _write_key(path: Path, key) -> None:
        """Private keys go out at 0600 and never anything looser."""
        pem = key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        )
        # Open with the right mode from the start.  Writing then chmod leaves a
        # window where the key is on disk world readable, and something
        # watching the folder can grab it in that window.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)


# ==============================================================================
# Reading certificates
# ==============================================================================

def parse_certificate(pem: str) -> dict:
    """Pull the useful bits out of a cert so the GUI can show them."""
    cert = x509.load_pem_x509_certificate(pem.encode())

    info = {
        "subject": cert.subject.rfc4514_string(),
        "issuer": cert.issuer.rfc4514_string(),
        "serial": format(cert.serial_number, "x"),
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "signature_algorithm": cert.signature_algorithm_oid._name,
    }

    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        info["domains"] = san.value.get_values_for_type(x509.DNSName)
    except x509.ExtensionNotFound:
        info["domains"] = []

    pub = cert.public_key()
    if isinstance(pub, ec.EllipticCurvePublicKey):
        info["key_type"] = f"ECDSA {pub.curve.name}"
    else:
        info["key_type"] = f"RSA {pub.key_size}"

    return info


def key_matches_cert(cert_pem: str, key_pem: str) -> bool:
    """
    Check that a key and a cert actually go together.

    Worth doing on any upload.  A mismatched pair passes every eyeball test and
    then nginx refuses to start, which is a rough way to find out.
    """
    try:
        cert = x509.load_pem_x509_certificate(cert_pem.encode())
        key = serialization.load_pem_private_key(key_pem.encode(), password=None)
    except Exception:
        return False

    cert_pub = cert.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    key_pub = key.public_key().public_bytes(
        serialization.Encoding.PEM,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    return cert_pub == key_pub
