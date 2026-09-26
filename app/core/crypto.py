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


# =============================================================================
# Encrypting things we store
# =============================================================================

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
    Decrypt a stored value, or return None if it won't decrypt.

    Usually that means the node secret key changed (node rebuilt).  Returning
    None lets the caller ask for the value again instead of erroring.
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
    sha256 of a session or join token, for storage.  These are long random
    strings so a fast hash is fine.  Passwords go through argon2 instead.
    """
    return hashlib.sha256(token.encode()).hexdigest()


def constant_time_equals(a: str, b: str) -> bool:
    """Compare without leaking how much matched through timing."""
    return hmac.compare_digest(a.encode(), b.encode())


def new_token(length: int = 32) -> str:
    """A random token, url safe so it can go in a header or a link."""
    return secrets.token_urlsafe(length)


# =============================================================================
# Signing messages between nodes
# =============================================================================

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


# =============================================================================
# The cluster CA
# =============================================================================

class ClusterCA:
    """
    The certificate authority the fleet trusts.

    The first node makes it.  Every node that joins gets a cert signed by it.
    Peer connections require a cert from this CA and nothing else, so being a
    member of the cluster is the same thing as holding one of these.

    The CA key never leaves the node that made it.  Joining nodes send a
    signing request and get a cert back, never the key.
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

        # A new key waits here until the sponsor signs it.  Joins fail often
        # (spent token, firewall, sponsor down), and if the new key had
        # already replaced the live one we'd be left with a mismatched pair
        # and a peer listener that crash loops.  A failed join must leave the
        # node exactly as it was.
        self.node_key_pending_path = self.dir / "node.key.pending"

    # ---- the CA itself ------------------------------------------------------

    def exists(self) -> bool:
        """
        Can this node sign for the cluster (holds the CA key and cert).

        Only true on the founding node.  Joined nodes get the CA cert but
        never the key.  This is not a membership check; using it as one made
        every joined node think it needed to rejoin.  Use has_identity.
        """
        return self.ca_cert_path.is_file() and self.ca_key_path.is_file()

    def has_identity(self) -> bool:
        """
        Is this node a cluster member: CA cert to verify peers, plus its own
        cert and key.  Joined nodes normally have these and no CA key.
        """
        return (self.ca_cert_path.is_file()
                and self.node_cert_path.is_file()
                and self.node_key_path.is_file())

    def ca_pair_ok(self) -> bool:
        """
        Does the CA cert go with the CA key.

        Report only, never regenerate.  Every node cert was signed by this
        CA, so silently replacing it would force every node to rejoin.
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
                # path_length 0: this CA signs end certs only, so a stolen
                # node key cannot mint new cluster members.
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

        # Write both to temp files, then move them in, so a crash can't
        # leave a CA cert and key that don't match.
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
                # Every node is both server and client to its peers.  Leave
                # out client auth and mTLS fails in a confusing way.
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
        Save a signed cert and promote the pending key that goes with it.

        The only place the live node key changes, and only once we hold the
        matching cert.
        """
        x509.load_pem_x509_certificate(cert_pem.encode())

        tmp = self.node_cert_path.with_suffix(".crt.tmp")
        tmp.write_text(cert_pem)
        os.chmod(tmp, 0o644)

        # Key first.  A key with no cert is regenerated on the next start;
        # a cert with the wrong key is what we're trying to avoid.
        if self.node_key_pending_path.is_file():
            os.replace(str(self.node_key_pending_path), str(self.node_key_path))
        os.replace(str(tmp), str(self.node_cert_path))

    def has_node_cert(self) -> bool:
        """
        Do we have a usable node cert.  Both files must exist and match;
        a mismatched pair would never get regenerated otherwise.
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
        # Create with 0600 up front.  Write-then-chmod leaves a window where
        # the key is world readable.
        fd = os.open(str(path), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as fh:
            fh.write(pem)


# =============================================================================
# Reading certificates
# =============================================================================

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
