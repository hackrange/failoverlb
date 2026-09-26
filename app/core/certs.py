"""
Certificates that did not come from Lets Encrypt.

Covers three cases:

  * importing existing material: key and certificate, chain, a combined
    bundle, or a password protected PKCS12 file
  * generating a self signed certificate
  * generating a CSR, keeping the key here, and pairing the returned
    certificate with it

Nothing is stored until the key and certificate are verified as a pair.
nginx loads a mismatched pair without complaint and then fails every
handshake.  Chains are rebuilt from verified links rather than trusted as
uploaded, since a misordered chain works on some clients and not others.
"""
import datetime
import ipaddress
import logging
import re

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import (AuthorityInformationAccessOID,
                                   ExtensionOID, NameOID)

log = logging.getLogger("nfm.certs")

# CSR key sizes: RSA only, and only sizes commercial CAs reliably accept.
CSR_KEY_SIZES = (2048, 4096)

# Self signed certificates may also use ECDSA P-256, since no public CA has
# to accept them.
SELF_SIGNED_KEY_TYPES = ("ecdsa", "rsa")

# Browser lifetime caps apply to publicly trusted certificates, not to self
# signed ones, so the default is long.  It can be changed per certificate.
SELF_SIGNED_DEFAULT_DAYS = 825
SELF_SIGNED_MAX_DAYS = 3650

# Far larger than any real bundle, but small enough to bound memory use.
MAX_UPLOAD_BYTES = 512 * 1024


class CertProblem(Exception):
    """A user-facing problem with uploaded or generated material."""


# ==============================================================================
# Reading whatever somebody hands over
# ==============================================================================

def _as_bytes(data) -> bytes:
    if data is None:
        return b""
    if isinstance(data, bytes):
        return data
    return str(data).encode()


def load_certificates(data) -> list:
    """
    All certificates in a blob.  Tries PEM (may hold several) first, then
    falls back to a single DER certificate.
    """
    raw = _as_bytes(data)
    if not raw:
        return []

    found = []
    if b"-----BEGIN" in raw:
        for block in re.findall(
                rb"-----BEGIN CERTIFICATE-----.*?-----END CERTIFICATE-----",
                raw, re.S):
            try:
                found.append(x509.load_pem_x509_certificate(block))
            except Exception as exc:
                raise CertProblem(f"one of the certificates will not parse: {exc}")
        if found:
            return found

    try:
        return [x509.load_der_x509_certificate(raw)]
    except Exception:
        pass

    raise CertProblem(
        "that does not look like a certificate.  PEM starts with "
        "-----BEGIN CERTIFICATE-----, and DER is the binary form of the same "
        "thing, usually named .cer or .der."
    )


def load_private_key(data, password=None):
    """The key, PEM or DER, with or without a password on it."""
    raw = _as_bytes(data)
    if not raw:
        raise CertProblem("no private key was sent")

    secret = _as_bytes(password) or None

    for loader in (serialization.load_pem_private_key,
                   serialization.load_der_private_key):
        try:
            return loader(raw, password=secret)
        except (TypeError, ValueError) as exc:
            message = str(exc).lower()
            if "password" in message or "encrypted" in message or "decrypt" in message:
                if secret:
                    raise CertProblem("that password does not open the private key")
                raise CertProblem(
                    "that private key has a password on it.  Type it in and try again."
                )
            continue
        except Exception:
            continue

    raise CertProblem(
        "that private key will not parse.  PEM starts with -----BEGIN PRIVATE "
        "KEY----- or -----BEGIN RSA PRIVATE KEY-----."
    )


def load_pkcs12(data, password=None):
    """
    Key, certificate and chain from a .p12/.pfx file.

    An empty password is not the same as no password, so both are tried.
    """
    raw = _as_bytes(data)
    secret = _as_bytes(password) or None

    last = None
    for attempt in (secret, b"", None):
        try:
            key, leaf, extras = pkcs12.load_key_and_certificates(raw, attempt)
            return key, leaf, list(extras or [])
        except Exception as exc:
            last = exc
            continue

    raise CertProblem(
        f"that PKCS12 file will not open.  Usually the password is wrong: {last}"
    )


# ==============================================================================
# The check everything else depends on
# ==============================================================================

def key_matches_certificate(cert, key) -> bool:
    """Whether the key and certificate are a pair, by public key."""
    try:
        want = cert.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
        have = key.public_key().public_bytes(
            serialization.Encoding.DER,
            serialization.PublicFormat.SubjectPublicKeyInfo)
    except Exception:
        return False
    return want == have


def _issued_by(child, parent) -> bool:
    """Whether parent signed child, verified by signature, not just name."""
    if child.issuer != parent.subject:
        return False
    try:
        parent.public_key().verify(
            child.signature,
            child.tbs_certificate_bytes,
            *_verify_args(child, parent.public_key()),
        )
        return True
    except Exception:
        # Matching names but a bad signature usually means the wrong
        # intermediate from the right CA.  Leave it out.
        return False


def _verify_args(child, public_key):
    from cryptography.hazmat.primitives.asymmetric import padding
    if isinstance(public_key, ec.EllipticCurvePublicKey):
        return (ec.ECDSA(child.signature_hash_algorithm),)
    return (padding.PKCS1v15(), child.signature_hash_algorithm)


def order_chain(leaf, pool) -> list:
    """
    Rebuild the chain from the leaf up, using only links that verify.

    The self signed root is left off: any client that trusts it already has
    it, so sending it only adds bytes to every handshake.
    """
    chain = [leaf]
    remaining = [c for c in pool if c.fingerprint(hashes.SHA256())
                 != leaf.fingerprint(hashes.SHA256())]

    while True:
        current = chain[-1]
        if current.issuer == current.subject:
            break   # self signed, so this is the top
        nxt = next((c for c in remaining if _issued_by(current, c)), None)
        if nxt is None:
            break
        remaining.remove(nxt)
        if nxt.issuer == nxt.subject:
            break   # the root is not sent
        chain.append(nxt)

    return chain


# ==============================================================================
# Describing what we ended up with
# ==============================================================================

def names_in(cert) -> list:
    """Names the certificate covers: SANs, or the CN if there are none."""
    names = []
    try:
        san = cert.extensions.get_extension_for_oid(
            ExtensionOID.SUBJECT_ALTERNATIVE_NAME).value
        names.extend(san.get_values_for_type(x509.DNSName))
        names.extend(str(ip) for ip in san.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass

    if not names:
        # CN fallback only when there are no SANs.  Modern clients ignore
        # the CN, so such a certificate will not be accepted anyway.
        for attr in cert.subject.get_attributes_for_oid(NameOID.COMMON_NAME):
            names.append(str(attr.value))

    seen, out = set(), []
    for name in names:
        if name not in seen:
            seen.add(name)
            out.append(name)
    return out


def _name_text(name) -> str:
    return ", ".join(f"{a.rfc4514_attribute_name}={a.value}" for a in name)


def _key_kind(cert) -> str:
    key = cert.public_key()
    if isinstance(key, ec.EllipticCurvePublicKey):
        return f"ecdsa {key.curve.name}"
    if isinstance(key, rsa.RSAPublicKey):
        return f"rsa {key.key_size}"
    return type(key).__name__


def _utc(value):
    """
    Convert a datetime to naive UTC.

    cryptography 42 deprecated the naive validity properties, but the
    certificate table stores naive UTC.  Mixing aware and naive values raises
    on comparison, so strip the tzinfo here.
    """
    return value.replace(tzinfo=None) if value.tzinfo else value


def _now():
    """Naive UTC, to compare against what _utc gives back."""
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def ocsp_url(cert):
    """
    The OCSP responder URL in the certificate, or None.

    Some CAs (including Lets Encrypt) have dropped OCSP.  Stapling is only
    rendered for certificates that name a responder; otherwise nginx logs
    "ssl_stapling ignored, no OCSP responder URL" on every reload.
    """
    try:
        aia = cert.extensions.get_extension_for_class(
            x509.AuthorityInformationAccess).value
    except x509.ExtensionNotFound:
        return None
    for description in aia:
        if description.access_method == AuthorityInformationAccessOID.OCSP:
            return str(description.access_location.value)
    return None


def describe(cert) -> dict:
    return {
        "subject": _name_text(cert.subject),
        "issuer": _name_text(cert.issuer),
        "domains": names_in(cert),
        "not_before": _utc(cert.not_valid_before_utc),
        "not_after": _utc(cert.not_valid_after_utc),
        "serial": format(cert.serial_number, "x"),
        "fingerprint": cert.fingerprint(hashes.SHA256()).hex(),
        "key": _key_kind(cert),
        "self_signed": cert.issuer == cert.subject,
        "ocsp_url": ocsp_url(cert),
    }


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


def _key_pem(key) -> str:
    return key.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


# ==============================================================================
# Taking one somebody already has
# ==============================================================================

def analyse_upload(cert_data=None, key_data=None, chain_data=None,
                   pkcs12_data=None, password=None) -> dict:
    """
    Parse and check an upload; raise CertProblem if the pieces do not fit.

    Has no side effects.  Returns the ordered fullchain, the key, certificate
    details for review, and non-fatal warnings.
    """
    for blob in (cert_data, key_data, chain_data, pkcs12_data):
        if blob is not None and len(_as_bytes(blob)) > MAX_UPLOAD_BYTES:
            raise CertProblem(
                f"that file is bigger than {MAX_UPLOAD_BYTES // 1024}KB, which "
                f"is far more than any certificate needs.  Is it the right file?"
            )

    extras = []
    if pkcs12_data:
        key, leaf, others = load_pkcs12(pkcs12_data, password)
        if leaf is None:
            raise CertProblem("that PKCS12 file has no certificate in it")
        if key is None:
            raise CertProblem("that PKCS12 file has no private key in it")
        extras.extend(others)
    else:
        certs = load_certificates(cert_data)
        if not certs:
            raise CertProblem("no certificate was sent")
        # Bundles are common, and some tools write them root first, so
        # find the leaf instead of taking the first certificate.
        leaf = _pick_leaf(certs)
        extras.extend(c for c in certs if c is not leaf)
        key = load_private_key(key_data, password)

    extras.extend(load_certificates(chain_data))

    # Must pass before anything else happens.
    if not key_matches_certificate(leaf, key):
        raise CertProblem(
            "that private key does not go with that certificate.  Nothing has "
            "been saved.  nginx will load a mismatched pair without complaining "
            "and then fail every handshake, so this is refused here rather than "
            "found later by a visitor."
        )

    chain = order_chain(leaf, extras)
    info = describe(leaf)

    warnings = []
    now = _now()
    if info["not_after"] < now:
        warnings.append(
            f"this certificate expired on {info['not_after']:%d %b %Y}.  It can "
            f"be stored, but nothing will trust it.")
    elif (info["not_after"] - now).days < 30:
        warnings.append(
            f"this certificate expires on {info['not_after']:%d %b %Y}, which is "
            f"{(info['not_after'] - now).days} days away.")
    if info["not_before"] > now:
        warnings.append(
            f"this certificate is not valid until {info['not_before']:%d %b %Y}.")

    if info["self_signed"]:
        warnings.append(
            "this is self signed, so browsers will warn about it unless every "
            "machine that visits has been told to trust it.")
    elif len(chain) == 1:
        warnings.append(
            "no intermediate certificates came with this, so the chain stops at "
            "the leaf.  Some clients keep a copy of the intermediate and will be "
            "fine, and others will refuse the site outright, which is why this is "
            "worth fixing before anybody notices for you.  The authority you "
            "bought it from publishes the file.")

    unused = len(extras) - (len(chain) - 1)
    if unused > 0:
        warnings.append(
            f"{unused} certificate(s) in what you sent are not part of this "
            f"chain and were left out.  A root belongs in that group and does "
            f"not need to be sent.")

    return {
        "fullchain": "".join(_pem(c) for c in chain),
        "privkey": _key_pem(key),
        "chain_length": len(chain),
        "warnings": warnings,
        **info,
    }


def _pick_leaf(certs):
    """The certificate that signed none of the others."""
    if len(certs) == 1:
        return certs[0]
    for candidate in certs:
        if not any(_issued_by(other, candidate) for other in certs
                   if other is not candidate):
            return candidate
    return certs[0]


# ==============================================================================
# Making one
# ==============================================================================

def _new_key(key_type: str, key_size: int):
    if key_type == "ecdsa":
        return ec.generate_private_key(ec.SECP256R1())
    if key_size not in CSR_KEY_SIZES:
        raise CertProblem(
            f"the key length has to be one of {', '.join(str(s) for s in CSR_KEY_SIZES)}")
    return rsa.generate_private_key(public_exponent=65537, key_size=key_size)


def _san_list(domains):
    entries = []
    for name in domains:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _subject_name(common_name, subject=None):
    subject = subject or {}
    parts = [x509.NameAttribute(NameOID.COMMON_NAME, common_name)]
    for key, oid in (("organization", NameOID.ORGANIZATION_NAME),
                     ("organizational_unit", NameOID.ORGANIZATIONAL_UNIT_NAME),
                     ("locality", NameOID.LOCALITY_NAME),
                     ("state", NameOID.STATE_OR_PROVINCE_NAME),
                     ("country", NameOID.COUNTRY_NAME),
                     ("email", NameOID.EMAIL_ADDRESS)):
        value = (subject.get(key) or "").strip()
        if value:
            parts.append(x509.NameAttribute(oid, value))
    return x509.Name(parts)


def check_domains(domains) -> list:
    cleaned = []
    for raw in domains or []:
        name = str(raw).strip().lower()
        if not name:
            continue
        if len(name) > 253 or re.search(r"[\s,;/\\]", name):
            raise CertProblem(f"{raw!r} is not a name a certificate can carry")
        if name not in cleaned:
            cleaned.append(name)
    if not cleaned:
        raise CertProblem("give it at least one name")
    return cleaned


def self_signed(domains, key_type="ecdsa", key_size=2048,
                days=SELF_SIGNED_DEFAULT_DAYS, subject=None) -> dict:
    """
    Generate a self signed certificate and key.

    Includes SANs and the usual key usage extensions so browsers accept it
    once trusted; missing them causes obscure failures.
    """
    domains = check_domains(domains)
    if key_type not in SELF_SIGNED_KEY_TYPES:
        raise CertProblem("the key has to be ecdsa or rsa")
    days = max(1, min(int(days or SELF_SIGNED_DEFAULT_DAYS), SELF_SIGNED_MAX_DAYS))

    key = _new_key(key_type, key_size)
    name = _subject_name(domains[0], subject)
    now = datetime.datetime.now(datetime.timezone.utc)

    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=days))
        .add_extension(_san_list(domains), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(
            x509.KeyUsage(
                digital_signature=True, key_encipherment=True,
                content_commitment=False, data_encipherment=False,
                key_agreement=False, key_cert_sign=False, crl_sign=False,
                encipher_only=False, decipher_only=False),
            critical=True)
        .add_extension(
            x509.ExtendedKeyUsage([x509.ObjectIdentifier("1.3.6.1.5.5.7.3.1")]),
            critical=False)
        .add_extension(
            x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )

    return {
        "fullchain": _pem(cert),
        "privkey": _key_pem(key),
        "chain_length": 1,
        "warnings": [
            "self signed, so browsers will warn about it unless every machine "
            "that visits has been told to trust it.  Fine for a staging box or "
            "an internal name, not for anything the public reaches."
        ],
        **describe(cert),
    }


def make_csr(domains, key_size=2048, subject=None) -> dict:
    """Generate an RSA key and a CSR for it.  The key never leaves here."""
    domains = check_domains(domains)
    key_size = int(key_size or 2048)
    if key_size not in CSR_KEY_SIZES:
        raise CertProblem(
            f"the key length has to be {' or '.join(str(s) for s in CSR_KEY_SIZES)}")

    key = _new_key("rsa", key_size)
    csr = (
        x509.CertificateSigningRequestBuilder()
        .subject_name(_subject_name(domains[0], subject))
        .add_extension(_san_list(domains), critical=False)
        .sign(key, hashes.SHA256())
    )

    return {
        "csr": csr.public_bytes(serialization.Encoding.PEM).decode(),
        "privkey": _key_pem(key),
        "domains": domains,
        "key": f"rsa {key_size}",
        "subject": _name_text(csr.subject),
    }


def complete_csr(csr_privkey_pem, cert_data=None, chain_data=None) -> dict:
    """
    Pair a CA-issued certificate with the key kept for its CSR.

    The match check catches the common mistake of pasting the certificate
    from a different request.
    """
    key = load_private_key(csr_privkey_pem)
    certs = load_certificates(cert_data)
    if not certs:
        raise CertProblem("no certificate was sent")

    leaf = _pick_leaf(certs)
    if not key_matches_certificate(leaf, key):
        raise CertProblem(
            "that certificate does not go with the key held for this request.  "
            "It is usually the certificate from a different request.  Nothing "
            "has been saved."
        )

    return analyse_upload(
        cert_data=cert_data,
        key_data=_key_pem(key),
        chain_data=chain_data,
    )
