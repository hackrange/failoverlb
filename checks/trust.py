"""
The things that stop one node being talked into doing what another one says.

Peer requests are signed on top of mutual TLS, which sounds like belt and braces
until you think about what mTLS alone proves: that the caller holds a cluster
certificate.  The signature is what says which node sent this message and that
nobody changed it on the way, and the timestamp and nonce are what stop a
captured request being played back later.

Also here: whether a key really goes with a certificate, and whether the audit
log keeps secrets out of itself.  Both come from real bugs.  Three separate key
and certificate pairs were once checked with is_file(), which a mismatched pair
passes happily, and two of them crash looped the process with no way out that
did not involve deleting files by hand.

Nothing here touches the fleet, the database or the peer API.  It is the
functions, given good input and bad.

    docker exec -i nginx-fleet-manager python < checks/trust.py
"""
import sys
import time

from app.core.crypto import (
    constant_time_equals,
    decrypt,
    encrypt,
    hash_token,
    key_matches_cert,
    new_token,
    sign_payload,
    verify_payload,
)

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


KEY = "a-shared-key-between-two-nodes"
NODE = "lb-check"
BODY = b'{"verb":"apply","version":42}'


def signed(key=KEY, node=NODE, timestamp=None, nonce="nonce-1", body=BODY):
    timestamp = timestamp or str(int(time.time()))
    return timestamp, nonce, sign_payload(key, node, timestamp, nonce, body)


print("  a signed peer request")

stamp, nonce, signature = signed()
check("a good signature verifies",
      verify_payload(KEY, NODE, stamp, nonce, BODY, signature))

check("a changed body does not",
      not verify_payload(KEY, NODE, stamp, nonce, b'{"verb":"apply","version":43}', signature),
      "the body was altered and the signature still passed")

check("a different node name does not",
      not verify_payload(KEY, "lb-someone-else", stamp, nonce, BODY, signature),
      "another node could sign as this one")

check("a different key does not",
      not verify_payload("some-other-key", NODE, stamp, nonce, BODY, signature),
      "the signature passed with the wrong shared key")

check("a changed timestamp does not",
      not verify_payload(KEY, NODE, str(int(stamp) + 60), nonce, BODY, signature),
      "the timestamp is outside the signature, so a replay could be re-dated")

check("a changed nonce does not",
      not verify_payload(KEY, NODE, stamp, "nonce-2", BODY, signature),
      "the nonce is outside the signature, so a replay could be re-labelled")

check("an empty signature does not",
      not verify_payload(KEY, NODE, stamp, nonce, BODY, ""),
      "an empty signature was accepted")

check("a signature from a different body of the same length does not",
      not verify_payload(KEY, NODE, stamp, nonce, b'{"verb":"apply","version":24}', signature),
      "same length, different content, still passed")

print()
print("  the same input always signs the same, and different input never does")
again = sign_payload(KEY, NODE, stamp, nonce, BODY)
check("signing twice gives the same signature", again == signature,
      "the signature is not deterministic, so a peer could never verify one")
other = sign_payload(KEY, NODE, stamp, "nonce-2", BODY)
check("changing only the nonce changes the signature", other != signature,
      "the nonce does not affect the signature, so replays are not distinguishable")

print()
print("  comparing secrets")
token = new_token()
check("a token compares equal to itself", constant_time_equals(token, token))
check("a token does not compare equal to another", not constant_time_equals(token, new_token()))
check("a token does not compare equal to a prefix of itself",
      not constant_time_equals(token, token[:-1]),
      "a shorter string matched, so a comparison is stopping early")
check("hashing a token twice gives the same hash", hash_token(token) == hash_token(token))
check("the hash is not the token", hash_token(token) != token,
      "the token is being stored as itself")

print()
print("  encryption at rest")
secret = "totp-seed-and-peer-key-material"
sealed = encrypt(secret)
check("what comes back out is what went in", decrypt(sealed) == secret)
check("the stored form is not the plain text", secret not in sealed,
      "the secret is readable in what gets written to the database")
check("encrypting twice does not give the same bytes", encrypt(secret) != sealed,
      "no nonce, so identical secrets look identical at rest")
# decrypt gives back None rather than raising, on purpose: the usual cause is
# the node key having changed, and throwing there would take the page down
# instead of letting the caller ask for the value again.  So the thing to check
# is that tampering never yields the secret, not that it raises.
tampered = decrypt(sealed[:-4] + "AAAA")
check("tampered ciphertext does not give the secret back", tampered != secret,
      f"tampering produced the plaintext: {tampered!r}")
check("tampered ciphertext gives nothing at all", tampered is None,
      f"expected None, got {tampered!r}")

print()
print("  a key that does not go with its certificate")

def a_pair(common_name):
    """A throwaway certificate and its key, built here so nothing is read off disk."""
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID

    key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])
    now = datetime.datetime.now(datetime.timezone.utc)
    cert = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=1))
        .sign(key, hashes.SHA256())
    )
    return (
        cert.public_bytes(serialization.Encoding.PEM).decode(),
        key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.PKCS8,
            encryption_algorithm=serialization.NoEncryption(),
        ).decode(),
    )


cert_a, key_a = a_pair("check-a")
cert_b, key_b = a_pair("check-b")

check("a real pair matches", key_matches_cert(cert_a, key_a),
      "a matching certificate and key were not recognised as a pair")
check("a mismatched pair is caught", not key_matches_cert(cert_a, key_b),
      "a certificate and a key from different pairs were called a match, which "
      "is the bug that crash looped the process twice")
check("rubbish is not a match", not key_matches_cert("not a cert", key_a),
      "garbage was accepted as a certificate")
check("an empty certificate is not a match", not key_matches_cert("", key_a),
      "an empty string was accepted as a certificate")

print()
print("  the audit log keeps secrets out of itself")
from app.core import audit  # noqa: E402

scrubbed = audit.scrub({
    "password": "hunter2",
    "totp_secret": "JBSWY3DPEHPK3PXP",
    "hmac_key": "abcdef",
    "token": "t-12345",
    "name": "websec_pool",
    "nested": {"api_key": "sk-live-9999", "port": 443},
    "list": [{"client_secret": "shh"}],
})
blob = str(scrubbed)
for secret in ("hunter2", "JBSWY3DPEHPK3PXP", "abcdef", "t-12345", "sk-live-9999", "shh"):
    check(f"{secret[:12]!r} is not in the audit entry", secret not in blob,
          f"the audit log would have stored it: {blob[:160]}")
check("the harmless fields survive", "websec_pool" in blob and "443" in blob,
      "scrubbing took the useful part of the entry with it")

print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed")
print()
print("  what this does not cover:")
print("    - mutual TLS itself, which is the layer under all of this")
print("    - the nonce store that refuses a replay, which needs two live nodes")
print("    - certificate expiry and renewal of the cluster CA")
print()
print("  RESULT:", "the trust layer holds" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
