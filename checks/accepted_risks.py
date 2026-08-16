"""
The advisories we decided not to patch, and whether that decision still holds.

Seven advisories exist in pinned dependencies and are not reachable in this
deployment.  Each was accepted rather than patched, because upgrading starlette
across a major version and cryptography across six, on a live fleet, to close
nothing, is a worse trade than leaving them.  The full reasoning is in the
security review; the short version is that each needs either an API this
codebase never calls, an operating system it does not run on, or network access
it does not grant.

**This file is what makes that a decision instead of a shrug.**  An acceptance
is only honest while the thing it depends on is still true, and the things it
depends on are all in the code, where they move.  So each one is asserted here
on every run.  When somebody adds a PKCS#7 path or serves a file from the peer
application, this fails and the acceptance gets revisited rather than quietly
becoming wrong.

Read this alongside the report.  Nothing here decides anything; it only reports
whether the grounds for a decision somebody already made still exist.

    docker exec -i nginx-fleet-manager python < checks/accepted_risks.py
"""
import pathlib
import re
import sys

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"          {detail}")


def sources(*folders):
    out = {}
    for folder in folders:
        base = pathlib.Path(folder)
        if not base.exists():
            continue
        for path in base.rglob("*.py"):
            out[str(path)] = path.read_text()
    return out


CODE = sources("app", "host-agent")
if not CODE:
    print("\n  could not read the source, so nothing here proved anything\n")
    sys.exit(1)


def uses(name):
    """Where a symbol appears in the product, ignoring comments."""
    hits = []
    for path, text in CODE.items():
        for n, line in enumerate(text.split("\n"), 1):
            bare = line.split("#", 1)[0]
            if name in bare:
                hits.append(f"{path}:{n}")
    return hits


print()
print("=== The accepted risk register, and whether it still holds ===")
print()
print("  cryptography: the APIs the advisories need are not called")

for ref, cve, names, what in (
    ("AR2", "CVE-2026-26007",
     ("load_pem_public_key", "load_der_public_key",
      "public_key_from_numbers", "EllipticCurvePublicNumbers"),
     "loading an attacker's public key, where a small order subgroup point "
     "would not be rejected"),
    ("AR3", "CVE-2026-69247",
     ("pkcs7_decrypt_der", "pkcs7_decrypt_pem", "pkcs7_decrypt_smime"),
     "decrypting attacker supplied PKCS#7, which gives a padding oracle"),
    ("AR4", "CVE-2026-69249",
     ("PolicyBuilder",),
     "verifying a certificate chain with this library rather than through "
     "the ssl module, where duplicate self signed certificates blow up"),
):
    found = [h for name in names for h in uses(name)]
    check(f"{ref}: nothing calls {', '.join(names[:2])}"
          + (" or others" if len(names) > 2 else ""),
          not found,
          f"{cve} needs {what}.  It was accepted on the grounds that this "
          f"code never does it, and now it does: {found[:4]}.  Either revisit "
          f"the acceptance or upgrade cryptography.")


print()
print("  starlette: the internet facing application still serves neither "
      "files nor forms")

peer = pathlib.Path("app/web/routes_peer.py")
peer_text = peer.read_text() if peer.exists() else ""
check("the peer routes file was found", bool(peer_text),
      "without it the two checks below prove nothing, which is worse than "
      "failing")

if peer_text:
    bare = "\n".join(l.split("#", 1)[0] for l in peer_text.split("\n"))

    check("AR6: the peer application serves no files",
          "StaticFiles" not in bare and "FileResponse" not in bare,
          "CVE-2025-62727 is a quadratic Range header parse on file "
          "responses.  It was accepted because port 7444 is the only one "
          "open to the internet and it served no files.  It does now.")

    check("AR7: the peer application parses no forms",
          ".form()" not in bare,
          "CVE-2026-54283 is form parsing limits being ignored for urlencoded "
          "bodies.  It was accepted because the internet facing application "
          "read only JSON.  It does not any more.")


print()
print("  the management allow list, which both starlette acceptances lean on")

# Read rather than imported, so this says what the box is configured with
# rather than what a settings object cached at import time believes.
from app.config import get_settings                                # noqa: E402

allowlist = (get_settings().admin_allowlist or "").strip()
entries = [e for e in re.split(r"[,\s]+", allowlist) if e]

check("the allow list is not empty",
      bool(entries),
      "AR6 and AR7 were both accepted because the GUI is reachable only from "
      "named addresses.  An empty allow list means no restriction at all, so "
      "the denial of service advisories become reachable by anybody who can "
      "reach the port.  Either set it, or upgrade starlette, or write down "
      "that you accept them unrestricted.")

if entries:
    print(f"      {len(entries)} entr{'y' if len(entries) == 1 else 'ies'}: "
          f"{', '.join(entries[:6])}")
    wide = [e for e in entries if e.endswith(("/0", "/1", "/2", "/3", "/4",
                                              "/5", "/6", "/7", "/8"))]
    check("no entry is so wide it is not really a restriction",
          not wide,
          f"these cover a large part of the internet, which is the same as no "
          f"allow list for the purpose of these two advisories: {wide}")

# The allow list runs before anything else, which is the other half of the
# argument: a refused request never reaches the parser.
main = pathlib.Path("app/main.py").read_text()
order = [m for m in re.findall(r"app\.add_middleware\((\w+)", main)]
check("the allow list runs before the rest of the middleware",
      order and order[-1] == "AdminAllowlistMiddleware",
      f"starlette runs the last one added first, so the allow list has to be "
      f"added last to be outermost.  Order found: {order}.  If it is not "
      f"outermost, a refused request still reaches whatever runs before it.")


print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} still hold")
print()
print("  what this does not do:")
print("    - decide anything.  It reports whether the grounds for a decision")
print("      somebody already made are still there")
print("    - check the advisories themselves, which is the quarterly scan's")
print("      job and needs a live feed")
print("    - cover AR1, the Windows only one, which needs no check because a")
print("      Windows port would be deliberate and very visible")
print()
print("  RESULT:", "every accepted risk still rests on something true"
      if not failed else f"{len(failed)} ACCEPTANCE(S) NO LONGER HOLD: {failed}")
sys.exit(1 if failed else 0)
