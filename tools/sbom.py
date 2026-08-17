#!/usr/bin/env python3
"""
Build the software bill of materials, in both formats people ask for.

    python3 tools/sbom.py            write sbom/ and say what changed
    python3 tools/sbom.py --check    fail if what is written is out of date

**Why this matters more here than in most projects.**  This tool builds its own
nginx from source, with its own OpenSSL, its own ModSecurity and thirteen
outside modules, and then runs that binary on somebody's load balancer.  A
person installing this is trusting a binary nobody else compiled, made of parts
nobody has listed.  A bill of materials is how that stops being a matter of
trust and starts being a matter of record.

Three layers, and only the first is the easy one:

  * **The application.**  Python packages and their pins.  Every SBOM tool
    already does this and it is the least interesting part.
  * **The nginx build.**  The version, OpenSSL, ModSecurity, every third party
    module and the exact git ref each is fetched at.  This is the part a
    generic scanner cannot see, because none of it is a package: it is a shell
    script that clones and compiles.
  * **What ships beside it.**  The OWASP rule set and the country database.
    Neither is code and both change what the product does.

**Read from the source of truth, never copied.**  Every version below is parsed
out of `nginx-installer.sh` or `requirements.txt` at the moment this runs.  A
bill of materials maintained by hand is one that is wrong by the second
release, and wrong in the direction that matters: it says you shipped something
you did not.  `checks/sbom.py` fails the build when the two disagree.
"""
import argparse
import hashlib
import json
import pathlib
import re
import subprocess
import sys
from datetime import datetime, timezone

ROOT = pathlib.Path(__file__).resolve().parent.parent
OUT = ROOT / "sbom"

SUPPLIER = "Failover LB"
NAMESPACE = "https://failoverlb.net/sbom"


# ==============================================================================
# Reading the sources of truth
# ==============================================================================

def _installer() -> str:
    return (ROOT / "nginx-installer.sh").read_text()


def _shell_var(text: str, name: str) -> str:
    """
    A `NAME="${NAME:-value}"` default out of the installer.

    The default is what a build uses unless somebody deliberately overrode it,
    so it is the honest thing to record.  An override at build time is a
    different build and should produce a different bill of materials, which is
    what --check exists to notice.
    """
    m = re.search(rf'^{name}="\$\{{{name}:-([^}}]+)\}}"', text, re.M)
    return m.group(1) if m else ""


def _module_list(text: str, array: str) -> list:
    """The "folder|url|ref" entries out of one of the module arrays."""
    m = re.search(rf"^{array}=\((.*?)^\)", text, re.M | re.S)
    if not m:
        return []
    out = []
    for line in m.group(1).split("\n"):
        line = line.split("#", 1)[0].strip().strip('"')
        if line.count("|") != 2:
            continue
        folder, url, ref = line.split("|")
        out.append({"name": folder, "url": url, "ref": ref})
    return out


def _expand(value: str, text: str) -> str:
    """Put the shell variables back, so v${HEADERS_MORE_VERSION} reads as v0.40."""
    def swap(m):
        return _shell_var(text, m.group(1)) or m.group(0)
    return re.sub(r"\$\{(\w+)\}", swap, value)


def _python_packages() -> list:
    out = []
    for line in (ROOT / "requirements.txt").read_text().split("\n"):
        line = line.split("#", 1)[0].strip()
        if not line or "==" not in line:
            continue
        name, version = line.split("==", 1)
        out.append({"name": name.split("[")[0].strip(),
                    "extras": name[name.find("["):] if "[" in name else "",
                    "version": version.strip()})
    return out


def _base_images() -> list:
    text = (ROOT / "Dockerfile").read_text()
    return sorted({m.group(1) for m in re.finditer(r"^FROM\s+(\S+)", text, re.M)})


def components() -> list:
    """
    Everything this product ships or builds, as one list.

    `layer` is the part a generic tool cannot produce and is the reason this
    script exists: it says whether a component is the application, the nginx
    binary somebody is being asked to trust, or data that changes behaviour.
    """
    text = _installer()
    out = []

    for image in _base_images():
        name, _, tag = image.partition(":")
        out.append({
            "layer": "container", "type": "container", "name": name,
            "version": tag or "latest",
            "purl": f"pkg:docker/{name}@{tag}" if tag else f"pkg:docker/{name}",
            "note": "the image the manager runs in",
        })

    for pkg in _python_packages():
        out.append({
            "layer": "application", "type": "library", "name": pkg["name"],
            "version": pkg["version"],
            "purl": f"pkg:pypi/{pkg['name'].lower()}@{pkg['version']}",
            "note": "pinned in requirements.txt",
        })

    # The nginx build.  None of this is a package; it is a shell script that
    # clones and compiles, which is exactly why nothing else can see it.
    for name, var, url, note in (
        ("nginx", "NGINX_VERSION", "https://nginx.org/download/nginx-{v}.tar.gz",
         "built from source so the module set can be chosen"),
        ("openssl", "OPENSSL_VERSION",
         "https://github.com/openssl/openssl/releases/download/openssl-{v}/openssl-{v}.tar.gz",
         "pinned at 3.5 or later for the QUIC API and ML-KEM, which is what "
         "makes the post quantum key exchange possible"),
        ("modsecurity", "MODSECURITY_VERSION",
         "https://github.com/owasp-modsecurity/ModSecurity",
         "the web application firewall engine, built only when asked for"),
    ):
        version = _shell_var(text, var)
        if not version:
            continue
        out.append({
            "layer": "nginx", "type": "library", "name": name,
            "version": version, "url": url.format(v=version),
            "purl": f"pkg:generic/{name}@{version}",
            "note": note,
        })

    for module in _module_list(text, "THIRD_PARTY_MODULES"):
        ref = _expand(module["ref"], text)
        out.append({
            "layer": "nginx", "type": "library", "name": module["name"],
            "version": ref, "url": module["url"],
            "purl": f"pkg:github/{module['url'].split('github.com/')[-1]}@{ref}"
                    if "github.com" in module["url"] else None,
            "note": "compiled into the nginx binary"
                    + ("" if ref not in ("master", "main")
                       else ".  Tracks a branch rather than a tag, so two "
                            "builds on different days are not the same build"),
        })

    # The dynamic ones are in a conditional block, so they are read from the
    # whole file rather than from an array literal.
    for m in re.finditer(r'"([\w-]+)\|(https://[^\|]+)\|([^"]+)"', text):
        if m.group(1) == "modsecurity-nginx":
            out.append({
                "layer": "nginx", "type": "library", "name": m.group(1),
                "version": _expand(m.group(3), text), "url": m.group(2),
                "purl": f"pkg:github/{m.group(2).split('github.com/')[-1]}"
                        f"@{_expand(m.group(3), text)}",
                "note": "built as a loadable module, present only when the "
                        "firewall was asked for",
            })

    for m in re.finditer(
            r"git clone --depth 1(?: --branch (?P<ref>\S+))? "
            r"(?P<url>https://github\.com/openresty/(?P<name>[\w-]+))", text):
        out.append({
            "layer": "nginx", "type": "library", "name": m.group("name"),
            "version": m.group("ref") or "master", "url": m.group("url"),
            "purl": f"pkg:github/openresty/{m.group('name')}"
                    f"@{m.group('ref') or 'master'}",
            "note": "the lua runtime the lua module needs",
        })

    # Data that changes behaviour without being code.  Neither carries a
    # version in this repository, because both are fetched at run time on a
    # schedule, and saying so is more use than inventing one.
    out.append({
        "layer": "data", "type": "data", "name": "owasp-crs",
        "version": "fetched at run time, lts or latest track",
        "url": "https://github.com/coreruleset/coreruleset",
        "purl": "pkg:github/coreruleset/coreruleset",
        "note": "the firewall rules.  Chosen by track and updated on a "
                "schedule, so the version on a node is a property of that node "
                "rather than of this release.  The GUI reports what each node "
                "actually has.",
    })
    out.append({
        "layer": "data", "type": "data", "name": "geolite2-country",
        "version": "fetched at run time",
        "url": "https://www.maxmind.com/",
        "purl": None,
        "note": "the country database for geo blocking.  Fetched with the "
                "operator's own credentials and never redistributed with this "
                "product.",
    })

    return out


# ==============================================================================
# The two formats
# ==============================================================================

def _release() -> dict:
    def git(*args):
        try:
            return subprocess.run(["git", "-C", str(ROOT), *args],
                                  capture_output=True, text=True,
                                  timeout=20).stdout.strip()
        except Exception:
            return ""
    return {
        "commit": git("rev-parse", "HEAD") or "unknown",
        "described": git("describe", "--tags", "--always", "--dirty") or "unknown",
        # A timestamp is what makes two builds of the same commit produce
        # different files, so it is deliberately not in the documents; the
        # commit is the identity.  See --check.
    }


def spdx(items, release) -> dict:
    """SPDX 2.3, which is the format procurement and legal teams ask for."""
    doc = {
        "spdxVersion": "SPDX-2.3",
        "dataLicense": "CC0-1.0",
        "SPDXID": "SPDXRef-DOCUMENT",
        "name": f"failover-lb-{release['described']}",
        "documentNamespace": f"{NAMESPACE}/spdx/{release['commit']}",
        "creationInfo": {
            "creators": [f"Tool: tools/sbom.py", f"Organization: {SUPPLIER}"],
            # Fixed rather than now(), so the same commit always produces the
            # same document.  A file that changes every time it is generated
            # cannot be committed and cannot be diffed, which defeats the point.
            "created": "1970-01-01T00:00:00Z",
            "comment": "The created time is fixed so the same commit always "
                       "produces the same document.  The commit in the "
                       "namespace is the identity of this build.",
        },
        "packages": [],
        "relationships": [],
    }

    for n, item in enumerate(items):
        ref = f"SPDXRef-{re.sub(r'[^A-Za-z0-9.-]', '-', item['name'])}-{n}"
        package = {
            "SPDXID": ref,
            "name": item["name"],
            "versionInfo": item["version"],
            "downloadLocation": item.get("url") or "NOASSERTION",
            "filesAnalyzed": False,
            "supplier": "NOASSERTION",
            "comment": f"[{item['layer']}] {item['note']}",
        }
        if item.get("purl"):
            package["externalRefs"] = [{
                "referenceCategory": "PACKAGE-MANAGER",
                "referenceType": "purl",
                "referenceLocator": item["purl"],
            }]
        doc["packages"].append(package)
        doc["relationships"].append({
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": ref,
        })
    return doc


def cyclonedx(items, release) -> dict:
    """CycloneDX 1.5, which is the format security tooling ingests."""
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "serialNumber": "urn:uuid:" + str(
            __import__("uuid").UUID(hashlib.sha256(
                release["commit"].encode()).hexdigest()[:32])),
        "version": 1,
        "metadata": {
            # Same reasoning as the SPDX timestamp: fixed, so the file is a
            # function of the commit and nothing else.
            "timestamp": "1970-01-01T00:00:00Z",
            "tools": [{"vendor": SUPPLIER, "name": "tools/sbom.py"}],
            "component": {
                "type": "application",
                "name": "failover-lb",
                "version": release["described"],
                "description": "nginx fleet manager: two phase config apply, "
                               "certificates, firewall, tunnel",
            },
            "properties": [
                {"name": "failoverlb:commit", "value": release["commit"]},
            ],
        },
        "components": [
            {
                "type": item["type"] if item["type"] in
                        ("library", "application", "container", "data",
                         "framework", "file") else "library",
                "name": item["name"],
                "version": item["version"],
                **({"purl": item["purl"]} if item.get("purl") else {}),
                **({"externalReferences": [
                    {"type": "distribution", "url": item["url"]}
                ]} if item.get("url") else {}),
                "description": item["note"],
                "properties": [{"name": "failoverlb:layer",
                                "value": item["layer"]}],
            }
            for item in items
        ],
    }


# ==============================================================================
# Writing and checking
# ==============================================================================

def render() -> dict:
    items = components()
    release = _release()
    return {
        "sbom.spdx.json": json.dumps(spdx(items, release), indent=2) + "\n",
        "sbom.cyclonedx.json": json.dumps(cyclonedx(items, release), indent=2) + "\n",
    }, items


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--check", action="store_true",
                    help="fail if what is committed is out of date")
    args = ap.parse_args()

    files, items = render()
    OUT.mkdir(exist_ok=True)

    stale = []
    for name, body in files.items():
        path = OUT / name
        current = path.read_text() if path.exists() else ""
        if current != body:
            stale.append(name)
            if not args.check:
                path.write_text(body)

    by_layer = {}
    for item in items:
        by_layer.setdefault(item["layer"], []).append(item)

    print(f"  {len(items)} components")
    for layer in ("application", "nginx", "container", "data"):
        got = by_layer.get(layer) or []
        print(f"    {layer:12} {len(got):3}")

    floating = [i["name"] for i in items if i["version"] in ("master", "main")]
    if floating:
        print()
        print(f"  {len(floating)} components track a branch rather than a tag, so two")
        print("  builds on different days are not the same build:")
        for name in floating:
            print(f"    {name}")

    if args.check:
        if stale:
            print()
            print(f"  OUT OF DATE: {', '.join(stale)}")
            print("  Run: python3 tools/sbom.py")
            return 1
        print()
        print("  the committed bill of materials matches the source")
        return 0

    print()
    print("  wrote" if stale else "  already current:",
          ", ".join(files) if stale else ", ".join(files))
    return 0


if __name__ == "__main__":
    sys.exit(main())
