"""
Whether the bill of materials still describes what this actually builds.

A bill of materials is only worth anything while it is true, and the way it
stops being true is not dramatic: somebody bumps a version in
`nginx-installer.sh`, or pins a new Python package, and the committed documents
go on describing last month's build.  Nobody notices, because a stale SBOM
looks exactly like a current one.

So this does not read the documents and admire them.  It regenerates from the
sources of truth and fails if what is committed differs, and it separately
asserts that every version named in the installer appears in the output, so a
component added to the build in a shape the generator does not recognise fails
here rather than going unlisted.

Runs anywhere, needs no fleet, reads files only.

    python3 checks/sbom.py
"""
import json
import pathlib
import re
import subprocess
import sys

ROOT = pathlib.Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"          {detail}")


print()
print("=== The bill of materials ===")
print()
print("  it exists, in both formats")

spdx_path = ROOT / "sbom" / "sbom.spdx.json"
cdx_path = ROOT / "sbom" / "sbom.cyclonedx.json"

check("SPDX is committed", spdx_path.exists(),
      "procurement and legal ask for this one")
check("CycloneDX is committed", cdx_path.exists(),
      "security tooling ingests this one")

if not (spdx_path.exists() and cdx_path.exists()):
    print("\n  nothing further can be checked\n")
    sys.exit(1)

spdx = json.loads(spdx_path.read_text())
cdx = json.loads(cdx_path.read_text())

check("SPDX says which version of the standard it is",
      spdx.get("spdxVersion", "").startswith("SPDX-2"),
      f"got {spdx.get('spdxVersion')!r}, and a document with no version is one "
      f"no tool will read")
check("CycloneDX says which version of the standard it is",
      cdx.get("bomFormat") == "CycloneDX" and cdx.get("specVersion"),
      f"got {cdx.get('bomFormat')!r} {cdx.get('specVersion')!r}")

packages = spdx.get("packages") or []
components = cdx.get("components") or []
check("both formats describe the same number of components",
      len(packages) == len(components),
      f"SPDX has {len(packages)} and CycloneDX has {len(components)}, so one "
      f"of them is describing a different build")


print()
print("  it matches what the build actually uses")

# The generator lives under tools/, which is deliberately not in the
# repository, so a clone has the committed documents and not the thing that
# makes them.  That is a check that cannot run rather than a check that
# failed, and the two must not look alike: reporting a missing file as a
# problem here would have somebody hunting a stale bill of materials that is
# perfectly current.
generator = ROOT / "tools" / "sbom.py"
if not generator.is_file():
    print("    skip  regenerating produces exactly what is committed")
    print(f"          {generator} is not here.  tools/ is kept out of the")
    print("          repository, so this half only runs where it is on disk.")
else:
    run = subprocess.run([sys.executable, str(generator), "--check"],
                         capture_output=True, text=True, cwd=str(ROOT))
    check("regenerating produces exactly what is committed",
          run.returncode == 0,
          "somebody changed a version and did not regenerate, so the committed "
          "documents describe a build that is no longer the one shipped.  "
          "Run: python3 tools/sbom.py\n" + (run.stdout or "").strip())


print()
print("  every version in the installer reached the output")

installer = (ROOT / "nginx-installer.sh").read_text()
listed = {(p.get("name", ""), p.get("versionInfo", "")) for p in packages}
listed_versions = {v for _n, v in listed}

# The pinned version variables.  A new one added to the installer and not
# recognised by the generator would otherwise be silently missing.
for name in re.findall(r'^([A-Z][A-Z0-9_]*_VERSION)="\$\{', installer, re.M):
    value = re.search(rf'^{name}="\$\{{{name}:-([^}}]+)\}}"', installer, re.M)
    if not value:
        continue
    version = value.group(1)
    # With and without a leading v.  HEADERS_MORE_VERSION is 0.40 and the git
    # tag it is fetched at is v0.40, so the documents correctly record the tag
    # and a bare string compare calls a right answer wrong.
    wanted = {version, f"v{version}", version.lstrip("v")}
    check(f"{name} ({version}) is in the bill of materials",
          bool(wanted & listed_versions),
          f"the installer builds with it and the documents do not mention it.  "
          f"Either tools/sbom.py does not know about this component or the "
          f"shape of the line changed.")

# Every third party module the build compiles in.
modules = re.search(r"^THIRD_PARTY_MODULES=\((.*?)^\)", installer, re.M | re.S)
if modules:
    names = [l.split("|")[0].strip().strip('"')
             for l in modules.group(1).split("\n")
             if l.count("|") == 2 and not l.strip().startswith("#")]
    missing = [n for n in names if not any(n == pn for pn, _ in listed)]
    check(f"all {len(names)} compiled in modules are listed",
          not missing,
          f"these are inside the nginx binary people are asked to trust and "
          f"are not in the documents: {missing}")


print()
print("  the three layers are all there")

layers = {}
for c in components:
    for prop in c.get("properties") or []:
        if prop.get("name") == "failoverlb:layer":
            layers.setdefault(prop["value"], []).append(c["name"])

for layer, why in (
    ("application", "the Python packages, which every tool can already see"),
    ("nginx", "the binary this builds from source, which is the part nothing "
              "else can see and the reason this file exists"),
    ("data", "the rule set and the country database, which are not code and "
             "change what the product does"),
):
    check(f"the {layer} layer is present", bool(layers.get(layer)),
          f"missing: {why}")

if layers.get("nginx"):
    print(f"      nginx layer holds {len(layers['nginx'])} components")


print()
print("  what it says about reproducibility")

# Not a failure.  A branch ref is a real property of this build and the honest
# thing is to report it rather than to pretend the build is reproducible or to
# fail a check over a decision somebody made deliberately.
floating = sorted(c["name"] for c in components
                  if c.get("version") in ("master", "main"))
if floating:
    print(f"      {len(floating)} of {len(components)} components track a branch "
          f"rather than a tag:")
    for name in floating:
        print(f"        {name}")
    print("      Two builds of the same commit on different days are therefore")
    print("      not the same binary.  That is a real property of this build and")
    print("      is reported rather than failed, because pinning them is a")
    print("      decision with its own cost: a pinned module stops getting")
    print("      fixes until somebody moves the pin.")
else:
    print("      every component is pinned to a tag or a version")


print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed")
print()
print("  what this does not do:")
print("    - verify a downloaded artefact matches a hash, which needs the")
print("      build to record one and none of them do yet")
print("    - sign anything.  An unsigned bill of materials in a repository")
print("      anybody can fork says what was intended, not what was received")
print("    - look for advisories, which is the dependency scan's job")
print()
print("  RESULT:", "the bill of materials describes this build" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
