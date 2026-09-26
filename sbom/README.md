# Software bill of materials

What this product is made of, in the two common formats.

    sbom.spdx.json         SPDX 2.3, which procurement and legal ask for
    sbom.cyclonedx.json    CycloneDX 1.5, which security tooling ingests

Same content in both, generated from one pass.

## Why this exists

This tool builds its own nginx from source, with its own OpenSSL, its own
ModSecurity and thirteen outside modules, and runs that binary on your load
balancer.  Installing it means trusting a binary nobody else compiled.  This
is the list of what went into it.

## Three layers

**application** is the Python that runs the manager.  Any SBOM tool can
produce this part.

**nginx** is the binary this builds: the version, OpenSSL, ModSecurity, and
every module with the exact git ref it is fetched at.  Generic tools can't see
this, because none of it is a package; it is a shell script that clones and
compiles.

**data** is the OWASP rule set and the country database.  Neither is code, but
both change what the product does.  Neither carries a version here, because
both are fetched at run time on a schedule, so the version is a property of
each node rather than of this release.  The GUI reports what each node has.

## Regenerating

    python3 tools/sbom.py            rewrite these files
    python3 tools/sbom.py --check    fail if they are out of date

The generator lives outside this repository.  It parses everything out of
`nginx-installer.sh` and `requirements.txt`; nothing here is typed by hand,
since a hand-maintained SBOM goes stale and ends up claiming you shipped
something you didn't.  A check fails when the committed files and the sources
disagree.

Timestamps inside are fixed rather than set at generation time, so the output
depends only on the commit and diffs cleanly.

## Limitations

**Nine of the forty five components track a branch rather than a tag**, so two
builds of the same commit on different days are not the same binary.  Pinning
them has its own cost: a pinned module stops getting fixes until somebody
moves the pin.

**Nothing here is signed, and no artifact is checked against a hash.**  An
unsigned SBOM in a repository anybody can fork tells you what was intended,
not what you received.

**These do not look for known vulnerabilities.**  Feed them to a scanner for
that.

## Licenses

Every component carries one, in both formats, read off the component itself:
a Python package's installed metadata and the license file it ships, the
`LICENSE` or `COPYING` file in each nginx module's source tree, and the rule
set's own license file.

Run `python3 tools/sbom.py --licence-evidence` on a node that has built nginx
to re-derive the table from those same sources and report anything that no
longer agrees.

Two entries are deliberately not an identifier, and they are the two worth
looking at:

- **`upstream-fair` ships no license at all.**  There is a copyright line and a
  note that it is based on nginx source, but nothing granting a right to use
  it.  It is compiled into the nginx binary this product installs, so whoever
  signs off on the deployment should know.  It is recorded as NOASSERTION.
- **`geolite2-country` is under MaxMind's end user agreement**, not an open
  source license.  This product does not redistribute it; it is fetched at run
  time by whoever runs the fleet, who accepts those terms.

The base image is Debian based and holds hundreds of packages under their own
terms, so it says NOASSERTION and points at the image.

Two components could not be resolved from metadata alone and were read from
their license files instead: `cryptography`, which is dual licensed, and
`pycryptodomex`, which is partly public domain and partly BSD.
