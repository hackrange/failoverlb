# Software bill of materials

What this product is made of, in both formats people ask for.

    sbom.spdx.json         SPDX 2.3, which procurement and legal ask for
    sbom.cyclonedx.json    CycloneDX 1.5, which security tooling ingests

Same content, two formats, generated from one pass.  Picking one would mean
half the people who ask cannot use the answer.

## Why this exists here in particular

This tool builds its own nginx from source, with its own OpenSSL, its own
ModSecurity and thirteen outside modules, and then runs that binary on your
load balancer.  Installing this means trusting a binary nobody else compiled,
made of parts nobody has listed.  This is the list.

## Three layers

**application** is the Python that runs the manager.  Every SBOM tool can
already produce this and it is the least interesting part.

**nginx** is the binary this builds.  The version, OpenSSL, ModSecurity, and
every module with the exact git ref it is fetched at.  Nothing generic can see
this, because none of it is a package: it is a shell script that clones and
compiles.

**data** is the OWASP rule set and the country database.  Neither is code and
both change what the product does.  Neither carries a version here, because
both are fetched at run time on a schedule, so the version on a node is a
property of that node rather than of this release.  The GUI reports what each
node actually has.

## Regenerating

    python3 tools/sbom.py            rewrite these files
    python3 tools/sbom.py --check    fail if they are out of date

Everything is parsed out of `nginx-installer.sh` and `requirements.txt` when it
runs.  Nothing here is typed by hand, because a bill of materials maintained by
hand is wrong by the second release, and wrong in the direction that matters:
it says you shipped something you did not.  `checks/sbom.py` fails when the
committed files and the sources disagree.

The timestamps inside are fixed rather than set to the time of generation, so
the documents are a function of the commit and nothing else.  A file that
changes every time it is built cannot be committed or diffed.

## What these do not tell you

**Nine of the forty five components track a branch rather than a tag**, so two
builds of the same commit on different days are not the same binary.  That is a
real property of this build and is reported rather than hidden.  Pinning them
has its own cost: a pinned module stops getting fixes until somebody moves the
pin.

**Nothing here is signed, and no artefact is checked against a hash.**  An
unsigned bill of materials in a repository anybody can fork tells you what was
intended, not what you received.  That is a gap, and it is written down rather
than glossed over.

**These do not look for known vulnerabilities.**  Feed them to a scanner for
that; the point of this file is to make that possible.

## Licences

Every component carries one, in both formats, and none of it is from memory.
Each entry was read off the thing itself: a Python package's own installed
metadata and the licence file it ships, the `LICENSE` or `COPYING` file in each
nginx module's source tree, and the rule set's own licence file.

Run `python3 tools/sbom.py --licence-evidence` on a node that has built nginx
to re-derive the table from those same sources and report anything that no
longer agrees.  It is written down, and anything written down goes stale.

Two entries are deliberately not an identifier, and they are the two worth
looking at:

- **`upstream-fair` ships no licence at all.**  Not an unrecognised one, none:
  a copyright line, a note that it is based on nginx source, and nothing
  granting anybody the right to use it.  It is compiled into the nginx binary
  this product installs.  That is a real question for whoever is signing off
  the estate, and it is recorded as NOASSERTION rather than smoothed over.
- **`geolite2-country` is MaxMind's own end user agreement**, not an open
  source licence.  This product does not redistribute it; it is fetched at run
  time by whoever runs the fleet, who accepts those terms.

The base image is a Debian based image holding hundreds of packages under their
own terms.  One identifier would be a lie, so it says NOASSERTION and points at
the image.

Two components could not be concluded from metadata alone and were read from
their licence files instead: `cryptography`, which is dual licensed, and
`pycryptodomex`, which is partly public domain and partly BSD.
