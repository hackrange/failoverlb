# Documentation

## The user guide

**[Failover-LB-User-Guide.docx](Failover-LB-User-Guide.docx)**

A complete guide to installing and running Failover LB, written for
somebody who has been handed a pair of servers and asked to put a load balancer
on them.  You do not need to have run one before.

Forty one chapters and three appendices.  Open it in Word and the contents page
fills itself in, so every heading becomes a link you can click.

### What is in it

| Part | Chapters | Covers |
|---|---|---|
| 1  | 1 to 7   | From two empty servers to signed in and looking around |
| 2  | 8 to 17  | The everyday work: pools, sites, paths, certificates, error pages, limits, maps, TCP and UDP, applying changes, utilization |
| 3  | 18 to 22 | Running two servers as a pair, DNS failover, the nginx build, upgrades |
| 4  | 23 to 25 | Users and roles, backup and recovery, what to do when something is wrong |
| 5  | 26 to 28 | Worked examples: putting a site live, DNS failover end to end, taking a server out for maintenance |
| 6  | 29 to 30 | The site and pool screens, control by control |
| 7  | 31       | Importing an existing nginx configuration |
| 8  | 32 to 33 | Settings, and your own account |
| 9  | 34 to 35 | The nginx build screen, and what the paid nginx has that this does not |
| 10 | 36       | Every dialog, field by field |
| 11 | 37       | The tunnel, for a backend with no public address |
| 12 | 38       | Certificates from a paid authority |
| 13 | 39       | Backup and restore, in full |
| 14 | 40 to 41 | How DNS failover works, and how big the servers need to be |
|    | Appendices | Ports, files and folders, glossary |

### Where to start

Installing for the first time, start at Chapter 1 and read Part 1 in order.
It takes about half an hour including the waiting.

Already running and want to get something done, go to Chapter 26.  It works
through putting a site live from beginning to end and touches most of what you
need.

Moving from an existing nginx, read Chapter 31 first.  It can read your current
configuration and show you what it would become without changing anything.

Something is broken, Chapter 25 is a list of things that go wrong, what they
look like, and what to do, in rough order of how often they happen.

### About the pictures

Every screenshot is of the software actually running.  Anything drawn on top in
red was added for the guide and is not on your screen.

The example domain throughout is `example.net` and the two servers are
`lb-01` and `lb-02`.  Substitute your own.

## Other documents

**[plus-parity.md](plus-parity.md)** lists the features that exist only in the
paid nginx subscription, and what this software does instead.  Chapter 35 of
the guide covers the same ground in plainer language.

## The rename

The software was called NGINX Management until August 2026.  The guide has been
rebuilt since: the text says Failover LB throughout, and every screenshot was
taken again against a node running the new build, so the name and the new look
are what you see in the pictures.  The one place the old name survives on
purpose is the nginx build screen, which is called NGINX® Build because that is
what the software it builds is called.

## Trademarks

NGINX® is a registered trademark of F5, Inc.  NGINX Plus is a trademark of
F5, Inc.  Failover LB is an independent project and is not affiliated with,
endorsed by, or sponsored by F5, Inc.

The same notice is on the guide's own cover and in Chapter 1.

## Keeping it up to date

The guide is generated from source rather than written as a document, so it can
be rebuilt as the software changes rather than drifting away from it.  The
tooling that builds it is kept outside this repository, because it is of no use
to anybody running the software.

If a feature has changed and the guide is now wrong, ask whoever maintains the
guide to rebuild it.  Do not edit the `.docx` by hand: it is overwritten every
time the guide is rebuilt.
