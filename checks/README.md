# Checks

Things that run against a real installed fleet and say whether it works.

These ship.  That is the difference between this folder and `test/`, which is
ignored on purpose and is where the old throwaway docker rig lived.  The names
are one letter apart, which is a trap, so it is worth saying plainly: anything
you want to keep goes in here, and anything in `test/` will be silently left out
of every commit.

## What belongs here

Checks that need a real box.  This project's bugs do not live in the renderer
producing a string, they live where the software meets a real host, a real
certificate authority, a real backend.  So these talk to the running agent, put
config through the real nginx, and make real requests.

Anything that can be answered without a host does not need to be here.

## What they must not do

**Never apply.**  Everything here stages config and tests it.  A check that
applies is a check that can take a site down, and nobody will run it twice.

**Never leave anything behind.**  Scratch objects live inside a transaction that
gets rolled back, or are removed before the run ends.  A check that pollutes the
database is worse than no check, because the next person inherits state nobody
meant to create.

**Never point at a real account.**  Anything exercising sign in enrols TOTP and
changes passwords.  Use a throwaway.

## Running them

From the box, inside the container, so they reach the agent socket and the same
database the manager uses:

```bash
docker exec -i nginx-fleet-manager python < checks/catalog_sweep.py
```

**One exception: `rollback.py` runs on the host**, not in the container.

```bash
python3 checks/rollback.py
```

It checks the host agent, which is the half of this system that lives outside
docker, and it loads the deployed `/opt/nginx-fleet-manager/nginx-mgr-agent.py`
by path rather than the copy in the checkout.  That is deliberate: a node whose
git is current while its agent was never replaced is a real thing that has
happened here, and reading the file the service actually runs is the only way to
catch it.

## What is here

| Check | What it proves |
|---|---|
| `catalog_sweep.py` | Every catalog setting renders config that real nginx loads, one at a time and all together. |
| `page_sweep.py` | Every page and read only endpoint answers without raising, signed in. |
| `regressions.py` | Every bug that has already cost a day, re-checked without applying anything. |
| `authz_sweep.py` | A viewer cannot write, an operator cannot do admin things, and a write with no token or a forged one is refused. |
| `health_checks.py` | The checker calls a backend up or down correctly, against real sockets that misbehave on purpose. |
| `upgrade_migration.py` | A database made by an older version upgrades cleanly and keeps its rows. |
| `parser.py` | Real nginx config parses, including the parts a regex gets wrong, and survives a round trip. |
| `render_safety.py` | A setting cannot write config of its own, and a missing certificate or an empty pool costs one site rather than the fleet. |
| `trust.py` | Peer signatures, secret comparison, encryption at rest, key and certificate pairing, and the audit log keeping secrets out of itself. |
| `templates.py` | A page that looks finished and does nothing: unclosed blocks, a form with no token, a button wired to nothing. |
| `users_page.py` | Changing a role, deleting an account, and refusing both when the target is yourself. |
| `geo_blocking.py` | Blocking by country, including the two defects that reached a fleet because both looked like they worked. |
| `tunnel_addresses.py` | A tunnel address is handed out once and never to two machines, including after a workload is removed. |
| `waf.py` | The WAF from the setting through to config nginx will load, with the exclusions in the order the rules need them. |
| `wiring.py` | Every setting reaches the rendered config, by walking the model fields rather than by anybody remembering to check. |
| `auth_modes.py` | The three ways in, the refusal path when local passwords are off, and that the sign in settings travel in the config snapshot. |
| `login_watch.py` | Brute force and password spray detection: that a spray is called, that the three ordinary Monday shapes are not, and that the slow version has its own thresholds. |
| `sbom.py` | The bill of materials still describes what this builds: regenerating matches what is committed, every version in the installer reached it, and all three layers are there. |
| `accepted_risks.py` | The seven advisories we decided not to patch, and whether the grounds still hold: that nothing calls the vulnerable APIs, the internet facing app serves no files or forms, and the allow list is neither empty nor wide. |
| `gslb_listener.py` | The DNS listener comes back after being stopped, rather than holding the port and never binding again. |
| `rollback.py` | A rollback to an archive nginx will not load leaves the node exactly as it was, rather than parking a broken config that only shows up at the next restart.  Runs on the host, see below. |
| `standby_message.py` | A refused apply says which of the three reasons it was, so nobody is sent to an active node that does not exist yet. |
| `adaptive_weights.py` | Weights move a little at a time or not at all: off unless asked for, left alone when everything is slow or the spread is noise, and never past the floor or the ceiling. |
| `default_site.py` | A second default site is refused rather than stopping every apply on the fleet. |
| `comparison.py` | The feature comparison holds together and has not turned into a brochure: every row scores every product, the totals match the data, and we still lose the rows we lose. |

## Proving a check would fail

Reading a check tells you what it claims.  Running it tells you it passes.
Neither tells you it would fail if the product were broken, and that is the
only question worth asking of a test.

`tools/mutation/` breaks one thing on purpose and runs one check against it.  A
check that still passes is the finding.  Three checks in here were passing for
the wrong reason before anybody went looking, and none of them was found by
reading:

- every role check in `authz_sweep.py` was proving the CSRF guard rather than
  the permission model, because TestClient never sent the cookie back
- `waf.py` and `default_site.py` each tested everything around a fix and
  nothing about the fix, so removing it changed no answer
- `trust.py` checked that the constant time comparison gave the right answers,
  which a plain `==` also does

It also found a feature with no check at all: adaptive weights, which moves
traffic between backends and had nothing watching it.

Run it before believing a check you have just written:

```bash
python3 tools/mutation/mutate.py
```

## A pass that touched nothing is not a pass

Three of these suites reported green while testing nothing, on their first run,
in three different ways.  It is the failure mode to watch for:

- the test client's address is the literal string `testclient`, which is in no
  allow list, so every request came back 404 and every check "passed"
- a path that does not exist gives a 404 that reads exactly like a refusal
- an incomplete request body is rejected by validation before the handler runs,
  so a permission check that never fired looks like one that refused
- searching the rendered config for a string finds it inside a quoted value,
  where it is harmless, and calls that an injection.  Ask the parser whether
  nginx would read it as config, rather than asking whether the text is there

Each of those is now caught by the check itself.  When you add one, make it
prove it reached the thing it claims to be testing.

## What is not here yet

The rest of the pass is in the project notes.  Most of it needs a person driving a
browser: every page and button, the sign in and lockout flow, the certificate
lifecycle, an upgrade over an older install.  Those are not automated and the
plan says so rather than pretending the gap does not exist.
