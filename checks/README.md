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

## What is here

| Check | What it proves |
|---|---|
| `catalog_sweep.py` | Every catalog setting renders config that real nginx loads, one at a time and all together. |

## What is not here yet

The rest of the pass in `.claude/PLAN.md`.  Most of it needs a person driving a
browser: every page and button, the sign in and lockout flow, the certificate
lifecycle, an upgrade over an older install.  Those are not automated and the
plan says so rather than pretending the gap does not exist.
