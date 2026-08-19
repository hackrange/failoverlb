# Mutation testing

Break the thing on purpose, and see whether its check notices.

This exists because reading a check tells you what it *claims*.  Running it
tells you it passes.  Neither tells you it would fail if the product were
broken, and that is the only question worth asking of a test.

Three checks in this project were passing for the wrong reason before anybody
went looking:

- every role check in `authz_sweep.py` was proving the CSRF guard, because
  `TestClient` never sent the cookie back and the checks read any 403 as a
  refusal
- "the site denies everything" was true of a site that denied nobody, because
  every site config already contains a `deny all` inside the block that hides
  dotfiles
- the WAF suite's idea of ordinary traffic was four tidy GETs, so it passed a
  claim that production disproved the same week

None of those were found by reading.  All of them were found by asking what
would still pass if the behaviour were removed.

## Running it

```bash
python3 tools/mutation/mutate.py            # every mutation
python3 tools/mutation/mutate.py waf        # ones whose name or check matches
```

Each mutation copies `app/`, `checks/` and `host-agent/` to a temporary tree,
applies one surgical edit, and runs one check against it.  A check that still
passes is reported as **BLIND** and is the finding.

## Two things it is careful about

**A mutation that does not apply is reported, not counted.**  A find string
that stops matching after a refactor would otherwise look exactly like a check
that caught nothing.

**It runs against a copy of the database.**  A mutation that turns a refusal
into a success does not just make a check pass, it makes the write happen: the
first run of this gave a viewer `edit_pools` and left a real pool and a real
site in the fleet's database.  A tool for finding checks that lie must not
leave litter of its own.  The copy is made with sqlite's backup API rather
than a file copy, because recent writes sit in the write ahead log and a copy
of the `.db` alone is the database as of some earlier moment.

## Adding one

A tuple of `(name, check, file, find, replace)`.  Aim at what the check
**claims**, not at whatever is nearby: an early attempt pointed at the adaptive
weight code and blamed `health_checks.py` for not noticing, when that check
never claimed to cover it.  The right answer there was a new check.

A mutation that is caught proves the check works.  A mutation that is not
caught is either a blind check or a missing one, and it is worth working out
which before writing anything.
