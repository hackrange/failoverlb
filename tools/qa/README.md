# The applying test pass

Suites that drive the real GUI in a real browser, **apply configuration for
real**, and then put real traffic through nginx.

## Why this is not in `checks/`

`checks/` has a rule, written at the top of its own README: *never apply*.  That
rule is right for what lives there, and it is also the reason those suites could
not catch the three worst defects found by this pass.  Two of them stopped the
entire fleet applying any configuration at all, and neither is visible until
something calls apply.

So these live here instead, under their own contract:

- **They apply.**  That is the point.
- **They need a fleet you are willing to disturb.**  They create sites, apply
  them, take backends away to force a failover, and move the active role.
- **They clean up after themselves.**  `cleanup.py` removes every object, and
  the run is designed so that what it leaves behind is nothing.

Never point them at a fleet carrying real traffic.

## Running them

They need a browser and python-docx, which is what the `nfm-docs` image already
has, and a fleet to talk to.

```bash
docker run --rm --network host -v "$PWD/tools/qa:/qa" \
  -e NFM_URL=https://127.0.0.1:7443 \
  -e NFM_USER=<a throwaway admin> \
  -e NFM_PASSWORD=<its password> \
  -e NFM_TOTP=<its totp secret, base32> \
  nfm-docs:latest python /qa/t03_sites.py
```

Run them in order.  `t15_failover.py` moves the active role and is deliberately
last.

Two things it needs that the others do not.  The account it signs in as has to
exist on **every** node, because accounts replicate outward from whichever node
is active, so a role change will otherwise remove an account that was only ever
made on one of them and the suite loses its session half way through.  And the
static tests in `t03` and `t04` need a directory of files on every node, which
`QA_STATIC_DIR` points at:

```bash
mkdir -p /var/www/qa-static/sub
echo '<h1>QA static site</h1>' > /var/www/qa-static/index.html
echo 'body { color: #abcdef }' > /var/www/qa-static/style.css
echo '<h1>a page in a subdirectory</h1>' > /var/www/qa-static/sub/page.html
head -c 40000 /dev/urandom > /var/www/qa-static/blob.bin
chmod -R a+rX /var/www/qa-static
```

## What is here

| File | What it covers |
|---|---|
| `qa.py` | The harness: sign in, drive the page, probe HTTP, TLS and DNS, record evidence. |
| `t01_settings.py` | Fleet settings, and that saving one card leaves the others alone. |
| `t02_pools.py` | Pools, weights, backup servers, health checking, real failover between backends. |
| `t03_sites.py` | Static, redirect and proxy sites, certificates, HTTP/2, extra names, switching a site off. |
| `t04_paths.py` | Match types and precedence, stripping a prefix, deny, static paths, the dialog round trip. |
| `t05_catalog.py` | Every site setting and every path setting, saved and read back, and the values that are refused. |
| `t06_mount_traffic.py` | Mounting a whole site under a path, upload limits, compression, security headers, blocks. |
| `t07_zones.py` | Rate limits, bursts, caching and connection limits, each proven by a burst of real requests. |
| `t08_behaviour2.py` | Rewrites, content rewriting, redirect and cookie rewriting, websockets, timeouts, CORS. |
| `t09_pages_admin.py` | Error page templates, raw config mode, cloning, odd ports, deleting. |
| `t10_geo_login.py` | Installing the country database on every node, blocking a country, login watching. |
| `t11_import_repair.py` | Importing a config nginx would refuse, and repairing one that will not load. |
| `t12_versions_certs.py` | Pending changes, rollback to a named version, backups, uploaded certificates, signing requests. |
| `t13_maps_streams_cluster.py` | Maps, plain TCP proxying, and both nodes really holding the same config. |
| `t14_gslb.py` | DNS zones, records, answers, and real UDP queries against the fleet's own server. |
| `t15_failover.py` | Moving the active role by hand, watched second by second. |
| `report.py` | Turns the evidence into the test plan document. |
| `cleanup.py` | Removes everything a run created. |

## The trap to watch for

Three checks in this pass reported green while testing nothing, in three
different ways: a config file read by the wrong name, a disabled site that
renders no config at all, and a helper returning a truthy "not found" string so
a fallback was never reached.  Each is now guarded.  When you add a suite, make
it prove it reached the thing it claims to be testing.
