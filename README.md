# NGINX Fleet Manager

A web GUI for running two or more nginx boxes as one unit.  Sites, backend
pools with real health checks, and Lets Encrypt certificates that work properly
in a cluster.

It is built to sit on top of nginx built from source by
`../nginx_installer/nginx-installer.sh`, and it follows that layout: sites in
their own files, certbot in webroot mode, no distro nginx package anywhere near
the binary.

## What it does

**Runs your whole fleet as one thing.**  Every box runs the same container.  One
is ACTIVE and takes the writes, the rest stay in sync and can take over.  There
is no separate controller to lose.

**Never lets a bad config out.**  Every change is staged and run through
`nginx -t` on every node *before* any node applies it.  If one node says no,
nothing changes anywhere.  If a node fails during the apply, the whole fleet
rolls back together.  A pooched config cannot stop nginx from starting.

**Does not forget a node that was down.**  A box that was offline during a
change gets the change written into its queue and is caught up when it comes
back, so it never quietly drifts.

**Health checks your backends for real.**  The free nginx only notices a dead
backend after a user already got the error.  This probes every backend on a
schedule from every node, and rewrites the upstream with the bad one marked
down.  That is the paid version's headline feature, done from out here.

**Gets certificates right in a cluster.**  This is the fiddly one.  Only the
node that currently owns the public address can answer an http-01 challenge,
and which node that is changes when you fail over.  So we work it out fresh at
every renewal, run certbot there, and copy the files to everybody else.  The
challenge token goes to every node before validation starts, so it does not
matter which one Lets Encrypt actually connects to.

**Only offers what your nginx can actually do.**  It reads `nginx -V` off each
box and works out which modules are compiled in.  Settings for a module you do
not have are simply not there.  Paid-only features are not offered at all, and
where there is a free way to get the same result, the help text says what it is.

## What is here right now

This is a work in progress.  Being straight about where it is:

### Done and tested

| Piece | File | What it is |
|---|---|---|
| Host agent | `host-agent/nginx-mgr-agent.py` | The root daemon.  Fixed verb list, path allow list, staged apply with rollback. |
| Agent hardening | `host-agent/nginx-mgr-agent.service` | systemd unit that gives it root and takes nearly everything else away. |
| Data model | `app/models.py` | Nodes, sites, pools, members, certs, users, audit, config versions, change queue. |
| Feature catalog | `app/catalog/` | Every nginx setting we offer, with help text, examples, validation and OSS/Plus gating. |
| Config parser | `app/core/nginx_parser.py` | Real tokenizer and parser.  Reads hand edited config back into GUI settings. |
| Config renderer | `app/core/render.py` | Turns the database into nginx config files. |
| Health checker | `app/core/health.py` | Active checks, slow start, adaptive weighting. |
| Cluster | `app/core/cluster.py` | Trust group, election with quorum, two phase apply, change queue. |
| Certificates | `app/core/acme.py` | Issuer selection, cluster wide challenge, replication, renewal scheduling. |
| Crypto | `app/core/crypto.py` | Cluster CA, node certs, secrets at rest, message signing. |
| Docker setup | `docker_setup.sh` | Docker CE on Ubuntu 22.04+, done properly. |
| Plus parity notes | `docs/plus-parity.md` | Every paid feature, and what we built instead. |

The config parser has been run against realistic nginx config and correctly
handles the things that break naive parsers: `server` meaning two different
things depending on context, braces and semicolons inside quoted strings, and
round tripping without losing hand written directives.

| Auth | `app/auth/` | Local break glass accounts with mandatory TOTP, plus OIDC with PKCE. |
| Web GUI and API | `app/web/` | Server rendered pages, JSON API, help modals, no build step. |
| Test harness | `test/` | Two Ubuntu 26.04 nodes with nginx built from source, plus the managers. |

**It runs.**  `test/run-test-cluster.sh up` brings up a working two node cluster
and 75 end to end tests pass against it.

### Still to come

| Piece | Notes |
|---|---|
| `install.sh` | Per node installer that lays down the agent and starts the container. |
| `nginx-gui-mgmt_setup.sh` | One shot install from the git repo into `/data/docker/nginx-gui-mgmt`. |
| nginx version upgrade | Driving the installer script remotely, one node at a time. |
| ACME against a real server | The flow is written.  It has not been run against Lets Encrypt or Pebble yet. |
| Editing pages | Sites and pools can be created and changed through the API.  The GUI has create forms but not full edit forms yet. |

## Testing

```bash
./test/run-test-cluster.sh up      # two nginx nodes plus two managers, isolated
docker cp test/e2e_test.py nfm-gui-1:/tmp/
docker exec -e E2E_PASSWORD=<the password from the log> nfm-gui-1 python /tmp/e2e_test.py
./test/run-test-cluster.sh down
```

Nothing in the harness touches the host's nginx.  It runs on its own bridge
network, publishes no ports, and mounts no host paths.

The tests are worth reading before you trust them.  An earlier version passed
while the login page was completely broken in a browser, because the test read
the CSRF token from the cookie instead of from the rendered form and was
helpfully supplying something the page never sent.  The suite now scrapes tokens
out of the HTML the way a browser does, and it covers both the first login and
the repeat login, which are different code paths.

## How the security works

Worth understanding before you install this anywhere.

**The container is not trusted.**  It runs as uid 10001, drops every capability,
and has a read only filesystem.  It cannot write `/etc/nginx` and it cannot
restart anything.

**The host agent is the boundary.**  It runs as root because the job needs root,
and it is deliberately small enough to read start to finish.  It accepts a fixed
list of verbs over a unix socket.  There is no "run this command" verb.  Every
path is resolved, symlinks and all, and checked against an allow list before
anything is touched.

**The peer port is not open.**  Three separate things have to line up: a client
certificate signed by this cluster's own CA and nothing else, a source address
on the node roster, and an HMAC signature made with a key only that node holds.
The timestamp and a nonce are inside the signed part, so a captured request
cannot be replayed.  A browser hitting that port gets nowhere.

**The GUI has its own allow list.**  `NFM_ADMIN_ALLOWLIST` is checked before the
login page even renders, so a stolen password from the wrong network still gets
nothing.

## Getting started

```bash
# 1. Docker, if it is not already there
sudo bash docker_setup.sh

# 2. Settings
cp .env.example .env
$EDITOR .env          # node name, address, and a secret key

# 3. Make a secret key
openssl rand -base64 48
```

Do not run this on a box with an nginx you care about until the install script
exists.  The compose file uses host networking and bind mounts `/etc/nginx`, and
the agent reloads the nginx service.

## Layout

```
nginx_manage/
├── app/
│   ├── catalog/          every setting, with its help text and rules
│   ├── core/             the engine: cluster, health, certs, render, parse
│   ├── models.py         database tables
│   ├── config.py         settings from the environment
│   └── db.py             sqlite setup
├── host-agent/           the root daemon, runs outside the container
├── docs/                 plus-parity.md and friends
├── docker_setup.sh       Docker CE on Ubuntu
├── docker-compose.yml
├── Dockerfile
└── .env.example
```

## Ports

| Port | What |
|---|---|
| 7443 | The web GUI |
| 7444 | Node to node.  Needs a cluster certificate.  Firewall it to your peers. |
| 7081 | `stub_status`, bound to localhost only, for the dashboard |

## Why sqlite

Every node keeps its own full copy of the config and the nodes sync to each
other.  Adding postgres would mean one more thing that has to be up before you
can manage your load balancers, which is exactly backwards.  When something is
broken at 3am you still need to get in and fix nginx.
