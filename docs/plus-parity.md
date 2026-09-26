# What the paid NGINX&reg; subscription gives you, and what we built instead

NGINX&reg; comes in two versions.  The free one, which is what the installer builds,
and NGINX Plus, which is a paid subscription.  Plus adds a set of features that
are genuinely useful for load balancing, and a lot of the reason people pay for
it is that list.

These boxes are not licensed.  So for every Plus feature that matters to a load
balancer, we either built our own version of it in the manager or we say plainly
that we could not.

The short version: almost all of it is doable from out here.  Plus does these
things inside the nginx process.  We do them from the manager, by watching what
is going on and rewriting the config when something changes.  A config reload in
nginx is graceful, old workers finish their requests while new ones pick up the
new config, so doing it this way does not drop traffic.

Turn these on from **Settings, Open Source Parity**.  They are off by default so
nothing surprises you.

---

## What we rebuilt

### Active health checks

**Plus does:** `health_check` inside a location block.  nginx itself probes each
backend on a timer and stops sending traffic to ones that fail.

**Free nginx does:** passive checks only.  `max_fails` and `fail_timeout` notice
a backend is bad after a real request to it already failed.  Somebody had to get
an error first.

**What we built:** the manager probes every backend on a schedule from each
node, on its own, whether or not anybody is browsing the site.  When a backend
fails enough checks in a row it gets rewritten into the upstream with `down` on
it and nginx reloads.  When it comes back and passes enough checks, the `down`
comes off.

You get to set the same things Plus lets you set: interval, timeout, how many
passes to come back up, how many fails to go down, which status codes count as
healthy, and a string that has to appear in the body.

One thing this does that Plus does not: every node checks the backends
separately and we keep the answers apart.  A backend that node A can reach and
node B cannot is a routing or firewall problem, and seeing it split out that way
usually tells you the answer immediately.

**Setup:** Pools, pick a pool, Health Check tab.

---

### Sticky sessions

**Plus does:** `sticky cookie srv_id`.  nginx sets its own cookie and reads it
back to send the same user to the same backend every time.

**Free nginx does:** `ip_hash`, which pins on the client address, and `hash`,
which pins on anything you can name.  Neither one sets a cookie for you.

**What we built:** the manager generates the cookie half.  You turn on sticky
sessions for a pool and it writes out two `map` blocks, one that reads the route
cookie for the upstream to hash on and one that decides whether this client
needs a cookie at all, plus an upstream that hashes with `consistent` on.

A user gets a cookie on their first request and lands on the same backend after
that.  The very first request is the exception: there is no cookie yet, so it
goes wherever the client's address hashes to, and the cookie takes over from the
second request onward.  Plus behaves the same way for the same reason.

**Two things about the cookie that are not obvious:**

The value has to be *stable* and does not have to mean anything.  It is a
request id.  What makes a client stick is the same string coming back every
time, not what the string says.  Writing the backend's own address in there
seems natural and is actively harmful: the hash of an address does not land on
that address, it lands wherever it lands, so the next response writes a
different backend into the cookie and the client walks around the pool one
request at a time.

And it must only be set when the client does not already have one.  Setting it
on every response overwrites the route they were given, every time, which undoes
the whole thing.

`consistent` matters and is worth knowing about.  Without it, taking one backend
out of a pool of four reshuffles roughly everybody.  With it, only the users who
were on that one backend move.  Everybody else stays put and never notices.

**Better still:** the real fix is to not need sticky sessions.  Put
sessions in redis or your database and any backend can serve any user.  Then you
can take servers out whenever you want.  Sticky sessions are a workaround for
apps that keep session state in local memory, and they come with a real cost:
one backend dying logs out everybody who was on it.

**Setup:** Pools, pick a pool, Load Balancing tab, Sticky Sessions.

---

### Slow start

**Plus does:** `slow_start=30s` on a server.  A backend that just came back gets
its traffic eased on over that window instead of all at once.

**Free nginx does:** nothing.  A recovered backend immediately gets its full
share.

**Why it matters:** a JVM app that just restarted has a cold JIT, an empty
connection pool and a cold cache.  Hit it with a third of your traffic in one
go and it can fall straight back over.  Then it comes back, gets slammed again,
and falls over again.  That flapping is worse than the server just staying down.

**What we built:** the manager ramps the weight.  A backend that comes back
healthy goes in at weight 1, and over your chosen window the weight climbs in
steps until it reaches what you configured.  Each step is a config rewrite and
a reload.

It is not as smooth as what Plus does inside the process, since it moves in
steps rather than continuously.  In practice a handful of steps over 30 to 60
seconds does the job, because the point is just to not hit a cold server with
everything at once.

**Setup:** Pools, pick a pool, Health Check tab, Slow Start.

---

### Least time load balancing

**Plus does:** `least_time`, which sends each request to whichever backend is
answering fastest right now.

**Free nginx does:** `least_conn`, which sends to whichever has the fewest open
connections.  That tracks speed pretty well on its own, since a slow server
piles up connections.

**What we built:** adaptive weighting.  The manager is already timing every
health check, so it knows which backends are slow.  Turn this on and it
periodically adjusts each member's weight based on its recent average response
time.  A backend answering in 20ms ends up with a higher weight than one taking
200ms, so it gets more of the traffic.

Two safety rails on it, because a feature that automatically changes traffic
distribution can make a bad situation worse:

- Weights only move a little each cycle, and there is a floor and a ceiling.
  One slow check cannot take a server out of rotation.
- If every backend is slow, nothing changes.  Everything being slow means the
  problem is downstream of the pool, and shifting weights around would just
  concentrate the load somewhere.

**Comparison:** Plus reacts per request.  Ours reacts on a cycle, so it
is minutes not milliseconds.  For backends that are consistently different
speeds, like a mixed hardware pool, it works well.  For traffic that spikes in
seconds, `least_conn` on its own reacts faster and you should just use that.

**Setup:** Pools, pick a pool, Load Balancing tab, Adaptive Weighting.

---

### The live activity dashboard (not built)

**This section describes something that does not exist yet.**  It is the
planned design; nothing below is in the product today.

There is a `log_parsing_enabled` setting in the database, but nothing reads it.
There is no log tailer, no `stub_status` scraper and no dashboard page.

**Plus does:** `ngx_http_api_module` and the status dashboard.  Live numbers per
server zone and per upstream, request rates, response codes, latency.

**Free nginx does:** `stub_status`, which gives you seven numbers for the whole
server.  Active connections, accepts, handled, requests, reading, writing,
waiting.  That is it.  Nothing per site and nothing per backend.

**What it should do:** read two sources and put them together.

`stub_status` gives the connection level picture, and the manager scrapes it on
a timer, so you get the same numbers with history behind them instead of just
this instant.

For the per site and per backend numbers, the manager tails the access log.  The
log format we generate includes `$upstream_addr`, `$upstream_response_time`,
`$request_time`, `$status` and `$upstream_cache_status`, which is everything you
need.  From that we work out, per site and per backend:

- requests per second, over a rolling window
- the status code mix, so a spike in 5xx is obvious
- response time at p50, p95 and p99, which is far more useful than an average
- cache hit rate
- which backend actually served each request

**How this compares:** the numbers come from completed requests, so the
dashboard is a few seconds behind rather than live to the millisecond.  For
watching a deploy or working out which backend is slow, a few seconds behind is
fine.  Where Plus wins is that it also shows in-flight requests, which a log
cannot show you because the line is not written until the request finishes.

**Cost:** parsing logs takes some CPU.  On a busy box it would be worth
watching, and there should be a way to keep the `stub_status` numbers and turn
the log parsing off.

**Setup:** nothing to set up, because none of it exists yet.  The log format the
manager already writes has everything it would need, which is the one part of
this that is done.

---

### Key-value store

**Plus does:** `keyval`, a lookup table you can change over the API without a
reload.  People use it for dynamic blocklists, feature flags and redirect maps.

**Free nginx does:** `map`, which does the same lookup but is read from the
config at load time.

**What we built:** managed map files.  You edit key-value pairs in the GUI or
push them over our API, and the manager writes the map file and reloads.  From
nginx's side it is a normal `map`, so it is fast.

**The difference:** Plus updates take effect with no reload.  Ours need one.  A
reload is cheap and graceful, but it is not free, so this is a poor fit for
something you would update thousands of times a minute.  For a blocklist you
update a few times an hour, it is exactly as good.

**Setup:** Maps, then New Key-Value Map.

---

### JWT validation

**Plus does:** `auth_jwt`, validating a token at the edge before the request
ever reaches your backend.

**Free nginx does:** `auth_request`, which asks another endpoint whether to
allow the request.

**What we built:** two options, pick whichever fits.

The simple one uses `auth_request` pointed at a small validation endpoint the
manager serves.  Nothing extra to install.  The cost is a subrequest per
request, so on a very high volume API you will feel it.

The faster one uses lua, which the installer already compiles in.  The manager
generates a lua block that checks the signature and the claims inside nginx
itself, no subrequest at all.  Supports HS256 and RS256, checks expiry, and can
require specific claims.

**Setup:** Sites, pick a site, Security tab, JWT Validation.

---

## What we did not rebuild

**HLS, DASH and f4f streaming.** These are `ngx_http_hls_module` and friends,
compiled into the nginx binary, and there is no way to add them from out here.
If you need packaged video streaming, that is a genuine reason to buy Plus, or
to put something else in front of it.

**NTLM connection pinning.** `ntlm` in an upstream keeps a connection pinned for
the whole NTLM handshake.  It is a Windows authentication thing and it cannot be
faked from outside the process.  If you are proxying to something that needs
NTLM, this one will actually bite you.

**MQTT preread and filter.** Stream level MQTT parsing.  Plus only, and no way
around it.

**NGINX App Protect.** This is the WAF, and it is a separate paid product on top
of Plus.  We are not going to pretend a few regex rules are a WAF.  If you need
one, look at ModSecurity or Coraza in front of nginx, and know that the
installer does not compile either one in, so that means changing the module list
and rebuilding.

**In-flight request counts on the dashboard.** As above, a request that has not
finished has not been logged yet, so we cannot show it.

**Truly reload-free reconfiguration.** Everything we do ends in a config reload.
nginx reloads gracefully so this is not the problem it sounds like, but if your
backends change many times a minute, the reload rate will become the limit.

---

## A note on reloads

Most of what is above works by rewriting config and reloading.  That is worth
being comfortable with, so here is what actually happens.

On reload, the nginx master reads the new config and starts new worker
processes with it.  The old workers stop taking new connections but keep serving
the requests they already have until those finish.  Then they exit.  No
connection gets cut and nobody sees an error.

Two things to know.  A reload costs a little CPU and briefly runs two sets of
workers, so memory goes up for a moment.  And if you have very long lived
connections, like WebSockets, the old workers stick around until those close.
Reload often enough with long connections and you can pile up old workers.

The manager already handles the busy part: reloads are debounced, so twenty
backends flapping at once turns into one reload rather than twenty.

---

## Trademarks

NGINX&reg; is a registered trademark of F5, Inc.  NGINX Plus is a trademark of
F5, Inc.  Failover LB is an independent project and is not affiliated with,
endorsed by, or sponsored by F5, Inc.  This page compares the two products and
names NGINX Plus only to say what it does; nothing here is an F5 statement
about either product.
