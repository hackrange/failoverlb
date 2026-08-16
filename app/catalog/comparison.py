"""
Failover LB against the load balancers people actually shortlist against it.

Read the honesty warning before the table, because it applies to every number
in this file: **we are rating our own product against three other people's.**
That is a conflict of interest and no amount of care removes it.  What can be
done is to be specific about why each score is what it is, so a reader can
disagree with the reasoning rather than having to take the number on trust.

The scale, and it is deliberately not "how good is this":

    0   not offered at all
    1   possible, but you are building it yourself
    2   there, and you will feel the gap
    3   does the job
    4   does the job well
    5   as good as this gets

A capability with a 5 against a paid product and a 3 against us is not a
complaint.  It means somebody paid for it and got something better, which is
what paying is for.  The rows worth arguing about are the ones where we claim
to be equal or better, and those are the ones with the longest notes.

Four things this table deliberately does **not** do:

  * **Count Instance Manager, NGINX One, App Protect, LoadMaster 360 or
    HAProxy Fusion as part of the product they sit beside.**  They are separate
    products with separate prices.  Where one of them is the real answer to a
    row, the note says so rather than the score pretending the base product
    lacks it entirely.
  * **Take credit for nginx itself.**  Most of what a load balancer does is in
    the free nginx both we and Plus run.  Those rows are 5 and 5, and saying so
    is more useful than leaving them out to make the table look flattering.
  * **Hide the rows we lose.**  Support is the obvious one, and the star total
    at the top of each column is another: we do not come first on it.
  * **Guess at a competitor and score the guess.**  Where we could not confirm
    something from published material, the score is 1 and the note says we
    could not confirm it.  A 1 that says "we do not know" is more use than a 0
    that pretends we do.

The two appliance columns were scored on 16 August 2026 from vendor
documentation, release notes and datasheets.  Both products move, so a score
here is a reading of what was published on that day and nothing stronger.
"""

# ---------------------------------------------------------------- the columns
#
# The page sorts these by star total, highest first, so the order here is only
# the order the scores are written in each row.
PRODUCTS = [
    {
        "key": "plus",
        "label": "NGINX® Plus",
        "vendor": "F5",
        "short": "The paid build of the same nginx we run.",
    },
    {
        "key": "lb",
        "label": "Failover LB",
        "vendor": "this project",
        "us": True,
        "short": "This project, running free nginx underneath.",
    },
    {
        "key": "kemp",
        "label": "Kemp LoadMaster",
        "vendor": "Progress",
        "short": "An appliance, virtual or physical, with its own stack.",
    },
    {
        "key": "aloha",
        "label": "HAProxy ALOHA",
        "vendor": "HAProxy Technologies",
        "short": "An appliance built on the HAProxy Enterprise engine.",
    },
]

RIVAL_KEYS = [p["key"] for p in PRODUCTS if not p.get("us")]

# Everything below is a judgement, and the notes are the argument for it.
#
#   key       stable id, so a link can point at a row
#   label     what the capability is called
#   category  how the page groups them
#   plus      0 to 5 for NGINX Plus
#   lb        0 to 5 for Failover LB
#   kemp      0 to 5 for Kemp LoadMaster
#   aloha     0 to 5 for HAProxy ALOHA
#   note      why Plus and we scored what we did, in plain words
#   others    why the two appliances scored what they did
#
# One optional key, and it matters more than it looks:
#
#   unconfirmed   product keys we could find nothing published about, either
#                 way.  Those score 1, and 1 there means "we do not know",
#                 which is a different thing from the 1 that means "possible,
#                 but you are building it yourself".  Both readings are honest
#                 and the star cannot tell them apart, so the row says which
#                 and checks/comparison.py holds us to it.
CAPABILITIES = [

    # ---------------------------------------------------------------- balancing
    {
        "key": "balancing_methods",
        "label": "Round robin, least connections, hashing",
        "category": "Load balancing",
        "plus": 5, "lb": 5, "kemp": 5, "aloha": 5,
        "note": "The same nginx underneath, so there is nothing to choose "
                "between them.  Most of what either product does for a living "
                "is here, and it is free in both.",
        "others": "All four do this and all four do it well.  Kemp adds "
                  "resource based and fixed weighting on top; ALOHA has both "
                  "the HAProxy algorithms at layer 7 and the LVS ones at layer "
                  "4, including maglev hashing.  Nobody wins a row like this.",
    },
    {
        "key": "least_time",
        "label": "Least time balancing",
        "category": "Load balancing",
        "plus": 5, "lb": 4, "kemp": 3, "aloha": 3,
        "note": "Also understated until the code was read.  Plus picks the "
                "fastest backend per request.  We time every health check "
                "already, so a pool can be set to lean weights toward the "
                "quicker boxes, with two rails: weights move one step at a "
                "time between a floor and a ceiling so one slow check cannot "
                "pull a server out, and if everything is slow it leaves them "
                "alone, because that means the problem is downstream and "
                "shuffling weights would pile load onto whichever box is least "
                "broken.  Four, not five: ours reacts per check interval, "
                "Plus per request.",
        "others": "Neither appliance balances on response time as such.  Kemp "
                  "has resource based scheduling, which asks each real server "
                  "for a number describing how loaded it is, so the server has "
                  "to be told to publish one.  HAProxy has no least time "
                  "algorithm at all; least connections is the usual stand in "
                  "and it is a good one.  Three each for doing the job by a "
                  "different route.",
    },
    {
        "key": "sticky",
        "label": "Sticky sessions",
        "category": "Load balancing",
        "plus": 5, "lb": 3, "kemp": 5, "aloha": 5,
        "note": "Plus issues its own cookie, so it works whatever the "
                "application does.  We hash a cookie the application already "
                "sets, which is as good when there is one, or hash the client "
                "address when there is not, and that sends a whole office "
                "behind one NAT to a single backend.",
        "others": "A row we lose to everybody, and it is worth saying so "
                  "twice.  Kemp has a long list of persistence methods "
                  "including its own inserted cookie.  HAProxy inserts its own "
                  "cookie and keeps stick tables that can key on almost "
                  "anything and are shared across the cluster.  Three of the "
                  "four issue their own cookie; we do not.",
    },
    {
        "key": "slow_start",
        "label": "Slow start after recovery",
        "category": "Load balancing",
        "plus": 5, "lb": 4, "kemp": 4, "aloha": 5,
        "note": "This row said two until somebody read the code.  It is built "
                "and has been for a while: turn it on for a pool, and a member "
                "that comes back returns at weight 1 and climbs to its real "
                "weight in five steps over a window you choose.  The reason it "
                "matters is a JVM with a cold JIT and an empty connection pool "
                "being handed a third of the traffic the instant it answers a "
                "health check, falling over again, and flapping, which is "
                "worse than it having stayed down.  Four rather than five "
                "because each step is a reload, where Plus ramps inside the "
                "worker.",
        "others": "HAProxy has a per server slowstart setting that ramps "
                  "inside the process, which is as good as this gets.  Kemp "
                  "throttles connections per second to a recovered server and "
                  "grows the limit over a window, which is the same idea, but "
                  "the setting is global and only applies to the least "
                  "connection schedulers.",
    },
    {
        "key": "queueing",
        "label": "Request queueing",
        "category": "Load balancing",
        "plus": 5, "lb": 1, "kemp": 2, "aloha": 5,
        "note": "Plus queues on the thing that matters, which is every backend "
                "being busy: at the connection limit we give a 502 rather than "
                "waiting, and there is no fixing that from out here.  One at "
                "rather than nought because rate limiting with a burst does "
                "queue.  Excess requests are delayed rather than refused unless "
                "you tick serve burst immediately, so load can be shaped "
                "before it reaches the limit.  It queues on arrival rate, not "
                "on how busy the backends are, and those are different "
                "questions.",
        "others": "This is one of the best things HAProxy does and ALOHA gets "
                  "all of it: a per server connection limit, a real queue in "
                  "front of it, a queue timeout, and the queue depth on the "
                  "stats page so you can see it filling.  It is the clearest "
                  "single win against us on the page.  Kemp rate limits a real "
                  "server and takes it out of rotation when the limit is hit, "
                  "which protects the server without holding the request.",
    },
    {
        "key": "stream",
        "label": "TCP and UDP proxying",
        "category": "Load balancing",
        "plus": 5, "lb": 5, "kemp": 5, "aloha": 5,
        "note": "The stream module is free.  Both get it, and ours is driven "
                "from a page rather than a config file.",
        "others": "Both appliances do layer 4 properly.  ALOHA runs LVS "
                  "alongside HAProxy, so it also does direct server return, "
                  "where the reply skips the load balancer entirely.  Neither "
                  "we nor Plus can do that.",
    },

    # ------------------------------------------------------------------- health
    {
        "key": "active_health",
        "label": "Active health checks",
        "category": "Health and resilience",
        "plus": 5, "lb": 4, "kemp": 5, "aloha": 5,
        "note": "Plus probes from inside nginx, so it reacts in the worker "
                "that is about to route the request.  We probe from the "
                "manager on a schedule and rewrite the upstream, so reaction "
                "is a check interval plus a reload rather than immediate.  "
                "Two things ours does that Plus does not: it checks from "
                "every node rather than one, and it refuses to mark the last "
                "healthy backend down, so a broken check cannot empty a pool.",
        "others": "Both appliances check from inside the data path and take a "
                  "server out without rewriting anything, which is the right "
                  "way round.  Kemp has a long list of check types built for "
                  "the applications it is usually put in front of.  Ours keeps "
                  "the two habits above, and those are worth something, but "
                  "not enough to move this row.",
    },
    {
        "key": "passive_health",
        "label": "Passive health checks",
        "category": "Health and resilience",
        "plus": 5, "lb": 5, "kemp": 4, "aloha": 5,
        "note": "max_fails and fail_timeout are free nginx.  Identical.",
        "others": "HAProxy watches live traffic for errors and can pull a "
                  "server on what it sees rather than only on what it probes.  "
                  "Kemp leans harder on active checks, which is a design "
                  "choice more than a gap.",
    },
    {
        "key": "ha",
        "label": "Load balancer failover",
        "category": "Health and resilience",
        "plus": 3, "lb": 5, "kemp": 4, "aloha": 4,
        "note": "Plus ships a keepalived package, which works and is "
                "configured in files on each box.  Ours is built in: election "
                "with a quorum rule, a standby that refuses to promote itself "
                "when it cannot see a majority, and the whole thing visible on "
                "a page.  The quorum rule is the part that matters, because "
                "the failure it prevents is two nodes both deciding they are "
                "active.",
        "others": "Both appliances do this well and have done for years.  Kemp "
                  "pairs two units with CARP; ALOHA clusters with VRRP and "
                  "will run active with active as well as active with standby, "
                  "which we will not.  Four rather than five for the same "
                  "reason in both cases: a two node pair reasons about the "
                  "peer it can see, and that is the split brain problem the "
                  "quorum rule exists to answer.",
    },
    {
        "key": "two_phase",
        "label": "Config tested on every node before any node applies",
        "category": "Health and resilience",
        "plus": 1, "lb": 5, "kemp": 1, "aloha": 1,
        "note": "The one we would keep if we could only keep one.  A change is "
                "staged and tested on every node, and applied nowhere unless "
                "it passed everywhere.  Plus has nothing here; Instance "
                "Manager, sold separately, can validate config, and that is "
                "still not the same as an all or nothing fleet apply.",
        "others": "Nobody else on this page does it either, which is the "
                  "surprise.  Kemp applies a change to the unit you are "
                  "logged into.  On ALOHA the configuration sync between "
                  "cluster members is a manual push, one service at a time, "
                  "and changes are not even saved to disk unless you save "
                  "them, so a reboot can undo an afternoon.  This row is our "
                  "clearest win on the page and it is against all three.",
    },

    # --------------------------------------------------------------------- TLS
    {
        "key": "tls",
        "label": "TLS termination, stapling, session cache",
        "category": "TLS and certificates",
        "plus": 5, "lb": 5, "kemp": 5, "aloha": 5,
        "note": "Free nginx, both sides.  Nothing to choose between them, and "
                "what we do with a current OpenSSL is its own row below.",
        "others": "Terminating TLS is the reason both appliances exist.  Kemp "
                  "and ALOHA both do it at line rate with hardware behind it "
                  "on the physical units.  Four ways of doing the same job "
                  "well.",
    },
    {
        "key": "pqc",
        "label": "Post quantum key exchange",
        "category": "TLS and certificates",
        "plus": 3, "lb": 5, "kemp": 1, "aloha": 4,
        "unconfirmed": ["kemp"],
        "note": "Harvest now, decrypt later is the reason this matters before "
                "anybody has a quantum computer: traffic captured today is "
                "decrypted whenever one arrives.  We build against OpenSSL "
                "3.5, so X25519MLKEM768 is there, and the shipped TLS snippet "
                "offers it first with classic curves behind it, so a site gets "
                "it without anybody knowing to ask.  F5 have been adding this "
                "to recent releases, so the honest gap is not whether Plus can "
                "but whether the build you have does and whether somebody "
                "configured the groups.  Building our own TLS stack is a cost "
                "in every other row and it buys this one.",
        "others": "ALOHA moved its TLS stack to AWS-LC, and HAProxy Enterprise "
                  "3.2 and later offer X25519MLKEM768 with a fall back to the "
                  "classic curves for older clients.  That is a real answer "
                  "and it is four rather than five only because you take what "
                  "the firmware ships with.  For Kemp we could find nothing "
                  "published either way, which is why this is a 1 and not a 0.  "
                  "On an appliance that matters more than it does for us: you "
                  "cannot rebuild it yourself, so you get what arrives.",
    },
    {
        "key": "acme",
        "label": "Certificate lifecycle, end to end",
        "category": "TLS and certificates",
        "plus": 3, "lb": 5, "kemp": 4, "aloha": 2,
        "note": "nginx has gained a native ACME module, and it issues "
                "certificates.  What is rated here is the rest of the job: "
                "issuing from whichever node owns the address, replicating to "
                "the others, renewing on a schedule, staging first, DNS-01 "
                "where HTTP-01 will not do, and degrading to the old "
                "certificate rather than freezing the fleet when something "
                "goes wrong.",
        "others": "Kemp is the strong one here.  There has been a built in "
                  "ACME client since firmware 7.2.53, it creates the service "
                  "that answers the challenge for you, and it renews on its "
                  "own.  Four rather than five because it validates over "
                  "HTTP-01 only, and HTTP-01 cannot issue a wildcard or cover "
                  "a name that is not reachable from the internet.  ALOHA is "
                  "the weak one: HAProxy itself gained ACME recently and the "
                  "ALOHA release notes do not carry it yet, so on the "
                  "appliance this is still a certificate you fetch elsewhere "
                  "and upload.",
    },
    {
        "key": "paid_ca",
        "label": "Certificates from a paid authority",
        "category": "TLS and certificates",
        "plus": 1, "lb": 5, "kemp": 4, "aloha": 2,
        "note": "Neither product is a certificate manager, but we became one: "
                "authorities are profiles with their own credentials, several "
                "can be in use at once, and a certificate renews from the "
                "authority that issued it rather than quietly from somewhere "
                "else in sixty days.",
        "others": "Kemp supports DigiCert alongside Let's Encrypt and has a "
                  "certificate console in LoadMaster 360, though that console "
                  "is the separate subscription rather than the box.  On ALOHA "
                  "you upload the file and remember the renewal date "
                  "yourself.",
    },

    # ---------------------------------------------------------------- security
    {
        "key": "waf",
        "label": "Web application firewall",
        "category": "Security",
        "plus": 5, "lb": 4, "kemp": 4, "aloha": 5,
        "note": "F5's App Protect is a serious WAF and a separate purchase, and "
                "it covers ground we do not: bot defence, API security, "
                "signature feeds.  That is why this is four and not five.\n\n"
                "This note used to claim that hardly anything off the shelf "
                "learns, and that was too strong.  All three of the others have "
                "a detection only mode and a way to turn what fired into an "
                "exclusion, which is the same shape as our watching mode.  "
                "Correcting it is worth more than the sentence it cost.\n\n"
                "What is actually different here is narrower and it is about "
                "**whose traffic the allowed list is built from.**  Put a site "
                "in watching, name the addresses your testers work from, "
                "exercise the application properly, and what fired for those "
                "addresses becomes a list you tick and save as a named profile "
                "reusable across sites.  Only traffic from a vouched-for "
                "address can be whitelisted at all, and a rule a stranger also "
                "tripped during the window is held back as mixed rather than "
                "averaged into looking safe.  So somebody scanning you in the "
                "middle of a test session cannot get their probes permanently "
                "excused, which is the failure ordinary tuning invites: you "
                "are excusing whatever fired, and you do not always know who "
                "made it fire.\n\n"
                "Worth knowing about the one on this page that goes furthest.  "
                "F5 do have a real policy builder that watches an application "
                "and proposes a positive model, and it is in BIG-IP Advanced "
                "WAF rather than here: F5's own conversion notes say traffic "
                "learning, policy building and staging are not supported in "
                "App Protect.  So the thing people assume they are buying with "
                "the F5 name is in the other product.",
        "others": "ALOHA has the best WAF on this page and we should say so.  "
                  "It carries its own engine rather than plain rule matching, "
                  "supports OWASP CRS 4, lets you build named WAF profiles and "
                  "apply a different one per application, and sells a bot "
                  "module and a threat detection engine beside it.  It also "
                  "has a non blocking learning mode for exactly this job, and "
                  "publishes a false positive rate at paranoia 2 far below "
                  "plain ModSecurity, which is the number that decides whether "
                  "anybody leaves a WAF switched on.  Kemp runs the same "
                  "ModSecurity and OWASP rules we do, adds a paid feed for IP "
                  "reputation and web shells, and has block and log only modes "
                  "with a tuning screen that lists the false positives it "
                  "recorded and writes exclusions from them, including "
                  "excluding one rule against one parameter.\n\n"
                  "So learning is not the differentiator; all three learn.  "
                  "The differentiator is that theirs learn from whatever "
                  "arrived and ours only learns from addresses somebody named "
                  "in advance.  That is one design decision, not a category, "
                  "and it is the only part of this row worth claiming.  Both "
                  "appliances need the higher tier before the WAF turns on at "
                  "all, which is a cost their star does not show.",
    },
    {
        "key": "jwt",
        "label": "JWT validation at the proxy",
        "category": "Security",
        "plus": 5, "lb": 2, "kemp": 3, "aloha": 4,
        "note": "Plus validates the token itself.  We use auth_request, which "
                "is free and works for any scheme, and which means you write "
                "and run a small service.  That is a real piece of work, not a "
                "setting.",
        "others": "HAProxy can verify a signed token in its own configuration "
                  "language, so ALOHA gets this without a helper service.  "
                  "Kemp reaches the same end through its authentication pack, "
                  "which is built around signing users in rather than checking "
                  "a token an API client already holds.",
    },
    {
        "key": "oidc",
        "label": "OIDC sign in for proxied applications",
        "category": "Security",
        "plus": 4, "lb": 1, "kemp": 5, "aloha": 4,
        "note": "Worth separating carefully.  Plus can put an OIDC login in "
                "front of an application it proxies.  We sign **admins** in to "
                "this GUI with OIDC, which is a different thing, and we do "
                "nothing for the traffic passing through.",
        "others": "This is the row Kemp wins outright, and it is the reason a "
                  "lot of people buy one.  The Edge Security Pack puts a login "
                  "in front of any application it publishes, against Active "
                  "Directory, LDAP, RADIUS, SAML or OIDC, and carries the "
                  "session across every service on the box.  ALOHA does "
                  "Kerberos and SAML sign on.  We do none of it for proxied "
                  "traffic and there is no honest way to dress that up.",
    },
    {
        "key": "geo",
        "label": "Blocking by country",
        "category": "Security",
        "plus": 3, "lb": 5, "kemp": 4, "aloha": 4,
        "note": "The geoip2 module is free for both.  The work is the "
                "database: getting one, putting it on every node, and keeping "
                "it current, which we do from a page on a schedule.  With Plus "
                "that is yours to arrange.",
        "others": "Both appliances ship the location database as part of the "
                  "firmware, which is a tidy answer: nothing to download and "
                  "nothing to schedule.  Kemp aims its location features at "
                  "steering traffic to the nearest site more than at shutting "
                  "a country out, and does both.  Four each, and the half step "
                  "we keep is that our database updates on its own schedule "
                  "rather than waiting for a firmware release.",
    },
    {
        "key": "acl",
        "label": "Allow and deny lists, basic auth",
        "category": "Security",
        "plus": 5, "lb": 5, "kemp": 5, "aloha": 5,
        "note": "Free nginx, and equal on capability, which is why this stays "
                "five and five however tempting the alternative is.  allow and "
                "deny per location is plain nginx; both products have it.\n\n"
                "Ours are reusable objects rather than lines repeated per "
                "server block, and they attach to a single path as readily as "
                "to a whole site, so locking a login page to nine addresses is "
                "a list and a tick.  That is a real difference and it is "
                "already counted, one row down, as managing the thing from a "
                "browser.  Counting it twice is how a table written by one of "
                "the two products stops being worth reading.",
        "others": "Both appliances have address lists and both let you attach "
                  "one to a published service.  ALOHA writes them as HAProxy "
                  "rules, which can match on nearly anything.  Five all round, "
                  "for the same reason as above: this is a capability every "
                  "serious product has, and the difference is in the shape of "
                  "the screen, not in what the traffic sees.",
    },
    {
        "key": "admin_security",
        "label": "Admin accounts, roles, two factor, audit log",
        "category": "Security",
        "plus": 0, "lb": 5, "kemp": 4, "aloha": 3,
        "note": "Plus has no administrative interface to secure, so this is "
                "not a gap in it so much as a thing it does not have.  Ours "
                "has roles, TOTP, lockout, and an audit log with secrets "
                "scrubbed.  Instance Manager is where F5 put this, separately.",
        "others": "Both appliances have this because both are things you log "
                  "in to.  Kemp has user accounts with permissions, change "
                  "auditing, and can hand sign in off to your directory.  "
                  "ALOHA has accounts on its interface but publishes less "
                  "about roles and audit trails, so it scores lower on what we "
                  "could read rather than on anything we found missing.",
    },

    # ----------------------------------------------------------- observability
    {
        "key": "live_stats",
        "label": "Live activity monitoring",
        "category": "Observability",
        "plus": 5, "lb": 3, "kemp": 4, "aloha": 5,
        "note": "Plus counts requests in flight, per upstream, inside the "
                "process.  Ours come from stub_status and the access log, and "
                "a request that has not finished has not been logged, so in "
                "flight is a number we genuinely cannot show.",
        "others": "The HAProxy stats page is the reference for this and ALOHA "
                  "carries it: sessions in flight, queue depth, per server "
                  "error counts, all of it live and all of it from inside the "
                  "process.  Kemp shows live counters per service in its "
                  "interface.  Both beat us and the reason is the same as with "
                  "Plus: they are the proxy, and we are a manager standing "
                  "next to one.",
    },
    {
        "key": "utilization",
        "label": "CPU, memory and load over time",
        "category": "Observability",
        "plus": 2, "lb": 5, "kemp": 3, "aloha": 2,
        "note": "Plus reports on nginx; the box it runs on is somebody else's "
                "problem, and its dashboard is the present tense.  We chart "
                "both load balancers on their own page and now keep it: one "
                "minute detail for 48 hours, five minute buckets for thirty "
                "days, and drag across any chart to zoom every chart to that "
                "range.  This was four while the history was two hours in "
                "memory that went on restart, which was the whole of the "
                "reason, so it is five now that reason is gone.  Every bucket "
                "keeps min, mean and max, because a five minute average alone "
                "is where a spike goes to die.  Measured on a real fleet at "
                "27 MB for four nodes across both tiers.",
        "others": "Both appliances are strong on the present tense and thin on "
                  "history.  ALOHA gives you a live stats page, SNMP and a "
                  "Prometheus endpoint, and then expects you to run a "
                  "monitoring system to keep any of it; the vendor's own "
                  "answer for stored history is HAProxy Fusion, which is a "
                  "separate product.  Kemp keeps more on the box and puts the "
                  "long view in LoadMaster 360, also separate.  Keeping thirty "
                  "days on the box with nothing else to install is the "
                  "difference.",
    },
    {
        "key": "backend_metrics",
        "label": "Backend CPU and memory",
        "category": "Observability",
        "plus": 0, "lb": 3, "kemp": 1, "aloha": 1,
        "note": "Neither product has an agent on your backends.  We read a "
                "Prometheus endpoint if a pool is given one, and label an "
                "application exporter differently from a machine one, because "
                "a JVM at 100% of one core is not a busy box.",
        "others": "Both can ask a backend how it is doing, and neither shows "
                  "you the answer.  Kemp's resource based scheduling and "
                  "HAProxy's agent check both read a number the server "
                  "publishes and use it to change the weight.  That is a "
                  "steering input, not a chart, so this is a 1 rather than a "
                  "0.  Something has to be running on the backend to publish "
                  "it either way.",
    },

    # -------------------------------------------------------------- operations
    {
        "key": "runtime_api",
        "label": "Changing upstreams without a reload",
        "category": "Operations",
        "plus": 5, "lb": 3, "kemp": 5, "aloha": 5,
        "note": "Plus changes upstreams over an API with no reload at all.  We "
                "rewrite the config and reload, which on nginx is graceful and "
                "drops nothing in flight, but it is a reload: a little CPU, two "
                "sets of workers briefly, and long lived connections holding "
                "the old ones open.",
        "others": "Both appliances add, drain and remove servers live over an "
                  "API with nothing restarted, and both have done for years.  "
                  "This is a row we lose to all three, and the reason is "
                  "structural: they own the process, we edit its config file.",
    },
    {
        "key": "gui",
        "label": "Managing the whole thing from a browser",
        "category": "Operations",
        "plus": 1, "lb": 5, "kemp": 5, "aloha": 3,
        "note": "This is the product.  Plus is configured in files; its GUI is "
                "a statistics dashboard, and configuration through a browser is "
                "Instance Manager or NGINX One, sold separately.  Everything "
                "here is a page, and the API exists because the page needed it.",
        "others": "Kemp matches us and should: the web interface is the "
                  "product there too, everything is a form, and it has been "
                  "polished for longer than this project has existed.  ALOHA "
                  "has a real interface with a setup wizard, but a lot of the "
                  "layer 7 work still comes down to editing HAProxy "
                  "configuration text in a box in the browser, which is a file "
                  "with a nicer background.",
    },
    {
        "key": "import",
        "label": "Importing an nginx config you already have",
        "category": "Operations",
        "plus": 0, "lb": 4, "kemp": 0, "aloha": 0,
        "note": "We parse an existing config into sites, pools and settings, "
                "so adopting this does not start with retyping.  Four because "
                "anything it cannot model is kept as raw config rather than "
                "quietly dropped, and you should read the result.",
        "others": "Neither appliance reads an nginx config, and there is no "
                  "reason either would: they are not nginx.  Moving to one "
                  "means building your services again in their model, by hand "
                  "or by script.  That is a real cost and it lands on the "
                  "week you migrate.",
    },
    {
        "key": "binaries",
        "label": "Where the nginx binary comes from",
        "category": "Operations",
        "plus": 5, "lb": 3, "kemp": 5, "aloha": 5,
        "note": "A row we lose and should.  Plus is a supported package from "
                "F5.  Ours is built from source on each node so the modules can "
                "be chosen, which means a rebuild to add one and means you are "
                "carrying that build yourself.  We drive it from a page, one "
                "node at a time, which makes it survivable rather than pleasant.",
        "others": "Both appliances ship a signed firmware image the vendor "
                  "tested, which is the whole point of buying an appliance.  "
                  "We lose this row to all three and it is the honest cost of "
                  "choosing our own modules.  The other side of that coin is "
                  "the post quantum row above, which we only win because we "
                  "build our own.",
    },
    # ------------------------------------------------------- backup and restore
    #
    # This was one row until somebody pointed out that backup and restore is
    # not one question.  Taking a copy, what is in the copy, and what you can
    # do with it later are three different jobs, and the four products are good
    # at different ones.  Three rows rather than the six it could have been:
    # expanding a category you happen to be strong in is the oldest way to tilt
    # a comparison, and doing it in a table you wrote about your own product is
    # worse.  Note what it did to the totals anyway, in the page copy.
    {
        "key": "backup_taking",
        "label": "Taking a backup, and where it goes",
        "category": "Backup and restore",
        "plus": 1, "lb": 3, "kemp": 5, "aloha": 3,
        "note": "With Plus this is your config files, so it is whatever your "
                "configuration management already does, which for a lot of "
                "people is a real answer and for the rest is nothing.  Ours is "
                "a button and one file that lands in your browser.  Three and "
                "not more, because there is no schedule and nowhere to send "
                "it: a backup somebody has to remember to take is a backup "
                "that is three months old when you need it.",
        "others": "Kemp is the best here and it is not close.  Backups can run "
                  "on a schedule and push themselves to a remote server over "
                  "SCP or SFTP, so the copy is off the box without anybody "
                  "doing anything.  FTP is the default and that is worth "
                  "changing, since it sends the file and the password in "
                  "clear.  ALOHA is an Export button on the Setup tab, which "
                  "is the same shape as ours.",
    },
    {
        "key": "backup_contents",
        "label": "What is actually in the backup",
        "category": "Backup and restore",
        "plus": 1, "lb": 5, "kemp": 2, "aloha": 3,
        "note": "The row that decides whether a backup is worth having.  Ours "
                "holds everything the fleet is configured to do: sites, pools, "
                "certificates and their private keys, WAF profiles and the "
                "exclusions somebody spent an afternoon earning, accounts, "
                "access lists, error pages.  Node names and cluster identity "
                "are deliberately left out, because they belong to the "
                "machines rather than to the configuration.  The file is "
                "encrypted with AES-256, and the honest caveat is that the "
                "password is the operator's login password through PBKDF2 at "
                "1000 iterations, which is not a lot: treat the file as the "
                "bag of private keys it is.",
        "others": "Kemp scores two for one specific reason, and it is the "
                  "single most useful fact on this page: **their documentation "
                  "says no SSL certificate information is contained within a "
                  "backup.**  Everything else is there, and the certificates "
                  "are a separate export you have to remember.  A restore that "
                  "brings back every virtual service and no certificates is a "
                  "restore that ends with every site down, and you find that "
                  "out at the worst moment.  For ALOHA the export carries the "
                  "configuration; we could not confirm from published material "
                  "whether uploaded certificates travel with it, so three "
                  "reflects what we could read and not a judgement.",
    },
    {
        "key": "backup_restore",
        "label": "Restoring, and rebuilding somewhere else",
        "category": "Backup and restore",
        "plus": 1, "lb": 4, "kemp": 4, "aloha": 2,
        "note": "Ours rebuilds a fleet that has nothing in common with the old "
                "one: different addresses, different node names, different "
                "hardware.  Secrets are unsealed on the way out and sealed "
                "again with the new fleet's own key, because the key that "
                "protects them here does not exist there.  Four and not five "
                "because it is all or nothing.  You cannot restore only the "
                "pools, and the one thing deliberately left behind is the "
                "management network list, since restoring it is a fine way to "
                "lock yourself out of the system you are in the middle of "
                "rebuilding.",
        "others": "Kemp draws with us by being good at the opposite half.  "
                  "You choose what comes back: the base configuration, the "
                  "virtual services, GEO, each on its own.  That is genuinely "
                  "better than our all or nothing for the everyday case of "
                  "undoing one afternoon.  It is weaker for the disaster case, "
                  "because the base configuration carries the addresses of the "
                  "box it came from.  ALOHA imports what it exported and has a "
                  "well documented factory reset, including one from the "
                  "serial console for when the config is bad enough that the "
                  "interface will not load, which is a nice thing to have and "
                  "not the same as a restore.",
    },
    {
        "key": "tunnel",
        "label": "Reaching backends with no public address",
        "category": "Operations",
        "plus": 0, "lb": 4, "kemp": 0, "aloha": 0,
        "note": "A WireGuard tunnel a workload enrols into with one command, "
                "so a machine behind NAT becomes a pool member without asking "
                "anybody for a firewall change.  Neither nginx nor Plus does "
                "anything like this; it assumes the backend is already "
                "reachable.",
        "others": "No load balancer on this page does this, because a load "
                  "balancer assumes it can already reach the servers.  If your "
                  "backends sit behind NAT you are buying a VPN alongside any "
                  "of the other three and wiring the two together yourself.",
    },
    {
        "key": "gslb",
        "label": "DNS based failover between sites",
        "category": "Operations",
        "plus": 0, "lb": 3, "kemp": 5, "aloha": 4,
        "note": "Not in Plus at all.  F5 sell that as a different product "
                "entirely.  Ours answers DNS with the healthy site, which "
                "covers the common case and inherits every DNS caching problem "
                "there has ever been.",
        "others": "Kemp is the best on this page by a distance.  Their GSLB "
                  "steers on the client's country, continent, address range or "
                  "actual distance in degrees, weighs the live load at each "
                  "site, and can refuse addresses with a bad reputation.  "
                  "ALOHA has a solid GSLB module and added health checks over "
                  "HTTPS so it can probe a site properly rather than guessing "
                  "from a port being open.  Both need the paid tier.",
    },
    {
        "key": "error_pages",
        "label": "Custom error pages",
        "category": "Operations",
        "plus": 2, "lb": 4, "kemp": 3, "aloha": 3,
        "note": "error_page is free in both, and then you are writing HTML and "
                "putting it on every node yourself.  Ours are templates you "
                "point sites at, replicated with the config.",
        "others": "Both appliances let you upload a page and attach it to a "
                  "service.  The step we keep is that ours are templates "
                  "several sites share and the fleet replicates, so fixing a "
                  "typo is one edit rather than one edit per box.",
    },
    {
        "key": "support",
        "label": "Somebody to call",
        "category": "Support",
        "plus": 5, "lb": 0, "kemp": 5, "aloha": 5,
        "note": "First row on the page, and the one we lose worst.  Plus comes "
                "with F5 support and an SLA: a number to ring at three in the "
                "morning and somebody contractually obliged to answer.  This is "
                "a project on a box, and when it breaks the person fixing it is "
                "you.  If that matters where you work it matters more than "
                "every other row put together, and no amount of features below "
                "changes it.",
        "others": "Both appliance vendors sell support with the box and both "
                  "are well regarded for it.  Kemp runs tiers, with 24x7 "
                  "premium cover on the higher plans.  HAProxy do not run "
                  "tiers at all: your ticket goes straight to an engineer, and "
                  "the enterprise subscription carries a thirty minute target "
                  "on a critical issue.  We have nothing, and adding two more "
                  "columns has only made that clearer.",
    },

    # --------------------------------------------------------------- protocols
    {
        "key": "http3",
        "label": "HTTP/3 and QUIC",
        "category": "Content and protocols",
        "plus": 5, "lb": 5, "kemp": 1, "aloha": 5,
        "unconfirmed": ["kemp"],
        "note": "Free in nginx now, and no longer a rebuild away: the installer "
                "builds it by default against the OpenSSL 3.5 it already pins, "
                "and a site turns it on from its own settings.  Four while the "
                "flag was missing, which was the whole of the reason.  Worth "
                "more here than the version number suggests, because a QUIC "
                "handshake is TLS 1.3 by definition and is therefore where the "
                "post quantum key exchange actually lands.",
        "others": "ALOHA has carried HTTP/3 since version 15 and has been "
                  "tuning it ever since, with QUIC memory limits, a switch to "
                  "turn it off per listener, and experimental HTTP/3 out to "
                  "the backend in version 18.  It is the most mature QUIC on "
                  "this page.  For Kemp we could find nothing published, so "
                  "this is a 1 meaning we do not know rather than a 0 meaning "
                  "it is absent.",
    },
    {
        "key": "streaming",
        "label": "HLS, DASH and f4f video packaging",
        "category": "Content and protocols",
        "plus": 5, "lb": 0, "kemp": 0, "aloha": 0,
        "note": "Compiled into the Plus binary and not available any other "
                "way.  If you need packaged video streaming, that is a real "
                "reason to buy Plus.",
        "others": "Neither appliance packages video either.  This is a row "
                  "Plus wins against everybody, and it is the clearest example "
                  "on the page of why a star total is a poor way to choose: if "
                  "you need this, three of the four products are simply out.",
    },
    {
        "key": "ntlm",
        "label": "NTLM connection pinning",
        "category": "Content and protocols",
        "plus": 5, "lb": 0, "kemp": 2, "aloha": 4,
        "note": "Keeps a connection pinned through a Windows authentication "
                "handshake.  It cannot be done from outside the process, so if "
                "you proxy to something needing NTLM this one will bite.",
        "others": "HAProxy handles this by never reusing a backend connection "
                  "for a different client, which is a documented setting and "
                  "does the job at some cost in connections, so ALOHA gets a "
                  "four.  Kemp publishes plenty about signing users in against "
                  "Windows and much less about pinning the connection itself, "
                  "so this is a 2 covering what we could confirm.",
    },
    {
        "key": "mqtt",
        "label": "MQTT preread and filtering",
        "category": "Content and protocols",
        "plus": 5, "lb": 0, "kemp": 0, "aloha": 4,
        "note": "Stream level MQTT parsing, Plus only.  No way around it.",
        "others": "Not Plus only after all, which is what happens when you "
                  "widen a comparison.  HAProxy can read MQTT fields and route "
                  "on them, so ALOHA does this.  Kemp does not.",
    },
    {
        "key": "keyval",
        "label": "Runtime key value store",
        "category": "Content and protocols",
        "plus": 4, "lb": 1, "kemp": 1, "aloha": 5,
        "unconfirmed": ["kemp"],
        "note": "Plus keeps a store you can change over the API, which is how "
                "people build live blocklists.  We have maps, which means "
                "rewriting config and reloading to change one entry.",
        "others": "ALOHA is the best of the four.  HAProxy stick tables hold "
                  "counters and state that survive a reload and replicate "
                  "between peers, and map files can be edited live over the "
                  "runtime socket, which is exactly the live blocklist people "
                  "want this for.  For Kemp we could confirm nothing "
                  "equivalent either way, so that is a 1 meaning we do not "
                  "know rather than a 0 meaning it is absent.",
    },
]

CATEGORIES = [
    # Support goes first on purpose.  It is the row we lose worst, and a
    # comparison written by one of the four products that buries its weakest
    # answer near the bottom has told you something about itself before you
    # reach any of the numbers.
    "Support",
    # Second, because this is where the product is strongest and it was sitting
    # in the middle of the page where nobody would reach it.  Somebody weighing
    # this up should meet the row we lose, then the rows we win outright.
    "TLS and certificates",
    "Load balancing",
    "Health and resilience",
    "Security",
    "Observability",
    "Operations",
    "Backup and restore",
    "Content and protocols",
]


# --------------------------------------------------------------------- pricing
#
# The date is not decoration.  Every vendor here moves its prices, two of them
# publish nothing at all, and a table of costs with no date on it is worse than
# no table, because it looks current forever.
PRICING_PULLED = "16 August 2026"

PRICING = [
    {
        "key": "lb",
        "headline": "$0",
        "unit": "per node, per year, forever",
        "model": "No licence, no per instance fee, no support contract.  "
                 "There is nobody to buy one from.",
        "detail": "Free nginx underneath and this project on top of it.  The "
                  "cost is not zero, it has just moved: you carry the build, "
                  "you carry the upgrades, and at three in the morning the "
                  "person on call is you.  The support row above is the price "
                  "written out properly.",
        "sources": "Not applicable.",
    },
    {
        "key": "plus",
        "headline": "About $1,500",
        "unit": "per instance, per year",
        "model": "Subscription per instance, annual or three year.  F5 publish "
                 "no list price; every deal is a quote.",
        "detail": "Price trackers put the range at roughly $849 to $2,099 per "
                  "instance per year, with about $1,495 the common figure for "
                  "a single node.  App Protect, the WAF, is roughly $2,000 per "
                  "instance per year on top.  Support tier changes the number "
                  "again.  Instance Manager and NGINX One, which is where the "
                  "browser based configuration lives, are priced separately.  "
                  "The engine itself, free nginx, costs nothing.",
        "sources": "Third party price trackers and reseller listings, because "
                   "F5 publish none.",
    },
    {
        "key": "kemp",
        "headline": "From $2,500 once",
        "unit": "perpetual licence, plus yearly support",
        "model": "Perpetual licence with an annual support subscription, or a "
                 "pooled subscription, or pay as you go in a cloud "
                 "marketplace.",
        "detail": "Reseller listings put the VLM-200 at about $2,500 and the "
                  "VLM-3000 at about $4,000 as a one time perpetual licence, "
                  "with support charged yearly on top.  In AWS and Azure a "
                  "VLM-200 runs around $0.29 an hour with support included.  "
                  "There is a genuinely free tier with capped throughput, "
                  "which is unusual and worth knowing about.  The catch is "
                  "which plan you are on: the WAF, GSLB and the "
                  "authentication pack all need Enterprise or Enterprise Plus, "
                  "so three of the rows Kemp wins above are not in the entry "
                  "price.",
        "sources": "Kemp's own pricing page lists the plans but no numbers; "
                   "the figures come from reseller listings.",
    },
    {
        "key": "aloha",
        "headline": "$995 to $5,000",
        "unit": "per instance, per year",
        "model": "Subscription per appliance, annual or multi year, priced on "
                 "throughput.  Hardware costs extra.",
        "detail": "HAProxy publish no list price either.  Trackers put HAProxy "
                  "Enterprise, the engine inside ALOHA, at roughly $995 to "
                  "$5,000 per instance per year across the Basic, Standard and "
                  "Premium tiers.  ALOHA itself is quoted by appliance model "
                  "and throughput, so a physical unit lands above that range.  "
                  "Support is included and is not tiered by who answers.  "
                  "HAProxy community edition, which is most of the engine, "
                  "costs nothing.",
        "sources": "Third party price trackers and the vendor's support and "
                   "product pages.",
    },
]


def by_category():
    """
    Rows grouped for the page, in the order the categories are listed.

    Each row is copied and given two extra keys the template needs: the best
    score any rival managed, and whether we beat it.  Doing it here keeps the
    template to displaying things.
    """
    out = []
    for name in CATEGORIES:
        rows = []
        for c in CAPABILITIES:
            if c["category"] != name:
                continue
            row = dict(c)
            row["rivals_best"] = max(c[k] for k in RIVAL_KEYS)
            row["row_best"] = max(row["rivals_best"], c["lb"])
            rows.append(row)
        out.append((name, rows))
    return out


def only_here():
    """
    What this does that none of the other three do at all.

    Kept to rows where every other product scores zero, rather than anywhere we
    happen to score higher.  "We do it better" is an argument; "nobody else has
    it" is a fact, and only the second belongs on a list with this title.

    Widening the comparison from one rival to three cut this list hard, which
    is the point of widening it.  Several rows that read as ours alone against
    NGINX Plus turned out to be things an appliance has had for years.
    """
    return [c for c in CAPABILITIES
            if c["lb"] > 0 and all(c[k] == 0 for k in RIVAL_KEYS)]


def product_totals():
    """
    Star total per product, highest first.

    Asked for, and worth handling carefully.  This is the crudest reading of
    the table there is: it says a request queue and a support contract weigh
    the same, and they do not.  It is published anyway, and in the order the
    numbers actually fall, because a comparison that only reports totals when
    they flatter the author is not a comparison.

    We do not come first on it.
    """
    ceiling = len(CAPABILITIES) * 5
    rows = []
    for p in PRODUCTS:
        rows.append({**p,
                     "total": sum(c[p["key"]] for c in CAPABILITIES),
                     "ceiling": ceiling})
    rows.sort(key=lambda r: r["total"], reverse=True)
    for i, r in enumerate(rows, start=1):
        r["rank"] = i
    return rows


def pricing():
    """
    The pricing cards, in the same order as the star totals.

    Two of the four vendors publish no price at all, so most of this is
    reseller listings and price trackers rather than a rate card.  The notes
    say which is which, and the date says how stale it is allowed to get.
    """
    order = [r["key"] for r in product_totals()]
    by_key = {p["key"]: p for p in PRODUCTS}
    out = []
    for key in order:
        entry = next(p for p in PRICING if p["key"] == key)
        out.append({**entry, "label": by_key[key]["label"],
                    "vendor": by_key[key]["vendor"]})
    return out


def totals():
    """
    Rows won, lost and drawn, against the field rather than against one rival.

    Ahead means we beat every other product on that row.  Behind means at least
    one of them beats us.  That is a harder test than the old one against NGINX
    Plus alone, and the numbers moved when the two appliances arrived, which is
    what an honest comparison is supposed to do.
    """
    wins = losses = 0
    for c in CAPABILITIES:
        best = max(c[k] for k in RIVAL_KEYS)
        if c["lb"] > best:
            wins += 1
        elif c["lb"] < best:
            losses += 1
    return {"total": len(CAPABILITIES), "ahead": wins, "behind": losses,
            "level": len(CAPABILITIES) - wins - losses,
            "pulled": PRICING_PULLED}
