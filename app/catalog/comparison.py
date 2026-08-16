"""
Failover LB against NGINX Plus, capability by capability.

Read the honesty warning before the table, because it applies to every number
in this file: **we are rating our own product against somebody else's.**  That
is a conflict of interest and no amount of care removes it.  What can be done
is to be specific about why each score is what it is, so a reader can disagree
with the reasoning rather than having to take the number on trust.

The scale, and it is deliberately not "how good is this":

    0   not offered at all
    1   possible, but you are building it yourself
    2   there, and you will feel the gap
    3   does the job
    4   does the job well
    5   as good as this gets

A capability with a 5 against Plus and a 3 against us is not a complaint.  It
means somebody paid for it and got something better, which is what paying is
for.  The rows worth arguing about are the ones where we claim to be equal or
better, and those are the ones with the longest notes.

Three things this table deliberately does **not** do:

  * **Count Instance Manager, NGINX One or App Protect as part of Plus.**  They
    are separate products with separate prices.  Where one of them is the real
    answer to a row, the note says so rather than the score pretending Plus
    lacks it entirely.
  * **Take credit for nginx itself.**  Most of what a load balancer does is in
    the free nginx both sides run.  Those rows are 5 and 5, and saying so is
    more useful than leaving them out to make the table look flattering.
  * **Hide the rows we lose.**  Support is the obvious one.
"""

# Everything below is a judgement, and the note is the argument for it.
#
#   key       stable id, so a link can point at a row
#   label     what the capability is called
#   category  how the page groups them
#   plus      0 to 5 for NGINX Plus
#   lb        0 to 5 for Failover LB
#   note      why those two numbers, in plain words
CAPABILITIES = [

    # ---------------------------------------------------------------- balancing
    {
        "key": "balancing_methods",
        "label": "Round robin, least connections, hashing",
        "category": "Load balancing",
        "plus": 5, "lb": 5,
        "note": "The same nginx underneath, so there is nothing to choose "
                "between them.  Most of what either product does for a living "
                "is here, and it is free in both.",
    },
    {
        "key": "least_time",
        "label": "Least time balancing",
        "category": "Load balancing",
        "plus": 5, "lb": 3,
        "note": "Plus picks the backend answering fastest right now.  We use "
                "least connections, which tracks response time closely in "
                "practice because a slow server piles up connections, but it "
                "is a proxy for the measurement rather than the measurement.",
    },
    {
        "key": "sticky",
        "label": "Sticky sessions",
        "category": "Load balancing",
        "plus": 5, "lb": 3,
        "note": "Plus issues its own cookie, so it works whatever the "
                "application does.  We hash a cookie the application already "
                "sets, which is as good when there is one, or hash the client "
                "address when there is not — and that sends a whole office "
                "behind one NAT to a single backend.",
    },
    {
        "key": "slow_start",
        "label": "Slow start after recovery",
        "category": "Load balancing",
        "plus": 5, "lb": 2,
        "note": "Plus eases traffic back onto a server that just came back.  "
                "We have no equivalent: the working method is to return the "
                "backend at a low weight and raise it once it is warm, which "
                "is two deliberate steps by a person.",
    },
    {
        "key": "queueing",
        "label": "Request queueing",
        "category": "Load balancing",
        "plus": 5, "lb": 0,
        "note": "Plus holds requests when every backend is busy.  We have "
                "nothing: at the connection limit a request gets a 502 rather "
                "than waiting.  Set the limit high enough and shape load with "
                "rate limiting before it gets there.",
    },
    {
        "key": "stream",
        "label": "TCP and UDP proxying",
        "category": "Load balancing",
        "plus": 5, "lb": 5,
        "note": "The stream module is free.  Both get it, and ours is driven "
                "from a page rather than a config file.",
    },

    # ------------------------------------------------------------------- health
    {
        "key": "active_health",
        "label": "Active health checks",
        "category": "Health and resilience",
        "plus": 5, "lb": 4,
        "note": "Plus probes from inside nginx, so it reacts in the worker "
                "that is about to route the request.  We probe from the "
                "manager on a schedule and rewrite the upstream, so reaction "
                "is a check interval plus a reload rather than immediate.  "
                "Two things ours does that Plus does not: it checks from "
                "every node rather than one, and it refuses to mark the last "
                "healthy backend down, so a broken check cannot empty a pool.",
    },
    {
        "key": "passive_health",
        "label": "Passive health checks",
        "category": "Health and resilience",
        "plus": 5, "lb": 5,
        "note": "max_fails and fail_timeout are free nginx.  Identical.",
    },
    {
        "key": "ha",
        "label": "Load balancer failover",
        "category": "Health and resilience",
        "plus": 3, "lb": 5,
        "note": "Plus ships a keepalived package, which works and is "
                "configured in files on each box.  Ours is built in: election "
                "with a quorum rule, a standby that refuses to promote itself "
                "when it cannot see a majority, and the whole thing visible on "
                "a page.  The quorum rule is the part that matters, because "
                "the failure it prevents is two nodes both deciding they are "
                "active.",
    },
    {
        "key": "two_phase",
        "label": "Config tested on every node before any node applies",
        "category": "Health and resilience",
        "plus": 1, "lb": 5,
        "note": "The one we would keep if we could only keep one.  A change is "
                "staged and tested on every node, and applied nowhere unless "
                "it passed everywhere.  Plus has nothing here; Instance "
                "Manager, sold separately, can validate config, and that is "
                "still not the same as an all or nothing fleet apply.",
    },

    # --------------------------------------------------------------------- TLS
    {
        "key": "tls",
        "label": "TLS termination, stapling, session cache",
        "category": "TLS and certificates",
        "plus": 5, "lb": 5,
        "note": "Free nginx, both sides.  Ours builds against a current "
                "OpenSSL so the post quantum key exchange is available, which "
                "is a build choice rather than a feature either product owns.",
    },
    {
        "key": "acme",
        "label": "Certificate issuance and renewal",
        "category": "TLS and certificates",
        "plus": 3, "lb": 5,
        "note": "nginx has gained a native ACME module, and it issues "
                "certificates.  What is rated here is the rest of the job: "
                "issuing from whichever node owns the address, replicating to "
                "the others, renewing on a schedule, staging first, DNS-01 "
                "where HTTP-01 will not do, and degrading to the old "
                "certificate rather than freezing the fleet when something "
                "goes wrong.",
    },
    {
        "key": "paid_ca",
        "label": "Certificates from a paid authority",
        "category": "TLS and certificates",
        "plus": 1, "lb": 5,
        "note": "Neither product is a certificate manager, but we became one: "
                "authorities are profiles with their own credentials, several "
                "can be in use at once, and a certificate renews from the "
                "authority that issued it rather than quietly from somewhere "
                "else in sixty days.",
    },

    # ---------------------------------------------------------------- security
    {
        "key": "waf",
        "label": "Web application firewall",
        "category": "Security",
        "plus": 5, "lb": 3,
        "note": "F5's App Protect is a serious WAF and a separate purchase.  "
                "Ours is ModSecurity with the OWASP rules, installed and kept "
                "current across the fleet from a page.  Three rather than four "
                "because the part that makes a WAF survivable — learning from "
                "known testers and turning that into exclusions — is specified "
                "and not yet built.",
    },
    {
        "key": "jwt",
        "label": "JWT validation at the proxy",
        "category": "Security",
        "plus": 5, "lb": 2,
        "note": "Plus validates the token itself.  We use auth_request, which "
                "is free and works for any scheme, and which means you write "
                "and run a small service.  That is a real piece of work, not a "
                "setting.",
    },
    {
        "key": "oidc",
        "label": "OIDC sign in for proxied applications",
        "category": "Security",
        "plus": 4, "lb": 1,
        "note": "Worth separating carefully.  Plus can put an OIDC login in "
                "front of an application it proxies.  We sign **admins** in to "
                "this GUI with OIDC, which is a different thing, and we do "
                "nothing for the traffic passing through.",
    },
    {
        "key": "geo",
        "label": "Blocking by country",
        "category": "Security",
        "plus": 3, "lb": 5,
        "note": "The geoip2 module is free for both.  The work is the "
                "database: getting one, putting it on every node, and keeping "
                "it current, which we do from a page on a schedule.  With Plus "
                "that is yours to arrange.",
    },
    {
        "key": "acl",
        "label": "Allow and deny lists, basic auth",
        "category": "Security",
        "plus": 5, "lb": 5,
        "note": "Free nginx.  Ours are reusable objects attached to sites "
                "rather than lines repeated per server block.",
    },
    {
        "key": "admin_security",
        "label": "Admin accounts, roles, two factor, audit log",
        "category": "Security",
        "plus": 0, "lb": 5,
        "note": "Plus has no administrative interface to secure, so this is "
                "not a gap in it so much as a thing it does not have.  Ours "
                "has roles, TOTP, lockout, and an audit log with secrets "
                "scrubbed.  Instance Manager is where F5 put this, separately.",
    },

    # ----------------------------------------------------------- observability
    {
        "key": "live_stats",
        "label": "Live activity monitoring",
        "category": "Observability",
        "plus": 5, "lb": 3,
        "note": "Plus counts requests in flight, per upstream, inside the "
                "process.  Ours come from stub_status and the access log, and "
                "a request that has not finished has not been logged, so in "
                "flight is a number we genuinely cannot show.",
    },
    {
        "key": "utilization",
        "label": "CPU, memory and load over time",
        "category": "Observability",
        "plus": 2, "lb": 4,
        "note": "Plus reports on nginx; the box it runs on is somebody else's "
                "problem.  We chart both load balancers over time on their own "
                "page.  Four rather than five because the history is a couple "
                "of hours in memory and goes when the manager restarts.",
    },
    {
        "key": "backend_metrics",
        "label": "Backend CPU and memory",
        "category": "Observability",
        "plus": 0, "lb": 3,
        "note": "Neither product has an agent on your backends.  We read a "
                "Prometheus endpoint if a pool is given one, and label an "
                "application exporter differently from a machine one, because "
                "a JVM at 100% of one core is not a busy box.",
    },

    # -------------------------------------------------------------- operations
    {
        "key": "runtime_api",
        "label": "Changing upstreams without a reload",
        "category": "Operations",
        "plus": 5, "lb": 3,
        "note": "Plus changes upstreams over an API with no reload at all.  We "
                "rewrite the config and reload, which on nginx is graceful and "
                "drops nothing in flight, but it is a reload: a little CPU, two "
                "sets of workers briefly, and long lived connections holding "
                "the old ones open.",
    },
    {
        "key": "gui",
        "label": "Managing the whole thing from a browser",
        "category": "Operations",
        "plus": 1, "lb": 5,
        "note": "This is the product.  Plus is configured in files; its GUI is "
                "a statistics dashboard, and configuration through a browser is "
                "Instance Manager or NGINX One, sold separately.  Everything "
                "here is a page, and the API exists because the page needed it.",
    },
    {
        "key": "import",
        "label": "Importing an nginx config you already have",
        "category": "Operations",
        "plus": 0, "lb": 4,
        "note": "We parse an existing config into sites, pools and settings, "
                "so adopting this does not start with retyping.  Four because "
                "anything it cannot model is kept as raw config rather than "
                "quietly dropped, and you should read the result.",
    },
    {
        "key": "binaries",
        "label": "Where the nginx binary comes from",
        "category": "Operations",
        "plus": 5, "lb": 3,
        "note": "A row we lose and should.  Plus is a supported package from "
                "F5.  Ours is built from source on each node so the modules can "
                "be chosen, which means a rebuild to add one and means you are "
                "carrying that build yourself.  We drive it from a page, one "
                "node at a time, which makes it survivable rather than pleasant.",
    },
    {
        "key": "backup",
        "label": "Backing up and rebuilding a fleet",
        "category": "Operations",
        "plus": 0, "lb": 5,
        "note": "One file holds the whole configuration, and a fleet with "
                "nothing in common with the old one can be rebuilt from it.  "
                "With Plus this is whatever you already do for config files, "
                "which for most people is whatever their configuration "
                "management does.",
    },
    {
        "key": "tunnel",
        "label": "Reaching backends with no public address",
        "category": "Operations",
        "plus": 0, "lb": 4,
        "note": "A WireGuard tunnel a workload enrols into with one command, "
                "so a machine behind NAT becomes a pool member without asking "
                "anybody for a firewall change.  Neither nginx nor Plus does "
                "anything like this; it assumes the backend is already "
                "reachable.",
    },
    {
        "key": "gslb",
        "label": "DNS based failover between sites",
        "category": "Operations",
        "plus": 0, "lb": 3,
        "note": "Not in Plus at all — F5 sell that as a different product "
                "entirely.  Ours answers DNS with the healthy site, which "
                "covers the common case and inherits every DNS caching problem "
                "there has ever been.",
    },
    {
        "key": "error_pages",
        "label": "Custom error pages",
        "category": "Operations",
        "plus": 2, "lb": 4,
        "note": "error_page is free in both, and then you are writing HTML and "
                "putting it on every node yourself.  Ours are templates you "
                "point sites at, replicated with the config.",
    },
    {
        "key": "support",
        "label": "Somebody to call",
        "category": "Support",
        "plus": 5, "lb": 0,
        "note": "First row on the page, and the one we lose worst.  Plus comes "
                "with F5 support and an SLA: a number to ring at three in the "
                "morning and somebody contractually obliged to answer.  This is "
                "a project on a box, and when it breaks the person fixing it is "
                "you.  If that matters where you work it matters more than "
                "every other row put together, and no amount of features below "
                "changes it.",
    },

    # --------------------------------------------------------------- protocols
    {
        "key": "http3",
        "label": "HTTP/3 and QUIC",
        "category": "Content and protocols",
        "plus": 5, "lb": 4,
        "note": "Free in nginx now.  Four because our installer does not turn "
                "it on by default, so it is a build flag and a rebuild away "
                "rather than already there.",
    },
    {
        "key": "streaming",
        "label": "HLS, DASH and f4f video packaging",
        "category": "Content and protocols",
        "plus": 5, "lb": 0,
        "note": "Compiled into the Plus binary and not available any other "
                "way.  If you need packaged video streaming, that is a real "
                "reason to buy Plus.",
    },
    {
        "key": "ntlm",
        "label": "NTLM connection pinning",
        "category": "Content and protocols",
        "plus": 5, "lb": 0,
        "note": "Keeps a connection pinned through a Windows authentication "
                "handshake.  It cannot be done from outside the process, so if "
                "you proxy to something needing NTLM this one will bite.",
    },
    {
        "key": "mqtt",
        "label": "MQTT preread and filtering",
        "category": "Content and protocols",
        "plus": 5, "lb": 0,
        "note": "Stream level MQTT parsing, Plus only.  No way around it.",
    },
    {
        "key": "keyval",
        "label": "Runtime key value store",
        "category": "Content and protocols",
        "plus": 4, "lb": 1,
        "note": "Plus keeps a store you can change over the API, which is how "
                "people build live blocklists.  We have maps, which means "
                "rewriting config and reloading to change one entry.",
    },
]

CATEGORIES = [
    # Support goes first on purpose.  It is the row we lose worst, and a
    # comparison written by one of the two products that buries its weakest
    # answer near the bottom has told you something about itself before you
    # reach any of the numbers.
    "Support",
    "Load balancing",
    "Health and resilience",
    "TLS and certificates",
    "Security",
    "Observability",
    "Operations",
    "Content and protocols",
]


def by_category():
    """Rows grouped for the page, in the order the categories are listed."""
    return [(name, [c for c in CAPABILITIES if c["category"] == name])
            for name in CATEGORIES]


def only_here():
    """
    What this does that Plus does not do at all.

    Kept to rows where Plus scores zero, rather than anywhere we happen to
    score higher.  "We do it better" is an argument; "it is not there" is a
    fact, and only the second belongs on a list with this title.
    """
    return [c for c in CAPABILITIES if c["plus"] == 0 and c["lb"] > 0]


def totals():
    """
    Rows won, lost and drawn.

    Offered as a summary and not as a score.  Adding up stars would say a
    request queue and a support contract weigh the same, and they do not.
    """
    wins = sum(1 for c in CAPABILITIES if c["lb"] > c["plus"])
    losses = sum(1 for c in CAPABILITIES if c["lb"] < c["plus"])
    return {"total": len(CAPABILITIES), "ahead": wins, "behind": losses,
            "level": len(CAPABILITIES) - wins - losses}
