"""
Part 2: the everyday work.

House style: two spaces between sentences, no em dashes, plain words, and
never assume the reader has done this before.
"""


def write(b, shot, term):
    _pools(b, shot)
    _sites(b, shot)
    _paths(b, shot)
    _certificates(b, shot, term)
    _error_pages(b, shot)
    _access(b, shot)
    _maps(b, shot)
    _streams(b, shot)
    _applying(b, shot)
    _utilization(b, shot)


# ---------------------------------------------------------------------------
def _pools(b, shot):
    b.h1("8. Backend pools")

    b.para(
        "A pool is the list of servers that run your application.  This chapter "
        "comes first because a site needs a pool to point at, so making the "
        "pool is the first real job.")

    b.picture(shot("pools"), "The Backend Pools page.")

    b.h2("Making a pool")
    b.steps([
        "Go to Backend Pools and press New pool.",
        "Give it a name.  Use something that says what is in it, such as "
        "shop-web or billing-api.  You will pick it from a list later and the "
        "name is all you will see.",
        "Add each server, one row per server.  You need its address and the "
        "port your application listens on.",
        "Press Save.",
    ])

    b.note(
        "Saving a pool changes nothing for your visitors yet.  Nothing is live "
        "until you apply, which is Chapter 16.")

    b.h2("What the settings mean")
    b.table(
        ["Setting", "What it does"],
        [
            ["Balancing method",
             "How requests are spread across the servers.  Round robin sends "
             "them out in turn and is the right answer for almost everybody.  "
             "Least connections favours whichever server is least busy, which "
             "helps when some requests take much longer than others."],
            ["Weight",
             "How much of the traffic a server takes compared to the others.  "
             "Leave it at 1 unless one machine is genuinely bigger, then give "
             "it 2 to send it twice as much."],
            ["Backup",
             "A server that is used only when every other server in the pool "
             "is down.  Useful for a holding page, and a common mistake "
             "otherwise, because a backup server sits idle and untested until "
             "the worst possible moment."],
            ["Max fails and fail timeout",
             "How many failures in a row before the server is taken out, and "
             "for how long.  Three failures and ten seconds suits most "
             "people."],
            ["Keep alive",
             "How many connections to hold open ready for the next request.  "
             "This makes a real difference to speed and the default is "
             "sensible."],
        ],
        widths=[1.6, 4.7])

    b.h2("Health checks")
    b.para(
        "The load balancer checks each server regularly and stops sending "
        "traffic to any that stop answering.  This is what makes a pool worth "
        "having.  By default it checks that the server accepts a connection.")

    b.para(
        "A better check asks for a page and looks at the answer.  If your "
        "application has a health page, point the check at it.  A server whose "
        "web process is running but whose database has gone will still accept a "
        "connection, so a connection check calls it healthy while every visitor "
        "gets an error.")

    b.warn(
        "Point the health check at something that genuinely tests the "
        "application.  A page that returns OK without touching anything is "
        "only telling you the web server is running, which you already knew.")

    b.h2("Servers that use https")
    b.para(
        "If your application speaks https rather than plain http, turn on the "
        "TLS setting for the pool.  There are two further settings and they "
        "matter.")

    b.table(
        ["Setting", "When to change it"],
        [
            ["Check the certificate",
             "On by default, and right for a backend with a real certificate.  "
             "Turn it off only for a backend using a self signed certificate, "
             "for example something on the same machine."],
            ["Certificate authority file",
             "If your company issues its own certificates, point this at your "
             "company's authority file.  Then checking stays on and still "
             "works."],
        ],
        widths=[1.9, 4.4])

    b.note(
        "If a pool with TLS turned on gives errors straight away, this is "
        "usually why.  The backend's certificate cannot be checked, so the "
        "connection is refused.  The page for the pool says so.")
    b.page_break()


# ---------------------------------------------------------------------------
def _sites(b, shot):
    b.h1("9. Sites")

    b.para(
        "A site is one web address and the rules for what happens when somebody "
        "visits it.  Now that you have a pool, you can put a site in front of "
        "it.")

    b.picture(shot("sites"), "The Sites page.")

    b.h2("Making a site")
    b.steps([
        "Go to Sites and press New site.",
        "Give it a name.  This is for your use only and visitors never see it.",
        "Under Server names, put the web address people will type, such as "
        "www.domain.com.  You can add more than one.",
        "Choose Proxy as the mode, and pick the pool you made in Chapter 8.",
        "Press Create site.",
    ])

    b.h2("The three modes")
    b.table(
        ["Mode", "What it does"],
        [
            ["Proxy",
             "Passes requests to a pool.  This is what you want for an "
             "application."],
            ["Static",
             "Serves files straight from a folder on the server.  Good for a "
             "holding page or a set of downloads."],
            ["Redirect",
             "Sends visitors somewhere else.  Used for old addresses you want "
             "to keep working."],
        ],
        widths=[1.1, 5.2])

    b.h2("www and the bare domain")
    b.para(
        "Most people want both domain.com and www.domain.com to work, and want "
        "one of them to be the real address so the other simply forwards to it.  "
        "Put both names on the site and turn on the setting to send everything "
        "to the first name.  Visitors who type either one end up in the same "
        "place, and search engines are not confused by the same pages appearing "
        "at two addresses.")

    b.note(
        "The forward is written so it does not interfere with certificate "
        "renewal.  This is worth knowing because doing it by hand in nginx "
        "usually does interfere, and the certificate then quietly fails to "
        "renew two months later.")

    b.h2("Secure traffic")
    b.para(
        "Turn on Listen on https and pick a certificate.  Chapter 11 covers "
        "getting one.  Leave Force https on, which sends anybody arriving on "
        "the plain address over to the secure one.")

    b.warn(
        "Do not turn off Listen on http.  Certificate renewal needs port 80 to "
        "answer.  Force https already means no real visitor stays on it.")
    b.page_break()


# ---------------------------------------------------------------------------
def _paths(b, shot):
    b.h1("10. Sending different paths to different places")

    b.para(
        "So far a site sends everything to one pool.  Often you want part of a "
        "site handled differently: /api to one set of servers and everything "
        "else to another, or /downloads served as files.  That is what paths "
        "are for.")

    b.h2("Adding a path")
    b.steps([
        "Open the site and find the Paths section.",
        "Press Add a path.",
        "Type the path, such as /api.",
        "Choose what it does.  The choices are the same three as a site: send "
        "it to a pool, serve files, or redirect.",
        "Press Save.",
    ])

    b.h2("How paths are chosen")
    b.para(
        "When a request arrives, the most specific matching path wins.  A "
        "request for /api/users matches a path of /api rather than the site's "
        "general rule, because /api is more specific.  You do not have to put "
        "them in any particular order.")

    b.h2("Taking the path off before passing it on")
    b.para(
        "There is a setting called Take this path off before sending it on.  It "
        "is worth understanding because getting it wrong produces a confusing "
        "failure.")

    b.para(
        "With it off, a request for /api/users reaches your application as "
        "/api/users.  With it on, the same request reaches it as /users.")

    b.para(
        "Which you want depends on the application.  If it was written knowing "
        "it lives under /api, leave the setting off.  If it expects to be at "
        "the top level and you are mounting it under a prefix it has never "
        "heard of, turn it on.")

    b.note(
        "The giveaway for getting this wrong is a page that loads but has no "
        "styling, because the page itself was found and the stylesheet was "
        "not.  It looks like a problem with the appearance and it is really the "
        "path.")
    b.page_break()


# ---------------------------------------------------------------------------
def _certificates(b, shot, term):
    b.h1("11. Certificates")

    b.para(
        "A certificate is what makes the padlock appear in the browser and what "
        "stops anybody between your visitor and your server reading the "
        "traffic.  This chapter covers the four ways to get one.")

    b.picture(shot("certificates"), "The Certificates page.")

    b.h2("Which one do I want?")
    b.table(
        ["If you want", "Use"],
        [
            ["A certificate that costs nothing and renews itself",
             "Lets Encrypt.  This is the right answer for nearly everybody."],
            ["To use a certificate your company already bought",
             "Upload one."],
            ["Something for testing that browsers will warn about",
             "Make a self signed one."],
            ["To buy from a particular supplier",
             "Make a signing request."],
        ],
        widths=[3.4, 2.9])

    b.h2("Getting one from Lets Encrypt")
    b.para(
        "Lets Encrypt gives out certificates free, and this software renews them "
        "for you before they run out.  For it to work, the name you are asking "
        "for has to already point at one of your servers, and port 80 has to be "
        "reachable from the internet.")

    b.picture(shot("cert-letsencrypt"),
              "Asking Lets Encrypt for a certificate.")

    b.steps([
        "Press Get one from Lets Encrypt.",
        "Type the domain name, such as www.domain.com.  You can add more names "
        "to one certificate.",
        "Press Request.  It takes about thirty seconds.",
    ])

    b.para(
        "The certificate appears in the list marked valid, with the number of "
        "days until it expires and which servers have a copy.")

    b.note(
        "Only the server that currently owns the public address can answer the "
        "check, and which server that is changes when you fail over.  The "
        "software works out which one can do it every time rather than assuming "
        "whoever did it last still can.  The Where? button explains its "
        "reasoning for any certificate.")

    b.h2("Renewal")
    b.para(
        "Renewal happens on its own, thirty days before expiry by default.  You "
        "do not need to do anything and you do not need a calendar reminder.  "
        "If a renewal fails, the certificate list says so, and it keeps trying, "
        "so a single bad night does not become an outage a month later.")

    b.h2("Uploading one you already have")
    b.para(
        "If your company buys certificates, press Upload one and paste in the "
        "certificate and its private key.  The software checks that the key "
        "actually matches the certificate before it saves anything, which "
        "catches the most common mistake, and it puts any intermediate "
        "certificates in the right order for you.")

    b.h2("Making a signing request")
    b.para(
        "If your supplier needs a signing request, press Make a signing "
        "request.  Choose a key length of 2048 or 4096.  Both are fine; 2048 is "
        "faster and 4096 is what some auditors ask for.")

    b.para(
        "You get a block of text to send to your supplier.  The private key "
        "stays here and is never sent anywhere, which is the point of doing it "
        "this way.  When your supplier sends the certificate back, find the "
        "request in the list, press Paste Certificate, and paste in what they "
        "sent.  It is then a normal certificate and can be used on a site.")

    b.h2("Self signed certificates")
    b.warn(
        "A self signed certificate makes every browser show a warning, because "
        "nothing has vouched for it.  It is fine for testing and for something "
        "only your own systems talk to.  Never use one on a site the public "
        "visits.")

    b.h2("Deleting a certificate")
    b.para(
        "A certificate that is not being used by any site can be deleted.  One "
        "that is in use cannot, and the page tells you which site is using it.  "
        "That is deliberate: deleting a certificate a site depends on would "
        "stop that site working the moment you next applied.")
    b.page_break()


# ---------------------------------------------------------------------------
def _error_pages(b, shot):
    b.h1("12. Error pages")

    b.para(
        "When something goes wrong, visitors see a bare page from nginx that "
        "says 502 Bad Gateway and nothing else.  Error page templates replace "
        "that with something of your own.")

    b.picture(shot("errorpages"), "The Error Pages page.")

    b.h2("Making a template")
    b.steps([
        "Go to Error Pages and press New template.",
        "Give it a name.",
        "Write the page for each error you care about.  404 for a page that "
        "does not exist and 502 for the application being down are the two "
        "worth doing first.",
        "Press Save.",
    ])

    b.para(
        "Then open a site and choose the template.  You can also set a "
        "different template on a single path, which is useful when part of a "
        "site is an API that should return something machine readable rather "
        "than a friendly page.")

    b.h2("Errors from your application")
    b.note(
        "By default your error pages are also used for errors your application "
        "returns, not just errors nginx generates itself.  If your application "
        "already returns its own nicely designed error pages, turn that setting "
        "off for the site so its pages are passed through untouched.")

    b.h2("What to write")
    b.para(
        "Keep it short and say what the visitor should do.  A page that says "
        "the site is having a problem and to try again in a few minutes is "
        "worth more than a clever design.  Avoid technical detail: it does not "
        "help the visitor and it tells anybody probing your site more than they "
        "need to know.")
    b.page_break()


# ---------------------------------------------------------------------------
def _access(b, shot):
    b.h1("13. Limits, caches and access lists")

    b.para(
        "The Zones and Access page holds the shared pieces your sites point "
        "at.  There are four kinds, on four tabs: rate limits, connection "
        "limits, caches, and access lists.  You make one here, then choose it "
        "on a site or on a single path.")

    b.h2("Why they live on their own page")
    b.para(
        "nginx wants these declared once near the top of its configuration and "
        "then used further down.  That is the reason they are not settings on a "
        "site.  It also turns out to be what you want, because several sites "
        "can share one: a single login limit protecting every sign in page you "
        "run is easier to reason about than six separate ones.")

    b.note(
        "Each list has a Used by column.  A zone that says it is not used yet "
        "is doing nothing.  Making one is only half the job, and choosing it on "
        "a site is the other half.")

    b.h2("Rate limits")
    b.para(
        "A rate limit caps how many requests one visitor may make in a period.  "
        "It is the simplest protection against somebody hammering a login page "
        "guessing passwords, and against one badly written script using all of "
        "your capacity.")

    b.picture(shot("zones-rate"), "The rate limits tab.")

    b.table(
        ["Setting", "What it does", "Usual value"],
        [
            ["Name", "What you will pick it by on a site", "login-limit"],
            ["Counts by",
             "What makes two requests count as the same visitor.  The "
             "visitor's address is the normal answer", "$binary_remote_addr"],
            ["Rate",
             "How many requests are allowed, per second or per minute",
             "10r/s"],
            ["Memory",
             "How much to set aside for remembering visitors.  10m holds "
             "roughly 160,000 addresses, which is plenty for most sites",
             "10m"],
        ],
        widths=[1.2, 3.9, 1.2])

    b.warn(
        "Set the rate well above what a real person does.  Somebody reading a "
        "site makes a handful of requests a second while a page loads, so ten a "
        "second stops abuse without anybody noticing.  Set it too low and real "
        "visitors get errors, which is a worse outage than the one you were "
        "protecting against, and harder to spot because most people just "
        "leave.")

    b.para(
        "Test it before you rely on it.  Ask for a page faster than the limit "
        "and confirm you get refused, then confirm normal use does not.")

    b.h2("Connection limits")
    b.para(
        "A connection limit caps how many conversations one visitor may have "
        "open at once, rather than how fast they ask.  The two are different "
        "and protect against different things.  A rate limit stops rapid "
        "requests; a connection limit stops one visitor holding open hundreds "
        "of slow ones, which is how a small number of machines can tie up a "
        "server without ever looking busy.")

    b.picture(shot("zones-conn"), "The connection limits tab.")

    b.table(
        ["Setting", "What it does", "Usual value"],
        [
            ["Name", "What you pick it by", "per-visitor"],
            ["Counts by", "What counts as one visitor", "$binary_remote_addr"],
            ["Memory", "Space for remembering them", "10m"],
        ],
        widths=[1.2, 3.9, 1.2])

    b.note(
        "Be careful with a low connection limit on a normal website.  A browser "
        "opens several connections at once on purpose, so a limit of one or two "
        "will break ordinary visitors.  Ten is a gentle starting point.")

    b.h2("Caches")
    b.para(
        "A cache lets the load balancer keep a copy of things that do not "
        "change often, so your application is not asked for the same image a "
        "thousand times.  Done well it is the cheapest speed improvement "
        "available.")

    b.picture(shot("zones-cache"), "The caches tab.")

    b.table(
        ["Setting", "What it does", "Usual value"],
        [
            ["Name", "What you pick it by", "static-files"],
            ["Folder", "Where on disk the copies are kept",
             "/var/cache/nginx/static"],
            ["Memory for the index",
             "Space for the list of what is cached, not the copies themselves",
             "10m"],
            ["Maximum size",
             "How much disk the copies may use before the oldest are thrown "
             "away", "1g"],
            ["Inactive",
             "Throw something away if nobody has asked for it in this long, "
             "even if there is room", "60m"],
        ],
        widths=[1.5, 3.6, 1.2])

    b.warn(
        "Cache static things: images, stylesheets, downloads.  Be careful with "
        "anything that differs per visitor.  A cached page belonging to one "
        "signed in user being served to another is the classic caching "
        "accident, and it is a data breach rather than a glitch.")

    b.h2("Access lists")
    b.para(
        "An access list decides who may reach a site or a path, by address.  "
        "The common use is putting an admin area behind your office network "
        "while the rest of the site stays public.")

    b.picture(shot("zones-acl"), "The access lists tab.")

    b.table(
        ["Setting", "What it does"],
        [
            ["Allowed",
             "Addresses or networks that may reach it.  One per line.  A single "
             "address or a range such as 198.51.100.0/24."],
            ["Blocked",
             "Addresses that may not.  Used with a default of allow, for "
             "shutting out a specific nuisance."],
            ["When nothing matches",
             "Allow or deny.  Deny with a list of allowed addresses is a "
             "private area.  Allow with a list of blocked ones is a public area "
             "with exceptions."],
            ["Include the management networks",
             "Adds the networks allowed to reach the management screen, so you "
             "do not lock yourself out of your own admin area."],
            ["Ask for a username and password",
             "A second lock on top of the address check.  Reasonable as a "
             "second layer, thin on its own."],
            ["Trust the address from a header",
             "Turn on only if something else sits in front of these load "
             "balancers, such as a CDN.  Without it you would be filtering on "
             "the address of that service rather than the real visitor."],
        ],
        widths=[1.9, 4.4])

    b.warn(
        "Trust the address from a header is the one to think about.  If you "
        "turn it on when nothing trustworthy is in front, anybody can set that "
        "header themselves and walk straight through your access list.  Turn it "
        "on only when you know what is in front and you have named it as "
        "trusted.")

    b.h2("Using one")
    b.steps([
        "Make the zone or list on this page.",
        "Open the site, or a single path on the site.",
        "Choose it from the list of that kind.",
        "Apply.",
    ])

    b.para(
        "Choosing it on a path rather than the whole site is what lets you rate "
        "limit only the login page, or lock down only the admin area, and leave "
        "everything else alone.  That is nearly always what you want.")
    b.page_break()


# ---------------------------------------------------------------------------
def _maps(b, shot):
    b.h1("14. Maps")

    b.para(
        "A map is a lookup table.  It reads one thing about a request, works "
        "down a list of rules, and sets a value you can then use elsewhere.  "
        "This is the most technical chapter in Part 2 and you can skip it until "
        "you need it.")

    b.picture(shot("maps"), "The Maps page.")

    b.h2("What it is for")
    b.para(
        "The usual reason is doing something conditionally without repeating "
        "yourself.  If three sites all need to treat requests from mobile "
        "phones differently, one map does the deciding and all three sites use "
        "the answer.")

    b.h2("Making one")
    b.steps([
        "Press Add one.",
        "Choose what it reads.  The browser type and the requested host are the "
        "common choices.",
        "Say what variable it sets.  This is a name you invent.",
        "Add the rules, most specific first.  The first match wins.",
        "Say what to use when nothing matches.",
    ])

    b.para(
        "A plain word matches exactly.  Starting a rule with a squiggle means "
        "it is a pattern rather than a fixed word, and a squiggle followed by a "
        "star means the pattern ignores capital letters.")

    b.note(
        "The value a map sets is checked before it is saved.  A name nginx does "
        "not recognise would stop nginx starting on every server at once, so it "
        "is refused here instead.")
    b.page_break()


# ---------------------------------------------------------------------------
def _streams(b, shot):
    b.h1("15. TCP and UDP")

    b.para(
        "Everything so far has been about web traffic.  This page balances "
        "things that are not web traffic: a database, a mail server, a game "
        "server, anything that speaks its own protocol.")

    b.picture(shot("streams"), "The TCP and UDP page.")

    b.h2("How it differs from a site")
    b.para(
        "There are no paths, no error pages and no redirects, because those are "
        "web ideas and this is not the web.  What you get is a port to listen "
        "on and a pool to send connections to.")

    b.h2("Making one")
    b.steps([
        "Press Add one.",
        "Choose TCP or UDP.  If you are not sure, it is TCP.",
        "Say which port to listen on.",
        "Choose the pool.",
        "Press Save, then apply.",
    ])

    b.warn(
        "Pools used here are kept separate from the pools used by sites, even "
        "when the servers in them are the same.  This is a rule in nginx "
        "itself, not a choice made here.  You will see the same servers listed "
        "twice and that is correct.")

    b.h2("Passing on the visitor's address")
    b.para(
        "By default your backend sees the connection as coming from the load "
        "balancer, because it is.  If your application needs the real visitor "
        "address, turn on the proxy protocol setting, but only if the "
        "application understands it.  A backend that does not will fail to read "
        "the connection at all.")
    b.page_break()


# ---------------------------------------------------------------------------
def _applying(b, shot):
    b.h1("16. Applying changes")

    b.para(
        "This chapter is short and it is the most important one in Part 2.  "
        "Everything you have saved so far is written down and none of it is "
        "live.  Applying is what makes it real.")

    b.picture(shot("changes"), "The Changes page, showing what is saved but not live.")

    b.h2("What happens when you press Apply")
    b.numbers([
        "The whole configuration is built from what you have saved.",
        "It is checked for problems before anything is sent.",
        "It is sent to every server and each one tests it without using it.",
        "Only if every server accepts it does each one switch over.",
        "If any server refuses, every server keeps what it had and you are told "
        "what was wrong.",
    ])

    b.para(
        "This is why applying is safe.  A configuration that would stop nginx "
        "starting cannot get halfway across your servers.  Either the change "
        "happens everywhere or it happens nowhere.")

    b.h2("The Changes page")
    b.para(
        "The Changes page shows what is saved and not yet live, and what "
        "changed.  Read it before applying, particularly if somebody else has "
        "been working on the same thing.  You are about to make their changes "
        "live along with your own.")

    b.h2("Warnings before applying")
    b.para(
        "Some changes get a warning first.  The most common is a pool with no "
        "healthy servers in it, which means the site would serve errors.  A "
        "warning is not a refusal.  Sometimes serving an error page from a pool "
        "you are about to fill is exactly what you meant to do.")

    b.h2("If something goes wrong anyway")
    b.para(
        "Every apply is kept, so you can look at what changed and put it back.  "
        "Chapter 24 covers going back to an earlier configuration.")

    b.note(
        "Get into the habit of applying in small steps.  One change applied and "
        "checked is easy to understand.  Nine changes applied together, one of "
        "which broke something, is an afternoon.")
    b.page_break()


# ---------------------------------------------------------------------------
def _utilization(b, shot):
    b.h1("17. Utilization")

    b.para(
        "The Utilization page shows how busy things are over time.  It answers "
        "the two questions people actually ask, which are whether the thing is "
        "coping now and whether it has been getting worse.")

    b.picture(shot("utilization"), "The Utilization page.")

    b.h2("What is on it")
    b.table(
        ["Chart", "What it tells you"],
        [
            ["Requests",
             "How much traffic is arriving.  A sudden change here explains most "
             "other charts."],
            ["Connections",
             "How many conversations are open at once.  Climbing while requests "
             "stay flat usually means something is answering slowly."],
            ["Processor and memory",
             "How hard each of your load balancer servers is working."],
            ["Backend servers",
             "The same for the servers in your pools, when they publish it.  "
             "This section is hidden when there is nothing to show."],
        ],
        widths=[1.7, 4.6])

    b.h2("Backend numbers")
    b.para(
        "The load balancer has no login on your application servers and does "
        "not want one.  Holding a password for every machine in the estate "
        "would make this the most valuable box on your network, which is a much "
        "bigger risk than a chart is worth.")

    b.para(
        "Instead it reads numbers your servers already publish, if they publish "
        "any.  Many do without anybody setting it up.  Put the address in the "
        "pool settings and the charts appear.  If a server publishes nothing, "
        "it is simply not measured and the page says so rather than guessing.")

    b.note(
        "A chart with a gap in it means no measurement was taken then, usually "
        "because something was restarting.  A gap is drawn as a gap and not as "
        "zero, because zero would read as the server being idle when it was "
        "actually being restarted.")
    b.page_break()
