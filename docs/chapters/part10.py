"""
Part 10: every dialog, field by field.

The dialogs are where the settings actually are.  A reader with the screen in
front of them and a box they do not understand should be able to find that box
here.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _intro(b)
    _site_pool(b, shot)
    _member(b, shot)
    _certs(b, shot)
    _content(b, shot)
    _zones_users(b, shot)


# ---------------------------------------------------------------------------
def _intro(b):
    b.h1("36. Every dialog, field by field")

    b.para(
        "This chapter is the reference half of the guide.  Earlier chapters "
        "explain when to use something and why.  This one lists what is in "
        "each box, so that somebody sitting in front of the screen with a "
        "field they do not recognise can look it up.")

    b.para(
        "Nothing here needs reading front to back.  Find the dialog you are "
        "looking at and read that section.")

    b.note(
        "Every dialog in this chapter saves without applying.  You can fill "
        "one in, save it, and nothing changes for your visitors until you "
        "press Apply config, as Chapter 16 describes.")


# ---------------------------------------------------------------------------
def _site_pool(b, shot):
    b.h2("New site")

    b.picture(shot("dlg-site"), "Making a site.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Name", "A label for your own use, never seen by visitors",
             "The main address"],
            ["Server names",
             "The web addresses this site answers for, one per line",
             "Just the one to start"],
            ["Mode", "Proxy, static or redirect", "Proxy"],
            ["Pool", "Which backend servers, when the mode is proxy",
             "The one you made first"],
            ["Listen on http", "Answer on the plain port", "On"],
            ["Listen on https", "Answer on the secure port", "On"],
            ["Certificate", "Which certificate to present",
             "Leave empty and add one later"],
        ],
        widths=[1.4, 3.6, 1.3])

    b.para(
        "Everything else about a site is on the site's own screen once it "
        "exists, which Chapter 29 covers in full.  This dialog only asks for "
        "enough to create it.")

    b.h2("New pool")

    b.picture(shot("dlg-pool"), "Making a pool.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Name", "A label you will pick from a list later",
             "Say what is in it, such as shop-web"],
            ["Description", "A note for whoever reads this next", "Optional"],
            ["Balancing method", "How requests are shared out",
             "Round robin"],
            ["Servers", "One row per backend, with address and port",
             "Add them all now"],
        ],
        widths=[1.4, 3.6, 1.3])

    b.para(
        "The rest of a pool's settings, including health checks and backend "
        "TLS, are on the pool's own screen.  Chapter 30 covers them.")
    b.page_break()


# ---------------------------------------------------------------------------
def _member(b, shot):
    b.h2("Adding a server to a pool")

    b.picture(shot("dlg-member"), "Adding one backend server.")

    b.table(
        ["Field", "What it does", "Usual value"],
        [
            ["Address", "Where the server is.  An address or a name",
             "10.0.0.11"],
            ["Port", "Which port your application listens on", "8080"],
            ["Weight", "Its share compared to the others", "1"],
            ["Backup", "Only used when everything else is down", "Off"],
            ["Max fails", "Failures in a row before it is taken out", "3"],
            ["Fail timeout", "How long it stays out", "10s"],
            ["Max connections", "A cap on connections at once.  0 is no cap",
             "0"],
            ["State", "Up, down, or draining", "Up"],
        ],
        widths=[1.4, 3.6, 1.1])

    b.note(
        "Draining is the one to remember.  It lets the server finish what it is "
        "doing while taking nothing new, so you can retire a machine without "
        "dropping anybody mid request.")
    b.page_break()


# ---------------------------------------------------------------------------
def _certs(b, shot):
    b.h2("Getting a certificate from Lets Encrypt")

    b.picture(shot("cert-letsencrypt"), "Asking for a free certificate.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Name", "A label, usually the domain", "The main domain"],
            ["Domains",
             "Every name this certificate should cover, one per line.  All of "
             "them must already point at your load balancers",
             "Just the site address"],
            ["Renew automatically",
             "Renew before it runs out, without anybody doing anything",
             "On"],
            ["Days before expiry to renew",
             "How early.  Leaves room for a few failed attempts", "30"],
        ],
        widths=[1.6, 3.5, 1.2])

    b.note(
        "This is the option most people want.  It costs nothing, it renews "
        "itself, and the only requirement is that the names already point here "
        "and port 80 is open.  Chapter 11 covers what happens if a renewal "
        "fails.")

    b.h2("Uploading a certificate")

    b.picture(shot("dlg-cert-upload"), "Uploading a certificate you already have.")

    b.table(
        ["Field", "What to paste"],
        [
            ["Name", "A label, usually the domain it covers"],
            ["Certificate",
             "The certificate itself, starting BEGIN CERTIFICATE.  Paste the "
             "intermediates below it as well if your supplier gave you any"],
            ["Private key",
             "The matching key, starting BEGIN PRIVATE KEY.  This never leaves "
             "your fleet"],
        ],
        widths=[1.3, 5.0])

    b.note(
        "The key is checked against the certificate before anything is saved, "
        "so a mismatched pair is refused here rather than discovered when a "
        "site stops working.  Intermediates are put in the right order for you, "
        "which is the other common upload mistake.")

    b.h2("Making a signing request")

    b.picture(shot("dlg-cert-csr"), "Making a request to send to a supplier.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Name", "A label", "The main domain"],
            ["Domains", "Every name the certificate should cover",
             "The site address"],
            ["Key length", "2048 or 4096 bits",
             "2048, unless told otherwise"],
            ["Organisation and country",
             "Your company details, if your supplier asks for them",
             "Ask your supplier"],
        ],
        widths=[1.6, 3.4, 1.3])

    b.para(
        "You get a block of text to send to your supplier.  The private key is "
        "made here and stays here, which is the point of doing it this way "
        "rather than letting somebody else generate it for you.")

    b.para(
        "When the certificate comes back, find the request in the list, press "
        "Paste Certificate, and paste in what they sent.  It becomes a normal "
        "certificate you can choose on a site.")

    b.h2("Making a self signed certificate")

    b.picture(shot("dlg-cert-self"), "Making one yourself, for testing.")

    b.warn(
        "Every browser shows a warning for these, because nothing has vouched "
        "for them.  Fine for testing and for something only your own systems "
        "talk to.  Never on a site the public visits.")
    b.page_break()


# ---------------------------------------------------------------------------
def _content(b, shot):
    b.h2("Adding a path to a site")

    b.picture(shot("dlg-path"), "Adding a path.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Path", "The part of the address, such as /api", "/api"],
            ["Match type",
             "Prefix matches anything starting with it and is what you want "
             "almost always.  Exact matches only that one address.  Regular "
             "expression is for patterns",
             "Prefix"],
            ["Mode", "Send it to a pool, serve files, or redirect", "Proxy"],
            ["Pool", "Which backend servers handle this path",
             "The pool for that part"],
            ["Take this path off before sending it on",
             "On when the backend knows nothing about the prefix.  Off when it "
             "has been told which prefix it lives under",
             "Off"],
            ["Access list and error pages",
             "Optional, and override whatever the site sets", "Leave empty"],
        ],
        widths=[1.7, 3.4, 1.2])

    b.warn(
        "The prefix setting is the one worth getting right first time.  Wrong "
        "either way gives a page that loads with no styling, which reads as an "
        "appearance problem and is really the path.  Chapter 10 explains it.")

    b.h2("New error page template")

    b.picture(shot("dlg-errorpage"), "Making an error page template.")

    b.para(
        "Give the template a name, then write a page for each error code you "
        "care about.  404 for a page that does not exist and 502 for the "
        "application being down are the two worth doing first.  Chapter 12 "
        "covers what to write.")

    b.h2("New map")

    b.picture(shot("dlg-map"), "Making a lookup.")

    b.table(
        ["Field", "What to put"],
        [
            ["Name", "A label for the list"],
            ["Reads", "What it looks at, such as the browser type"],
            ["Sets the variable",
             "A name you invent.  You then use it elsewhere as a setting value"],
            ["Rules",
             "What to look for and what to set, most specific first.  The "
             "first match wins"],
            ["When nothing matches", "The value to use as a fallback"],
        ],
        widths=[1.6, 4.7])

    b.para(
        "A plain word matches exactly.  Start a rule with a squiggle for a "
        "pattern, or a squiggle and a star to ignore capital letters.  Chapter "
        "14 explains when a map is the right tool.")

    b.h2("New TCP or UDP service")

    b.picture(shot("dlg-stream"), "Balancing something that is not web traffic.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Name", "A label", "What it is for"],
            ["Protocol", "TCP or UDP", "TCP"],
            ["Listen port", "The port to accept connections on",
             "The port clients already use"],
            ["Pool", "Which backends to send them to",
             "A pool made for this"],
            ["Proxy protocol",
             "Pass the real client address to the backend.  Only if the "
             "backend understands it", "Off"],
        ],
        widths=[1.4, 3.6, 1.3])

    b.warn(
        "Pools used here are separate from the pools used by sites, even when "
        "the servers are the same.  That is a rule in nginx, not a choice made "
        "here, so you will see the same machines listed twice.")
    b.page_break()


# ---------------------------------------------------------------------------
def _zones_users(b, shot):
    b.h2("New rate limit zone")

    b.picture(shot("dlg-rate"), "Making a rate limit.")

    b.table(
        ["Field", "What to put", "Usual value"],
        [
            ["Name", "A label", "login-limit"],
            ["Counts by", "What makes two requests the same visitor",
             "$binary_remote_addr"],
            ["Rate", "How many allowed, per second or minute", "10r/s"],
            ["Memory", "Space for remembering visitors", "10m"],
        ],
        widths=[1.3, 3.8, 1.2])

    b.h2("New cache zone")

    b.picture(shot("dlg-cache"), "Making a cache.")

    b.table(
        ["Field", "What to put", "Usual value"],
        [
            ["Name", "A label", "static-files"],
            ["Folder", "Where the copies are kept on disk",
             "/var/cache/nginx/static"],
            ["Memory for the index",
             "Space for the list of what is cached, not the copies", "10m"],
            ["Maximum size", "How much disk the copies may use", "1g"],
            ["Inactive",
             "Throw something out if nobody asks for it in this long", "60m"],
        ],
        widths=[1.6, 3.5, 1.2])

    b.h2("New access list")

    b.picture(shot("dlg-acl"), "Making an access list.")

    b.table(
        ["Field", "What to put"],
        [
            ["Name", "A label"],
            ["Allowed", "Addresses or ranges that may reach it, one per line"],
            ["Blocked", "Addresses that may not"],
            ["When nothing matches", "Allow or deny"],
            ["Include the management networks",
             "Adds the networks from Settings, so you cannot lock yourself out"],
            ["Ask for a username and password",
             "A second lock on top of the address check"],
            ["Trust the address from a header",
             "Only when something trustworthy sits in front, such as a CDN"],
        ],
        widths=[2.0, 4.3])

    b.warn(
        "Trust the address from a header with nothing trustworthy in front "
        "means anybody can set that header themselves and walk straight "
        "through the list.  Chapter 13 explains this in full.")

    b.h2("New user")

    b.picture(shot("dlg-user"), "Adding somebody.")

    b.table(
        ["Field", "What to put", "If unsure"],
        [
            ["Username", "What they will sign in with", "Their work username"],
            ["Full name and email", "For the audit log and for contacting them",
             "Optional"],
            ["Role", "Viewer, operator or admin", "Viewer"],
            ["First password",
             "Something to give them once.  They change it on first sign in",
             "A generated password"],
        ],
        widths=[1.5, 3.6, 1.2])

    b.para(
        "They set up their own authenticator app the first time they sign in.  "
        "Chapter 23 covers the roles and what each can do.")
    b.page_break()
