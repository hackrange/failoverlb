"""
Part 6: the two detail screens, field by field.

These are the biggest screens in the product and where most of the real work
happens.  Every control is listed, including the ones that only appear in
certain modes, so this doubles as the reference somebody keeps open beside the
screen.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _site_detail(b, shot)
    _pool_detail(b, shot)


# ---------------------------------------------------------------------------
def _site_detail(b, shot):
    b.h1("29. The site screen, control by control")

    b.para(
        "Opening a site from the Sites list gives you this screen.  It is the "
        "longest one in the product because a site has the most to say about "
        "it.  This chapter goes through every part of it.")

    b.picture(shot("site-detail"), "The site screen.")

    b.note(
        "Some controls only appear when they are relevant.  The pool chooser "
        "is only shown when the mode is Proxy, and the folder box only when it "
        "is Static.  If something in this chapter is not on your screen, check "
        "the mode first.")

    b.h2("Naming and turning it on")
    b.table(
        ["Control", "What it does"],
        [
            ["Name",
             "For finding it in the list.  Visitors never see this and it can "
             "be changed at any time."],
            ["Server names",
             "The web addresses this site answers for.  One per line.  This is "
             "the setting that decides which requests reach this site, so it "
             "is the one to check first when a site is not being used."],
            ["Enabled",
             "Turn a site off without deleting it.  A disabled site is left "
             "out of the configuration entirely at the next apply."],
            ["Default site",
             "Answers anything that does not match another site's names.  Only "
             "one site can be the default.  Useful for showing a holding page "
             "to somebody who reaches your address by its IP."],
        ],
        widths=[1.5, 4.8])

    b.h2("Listening")
    b.table(
        ["Control", "What it does", "Usual setting"],
        [
            ["Listen on http", "Answer on the plain port", "On"],
            ["Listen on https", "Answer on the secure port", "On"],
            ["http port", "Which plain port", "80"],
            ["https port", "Which secure port", "443"],
            ["HTTP/2", "A faster newer way of speaking https", "On"],
            ["Force https",
             "Send anybody arriving on the plain address to the secure one",
             "On"],
        ],
        widths=[1.4, 3.6, 1.3])

    b.warn(
        "Leave Listen on http on even when everything is secure.  Certificate "
        "renewal needs port 80 to answer.  Force https already means no real "
        "visitor stays there, so the only thing you gain by turning it off is "
        "a certificate that quietly stops renewing.")

    b.h2("The www setting")
    b.para(
        "Send everything to the first name takes any request arriving on one of "
        "the other names and forwards it to the first one in the list.  Put "
        "both domain.com and www.domain.com in the names, decide which you want "
        "to be the real one, and put that first.")

    b.para(
        "The forward is written so it does not interfere with certificate "
        "renewal, which is the usual trap when this is done by hand.")

    b.h2("The mode, and what each one adds")
    b.table(
        ["Mode", "Extra controls", "What it does"],
        [
            ["Proxy", "Pool",
             "Passes requests to the servers in that pool."],
            ["Static", "Folder",
             "Serves files straight from a folder on the load balancer."],
            ["Redirect", "Target, and permanent or temporary",
             "Sends visitors to another address.  Permanent tells browsers and "
             "search engines to remember the change; temporary does not."],
        ],
        widths=[0.9, 1.8, 3.6])

    b.h2("Security")
    b.table(
        ["Control", "What it does"],
        [
            ["Access list",
             "Restrict who may reach the site by address.  Made on the Zones "
             "and Access page and chosen here."],
            ["Username and password",
             "Ask for a username and password before anything is served.  A "
             "reasonable second lock on something already limited by address, "
             "and a thin one on its own."],
            ["Certificate",
             "Which certificate to present.  Needed if Listen on https is "
             "on."],
        ],
        widths=[1.7, 4.6])

    b.h2("Error pages")
    b.para(
        "Choose a template made on the Error Pages page.  There is also a "
        "setting for whether your own error pages are used for errors your "
        "application returns, as well as errors nginx makes itself.  Turn it "
        "off if your application already returns error pages you are happy "
        "with.")

    b.h2("Paths")
    b.para(
        "The Paths section is where a site sends different parts of itself to "
        "different places.  Chapter 10 covers this and Chapter 26 works through "
        "an example.  Each path has its own mode, its own pool or folder, and "
        "can have its own access list and error pages.")

    b.h2("Raw configuration")
    b.para(
        "At the bottom there is a box for nginx configuration typed by hand, "
        "for the occasional thing the screen does not offer.  What you put here "
        "is stored with the site and survives every apply, which is why this "
        "exists and editing the generated files does not.")

    b.para(
        "Next to it is a Check it button.  It builds the whole configuration "
        "including your raw block and tests it, without applying anything.  Use "
        "it every time you touch this box.")

    b.warn(
        "Raw configuration is not checked for sense, only for syntax.  A "
        "directive that is valid but wrong will apply cleanly and behave "
        "strangely.  Keep what goes in here small, and write a note next to it "
        "saying why it is there.")

    b.h2("Deleting a site")
    b.para(
        "Delete removes the site at the next apply.  The pools it used are left "
        "alone, because other sites may be using them.  If you only want it off "
        "for a while, turn Enabled off instead: it keeps everything and can be "
        "put back with one click.")
    b.page_break()


# ---------------------------------------------------------------------------
def _pool_detail(b, shot):
    b.h1("30. The pool screen, control by control")

    b.para(
        "Opening a pool gives you this screen.  It has fewer sections than a "
        "site but more detail in them, because this is where you decide how "
        "traffic is shared out and how a broken server is noticed.")

    b.picture(shot("pool-detail"), "The pool screen.")

    b.h2("The servers")
    b.para(
        "Each row is one server.  Add as many as you have.")

    b.table(
        ["Control", "What it does", "Usual setting"],
        [
            ["Address and port", "Where the server is", "Your app server"],
            ["Weight",
             "How much traffic this one takes compared to the others.  2 sends "
             "it twice as much as a 1", "1"],
            ["Backup",
             "Only used when every non backup server is down", "Off"],
            ["Max fails",
             "How many failures in a row before it is taken out", "3"],
            ["Fail timeout",
             "How long it stays out before being tried again", "10s"],
            ["Max connections",
             "A cap on how many at once this server will be given.  0 means no "
             "cap", "0"],
            ["State",
             "Up, down, or draining.  Draining finishes what it is doing and "
             "takes nothing new, which is how you retire a server without "
             "dropping anybody", "Up"],
        ],
        widths=[1.3, 3.8, 1.2])

    b.note(
        "Draining is the setting worth remembering.  Turning a server off "
        "outright drops whatever it was in the middle of.  Draining lets it "
        "finish, and you watch the connection count fall to zero before you "
        "touch the machine.")

    b.h2("How traffic is shared")
    b.table(
        ["Method", "When to use it"],
        [
            ["Round robin",
             "In turn, one after another.  The right answer for almost "
             "everybody and the default."],
            ["Least connections",
             "Whichever server is least busy right now.  Better when some "
             "requests take much longer than others."],
            ["By address",
             "The same visitor always reaches the same server.  Use only when "
             "the application keeps things in memory per visitor and cannot be "
             "changed."],
            ["By something you choose",
             "The same value always reaches the same server, using a variable "
             "you name.  For caches and shards."],
        ],
        widths=[1.6, 4.7])

    b.para(
        "The consistent option, offered with the last two, changes what happens "
        "when a server is added or removed.  Without it, nearly every visitor "
        "moves to a different server.  With it, only the share belonging to the "
        "changed server moves.  Turn it on if you are hashing at all.")

    b.h2("Health checks")
    b.para(
        "This is what makes a pool worth having.  Without a working check, a "
        "dead server keeps being sent traffic.")

    b.table(
        ["Control", "What it does", "Usual setting"],
        [
            ["Type",
             "Open a connection, or ask for a page and read the answer",
             "Ask for a page"],
            ["Path", "Which page to ask for", "A health page"],
            ["Interval", "How often to check", "5s to 10s"],
            ["Timeout", "How long to wait for an answer", "2s to 5s"],
            ["Rise", "How many good checks before it is used again", "2"],
            ["Fall", "How many bad checks before it is taken out", "3"],
            ["Expected status", "What counts as a good answer", "200"],
            ["Host header",
             "The name to ask for, when the server hosts several", "Your site"],
            ["Expected text",
             "Words that must appear in the answer.  Catches a page that "
             "returns 200 while saying it is broken", "Optional"],
        ],
        widths=[1.4, 3.7, 1.2])

    b.warn(
        "A check that asks for the front page tells you the web server is "
        "running.  A check that asks for a page which talks to the database "
        "tells you the application works.  The difference only shows up during "
        "an outage, when the first kind reports everything healthy.")

    b.h2("Talking to backends over https")
    b.table(
        ["Control", "What it does"],
        [
            ["Use TLS", "Speak https to the servers rather than http."],
            ["Check the certificate",
             "On by default and correct for a real certificate.  Turn it off "
             "only for something self signed, such as a service on the same "
             "machine."],
            ["Authority file",
             "Point at your company's certificate authority file if your "
             "servers use certificates you issue yourselves.  Then checking "
             "stays on and works."],
            ["Server name",
             "The name to ask for in the handshake, when it differs from the "
             "address."],
        ],
        widths=[1.6, 4.7])

    b.note(
        "A pool that starts failing the moment you turn on TLS is nearly always "
        "the certificate check.  Prove it by turning the check off, then put it "
        "back on and fix it properly with the authority file.  Leaving the "
        "check off works and gives up the point of using https.")

    b.h2("Connection reuse")
    b.para(
        "Keep alive holds connections open ready for the next request instead "
        "of making a new one each time.  It makes a real difference to speed "
        "and the defaults are sensible.  The number is how many idle "
        "connections to hold per server, not a limit on traffic.")

    b.h2("Slow start")
    b.para(
        "A server coming back after being down can be given a small share at "
        "first, growing to its full weight over a period you set.  This stops a "
        "cold server with empty caches being hit with its full load the instant "
        "it says it is well, which is a good way to knock it straight back "
        "down.")

    b.h2("Where the numbers for the charts come from")
    b.para(
        "If your servers publish their own measurements, put the address "
        "pattern here and the Utilization page grows charts for them.  Use "
        "{host} where the server address goes, so one pattern covers every "
        "member.  Chapter 17 explains what is collected and why it is done this "
        "way.")

    b.h2("Deleting a pool")
    b.para(
        "A pool being used by a site cannot be deleted, and the screen says "
        "which site is using it.  Point that site somewhere else first.  This "
        "is deliberate, since deleting a pool a site depends on would take that "
        "site down at the next apply.")
    b.page_break()
