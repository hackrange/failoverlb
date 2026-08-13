"""
Part 8: the settings screens.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _settings(b, shot)
    _account(b, shot)


# ---------------------------------------------------------------------------
def _settings(b, shot):
    b.h1("32. Settings")

    b.para(
        "The Settings page holds the choices that apply to the whole fleet "
        "rather than to one site.  Most people set these once during "
        "installation and never come back.  This chapter goes through every "
        "one of them so you know what you have.")

    b.picture(shot("settings"), "The Settings page.")

    b.h2("Where a setting comes from")
    b.para(
        "A setting can be set in two places: here on this screen, or in the "
        "settings file on each server.  When both have a value, the file "
        "wins.")

    b.para(
        "That is why there is a section at the bottom of the page called Set in "
        "the environment.  Anything listed there is being controlled by the "
        "file and cannot be changed from this screen.  If a box will not save, "
        "or saves and then goes back to its old value, look at that list "
        "first.")

    b.note(
        "This arrangement exists so that somebody building servers "
        "automatically can set everything in the file and know the screen "
        "cannot quietly change it later.  If you are not doing that, use the "
        "screen and ignore the file.")

    b.h2("Certificates")
    b.table(
        ["Setting", "What it does", "Usual value"],
        [
            ["Contact email",
             "Where Lets Encrypt sends warnings, such as a certificate about "
             "to expire that has not renewed.  Use an address somebody reads",
             "A team address"],
            ["Use the staging service",
             "Ask a practice version of Lets Encrypt instead of the real one.  "
             "Certificates from it are not trusted by browsers.  For testing "
             "the process without using up your allowance",
             "Off"],
            ["Renew this many days before expiry",
             "How early to renew.  Thirty days leaves plenty of room for a few "
             "failed attempts before anything is urgent",
             "30"],
            ["DNS provider",
             "For the dns-01 method, used when a name cannot be checked over "
             "the web.  Needed for a wildcard certificate",
             "Blank"],
            ["DNS credentials",
             "The login for that provider.  Stored encrypted and never shown "
             "again once saved",
             "Blank"],
        ],
        widths=[1.6, 3.6, 1.1])

    b.warn(
        "Turn the staging service off before you rely on any certificate.  A "
        "staging certificate looks completely normal on this screen and every "
        "browser refuses it.  There is a check that warns if one is in use, and "
        "it is easier not to get there.")

    b.h3("When you would use dns-01")
    b.para(
        "The usual way Lets Encrypt checks you own a name is by asking for a "
        "file over the web, which needs port 80 open.  The other way is asking "
        "you to put a special record in your DNS, which this software can do "
        "for you if you give it credentials for your DNS provider.")

    b.para(
        "You need this in two situations: a wildcard certificate covering "
        "anything.domain.com, which cannot be done any other way, and a name "
        "that is not reachable from the internet at all.")

    b.h2("DNS")
    b.table(
        ["Setting", "What it does"],
        [
            ["DNS servers to ask",
             "Which servers to use when this software has to look a name up, "
             "for example checking that a name points here before asking for a "
             "certificate.  Leave blank to use the box's own settings."],
            ["Ask this box's own resolver as well",
             "Check both, and treat a name as good if either answers.  Useful "
             "when some names are only in your internal DNS."],
        ],
        widths=[2.0, 4.3])

    b.note(
        "This does not affect the DNS failover feature in Chapter 19, which "
        "answers questions rather than asking them.  These settings are about "
        "lookups this software makes on your behalf.")

    b.h2("Management networks")
    b.para(
        "The networks that count as management for the whole fleet.  Two things "
        "use this list.")

    b.bullets([
        "Access lists that have Include the management networks turned on, so "
        "you do not lock yourself out of your own admin areas.",
        "Warnings on the Cluster page when a node appears to be reachable from "
        "somewhere it should not be.",
    ])

    b.para(
        "One network per line, written as a range such as 198.51.100.0/24 or a "
        "single address such as 203.0.113.25.")

    b.warn(
        "This is not the same as the allowlist that controls who may open the "
        "management screen.  That one lives in the settings file on each "
        "server, is applied before anybody signs in, and is the one that "
        "actually keeps strangers out.  Chapter 4 covers it.")

    b.h2("Monitoring")
    b.table(
        ["Setting", "What it does", "Usual value"],
        [
            ["Default health check interval",
             "How often to check a backend, for pools that have not been given "
             "their own value.  Lower notices a failure sooner and asks your "
             "servers more often",
             "5s to 10s"],
        ],
        widths=[1.7, 3.5, 1.1])

    b.para(
        "A pool can override this, and Chapter 30 covers the per pool health "
        "check settings in full.  This is only the starting point for pools "
        "that have not been told otherwise.")

    b.h2("Set in the environment")
    b.para(
        "A read only list of everything currently being controlled by the "
        "settings file rather than by this screen.  It is worth a look after "
        "any installation or upgrade, because it tells you exactly which of "
        "these boxes will do nothing if you change them.")
    b.page_break()


# ---------------------------------------------------------------------------
def _account(b, shot):
    b.h1("33. Your own account")

    b.para(
        "My Account is where you look after your own sign in.  Everything here "
        "affects only you.  Managing other people is Chapter 23.")

    b.picture(shot("acct-mine"), "The My Account page.")

    b.h2("Changing your password")
    b.para(
        "You need your current password as well as the new one.  Changing it "
        "ends your other sessions, so a browser you left signed in somewhere "
        "else stops working.  That is deliberate, and it is the quickest thing "
        "to do if you think somebody else has your password.")

    b.h2("Your authenticator")
    b.para(
        "This is the app that gives you a six digit code when you sign in.  "
        "There are two reasons to come here.")

    b.table(
        ["Situation", "What to do"],
        [
            ["New phone, old one still working",
             "Set up the new one from this page before you wipe the old.  You "
             "are shown a fresh code to scan and the old phone stops working "
             "once you confirm."],
            ["Phone lost or broken",
             "Sign in with one of your recovery codes instead of a six digit "
             "code, then come here and set up the new phone."],
            ["Phone gone and no recovery codes left",
             "Nobody can help you from inside the software.  Somebody with "
             "administrator access to the server has to run the recovery "
             "command in Chapter 23."],
        ],
        widths=[2.0, 4.3])

    b.h2("Recovery codes")
    b.para(
        "Recovery codes each work once, in place of a code from your app.  You "
        "were shown a list when you first set up your account and told to save "
        "them.  This page tells you how many you have left and lets you make a "
        "fresh set.")

    b.warn(
        "Making a fresh set cancels every old code immediately, including any "
        "you have written down.  Do it when you are down to one or two, and "
        "save the new list before you close the page.  It is shown once and "
        "cannot be shown again.")

    b.note(
        "Save them somewhere that is not your phone.  A password manager or a "
        "printed copy in a drawer are both fine.  Codes stored only on the "
        "device you might lose are not doing the job they exist for.")

    b.h2("Your sessions")
    b.para(
        "The page lists where you are currently signed in.  If you see "
        "something you do not recognise, change your password, which ends all "
        "of them at once, and tell whoever looks after security where you "
        "work.")
    b.page_break()
