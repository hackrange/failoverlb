"""
Part 9: the nginx build, and what the paid nginx has.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _build(b, shot, term)
    _parity(b, shot)


# ---------------------------------------------------------------------------
def _build(b, shot, term):
    b.h1("34. The nginx build")

    b.para(
        "The nginx Build page shows exactly which nginx each of your servers is "
        "running, and rebuilds it when you need a newer one.  Chapter 20 "
        "introduced it briefly.  This chapter covers the whole screen.")

    b.picture(shot("nginx-build"), "The nginx Build page.")

    b.h2("Why nginx is built rather than installed from Ubuntu")
    b.para(
        "The nginx that comes with Ubuntu is built with a small set of "
        "features.  Several of the things this software can configure for you "
        "need features that are not in it, so nginx is compiled from source "
        "with all of them included.  That is what the installer did in Chapter "
        "4 and it is why that step took the longest.")

    b.para(
        "The cost of this is that you cannot update nginx with the usual system "
        "update command.  This page is where that happens instead.")

    b.h2("What is installed now")
    b.para(
        "The bottom section reports what each server is actually running.")

    b.table(
        ["Shown", "What it means"],
        [
            ["nginx version", "The version currently serving your traffic."],
            ["OpenSSL version",
             "The library that does the encryption.  Worth knowing when a "
             "security notice goes round, because that is usually what it is "
             "about."],
            ["Module count",
             "How many extra features were compiled in.  Two servers showing "
             "different counts is the thing to notice on this page."],
        ],
        widths=[1.5, 4.8])

    b.warn(
        "Both servers should show the same versions and the same module count.  "
        "A fleet where they differ is one where a configuration can work on one "
        "server and be refused by the other, and the apply will fail with an "
        "error that points at your configuration rather than at the real "
        "cause.")

    b.h2("Checking before you build")
    b.para(
        "There is a check button that works out what a rebuild would do without "
        "doing it.  It reports the versions that would be installed and whether "
        "your current configuration would still be accepted by them.  Run it "
        "first, every time.")

    b.h2("Rebuilding")
    b.para(
        "Rebuild fetches the sources, compiles nginx, and installs it.  It "
        "takes several minutes and the progress is shown on screen as it goes.")

    b.para(
        "The order it works in is what makes this safe.")

    b.numbers([
        "The new nginx is built, while the old one carries on serving.",
        "Your existing configuration is tested against the new build.",
        "Only if that passes is the running nginx replaced.",
        "If it fails, the old nginx is left exactly as it was and you are told "
        "what was wrong.",
    ])

    b.picture(
        term("build", [
            "[+] Fetching sources.",
            "[+] Building.  This takes a few minutes.",
            "[+] Testing the config before we stop anything.",
            "nginx: configuration file /etc/nginx/nginx.conf test is successful",
            "[+] Done.  Here is what got installed:",
            "    nginx version: nginx/1.30.4",
            "    built with OpenSSL 3.5.7",
            "[+] nginx is running.",
        ], "root@lb-01: ~"),
        "A rebuild finishing.  The same output appears on the page as it "
        "happens.")

    b.h2("Do one server at a time")
    b.warn(
        "Rebuild one server, check your sites still work, and only then do the "
        "second.  Rebuilding both at once removes the whole point of having "
        "two.  If you use DNS failover, take the server out of the answer first "
        "as described in Chapter 28.")

    b.h2("If a rebuild fails")
    b.para(
        "The old nginx keeps running, so nothing is down.  Read the output on "
        "the page: a build failure is nearly always a missing system package or "
        "a source that could not be downloaded, and both say so plainly.  Fix "
        "it and press the button again.")

    b.note(
        "A rebuild does not change your configuration and cannot lose it.  Your "
        "sites, pools and certificates live in the database and are written out "
        "again on the next apply.")
    b.page_break()


# ---------------------------------------------------------------------------
def _parity(b, shot):
    b.h1("35. Open source parity")

    b.para(
        "There are two nginx products.  The free one, which is what this "
        "software runs, and a paid subscription called nginx Plus.  A handful "
        "of features exist only in the paid one.")

    b.picture(shot("parity"), "The Open source parity page.")

    b.h2("Why this page exists")
    b.para(
        "You will read about a feature somewhere, go looking for it, and not "
        "find it.  Without this page you would spend an hour hunting before "
        "discovering it needs a subscription.  This page lists each one, says "
        "so plainly, and tells you what to use instead.")

    b.para(
        "In most cases there is a perfectly good free answer, and this software "
        "has already built it.  Sticky sessions are the clearest example: the "
        "paid nginx has a directive for it, and this software gets the same "
        "result another way, so you have the feature without the subscription.")

    b.h2("What is on the list")
    b.table(
        ["Feature", "What it is", "What you have instead"],
        [
            ["Sticky sessions",
             "Sending the same visitor back to the same backend every time",
             "Built here a different way, and it works the same"],
            ["Active health checks",
             "nginx testing backends by itself on a timer",
             "This software runs the checks and updates the config, which is "
             "what Chapter 8 sets up"],
            ["Slow start",
             "Easing traffic onto a server that has just come back",
             "Built here, on the pool screen"],
            ["Least time balancing",
             "Choosing the backend answering fastest right now",
             "Least connections, which is close in practice"],
            ["Runtime API and dashboard",
             "Changing backends without reloading, and a live status page",
             "The Utilization page, and applying a change is quick"],
            ["JWT validation",
             "nginx checking signed tokens itself",
             "Have your application check them"],
            ["Request queueing",
             "Holding requests when every backend is busy rather than failing",
             "Nothing directly.  Add capacity, or use a connection limit so the "
             "failure is predictable"],
        ],
        widths=[1.3, 2.4, 2.6])

    b.h2("A note about reloads")
    b.para(
        "The page has a section about this and it is worth understanding.  The "
        "paid nginx can change its list of backends without reloading.  The "
        "free one reloads to pick up a change.")

    b.para(
        "A reload sounds alarming and is not.  nginx starts new workers with "
        "the new configuration, hands new connections to them, and lets the old "
        "ones finish what they were doing before they stop.  Nobody is "
        "disconnected and no request is dropped.")

    b.note(
        "This matters in one situation: a health check taking a backend out "
        "causes a reload, so a flapping backend causes repeated reloads.  That "
        "is worth avoiding for its own sake, and the fix is the same either "
        "way, which is to work out why the backend keeps failing.")

    b.h2("Should you buy nginx Plus?")
    b.para(
        "This software does not use it and cannot configure it.  If you need "
        "something on the list above that has no free answer, the honest "
        "position is that this is not the tool for that job.  For everything "
        "else, the free nginx with this in front of it does what most people "
        "need.")
    b.page_break()
