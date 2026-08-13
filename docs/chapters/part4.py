"""
Part 4: keeping it safe and healthy, and the reference material.

House style: two spaces between sentences, no em dashes, plain words, and
never assume the reader has done this before.
"""


def write(b, shot, term):
    _users(b, shot)
    _backup(b, shot, term)
    _troubleshooting(b, shot, term)


# ---------------------------------------------------------------------------
def _users(b, shot):
    b.h1("23. Users, roles and the audit log")

    b.para(
        "Anybody who can sign in here can change where all of your traffic "
        "goes.  That is worth a few minutes of thought about who has an account "
        "and what each of them is allowed to do.")

    b.picture(shot("users"), "The Users page.")

    b.h2("The three roles")
    b.table(
        ["Role", "Can do"],
        [
            ["Viewer",
             "Look at everything and change nothing.  The right role for most "
             "people, including anybody who only needs to check whether "
             "something is up."],
            ["Operator",
             "Change sites, pools and certificates, and apply.  The role for "
             "the people who run the service day to day."],
            ["Admin",
             "Everything, including managing users, the cluster and failover."],
        ],
        widths=[1.1, 5.2])

    b.para(
        "Give people the smallest role that lets them do their job.  It is easy "
        "to raise somebody later and awkward to explain an outage caused by an "
        "account that did not need the rights it had.")

    b.h2("Adding somebody")
    b.steps([
        "Go to Users and press Add a user.",
        "Give them a username and pick a role.",
        "Set a first password and tell them to change it.",
        "They set up their own authenticator app the first time they sign in, "
        "as in Chapter 6.",
    ])

    b.note(
        "Accounts are shared across both servers, so you add somebody once.  "
        "Things that belong to one machine, such as how many times a password "
        "has been typed wrongly, stay on the machine that saw it.")

    b.h2("When somebody leaves")
    b.para(
        "Turn the account off rather than deleting it.  Turning it off ends "
        "their sessions immediately, so a browser they left open somewhere "
        "stops working.  Keeping the account means the audit log still makes "
        "sense, because entries against a deleted user are harder to follow "
        "later.")

    b.h2("The audit log")
    b.para(
        "Every change is recorded: who did it, when, and what changed.  So is "
        "every sign in, and every failed one.")

    b.picture(shot("audit"), "The Audit Log.")

    b.para(
        "The audit log is written on the server where the thing happened and "
        "stays there.  When you are looking for something and cannot find it, "
        "check the other server.  This is deliberate.  A log that travelled "
        "between machines could claim something was done on a server that never "
        "did it, which would make it useless as a record.")

    b.h2("Recovery outside the screen")
    b.para(
        "There is one job the screen cannot do for you, which is getting an "
        "administrator back in when they have lost their phone and used all "
        "their recovery codes.  There is nobody inside the tool who can help, "
        "because the tool is the thing they cannot reach.")

    b.para(
        "For that case there is a command on the server.  It needs "
        "administrator access to the machine, which anybody who has it could "
        "read the database anyway, so it hands out nothing new.")

    b.code([
        "$ sudo docker exec nginx-fleet-manager \\",
        "      python -m app.reset_admin --list",
        "$ sudo docker exec nginx-fleet-manager \\",
        "      python -m app.reset_admin alice --reset-totp",
    ])

    b.note(
        "Every use of this is written to the audit log as coming from the "
        "console.  An account recovery done outside the screen is exactly the "
        "sort of thing that should stand out when somebody reads the log "
        "later.")
    b.page_break()


# ---------------------------------------------------------------------------
def _backup(b, shot, term):
    b.h1("24. Backup and going back")

    b.para(
        "There are two different questions here and they have different "
        "answers.  One is undoing a change you just made.  The other is getting "
        "everything back after losing a machine.")

    b.h2("Undoing a change you just made")
    b.para(
        "Every apply is kept, with what changed and who did it.  Open the "
        "Changes page and look at the history.  You can see any earlier version "
        "and put it back, which applies it the same way any other change is "
        "applied: checked first, sent to every server, and only then used.")

    b.para(
        "This is the answer nearly every time.  It is quick, it needs no files, "
        "and it works while you are standing there wondering what you just "
        "did.")

    b.h2("What is already backed up for you")
    b.para(
        "Before every apply, the previous configuration is saved on each server "
        "in a folder of its own.  That is what makes an apply safe to roll back "
        "even if the management screen is not running.")

    b.table(
        ["What", "Where"],
        [
            ["Previous nginx configurations", "/var/backups/nginx-fleet-manager"],
            ["The configuration database", "Inside the Docker volume nfm-data"],
            ["Certificates and keys", "/etc/nginx/nginxmgr/certs"],
            ["Your settings and secret key", "The .env file in the install folder"],
        ],
        widths=[2.5, 3.8])

    b.h2("Backing up properly")
    b.warn(
        "The one file worth guarding is .env, because it holds the secret key "
        "that unlocks stored passwords and authenticator seeds.  Without it a "
        "restored database cannot read its own encrypted values.  Keep a copy "
        "somewhere safe and separate.")

    b.para(
        "Beyond that, take a copy of the Docker volume on a schedule that suits "
        "you.  If your servers are virtual machines, a snapshot of the machine "
        "covers everything in the table above at once, and is the simplest "
        "thing that works.")

    b.h2("Losing one server")
    b.para(
        "If one of the pair is lost, the other carries on serving.  Build a "
        "replacement, install it as in Chapter 4, and join it to the survivor "
        "as in Chapter 5.  It gets the configuration from the survivor as part "
        "of joining.  There is nothing to restore by hand.")

    b.para(
        "Give the replacement the same name as the machine it replaces if you "
        "can, then anything that referred to that server by name still means "
        "what it meant before.  If you cannot, check the DNS Failover page "
        "afterwards, because an answer tied to a server that no longer exists "
        "will not be handed out.")

    b.h2("Losing both")
    b.para(
        "Build one server as in Chapter 4, restore the database volume and the "
        ".env file from your backup, and start it.  Then join a second server "
        "to it as in Chapter 5.  Check the certificates page, because a "
        "certificate that expired while everything was down will need "
        "renewing.")
    b.page_break()


# ---------------------------------------------------------------------------
def _troubleshooting(b, shot, term):
    b.h1("25. When something is wrong")

    b.para(
        "This chapter is a list of things that go wrong, what they look like, "
        "and what to do.  They are in rough order of how often they happen.")

    b.h2("A button is greyed out")
    b.para(
        "You are almost certainly looking at the standby.  Changes are made on "
        "the active server.  Check the top right of the screen for which server "
        "you are on, and open the other one.")

    b.h2("The second server does not appear after joining")
    b.para(
        "Look at the Cluster page on the first server.  If the second is "
        "missing entirely, the join did not finish and the installer output "
        "will say why.  The usual cause is port 7444 being blocked between the "
        "two machines.")

    b.para(
        "If it appears but keeps saying its credentials were refused and it may "
        "need to rejoin, the problem is nearly always its name rather than its "
        "certificate.  Check what the second server thinks it is called:")

    b.code([
        "$ grep NFM_NODE_NAME /data/docker/nginx-gui-mgmt/.env",
    ])

    b.para(
        "If that says the name of your first server, the settings file was "
        "copied from it.  Delete the .env file on the second server and install "
        "it again, so it makes its own.  Newer versions refuse to join in this "
        "state and tell you, but a machine set up before that will sit there "
        "failing quietly.")

    b.warn(
        "A copied .env also means both machines are sharing one secret key, "
        "which they should not.  Treat that key as needing to be changed.")

    b.h2("A site returns 502")
    b.para(
        "502 means the load balancer could not get an answer from your "
        "application.  Work through these in order.")

    b.numbers([
        "Open the pool and look at the servers in it.  If they are marked "
        "down, the health check is failing and the problem is behind the load "
        "balancer, not in it.",
        "If the pool uses https to reach the backend, try turning off checking "
        "the certificate.  If that fixes it, the backend's certificate cannot "
        "be verified, and the proper fix is to point the pool at the right "
        "certificate authority file rather than to leave checking off.",
        "Check the port.  A pool pointing at the wrong port fails exactly like "
        "an application being down.",
    ])

    b.h2("A page loads but has no styling")
    b.para(
        "The page was found and its stylesheet was not.  When the application "
        "is served under a path, this is the prefix setting described in "
        "Chapter 10.  Either the application has not been told which prefix it "
        "lives under, or the path is being taken off when the application "
        "expects it, or it is not being taken off when the application does not "
        "expect it.")

    b.para(
        "It looks like a problem with the appearance, and it is a problem with "
        "the path.")

    b.h2("A certificate will not renew")
    b.para(
        "Renewal needs the name to point at one of your servers and port 80 to "
        "be reachable from the internet.  The two common causes are a firewall "
        "closing port 80, and somebody turning off Listen on http for the site "
        "because everything is on https anyway.  Turn it back on.  Force https "
        "already means no real visitor stays on the plain address.")

    b.h2("A name in DNS Failover does not resolve")
    b.para(
        "Check these in order, because the first two are where nearly all of "
        "these end.")

    b.numbers([
        "Ask the server directly, with no port on the end.  If that answers, "
        "the software is working and the problem is the delegation.",
        "Check the records at your domain provider against the ones printed on "
        "the zone.  The glue records are the ones people miss.",
        "Look at the DNS listener panel on each server.  It reports what that "
        "server is really doing, which is not always what the page shows.",
        "Remember that a name only starts working once the old answer has been "
        "forgotten everywhere, which can take longer than the TTL suggests.",
    ])

    b.h2("nginx will not start after an upgrade")
    b.para(
        "It should not be possible to apply a configuration nginx will not "
        "accept, because it is tested on every server before any of them use "
        "it.  If it happens anyway, the previous configuration is on the server "
        "in /var/backups/nginx-fleet-manager and can be put back by hand.  Then "
        "open the Changes page and go back to the last version that worked.")

    b.h2("Where to look for more")
    b.table(
        ["What", "Command"],
        [
            ["The management screen's log",
             "sudo docker logs nginx-fleet-manager"],
            ["The agent's log", "sudo journalctl -u nginx-mgr-agent -n 50"],
            ["nginx's error log", "sudo tail -50 /var/log/nginx/error.log"],
            ["Whether nginx is happy", "sudo nginx -t"],
        ],
        widths=[2.2, 4.1])

    b.note(
        "When you report a problem, the first of those three logs and what you "
        "were doing at the time is nearly always enough for somebody to work "
        "out what happened.")
    b.page_break()


