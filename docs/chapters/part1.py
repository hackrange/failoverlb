"""
Part 1: getting it running.

House style, repeated here because this is the file people will edit:
two spaces between sentences, no em dashes, plain words, and never assume the
reader has done this before.
"""

TERM_TITLE = "you@your-computer: ~"


def write(b, shot, term):
    """
    `b` is the book.  `shot(name)` gives the path to an annotated screenshot.
    `term(name, lines, title)` renders a terminal picture and gives its path.
    """
    _about(b)
    _concepts(b)
    _before(b, term)
    _first_node(b, term)
    _second_node(b, term)
    _signing_in(b, shot)
    _tour(b, shot)


# ---------------------------------------------------------------------------
def _about(b):
    b.h1("1. About this guide")

    b.para(
        "This guide explains how to install and run NGINX Management.  It is "
        "written for somebody who has been handed a pair of servers and asked "
        "to put a load balancer on them.  You do not need to have run one "
        "before.  Where a word is unavoidable jargon, it is explained in plain "
        "language the first time it appears, and again in the glossary at the "
        "back.")

    b.h2("What this software is")
    b.para(
        "NGINX Management is a web page that runs your nginx servers for you.  "
        "nginx is the program that actually takes requests from the internet "
        "and passes them to your applications.  It is controlled by text files "
        "that are easy to get wrong and unforgiving when you do.  This software "
        "puts a screen in front of those files, checks your changes before they "
        "go live, and pushes them to every server at once so the two never "
        "drift apart.")

    b.h2("How to read this")
    b.para(
        "Part 1 takes you from two empty servers to a working pair with the "
        "screen open in front of you.  Read it in order and type the commands "
        "as they appear.  Part 2 covers the everyday work of adding sites and "
        "certificates.  Part 3 is about running two servers as a pair, "
        "including what happens when one of them fails.  Part 4 is for keeping "
        "the thing safe and healthy over time.")

    b.para(
        "You can read Part 2 onward in any order.  Each chapter says what it "
        "assumes you have already done.")

    b.h2("How the pictures work")
    b.para(
        "Screenshots in this guide are of the real software.  Anything drawn on "
        "top in red was added for this guide and is not on your screen.  Red "
        "arrows point at the thing being described.")

    b.note(
        "Throughout this guide the example domain is domain.com and the two "
        "servers are called lb-01 and lb-02.  Wherever you see those, use your "
        "own domain and your own server names instead.")

    b.h2("A word about what this cannot do")
    b.para(
        "No load balancer can send traffic to a server that is switched off, "
        "and none of them can make a broken application work.  What this does "
        "is notice quickly, stop sending people to something that is not "
        "answering, and let you fix it without a maintenance window.  Chapter "
        "19 is honest about the limits of the failover in particular, because "
        "those limits are set by how the internet works and not by this "
        "software.")
    b.page_break()


# ---------------------------------------------------------------------------
def _concepts(b):
    b.h1("2. The ideas you need first")
    b.para(
        "There are five words used constantly in this guide.  Learning them now "
        "will save you time later.  Nothing here needs to be memorised, and the "
        "glossary repeats all of it.")

    b.h2("A site")
    b.para(
        "A site is one name that people type into a browser, such as "
        "www.domain.com, and the rules for what happens when they do.  If you "
        "run three different web addresses, you have three sites.")

    b.h2("A backend pool")
    b.para(
        "A pool is the list of servers that actually run your application.  "
        "The load balancer takes a request and hands it to one of the servers "
        "in the pool.  If a pool has four servers in it and one stops "
        "answering, the other three carry on and nobody outside notices.")

    b.para(
        "Sites and pools are kept separate on purpose.  Several sites can share "
        "one pool, and you can swap the pool a site uses without touching "
        "anything else.")

    b.h2("Applying")
    b.para(
        "Changes you make on the screen are saved right away, but they are not "
        "live until you apply them.  Applying is one button.  It checks the "
        "whole configuration first, sends it to every server, and only then "
        "tells nginx to start using it.  If any server refuses the new "
        "configuration, the change is rolled back everywhere and nothing goes "
        "live.")

    b.note(
        "This is the single most important habit to build.  Save as often as "
        "you like, because saving changes nothing for your visitors.  Apply "
        "when you are ready for the change to be real.")

    b.h2("Active and standby")
    b.para(
        "You run two servers.  At any moment one is active and the other is "
        "standby.  Both hold exactly the same configuration and both are "
        "capable of serving traffic.  The active one is simply the one in "
        "charge of making changes.  If it fails, the standby takes over on its "
        "own, without anybody being woken up.")

    b.h2("The agent")
    b.para(
        "The web screen runs with very few privileges, which is deliberate: it "
        "faces your staff and it is the part most likely to be attacked.  "
        "Anything that genuinely needs administrator rights, such as writing "
        "nginx configuration or restarting a service, is done by a separate "
        "small program called the agent.  The agent will only carry out a short "
        "fixed list of jobs and will refuse anything else.")

    b.para(
        "You do not have to do anything with the agent.  It is installed for "
        "you and it looks after itself.  It is mentioned here because you will "
        "see the word in a few places, and because it is the reason this "
        "software can be run without giving the web page administrator rights "
        "over your servers.")
    b.page_break()


# ---------------------------------------------------------------------------
def _before(b, term):
    b.h1("3. Before you start")

    b.h2("What you need")
    b.table(
        ["You need", "Why"],
        [
            ["Two servers running Ubuntu",
             "One is enough to start, but a pair is what gives you failover."],
            ["Administrator access to both",
             "The installer has to add software and start services."],
            ["A domain name you control",
             "For certificates, and for the DNS failover in Part 3."],
            ["The ability to add DNS records",
             "At whoever runs your domain, such as Route 53 or GoDaddy."],
        ],
        widths=[2.4, 3.9])

    b.para(
        "The servers do not need to be large.  Two processors and two gigabytes "
        "of memory is a sensible starting point for most workloads, and nginx "
        "itself is famously light.  What matters far more is that both servers "
        "can be reached from the internet on their own addresses.")

    b.h2("Ports that need to be open")
    b.table(
        ["Port", "Used for", "Who needs to reach it"],
        [
            ["80", "Ordinary web traffic, and certificate checks", "Everyone"],
            ["443", "Secure web traffic", "Everyone"],
            ["7443", "The management screen", "Your staff only"],
            ["7444", "The two servers talking to each other", "The other server only"],
            ["53", "DNS failover, if you use it (Part 3)", "Everyone"],
        ],
        widths=[0.8, 3.2, 2.3])

    b.warn(
        "Port 7443 is the management screen and should not be open to the "
        "whole internet.  The installer asks which networks may reach it, and "
        "Chapter 4 shows where to put your office address.")

    b.h2("Getting a terminal")
    b.para(
        "Everything in the next two chapters is typed into a terminal on your "
        "own computer, connected to the server.  On a Mac or on Linux, open the "
        "Terminal application.  On Windows, open PowerShell.  Then connect to "
        "the first server:")

    b.picture(
        term("connect", [
            "$ ssh root@lb-01.domain.com",
            "Welcome to Ubuntu 26.04 LTS (GNU/Linux 6.8.0 x86_64)",
            "",
            "  System information as of Thu Aug 13 16:20:11 UTC 2026",
            "",
            "  System load:  0.02              Processes:      128",
            "  Usage of /:   4.1% of 78.00GB   Users logged in: 0",
            "",
            "root@lb-01:~#",
        ], TERM_TITLE),
        "Connecting to the first server.  The last line, ending in a hash, is "
        "the server waiting for you.")

    b.para(
        "From here on, a line starting with a dollar sign is something you "
        "type.  Everything else is what the server prints back.  You do not "
        "type the dollar sign.")
    b.page_break()


# ---------------------------------------------------------------------------
def _first_node(b, term):
    b.h1("4. Installing the first server")

    b.para(
        "This chapter sets up the first of your two servers.  At the end of it "
        "you will have the management screen running and be able to sign in.  "
        "It takes about fifteen minutes, most of which is the server "
        "downloading things.")

    b.h2("Step 1: get the software")
    b.para(
        "Copy the software onto the server.  The folder it goes in does not "
        "matter, and the one used here is a sensible default.")
    b.code([
        "$ sudo git clone https://git.domain.com/nginx-gui-mgmt.git \\",
        "      /data/docker/nginx-gui-mgmt",
    ])

    b.h2("Step 2: install Docker")
    b.para(
        "The management screen runs inside Docker, which is a way of packaging "
        "a program with everything it needs so it behaves the same everywhere.  "
        "There is a script that installs and configures it for you.")

    b.picture(
        term("docker", [
            "$ sudo /data/docker/nginx-gui-mgmt/docker_setup.sh",
            "== Installing Docker ==",
            "[ok] Docker installed.",
            "",
            "== Daemon settings ==",
            "[docker] Wrote /etc/docker/daemon.json",
            "         log rotation at 20m x 5 files per container",
            "         live-restore keeps containers up across a daemon restart",
            "",
            "== Checking it works ==",
            "Docker version 29.7.2, build a7dcaa6",
            "[ok] hello-world ran fine.",
            "",
            "[ok] Docker is set up.",
        ], "root@lb-01: ~"),
        "Installing Docker.  This takes a couple of minutes.")

    b.h2("Step 3: install the manager")
    b.para(
        "Now install the management software itself.  The allowlist is the list "
        "of networks allowed to open the management screen.  Put your office "
        "address here.  If you are not sure what it is, visit any website that "
        "reports your public address and use that, followed by /32.")

    b.code([
        "$ sudo /data/docker/nginx-gui-mgmt/nginx-gui-mgmt_setup.sh \\",
        "      --allowlist 198.51.100.25/32 \\",
        "      --acme-email you@domain.com",
    ])

    b.para(
        "The installer prints what it is doing as it goes.  The important lines "
        "are near the end.")

    b.picture(
        term("install", [
            "== Checks ==",
            "[setup] Ubuntu 26.04 LTS",
            "",
            "== Code ==",
            "[setup] installed at /data/docker/nginx-gui-mgmt",
            "",
            "[nfm] node lb-01 at 203.0.113.10, priority 100",
            "",
            "== The nginxmgr group ==",
            "[nfm] made group nginxmgr with gid 10001",
            "",
            "== Host agent ==",
            "[nfm] installed the agent to /opt/nginx-fleet-manager",
            "[ok] nginx-mgr-agent.service is running",
            "",
            "== Done ==",
            "[ok] NGINX Management is running on lb-01.",
            "",
            "      GUI:   https://203.0.113.10:7443",
            "      Peers: 203.0.113.10:7444",
        ], "root@lb-01: ~"),
        "The end of a successful install.  Write down the GUI address on the "
        "second to last line.")

    b.note(
        "The installer is safe to run again.  If something goes wrong, fix it "
        "and run the same command a second time.  It leaves alone anything it "
        "has already done.")

    b.h2("Step 4: install nginx")
    b.para(
        "The manager manages nginx, but it does not bring its own copy.  "
        "Install it now.  This one takes the longest, because it builds nginx "
        "from source with every module this software knows how to configure.")

    b.code(["$ sudo /data/docker/nginx-gui-mgmt/nginx-installer.sh install"])

    b.picture(
        term("nginx", [
            "[+] Fetching sources.",
            "[+] Building.  This takes a few minutes.",
            "[+] Testing the config before we stop anything.",
            "nginx: the configuration file /etc/nginx/nginx.conf syntax is ok",
            "nginx: configuration file /etc/nginx/nginx.conf test is successful",
            "[+] Done.  Here is what got installed:",
            "    nginx version: nginx/1.30.4",
            "    built with OpenSSL 3.5.7",
            "    TLS SNI support enabled",
            "[+] nginx is running.  Check it with: curl -I http://localhost",
        ], "root@lb-01: ~"),
        "nginx built and running.  Yours may show a slightly newer version.")

    b.para(
        "That is the first server finished.  You can sign in now if you like, "
        "and Chapter 6 shows you how, but it is easier to add the second server "
        "first while you still have the terminal open.")
    b.page_break()


# ---------------------------------------------------------------------------
def _second_node(b, term):
    b.h1("5. Adding the second server")

    b.para(
        "The second server joins the first one.  Joining means the two share "
        "one configuration from then on: anything you change on either is sent "
        "to both.  To join, the second server needs a token from the first, "
        "which is a short lived password that lets it in once.")

    b.warn(
        "Do not copy the folder from the first server to the second to save a "
        "download.  It contains a settings file with that server's identity and "
        "its secret key, and the second server will come up believing it is the "
        "first one.  Install it fresh, as below.  The installer now refuses to "
        "join if it spots this, but it is easier not to do it.")

    b.h2("Step 1: get a token from the first server")
    b.para(
        "Sign in to the management screen on the first server, go to Cluster, "
        "and press Add a node.  It gives you a command with a token already in "
        "it.  Copy the whole thing.")

    b.para(
        "The token can be used once and expires after two hours.  If you take "
        "longer than that, come back and press the button again for a fresh "
        "one.")

    b.h2("Step 2: run it on the second server")
    b.para(
        "Connect to the second server and run the three steps from Chapter 4 "
        "again: get the software, install Docker, then install the manager.  "
        "The only difference is the last command, which now carries the join "
        "details.")

    b.code([
        "$ sudo /data/docker/nginx-gui-mgmt/nginx-gui-mgmt_setup.sh \\",
        "      --join 203.0.113.10:7444 \\",
        "      --token <the token you copied> \\",
        "      --allowlist 198.51.100.25/32",
    ])

    b.picture(
        term("join", [
            "[nfm] making a key pair and a signing request for lb-02",
            "[nfm] asking https://203.0.113.10:7444/peer/join to let us in",
            "[nfm] got a signed certificate, saving it",
            "[nfm] joined the cluster that lb-01 is in",
            "",
            "joined through lb-01",
            "[nfm] joined, restarting so the peer listener comes up",
            "[ok]  this node is part of the cluster",
            "",
            "== Done ==",
            "[ok] NGINX Management is running on lb-02.",
        ], "root@lb-02: ~"),
        "The second server joining the first.")

    b.para(
        "Then install nginx on this server too, exactly as before.")
    b.code(["$ sudo /data/docker/nginx-gui-mgmt/nginx-installer.sh install"])

    b.h2("Step 3: check they can see each other")
    b.para(
        "Open the management screen and go to Cluster.  Both servers should be "
        "listed, one marked active and the other standby, and both should say "
        "online.  If the second one is missing or shows an error, Chapter 25 "
        "has the usual causes.")

    b.note(
        "It does not matter which server ends up active.  They are equal, and "
        "which one is in charge will change over time as they are restarted.")
    b.page_break()


# ---------------------------------------------------------------------------
def _signing_in(b, shot):
    b.h1("6. Signing in for the first time")

    b.para(
        "Open a browser and go to the address the installer printed, which "
        "looks like https://203.0.113.10:7443.  Chapter 21 shows how to put "
        "this behind a proper name and certificate so it is easier to "
        "remember.")

    b.note(
        "The first time you visit, your browser will warn you that the "
        "connection is not private.  That is expected.  The server made its own "
        "certificate during installation and no browser has been told to trust "
        "it.  Continue past the warning.  Chapter 21 replaces it with a real "
        "certificate.")

    b.picture(shot("login-empty"),
              "The sign in page.  Type your username and password, then press "
              "Continue.")

    b.para(
        "Your username and first password are the ones set during installation, "
        "or given to you by whoever installed it.")

    b.h2("Setting up your authenticator")
    b.para(
        "After your password, you are asked for a six digit code from an "
        "authenticator app.  Everybody with a local account has to set one up.  "
        "A password on its own is not enough to reach a screen that can change "
        "where all of your traffic goes.")

    b.para(
        "If you have never used one, install any authenticator app on your "
        "phone.  Google Authenticator, Microsoft Authenticator and 1Password "
        "all work, and so does anything else that scans this kind of code.")

    b.steps([
        "Open your authenticator app and choose to add an account.",
        "Point your phone at the square code on the screen.",
        "The app starts showing a six digit number that changes every thirty "
        "seconds.  Type the current one into the box and press Continue.",
    ])

    b.picture(shot("acct-enrol"),
              "The setup screen.  Scan the square code with your phone, then "
              "type the six digit number it shows.")

    b.note(
        "If your phone cannot scan the code, there is a line of letters and "
        "numbers underneath it.  Type that into the app by hand instead.  It "
        "is the same thing in a different form.")

    b.picture(shot("login-code"),
              "Entering the six digit code from your authenticator app.")

    b.h2("Your recovery codes")
    b.warn(
        "You are shown a list of recovery codes once, and never again.  Each "
        "one works a single time in place of a code from your app.  They are "
        "how you get back in if your phone is lost, broken, or in another "
        "building.  Save them somewhere that is not your phone.")

    b.picture(shot("acct-recovery"),
              "The recovery codes.  This screen is shown once and never again.")

    b.para(
        "A password manager is a good place.  Printed and put in a drawer is "
        "also fine.  What matters is that they are not only on the device you "
        "might lose.")

    b.para(
        "Each code works once.  When you use one, it is gone, and the count on "
        "the My Account page goes down by one.  Chapter 33 shows how to make a "
        "fresh set when you are running low.")
    b.page_break()


# ---------------------------------------------------------------------------
def _tour(b, shot):
    b.h1("7. A tour of the screens")

    b.para(
        "You are now looking at the dashboard.  This chapter is a quick walk "
        "through what is where.  You do not need to do anything yet.")

    b.picture(shot("dashboard"),
              "The dashboard, with the menu down the left.")

    b.h2("The menu")
    b.para(
        "The menu is grouped into four sections, and the grouping is worth "
        "learning because it tells you where to look for things.")

    b.table(
        ["Group", "What lives there"],
        [
            ["Traffic",
             "Everything about handling requests: sites, pools, error pages "
             "and the rest.  This is where you will spend most of your time."],
            ["Security",
             "Certificates."],
            ["Fleet",
             "The two servers as a pair: cluster status, DNS failover, "
             "upgrades and the nginx build."],
            ["Account",
             "Your own login, users, settings, and the record of who changed "
             "what."],
        ],
        widths=[1.3, 5.0])

    b.h2("The bar along the top")
    b.para(
        "On the right of the top bar is the name of the server you are looking "
        "at and whether it is active or standby.  This matters more than it "
        "looks.  Both servers show the same screens, but changes are made on "
        "the active one.  If you find a button greyed out, check this first.")

    b.h2("The pages you will use most")
    b.table(
        ["Page", "What it is for", "Chapter"],
        [
            ["Sites", "The web addresses you serve", "9"],
            ["Backend Pools", "The servers behind them", "8"],
            ["Certificates", "Making traffic secure", "11"],
            ["Changes", "What is saved but not yet live", "16"],
            ["Cluster", "The two servers as a pair", "18"],
            ["DNS Failover", "Sending people to a server that is up", "19"],
        ],
        widths=[1.5, 3.6, 0.8])

    b.para(
        "The next part of this guide works through the everyday jobs in the "
        "order you are most likely to need them.  If you are setting this up "
        "for the first time, start with Chapter 8 and work forward, because a "
        "site needs a pool to point at and a certificate to be secure.")
    b.page_break()
