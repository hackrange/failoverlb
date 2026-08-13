"""
Part 3: running the two servers as a fleet.

House style: two spaces between sentences, no em dashes, plain words, and
never assume the reader has done this before.
"""


def write(b, shot, term):
    _cluster(b, shot, term)
    _dns_failover(b, shot, term)
    _nginx_build(b, shot)
    _reaching_by_name(b, shot)
    _upgrades(b, shot, term)


# ---------------------------------------------------------------------------
def _cluster(b, shot, term):
    b.h1("18. Running the two servers as a pair")

    b.para(
        "Your two servers are a pair.  They hold the same configuration, they "
        "both serve traffic, and one of them is in charge at any moment.  This "
        "chapter explains what that means day to day and what happens when one "
        "of them fails.")

    b.picture(shot("cluster"), "The Cluster page, showing both servers.")

    b.h2("Active and standby")
    b.para(
        "The active server is the one that accepts changes.  The standby holds "
        "an identical copy of everything and is ready to take over.  Both are "
        "serving traffic the whole time.  Standby does not mean idle, and this "
        "catches people out: the standby is not a spare sitting in a cupboard, "
        "it is a working server that happens not to be the one you make changes "
        "on.")

    b.para(
        "Which server is active will change over time, usually because one was "
        "restarted.  That is normal and needs no action.  If you find a button "
        "greyed out, check the top right of the screen to see whether you are "
        "looking at the standby, and open the other server instead.")

    b.h2("How they keep in step")
    b.para(
        "The two servers send each other a heartbeat every few seconds.  A "
        "heartbeat is a short message that says I am here and this is the "
        "version of the configuration I am running.  If one stops hearing from "
        "the other for long enough, it decides the other has gone.")

    b.para(
        "When you apply a change, it is sent to both servers before either "
        "starts using it, which is what Chapter 16 described.  So the two "
        "cannot drift apart through normal use.")

    b.h2("What happens when the active server fails")
    b.para(
        "The standby notices the heartbeats have stopped, promotes itself to "
        "active, and carries on.  Nobody has to be woken up and nothing has to "
        "be typed.  Traffic already going to the surviving server is unaffected "
        "throughout, because it was already serving.")

    b.para(
        "What is not solved by this is traffic that was going to the server "
        "that died.  Nothing on this page can help with that, because the "
        "decision about where to send a visitor was made before the connection "
        "was even attempted.  That is what Chapter 19 is for, and it is the "
        "reason that chapter exists.")

    b.h2("Failing over on purpose")
    b.para(
        "There is a button to hand over to the other server.  Use it before "
        "planned work, such as rebooting a machine.  Handing over deliberately "
        "is calmer than pulling the plug and letting the software work it out, "
        "and it lets you confirm the other server is healthy first.")

    b.h2("Taking a server out for a while")
    b.para(
        "Forced standby stops a server from becoming active without removing it "
        "from the pair.  Use it on a machine you are working on.  Remember to "
        "turn it off afterwards, because a fleet where one server can never take "
        "over is a fleet with no failover, and nothing will remind you.")

    b.h2("Adding a third server")
    b.para(
        "The steps are exactly those in Chapter 5.  Get a token from any server "
        "that is already in the cluster, then run the installer on the new "
        "machine with the join details.  There is nothing special about having "
        "two.")

    b.h2("If a server says it needs to rejoin")
    b.note(
        "A server complaining that its credentials were refused is nearly "
        "always a name problem rather than a certificate problem.  The usual "
        "cause is the settings file having been copied from another machine, so "
        "the server believes it is that machine.  Chapter 25 covers how to tell "
        "and how to fix it.")
    b.page_break()


# ---------------------------------------------------------------------------
def _dns_failover(b, shot, term):
    b.h1("19. DNS failover")

    b.para(
        "This chapter solves the problem Chapter 18 could not.  It is the "
        "longest chapter in the guide because it is the one that involves your "
        "domain provider as well as this software, and because it is worth "
        "being honest about what it can and cannot do.")

    b.h2("The problem")
    b.para(
        "A load balancer can only move traffic that reaches it.  If a whole "
        "server is gone, nothing reaches it, so nothing it might have done "
        "matters.  Visitors are still being sent there because their computer "
        "looked up your address before it tried to connect, and it was given the "
        "address of a server that has since died.")

    b.para(
        "The only thing that can send them somewhere else is the lookup itself.  "
        "So these servers answer that lookup, and they leave out any server that "
        "is not healthy.")

    b.h2("What this is called elsewhere")
    b.para(
        "If you have used other products, you may know this as GSLB, or global "
        "server load balancing.  F5 call it GTM or BIG-IP DNS, Infoblox call it "
        "DTC, and Amazon Route 53 does the same thing with its health checks.  "
        "It is all the same idea.")

    b.h2("Being honest about the limits")
    b.warn(
        "DNS failover is not instant and cannot be made instant.  How long a "
        "computer remembers an answer is a request from you, not a rule.  Some "
        "providers refuse very short values, browsers keep their own copy, and "
        "some programs remember an address for as long as they are running.  "
        "Expect most visitors to move within a minute or two and expect a small "
        "number to take much longer.")

    b.para(
        "Anybody who has promised you instant failover through DNS has promised "
        "something DNS cannot do.  What it is genuinely good at is the case "
        "where nothing else works at all: two servers in different buildings, "
        "on different networks, with different addresses.  Two servers on one "
        "network can share a floating address and move it in a second.  Two "
        "servers in different places cannot, and then this is the answer.")

    b.h2("What you need before you start")
    b.table(
        ["You need", "Why"],
        [
            ["Each server on its own public address",
             "The whole point is handing out different addresses."],
            ["A part of your domain you can delegate",
             "Such as gslb.domain.com.  Not the whole domain."],
            ["Access to your domain provider",
             "To point that part at these servers."],
        ],
        widths=[2.6, 3.7])

    b.note(
        "Use a piece of your domain rather than the whole thing.  Delegating "
        "domain.com itself moves every other record you have, including mail, "
        "onto these servers.  Delegating gslb.domain.com moves nothing except "
        "what you put there.")

    b.h2("Step 1: make a zone")
    b.para(
        "Go to DNS Failover and press Add a zone.")

    b.picture(shot("gslb-add-zone"), "Adding a zone.")

    b.steps([
        "For the zone name, use the piece of your domain you are delegating, "
        "such as gslb.domain.com.",
        "For nameserver names, give one name per server, in the same order as "
        "your servers.  Something like ns1.domain.com and ns2.domain.com.  You "
        "are inventing these now and creating them at your provider in step 3.",
        "Press Save.",
    ])

    b.h2("Step 2: add a name")
    b.para(
        "A zone on its own answers nothing.  Add the name people will actually "
        "use.  Press Add a name on the zone.")

    b.picture(shot("gslb-edit-record"), "Adding or editing a name in the zone.")

    b.table(
        ["Setting", "What to put"],
        [
            ["Name", "The label, such as www.  This makes www.gslb.domain.com."],
            ["Type", "A, unless you are giving out IPv6 addresses."],
            ["TTL",
             "How long the answer is remembered.  30 seconds is a sensible "
             "low number.  Going much lower mostly buys extra lookups without "
             "moving anybody faster."],
            ["When a server is down",
             "Hand out all the healthy ones spreads visitors across everything "
             "that is up.  Hand out the best one only keeps everybody on one "
             "server until it fails, which is what you want when the servers "
             "are not equal."],
            ["If every server is down",
             "Hand them out anyway is usually right.  If the health check "
             "itself is what broke, an empty answer takes the site down when it "
             "did not have to be."],
        ],
        widths=[1.7, 4.6])

    b.para(
        "Then add one answer per server.  Pick the server from the list and its "
        "address is filled in for you.  An answer tied to a server is only given "
        "out while that server is healthy.  An answer left untied is always "
        "given out, which is what you want for an address that is not one of "
        "these servers.")

    b.h2("Step 3: point your domain at these servers")
    b.para(
        "This is the step people miss, and missing it looks exactly like the "
        "feature being broken.  Everything on the page reads correctly and the "
        "name still does not work, because nothing has told the internet to ask "
        "your servers.")

    b.para(
        "The page prints the exact records to create, with your addresses "
        "already filled in.  Copy them to your domain provider.")

    b.picture(shot("gslb"),
              "The DNS Failover page.  The records to create at your provider "
              "are printed under the zone.")

    b.para(
        "There are two kinds and you need both.")

    b.table(
        ["Record", "What it does"],
        [
            ["NS",
             "Says who answers for this part of your domain.  One per server."],
            ["A, called glue",
             "Gives the address of each nameserver.  Needed because a "
             "nameserver named inside the part of the domain it answers for "
             "cannot be looked up without it, which is a loop."],
        ],
        widths=[1.5, 4.8])

    b.h3("Doing this in Amazon Route 53")
    b.para(
        "In Route 53, open the hosted zone for domain.com, which is the parent "
        "of the part you are delegating.  Create these records there, not in a "
        "new hosted zone.")

    b.steps([
        "Create a record named gslb, of type NS, with your two nameserver names "
        "as the value, one per line.  Set the TTL to 300.",
        "Create a record named ns1, of type A, with the address of your first "
        "server.",
        "Create a record named ns2, of type A, with the address of your second "
        "server.",
    ])

    b.para(
        "If you are pointing an existing address at this, add one more record: "
        "a CNAME from the name people use, such as shop.domain.com, to the name "
        "in your new zone, www.gslb.domain.com.")

    b.note(
        "Do not create a hosted zone in Route 53 for gslb.domain.com.  Your "
        "servers are the nameservers for it now.  A hosted zone there as well "
        "gives two different sets of servers claiming the same name.")

    b.h2("Step 4: check it works")
    b.para(
        "Ask each of your servers directly.  On any computer with the dig "
        "command, which Macs and Linux have built in:")

    b.picture(
        term("dig", [
            "$ dig +short @203.0.113.10 www.gslb.domain.com A",
            "203.0.113.10",
            "203.0.113.11",
            "",
            "$ dig +short @203.0.113.11 www.gslb.domain.com A",
            "203.0.113.11",
            "203.0.113.10",
        ], "you@your-computer: ~"),
        "Both servers answering, each listing both addresses.")

    b.para(
        "Both servers should answer, and both should list every healthy server.  "
        "If one answers and the other does not, look at the DNS listener panel "
        "on the quiet one.  That panel reports what the server is actually "
        "doing rather than what was typed in, and the gap between those two is "
        "where nearly all confusion here lives.")

    b.h2("A note about port 53")
    b.para(
        "Lookups arrive on port 53.  The part of this software that answers "
        "them runs without administrator rights on purpose, and a program "
        "without those rights is not allowed to use port 53.  So it listens on "
        "a higher port and a firewall rule sends port 53 to it.")

    b.para(
        "You do not have to set any of this up and it is mentioned for one "
        "reason: if you test using the high port you will get an answer whether "
        "or not the public path works.  Always test with no port on the end, as "
        "above, because that is the path your visitors use.")

    b.h2("What failover actually looks like")
    b.para(
        "The table below is from a real test on a pair of servers.  The active "
        "server was stopped, and the surviving server was asked for the address "
        "every five seconds.")

    b.table(
        ["What happened", "How long it took"],
        [
            ["Dead server removed from the answer", "About 30 seconds"],
            ["Server restored, back in the answer", "About 5 seconds"],
            ["A visitor whose computer had already asked",
             "Up to the TTL on top of the above, so about a minute"],
        ],
        widths=[3.8, 2.5])

    b.para(
        "Removal is deliberately slower than restoring.  A server is only taken "
        "out after it has failed for a while, so a brief hiccup does not move "
        "everybody, and it is put back as soon as it is well.")
    b.page_break()


# ---------------------------------------------------------------------------
def _nginx_build(b, shot):
    b.h1("20. The nginx build")

    b.para(
        "The nginx Build page shows which version of nginx each server is "
        "running and what it was built with, and lets you rebuild it without "
        "opening a terminal.")

    b.h2("Why nginx is built rather than installed")
    b.para(
        "The version of nginx that comes with Ubuntu is built with a small set "
        "of features.  Several things this software can configure need features "
        "that are not in it.  So nginx is built from source with everything "
        "included, which is what the installer did in Chapter 4.")

    b.h2("Rebuilding")
    b.para(
        "Press Rebuild and the server fetches the current source and builds it.  "
        "It takes several minutes.  The new build is tested before anything is "
        "stopped, and your existing configuration is checked against it.  If the "
        "test fails, the old nginx keeps running.")

    b.warn(
        "Do one server at a time and check the site still works before starting "
        "the second.  Rebuilding both at once removes the point of having two.")

    b.h2("Checking the two match")
    b.para(
        "The page shows the version and module count for each server side by "
        "side.  They should match.  Two servers running different builds is a "
        "fleet where a configuration can work on one and fail on the other, and "
        "that is a confusing morning.")
    b.page_break()


# ---------------------------------------------------------------------------
def _reaching_by_name(b, shot):
    b.h1("21. Reaching the management screen by name")

    b.para(
        "So far you have been opening the management screen by address and port, "
        "and clicking past a browser warning every time.  This chapter puts it "
        "behind a proper name with a real certificate.  It is optional, and it "
        "is a good exercise because it uses the things Part 2 taught.")

    b.para(
        "By the end, https://lb-01.domain.com/lb opens the screen with no "
        "warning.")

    b.h2("How it works")
    b.para(
        "You are going to point a site at the management screen, the same way "
        "you would point one at any other application.  The management screen "
        "just happens to be running on the same machine.")

    b.h2("Step 1: a pool for it")
    b.steps([
        "Make a pool with one server in it: address 127.0.0.1, port 7443.  "
        "That address means this machine.",
        "Turn on TLS for the pool, because the management screen speaks https.",
        "Turn off checking the certificate.  The screen uses the self signed "
        "certificate it made at installation, and there is nothing to check it "
        "against.  The traffic never leaves the machine.",
    ])

    b.h2("Step 2: tell the screen it lives under a path")
    b.para(
        "The management screen needs to know it is being served under /lb, so "
        "that every link it writes includes that.  Add a line to the settings "
        "file on the server and restart it.")

    b.code([
        "$ echo 'NFM_ROOT_PATH=/lb' | sudo tee -a \\",
        "      /data/docker/nginx-gui-mgmt/.env",
        "$ sudo docker compose \\",
        "      --project-directory /data/docker/nginx-gui-mgmt up -d",
    ])

    b.h2("Step 3: a site in front of it")
    b.steps([
        "Make a site with the server name lb-01.domain.com.",
        "Add a path of /lb, set to send requests to the pool you just made.",
        "Leave Take this path off before sending it on turned off.  The screen "
        "now knows it lives under /lb and expects to be given the whole path.",
        "Apply.",
    ])

    b.h2("Step 4: a real certificate")
    b.steps([
        "Go to Certificates and get one from Lets Encrypt for "
        "lb-01.domain.com, as in Chapter 11.",
        "Open the site, choose that certificate, turn on Listen on https and "
        "Force https.",
        "Apply.",
    ])

    b.para(
        "Open https://lb-01.domain.com/lb.  You should get the sign in page "
        "with a padlock and no warning.")

    b.note(
        "If the page appears but looks plain and unstyled, the setting in step "
        "2 has not taken effect, or the path setting in step 3 is stripping the "
        "prefix.  Both produce the same symptom: the page is found and the "
        "styling is not.")

    b.warn(
        "Putting the management screen on a public name makes it easier for "
        "your staff to reach and easier for everybody else to find.  Keep the "
        "allowlist from Chapter 4 set to your office networks.  The name being "
        "public and the screen being reachable are two different things.")
    b.page_break()


# ---------------------------------------------------------------------------
def _upgrades(b, shot, term):
    b.h1("22. Upgrades")

    b.para(
        "Upgrading gets the newest version of this software onto your servers.  "
        "It does not touch your configuration and it does not change your "
        "settings file.")

    b.h2("Doing it")
    b.para(
        "On each server in turn, fetch the new version and run the installer "
        "with the upgrade option.")

    b.code([
        "$ cd /data/docker/nginx-gui-mgmt && sudo git pull",
        "$ sudo /data/docker/nginx-gui-mgmt/install.sh --upgrade",
    ])

    b.para(
        "This rebuilds the management screen, updates the agent if it has "
        "changed, and starts everything again.  It takes a couple of minutes.  "
        "nginx keeps running throughout, so your sites stay up.")

    b.h2("Do every server")
    b.warn(
        "Upgrade every server, not just one.  A pair where the two are running "
        "different versions is a pair that can disagree about what it is able "
        "to do.  Do them one after the other, not at the same time, and check "
        "the Cluster page in between.")

    b.para(
        "The gap between upgrading the first and the second should be minutes, "
        "not days.  While they differ, a new setting that only one of them "
        "understands is being shared between them.")

    b.h2("Checking it worked")
    b.para(
        "Open the Cluster page.  Both servers should be online and showing the "
        "same version.  Then apply your configuration once, even though nothing "
        "has changed, to confirm both servers still accept it.")
    b.page_break()
