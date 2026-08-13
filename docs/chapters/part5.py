"""
Part 5: worked examples.

These follow one scenario from beginning to end.  Everything in them has
appeared earlier as a topic.  What they add is the order, and the checks in
between, which is the part that is hard to get from a reference chapter.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _first_site(b, shot, term)
    _dns_example(b, shot, term)
    _maintenance(b, shot, term)


# ---------------------------------------------------------------------------
def _first_site(b, shot, term):
    b.h1("26. Worked example: putting a site live")

    b.para(
        "This chapter takes one site from nothing to working, with a "
        "certificate, and then adds a second set of servers for part of it.  "
        "Follow it with your own names in place of the example ones and you "
        "will have done most of the jobs in Part 2 once.")

    b.h2("The example")
    b.para(
        "A company runs a shop.  The application runs on two servers inside "
        "their network, and there is a separate pair running the part of it "
        "that the mobile app talks to.")

    b.table(
        ["Thing", "Value"],
        [
            ["The address people type", "shop.domain.com"],
            ["Web servers", "10.0.0.11 and 10.0.0.12, both on port 8080"],
            ["API servers", "10.0.0.21 and 10.0.0.22, both on port 9000"],
            ["Everything under /api", "Should go to the API servers"],
        ],
        widths=[2.2, 4.1])

    b.h2("Step 1: a pool for the web servers")
    b.steps([
        "Go to Backend Pools and press New pool.",
        "Name it shop-web.",
        "Add 10.0.0.11 port 8080, then add 10.0.0.12 port 8080.",
        "Leave the balancing method as round robin.",
        "Set the health check to ask for a page rather than just open a "
        "connection.  If the application has a health page, use it.  If not, "
        "use / for now and come back to it.",
        "Press Save.",
    ])

    b.para(
        "Wait a few seconds and look at the pool.  Both servers should turn "
        "green.  If they do not, stop here and fix it.  Everything after this "
        "assumes the load balancer can reach your application, and a site in "
        "front of a pool that cannot answer will only produce a more confusing "
        "version of the same problem.")

    b.note(
        "Nothing you have done so far affects anybody.  The pool exists in the "
        "screen and nginx has not been told about it.")

    b.h2("Step 2: a pool for the API servers")
    b.para(
        "Do the same again.  Name it shop-api, add 10.0.0.21 and 10.0.0.22 on "
        "port 9000, and check both go green.")

    b.h2("Step 3: the site")
    b.steps([
        "Go to Sites and press New site.",
        "Name it shop.",
        "Under server names, put shop.domain.com.",
        "Set the mode to Proxy and choose the pool shop-web.",
        "Leave Listen on http turned on.  Leave Listen on https turned on.  "
        "Leave the certificate empty for now.",
        "Press Create site.",
    ])

    b.h2("Step 4: apply, and check the plain address")
    b.para(
        "Press Apply config.  It takes a few seconds and tells you which "
        "servers took the change.")

    b.para(
        "Now check it.  Ask for the site over plain http, since there is no "
        "certificate yet.")

    b.picture(
        term("check-http", [
            "$ curl -I http://shop.domain.com/",
            "HTTP/1.1 200 OK",
            "Server: nginx",
            "Content-Type: text/html; charset=utf-8",
        ], "you@your-computer: ~"),
        "The site answering over plain http.")

    b.para(
        "If you get 502, the load balancer reached nginx but could not get an "
        "answer from your application.  Go back to the pool and look at the "
        "servers.  If you get no answer at all, the name does not point at your "
        "load balancer yet, which is a DNS job rather than anything here.")

    b.h2("Step 5: the certificate")
    b.steps([
        "Go to Certificates and press Get one from Lets Encrypt.",
        "Type shop.domain.com.",
        "Press Request and wait.",
    ])

    b.para(
        "The certificate appears in the list marked valid, with the days "
        "remaining and how many servers have a copy.  It should say it reached "
        "all of them.")

    b.picture(shot("certificates"),
              "The certificate, issued and copied to both servers.")

    b.h2("Step 6: turn on https")
    b.steps([
        "Open the site.",
        "Choose the certificate you just got.",
        "Turn on Force https.",
        "Press Apply config.",
    ])

    b.picture(
        term("check-https", [
            "$ curl -I https://shop.domain.com/",
            "HTTP/2 200",
            "server: nginx",
            "",
            "# and the plain address now sends people to the secure one",
            "$ curl -I http://shop.domain.com/",
            "HTTP/1.1 301 Moved Permanently",
            "Location: https://shop.domain.com/",
        ], "you@your-computer: ~"),
        "The secure address working, and the plain one forwarding to it.")

    b.para(
        "Open it in a browser.  You should get a padlock and no warning.")

    b.h2("Step 7: send /api somewhere else")
    b.steps([
        "Open the site and find the Paths section.",
        "Press Add a path.",
        "Type /api for the path.",
        "Set it to send requests to a pool, and choose shop-api.",
        "Leave Take this path off before sending it on turned off, because the "
        "API application was written knowing it lives under /api.",
        "Press Save, then Apply config.",
    ])

    b.picture(
        term("check-api", [
            "$ curl -s -o /dev/null -w '%{http_code}\\n' \\",
            "      https://shop.domain.com/",
            "200",
            "$ curl -s -o /dev/null -w '%{http_code}\\n' \\",
            "      https://shop.domain.com/api/health",
            "200",
        ], "you@your-computer: ~"),
        "Both parts of the site answering, from two different sets of "
        "servers.")

    b.h2("Step 8: prove the failover works")
    b.para(
        "This is the step people skip and it is the one worth doing.  Stop the "
        "application on 10.0.0.11, or take it off the network.  Within a few "
        "seconds the pool should show that server red and the other green.  The "
        "site should keep working throughout.")

    b.para(
        "Start it again and watch it come back.  You now know the health check "
        "works, which is not something to find out during a real failure.")

    b.warn(
        "If the site kept working but the pool never went red, your health "
        "check is not testing anything useful.  Point it at a page that "
        "genuinely exercises the application and try again.")

    b.h2("What you have")
    b.para(
        "A site on a real certificate that renews itself, spread across two "
        "servers, with part of it going to a different pair, and you have seen "
        "it survive one of them failing.  That is the common shape of most of "
        "the work you will do here.")
    b.page_break()


# ---------------------------------------------------------------------------
def _dns_example(b, shot, term):
    b.h1("27. Worked example: DNS failover end to end")

    b.para(
        "Chapter 19 explained the idea and the settings.  This chapter does it "
        "once, all the way through, including the test that proves it works.")

    b.h2("The example")
    b.para(
        "The same company as Chapter 26.  Their two load balancers are in "
        "different buildings on different networks, so they cannot share a "
        "floating address.  They want shop.domain.com to keep working when one "
        "building goes dark.")

    b.table(
        ["Thing", "Value"],
        [
            ["First load balancer", "lb-01, public address 203.0.113.10"],
            ["Second load balancer", "lb-02, public address 203.0.113.11"],
            ["Part of the domain to delegate", "gslb.domain.com"],
            ["Nameserver names to invent", "ns1.domain.com and ns2.domain.com"],
        ],
        widths=[2.4, 3.9])

    b.h2("Step 1: the zone")
    b.steps([
        "Go to DNS Failover and press Add a zone.",
        "Zone name: gslb.domain.com.",
        "Nameserver names: ns1.domain.com, ns2.domain.com.",
        "Press Save.",
    ])

    b.h2("Step 2: the name")
    b.steps([
        "Press Add a name on the zone.",
        "Name: www.  Type: A.  TTL: 30.",
        "When a server is down: hand out all the healthy ones.",
        "If every server is down: hand them out anyway.",
        "Add an answer and pick lb-01 from the list.  Its address fills in.",
        "Add a second answer and pick lb-02.",
        "Press Save.",
    ])

    b.para(
        "The page now shows the name with two answers, each with a green dot "
        "and the words node is up, handed out.")

    b.picture(shot("gslb"), "The zone with both servers handed out.")

    b.h2("Step 3: the delegation")
    b.para(
        "The zone prints the records to create.  In Route 53, open the hosted "
        "zone for domain.com and create them there.")

    b.table(
        ["Name", "Type", "Value", "TTL"],
        [
            ["gslb", "NS", "ns1.domain.com. and ns2.domain.com.", "300"],
            ["ns1", "A", "203.0.113.10", "300"],
            ["ns2", "A", "203.0.113.11", "300"],
            ["shop", "CNAME", "www.gslb.domain.com.", "60"],
        ],
        widths=[0.9, 0.7, 3.2, 0.6])

    b.para(
        "The last row is what points the address people actually use at the new "
        "zone.  Until you add it, everything works and nobody is using it.")

    b.h2("Step 4: check the servers answer")
    b.para(
        "Ask each server directly, with no port on the end.")

    b.picture(
        term("ex-dig", [
            "$ dig +short @203.0.113.10 www.gslb.domain.com A",
            "203.0.113.10",
            "203.0.113.11",
            "",
            "$ dig +short @203.0.113.11 www.gslb.domain.com A",
            "203.0.113.11",
            "203.0.113.10",
        ], "you@your-computer: ~"),
        "Both servers answering, and both listing both addresses.")

    b.h2("Step 5: check the delegation took")
    b.para(
        "Now ask the internet rather than the servers, so you are testing the "
        "whole path.  Leave it a few minutes after making the records.")

    b.picture(
        term("ex-dig2", [
            "$ dig +short shop.domain.com",
            "www.gslb.domain.com.",
            "203.0.113.10",
            "203.0.113.11",
        ], "you@your-computer: ~"),
        "The address people use, followed through to both load balancers.")

    b.para(
        "If this returns nothing, the delegation is the problem and not the "
        "software.  Check the NS records and the two address records for the "
        "nameservers.  Those address records are the ones people forget.")

    b.h2("Step 6: test the failover")
    b.para(
        "Stop the manager on lb-01, or shut the machine down entirely.  Then "
        "ask the surviving server for the address every few seconds and watch "
        "what happens.")

    b.picture(
        term("ex-failover", [
            "$ dig +short @203.0.113.11 www.gslb.domain.com A",
            "203.0.113.10",
            "203.0.113.11",
            "",
            "# about thirty seconds later",
            "$ dig +short @203.0.113.11 www.gslb.domain.com A",
            "203.0.113.11",
        ], "you@your-computer: ~"),
        "The failed server removed from the answer.")

    b.para(
        "The dead server drops out of the answer in about thirty seconds.  New "
        "visitors are sent only to the survivor.  Visitors whose computers "
        "already had the old answer move once it is forgotten, which is the TTL "
        "on top, so about a minute in total.")

    b.h2("Step 7: bring it back")
    b.para(
        "Start lb-01 again.  It rejoins and is back in the answer within about "
        "five seconds.  Removal is slower than restoring on purpose, so a brief "
        "hiccup does not move everybody.")

    b.h2("What to check afterwards")
    b.bullets([
        "The DNS Failover page on both servers says it is answering, not just "
        "one of them.",
        "Both answers show a green dot.",
        "The address people use still resolves through to both load "
        "balancers.",
    ])

    b.warn(
        "Do this test on purpose, in daylight, before you need it.  A failover "
        "that has never been tried is a plan, not a capability, and the two "
        "look identical right up until the moment they do not.")
    b.page_break()


# ---------------------------------------------------------------------------
def _maintenance(b, shot, term):
    b.h1("28. Worked example: taking a server out for maintenance")

    b.para(
        "You need to reboot one of the load balancers, patch it, or move it.  "
        "This is how to do that without anybody noticing.  It is short, and "
        "doing it in this order is the whole point.")

    b.h2("Before you touch anything")
    b.steps([
        "Open the Cluster page and check both servers are online.  If the other "
        "one is not healthy, stop.  You are about to be running on one server "
        "and it needs to be a good one.",
        "Open the Changes page and check nothing is saved but not applied.  "
        "Applying somebody else's half finished work in the middle of "
        "maintenance is a bad afternoon.",
    ])

    b.h2("Take it out of the DNS answer")
    b.para(
        "If you use DNS failover, do this first and give it time.  Open DNS "
        "Failover, edit the name, and turn off the answer for the server you "
        "are about to work on.  Save.")

    b.para(
        "Wait at least twice the TTL before going further.  With a TTL of 30 "
        "seconds, wait two minutes.  That is not the software being slow, it is "
        "the time for computers elsewhere to forget the old answer.  Skipping "
        "this is the difference between nobody noticing and a few people "
        "getting errors.")

    b.h2("Hand over being in charge")
    b.para(
        "If the server you are working on is the active one, use the failover "
        "button on the Cluster page to hand over to the other.  Doing it "
        "yourself is calmer than pulling the plug and letting the software work "
        "it out, and you can confirm the other server took over before you go "
        "any further.")

    b.h2("Stop it from coming back too early")
    b.para(
        "Turn on forced standby for the server you are working on.  That stops "
        "it becoming active again halfway through your work, for example after "
        "a reboot you did not expect to change anything.")

    b.h2("Do the work")
    b.para(
        "Reboot it, patch it, whatever you came to do.  The other server is "
        "carrying all of the traffic.  Nothing about this is urgent, which is "
        "the point of doing it in this order.")

    b.h2("Putting it back")
    b.steps([
        "Wait for it to come back and check the Cluster page shows it online.",
        "Turn off forced standby.",
        "Turn the DNS answer back on.  It returns to the answer within a few "
        "seconds.",
        "Watch it for a few minutes before you go home.",
    ])

    b.note(
        "The order going back in is the reverse of the order coming out.  "
        "Health first, then being allowed to be in charge, then traffic.  "
        "Turning the DNS answer back on before the server is actually well "
        "sends people to something that is not ready.")

    b.h2("A checklist you can print")
    b.table(
        ["Order", "Coming out", "Going back in"],
        [
            ["1", "Check both servers healthy", "Check it is online again"],
            ["2", "Check nothing unapplied", "Turn off forced standby"],
            ["3", "Turn off its DNS answer, wait", "Turn its DNS answer on"],
            ["4", "Hand over if it is active", "Watch for a few minutes"],
            ["5", "Turn on forced standby", ""],
            ["6", "Do the work", ""],
        ],
        widths=[0.6, 2.9, 2.8])
    b.page_break()
