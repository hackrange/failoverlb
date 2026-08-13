"""
The back matter: reference tables and the glossary.

Kept apart from the chapters so it is always last, whatever gets added in
between.  It used to live at the end of Part 4, which meant adding Part 5 put
the appendices in the middle of the book.

House style: two spaces between sentences, no em dashes, plain words.
"""


def write(b, shot, term):
    _appendix_ports(b)
    _appendix_files(b)
    _glossary(b)


# ---------------------------------------------------------------------------
def _appendix_ports(b):
    b.h1("Appendix A: Ports")

    b.table(
        ["Port", "Protocol", "What it is", "Who should reach it"],
        [
            ["80", "TCP", "Web traffic and certificate checks", "Everyone"],
            ["443", "TCP", "Secure web traffic", "Everyone"],
            ["7443", "TCP", "The management screen", "Your office networks"],
            ["7444", "TCP", "The servers talking to each other", "The other servers"],
            ["53", "TCP and UDP", "DNS failover answers", "Everyone"],
            ["5353", "TCP and UDP", "Where the DNS part really listens", "Nobody directly"],
        ],
        widths=[0.7, 1.1, 2.6, 1.9])

    b.para(
        "Port 5353 is in the table for completeness.  Port 53 is sent to it by "
        "a firewall rule the software manages, so you never open 5353 and you "
        "never test against it.")
    b.page_break()


# ---------------------------------------------------------------------------
def _appendix_files(b):
    b.h1("Appendix B: Files and folders")

    b.table(
        ["Path", "What it is"],
        [
            ["/data/docker/nginx-gui-mgmt", "The software, and the .env settings file"],
            ["/opt/nginx-fleet-manager", "The agent"],
            ["/etc/nginx", "nginx's configuration, written by this software"],
            ["/etc/nginx/nginxmgr", "The parts this software generates"],
            ["/etc/nginx/nginxmgr/certs", "Certificates and keys"],
            ["/var/backups/nginx-fleet-manager", "The configuration before each apply"],
            ["/var/log/nginx", "nginx's own logs"],
            ["/run/nginxmgr/agent.sock", "How the screen talks to the agent"],
        ],
        widths=[2.7, 3.6])

    b.warn(
        "Do not edit anything under /etc/nginx/nginxmgr by hand.  It is written "
        "again from scratch on every apply, so your change will disappear "
        "without warning at the least convenient moment.  Use raw configuration "
        "mode on a site if you need something the screen does not offer, "
        "because that is stored and survives.")
    b.page_break()


# ---------------------------------------------------------------------------
def _glossary(b):
    b.h1("Appendix C: Glossary")

    terms = [
        ["Active", "The server currently in charge of making changes.  Both "
         "servers serve traffic."],
        ["Agent", "The small program that does the few jobs needing "
         "administrator rights, so the web screen does not need them."],
        ["Apply", "Making your saved changes live on every server at once."],
        ["Backend", "One of your application servers, behind the load "
         "balancer."],
        ["Certificate", "The file that makes the padlock appear and encrypts "
         "traffic."],
        ["Delegation", "Telling the internet that your servers answer for part "
         "of your domain."],
        ["Failover", "Traffic moving to a working server when one fails."],
        ["Glue", "An address record that lets a nameserver inside a zone be "
         "found at all."],
        ["GSLB", "Sending people to a healthy server using DNS.  What Chapter "
         "19 sets up."],
        ["Health check", "A regular test of whether a backend is answering "
         "properly."],
        ["Lets Encrypt", "A service giving out free certificates that renew "
         "automatically."],
        ["Location, or path", "A rule for part of a site, such as everything "
         "under /api."],
        ["nginx", "The program that actually handles the traffic.  This "
         "software configures it."],
        ["Node", "One of your load balancer servers."],
        ["Pool", "A named list of backends that a site sends requests to."],
        ["Proxy", "Passing a request on to another server and returning its "
         "answer."],
        ["Rate limit", "A cap on how many requests one visitor may make."],
        ["Site", "One web address and the rules for it."],
        ["Standby", "The server not currently in charge.  It still serves "
         "traffic."],
        ["TTL", "How long a DNS answer is remembered before being looked up "
         "again."],
        ["Upstream", "Another word for a pool, used inside nginx itself."],
    ]
    b.table(["Term", "What it means"], terms, widths=[1.5, 4.8])
