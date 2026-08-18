"""
Suite 19: the refusal half, asked from outside the fleet.

Every other suite runs in the node's own network namespace, which makes them
useful for almost everything and useless for exactly one thing: they can never
be an outsider.  The allow list a management only site renders is generated
from the node roster, and the roster holds every address each node has, so any
address those suites can send from is already on the list.  Putting a spare one
on the loopback does not help.  That was tried: within a minute the fleet had
picked it up as another of the node's addresses and was allowing it.

This runs on a **bridge** network instead, so its source address is the
container's own and belongs to no node.  It drives no browser and needs no
account, because the admin allow list would refuse it from here anyway, which
is itself the right behaviour.  Everything it needs was written out by
`t17_access_lists.py` when it left the site switched on:

    tools/qa/evidence/outside-handoff.json

It reads its own source address off the socket rather than being told, checks
that address against the allow lines the fleet really rendered, and only then
believes a refusal.  Without that check a 403 could mean anything: a site that
is down, a name that does not resolve to a server block, a typo in the Host
header.  The point of the test is that the site answered somebody else in the
same breath and refused us.

    docker run --rm -v "$PWD/tools/qa:/qa" \\
      -e QA_LB01=<node address> nfm-docs:latest python /qa/t19_outside_address.py

Note the missing --network host.  That is the whole suite.
"""
import json
import pathlib
import socket
import sys
sys.path.insert(0, "/qa")
import qa

HANDOFF = pathlib.Path("/qa/evidence/outside-handoff.json")

r = qa.Runner.__new__(qa.Runner)          # no browser, no sign in, no session
r.suite = "t19_outside_address"
r.dir = qa.ROOT
r.shots = qa.ROOT / "shots"
r.logfile = qa.ROOT / "t19_outside_address.jsonl"


def our_address(host, port):
    """
    Which address this container really sends from, asked of the kernel.

    Read off the socket rather than off an interface, because what matters is
    the address that arrives at nginx after any routing and any translation on
    the way, and only the connected socket knows that.
    """
    probe = socket.create_connection((host, port), 10)
    try:
        return probe.getsockname()[0]
    finally:
        probe.close()


print("\n  asking from outside the fleet\n")

if not HANDOFF.is_file():
    print(f"    {HANDOFF} is not there.  Run t17_access_lists.py first: it "
          f"sets the site up and writes what this needs.")
    sys.exit(0)

plan = json.loads(HANDOFF.read_text())
NODE = plan["node"]
HOST = plan["hostname"]
RULES = plan["server_rules"]

t = r.test("OUT-01", "Access lists", "A management only site refuses an outsider",
           "Ask a site that is set to management access only for a page, from "
           "an address that is on no node and in no management network, and "
           "prove it is refused while the fleet's own addresses are served.",
           "The whole promise of the tick box.  Everything else about it can "
           "be read off the config, and reading the config is what let a "
           "different access list defect sit in this product until somebody "
           "made a request instead.  Until a stranger has actually been turned "
           "away, the feature is untested.",
           "403 for the outsider, and the rendered rules confirm the outsider "
           "was never on the list.")

t.step(f"work out what address this container sends from, talking to {NODE}")
try:
    source = our_address(NODE, 80)
except OSError as exc:
    t.ok("this container can reach the node at all", False, str(exc))
    t.close()
    r.stop = lambda: None
    print("\nT19 DONE")
    sys.exit(1)

t.proof("the address the kernel says this connection goes out from", source)
t.ok("this container is not sending from the node itself", source != NODE, source)

t.step("check that address against the allow lines the fleet really rendered")
t.proof("the rules the site is running, as t17 recorded them", RULES or "[none]")
covered = qa.covered_by(source, RULES)
t.ok(f"{source} is on none of the site's allow lines", not covered,
     f"{source} is matched by one of them, so a refusal would prove nothing")

t.step("now ask for the page")
outside = qa.probe(HOST, "/", ip=NODE, scheme="http")
t.proof(f"the management only site, asked from {source}", qa.summarise(outside))
t.ok("the outsider is refused", outside["status"] == plan["expect"],
     f"expected {plan['expect']}, got {outside['status']}")
t.ok("and refused by the site rather than by nothing answering",
     outside["status"] != 0, outside)

t.step("and prove this container reached that nginx at all")
# The control site is open to everybody and sits on the same nginx, so the
# same container asking a moment later separates "the outsider was refused"
# from "nothing was listening".  Without it a 403 could be a name that
# resolves nowhere or a container that cannot route to the node.
control = qa.probe(plan["control_hostname"], "/", ip=NODE, scheme="http")
t.proof(f"the open site beside it, from the same {source}", qa.summarise(control))
t.ok("the open site on the same nginx serves this same container",
     control["status"] == plan["control_expect"],
     f"expected {plan['control_expect']}, got {control['status']}")
t.ok("so the refusal was the site's rule and not a dead end",
     control["status"] == plan["control_expect"]
     and outside["status"] == plan["expect"],
     f"open {control['status']}, locked {outside['status']}")

t.note(f"one nginx, one container, one moment, two answers: {source} is served "
       f"by the open site and turned away by the management only one.  That is "
       f"the tick box working, measured rather than read off a config file.")
t.close()

print("\nT19 DONE")
