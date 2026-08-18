"""
A refused apply has to say something true about why.

`is_active` gives back false for three different situations, and every refusal
used to answer all three with one sentence:

    this node is a standby, so it does not take config changes.
    Make your change on the active node.

Two of the three make that advice wrong.  `register_self` deliberately stands a
returning node down to standby and waits for an election, so for the seconds
after a restart this node is not active and neither is anybody else.  Somebody
applying in that window was sent to "the active node", and there was no active
node to go to.  It is not a rare window either: the container restarts on every
`install.sh --upgrade`, and the election job is on an interval, which does not
fire until one whole interval has gone by.

Seen once on the fleet on 18 August 2026 and written off as unexplained, with a
locked database in the same window making it look like a database fault.  It was
the restart.

So there are three answers now, and the two that mean "wait" come back as
`RoleNotSettled`, which the API turns into a 503 with a retry in it rather than
the 409 an ordinary refusal gets.

Builds its own roster in memory.  It never opens the node's database, adds
nothing to the real roster, and applies nothing.

    docker exec -i nginx-fleet-manager python < checks/standby_message.py
"""
import sys

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.core.cluster import ClusterError, RoleNotSettled, get_cluster
from app.models import Node, NodeRole, NodeState

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")
    return ok


ME = "lb-check-self"
PEER = "lb-check-peer"

# A roster of our own, in memory, with only the table this needs.  Nothing here
# touches the database the manager is using.
engine = create_engine("sqlite://")
Node.__table__.create(engine)
Session = sessionmaker(bind=engine)

cluster = get_cluster()
was_name = cluster.node_name
cluster.node_name = ME


def roster(session, mine, theirs=None):
    session.query(Node).delete()
    session.add(Node(name=ME, address="10.0.0.1", gui_port=7443,
                     role=mine, state=NodeState.ONLINE, is_self=True))
    if theirs is not None:
        session.add(Node(name=PEER, address="10.0.0.2", gui_port=7443,
                         role=theirs, state=NodeState.ONLINE))
    session.commit()


print("\n  what a node says when it will not take a config change\n")

try:
    session = Session()

    # ---- the situation the message was written for --------------------------
    roster(session, NodeRole.STANDBY, NodeRole.ACTIVE)
    err = cluster.not_active_error(session)
    text = str(err)
    check("a real standby is still told it is a standby", "standby" in text, text)
    check("and it is worth retrying nowhere else, so not a RoleNotSettled",
          not isinstance(err, RoleNotSettled) and isinstance(err, ClusterError))
    check("it names the node that does hold the role", PEER in text, text)
    check("and says where to find it", "https://10.0.0.2:7443" in text, text)

    # ---- the window this was actually hit in --------------------------------
    # Both nodes standby is exactly what register_self leaves behind on a
    # restart, until the first election runs.
    roster(session, NodeRole.STANDBY, NodeRole.STANDBY)
    err = cluster.not_active_error(session)
    text = str(err)
    check("with nobody active it is a retry, not a refusal",
          isinstance(err, RoleNotSettled), type(err).__name__)
    check("it does not send anybody to another node",
          "Make your change on" not in text and "active node." not in text, text)
    check("it says to try again", "again" in text.lower(), text)
    check("it says why, so a restart is not mistaken for a fault",
          "restart" in text.lower(), text)
    check("it does not name a node that cannot help", PEER not in text, text)

    # ---- a fresh row is UNKNOWN, not STANDBY, and the words must follow -----
    roster(session, NodeRole.UNKNOWN, NodeRole.ACTIVE)
    text = str(cluster.not_active_error(session))
    check("a node that is not a standby is not called one",
          "is a standby" not in text, text)
    check("and is still pointed at the node that holds the role",
          PEER in text, text)

    # ---- no row for ourselves at all ---------------------------------------
    session.query(Node).delete()
    session.commit()
    err = cluster.not_active_error(session)
    text = str(err)
    check("a node with no row for itself is a retry as well",
          isinstance(err, RoleNotSettled), type(err).__name__)
    check("and says it is not in the roster yet rather than blaming a standby",
          "roster" in text.lower() and "is a standby" not in text, text)

    # ---- the roles the fleet really uses ------------------------------------
    # Belt and braces on the branch that decides between the two: whatever the
    # roster says, a node holding ACTIVE never gets here at all.
    roster(session, NodeRole.ACTIVE, NodeRole.STANDBY)
    check("an active node is not refused in the first place",
          cluster.is_active(session) is True)

    session.close()
finally:
    cluster.node_name = was_name
    engine.dispose()

failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: a refused apply says which of the three things happened "
      f"({len(results)} checks)\n")
