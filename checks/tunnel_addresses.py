"""
Tunnel addresses are handed out once, and never to two machines.

Removing a workload used to free its address immediately, so the next one
enrolled took it.  Anything still pointing at that address, a pool member most
of all, then talked to a different machine with nothing anywhere saying the
meaning of the address had changed.  The Tunnel page tells people to put the
address in a pool, so that is the normal case and not a corner of one.

Everything here happens on rows this check makes and removes, in a range of
its own, and it touches no real tunnel: no interface is brought up, no peer is
pushed to a node, nothing is applied.

    docker exec -i nginx-fleet-manager python < checks/tunnel_addresses.py
"""
import sys

from app.core import tunnel
from app.db import session_scope
from app.models import Pool, PoolMember, TunnelNetwork, TunnelNodeKey, TunnelPeer

CIDR = "10.99.0.0/24"           # nobody's real range, and its own network row
POOL = "check-tunnel-pool"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail}")


def make_network(session):
    net = TunnelNetwork(cidr=CIDR, listen_port=51999, enabled=False)
    session.add(net)
    session.flush()
    return net


def add_peer(session, net, name):
    address = tunnel.next_free_address(session, net)
    session.add(TunnelPeer(network_id=net.id, name=name, address=address))
    session.flush()
    return address


def clean(session):
    for peer in session.query(TunnelPeer).filter(
            TunnelPeer.name.like("check-tunnel-%")).all():
        session.delete(peer)
    pool = session.query(Pool).filter(Pool.name == POOL).first()
    if pool:
        for member in list(pool.members):
            session.delete(member)
        session.delete(pool)
    for net in session.query(TunnelNetwork).filter(
            TunnelNetwork.cidr == CIDR).all():
        session.delete(net)
    session.commit()


def main():
    with session_scope() as session:
        clean(session)
        net = make_network(session)

        # Two nodes' worth at the bottom of the range, the same assumption the
        # allocator makes on a fleet that has not made its keys yet.
        nodes = session.query(TunnelNodeKey).count()
        first_workload = max(nodes, 2)
        hosts = [f"10.99.0.{i + 1}" for i in range(254)]

        one = add_peer(session, net, "check-tunnel-one")
        two = add_peer(session, net, "check-tunnel-two")
        check("workloads start after the nodes", one == hosts[first_workload],
              f"first workload got {one}, expected {hosts[first_workload]}")
        check("the second one is the next address up", two == hosts[first_workload + 1],
              f"got {two}")

        # Remove the first, then enrol another.  The old rule handed the freed
        # address straight over.
        session.delete(session.query(TunnelPeer).filter(
            TunnelPeer.name == "check-tunnel-one").first())
        session.flush()
        three = add_peer(session, net, "check-tunnel-three")
        check("a freed address is not handed to the next workload", three != one,
              f"the new workload got {three}, which used to be check-tunnel-one")
        check("it carries on up the range instead", three == hosts[first_workload + 2],
              f"got {three}")

        # An address a pool still names is not handed out either, even when the
        # counting comes back round to it.
        pool = Pool(name=POOL, lb_method="round_robin")
        session.add(pool)
        session.flush()
        session.add(PoolMember(pool_id=pool.id, address=one, port=8080,
                               enabled=True, weight=1))
        session.flush()
        net.address_high_water = 0      # as if the range had wrapped
        four = add_peer(session, net, "check-tunnel-four")
        check("an address a pool still points at is skipped", four != one,
              f"handed out {four}, which {POOL} still has a member on")

        # And the pool can see itself in the answer, which is what the remove
        # dialog reads to say which pools are about to break.
        from app.web.routes_tunnel import _pools_pointing_at
        stray = TunnelPeer(network_id=net.id, name="check-tunnel-five", address=one)
        session.add(stray)
        session.flush()
        check("the peer says which pools point at it",
              _pools_pointing_at(stray) == [POOL],
              f"got {_pools_pointing_at(stray)}")

        clean(session)
        print("    (rows made by this check removed)")

    failed = [name for name, ok, _ in results if not ok]
    print()
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


sys.exit(main())
