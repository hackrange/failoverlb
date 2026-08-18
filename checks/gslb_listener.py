"""
The DNS listener has to come back after it has been stopped.

The listener starts when the first gslb zone appears and stops when the last
one goes, so a fleet that uses gslb at all goes round that loop every time
somebody adds or removes a zone.

It only survived the first lap.  `stop` closed the sockets and returned, while
the serving threads were still blocked inside `recvfrom` and `accept` on them.
Closing a socket from another thread does not reliably wake a thread already
inside a call on it, so those threads stayed alive holding the port, and every
later `start` failed:

    [Errno 98] Address already in use

with the operating system's own socket list showing the port free, and the
status reporting `listening: false` with that error against it.  Nothing
recovered it short of restarting the manager, so deleting and recreating the
zone, which is the obvious thing to try, did not help.  Global load balancing
served nothing and the only sign was one field on the page.

The fix is the ordinary shape for this: the sockets carry a timeout so the
loops wake up and look at the flag, and `stop` puts the flag down, waits for
the threads to end, and only then closes anything.

Binds a real socket on a high port, on this box, and gives it back.  Writes
nothing, applies nothing, and touches no zone anybody has made.

    docker exec -i nginx-fleet-manager python < checks/gslb_listener.py
"""
import socket
import sys
import threading
import time

from app.core.gslb import GslbServer

# High, and out of the way of the real listener on 5353.
PORT = 15353
ADDRESS = "127.0.0.1"

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")
    return ok


def port_is_free(port):
    """Could somebody else bind it right now, both ways round."""
    for kind in (socket.SOCK_DGRAM, socket.SOCK_STREAM):
        probe = socket.socket(socket.AF_INET, kind)
        try:
            probe.bind((ADDRESS, port))
        except OSError:
            probe.close()
            return False
        probe.close()
    return True


print("\n  the listener starting, stopping and starting again\n")

if not port_is_free(PORT):
    print(f"    port {PORT} is already in use on this box, so this check "
          f"cannot run")
    sys.exit(0)

server = GslbServer(address=ADDRESS, port=PORT)

server.start()
check("it starts", server._running)
check("the port is taken while it is running", not port_is_free(PORT))

server.stop()
check("it stops", not server._running)
check("the port comes free as soon as it has stopped", port_is_free(PORT),
      "the serving threads are still holding it, which is the fault this "
      "check exists for")
check("no serving thread is left behind",
      not [t for t in server._threads if t.is_alive()])

# The lap that used to be impossible.  Five of them, because one working does
# not tell you the second will.
laps = 0
for lap in range(1, 6):
    try:
        server.start()
    except OSError as exc:
        check(f"lap {lap}: it binds again after a stop", False, str(exc))
        break
    if not check(f"lap {lap}: it binds again after a stop",
                 server._running and not port_is_free(PORT)):
        break
    server.stop()
    if not check(f"lap {lap}: and gives the port back", port_is_free(PORT)):
        break
    laps += 1
check("five stop and start laps in a row", laps == 5, f"managed {laps}")

# A stop has to be prompt.  If the loops are blocking forever then this is
# where it shows, rather than in a bind failure somewhere else much later.
server.start()
started = time.time()
server.stop()
took = time.time() - started
check("stopping does not hang waiting on a blocked read", took < 3.0,
      f"took {took:.1f} seconds")

check("stopping something already stopped is harmless",
      (server.stop() or True) and not server._running)
check("the port is free at the end", port_is_free(PORT))

failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: the listener comes back after being stopped "
      f"({len(results)} checks)\n")
