"""
Put the health checker in front of backends that misbehave on purpose.

Deciding a backend is down is the one job here where being wrong is expensive in
both directions.  Call a healthy backend down and you have taken capacity away
for no reason.  Call a broken one up and every visitor it serves gets the error.

So this drives the real checker against real sockets: one that answers properly,
one that returns the wrong status, one that returns the wrong body, one that
takes too long, and one that is not listening at all.

Nothing here touches the database or the live fleet.  The pool and member are
stand ins with the same fields the checker reads, and the backends are servers
this file starts and stops itself on ports nothing else uses.

    docker exec -i nginx-fleet-manager python < checks/health_checks.py
"""
import asyncio
import http.server
import socket
import sys
import threading
import time

from app.core.health import HealthChecker
from app.models import MemberState, Pool, PoolMember

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:180]}")


class Backend(http.server.BaseHTTPRequestHandler):
    """A backend that behaves however the test needs it to."""

    status = 200
    body = b"ok"
    delay = 0.0

    def do_GET(self):
        if self.delay:
            time.sleep(self.delay)
        payload = self.body
        self.send_response(self.status)
        # A redirect with no Location is malformed and the client blows up on it
        # rather than reporting a status, which looks like a checker bug and is
        # a broken test backend.
        if 300 <= self.status < 400:
            self.send_header("Location", "/somewhere-else")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *_args):
        pass          # the checker's own output is the interesting part


def serve(status=200, body=b"ok", delay=0.0):
    """Start a backend on a free port and give back the port and a way to stop it."""
    handler = type("H", (Backend,), {"status": status, "body": body, "delay": delay})
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    return port, server


def free_port():
    """A port with nothing on it, for the refused connection case."""
    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def make_pool(**kw):
    """
    A real Pool object that never reaches a session.

    Built from the real class rather than a stand in with the fields I thought
    the checker read.  The first version of this file was a stand in and it kept
    failing on attributes nobody had thought of, which tests my guesses about
    the checker rather than the checker.

    Column defaults are only applied on flush, so anything the checker needs a
    value for is set here on purpose.
    """
    pool = Pool(name="check-pool")
    pool.health_check_type = "http"
    pool.health_check_path = "/"
    pool.health_check_method = "GET"
    pool.health_check_expect_status = "200-399"
    pool.health_check_expect_body = None
    pool.health_check_host_header = None
    pool.health_check_timeout = 2
    pool.health_check_port = None
    pool.health_check_verify_tls = False
    pool.health_check_rise = 2
    pool.health_check_fall = 3
    pool.backend_tls = False
    pool.backend_tls_set = True
    pool.token_enabled = False
    pool.token_encrypted = None
    pool.settings = "{}"
    for key, value in kw.items():
        setattr(pool, key, value)
    return pool


class NoSession:
    """
    Stands in for the database session while rise and fall are exercised.

    The checker records an event when a member changes state, which needs
    somewhere to put it.  Collecting them here keeps the check away from the
    real database and lets it assert the event was recorded at all.
    """

    def __init__(self):
        self.added = []

    def add(self, row):
        self.added.append(row)

    def commit(self):
        pass

    def flush(self):
        pass


def make_member(port, address="127.0.0.1"):
    member = PoolMember(address=address, port=port)
    member.id = 1
    member.enabled = True
    member.weight = 1
    member.state = MemberState.UNKNOWN
    member.admin_state = "up"
    member.consecutive_ok = 0
    member.consecutive_fail = 0
    member.check_count = 0
    member.last_error = None
    member.node_state = "{}"
    return member


async def main():
    checker = HealthChecker(node_name="check")
    servers = []

    # start() is what builds the http client, and without it every check that
    # gets as far as making a request dies on a None.  Only the client is wanted
    # here, not the scheduled loop, so it is started and the loop never runs.
    await checker.start()
    checker._running = False

    print("  a backend that answers properly")
    port, server = serve(); servers.append(server)
    pool = make_pool()
    result = await checker._check_member(pool, make_member(port))
    check("a 200 with the right body is up", result["ok"], result.get("detail", ""))

    print()
    print("  a backend that answers wrongly")

    port, server = serve(status=500); servers.append(server)
    result = await checker._check_member(make_pool(), make_member(port))
    check("a 500 is down", not result["ok"], f"said ok: {result.get('detail')}")

    port, server = serve(status=404); servers.append(server)
    result = await checker._check_member(make_pool(), make_member(port))
    check("a 404 is down when 200-399 is expected", not result["ok"],
          f"said ok: {result.get('detail')}")

    port, server = serve(status=301); servers.append(server)
    result = await checker._check_member(make_pool(), make_member(port))
    check("a 301 is up when 200-399 is expected", result["ok"], result.get("detail", ""))

    print()
    print("  a backend whose body is wrong, which is the one a status misses")
    port, server = serve(body=b"maintenance in progress"); servers.append(server)
    pool = make_pool(health_check_expect_body="ok")
    result = await checker._check_member(pool, make_member(port))
    check("a 200 with the wrong body is down", not result["ok"],
          "a backend can answer 200 while serving nothing useful")

    port, server = serve(body=b"everything is ok here"); servers.append(server)
    pool = make_pool(health_check_expect_body="ok")
    result = await checker._check_member(pool, make_member(port))
    check("the body only has to contain the text", result["ok"], result.get("detail", ""))

    print()
    print("  a backend that is too slow, and one that is not there")

    port, server = serve(delay=3); servers.append(server)
    pool = make_pool(health_check_timeout=1)
    started = time.monotonic()
    result = await checker._check_member(pool, make_member(port))
    took = time.monotonic() - started
    check("a backend slower than the timeout is down", not result["ok"],
          f"said ok after {took:.1f}s")
    check("it gives up near the timeout rather than hanging", took < 2.5,
          f"took {took:.1f}s with a 1s timeout")

    dead = free_port()
    result = await checker._check_member(make_pool(), make_member(dead))
    check("a refused connection is down", not result["ok"],
          f"said ok: {result.get('detail')}")

    print()
    print("  a tcp check only asks whether something is listening")
    port, server = serve(status=500); servers.append(server)
    pool = make_pool(health_check_type="tcp")
    result = await checker._check_member(pool, make_member(port))
    check("tcp is up even when http would be down", result["ok"],
          "tcp connect should not care about the status code")

    pool = make_pool(health_check_type="tcp")
    result = await checker._check_member(pool, make_member(free_port()))
    check("tcp is down when nothing is listening", not result["ok"], "")

    print()
    print("  rise and fall, so one blip does not move anything")

    pool = make_pool(health_check_rise=2, health_check_fall=3)
    member = make_member(1)
    member.state = MemberState.UP
    session = NoSession()

    for i in range(1, 3):
        checker._apply_result(session, pool, member, {"ok": False, "detail": "x", "ms": 1})
        check(f"still up after {i} failure{'s' if i > 1 else ''}",
              member.state == MemberState.UP,
              f"went {member.state.value} after {i}, fall is {pool.health_check_fall}")

    checker._apply_result(session, pool, member, {"ok": False, "detail": "x", "ms": 1})
    check("down on the third failure, which is the fall count",
          member.state == MemberState.DOWN, f"state is {member.state.value}")

    checker._apply_result(session, pool, member, {"ok": True, "detail": "", "ms": 1})
    check("still down after one success, because rise is 2",
          member.state == MemberState.DOWN, f"state is {member.state.value}")

    checker._apply_result(session, pool, member, {"ok": True, "detail": "", "ms": 1})
    check("up on the second success", member.state == MemberState.UP,
          f"state is {member.state.value}")

    check("a state change is written to the event log", len(session.added) >= 2,
          f"only {len(session.added)} events for a down and an up")

    await checker.stop()
    for server in servers:
        server.shutdown()

    print()
    failed = [name for name, ok, _ in results if not ok]
    print(f"  {len(results) - len(failed)} of {len(results)} behaved correctly")
    print()
    print("  what this does not cover:")
    print("    - the checker running on a schedule against the real fleet")
    print("    - the floor that stops a pool being taken out entirely")
    print("    - what nginx does with the result, which the apply covers")
    print()
    print("  RESULT:", "the checker judges backends correctly" if not failed
          else f"{len(failed)} WRONG: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(asyncio.run(main()))
