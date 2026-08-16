"""
Prove a viewer cannot change anything, and that a write without a token fails.

Both of these are the sort of thing that works for a year and then quietly stops
working when somebody adds a route and forgets a guard.  Nothing about that
failure is visible from the page: the button is still hidden for a viewer, and
the API behind it is wide open to anybody who knows the path.

Every request here is one that should be REFUSED, so nothing is mutated even
when the check fails.  That is deliberate.  A permission check that has to make
a real change to prove itself is one nobody dares run against a live fleet, and
a check nobody runs is worse than no check.

The allowed side is not tested here for the same reason.  A viewer being wrongly
allowed shows up as a failure below; an admin being wrongly refused shows up the
moment somebody uses the GUI.

    docker exec -i nginx-fleet-manager python < checks/authz_sweep.py
"""
import pathlib
import sys

from fastapi.testclient import TestClient

from app.models import AuthSource, User, UserRole

# Writes a viewer must never get through.  Path, method, and a body that would
# be valid if the role were allowed, so a refusal is about permission and not
# about the request being malformed.
WRITES = [
    ("POST", "/api/pools", {"name": "authz-check-should-not-exist"}),
    ("POST", "/api/hosts", {"name": "authz-check.subdomain.domain.tld"}),
    ("POST", "/api/apply", {"summary": "authz check"}),
    ("POST", "/api/rollback", {}),
    ("POST", "/api/certs", {"name": "authz-check.subdomain.domain.tld",
                            "domains": ["authz-check.subdomain.domain.tld"]}),
]

# Things only an admin may do, checked as an operator.
#
# Users and settings are page form posts, not API endpoints.  Naming the API
# paths they do not have gets a 404 that reads exactly like a refusal, so the
# check passes while testing nothing.  That happened on the first run of this
# file and is the reason a 404 is treated as broken below.
# The body has to be complete.  An incomplete one is rejected by request
# validation before the handler is entered, so it never reaches the permission
# check and a 422 comes back that looks like a refusal without being one.
ADMIN_ONLY = [
    ("POST", "/users/create",
     {"username": "authz-check-delete-me", "role": "viewer",
      "password": "Nx7#qL2v!wR9zT4m", "full_name": "", "email": ""}),
    ("POST", "/api/cluster/failover", {}),
    ("POST", "/settings", {"acme_staging": "true"}),
]

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


def client_as(role):
    """A signed in client for one role, with a user that never reaches the database."""
    from app.main import create_gui_app
    from app.web import routes_pages, routes_api, security

    ghost = User(id=-1, username=f"check-{role.value}", role=role,
                 source=AuthSource.LOCAL, enabled=True,
                 totp_enrolled=True, must_change_password=False)

    routes_pages.page_user = lambda request, db: ghost
    routes_pages.require_page_user = lambda request, db: ghost
    routes_api.get_user = lambda request, db: ghost
    security.client_ip = lambda request: "127.0.0.1"

    app = create_gui_app()
    return TestClient(app, raise_server_exceptions=False), ghost


def main():
    print("  a viewer cannot write")
    client, _ghost = client_as(UserRole.VIEWER)
    # Get a token the honest way, so a refusal is about the role and not the token.
    client.get("/")
    token = client.cookies.get("nfm_csrf") or ""

    for method, path, body in WRITES:
        response = client.request(method, path, json=body,
                                  headers={"X-CSRF-Token": token})
        refused = response.status_code in (401, 403, 404)
        check(f"viewer {method} {path} -> {response.status_code}", refused,
              f"a viewer got through: {response.text[:160]}")

    print()
    print("  an operator cannot do the admin only things")
    client, _ghost = client_as(UserRole.OPERATOR)
    client.get("/")
    token = client.cookies.get("nfm_csrf") or ""

    for method, path, body in ADMIN_ONLY:
        # Form posts, because that is what these routes are.
        response = client.request(method, path, data=body,
                                  headers={"X-CSRF-Token": token})
        if response.status_code == 404:
            check(f"operator {method} {path} -> 404", False,
                  "no such route, so this check proved nothing.  Fix the path.")
            continue
        if response.status_code == 422:
            check(f"operator {method} {path} -> 422", False,
                  "request validation refused this before the permission check ran, "
                  "so the check proved nothing.  Send a complete body.")
            continue
        refused = response.status_code in (401, 403)
        check(f"operator {method} {path} -> {response.status_code}", refused,
              f"an operator got through: {response.text[:160]}")

    # Belt and braces.  If the permission check above were broken, the refusal
    # test would fail AND an account would exist, so look, and clean up rather
    # than leave a login on a management box that nobody remembers making.
    from app.db import session_scope
    with session_scope() as session:
        stray = session.query(User).filter(
            User.username == "authz-check-delete-me"
        ).first()
        check("no account was created by the refused request", stray is None,
              "an account was created despite the refusal, and has been removed")
        if stray:
            session.delete(stray)
            session.commit()

    print()
    print("  a write with no csrf token is refused, even for an admin")
    client, _ghost = client_as(UserRole.ADMIN)
    client.get("/")

    for method, path, body in WRITES[:3]:
        response = client.request(method, path, json=body)  # no token on purpose
        refused = response.status_code in (400, 401, 403, 419)
        check(f"admin {method} {path} with no token -> {response.status_code}", refused,
              f"a write went through without a token: {response.text[:160]}")

    print()
    print("  a forged token is refused too")
    for method, path, body in WRITES[:2]:
        response = client.request(method, path, json=body,
                                  headers={"X-CSRF-Token": "not-the-real-token"})
        refused = response.status_code in (400, 401, 403, 419)
        check(f"admin {method} {path} with a wrong token -> {response.status_code}", refused,
              f"a forged token was accepted: {response.text[:160]}")

    print()
    # -----------------------------------------------------------------------
    # Nothing fetches a row by id outside the guard
    #
    # ObjectGuard is this project's answer to BOLA, and its whole value is
    # being the only way in.  Its docstring says so: "There is no path where a
    # route fetches a row itself and forgets the check, because routes do not
    # have a way to fetch rows by id at all."
    #
    # That was a claim rather than a fact, and by the time the security review
    # looked, five endpoints had gone around it.  Each took a host id from the
    # URL and fetched the row behind get_user(), which establishes that
    # somebody is signed in and nothing else, so the view permission was never
    # checked and the 404 rather than 403 behaviour was lost with it.  Nothing
    # noticed, because a route that skips the guard looks exactly like one that
    # uses it.
    #
    # So the claim is enforced here instead.  The allowed exceptions are named
    # and each one has a reason; anything else is a finding.
    print()
    print("  the object guard is the only way to a row by id")

    import re as _re

    # Legitimate, and why.
    ALLOWED = {
        # Administering an account is not an object lookup in the guard's
        # sense: these check can(actor, "manage_users") themselves, on the line
        # before, and the object they fetch is the account being administered.
        ("routes_account.py", "User"),
        # Not a route.  Building the renderer's input, looking a host up by a
        # foreign key it already read from another row.
        ("routes_api.py", "VirtualHost.row"),
        # Not a route either.  Looping over peer ids this function enumerated
        # itself a few lines earlier.
        ("routes_api.py", "Node.peer"),
    }

    LOOKUP = _re.compile(
        r"(?:db|session)\.get\(\s*(\w+)|\.filter\(\s*(\w+)\.id\s*==")

    stray = []
    for path in sorted(pathlib.Path("app/web").glob("*.py")):
        if path.name == "security.py":
            continue                      # where the guard itself lives
        for n, line in enumerate(path.read_text().split("\n"), 1):
            if "g.get(" in line or "g.session" in line:
                continue
            m = LOOKUP.search(line)
            if not m:
                continue
            model = m.group(1) or m.group(2)
            keys = {(path.name, model), (path.name, f"{model}.row"),
                    (path.name, f"{model}.peer")}
            if keys & ALLOWED:
                continue
            stray.append(f"{path.name}:{n} fetches {model} by id")

    check("no route fetches a row by id without going through ObjectGuard",
          not stray,
          "the guard checks the permission and answers 404 rather than 403 so "
          "ids cannot be probed.  A route that goes around it has neither: "
          + "; ".join(stray))

    failed = [name for name, ok, _ in results if not ok]
    print(f"  {len(results) - len(failed)} of {len(results)} were refused as they should be")
    # Every permission a route asks for has to be one that exists.
    #
    # A name that is not in ROLE_PERMISSIONS is in nobody's set, so `require`
    # refuses everybody, including an admin, and the message says their role
    # cannot do it.  That reads like a permissions decision rather than a typo,
    # which is what makes it worth a check: the import routes shipped asking for
    # "edit_hosts", the real name is "edit_sites", and an admin was told their
    # role was not allowed.
    import re
    from pathlib import Path

    from app.auth.service import ROLE_PERMISSIONS

    real = set().union(*ROLE_PERMISSIONS.values())
    # The modules' own files, because these suites are run through stdin and
    # __file__ is then "<stdin>".
    #
    # Every route module, not just routes_api.  This check was written after
    # the import routes shipped with a made up name, and it only ever looked at
    # the one file that bug happened to be in.  The firewall routes then did the
    # same thing, in the same file, and it was still only caught by somebody
    # pressing the button.  Routes live in five modules now and a permission is
    # equally invisible in any of them.
    import app.web.routes_api as routes_api

    folder = Path(routes_api.__file__).parent
    asked = set()
    scanned = []
    for module in sorted(folder.glob("routes_*.py")):
        asked |= set(re.findall(r'require\("([a-z_]+)"\)', module.read_text()))
        scanned.append(module.name)
    invented = sorted(asked - real)
    print(f"    scanned {len(scanned)} route modules: {', '.join(scanned)}")

    results.append(("every permission a route asks for exists", not invented,
                    f"these are asked for but defined nowhere, so they refuse "
                    f"everybody including an admin: {invented}"))
    print(f"    {'pass' if not invented else 'FAIL'}  "
          f"every permission a route asks for exists")
    if invented:
        print(f"          asked for but not defined anywhere: {invented}")

    print()
    print("  what this does not cover:")
    print("    - that an admin CAN do these, which the GUI shows the moment it cannot")
    print("    - sign in, lockout and TOTP, which need a throwaway account for real")
    print("    - object level checks across tenants, since there is one tenant")
    print()
    print("  RESULT:", "nothing got through" if not failed
          else f"{len(failed)} GOT THROUGH: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
