"""
The Users page: change a role, delete an account, and refuse both on your own.

Three of these were broken at once and none of them said so.  The role
dropdown had its handler written on the tag, which the page's own Content
Security Policy refuses to run, so it moved and nothing was sent.  The delete
route existed with every guard on it and no page reached it.  And the role
route, unlike the delete route, would happily let an admin demote themselves
out of the page they were standing on.

Everything here happens to accounts this check makes and removes.  No real
account is read, written or signed in as, and the rows go in a finally so a
failure half way through does not leave a login on a management box.

    docker exec -i nginx-fleet-manager python < checks/users_page.py
"""
import re
import sys

from fastapi.testclient import TestClient

from app.auth.service import hash_password
from app.db import session_scope
from app.models import AuthSource, User, UserRole

PREFIX = "check-users-"
BOSS = PREFIX + "boss"       # the admin the check acts as
MATE = PREFIX + "mate"       # somebody else, whose role gets changed
SPARE = PREFIX + "spare"     # somebody else, who gets deleted

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:300]}")


def make_users():
    with session_scope() as session:
        for username, role in ((BOSS, UserRole.ADMIN),
                               (MATE, UserRole.OPERATOR),
                               (SPARE, UserRole.VIEWER)):
            session.add(User(username=username, role=role,
                             source=AuthSource.LOCAL, enabled=True,
                             totp_enrolled=True, must_change_password=False,
                             password_hash=hash_password("not-a-real-password-1A!"),
                             full_name="made by checks/users_page.py"))
        session.commit()
        return {u.username: u.id for u in session.query(User)
                .filter(User.username.like(PREFIX + "%")).all()}


def remove_users():
    with session_scope() as session:
        for user in session.query(User).filter(
                User.username.like(PREFIX + "%")).all():
            session.delete(user)
        session.commit()


def role_of(username):
    with session_scope() as session:
        row = session.query(User).filter(User.username == username).first()
        return row.role.value if row else None


def exists(username):
    with session_scope() as session:
        return session.query(User).filter(User.username == username).count() == 1


def main():
    from app.main import create_gui_app
    from app.web import routes_account, security

    # The tables first.  On a fleet that has been running for months they are
    # there anyway; on a fresh database, which is where this gets run before
    # anybody trusts it, they are not, and the first insert says "no such
    # table: users".
    from app.db import init_db
    init_db()

    app = create_gui_app()

    ids = make_users()
    try:

        # Signed in as our own admin, looked up fresh on every request so the
        # row the route compares against is the row in that route's session.
        # A detached copy would never match, and the self guards being checked
        # here are exactly an id comparison.
        def as_boss(request, db):
            return db.query(User).filter(User.username == BOSS).first()

        routes_account.require_page_user = as_boss

        # The management allow list turns away anything that is not on it, and
        # the test client's address is the literal string "testclient".
        security.client_ip = lambda request: "127.0.0.1"

        client = TestClient(app, raise_server_exceptions=False)
        token = "check-csrf-token"
        client.cookies.set(security.CSRF_COOKIE, token)

        def post(path, **fields):
            return client.post(path, data={"csrf_token": token, **fields},
                               follow_redirects=False)

        # ---- what the page offers ---------------------------------------
        page = client.get("/users")
        check("GET /users -> 200", page.status_code == 200,
              f"status {page.status_code}")
        html = page.text

        check("no inline event handler anywhere on the page",
              not re.search(r"\son[a-z]+=\"", html),
              "the page's own CSP refuses to run these, so a control using one "
              "does nothing at all")

        check("somebody else can be deleted",
              f"/users/{ids[SPARE]}/delete" in html)
        check("your own row has no delete",
              f"/users/{ids[BOSS]}/delete" not in html)
        check("somebody else's role can be changed",
              f"/users/{ids[MATE]}/role" in html)
        check("your own role is not a dropdown",
              f"/users/{ids[BOSS]}/role" not in html)

        # ---- changing a role --------------------------------------------
        response = post(f"/users/{ids[MATE]}/role", role="admin")
        check("changing somebody else's role works",
              response.status_code == 303 and role_of(MATE) == "admin",
              f"status {response.status_code}, role now {role_of(MATE)}")

        response = post(f"/users/{ids[BOSS]}/role", role="viewer")
        check("changing your own role is refused",
              role_of(BOSS) == "admin",
              f"role now {role_of(BOSS)}")
        check("and it says why",
              "your%20own%20role" in response.headers.get("location", ""),
              response.headers.get("location", ""))

        # ---- deleting ----------------------------------------------------
        response = post(f"/users/{ids[BOSS]}/delete")
        check("deleting your own account is refused", exists(BOSS),
              "the account the check is signed in as was deleted")

        response = post(f"/users/{ids[SPARE]}/delete")
        check("deleting somebody else works",
              response.status_code == 303 and not exists(SPARE),
              f"status {response.status_code}")

        # ---- another admin, which is the point of the page ----------------
        # MATE is an admin by now, and an admin has to be able to change
        # another admin's role.  Only your own is off limits.  There is always
        # at least one other admin here, the one this check is signed in as,
        # so the last admin guard is not in the way of this.
        response = post(f"/users/{ids[MATE]}/role", role="viewer")
        check("another admin's role can be changed too",
              response.status_code == 303 and role_of(MATE) == "viewer",
              f"status {response.status_code}, role now {role_of(MATE)}")
    finally:
        remove_users()
        print("    (accounts made by this check removed)")

    print()
    failed = [name for name, ok, _ in results if not ok]
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed")
    return 1 if failed else 0


sys.exit(main())
