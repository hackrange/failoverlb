"""
Break glass account recovery.

For the one case the GUI cannot help with: the only admin has lost their phone
and has no recovery codes left.  There is nobody who can reset it for them from
inside the tool, because the tool is what they cannot get into.

    docker exec nginx-fleet-manager python -m app.reset_admin --list
    docker exec nginx-fleet-manager python -m app.reset_admin admin --reset-totp
    docker exec nginx-fleet-manager python -m app.reset_admin admin --new-password

Getting to this needs shell on the box and the ability to exec into the
container, which on any sane setup means root.  Somebody with that could read
the database anyway, so this hands out nothing they could not already take.  It
just saves them an afternoon with a sqlite prompt.

Every use is written to the audit log as coming from the console, because an
account recovery done outside the GUI is exactly the sort of thing that should
be obvious when somebody reads the log later.
"""

import argparse
import json
import secrets
import sys

from app.auth.service import hash_password, password_problems, revoke_all_for_user
from app.core import audit
from app.db import init_db, session_scope
from app.models import User, UserRole


def list_users():
    with session_scope() as session:
        users = session.query(User).order_by(User.username).all()
        if not users:
            print("there are no accounts at all")
            return

        print(f"{'username':<24} {'role':<10} {'source':<8} {'enabled':<8} {'authenticator':<14} locked")
        print("-" * 82)
        for u in users:
            try:
                left = len(json.loads(u.recovery_codes or "[]"))
            except json.JSONDecodeError:
                left = 0
            totp = f"yes ({left} codes)" if u.totp_enrolled else "not set up"
            print(f"{u.username:<24} {u.role.value:<10} {u.source.value:<8} "
                  f"{str(u.enabled):<8} {totp:<14} {u.is_locked}")


def reset_totp(username: str):
    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"there is no account called {username}")
            return 1

        user.totp_enrolled = False
        user.totp_secret_encrypted = None
        user.recovery_codes = "[]"
        user.failed_attempts = 0
        user.locked_until = None
        revoked = revoke_all_for_user(session, user.id, "authenticator reset from the console")
        session.commit()

    audit.record("user.totp_reset", user="console", object_type="user",
                 object_name=username,
                 detail="authenticator cleared from the console, break glass")

    print(f"cleared the authenticator on {username}")
    print(f"signed out {revoked} session(s)")
    print()
    print("Next time they sign in with their password they get the setup page")
    print("and scan a fresh code.")
    return 0


def new_password(username: str, password: str = None):
    if not password:
        # A generated one beats asking, because a person picking a password at a
        # console under pressure picks a bad one, and this is only meant to last
        # until they sign in and change it.
        password = secrets.token_urlsafe(18)
        generated = True
    else:
        generated = False
        problems = password_problems(password)
        if problems:
            print("that password will not do: " + "; ".join(problems))
            return 1

    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"there is no account called {username}")
            return 1

        user.password_hash = hash_password(password)
        user.must_change_password = True
        user.failed_attempts = 0
        user.locked_until = None
        revoked = revoke_all_for_user(session, user.id, "password reset from the console")
        session.commit()

    audit.record("user.password_reset", user="console", object_type="user",
                 object_name=username, detail="password reset from the console, break glass")

    print(f"set a new password on {username}")
    if generated:
        print(f"  password: {password}")
    print(f"signed out {revoked} session(s)")
    print()
    print("They have to change it at their next sign in.")
    return 0


def make_admin(username: str):
    """
    Last resort: there is no working admin at all any more.

    Happens when the only admin account gets disabled or deleted by mistake.
    """
    with session_scope() as session:
        user = session.query(User).filter(User.username == username).first()
        if not user:
            print(f"there is no account called {username}")
            return 1

        user.role = UserRole.ADMIN
        user.enabled = True
        user.failed_attempts = 0
        user.locked_until = None
        session.commit()

    audit.record("user.role_change", user="console", object_type="user",
                 object_name=username, detail="made an admin from the console, break glass")
    print(f"{username} is now an enabled admin")
    return 0


def main():
    parser = argparse.ArgumentParser(
        prog="python -m app.reset_admin",
        description="Get back into the manager when the GUI cannot help.",
    )
    parser.add_argument("username", nargs="?", help="the account to work on")
    parser.add_argument("--list", action="store_true", help="show every account")
    parser.add_argument("--reset-totp", action="store_true",
                        help="clear their authenticator so they set up a new one")
    parser.add_argument("--new-password", action="store_true",
                        help="set a new password, generated unless you pass --password")
    parser.add_argument("--password", help="the password to set, rather than a generated one")
    parser.add_argument("--make-admin", action="store_true",
                        help="give the account the admin role and enable it")

    args = parser.parse_args()
    init_db()

    if args.list or not args.username:
        list_users()
        if not args.username:
            print()
            print("Pick an account and one of --reset-totp, --new-password, --make-admin")
        return 0

    did_something = False
    if args.reset_totp:
        reset_totp(args.username)
        did_something = True
    if args.new_password or args.password:
        new_password(args.username, args.password)
        did_something = True
    if args.make_admin:
        make_admin(args.username)
        did_something = True

    if not did_something:
        print("nothing to do.  Add --reset-totp, --new-password or --make-admin")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
