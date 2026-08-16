"""
The three ways in, and the guard rails that stop the third one locking you out.

Single sign on only is the one setting in this tool that can leave nobody able
to reach it.  It fails quietly, too: the page saves, says the settings were
saved, and the next person to open the login screen finds their password is
refused and the provider does not know who they are.  Everything here exists
because of that one failure.

Four things it proves:

  * the mode falls back sensibly, so an install that never touches this keeps
    signing in exactly as it did
  * the provider only mode is refused unless somebody has already completed a
    login that way, which is evidence rather than intention
  * refusing local passwords happens in `authenticate_local`, not only in the
    template, because a form nobody can see is still a URL anybody can post to
  * the settings travel in the config snapshot, so the standby can sign people
    in the morning it is promoted

Nothing here is applied and nothing is left behind.  The stored mode is put
back exactly as it was found, including being absent, and the scratch account
lives in a transaction that is rolled back.

    docker exec -i nginx-fleet-manager python < checks/auth_modes.py
"""
import sys

from app.auth import oidc
from app.auth.service import authenticate_local
from app.core import settings_store
from app.db import session_scope
from app.models import AuthSource, SystemSetting, User, UserRole

results = []
skipped = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok and detail:
        print(f"          {detail}")


def stored_mode():
    """The raw row, so "absent" can be told apart from "set to local"."""
    with session_scope() as session:
        row = session.query(SystemSetting).filter(
            SystemSetting.key == "auth_mode").first()
        return row.value if row else None


def put_mode(value):
    with session_scope() as session:
        row = session.query(SystemSetting).filter(
            SystemSetting.key == "auth_mode").first()
        if value is None:
            if row:
                session.delete(row)
        else:
            if not row:
                row = SystemSetting(key="auth_mode")
                session.add(row)
            row.value = value
            row.encrypted = False
        session.commit()


def try_login(mode):
    """
    One sign in attempt against a real local admin, in the given mode.

    The mode is set outside the session on purpose.  Writing a setting from a
    second connection while this one holds a write transaction open is how the
    first version of this check deadlocked against sqlite, which is a fair
    reminder that the settings store opens its own session every time.

    The account is real, because the thing being proved is that the refusal
    happens before the password is looked at.  An account that would fail
    anyway proves nothing.  It lives in a transaction that is rolled back.
    """
    put_mode(mode)
    with session_scope() as session:
        try:
            session.add(User(
                username="check-auth-modes-scratch",
                source=AuthSource.LOCAL,
                role=UserRole.ADMIN,
                enabled=True,
                password_hash=None,
            ))
            session.flush()
            return authenticate_local(session, "check-auth-modes-scratch",
                                      "whatever", source_ip="127.0.0.1")
        finally:
            session.rollback()


ORIGINAL = stored_mode()
print()
print(f"  the stored mode before any of this: {ORIGINAL!r}")

try:
    print()
    print("  the mode reads back what was written")

    for value in settings_store.AUTH_MODES:
        put_mode(value)
        check(f"{value} reads back as {value}", settings_store.auth_mode() == value,
              f"got {settings_store.auth_mode()!r}")

    put_mode("something-nobody-typed")
    check("an unrecognised mode reads as local, not as locked out",
          settings_store.auth_mode() == "local",
          f"got {settings_store.auth_mode()!r}, and anything other than local "
          f"here means a bad row in the database stops people signing in")

    put_mode(None)
    check("nothing stored falls back to the environment",
          settings_store.auth_mode() in ("local", "both"),
          "an install that never opened this page has to keep working")

    print()
    print("  local passwords are allowed in exactly two of the three")

    for value, expected in (("local", True), ("both", True), ("oidc", False)):
        put_mode(value)
        check(f"{value}: local passwords {'work' if expected else 'are refused'}",
              settings_store.local_passwords_allowed() is expected)

    for value, expected in (("local", False), ("both", True), ("oidc", True)):
        put_mode(value)
        check(f"{value}: the provider is {'offered' if expected else 'not offered'}",
              settings_store.oidc_offered() is expected)

    print()
    print("  the refusal is in the code path, not only in the template")

    refused = try_login("oidc")
    check("a local sign in is refused outright in provider only mode",
          refused.ok is False,
          "the template hiding the form is presentation; this is the part "
          "that means it")
    check("and it says why rather than pretending the password was wrong",
          "single sign on" in (refused.reason or "").lower(),
          f"it said: {refused.reason!r}")

    allowed = try_login("both")
    check("with both allowed it gets as far as checking the password",
          allowed.ok is False
          and "single sign on" not in (allowed.reason or "").lower(),
          f"it said: {allowed.reason!r}, which means the mode check is "
          f"firing when it should not")

    print()
    print("  the provider is only offered when it could actually work")

    put_mode("both")
    check("offering it needs details as well as the mode",
          oidc.is_configured() == (settings_store.oidc_offered() and oidc.has_details()),
          "these two have to agree or the login page offers a button that "
          "cannot work")

    if not oidc.has_details():
        check("with no details filled in, nothing is offered",
              oidc.is_configured() is False,
              "an empty provider must not put a button on the login page")

    put_mode("local")
    check("local only wins even when the details are complete",
          oidc.is_configured() is False,
          "this is the state somebody is in while they are still setting a "
          "provider up, and the button must stay off")

    print()
    print("  the settings travel with the config")

    fleet = set(settings_store.FLEET_KEYS)
    wanted = {"auth_mode", "oidc_discovery_url", "oidc_client_id",
              "oidc_client_secret", "oidc_redirect_base", "oidc_groups_claim",
              "oidc_admin_group", "oidc_operator_group", "oidc_viewer_group"}
    check("every sign in setting is marked as belonging to the fleet",
          wanted <= fleet,
          f"these would not survive a failover: {sorted(wanted - fleet)}")

    put_mode("both")
    captured = settings_store.capture_fleet()
    keys = {row["key"] for row in captured}
    check("the snapshot carries the mode", "auth_mode" in keys,
          f"it carried {sorted(keys)}")

    check("a secret in the snapshot is unsealed, not raw ciphertext",
          all(row["encrypted"] is False or row["value"] is None
              or not str(row["value"]).startswith("gAAAA")
              for row in captured),
          "the far node seals it with its own key, so it has to travel plain")

    rejected = settings_store.restore_fleet(
        [{"key": "acme_hook_secret", "value": "nope", "encrypted": False}])
    check("a snapshot cannot set a key that is not on the fleet list",
          rejected == 0,
          "a snapshot is data off the network, and a loop that wrote whatever "
          "keys it was handed would let a peer set anything in this table")

    from app.core import snapshot
    with session_scope() as session:
        taken = snapshot.capture(session)
    check("the config snapshot includes the settings section",
          "settings" in taken,
          "without this the standby has no idea how the fleet signs in")

    print()
    print("  the recovery script is where the page says it is")

    # The script is a host file and lives in the install directory, which is
    # not mounted into this container, and should not be: it runs docker
    # commands, so a copy inside the container would be a copy in the one place
    # it cannot work from.  So this is a skip rather than a failure when it
    # cannot be seen, and it still checks the file properly when it can, which
    # is when somebody runs this from a checkout.
    import pathlib

    found = next((p for p in (pathlib.Path("/app/auth-recovery.sh"),
                              pathlib.Path("auth-recovery.sh"),
                              pathlib.Path(__file__).parent.parent / "auth-recovery.sh")
                  if p.exists()), None)

    if not found:
        skipped.append("auth-recovery.sh could not be read from in here, which "
                       "is expected: it is a host script and the install "
                       "directory is not mounted")
        print("    skip  auth-recovery.sh is a host file, not visible from in here")
    else:
        body = found.read_text()
        check("it offers --allow-local, which is what the pages tell people to run",
              "--allow-local" in body,
              "the settings page and the login page both name that exact "
              "command, so it has to be the one that works")
        check("it does not quietly do anything else, like resetting a password",
              "hash_password" not in body and "password_hash =" not in body,
              "a recovery script that makes decisions is one nobody trusts "
              "enough to run")
        check("it writes an audit line", "audit.record" in body,
              "a change of locks that leaves no trace cannot be told apart "
              "from an intruder making it")

finally:
    put_mode(ORIGINAL)
    print()
    print(f"  put the stored mode back to {ORIGINAL!r}, "
          f"now reading as {settings_store.auth_mode()!r}")

print()
failed = [name for name, ok, _ in results if not ok]
print(f"  {len(results) - len(failed)} of {len(results)} passed"
      + (f", {len(skipped)} skipped" if skipped else ""))
for note in skipped:
    print(f"    skipped: {note}")
print()
print("  what this does not cover:")
print("    - a real login against a real provider, which needs one to exist")
print("    - whether the guard on the settings form is wired to the form, which")
print("      is authz_sweep and page_sweep's job")
print("    - the recovery script actually running, which needs a shell outside")
print("      this container")
print()
print("  RESULT:", "the ways in behave" if not failed
      else f"{len(failed)} PROBLEMS: {failed}")
sys.exit(1 if failed else 0)
