#!/usr/bin/env bash
#
# The way back in when single sign on is the only way in and it has stopped
# working.
#
# The GUI can be set so local passwords do not work at all.  That is the right
# setting once an identity provider is the system of record, and it has one
# obvious failure: the provider goes down, its certificate expires, or
# somebody deletes the application registration, and now nobody can sign in
# to the thing that manages your load balancers.
#
# This script does not depend on any of that.  It talks to the database
# directly through the running container and puts local passwords back on.
# It needs a root shell on the box, which is already more trust than any
# login page could check.
#
# It does not create accounts, reset passwords or touch the provider
# settings.  All it does is stop local passwords being refused.
#
#   ./auth-recovery.sh                 say what the current setting is
#   ./auth-recovery.sh --allow-local   local accounts or single sign on
#   ./auth-recovery.sh --local-only    local accounts only, provider ignored
#
# Run it on any node.  The setting travels with the config, so a fleet that is
# applying normally will carry it to the others; if it is not, run it on each.
#
# Set NFM_CONTAINER first if the manager's container runs under a different
# name.
#
# usage() prints lines 3-29 above as the help text; keep that range intact.
set -euo pipefail

CONTAINER="${NFM_CONTAINER:-nginx-fleet-manager}"

fail() { printf '\n  %s\n\n' "$*" >&2; exit 1; }

usage() {
    sed -n '3,29p' "$0" | sed 's/^#\s\?//'
    exit "${1:-0}"
}

MODE=""
while [ $# -gt 0 ]; do
    case "$1" in
        --allow-local) MODE="both" ;;
        --local-only)  MODE="local" ;;
        -h|--help)     usage 0 ;;
        *)             printf '\n  %s is not an option this script has.\n' "$1" >&2
                       usage 1 ;;
    esac
    shift
done

command -v docker >/dev/null 2>&1 || fail "docker is not on the path, so this
  cannot reach the manager.  If the container runs under a different name, set
  NFM_CONTAINER first."

if ! docker inspect -f '{{.State.Running}}' "$CONTAINER" 2>/dev/null | grep -q true; then
    fail "the $CONTAINER container is not running, so there is nothing to talk
  to.  Start it with 'docker compose up -d' from the install directory and run
  this again.  If the container is the thing that will not start, this is not
  your problem: look at 'docker compose logs'."
fi

printf '\n'

# Runs inside the container, where the database and encryption key are.
# Goes through settings_store rather than the table so the value is stored
# exactly as the application would store it.
if [ -z "$MODE" ]; then
    docker exec -i "$CONTAINER" python - <<'PY'
from app.core import settings_store
from app.db import session_scope
from app.models import AuthSource, User, UserRole

mode = settings_store.auth_mode()
words = {
    "local": "local accounts only.  Single sign on is not offered.",
    "both":  "local accounts or single sign on.  Both work.",
    "oidc":  "single sign on only.  Local passwords are refused.",
}
print(f"  Sign in is set to: {mode}")
print(f"  Which means: {words.get(mode, 'something unrecognised, which reads as local')}")

with session_scope() as s:
    locals_ = s.query(User).filter(
        User.role == UserRole.ADMIN, User.enabled.is_(True),
        User.source == AuthSource.LOCAL).all()
    names = sorted(u.username for u in locals_)

print()
if names:
    print(f"  Admins with a local password: {', '.join(names)}")
else:
    print("  No enabled admin has a local password.  Turning local sign in")
    print("  back on will not help on its own; somebody has to be able to use")
    print("  it.  Look at the users table before relying on this.")

if mode == "oidc":
    print()
    print("  To put local passwords back:  ./auth-recovery.sh --allow-local")
PY
    printf '\n'
    exit 0
fi

docker exec -i "$CONTAINER" python - "$MODE" <<'PY'
import sys

from app.core import audit, settings_store
from app.db import session_scope
from app.models import AuthSource, User, UserRole

wanted = sys.argv[1]
before = settings_store.auth_mode()

if before == wanted:
    print(f"  Sign in is already set to {wanted}.  Nothing to change.")
    raise SystemExit(0)

settings_store.set("auth_mode", wanted, "auth-recovery.sh")

# Recorded like any other change.  A recovery script that leaves no trace is
# one nobody can tell apart from an intruder switching the locks.
audit.record("settings.update", user="auth-recovery.sh",
             source_ip="console",
             object_type="settings",
             detail="auth mode changed from the recovery script",
             changes={"auth_mode": {"from": before, "to": wanted}})

print(f"  Sign in changed from {before} to {wanted}.")
print("  It applies to the next login.  Nothing needs restarting.")

with session_scope() as s:
    names = sorted(u.username for u in s.query(User).filter(
        User.role == UserRole.ADMIN, User.enabled.is_(True),
        User.source == AuthSource.LOCAL).all())

print()
if names:
    print(f"  Sign in with one of these and a password: {', '.join(names)}")
    print("  A second factor is still required, as it always was.")
else:
    print("  Careful: no enabled admin has a local password, so the login page")
    print("  will take a username and still refuse everybody.  You will need to")
    print("  fix an account before this helps.")
PY

printf '\n  Put it back from Settings once the provider is answering again.\n\n'
