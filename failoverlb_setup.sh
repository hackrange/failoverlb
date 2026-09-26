#!/usr/bin/env bash
# =============================================================================
# Failover LB - one shot setup
#
# Author: Tim Rice
#
# Takes a bare Ubuntu box with nginx already built on it and gets the manager
# running.  Pulls the code from git into /data/docker/failoverlb, sets up
# docker if it is missing, then hands off to install.sh.
#
#   sudo ./failoverlb_setup.sh
#   sudo ./failoverlb_setup.sh --join lb-01:7444 --token <token>
#
# Run it again any time to pull the latest code and rebuild.  Your .env and
# your database are left alone.
#
# If nginx is not on the box yet, build it first:
#
#   sudo ./nginx-installer.sh install
#
# That script ships in this folder next to this one.
# =============================================================================
{
set -euo pipefail

# The public repository on GitHub.  A wrong URL here does not 404: GitHub
# answers a missing or private repository with a request to log in, so the
# failure presents as the repository being private rather than as a bad URL.
REPO_URL="${NFM_REPO_URL:-https://github.com/hackrange/failoverlb.git}"
INSTALL_DIR="${NFM_INSTALL_DIR:-/data/docker/failoverlb}"
BRANCH="${NFM_BRANCH:-master}"

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]:-$0}")" 2>/dev/null && pwd || echo /nonexistent)"

GIT_USER="${NFM_GIT_USER:-}"
GIT_TOKEN="${NFM_GIT_TOKEN:-}"

PASSTHROUGH=()
SKIP_DOCKER=false

# The files that say "yes, this really is the project and not some other folder
# that happens to exist".
looks_like_project() {
    [[ -f "$1/docker-compose.yml" && -f "$1/install.sh" && -d "$1/app" ]]
}

# Build a clone URL with credentials in it, if we were given any.  Kept in a
# function so the token never ends up in a log line or in the process list of
# anything except git itself.
clone_url() {
    if [[ -n "$GIT_TOKEN" ]]; then
        local user="${GIT_USER:-oauth2}"
        echo "${REPO_URL/https:\/\//https://${user}:${GIT_TOKEN}@}"
    else
        echo "$REPO_URL"
    fi
}

c_reset=$'\033[0m'; c_red=$'\033[31m'; c_grn=$'\033[32m'
c_ylw=$'\033[33m'; c_cyn=$'\033[36m'
log()     { echo "${c_cyn}[setup]${c_reset} $*"; }
info()    { echo "        $*"; }
warn()    { echo "${c_ylw}[warn]${c_reset} $*"; }
success() { echo "${c_grn}$*${c_reset}"; }
fail()    { echo "${c_red}[error]${c_reset} $*" >&2; exit 1; }
header()  { echo; echo "${c_cyn}== $* ==${c_reset}"; }

usage() {
    cat <<USAGE
Failover LB setup

Usage: sudo ./failoverlb_setup.sh [options]

  -d, --dir <path>      Where to install.  Default ${INSTALL_DIR}.
  -b, --branch <name>   Branch to check out.  Default ${BRANCH}.
  -r, --repo <url>      Where to clone from.
      --git-user <name> Username for a private repo.
      --git-token <tok> Access token for a private repo.  NFM_GIT_TOKEN works too.
      --skip-docker     Do not touch docker, it is already sorted.
  -h, --help            This.

You do not need git access at all if you already have the code on the box.
Copy the folder over, cd into it, and run this script from inside it.  It will
use what is already there.

Anything else is handed straight to install.sh, so these work:

      --join <host:port>    Join an existing cluster.
      --token <token>       Join token from that cluster's Cluster page.
      --name <name>         Name for this node.
      --address <ip>        Address peers reach this node on.
      --priority <1-255>    Election priority, higher wins.
      --allowlist <cidrs>   Networks allowed to load the GUI.
      --acme-email <addr>   Where the CA sends expiry warnings.
  -y, --yes                 Do not ask about anything.

Run ./install.sh --help for the full list.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -d|--dir)     INSTALL_DIR="$2"; shift 2 ;;
        -b|--branch)  BRANCH="$2"; shift 2 ;;
        -r|--repo)    REPO_URL="$2"; shift 2 ;;
        --git-user)   GIT_USER="$2"; shift 2 ;;
        --git-token)  GIT_TOKEN="$2"; shift 2 ;;
        --skip-docker) SKIP_DOCKER=true; shift ;;
        -h|--help)    usage; exit 0 ;;
        *)            PASSTHROUGH+=("$1"); shift ;;
    esac
done

# ============================================================== checks
header "Checks"

[[ "$(id -u)" -eq 0 ]] || fail "Run this with sudo."

if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    log "${PRETTY_NAME:-unknown Linux}"
    if [[ "${ID:-}" != "ubuntu" && "${ID_LIKE:-}" != *debian* ]]; then
        warn "This was written for Ubuntu.  Other distros may work but are untested."
    fi
fi

if ! command -v git >/dev/null 2>&1; then
    log "installing git"
    apt-get update -qq && apt-get install -y -qq git
fi

# ============================================================== docker
if $SKIP_DOCKER; then
    header "Docker"
    log "skipping docker setup because you asked"
elif command -v docker >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; then
    header "Docker"
    log "docker and the compose plugin are already here"
    info "$(docker --version)"
else
    header "Docker"
    log "docker is missing or has no compose plugin, setting it up"

    # docker_setup.sh lives beside this script if we are running from a copy of
    # the project, otherwise we grab it from the repo we are about to pull.
    if [[ -f "$SELF_DIR/docker_setup.sh" ]]; then
        bash "$SELF_DIR/docker_setup.sh"
    else
        TMP_CLONE="$(mktemp -d)"
        GIT_TERMINAL_PROMPT=0 git clone --quiet --depth 1 --branch "$BRANCH" \
            "$(clone_url)" "$TMP_CLONE/repo" >/dev/null 2>&1 \
            || fail "Could not clone ${REPO_URL} to get docker_setup.sh.  Run
        docker_setup.sh yourself first, then rerun this with --skip-docker."
        bash "$TMP_CLONE/repo/docker_setup.sh"
        rm -rf "$TMP_CLONE"
    fi

    command -v docker >/dev/null 2>&1 || fail "Docker setup finished but docker still is not here."
fi

# ============================================================== the code
header "Code"

# Four ways to end up with the project in place, tried in this order.  The point
# is that you should not need git access just to install this, because plenty of
# boxes cannot reach the git server and plenty of people just copy a folder over.

if [[ -d "$INSTALL_DIR/.git" ]]; then
    # 1. Already a clone.  Update it.
    log "already installed at ${INSTALL_DIR}, pulling the latest"
    cd "$INSTALL_DIR"

    # Refuse to clobber local edits.  Somebody hand patching a live box and
    # losing it to a git pull is a bad afternoon.
    #
    # core.fileMode=false on purpose.  This script chmods the scripts executable
    # further down, and git counts a changed permission bit as a modified file.
    # So without this, running the script once was enough to make every later
    # run refuse, complaining about a change it had made itself.  We care about
    # content here, not permissions.
    if [[ -n "$(git -c core.fileMode=false status --porcelain --untracked-files=no)" ]]; then
        warn "There are local changes here:"
        git status --short --untracked-files=no | sed 's/^/        /'
        fail "Commit them, stash them, or move them out of the way, then run again."
    fi

    BEFORE="$(git rev-parse --short HEAD)"
    if git fetch --quiet origin "$BRANCH" 2>/dev/null; then
        git checkout --quiet "$BRANCH"
        git merge --quiet --ff-only "origin/$BRANCH" || \
            fail "Could not fast forward.  This clone has diverged from origin."
        AFTER="$(git rev-parse --short HEAD)"
        if [[ "$BEFORE" == "$AFTER" ]]; then
            log "already up to date at ${AFTER}"
        else
            log "updated ${BEFORE} to ${AFTER}"
        fi
    else
        warn "Could not reach the git server, carrying on with what is here (${BEFORE})."
    fi

elif looks_like_project "$INSTALL_DIR"; then
    # 2. The code is already there but is not a clone.  Somebody copied it in.
    log "found the project already at ${INSTALL_DIR}, using it as is"
    info "It is not a git clone, so this script will not try to update it."
    cd "$INSTALL_DIR"

elif looks_like_project "$SELF_DIR"; then
    # 3. We are being run from inside a copy of the project.  This is the case
    #    when somebody copied the folder onto the box, which is the easiest way
    #    to do this on a server with no route to the git server.
    if [[ "$SELF_DIR" == "$INSTALL_DIR" ]]; then
        log "running from ${INSTALL_DIR} already"
        cd "$INSTALL_DIR"
    else
        log "running from a copy of the project at ${SELF_DIR}"
        log "copying it to ${INSTALL_DIR}"
        mkdir -p "$INSTALL_DIR"
        # Leave .env, the database and any certs alone if this is a reinstall.
        tar -C "$SELF_DIR" --exclude=.env --exclude=.git -cf - . \
            | tar -C "$INSTALL_DIR" -xf -
        cd "$INSTALL_DIR"
    fi

else
    # 4. Nothing local, so clone it.
    if [[ -d "$INSTALL_DIR" ]] && [[ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
        fail "${INSTALL_DIR} already has things in it but is not the project.  Move it aside first."
    fi

    mkdir -p "$(dirname "$INSTALL_DIR")"
    log "cloning ${REPO_URL}"

    if ! GIT_TERMINAL_PROMPT=0 git clone --quiet --branch "$BRANCH" \
            "$(clone_url)" "$INSTALL_DIR" 2>/tmp/nfm-clone-err.$$; then
        CLONE_ERR="$(cat /tmp/nfm-clone-err.$$ 2>/dev/null || true)"
        rm -f /tmp/nfm-clone-err.$$
        echo "${CLONE_ERR}" | sed 's/^/        /'

        if echo "$CLONE_ERR" | grep -qi "could not read Username\|Authentication failed\|terminal prompts disabled"; then
            fail "That repository wants credentials.  Either pass --git-user and
        --git-token, or copy the project folder onto this box and run this
        script from inside it, which needs no git access at all."
        fi
        fail "Clone failed.  Check the URL and that this box can reach it."
    fi
    rm -f /tmp/nfm-clone-err.$$

    cd "$INSTALL_DIR"
    log "checked out $(git rev-parse --short HEAD)"
fi

looks_like_project "$INSTALL_DIR" || \
    fail "${INSTALL_DIR} does not look like the project.  Expected docker-compose.yml, install.sh and app/."

chmod 0750 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true

# ============================================================== hand off
header "Handing off to install.sh"

[[ -f "$INSTALL_DIR/install.sh" ]] || fail "No install.sh in the clone.  That should not happen."

echo
exec bash "$INSTALL_DIR/install.sh" "${PASSTHROUGH[@]}"

}
