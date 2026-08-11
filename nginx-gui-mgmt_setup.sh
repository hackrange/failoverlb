#!/usr/bin/env bash
# =============================================================================
# NGINX Management - one shot setup
#
# Author: Tim Rice
#
# Takes a bare Ubuntu box with nginx already built on it and gets the manager
# running.  Pulls the code from git into /data/docker/nginx-gui-mgmt, sets up
# docker if it is missing, then hands off to install.sh.
#
#   sudo ./nginx-gui-mgmt_setup.sh
#   sudo ./nginx-gui-mgmt_setup.sh --join lb-01:7444 --token <token>
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

REPO_URL="${NFM_REPO_URL:-https://git.hackrange.com/trice/nginx-gui-mgmt.git}"
INSTALL_DIR="${NFM_INSTALL_DIR:-/data/docker/nginx-gui-mgmt}"
BRANCH="${NFM_BRANCH:-master}"

PASSTHROUGH=()
SKIP_DOCKER=false

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
NGINX Management setup

Usage: sudo ./nginx-gui-mgmt_setup.sh [options]

  -d, --dir <path>      Where to install.  Default ${INSTALL_DIR}.
  -b, --branch <name>   Branch to check out.  Default ${BRANCH}.
  -r, --repo <url>      Where to clone from.
      --skip-docker     Do not touch docker, it is already sorted.
  -h, --help            This.

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

    # docker_setup.sh lives beside this script if we are running from a clone,
    # otherwise we grab it from the repo we are about to pull anyway.
    SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
    if [[ -f "$SELF_DIR/docker_setup.sh" ]]; then
        bash "$SELF_DIR/docker_setup.sh"
    else
        TMP_CLONE="$(mktemp -d)"
        git clone --depth 1 --branch "$BRANCH" "$REPO_URL" "$TMP_CLONE/repo" >/dev/null 2>&1 \
            || fail "Could not clone ${REPO_URL} to get docker_setup.sh."
        bash "$TMP_CLONE/repo/docker_setup.sh"
        rm -rf "$TMP_CLONE"
    fi

    command -v docker >/dev/null 2>&1 || fail "Docker setup finished but docker still is not here."
fi

# ============================================================== the code
header "Code"

if [[ -d "$INSTALL_DIR/.git" ]]; then
    log "already installed at ${INSTALL_DIR}, pulling the latest"

    cd "$INSTALL_DIR"

    # Refuse to clobber local edits.  Somebody hand patching a live box and
    # losing it to a git pull is a bad afternoon.
    if [[ -n "$(git status --porcelain --untracked-files=no)" ]]; then
        warn "There are local changes here:"
        git status --short --untracked-files=no | sed 's/^/        /'
        fail "Commit them, stash them, or move them out of the way, then run again."
    fi

    BEFORE="$(git rev-parse --short HEAD)"
    git fetch --quiet origin "$BRANCH"
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
    if [[ -d "$INSTALL_DIR" ]] && [[ -n "$(ls -A "$INSTALL_DIR" 2>/dev/null)" ]]; then
        fail "${INSTALL_DIR} already has things in it but is not a git clone.  Move it aside first."
    fi

    mkdir -p "$(dirname "$INSTALL_DIR")"
    log "cloning into ${INSTALL_DIR}"
    git clone --branch "$BRANCH" "$REPO_URL" "$INSTALL_DIR" \
        || fail "Clone failed.  Check the URL and that this box can reach it."
    cd "$INSTALL_DIR"
    log "checked out $(git rev-parse --short HEAD)"
fi

chmod 0750 "$INSTALL_DIR"
chmod +x "$INSTALL_DIR"/*.sh 2>/dev/null || true

# ============================================================== hand off
header "Handing off to install.sh"

[[ -f "$INSTALL_DIR/install.sh" ]] || fail "No install.sh in the clone.  That should not happen."

echo
exec bash "$INSTALL_DIR/install.sh" "${PASSTHROUGH[@]}"

}
