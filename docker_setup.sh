#!/usr/bin/env bash
# =============================================================================
# Docker setup for Ubuntu 22.04 and newer.
#
# Author: Tim Rice
#
# Installs Docker CE from Docker's apt repository. Ubuntu's docker.io
# package is usually well behind and lacks the compose plugin.
#
#   sudo bash docker_setup.sh
#
# An existing install is left alone unless you pass --force, so running
# containers are not restarted by accident.
#
# Wrapped in { } so "curl | bash" reads the whole file before running it.
# =============================================================================
{
set -euo pipefail

# --------------------------------------------------------------------- config
COMPOSE_MIN_VERSION="2"
DOCKER_USER="${SUDO_USER:-}"
LOG_FILE="/tmp/docker-setup-$(date +%Y%m%d-%H%M%S).log"

FORCE=false
SKIP_DAEMON_CONFIG=false
ADD_USER=true

# ---------------------------------------------------------------- output bits
c_reset=$'\033[0m'; c_red=$'\033[31m'; c_grn=$'\033[32m'
c_ylw=$'\033[33m'; c_cyn=$'\033[36m'
log()     { echo "${c_cyn}[docker]${c_reset} $*" | tee -a "$LOG_FILE"; }
info()    { echo "         $*" | tee -a "$LOG_FILE"; }
warn()    { echo "${c_ylw}[warn]${c_reset} $*" | tee -a "$LOG_FILE"; }
success() { echo "${c_grn}$*${c_reset}" | tee -a "$LOG_FILE"; }
fail()    { echo "${c_red}[error]${c_reset} $*" | tee -a "$LOG_FILE"; exit 1; }
header()  { echo | tee -a "$LOG_FILE"; echo "${c_cyn}== $* ==${c_reset}" | tee -a "$LOG_FILE"; }

usage() {
    cat <<USAGE
Docker setup for Ubuntu 22.04 and newer

Usage: sudo bash docker_setup.sh [options]

      --force              Reinstall even if Docker is already here
      --no-daemon-config   Do not write /etc/docker/daemon.json
      --no-user            Do not add your user to the docker group
  -h, --help               This message

What it does:

  1. Checks you are on a version of Ubuntu this works on
  2. Removes the old unofficial packages if they are in the way
  3. Adds Docker's apt key and repository properly
  4. Installs the engine, the CLI, containerd, buildx and compose
  5. Writes a daemon.json that rotates logs, so containers cannot fill the disk
  6. Puts your user in the docker group so you can drop the sudo
  7. Runs hello-world to prove it works

Being careful about an existing install:

  If Docker is already installed this stops and tells you, rather than
  reinstalling.  On a box with containers running, a reinstall can restart the
  daemon and take everything down with it.  Use --force only when you know
  what is running.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --force)            FORCE=true; shift ;;
        --no-daemon-config) SKIP_DAEMON_CONFIG=true; shift ;;
        --no-user)          ADD_USER=false; shift ;;
        -h|--help)          usage; exit 0 ;;
        *)                  fail "Do not know the option $1.  Try --help." ;;
    esac
done

# ------------------------------------------------------------------ pre flight
header "Checks"

[[ "$(id -u)" -eq 0 ]] || fail "Run this with sudo."

# Tested on Ubuntu only. Debian likely works but uses a different repo path.
if [[ ! -f /etc/os-release ]]; then
    fail "Cannot tell what distribution this is.  No /etc/os-release."
fi

# shellcheck disable=SC1091
. /etc/os-release

if [[ "${ID:-}" != "ubuntu" ]]; then
    warn "This is written for Ubuntu.  Found '${ID:-unknown}'."
    warn "Carrying on, but you are off the tested path."
fi

UBUNTU_VERSION="${VERSION_ID:-0}"
UBUNTU_MAJOR="${UBUNTU_VERSION%%.*}"

if [[ "${ID:-}" == "ubuntu" ]] && (( UBUNTU_MAJOR < 22 )); then
    fail "This needs Ubuntu 22.04 or newer.  Found ${UBUNTU_VERSION}."
fi

log "Ubuntu ${UBUNTU_VERSION} (${VERSION_CODENAME:-unknown})"

ARCH="$(dpkg --print-architecture)"
log "Architecture: ${ARCH}"

# ------------------------------------------------- is Docker already here
if command -v docker >/dev/null 2>&1 && ! $FORCE; then
    header "Docker is already installed"

    docker --version | tee -a "$LOG_FILE"
    if docker compose version >/dev/null 2>&1; then
        docker compose version | tee -a "$LOG_FILE"
    else
        warn "The compose plugin is missing.  Installing just that."
        apt-get update -qq
        apt-get install -y docker-compose-plugin
        success "Compose plugin installed."
    fi

    RUNNING="$(docker ps -q 2>/dev/null | wc -l)"
    if (( RUNNING > 0 )); then
        info "There are ${RUNNING} containers running right now."
        info "Not touching anything.  Reinstalling would restart the daemon and"
        info "take those down with it."
    fi

    echo
    success "Nothing to do.  Use --force if you really want to reinstall."
    exit 0
fi

# ------------------------------------------------ clear out the old packages
header "Clearing out old packages"

# Ubuntu's docker packages install to the same paths as Docker's and
# conflict. apt-get remove keeps config and volumes.
OLD_PACKAGES=(docker.io docker-doc docker-compose docker-compose-v2 podman-docker containerd runc)
REMOVED=false
for pkg in "${OLD_PACKAGES[@]}"; do
    if dpkg -l "$pkg" 2>/dev/null | grep -q '^ii'; then
        log "Removing ${pkg}"
        apt-get remove -y "$pkg" >>"$LOG_FILE" 2>&1 || true
        REMOVED=true
    fi
done
$REMOVED || info "None of the old packages were here."

# --------------------------------------------------------------- dependencies
header "Dependencies"

export DEBIAN_FRONTEND=noninteractive
apt-get update -qq
apt-get install -y --no-install-recommends \
    ca-certificates \
    curl \
    gnupg \
    >>"$LOG_FILE" 2>&1
success "Dependencies installed."

# ----------------------------------------------------------- apt key and repo
header "Docker apt repository"

# Use /etc/apt/keyrings, not apt-key, which trusts a key for every repo.
install -m 0755 -d /etc/apt/keyrings

if [[ ! -f /etc/apt/keyrings/docker.asc ]]; then
    log "Fetching Docker's signing key"
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        -o /etc/apt/keyrings/docker.asc \
        || fail "Could not download the Docker signing key.  Check the network."
    chmod a+r /etc/apt/keyrings/docker.asc
else
    info "The signing key is already here."
fi

# signed-by pins the repo to this one key.
CODENAME="${VERSION_CODENAME:-jammy}"

# Docker may not have packages for a brand new Ubuntu release yet. Fall
# back to the newest release they do have; those packages work fine.
if ! curl -fsSI "https://download.docker.com/linux/ubuntu/dists/${CODENAME}/Release" >/dev/null 2>&1; then
    warn "Docker has no repository for '${CODENAME}' yet."
    for fallback in noble jammy; do
        if curl -fsSI "https://download.docker.com/linux/ubuntu/dists/${fallback}/Release" >/dev/null 2>&1; then
            warn "Falling back to the '${fallback}' packages, which will work fine."
            CODENAME="$fallback"
            break
        fi
    done
fi

echo "deb [arch=${ARCH} signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/ubuntu ${CODENAME} stable" \
    > /etc/apt/sources.list.d/docker.list

log "Repository set to ${CODENAME} stable"
apt-get update -qq

# -------------------------------------------------------------------- install
header "Installing Docker"

apt-get install -y \
    docker-ce \
    docker-ce-cli \
    containerd.io \
    docker-buildx-plugin \
    docker-compose-plugin \
    >>"$LOG_FILE" 2>&1 \
    || fail "The install failed.  Look at ${LOG_FILE}."

success "Docker installed."

# --------------------------------------------------------------- daemon.json
if ! $SKIP_DAEMON_CONFIG; then
    header "Daemon settings"

    if [[ -f /etc/docker/daemon.json ]]; then
        warn "/etc/docker/daemon.json already exists, leaving it alone."
        info "Check that it has log rotation in it, or a chatty container can"
        info "fill the disk.  Without a limit, json-file logs grow forever."
    else
        mkdir -p /etc/docker

        # The default json-file driver has no size limit, so one chatty
        # container can fill the disk. Rotation is the important part.
        cat > /etc/docker/daemon.json <<'DAEMON'
{
  "log-driver": "json-file",
  "log-opts": {
    "max-size": "20m",
    "max-file": "5"
  },
  "live-restore": true,
  "userland-proxy": false,
  "default-address-pools": [
    { "base": "172.20.0.0/16", "size": 24 }
  ]
}
DAEMON
        log "Wrote /etc/docker/daemon.json"
        info "  log rotation at 20m x 5 files per container"
        info "  live-restore keeps containers up across a daemon restart"
        info "  address pool set so docker networks do not collide with your LAN"
    fi
fi

# ------------------------------------------------------------------- start it
header "Starting Docker"

systemctl enable docker >>"$LOG_FILE" 2>&1
systemctl restart docker

sleep 2
systemctl is-active --quiet docker || fail "Docker will not start.  Try: journalctl -u docker -n 50"
success "Docker is running."

# ------------------------------------------------------------ the docker group
if $ADD_USER && [[ -n "$DOCKER_USER" ]] && [[ "$DOCKER_USER" != "root" ]]; then
    header "User access"

    if id -nG "$DOCKER_USER" | grep -qw docker; then
        info "${DOCKER_USER} is already in the docker group."
    else
        usermod -aG docker "$DOCKER_USER"
        success "Added ${DOCKER_USER} to the docker group."
        warn "Log out and back in for that to take effect."
        info "Or run: newgrp docker"
    fi

    # The docker group is root-equivalent: members can mount the host
    # filesystem into a container. Say so.
    echo
    warn "Being in the docker group is effectively root on this box."
    info "Anybody in it can mount / into a container and take over.  That is"
    info "how docker works, not a bug, but only add people you would give root."
fi

# ------------------------------------------------------------------ verify it
header "Checking it works"

docker --version | tee -a "$LOG_FILE"
docker compose version | tee -a "$LOG_FILE"

log "Running hello-world"
if docker run --rm hello-world >>"$LOG_FILE" 2>&1; then
    success "hello-world ran fine."
    docker rmi hello-world >/dev/null 2>&1 || true
else
    warn "hello-world did not run.  Look at ${LOG_FILE}."
    warn "Usually this is DNS or a proxy in the way of the registry."
fi

echo
success "Docker is set up."
echo
info "Log:  ${LOG_FILE}"
echo
info "Next, to install Failover LB:"
info "  sudo bash failoverlb_setup.sh"
echo

}
