#!/usr/bin/env bash
# =============================================================================
# NGINX Management - per node installer
#
# Author: Tim Rice
#
# Run this on every nginx box you want managed.  It sets up the host side, then
# builds and starts the container.
#
#   sudo ./install.sh                          # first node, starts a cluster
#   sudo ./install.sh --join lb-01:7444 --token <token>   # every node after
#
# What it does, in order:
#
#   1. Checks nginx is here and was built from source
#   2. Makes the nginxmgr group, which is how the container reaches the agent
#   3. Installs the host agent and its systemd unit
#   4. Writes .env with a freshly generated secret
#   5. Builds and starts the container
#   6. Joins an existing cluster, if you gave it a token
#   7. Turns off certbot.timer, and explains why
#
# It is safe to run again.  Anything already done is left alone, and your .env
# is never overwritten without asking.
#
# The whole thing is wrapped in a { } block so "curl | bash" reads the entire
# file before running any of it.
# =============================================================================
{
set -euo pipefail

# --------------------------------------------------------------------- config
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
AGENT_DIR="/opt/nginx-fleet-manager"
AGENT_UNIT="/etc/systemd/system/nginx-mgr-agent.service"
SOCKET_GROUP="nginxmgr"
SOCKET_GID="10001"
INSTALLER_PATH="/opt/nginx-installer.sh"

NODE_NAME=""
NODE_ADDRESS=""
PRIORITY="100"
JOIN_TARGET=""
JOIN_TOKEN=""
ADMIN_ALLOWLIST=""
ACME_EMAIL=""
ASSUME_YES=false
KEEP_CERTBOT_TIMER=false

# ---------------------------------------------------------------- output bits
c_reset=$'\033[0m'; c_red=$'\033[31m'; c_grn=$'\033[32m'
c_ylw=$'\033[33m'; c_cyn=$'\033[36m'
log()     { echo "${c_cyn}[nfm]${c_reset} $*"; }
info()    { echo "      $*"; }
warn()    { echo "${c_ylw}[warn]${c_reset} $*"; }
success() { echo "${c_grn}$*${c_reset}"; }
fail()    { echo "${c_red}[error]${c_reset} $*" >&2; exit 1; }
header()  { echo; echo "${c_cyn}== $* ==${c_reset}"; }

# Things that went wrong but are not worth stopping over.
#
# Most of what this script does is independent.  The agent not starting has
# nothing to do with whether the container will run, and the manager is built to
# come up without it and say so.  So a problem gets written down and repeated at
# the end with the fix next to it, rather than killing the install halfway and
# leaving somebody with a half configured box and no GUI.
#
# Only a handful of things are actually fatal: not being root, not being in the
# project folder, no docker, and the image not building.  Everything else is a
# note.
PROBLEMS=()
problem() {
    # problem "<short title>" "<what to do about it>"
    PROBLEMS+=("$1"$'\n'"$2")
    warn "$1"
    while IFS= read -r line; do [[ -n "$line" ]] && info "$line"; done <<< "$2"
}

usage() {
    cat <<USAGE
NGINX Management installer

Usage: sudo ./install.sh [options]

  -n, --name <name>         What to call this node.  Defaults to the hostname.
  -a, --address <ip>        Address other nodes reach this one on.  Guessed if
                            you leave it out, but check the guess.
  -p, --priority <1-255>    Who wins the election.  Higher takes it.
      --join <host:port>    Join an existing cluster through this node.
      --token <token>       The join token, made on that node's Cluster page.
      --allowlist <cidrs>   Networks allowed to load the GUI, comma separated.
      --acme-email <addr>   Where the CA sends expiry warnings.  Optional.
      --keep-certbot-timer  Leave certbot.timer alone.  Read the warning first.
  -y, --yes                 Do not ask about anything.
  -h, --help                This.

The first node needs no --join.  It starts a cluster and becomes its CA.
Every node after that needs --join and --token together.
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        -n|--name)      NODE_NAME="$2"; shift 2 ;;
        -a|--address)   NODE_ADDRESS="$2"; shift 2 ;;
        -p|--priority)  PRIORITY="$2"; shift 2 ;;
        --join)         JOIN_TARGET="$2"; shift 2 ;;
        --token)        JOIN_TOKEN="$2"; shift 2 ;;
        --allowlist)    ADMIN_ALLOWLIST="$2"; shift 2 ;;
        --acme-email)   ACME_EMAIL="$2"; shift 2 ;;
        --keep-certbot-timer) KEEP_CERTBOT_TIMER=true; shift ;;
        -y|--yes)       ASSUME_YES=true; shift ;;
        -h|--help)      usage; exit 0 ;;
        *)              fail "Do not know the option $1.  Try --help." ;;
    esac
done

ask() {
    $ASSUME_YES && return 0
    read -r -p "      $1 [y/N] " reply
    [[ "$reply" =~ ^[Yy] ]]
}

# ============================================================== checks
header "Checks"

[[ "$(id -u)" -eq 0 ]] || fail "Run this with sudo."

[[ -f "$SCRIPT_DIR/docker-compose.yml" ]] || \
    fail "Run this from inside the project folder, the one with docker-compose.yml in it."

command -v docker >/dev/null 2>&1 || \
    fail "Docker is not installed.  Run docker_setup.sh first."

docker compose version >/dev/null 2>&1 || \
    fail "The docker compose plugin is missing.  Run docker_setup.sh first."

HAVE_SYSTEMD=true
if [[ ! -d /run/systemd/system ]]; then
    HAVE_SYSTEMD=false
    problem "No systemd on this box, so the agent cannot run as a service." \
"The GUI will still come up and you can look around, but nothing can be
applied to nginx until the agent is running.  Start it by hand with:
    python3 ${AGENT_DIR}/nginx-mgr-agent.py"
fi

HAVE_NGINX=true
if [[ ! -x /usr/sbin/nginx ]]; then
    HAVE_NGINX=false
    problem "No nginx at /usr/sbin/nginx." \
"The manager manages an nginx, it does not bring its own.  Install it with:
    sudo ./nginx-installer.sh install
You can do that after this finishes.  The GUI comes up either way."
else
    NGINX_VERSION="$(/usr/sbin/nginx -v 2>&1 | sed 's|.*nginx/||')"
    log "nginx ${NGINX_VERSION}"
fi

# The manager drives the installer script when you rebuild nginx from the GUI,
# so it needs a copy somewhere predictable.  nginx-installer.sh ships in this
# folder for exactly this reason.
if [[ -f "$SCRIPT_DIR/nginx-installer.sh" ]]; then
    if [[ ! -f "$INSTALLER_PATH" ]] || ! cmp -s "$SCRIPT_DIR/nginx-installer.sh" "$INSTALLER_PATH"; then
        install -m 0700 "$SCRIPT_DIR/nginx-installer.sh" "$INSTALLER_PATH"
        log "put nginx-installer.sh at ${INSTALLER_PATH} so rebuilds work from the GUI"
    else
        log "nginx-installer.sh at ${INSTALLER_PATH} is already current"
    fi
else
    warn "No nginx-installer.sh in this folder, which is odd since it ships here."
    if [[ ! -f "$INSTALLER_PATH" ]]; then
        info "Rebuilding nginx from the GUI will not work until one is at ${INSTALLER_PATH}."
    fi
fi

if [[ -z "$NODE_NAME" ]]; then
    NODE_NAME="$(hostname -s)"
fi
if [[ -z "$NODE_ADDRESS" ]]; then
    # The address on the default route, which is usually the one peers can
    # reach.  Worth checking though, since a box with a separate management
    # network probably wants that address instead.
    NODE_ADDRESS="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1)}' | head -1)"
    [[ -n "$NODE_ADDRESS" ]] || fail "Could not work out this box's address.  Pass --address."
    warn "Guessed this node's address as ${NODE_ADDRESS}."
    info "If your peers talk over a different network, stop and rerun with --address."
fi

log "node ${NODE_NAME} at ${NODE_ADDRESS}, priority ${PRIORITY}"

if [[ -n "$JOIN_TARGET" && -z "$JOIN_TOKEN" ]]; then
    fail "--join needs --token as well.  Make one on the Cluster page of a node that is already up."
fi

# ============================================================== the group
header "The nginxmgr group"

if getent group "$SOCKET_GROUP" >/dev/null; then
    SOCKET_GID="$(getent group "$SOCKET_GROUP" | cut -d: -f3)"
    log "group ${SOCKET_GROUP} already exists with gid ${SOCKET_GID}"
else
    if getent group "$SOCKET_GID" >/dev/null; then
        warn "gid ${SOCKET_GID} is taken, letting the system pick one"
        groupadd "$SOCKET_GROUP"
    else
        groupadd --gid "$SOCKET_GID" "$SOCKET_GROUP"
    fi
    SOCKET_GID="$(getent group "$SOCKET_GROUP" | cut -d: -f3)"
    log "made group ${SOCKET_GROUP} with gid ${SOCKET_GID}"
fi

info "This group owns the agent socket.  The container joins it, and that is"
info "the only reason a non root process in there can talk to the agent."

# ============================================================== the agent
header "Host agent"

mkdir -p "$AGENT_DIR"
install -m 0750 "$SCRIPT_DIR/host-agent/nginx-mgr-agent.py" "$AGENT_DIR/nginx-mgr-agent.py"
log "installed the agent to ${AGENT_DIR}"

# Everything the unit file lists under ReadWritePaths has to exist before the
# agent will start.  ProtectSystem=strict makes systemd bail out with a bare
# 226/NAMESPACE if even one of them is missing, and it does not say which.
#
# The letsencrypt folders normally turn up the first time certbot runs, which
# on a new box has not happened yet.  Making them here is cheap and saves a
# confusing failure.  The unit also marks the optional ones with a dash, so
# this is belt and braces.
mkdir -p /var/backups/nginx-fleet-manager /var/lib/nginx-fleet-manager \
         /usr/local/lib/nginx-fleet-manager /var/www/certbot \
         /etc/letsencrypt /var/log/letsencrypt /var/lib/letsencrypt \
         /var/cache/nginx /var/log/nginx
chmod 0750 /usr/local/lib/nginx-fleet-manager

install -m 0644 "$SCRIPT_DIR/host-agent/nginx-mgr-agent.service" "$AGENT_UNIT"

# The unit ships with a default installer path.  Point it at wherever it really
# is on this box.
if [[ -f "$INSTALLER_PATH" ]]; then
    if ! grep -q "NFM_INSTALLER" "$AGENT_UNIT"; then
        sed -i "/^Environment=NFM_ACME_WEBROOT/a Environment=NFM_INSTALLER=${INSTALLER_PATH}" "$AGENT_UNIT"
    fi
fi

AGENT_OK=false

if ! $HAVE_SYSTEMD; then
    info "skipping the service setup, there is no systemd here"
else
systemctl daemon-reload
systemctl enable nginx-mgr-agent >/dev/null 2>&1
systemctl restart nginx-mgr-agent

sleep 2
if systemctl is-active --quiet nginx-mgr-agent; then
    success "      agent is running"
    AGENT_OK=true
else
    echo
    systemctl status nginx-mgr-agent --no-pager -l | head -12
    echo
    info "The last few log lines:"
    journalctl -u nginx-mgr-agent -n 15 --no-pager 2>/dev/null | sed 's/^/        /'
    echo

    # 226/NAMESPACE means systemd could not build the sandbox, which nearly
    # always means a folder in ReadWritePaths is missing.  The bare number tells
    # you nothing, so spell it out and point at the likely one.
    if systemctl show nginx-mgr-agent -p ExecMainStatus --value 2>/dev/null | grep -q '^226$'; then
        warn "That is 226/NAMESPACE: systemd could not set up the agent's sandbox."
        info "Nearly always a folder the unit wants to write does not exist."
        info "Checking the ones it needs:"
        for d in /etc/nginx /var/www/certbot /var/backups/nginx-fleet-manager \
                 /usr/local/lib/nginx-fleet-manager; do
            [[ -d "$d" ]] && info "    ok      $d" || warn "    MISSING $d"
        done
        info ""
        info "Make any missing folder above, then: systemctl restart nginx-mgr-agent"
    fi

    # signal=SYS means seccomp shot it.  The message never says which syscall,
    # so point at the two settings that cause it rather than leaving somebody
    # reading "code=dumped, signal=SYS" and guessing.
    if systemctl show nginx-mgr-agent -p Result --value 2>/dev/null | grep -q 'core-dump' \
       || journalctl -u nginx-mgr-agent -n 20 --no-pager 2>/dev/null | grep -q 'signal=SYS'; then
        warn "That is SIGSYS: the syscall filter killed it, not the agent crashing."
        info "The two settings in the unit that cause this are:"
        info "    MemoryDenyWriteExecute=yes"
        info "    SystemCallFilter=~...  (the deny list)"
        info ""
        info "Both ship in a form Python is happy with, so if you are seeing this"
        info "on a stock install please report it.  To get moving now, comment"
        info "them out in ${AGENT_UNIT} and:"
        info "    systemctl daemon-reload && systemctl restart nginx-mgr-agent"
    fi

    problem "The host agent will not start." \
"Carrying on anyway.  The GUI comes up without it and tells you the same
thing, you just cannot apply anything to nginx until it is fixed.  See the
log above, then:
    systemctl restart nginx-mgr-agent
    journalctl -u nginx-mgr-agent -f"
fi
fi

if $AGENT_OK; then
    for _ in $(seq 1 15); do
        [[ -S /run/nginxmgr/agent.sock ]] && break
        sleep 1
    done
    if [[ -S /run/nginxmgr/agent.sock ]]; then
        log "socket is at /run/nginxmgr/agent.sock"
    else
        AGENT_OK=false
        problem "The agent started but its socket never turned up." \
"Expected /run/nginxmgr/agent.sock.  Check RuntimeDirectory in
${AGENT_UNIT} and the agent log:
    journalctl -u nginx-mgr-agent -n 50"
    fi
fi

# ============================================================== .env
header "Settings"

ENV_FILE="$SCRIPT_DIR/.env"

if [[ -f "$ENV_FILE" ]]; then
    warn ".env already exists, leaving it alone."
    info "Delete it and run again if you want a fresh one."
    # Keep the existing secret.  Generating a new one would make every stored
    # TOTP seed and peer key unreadable, which looks exactly like the cluster
    # falling apart.
    SECRET_KEY="$(grep '^NFM_SECRET_KEY=' "$ENV_FILE" | cut -d= -f2- || true)"
    [[ -n "$SECRET_KEY" ]] || fail "That .env has no NFM_SECRET_KEY in it."
else
    SECRET_KEY="$(openssl rand -base64 48)"
    cat > "$ENV_FILE" <<EOF
# Written by install.sh on $(date -Is).
#
# The secret key below encrypts TOTP seeds and peer keys in the database.
# Every node needs its own.  Do not copy this file between boxes, and do not
# lose it: change it and everything encrypted becomes unreadable.

NFM_NODE_NAME=${NODE_NAME}
NFM_NODE_ADDRESS=${NODE_ADDRESS}
NFM_CLUSTER_PRIORITY=${PRIORITY}

NFM_GUI_PORT=7443
NFM_PEER_PORT=7444
NFM_BIND_ADDRESS=0.0.0.0

NFM_SECRET_KEY=${SECRET_KEY}
NFM_ADMIN_ALLOWLIST=${ADMIN_ALLOWLIST}
NFM_SESSION_TIMEOUT_MINUTES=60

NFM_OIDC_ENABLED=false

NFM_ACME_EMAIL=${ACME_EMAIL}

# Real certificates by default.  This used to install as true, on the reasoning
# that a first run should not burn a rate limit.  What it actually did was hand
# people a certificate from the staging CA, which no browser trusts, on a site
# they had just watched come up green in the GUI.  Nothing says staging except
# the issuer name, so it reads as a broken certificate rather than the wrong CA.
#
# Getting a real one is the normal case and the rate limits are generous.  Turn
# this on in Settings while you are testing an issuance you expect to fail.
NFM_ACME_STAGING=false

NFM_LOG_LEVEL=info
NFM_HOST_GID=${SOCKET_GID}
NFM_VERSION=1.0.0
EOF
    chmod 600 "$ENV_FILE"
    log "wrote .env with a fresh secret"
fi

if [[ -z "$ADMIN_ALLOWLIST" ]]; then
    warn "No GUI allow list set."
    info "Anybody who can reach port 7443 gets the login page.  Set"
    info "NFM_ADMIN_ALLOWLIST in .env to your management networks and restart."
fi

# Staging is on by default on purpose.  The real service will lock you out for
# a week if you get it wrong five times, and people always get it wrong at
# least once.
info "Certificates are pointed at the Lets Encrypt staging service to start."
info "Turn that off in Settings once you have one working."

# ============================================================== build and start
header "Building and starting"

cd "$SCRIPT_DIR"
docker compose build >/dev/null 2>&1 || {
    warn "the quiet build failed, running it again so you can see why"
    docker compose build
    fail "Build failed."
}
log "image built"

docker compose up -d
sleep 8

if ! docker compose ps --status running 2>/dev/null | grep -q .; then
    docker compose logs --tail 30
    fail "The container did not stay up.  See the log above."
fi
success "      container is running"

# ============================================================== joining
if [[ -n "$JOIN_TARGET" ]]; then
    header "Joining the cluster"

    # Wait for the app to finish starting, or the join races it.
    for _ in $(seq 1 30); do
        if docker compose exec -T nginx-fleet-manager \
            python -c "import socket,sys; s=socket.socket(); sys.exit(0 if s.connect_ex(('127.0.0.1',7443))==0 else 1)" 2>/dev/null; then
            break
        fi
        sleep 2
    done

    # Keep the output.  The join says exactly why it failed, and that line is
    # the whole diagnosis, but it used to scroll past and the summary at the end
    # just said it did not work.  That is useless: "could not reach" and "token
    # refused" are completely different problems.
    JOIN_LOG="$(mktemp)"
    if docker compose exec -T nginx-fleet-manager \
        python -m app.join "$JOIN_TARGET" "$JOIN_TOKEN" 2>&1 | tee "$JOIN_LOG"; then
        log "joined, restarting so the peer listener comes up"
        docker compose restart
        sleep 6
        success "      this node is part of the cluster"
        rm -f "$JOIN_LOG"
    else
        JOIN_WHY="$(grep -i "join failed:" "$JOIN_LOG" | head -1 | sed 's/^[[:space:]]*//')"
        [[ -z "$JOIN_WHY" ]] && JOIN_WHY="$(tail -3 "$JOIN_LOG" | tr '\n' ' ' | cut -c1-300)"
        rm -f "$JOIN_LOG"

        problem "Joining the cluster did not work." \
"${JOIN_WHY}

The node is installed and the GUI is up, it is just on its own for now.
Tokens are single use and expire after two hours, so a token that has
already been tried once will not work again.  Make a fresh one on the
Cluster page of the node that is already running, then run the join on its
own so you can see what it says:
    docker compose exec nginx-fleet-manager python -m app.join ${JOIN_TARGET} <token>
    docker compose restart

If it says it could not reach ${JOIN_TARGET}, the peer port is blocked
between these boxes.  Check from here with:
    curl -k -m 5 https://${JOIN_TARGET}/"
    fi
fi

# ============================================================== certbot timer
header "The certbot timer"

if $KEEP_CERTBOT_TIMER; then
    warn "Leaving certbot.timer alone because you asked."
    info "Expect renewal failures on any node that does not own the public address."
elif systemctl is-enabled --quiet certbot.timer 2>/dev/null; then
    info "The stock certbot timer fires on every box.  On a node that does not"
    info "currently own the public address for a domain, the challenge fails"
    info "every single time, so you end up with a mailbox full of failures from"
    info "most of your fleet and the real problem buried in it."
    info ""
    info "The manager schedules renewals itself and works out which node can"
    info "actually answer, at renewal time, with current DNS."
    info ""
    if $ASSUME_YES || ask "Turn certbot.timer off?"; then
        systemctl disable --now certbot.timer
        log "certbot.timer is off.  The manager handles renewals now."
    else
        warn "Left on.  You will get renewal failures from the nodes that cannot answer."
    fi
else
    log "certbot.timer is not enabled, nothing to do"
fi

# ============================================================== done
header "Done"

echo
success "NGINX Management is running on ${NODE_NAME}."
echo
info "GUI:   https://${NODE_ADDRESS}:7443"
info "Peers: ${NODE_ADDRESS}:7444  (firewall this to your other nodes)"
echo

if [[ -z "$JOIN_TARGET" ]]; then
    # Dig the first login out of the log rather than telling somebody to go and
    # grep for it.  It is printed once and once only, so the moment it scrolls
    # off you are into resetting the account instead.
    ADMIN_PW="$(docker compose logs 2>/dev/null \
        | grep -A3 'Made the first admin' | grep 'password:' \
        | sed 's/.*password: //' | tr -d '\r' | tail -1)"

    if [[ -n "$ADMIN_PW" ]]; then
        info "First login, shown once and never again:"
        echo
        echo "        username: admin"
        echo "        password: ${ADMIN_PW}"
        echo
        info "You have to change it and set up an authenticator on the way in."
    else
        info "The first login password was printed once in the log:"
        info "    docker compose logs | grep -A3 'Made the first admin'"
        info "If it is gone already, make a new one with:"
        info "    docker compose exec nginx-fleet-manager python -m app.reset_admin"
    fi
    echo
    info "This node started a new cluster and holds its certificate authority."
    info "To add another node, log in, go to Cluster, and press Add a node."
else
    info "Sign in with an account from the cluster you joined."
fi

echo
info "Logs:    docker compose logs -f"
info "Agent:   journalctl -u nginx-mgr-agent -f"

# ---- anything that went wrong on the way through --------------------------
if [[ ${#PROBLEMS[@]} -gt 0 ]]; then
    echo
    echo "${c_ylw}== ${#PROBLEMS[@]} thing(s) to come back to ==${c_reset}"
    echo
    n=1
    for p in "${PROBLEMS[@]}"; do
        echo "  ${n}. $(head -1 <<< "$p")"
        tail -n +2 <<< "$p" | while IFS= read -r line; do
            [[ -n "$line" ]] && echo "     $line"
        done
        echo
        n=$((n + 1))
    done
    info "None of these stop you logging in and looking around."
    info "Fix them, then run this script again.  It is safe to re-run."
fi

echo

}
