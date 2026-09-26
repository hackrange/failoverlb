#!/usr/bin/env bash
# =============================================================================
# Pull the latest and put it live on this node.
#
#   sudo ./get_latest_and_build.sh
#
# Run it on every node, not just one.  A fleet with one node upgraded is a
# fleet where the two disagree about what they can do.
#
# This used to be "docker compose up -d --build", which updates half the
# system.  The manager runs in the container and the agent runs on the host,
# outside the image, so rebuilding the image leaves the agent exactly as it
# was: old code against a new manager, both looking healthy, nothing saying so.
#
# install.sh --upgrade does both halves, leaves .env alone, and proves each one
# landed rather than assuming it.
# =============================================================================
set -euo pipefail

# Wherever this script lives is the checkout to upgrade.  Worked out rather
# than written down, so a second clone somewhere else upgrades itself and not
# the first one.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

git pull

# sudo either way.  It does nothing when this is already running as root, and
# the upgrade needs it for the agent and the systemd units.
sudo ./install.sh --upgrade
