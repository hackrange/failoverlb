#!/usr/bin/env bash
# =============================================================================
# Pull the latest and put it live on this node.
#
#   sudo ./get_latest_and_build.sh
#
# Run it on every node, not just one, or the nodes will disagree about what
# they support.
#
# A plain "docker compose up -d --build" only updates the manager; the agent
# runs on the host outside the image.  install.sh --upgrade does both, leaves
# .env alone, and checks each half actually landed.
# =============================================================================
set -euo pipefail

# Upgrade the checkout this script lives in, wherever that is.
cd "$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

git pull

# Needs root for the agent and systemd units; harmless if already root.
sudo ./install.sh --upgrade
