#!/usr/bin/env bash
# =============================================================================
# Put everything the tunnel needs on this load balancer.
#
#   sudo ./tunnel-installer.sh install
#   sudo ./tunnel-installer.sh check
#
# The GUI runs this through nfm-tunnel-install.service, since the agent's
# sandbox is too tight for a package manager.  "check" changes nothing and
# reports what is missing; the GUI uses it to decide whether to offer install.
#
# Ubuntu 22.04 and up, or anything Debian based.  VMs usually have the
# wireguard module already, containers get whatever the host loaded, and
# minimal cloud images may lack the tools, so this checks rather than assumes.
# =============================================================================
set -uo pipefail

IFACE="${NFM_TUNNEL_IF:-nfm0}"

say()  { echo "[tunnel] $*"; }
fail() { echo "[tunnel] $*" >&2; }

# -----------------------------------------------------------------------------
# What the tunnel needs, and how to tell whether it is here
# -----------------------------------------------------------------------------
#
# Three things, reported separately:
#
#   the tools    wg and wg-quick, from wireguard-tools
#   the unit     wg-quick@.service, which owns the interface
#   the datapath the kernel module, or wireguard-go if the kernel has none
#
# Tools without a datapath looks fine and carries nothing, so the datapath is
# checked directly, not inferred from the package.

have_tools()    { command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; }
have_unit()     { systemctl cat "wg-quick@${IFACE}.service" >/dev/null 2>&1; }
have_userspace(){ command -v wireguard-go >/dev/null 2>&1; }

have_module() {
    # Loaded, built in, or loadable.  Actually try modprobe: a container
    # cannot load modules even when the module file exists.
    [[ -d /sys/module/wireguard ]] && return 0
    modprobe wireguard >/dev/null 2>&1 && [[ -d /sys/module/wireguard ]]
}

have_tun() { [[ -c /dev/net/tun ]]; }

# Kernel if available, else userspace, else none.
datapath() {
    if have_module; then
        echo kernel
    elif have_userspace && have_tun; then
        echo userspace
    else
        echo none
    fi
}

report() {
    say "wireguard tools: $(have_tools    && echo yes || echo no)"
    say "wg-quick unit:   $(have_unit     && echo yes || echo no)"
    say "kernel module:   $(have_module   && echo yes || echo no)"
    say "wireguard-go:    $(have_userspace && echo yes || echo no)"
    say "/dev/net/tun:    $(have_tun      && echo yes || echo no)"
    say "datapath:        $(datapath)"
}

ready() {
    have_tools && have_unit && [[ "$(datapath)" != "none" ]]
}

# -----------------------------------------------------------------------------
# check
# -----------------------------------------------------------------------------
if [[ "${1:-}" == "check" ]]; then
    report
    if ready; then
        say "this node can run the tunnel"
        exit 0
    fi
    say "this node cannot run the tunnel yet"
    exit 1
fi

if [[ "${1:-}" != "install" ]]; then
    fail "usage: $0 [install|check]"
    exit 2
fi

if [[ "$(id -u)" != "0" ]]; then
    fail "this has to run as root"
    exit 1
fi

# -----------------------------------------------------------------------------
# install
# -----------------------------------------------------------------------------
say "checking what is already here"
report

if ready; then
    say "nothing to do, this node can already run the tunnel"
    exit 0
fi

if ! command -v apt-get >/dev/null 2>&1; then
    fail "this is not an apt based system, so nothing can be installed from here."
    fail "wireguard-tools is what is needed, by whatever means this system uses."
    exit 1
fi

export DEBIAN_FRONTEND=noninteractive

# Not fatal: a broken third party source can fail the update while our
# packages are still fetchable.  Let the install fail with a real reason.
say "refreshing the package lists"
apt-get update -qq >/dev/null 2>&1 || say "could not refresh every package list, carrying on"

if ! have_tools; then
    say "installing wireguard-tools"
    if ! apt-get install -y -qq wireguard-tools >/dev/null; then
        fail "could not install wireguard-tools"
        fail "try it by hand to see why:  apt-get install wireguard-tools"
        exit 1
    fi
fi

if ! have_tools; then
    fail "wireguard-tools installed but wg is still not on the path"
    exit 1
fi

# wireguard is in the kernel since 5.6 (22.04 ships 5.15), so this is mostly
# for containers without the host module.  wireguard-go needs no module but
# does need /dev/net/tun, which a container has to be given.
if [[ "$(datapath)" == "none" ]]; then
    say "the kernel here has no wireguard, trying the userspace one"
    apt-get install -y -qq wireguard-go >/dev/null 2>&1 \
        || say "wireguard-go is not available from these sources"

    if have_userspace && ! have_tun; then
        fail "wireguard-go is installed but there is no /dev/net/tun."
        fail "This is normally a container that has not been given the device."
        fail "For LXC, add this to the container config and restart it:"
        fail "    lxc.cgroup2.devices.allow = c 10:200 rwm"
        fail "    lxc.mount.entry = /dev/net dev/net none bind,create=dir"
        exit 1
    fi

    if [[ "$(datapath)" == "userspace" ]]; then
        # A drop-in, so it survives package upgrades.
        say "telling wg-quick to use the userspace implementation"
        mkdir -p "/etc/systemd/system/wg-quick@${IFACE}.service.d"
        cat > "/etc/systemd/system/wg-quick@${IFACE}.service.d/userspace.conf" <<EOF
# Written by Failover LB.  This kernel has no wireguard, so the interface
# is carried by wireguard-go in userspace instead.  Remove this file if the
# kernel gains the module later.
[Service]
Environment=WG_QUICK_USERSPACE_IMPLEMENTATION=wireguard-go
EOF
        systemctl daemon-reload >/dev/null 2>&1 || true
    fi
fi

# Ships with wireguard-tools, so if it is missing something else is wrong.
if ! have_unit; then
    fail "wireguard-tools is installed but wg-quick@.service is not there."
    fail "The tunnel is brought up through that unit, so it cannot work without it."
    exit 1
fi

say
say "what this node has now:"
report

if ready; then
    say "done, this node can run the tunnel"
    exit 0
fi

fail "still not ready, see above for which part is missing"
exit 1
