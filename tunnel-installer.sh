#!/usr/bin/env bash
# =============================================================================
# Put everything the tunnel needs on this load balancer.
#
#   sudo ./tunnel-installer.sh install
#   sudo ./tunnel-installer.sh check
#
# Run from the GUI, through a systemd unit, for the same reason the nginx build
# is: the agent runs under ProtectSystem=strict with a short list of writable
# paths, a child process inherits that sandbox, and a package manager needs far
# more than that.  Widening the agent's paths to help this one job would take
# the protection away from every other verb.
#
# "check" changes nothing and says what is missing.  It is what the GUI asks
# before it offers to install anything, so a box that is already set up is
# never offered a button that would do nothing.
#
# Ubuntu 22.04 and up, and it should be equally happy on anything Debian based.
# The two of those differ less than the machines do: a virtual machine with a
# distribution kernel has wireguard already, a container gets whatever its host
# loaded, and a minimal cloud image can be missing the tools that would tell
# you either way.  So this checks rather than assumes, and says which of those
# it found.
# =============================================================================
set -uo pipefail

IFACE="${NFM_TUNNEL_IF:-nfm0}"

say()  { echo "[tunnel] $*"; }
fail() { echo "[tunnel] $*" >&2; }

# -----------------------------------------------------------------------------
# What the tunnel needs, and how to tell whether it is here
# -----------------------------------------------------------------------------
#
# Three separate things, which fail in different ways and are worth reporting
# apart:
#
#   the tools    wg and wg-quick, from wireguard-tools
#   the unit     wg-quick@.service, which is how the interface is owned
#   the datapath the kernel module, or wireguard-go if the kernel has none
#
# A box can have the tools and no datapath.  That is the case that looks fine
# and carries nothing, so it gets checked properly rather than inferred from
# the package being installed.

have_tools()    { command -v wg >/dev/null 2>&1 && command -v wg-quick >/dev/null 2>&1; }
have_unit()     { systemctl cat "wg-quick@${IFACE}.service" >/dev/null 2>&1; }
have_userspace(){ command -v wireguard-go >/dev/null 2>&1; }

have_module() {
    # Loaded already, built in, or loadable.  A container usually cannot load
    # anything and inherits whatever its host has, so "can we load it" has to
    # be tried rather than assumed from the module file existing.
    [[ -d /sys/module/wireguard ]] && return 0
    modprobe wireguard >/dev/null 2>&1 && [[ -d /sys/module/wireguard ]]
}

have_tun() { [[ -c /dev/net/tun ]]; }

# The datapath question, answered honestly: the kernel if it will have us, the
# userspace implementation if it will not, and nothing if neither.
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

# One update, and not a fatal one.  A box with a broken third party source
# fails here through no fault of ours, and the packages we want are very likely
# already fetchable.  Better to try the install and let that be the thing that
# fails with a real reason.
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

# The datapath, if the kernel will not give us one.
#
# wireguard has been in the mainline kernel since 5.6 and Ubuntu 22.04 ships
# 5.15, so the usual answer here is that it is already there.  The exception is
# a container, which gets whatever its host loaded and cannot load anything
# itself.  wireguard-go does the same job in userspace, needs no module, and
# needs /dev/net/tun, which a container has to be given.
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
        # wg-quick has to be told, and told in a way that survives a reboot and
        # a package upgrade, so a drop-in rather than an edited unit.
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

# wg-quick@.service comes with wireguard-tools.  If it is missing after all
# that, something is wrong that guessing will not fix.
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
