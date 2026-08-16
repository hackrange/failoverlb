"""
Reading CPU and memory off a backend that already publishes it.

These are somebody else's servers and there is no agent on them, so the only
polite way to know what they are doing is to ask something they are already
running.  The one format worth supporting is the Prometheus text exposition
format, because node_exporter speaks it, and so does nearly every runtime with
a metrics endpoint bolted on: Go, Spring Boot, .NET, Python.

**Deliberately not SSH.**  Reading /proc over ssh would work and would mean this
manager holding credentials for every backend in the estate.  That turns a load
balancer manager into the most valuable box on the network, which is a much
bigger security story than a chart is worth.  If a backend publishes nothing,
the answer is that it is not measured, and the page says so.

Two shapes of exporter, and both are handled because both turn up:

  * **A machine exporter**, node_exporter being the one everybody has.  It
    reports the whole box: every cpu, total and available memory.  This is the
    one people mean when they ask for backend CPU.
  * **An application exporter**, which reports the one process.  Useful, and a
    different number: a JVM at 100% of one core on a sixteen core box is not a
    busy box.  It is labelled as process level so nobody reads it as the
    machine.

Everything CPU related is a counter of seconds, so a percentage needs two
readings.  That is the caller's job, the same as it is for our own boxes.
"""
import logging
import re

log = logging.getLogger("nfm.exporters")

# A metrics endpoint is text and small.  This is a generous ceiling for a
# node_exporter page, which is a few hundred kilobytes at most, and stops a
# backend that answers with something enormous from being read into memory.
MAX_BODY_BYTES = 4 * 1024 * 1024

# One line of the exposition format: name, optional labels, value.  Comments
# and blank lines are skipped by the caller.
SAMPLE = re.compile(
    r"^(?P<name>[A-Za-z_:][A-Za-z0-9_:]*)"
    r"(?:\{(?P<labels>[^}]*)\})?"
    r"\s+(?P<value>[^\s]+)"
)

LABEL = re.compile(r'([A-Za-z_][A-Za-z0-9_]*)\s*=\s*"((?:[^"\\]|\\.)*)"')


def _labels(text):
    if not text:
        return {}
    return {m.group(1): m.group(2) for m in LABEL.finditer(text)}


def parse(body: str) -> dict:
    """
    Pull out the handful of numbers worth charting, ignoring everything else.

    A node_exporter page has well over a thousand metrics on it.  Reading only
    the ones asked for keeps this cheap and, more usefully, keeps it from
    breaking when an exporter adds something new, which they do constantly.

    Gives back what it found, and says nothing about what it did not.  A caller
    that wanted cpu and got only memory should show memory rather than treating
    the whole read as a failure.
    """
    if not body:
        return {}

    cpu_seconds = {}          # mode -> seconds, summed over every cpu
    out = {}
    process_cpu = None
    process_rss = None
    jvm_used = None
    jvm_max = None

    for line in body.splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        m = SAMPLE.match(line)
        if not m:
            continue

        name = m.group("name")
        try:
            value = float(m.group("value"))
        except ValueError:
            continue

        if name == "node_cpu_seconds_total":
            mode = _labels(m.group("labels")).get("mode", "")
            if mode:
                cpu_seconds[mode] = cpu_seconds.get(mode, 0.0) + value
        elif name == "node_memory_MemTotal_bytes":
            out["memory_total"] = value
        elif name == "node_memory_MemAvailable_bytes":
            out["memory_available"] = value
        elif name == "node_load1":
            out["load_1m"] = round(value, 2)
        elif name == "node_filesystem_avail_bytes":
            labels = _labels(m.group("labels"))
            if labels.get("mountpoint") == "/":
                out["disk_free"] = value
        elif name == "node_filesystem_size_bytes":
            labels = _labels(m.group("labels"))
            if labels.get("mountpoint") == "/":
                out["disk_total"] = value
        elif name == "process_cpu_seconds_total":
            process_cpu = value
        elif name == "process_resident_memory_bytes":
            process_rss = value
        elif name == "jvm_memory_used_bytes":
            jvm_used = (jvm_used or 0.0) + value
        elif name == "jvm_memory_max_bytes" and value > 0:
            jvm_max = (jvm_max or 0.0) + value

    if cpu_seconds:
        out["cpu_seconds"] = cpu_seconds
        out["level"] = "machine"

    if "memory_total" in out and "memory_available" in out:
        total = out["memory_total"]
        if total > 0:
            out["memory_used"] = total - out["memory_available"]
            out["memory_percent"] = round(out["memory_used"] / total * 100, 1)
        out["level"] = "machine"

    # Only fall back to the process numbers when the machine ones are absent.
    # An application exporter running beside node_exporter would otherwise
    # overwrite the box's memory with one process's, which reads as a machine
    # using 200MB and is a quietly wrong answer.
    if "memory_percent" not in out:
        if jvm_used is not None and jvm_max:
            out["memory_used"] = jvm_used
            out["memory_total"] = jvm_max
            out["memory_percent"] = round(jvm_used / jvm_max * 100, 1)
            out["level"] = "process"
        elif process_rss is not None:
            out["memory_used"] = process_rss
            out["level"] = "process"

    if "cpu_seconds" not in out and process_cpu is not None:
        # One number rather than a breakdown by mode, and it is time this
        # process spent on cpu rather than time the box spent.  Kept apart so
        # the percentage worked out from it is not labelled as the machine.
        out["process_cpu_seconds"] = process_cpu
        out.setdefault("level", "process")

    return out


def cpu_percent(older: dict, newer: dict, cpu_count: int = None):
    """
    Busy percentage between two reads of the same exporter.

    node_exporter counts seconds per cpu per mode, so the busy fraction is one
    minus the idle share of the total.  That comes out as a percentage of all
    cores together, which is the same thing our own boxes report, so the two
    charts mean the same thing.

    None when there is nothing to compare or the counters went backwards, which
    is a restart.  A gap is not zero percent, and drawing it as zero says the
    backend was idle when it was actually being restarted.
    """
    if not older or not newer:
        return None

    old_modes = older.get("cpu_seconds")
    new_modes = newer.get("cpu_seconds")
    if old_modes and new_modes:
        total = sum(new_modes.values()) - sum(old_modes.values())
        idle = new_modes.get("idle", 0.0) - old_modes.get("idle", 0.0)
        if total <= 0:
            return None
        return round(max(0.0, min(100.0, (1 - idle / total) * 100)), 1)

    old_proc = older.get("process_cpu_seconds")
    new_proc = newer.get("process_cpu_seconds")
    old_at, new_at = older.get("at"), newer.get("at")
    if old_proc is not None and new_proc is not None and old_at and new_at:
        span = new_at - old_at
        used = new_proc - old_proc
        if span <= 0 or used < 0:
            return None
        # Against one core, because that is what a process cpu counter means.
        # Dividing by the core count would be a smaller number that looks
        # reassuring and is not what anybody is asking.
        return round(max(0.0, min(100.0 * (cpu_count or 1), used / span * 100)), 1)

    return None


def unsafe_fetch_target(url: str) -> str:
    """
    Why this URL should not be fetched by the manager, or empty when it may be.

    The manager runs on a load balancer, which is one of the best connected
    hosts on the network, so anything that makes it fetch a URL somebody typed
    is a request forgery primitive.  The scheme is already restricted where
    these are saved, which closes file: and gopher: and is the important half.
    This closes the other half: where it may point.

    Refused are the addresses that are only ever interesting to an attacker.
    Loopback and link local, because 169.254.169.254 is the cloud metadata
    service and 127.0.0.1 is every service that thought it was private.
    Multicast and unspecified, because nothing legitimate is there.

    **Private ranges are allowed on purpose.**  A backend exporter on
    10.0.0.0/8 is the ordinary case and the whole reason the setting exists,
    so refusing RFC1918 would break the feature to close a hole that is mostly
    already inside the trust boundary.  The line is drawn at the addresses that
    reach *this* machine or its metadata rather than at private space in
    general.

    A name is left alone.  Resolving it here and checking the answer invites
    the rebind: the name resolves to something allowed now and to loopback when
    the fetch happens a moment later.  The honest answer is that a name cannot
    be checked at save time, so this checks what it can and the caller keeps
    redirects switched off.
    """
    import ipaddress
    from urllib.parse import urlsplit

    try:
        host = urlsplit(str(url or "")).hostname
    except ValueError:
        return "that is not a URL we can read"
    if not host:
        return ""

    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        return ""            # a name, see above

    if address.is_loopback:
        return (f"{address} is this machine.  Pointing the manager at its own "
                f"loopback is how an internal service ends up readable from a "
                f"settings box.")
    if address.is_link_local:
        return (f"{address} is link local, which is where cloud instance "
                f"metadata lives.  That is not somewhere this should reach.")
    if address.is_multicast or address.is_unspecified or address.is_reserved:
        return f"{address} is not an address anything legitimate answers on"
    return ""


def build_url(template: str, address: str, port: int = None) -> str:
    """
    Turn a per pool template into the URL for one member.

    A template rather than a URL per member, because the members of a pool are
    nearly always the same kind of box with the same exporter on the same port,
    and asking somebody to paste the same thing once per backend is how it ends
    up half filled in.

    `{host}` is the member's address and `{port}` is the port it serves on,
    which is occasionally what somebody wants when the app exposes its own
    metrics on the same port as the traffic.
    """
    text = str(template or "").strip()
    if not text:
        return ""
    return (text
            .replace("{host}", str(address))
            .replace("{address}", str(address))
            .replace("{port}", str(port if port is not None else "")))
