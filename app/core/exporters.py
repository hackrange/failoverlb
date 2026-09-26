"""
Reading CPU and memory from a backend's existing metrics endpoint.

Backends have no agent, so we read the Prometheus text format they already
publish (node_exporter, and most Go, Spring Boot, .NET and Python apps).

Deliberately not SSH: that would mean holding credentials for every backend
and make the manager the most valuable box on the network.  A backend that
publishes nothing is shown as not measured.

Two kinds of exporter:

  - Machine (node_exporter): the whole box, all CPUs and total memory.
  - Application: one process.  Labeled "process" so a JVM using one core of
    sixteen isn't read as a busy machine.

CPU values are counters of seconds, so the caller needs two readings to get
a percentage.
"""
import logging
import re

log = logging.getLogger("nfm.exporters")

# Generous ceiling (node_exporter pages are a few hundred KB) that keeps a
# huge response out of memory.
MAX_BODY_BYTES = 4 * 1024 * 1024

# One exposition line: name, optional labels, value.  The caller skips
# comments and blank lines.
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
    Pull out the few metrics worth charting and ignore the rest, which keeps
    it cheap and robust to exporters adding new metrics.

    Returns only what was found; a partial result is still useful.
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

    # Process numbers only when machine numbers are missing, or an app
    # exporter beside node_exporter would replace the box's memory with one
    # process's.
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
        # Process CPU time, kept separate so it isn't labeled as the machine.
        out["process_cpu_seconds"] = process_cpu
        out.setdefault("level", "process")

    return out


def cpu_percent(older: dict, newer: dict, cpu_count: int = None):
    """
    Busy percentage between two reads of the same exporter.

    For node_exporter it is one minus the idle share, as a percentage of all
    cores, matching what our own nodes report.

    None when there is nothing to compare or the counters went backwards (a
    restart).  A gap must not be drawn as zero, which would look idle.
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
        # Relative to one core, which is what a process CPU counter means.
        return round(max(0.0, min(100.0 * (cpu_count or 1), used / span * 100)), 1)

    return None


def unsafe_fetch_target(url: str) -> str:
    """
    Reason the manager should not fetch this URL, or "" if it may.

    Fetching user-supplied URLs from a well connected load balancer is an
    SSRF risk.  The scheme is restricted where these are saved; this checks
    the destination.  Refused: loopback, link local (cloud metadata lives at
    169.254.169.254), multicast, unspecified and reserved.

    Private ranges are allowed on purpose.  Exporters on 10.0.0.0/8 are the
    normal case.

    Hostnames are not checked: resolving now proves nothing against DNS
    rebinding at fetch time.  The caller keeps redirects off.
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
    Expand a per-pool template into one member's URL.  Pool members are
    usually identical, so one template beats a URL per member.

    `{host}` (or `{address}`) is the member's address; `{port}` is its
    serving port, for apps that expose metrics on the traffic port.
    """
    text = str(template or "").strip()
    if not text:
        return ""
    return (text
            .replace("{host}", str(address))
            .replace("{address}", str(address))
            .replace("{port}", str(port if port is not None else "")))
