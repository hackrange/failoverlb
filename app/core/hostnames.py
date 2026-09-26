"""
Hostname helpers: what kind of name this is, and whether a certificate
covers it.

Getting these slightly wrong gives a site that looks fine in the manager and
shows a browser warning to anyone who adds or drops the www.  The coverage
rules are the CA's, not ours.  A wildcard covers exactly one label:
`*.example.com` is good for `www.example.com` but not for `example.com` or
`a.b.example.com`.
"""
import re

# Suffixes where the registrable name has three labels rather than two.
# The full public suffix list is overkill for one checkbox, so this covers the
# common ones.  If a suffix is missing, we just don't offer to add the www.
MULTI_LABEL_SUFFIXES = (
    "co.uk", "org.uk", "me.uk", "ltd.uk", "plc.uk", "net.uk", "sch.uk",
    "ac.uk", "gov.uk", "nhs.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "co.za", "org.za", "web.za",
    "com.br", "com.mx", "com.ar", "com.sg", "com.hk", "com.tr", "com.tw",
    "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
    "co.in", "net.in", "org.in", "gov.in",
    "com.cn", "net.cn", "org.cn", "gov.cn",
)

HOST_RE = re.compile(r"^[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?"
                     r"(\.[A-Za-z0-9]([A-Za-z0-9-]{0,61}[A-Za-z0-9])?)*$")


def is_real_name(name: str) -> bool:
    """
    True if a certificate could be issued for this name.

    `_` is nginx's catch-all server name, not a hostname.  Counting it as
    uncovered would put a permanent warning on the default site.
    """
    name = (name or "").strip()
    return bool(name) and name != "_" and not name.startswith("*.") \
        and bool(HOST_RE.match(name))


def is_bare_domain(name: str) -> bool:
    """
    True for the domain itself (`example.com`, `example.co.uk`), false for
    anything under it.  Decides whether offering to add the www makes sense.
    """
    name = (name or "").strip().lower().rstrip(".")
    if not is_real_name(name):
        return False

    labels = name.split(".")
    if len(labels) == 2:
        return True
    if len(labels) == 3 and ".".join(labels[-2:]) in MULTI_LABEL_SUFFIXES:
        return True
    return False


def www_partner(name: str):
    """
    `example.com` gives `www.example.com` and vice versa.  Anything else
    gives None; nobody means `www.api.example.com`.
    """
    name = (name or "").strip().lower().rstrip(".")
    if not name or name == "_":
        return None

    if name.startswith("www."):
        rest = name[4:]
        return rest if is_bare_domain(rest) else None

    return f"www.{name}" if is_bare_domain(name) else None


def covers(cert_names, name: str) -> bool:
    """
    Would a certificate carrying these names be accepted for this one.
    A wildcard matches exactly one label (see the module docstring).
    """
    name = (name or "").strip().lower().rstrip(".")
    if not name:
        return False

    for raw in cert_names or []:
        entry = (raw or "").strip().lower().rstrip(".")
        if not entry:
            continue
        if entry == name:
            return True
        if entry.startswith("*."):
            suffix = entry[2:]
            if not name.endswith("." + suffix):
                continue
            # Exactly one label: no dots in front of the suffix.
            head = name[: -(len(suffix) + 1)]
            if head and "." not in head:
                return True
    return False


def uncovered(cert_names, names) -> list:
    """
    Names the certificate would not be accepted for.  Non-hostnames are
    skipped so the catch-all site doesn't carry a warning it can never clear.
    """
    return [n for n in (names or [])
            if is_real_name(n) and not covers(cert_names, n)]
