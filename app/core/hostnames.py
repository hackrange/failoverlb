"""
Working out what a name is, and whether a certificate covers it.

Small, and every line of it exists because getting one of these slightly wrong
produces a site that looks completely fine in the manager and shows a browser
warning to everybody who types the name with a www on the front.

The certificate coverage rules are the part worth reading.  They are nginx's
and the CA's rules, not ours, and the one that catches people is that a
wildcard covers exactly one label: `*.example.com` is good for
`www.example.com` and is **not** good for `example.com` itself, nor for
`a.b.example.com`.  Somebody who buys a wildcard and points their bare domain
at it has a broken site and a certificate page that says valid.
"""
import re

# Suffixes where the registrable name has three labels rather than two.
#
# A list rather than a rule because there is no rule: whether `co.uk` is a
# suffix or a domain somebody owns is a fact about the registry, which is what
# the public suffix list exists to record.  Carrying that whole list for one
# tick box is out of proportion, so this covers the ones people actually have
# and the failure when it is wrong is only that we do not offer to add the www.
# They can still type it, and everything else here still works.
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
    Is this something a certificate could be issued for.

    `_` is nginx's catch all server name and matches anything that did not
    match elsewhere.  It is not a hostname, nothing can cover it, and treating
    it as an uncovered name would put a permanent warning on the default site.
    """
    name = (name or "").strip()
    return bool(name) and name != "_" and not name.startswith("*.") \
        and bool(HOST_RE.match(name))


def is_bare_domain(name: str) -> bool:
    """
    Is this the domain itself rather than something under it.

    `example.com` and `example.co.uk` are bare.  `www.example.com` and
    `api.example.com` are not.  This is what decides whether offering to add
    the www makes any sense: on `api.example.com` it would be nonsense.
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
    The other half of the pair, if this name has one.

    `example.com` gives `www.example.com` and the other way round.  Anything
    else gives None, because `www.api.example.com` is not a thing anybody
    means and offering it would be noise.
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

    A wildcard matches exactly one label, which is the rule everybody forgets.
    `*.example.com` is good for `www.example.com`, is not good for
    `example.com`, and is not good for `a.b.example.com`.
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
            # One label, and only one.  The bit in front of the suffix must
            # have no dots of its own.
            head = name[: -(len(suffix) + 1)]
            if head and "." not in head:
                return True
    return False


def uncovered(cert_names, names) -> list:
    """
    Which of these names the certificate would not be accepted for.

    Anything that is not a real hostname is left out rather than reported, so
    the catch all site does not carry a warning it can never clear.
    """
    return [n for n in (names or [])
            if is_real_name(n) and not covers(cert_names, n)]
