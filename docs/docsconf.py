"""
Where the manual's tooling is pointed, and what gets renamed in the pictures.

Kept in one place because it is the only part that is specific to whoever is
building the book.  Everything else works anywhere.

The names in a screenshot are rewritten in the browser before the shutter, so
the pictures are of a real running system while reading as the example domain
the manual talks about.  Set NFM_DOCS_SUBS to a json list of pairs to override
the list below without editing this file.
"""
import json
import os

# Where to point the browser.  Override with NFM_URL.
BASE = os.environ.get("NFM_URL", "https://localhost:7443")

# Longest first, so a full hostname is rewritten before its domain is.
DEFAULT_SUBSTITUTIONS = [
    ["lb-10.example.invalid", "lb-01.domain.com"],
    ["lb-11.example.invalid", "lb-02.domain.com"],
    ["gslb.example.invalid", "gslb.domain.com"],
    ["ns1.example.invalid", "ns1.domain.com"],
    ["ns2.example.invalid", "ns2.domain.com"],
    ["example.invalid", "domain.com"],
    ["lb-10", "lb-01"],
    ["lb-11", "lb-02"],
]


def substitutions():
    raw = os.environ.get("NFM_DOCS_SUBS")
    if raw:
        return [tuple(pair) for pair in json.loads(raw)]
    return [tuple(pair) for pair in DEFAULT_SUBSTITUTIONS]


SUBSTITUTIONS = substitutions()


# Names that must never reach the finished book.  The pictures are taken from a
# real system, so this is the backstop for a substitution that was missed or a
# hostname typed into a chapter by hand.  Put your own real hostnames and
# addresses here, or set NFM_DOCS_FORBIDDEN to a json list.
DEFAULT_FORBIDDEN = [
    r"\.invalid\b",
]


def forbidden():
    raw = os.environ.get("NFM_DOCS_FORBIDDEN")
    if raw:
        return json.loads(raw)
    return DEFAULT_FORBIDDEN
