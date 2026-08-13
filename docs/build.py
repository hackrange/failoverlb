"""
Build the manual.

    docker run --rm -v /root/nfm-docs:/docs nfm-docs:latest python /docs/build.py

Reads the chapters, draws the callouts onto the screenshots using the element
positions recorded when they were taken, renders the terminal transcripts, and
writes the Word file.

Nothing here knows anything about the product.  Adding a chapter means adding a
file under chapters/ and a line in CHAPTERS below, which is what keeps this a
living document rather than one that goes stale the first time somebody is
busy.
"""
import importlib
import json
import pathlib
import sys

sys.path.insert(0, "/docs")

import media                                    # noqa: E402
from book import Book                           # noqa: E402

ROOT = pathlib.Path("/docs")
SHOTS = ROOT / "shots"
BUILT = ROOT / "built"
OUT = ROOT / "NGINX-Management-User-Guide.docx"

BUILT.mkdir(exist_ok=True)

VERSION = "Version 1.0  |  For NGINX Management 1.0"

CHAPTERS = [
    "part1",
    "part2",
    "part3",
    "part4",
    "part5",
    "part6",
    "part7",
    "part8",
    "part9",
    "part10",
    # Always last, whatever gets added above.
    "backmatter",
]

# Where the arrows go.  Keyed by screenshot, then by the name recorded when the
# shot was taken.  The label is what the arrow says.
#
# `side` decides which way the arrow comes in.  Left is the default because
# that is where the reader's eye already is, but a control near the left edge
# needs the arrow to come from the right or it points off the page.
CALLOUTS = {
    "login-empty": [
        ("username", "Your username", "left"),
        ("password", "Your password", "left"),
        ("continue", "Click here", "right"),
    ],
    "login-code": [
        ("code", "The six digit code from your app", "left"),
        ("continue", "Click here", "right"),
    ],
    "dashboard": [
        ("nav", "The menu, grouped by job", "right"),
        ("node", "Which server, and whether it is in charge", "left"),
    ],
    "sites": [
        ("add", "Click here to add a site", "left"),
        ("apply", "Nothing is live until you click this", "left"),
    ],
    "certificates": [
        ("letsencrypt", "A free certificate, renewed for you", "left"),
        ("upload", "A certificate you already bought", "right"),
        ("selfsigned", "For testing only", "right"),
        ("csr", "To buy one from a supplier", "right"),
    ],
    "gslb": [
        ("addzone", "Click here to add a zone", "left"),
        ("listener", "Whether this server is really answering DNS", "left"),
        ("delegation", "Copy these to your domain host", "left"),
    ],
    "gslb-add-zone": [
        ("name", "The part of your domain these servers answer for", "left"),
        ("nameservers", "One name per server", "left"),
        ("save", "Click here", "right"),
    ],
    "pools": [
        ("apply", "Nothing is live until you click this", "left"),
    ],
    "cluster": [
        ("addnode", "Click here to add another server", "left"),
        ("resync", "Push the current settings at anybody behind", "left"),
        ("nodes", "Which one is in charge", "right"),
    ],
    "utilization": [
        ("charts", "How busy your load balancers are", "right"),
    ],
    "errorpages": [
        ("add", "Click here to make a template", "left"),
    ],
    "streams": [
        ("add", "Click here to add a port to balance", "left"),
    ],
    "maps": [
        ("add", "Click here to add a lookup", "left"),
    ],
    "users": [
        ("add", "Click here to add somebody", "left"),
    ],
    "changes": [
        ("apply", "Click here to make your changes live", "left"),
        ("summary", "What is saved and not yet live", "right"),
        ("diffs", "Exactly what will change", "right"),
    ],
    "audit": [
        ("entries", "Who changed what, and when", "right"),
    ],
    "settings": [
        ("acme", "Where expiry warnings are sent", "left"),
        ("staging", "Leave this off for real certificates", "left"),
        ("mgmt", "Networks that count as management", "left"),
    ],
    "zones-rate": [
        ("new", "Click here to make one", "left"),
        ("list", "Used by tells you if it is doing anything", "right"),
    ],
    "zones-conn": [("list", "One row per limit", "right")],
    "zones-cache": [("list", "One row per cache", "right")],
    "import": [
        ("config", "Paste your config here", "right"),
        ("pickfile", "Or load it from a file", "left"),
        ("preview", "Click here.  This writes nothing", "left"),
    ],
    "import-preview": [
        ("summary", "Untick anything you do not want", "right"),
        ("doimport", "Everything arrives switched off", "left"),
    ],
    "site-detail": [
        ("names", "The addresses this site answers for", "left"),
        ("mode", "What it does with a request", "left"),
        ("cert", "Which certificate it presents", "left"),
        ("delete", "Removes it at the next apply", "right"),
    ],
    "pool-detail": [
        ("members", "Click here to add a server", "left"),
        ("delete", "Blocked while a site is using it", "right"),
    ],
    "gslb-edit-record": [
        ("ttl", "How long the answer is remembered", "left"),
        ("policy", "What to do when a server is down", "left"),
        ("answers", "One answer per server", "left"),
    ],
}


# Shots that are mostly empty page around one dialog.  A full page screen is
# left alone, because the menu down the side is part of what is being
# explained.
TRIM = {"login-empty", "login-code", "gslb-add-zone", "gslb-edit-record",
        "cert-letsencrypt"} | {
    # Every dialog is a box in the middle of a dimmed page.  Trimming to the
    # box keeps the words in it readable at print size.
    p.stem for p in __import__("pathlib").Path("/docs/shots").glob("dlg-*.png")}


def build_shot(name):
    """
    An annotated screenshot, or the plain one if there is nothing to point at.

    A callout naming an element that was not found is skipped and reported.
    The alternative is an arrow pointing at the top left corner, which looks
    deliberate and is worse than no arrow at all.
    """
    source = SHOTS / f"{name}.png"
    if not source.exists():
        print(f"  no screenshot: {name}", file=sys.stderr)
        return str(source)

    marks_spec = CALLOUTS.get(name)
    if not marks_spec:
        return str(source)

    positions = {}
    pos_file = SHOTS / f"{name}.json"
    if pos_file.exists():
        positions = json.loads(pos_file.read_text())

    marks = []
    for key, label, side in marks_spec:
        box = positions.get(key)
        if not box:
            print(f"  {name}: no position for '{key}', callout skipped",
                  file=sys.stderr)
            continue
        if side == "left":
            at = (box["x"] - 6, box["cy"])
            start = (max(20, box["x"] - 200), box["cy"] - 70)
        else:
            at = (box["x"] + box["w"] + 6, box["cy"])
            start = (box["x"] + box["w"] + 200, box["cy"] - 70)
        marks.append({"at": at, "from": start, "text": label,
                      "align": "left" if side == "left" else "right"})

    out = BUILT / f"{name}-marked.png"
    media.annotate(source, out, marks, scale=2)
    if name in TRIM:
        media.trim(out)
    return str(out)


def build_term(name, lines, title):
    out = BUILT / f"term-{name}.png"
    media.terminal(lines, out, title=title)
    return str(out)


def main():
    book = Book(
        "NGINX Management",
        "The complete guide to installing and running it",
        VERSION)
    book.cover()
    book.contents()

    for module_name in CHAPTERS:
        module = importlib.import_module(f"chapters.{module_name}")
        module.write(book, build_shot, build_term)
        print(f"  wrote chapter file: {module_name}")

    book.save(str(OUT))
    size = OUT.stat().st_size / 1024
    print(f"\n  {OUT.name}  ({size:.0f} KB)")


main()
