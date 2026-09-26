"""
Work out what to remove from a config nginx will not load, and show it first.

Imported or pasted config can carry a directive that is valid where it came
from but not where it landed (`ssl_session_cache` in a location, for
example).  The site looks fine in the GUI and the next apply fails on a
generated file.

Nothing here applies or saves anything.  plan_repair works out what it would
comment out and why, for a person to approve; applying it is a separate step.

Design choices:

  - nginx is the oracle.  The misplaced directives are the ones the settings
    catalog doesn't model, and hand-maintaining context rules for hundreds of
    directives would drift.  nginx reports the directive, file and line.
  - The fix goes into the source custom config field, not the rendered file,
    or the next render would bring the line back.
  - Lines are commented out, never deleted (as the importer's `_commented`
    does), so the record of what was wanted survives.
"""

import logging
import re

from app.models import Location, VirtualHost

log = logging.getLogger("nfm.repair")

# Live config root.  A complaint about /etc/nginx/nginxmgr/sites/x.conf maps
# to the rendered file sites/x.conf.
LIVE_ROOT = "/etc/nginx/nginxmgr/"

# Most nginx errors end with "in <file>:<line>".  Matching that tail handles
# messages we have never seen.
_WHERE = re.compile(r"in (?P<file>/\S+?):(?P<line>\d+)")

# The directive it is complaining about, when it names one.
_WHICH = re.compile(r'"(?P<name>[A-Za-z0-9_]+)"')

# Errors that removing the line genuinely fixes.  Others (bad arguments,
# missing files) are reported, not papered over.
REPAIRABLE = (
    "directive is not allowed here",
    "directive is duplicate",
    "unknown directive",
    # Needs the whole block removed.  Left behind by older imports that
    # wrote every path twice.
    "duplicate location",
)

# nginx stops at the first error, so each pass fixes one.  The cap guards
# against looping on a repair that doesn't help.
MAX_PASSES = 25

# Directives naming a certificate file.  Removing only one of a pair leaves
# nginx complaining about the other, so they go together.
_CERT_DIRECTIVES = ("ssl_certificate", "ssl_certificate_key",
                    "ssl_trusted_certificate", "ssl_client_certificate")

# `cannot load certificate "/path/to.pem": BIO_new_file() failed ...`, and
# the same for a key.  The quoted path is the only location information.
_CERT_TROUBLE = re.compile(
    r'cannot load certificate(?: key)?\s+"(?P<path>[^"]+)"')


class Complaint:
    """One thing nginx refused, placed against the file it came from."""

    def __init__(self, raw, directive, rel_path, line_no, reason,
                 cert_path=None):
        self.raw = raw
        self.directive = directive
        self.rel_path = rel_path          # e.g. sites/example.com.conf
        self.line_no = line_no            # 1 based, into the rendered file
        self.reason = reason
        # Set for certificate load errors, which have no file or line and are
        # located by searching for the path.
        self.cert_path = cert_path

    def __repr__(self):
        return f"<Complaint {self.directive} {self.rel_path}:{self.line_no}>"


def read_complaint(output: str):
    """
    Parse the first [emerg] line of nginx output into a Complaint.

    None when it isn't about a file we generated or isn't fixable by removing
    a line.  Better to say nothing than guess.
    """
    if not output:
        return None

    first = None
    for line in output.splitlines():
        if "[emerg]" in line:
            first = line.strip()
            break
    if not first:
        return None

    # Unreadable certificate: names the cert file but no config file or line.
    # A common failure, since certs get deleted, renamed or not issued yet.
    cert = _CERT_TROUBLE.search(first)
    if cert:
        return Complaint(
            raw=first,
            directive="ssl_certificate",
            rel_path=None,
            line_no=None,
            reason=first.split("[emerg]", 1)[1].strip(),
            cert_path=cert.group("path"),
        )

    if not any(kind in first for kind in REPAIRABLE):
        return None

    where = _WHERE.search(first)
    if not where:
        return None

    path = where.group("file")
    if not path.startswith(LIVE_ROOT):
        # Not a file we write.
        return None

    which = _WHICH.search(first)
    reason = first.split("[emerg]", 1)[1].strip()
    # Drop the file:line from the message shown to the user.
    reason = _WHERE.sub("", reason).strip().rstrip(",")

    return Complaint(
        raw=first,
        directive=which.group("name") if which else "",
        rel_path=path[len(LIVE_ROOT):],
        line_no=int(where.group("line")),
        reason=reason,
    )


def _line_at(text: str, line_no: int) -> str:
    lines = text.splitlines()
    if 1 <= line_no <= len(lines):
        return lines[line_no - 1]
    return ""


def _location_around(text: str, line_no: int):
    """
    Which `location` block a rendered line falls inside, if any.

    The same directive may be in both the site's and a path's custom config,
    and commenting out the wrong one fixes nothing.  Counts braces, since
    custom config indentation is arbitrary.
    """
    depth = 0
    current = None
    opened_at = None

    for index, raw in enumerate(text.splitlines(), start=1):
        stripped = raw.strip()
        if index > line_no:
            break

        if stripped.startswith("location ") and stripped.endswith("{"):
            if depth >= 1 and current is None:
                current = stripped[len("location "):-1].strip()
                opened_at = depth

        depth += raw.count("{") - raw.count("}")

        if current is not None and depth <= opened_at:
            # Block closed before our line.
            current = None
            opened_at = None

    return current


def _match_path(spec: str) -> str:
    """A rendered `location` argument back to the bare path we store."""
    spec = (spec or "").strip()
    for marker in ("^~ ", "= ", "~* ", "~ "):
        if spec.startswith(marker):
            return spec[len(marker):].strip()
    return spec


def _comment_out(text: str, target: str, why: str) -> tuple:
    """
    Comment out the first line matching `target`, with the reason.  Returns
    (new_text, changed).  Compares stripped lines, since the renderer adds
    indentation.
    """
    wanted = (target or "").strip()
    if not wanted:
        return text, False

    out = []
    done = False
    for line in (text or "").splitlines():
        if not done and line.strip() == wanted:
            out.append(f"# {line.strip()}")
            out.append(f"# ^ taken out by the config repair.  nginx said: {why}")
            done = True
        else:
            out.append(line)
    return "\n".join(out), done


def _comment_out_block(text: str, opener: str, why: str) -> tuple:
    """
    Comment out a whole `location` block, opener to matching close.  For a
    duplicate location, removing only the opener would leave its body loose
    in the server block.
    """
    wanted = (opener or "").strip()
    if not wanted:
        return text, False

    lines = (text or "").splitlines()
    start = None
    for index, line in enumerate(lines):
        if line.strip() == wanted:
            start = index
            break
    if start is None:
        return text, False

    depth = 0
    end = None
    for index in range(start, len(lines)):
        depth += lines[index].count("{") - lines[index].count("}")
        if depth <= 0:
            end = index
            break
    if end is None:
        # Never closed.  Refuse rather than guess.
        return text, False

    out = lines[:start]
    out.append(f"# ^ block below taken out by the config repair.  nginx said: {why}")
    out.extend("# " + lines[i] for i in range(start, end + 1))
    out.extend(lines[end + 1:])
    return "\n".join(out), True


def _site_for(session, rel_path: str):
    """The VirtualHost row for a rendered file like sites/example.com.conf."""
    if not rel_path.startswith("sites/") or not rel_path.endswith(".conf"):
        return None
    name = rel_path[len("sites/"):-len(".conf")]
    return session.query(VirtualHost).filter(VirtualHost.name == name).first()


async def plan_repair(session, render, test) -> dict:
    """
    Render, test with nginx, and work out what would have to come out.

    `render()` returns the files dict; `await test(files)` returns
    (ok, output).  Injected so this runs without an agent.

    Commits nothing.  Changes are made to objects in this session and the
    caller rolls them back unless the repair is approved.
    """
    files = render()
    ok, output = await test(files)
    if ok:
        return {"ok": True, "fixed": True, "changes": [], "output": output,
                "unrepairable": None}

    changes = []
    seen = set()

    for _ in range(MAX_PASSES):
        complaint = read_complaint(output)
        if complaint is None:
            # Not fixable by removing a line; stop cutting.
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output, "unrepairable": output}

        # Unreadable certificate: search all custom config for directives
        # naming that path and comment them out.  Generated cert lines (from a
        # certificate attached on the Basics tab) are left alone; the fix
        # there is to issue or detach the certificate.
        if complaint.cert_path:
            hit_any = False
            for site in session.query(VirtualHost).all():
                holders = [("the site", site)] + [
                    (f"the path {loc.path}", loc) for loc in site.locations]
                for where, holder in holders:
                    current = holder.custom_config or ""
                    if complaint.cert_path not in current:
                        continue
                    kept = []
                    for line in current.splitlines():
                        bare = line.strip()
                        if (complaint.cert_path in bare
                                and bare.split(" ")[0] in _CERT_DIRECTIVES
                                and not bare.startswith("#")):
                            kept.append(f"# {line}    # taken out by the config "
                                        f"repair: {complaint.reason}")
                            changes.append({
                                "site": site.name,
                                "where": where,
                                "directive": bare.split(" ")[0],
                                "line": bare,
                                "reason": complaint.reason,
                            })
                            hit_any = True
                        else:
                            kept.append(line)
                    holder.custom_config = "\n".join(kept)
            if not hit_any:
                return {"ok": False, "fixed": False, "changes": changes,
                        "output": output,
                        "unrepairable": (
                            f"{complaint.raw}\n\nThat certificate is not named "
                            f"in anything anybody typed, so it comes from a "
                            f"certificate attached to a site.  Issue it, or "
                            f"detach it from the site, rather than editing the "
                            f"config.")}
            session.flush()
            files = render()
            ok, output = await test(files)
            if ok:
                return {"ok": False, "fixed": True, "changes": changes,
                        "output": output, "unrepairable": None}
            continue

        text = files.get(complaint.rel_path, "")
        offending = _line_at(text, complaint.line_no)
        if not offending.strip():
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output, "unrepairable": output}

        site = _site_for(session, complaint.rel_path)
        if site is None:
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output, "unrepairable": output}

        # Prefer the location the line sits in, then fall back to the site:
        # site custom config can also render inside a location.
        holder = None
        where = "the site"
        spec = _location_around(text, complaint.line_no)
        if spec:
            wanted = _match_path(spec)
            for loc in site.locations:
                if loc.path == wanted:
                    new_text, hit = _comment_out(
                        loc.custom_config or "", offending, complaint.reason)
                    if hit:
                        loc.custom_config = new_text
                        holder = loc
                        where = f"the path {loc.path}"
                    break

        if holder is None:
            new_text, hit = _comment_out(
                site.custom_config or "", offending, complaint.reason)
            if hit:
                site.custom_config = new_text
                holder = site

        if holder is None:
            # Generated, not typed: a renderer bug that editing would hide.
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output,
                    "unrepairable": (
                        f"{complaint.raw}\n\nThat line is generated rather than "
                        f"typed, so there is nothing in a custom config box to "
                        f"take out.  Worth reporting: the renderer should not be "
                        f"producing it.")}

        key = (complaint.rel_path, offending.strip(), where)
        if key in seen:
            # Same cut twice: no progress.
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output, "unrepairable": output}
        seen.add(key)

        changes.append({
            "site": site.name,
            "where": where,
            "directive": complaint.directive,
            "line": offending.strip(),
            "reason": complaint.reason,
        })

        session.flush()
        files = render()
        ok, output = await test(files)
        if ok:
            return {"ok": False, "fixed": True, "changes": changes,
                    "output": output, "unrepairable": None}

    return {"ok": False, "fixed": False, "changes": changes, "output": output,
            "unrepairable": "gave up after too many passes"}
