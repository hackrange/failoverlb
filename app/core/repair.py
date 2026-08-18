"""
Work out what to take out of a config nginx will not load, and say so first.

This exists because of a class of failure that is nobody's fault and lands at
the worst moment.  Config comes in from somewhere else, an import or a paste
into a custom config box, carrying a directive that is perfectly good nginx in
the place it came from and not allowed where it has ended up.  `ssl_session_cache`
is the one that started this: fine in a server block, refused in a location.
The site looks right on the page, the rows are all there, and the next apply
dies on a generated file nobody hand edited.

**Nothing here applies anything and nothing here edits by itself.**  It works
out a repair, says exactly what it would take out and why, and hands that back
for a person to agree to.  `apply_repair` is a separate call and only ever acts
on changes that came out of `plan_repair`.

Three things shaped how this works.

**nginx is the oracle, not a table of directives.**  The obvious design is a
list of which directives are allowed in which block, checked before writing.  It
does not work.  The directives that end up misplaced are exactly the ones the
catalog does not model, because a directive the catalog models becomes a setting
and gets rendered in the right place by construction.  `ssl_session_cache` is
not in the catalog, and neither is most of what people paste.  Covering it would
mean hand maintaining the context rules for hundreds of nginx directives, which
would drift, and drift silently.  So we ask nginx, which already knows, and
which answers with the directive, the file and the line.

**The repair goes into the source, not the rendered file.**  Commenting out a
line in rendered output fixes nothing: the next render builds it again from the
database.  So a complaint has to be traced back to the field it came from, which
is some site's or some path's custom config, and commented out there.  That is
what makes it stick and what makes it visible to whoever looks next.

**Commented out, never deleted.**  Same bargain the importer already makes in
`_commented`.  A commented directive changes nothing, still loads, and is still
there for somebody who knows why it was needed to put it back somewhere valid.
Deleting it would be tidier and would throw away the only record that it was
ever wanted.
"""

import logging
import re

from app.models import Location, VirtualHost

log = logging.getLogger("nfm.repair")

# Where the live config lives, and what the agent rewrites its paths to before
# handing the output back.  A complaint names /etc/nginx/nginxmgr/sites/x.conf
# and the render calls the same file sites/x.conf.
LIVE_ROOT = "/etc/nginx/nginxmgr/"

# nginx says a lot of different things and almost all of them end the same way:
# some complaint, then "in <file>:<line>".  Matching the tail rather than each
# individual message means a phrasing we have never seen still gets placed.
_WHERE = re.compile(r"in (?P<file>/\S+?):(?P<line>\d+)")

# The directive it is complaining about, when it names one.
_WHICH = re.compile(r'"(?P<name>[A-Za-z0-9_]+)"')

# What we are willing to repair by taking a line out.
#
# Deliberately a short list.  Every one of these is "this line cannot be here",
# which a line removal genuinely fixes.  Anything else, a bad argument or a file
# that is missing, is a different problem and taking the line out would paper
# over it, so those are reported and left alone.
REPAIRABLE = (
    "directive is not allowed here",
    "directive is duplicate",
    "unknown directive",
    # A whole block rather than a line, and it needs the whole block taking out.
    # This is what a config imported before the importer stopped writing every
    # path twice still has in it, so it is worth being able to clear up rather
    # than telling somebody to import the file again.
    "duplicate location",
)

# How many times round before we give up.  One complaint is fixed per pass,
# because nginx stops at the first one, so a file with several needs several
# passes.  The cap is a backstop against a repair that does not actually help
# and would otherwise loop.
MAX_PASSES = 25

# `cannot load certificate "/path/to.pem": BIO_new_file() failed ...`, and the
# same shape for a key.  The quoted path is the only thing in the message that
# says where the trouble is.
# The directives that name a certificate file.  Taking out only one of a pair
# leaves nginx complaining about the other, so all of them go together, which
# is what "remove it and the ssl related directives" means in practice.
_CERT_DIRECTIVES = ("ssl_certificate", "ssl_certificate_key",
                    "ssl_trusted_certificate", "ssl_client_certificate")

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
        # Set when nginx complained about a certificate file rather than about
        # a line.  That complaint carries no file and no line number, so it is
        # placed by looking for the path instead.
        self.cert_path = cert_path

    def __repr__(self):
        return f"<Complaint {self.directive} {self.rel_path}:{self.line_no}>"


def read_complaint(output: str):
    """
    Turn what nginx said into something we can act on.

    None when it is not about a file we generated, or not a thing a line removal
    would fix.  Saying nothing is the right answer far more often than guessing.
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

    # A certificate nginx cannot read.  This one is different in shape from
    # every other complaint here: it names a file it tried to open, and it
    # carries no config file and no line number at all, so the usual placement
    # by file and line finds nothing and the whole thing was reported as
    # unrepairable.  It is also one of the commonest ways a config stops
    # loading, since a certificate can be deleted, renamed, or simply not
    # issued yet.
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
        # The candidate file itself, or something outside what we write.  Not
        # ours to edit.
        return None

    which = _WHICH.search(first)
    reason = first.split("[emerg]", 1)[1].strip()
    # The file and line are for us, not for the person reading it.
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
    Which `location` block a line of rendered config falls inside, if any.

    Needed because the same directive can sit in a site's custom config and in a
    path's, and commenting out the wrong one leaves the config still broken
    while looking like something was done about it.

    Counts braces rather than matching indentation, because the custom config
    boxes take text as typed and its indentation means nothing.
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
            # That block closed before reaching the line we care about.
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
    Comment out the first line matching `target`, with the reason beside it.

    Gives back (new_text, True) when something changed.  Compared on the
    stripped line so that the renderer's indentation, which is added on the way
    out, does not stop a match.
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
    Comment out a whole `location` block, opener to matching close.

    A duplicate location cannot be fixed a line at a time.  Taking out only the
    line nginx named leaves the body behind, loose in the server block, which is
    both wrong and a fresh pile of errors.  So the braces are counted and the
    lot goes.
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
        # Never closed, so the safest reading is that everything after it
        # belonged to it.  Refuse rather than guess.
        return text, False

    out = lines[:start]
    out.append(f"# ^ block below taken out by the config repair.  nginx said: {why}")
    out.extend("# " + lines[i] for i in range(start, end + 1))
    out.extend(lines[end + 1:])
    return "\n".join(out), True


def _site_for(session, rel_path: str):
    """The site a rendered file belongs to.  sites/example.com.conf -> the row."""
    if not rel_path.startswith("sites/") or not rel_path.endswith(".conf"):
        return None
    name = rel_path[len("sites/"):-len(".conf")]
    return session.query(VirtualHost).filter(VirtualHost.name == name).first()


async def plan_repair(session, render, test) -> dict:
    """
    Render, ask nginx, and work out what would have to come out.

    `render` is called with no arguments and gives back the files dict.  `test`
    is awaited with a files dict and gives back (ok, output).  Both are passed
    in so this can be exercised without an agent and so the caller decides what
    "test" means.

    Writes nothing.  The changes it works out are held against the objects in
    this session and rolled back by the caller; `apply_repair` is what makes any
    of it real.
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
            # Something is wrong that taking a line out will not fix.  Report it
            # as it stands rather than keep cutting.
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output, "unrepairable": output}

        # A certificate nginx cannot read is placed by the path it names rather
        # than by a line number, because the message carries neither a file nor
        # a line.  Everything a person typed is searched for a directive naming
        # that file, and those lines come out.  Generated certificate lines are
        # left alone on purpose, the same rule the rest of this follows: those
        # come from a certificate attached on the Basics tab, and the answer
        # there is to issue it or detach it, not to have this quietly edit the
        # config out from under somebody.
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

        # Prefer the path the line actually sits in.  Falling back to the site
        # matters: a directive the renderer wrote into a location can still have
        # come from the site's own custom config.
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
            # It is in generated config rather than in anything somebody typed,
            # so there is no source line to comment out.  That is a bug in the
            # renderer and quietly editing the output would hide it.
            return {"ok": False, "fixed": False, "changes": changes,
                    "output": output,
                    "unrepairable": (
                        f"{complaint.raw}\n\nThat line is generated rather than "
                        f"typed, so there is nothing in a custom config box to "
                        f"take out.  Worth reporting: the renderer should not be "
                        f"producing it.")}

        key = (complaint.rel_path, offending.strip(), where)
        if key in seen:
            # Cut the same thing twice and we are not making progress.
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
