"""
Turning an error page template into the HTML nginx will actually serve.

Kept apart from render.py because none of it is nginx config.  It is somebody
else's HTML, four string swaps, and a list of rules about what an upload is
allowed to be, and that mix wants to be readable on its own.

How the whole thing hangs together, since it is not obvious from any one file:

  * A template is one piece of HTML with placeholders in it.  We render it once
    per status code it covers, so the code is filled in before nginx ever sees
    the page.  There is no substitution at request time and nothing dynamic on
    the page at all.
  * The rendered pages go into the config bundle like any other generated file,
    which means they stage, they get tested, they swap into place atomically,
    and they replicate to every node, all through paths that already exist.  No
    second copy of any of that.
  * Pictures are inlined as data URIs, so a finished page carries everything it
    needs.  Nothing to fetch means nothing to be missing at the moment the site
    is already in trouble.

The one thing that bites, and it is a permissions problem rather than an nginx
one: when nginx cannot *read* the file an error_page points at, it throws away
the real status and answers 403.  A 502 turns into a 403 and the log line is
about a file, not about the backend that actually failed.  A file that is
simply *missing* is fine, nginx falls back to its own page and keeps the real
status.  So the rendered pages have to be world readable, because nginx workers
are www-data and everything else we stage is root only.  That is why the agent
writes this one folder with a different mode.
"""
import base64
import html as html_mod
import re

# Where the rendered pages live, and the URI a site's error_page points at.
#
# The path is the same on every node on purpose.  One render goes to the whole
# fleet, so anything node specific in it is an outage on the boxes you did not
# render on.
PAGES_DIR = "errorpages"

# Deliberately ugly, because it shares a URI space with whatever the site
# already serves and a collision means somebody's real page stops working.  The
# location is `internal`, so this is never reachable from outside whatever the
# name is, but it still has to not be a path anybody would have chosen.
URI_PREFIX = "/__nfm_error"

# What nginx will take on an error_page line.  Below 300 is not an error and
# above 599 is not a status.
MIN_CODE = 300
MAX_CODE = 599

# The codes a new template starts out covering.  Everything a site in front of
# a backend actually produces, and nothing that would never reach a browser.
DEFAULT_CODES = [400, 401, 403, 404, 405, 408, 413, 429, 500, 502, 503, 504]

# What each code says on the page when the template asks for {{message}}.
MESSAGES = {
    400: "Bad Request",
    401: "Unauthorized",
    402: "Payment Required",
    403: "Forbidden",
    404: "Not Found",
    405: "Method Not Allowed",
    406: "Not Acceptable",
    408: "Request Timeout",
    409: "Conflict",
    410: "Gone",
    411: "Length Required",
    412: "Precondition Failed",
    413: "Payload Too Large",
    414: "URI Too Long",
    415: "Unsupported Media Type",
    416: "Range Not Satisfiable",
    418: "I'm a teapot",
    421: "Misdirected Request",
    422: "Unprocessable Content",
    425: "Too Early",
    426: "Upgrade Required",
    428: "Precondition Required",
    429: "Too Many Requests",
    431: "Request Header Fields Too Large",
    451: "Unavailable For Legal Reasons",
    500: "Internal Server Error",
    501: "Not Implemented",
    502: "Bad Gateway",
    503: "Service Unavailable",
    504: "Gateway Timeout",
    505: "HTTP Version Not Supported",
    507: "Insufficient Storage",
    508: "Loop Detected",
}

# A friendlier line under the heading, for the codes somebody actually meets.
EXPLANATIONS = {
    400: "The request could not be understood.",
    401: "You need to sign in to see this.",
    403: "You do not have access to this.",
    404: "That page is not here.",
    405: "That is not something this page accepts.",
    408: "The request took too long to arrive.",
    413: "That upload is too big.",
    429: "Too many requests, one moment.",
    500: "Something went wrong at our end.",
    502: "We could not reach the service behind this page.",
    503: "This is temporarily unavailable.",
    504: "The service behind this page took too long to answer.",
}

# Pictures we will take, keyed by the bytes a file of that type starts with.
#
# The check is on the file's own first bytes and not on what the browser said
# it was, because the browser is only repeating the name the uploader typed.
# An .png that is really something else is the ordinary case here, not a clever
# one, and there is no reason to store it.
IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
)

# One picture, and everything one template holds.  A logo and a background is
# the case this is built for.  These travel in every config apply to every node,
# so the ceiling is about what is polite to push around a fleet rather than
# about what a disk can hold.
MAX_IMAGE_BYTES = 256 * 1024
MAX_IMAGES_TOTAL_BYTES = 1024 * 1024

# What one rendered page is allowed to come to, pictures included.  An error
# page is the thing you serve when the site is already struggling, so a page
# that is megabytes of base64 is the wrong answer to that.
MAX_PAGE_BYTES = 512 * 1024

# The whole placeholder language.  There is no expression, no condition and no
# loop, because there is no engine: it is str.replace, four times, on text that
# came out of a form.  Anything that could evaluate what is written here would
# be a way from that form into this process.
PLACEHOLDER_HELP = [
    ("{{code}}", "The status code, like 404."),
    ("{{message}}", "What that code is called, like Not Found."),
    ("{{explain}}", "A plain sentence about what happened, for the codes that "
                    "have one.  Empty for the ones that do not."),
    ("{{image:name}}", "A picture you uploaded.  On its own in the page it "
                       "becomes the picture.  Inside src=\"...\" or a CSS "
                       "url() it becomes just the address, so either works."),
]

_IMAGE_TOKEN = re.compile(r"\{\{image:([A-Za-z0-9._-]{1,128})\}\}")


class ErrorPageProblem(Exception):
    """Something about a template or an upload that has to be said out loud."""


def message_for(code: int) -> str:
    return MESSAGES.get(int(code), "Error")


def explain_for(code: int) -> str:
    return EXPLANATIONS.get(int(code), "")


def valid_codes(raw) -> list:
    """
    Clean up a list of status codes, or say why it cannot be used.

    nginx refuses an error_page outside 300 to 599 and refuses a duplicate for
    the same code in the same block, so both are settled here rather than at
    apply time on somebody else's box.
    """
    out = []
    for item in raw or []:
        try:
            code = int(item)
        except (TypeError, ValueError):
            raise ErrorPageProblem(f"{item!r} is not a status code")
        if code < MIN_CODE or code > MAX_CODE:
            raise ErrorPageProblem(
                f"{code} is not a status code nginx will show a page for.  "
                f"It has to be between {MIN_CODE} and {MAX_CODE}."
            )
        if code not in out:
            out.append(code)
    return sorted(out)


def sniff_image(raw: bytes, declared_name: str = "") -> str:
    """
    Work out what an upload really is, and refuse it if it is not a picture.

    SVG is the exception to reading the first bytes, because it is text and has
    no signature to read.  It is also the only one of these that can carry
    script, so it is checked for that rather than waved through: a browser will
    not run script in an SVG loaded as an image, but the same file dropped into
    a page by somebody later would, and the upload does not know which it will
    be.
    """
    if not raw:
        raise ErrorPageProblem("that file is empty")

    if len(raw) > MAX_IMAGE_BYTES:
        raise ErrorPageProblem(
            f"that picture is {len(raw) // 1024}KB and the limit is "
            f"{MAX_IMAGE_BYTES // 1024}KB.  These get sent to every node on "
            f"every apply, and an error page wants to be small anyway."
        )

    for signature, kind in IMAGE_SIGNATURES:
        if raw.startswith(signature):
            return kind

    head = raw[:1024].lstrip()
    if head.startswith(b"<?xml") or head.startswith(b"<svg"):
        lowered = raw.lower()
        if b"<script" in lowered or b"javascript:" in lowered or b"onload=" in lowered:
            raise ErrorPageProblem(
                "that SVG has script in it.  Pictures on an error page are "
                "pictures, and this one would run as code the moment somebody "
                "put it in the page rather than in an img tag."
            )
        return "image/svg+xml"

    raise ErrorPageProblem(
        f"{declared_name or 'that file'} is not a picture we recognise.  "
        f"PNG, JPEG, GIF, SVG and ICO are the ones that work everywhere."
    )


def data_uri(content_type: str, encoded: str) -> str:
    return f"data:{content_type};base64,{encoded}"


def _needs_bare_uri(text: str, pos: int) -> bool:
    """
    Is the token at this offset somewhere that wants the address on its own?

    Three places want the bare data: address and nothing around it:

      inside a quoted attribute, which is <img src="{{image:logo}}">
      inside a CSS url(), which is background: url({{image:logo}})
      anywhere in a <style> block, which is the same thing spread over lines

    Everywhere else the person has written the token into the body of the page
    on its own, and what they mean by that is "put the picture here".  A bare
    data: address there renders as a screenful of base64, which is what a
    person reported after following the help text to the letter.
    """
    before = text[:pos]

    # In a style block: count the tags, because a </style> closes it.
    if before.count("<style") > before.count("</style"):
        return True

    # In a url(), allowing a quote and spaces after the bracket.
    if re.search(r"url\(\s*[\"']?\s*$", before):
        return True

    # In a tag at all?  If the last angle bracket before us opened one.
    opened = before.rfind("<")
    if opened == -1 or before.rfind(">") > opened:
        return False

    # In a tag, so in a quoted value if the quotes so far are unbalanced.
    quote = None
    for char in before[opened:]:
        if quote:
            if char == quote:
                quote = None
        elif char in "\"'":
            quote = char
    return quote is not None


def render_page(template, code: int, images_by_name: dict = None) -> str:
    """
    Fill one template in for one status code.

    Four string swaps and nothing else.  See PLACEHOLDER_HELP for why it is
    swaps rather than a template engine.
    """
    images_by_name = images_by_name or {}
    text = template.html or ""

    def swap_image(match):
        name = match.group(1)
        found = images_by_name.get(name)
        if not found:
            # A picture that is not there leaves the page short of a picture,
            # which beats leaving the site short of an error page.  The name
            # comes out rather than staying in as a visible {{image:...}}.
            return ""
        uri = data_uri(found["content_type"], found["data"])
        if _needs_bare_uri(text, match.start()):
            return uri
        # On its own in the page, so write the tag as well.  The help text and
        # the toast after an upload both say to put the token in the page, and
        # taking them at their word used to print the data: address as text.
        return f'<img src="{uri}" alt="{html_mod.escape(name)}">'

    text = _IMAGE_TOKEN.sub(swap_image, text)
    text = text.replace("{{code}}", html_mod.escape(str(int(code))))
    text = text.replace("{{message}}", html_mod.escape(message_for(code)))
    text = text.replace("{{explain}}", html_mod.escape(explain_for(code)))
    return text


def images_for(template) -> dict:
    """The pictures a template holds, ready to drop into a page."""
    out = {}
    for image in getattr(template, "images", None) or []:
        out[image.name] = {
            "content_type": image.content_type,
            "data": image.data,
        }
    return out


def rendered_files(template) -> dict:
    """
    Every page one template turns into, as relative path to contents.

    One file per status code, because the code has to be in the page before
    nginx serves it and nginx will not put it there.  They are small and they
    are text, so a dozen of them is nothing.
    """
    folder = f"{PAGES_DIR}/{_folder_name(template.name)}"
    images = images_for(template)

    files = {}
    for code in valid_codes(template.code_list()):
        page = render_page(template, code, images)
        if len(page.encode("utf-8")) > MAX_PAGE_BYTES:
            raise ErrorPageProblem(
                f"the {code} page from {template.name} comes to more than "
                f"{MAX_PAGE_BYTES // 1024}KB with its pictures in it.  Use a "
                f"smaller picture: this is the page you serve when the site is "
                f"already having a bad time."
            )
        files[f"{folder}/{code}.html"] = page
    return files


def _folder_name(name: str) -> str:
    cleaned = re.sub(r"[^A-Za-z0-9._-]", "_", str(name))
    return cleaned[:64] or "unnamed"


def starter_html() -> str:
    """
    What a brand new template starts as.

    Something that already works, because the alternative is an empty box and
    a person guessing at the placeholder names.  No external anything: this is
    served by a site that may well be the reason somebody cannot reach the
    internet right now.
    """
    return """<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{{code}} {{message}}</title>
<style>
  body { font-family: system-ui, -apple-system, "Segoe UI", Arial, sans-serif;
         background: #fff; color: #111; margin: 0;
         display: flex; align-items: center; justify-content: center;
         min-height: 100vh; text-align: center; }
  main { padding: 2rem; max-width: 34rem; }
  .code { font-size: 4rem; font-weight: 700; letter-spacing: -0.02em; margin: 0; }
  .message { font-size: 1.25rem; margin: 0.25rem 0 1rem; }
  .explain { color: #555; line-height: 1.6; margin: 0; }
</style>
</head>
<body>
<main>
  <p class="code">{{code}}</p>
  <p class="message">{{message}}</p>
  <p class="explain">{{explain}}</p>
</main>
</body>
</html>
"""
