"""
Turning an error page template into the HTML nginx will serve.

Separate from render.py because none of this is nginx config: it is user
HTML, a few string swaps, and rules for what an upload may be.

  - A template is rendered once per status code it covers, so the code is
    baked in before nginx sees the page.  Nothing happens at request time.
  - Rendered pages go into the config bundle like any generated file, so
    they are staged, tested, swapped in atomically and replicated.
  - Images are inlined as data URIs, so a page has nothing to fetch while
    the site is already in trouble.

Gotcha: if nginx cannot read the file an error_page points at, it answers
403 instead of the real status, and the log talks about a file rather than
the failed backend.  (A missing file is fine; nginx falls back to its own
page.)  So these pages must be world readable for www-data, while everything
else we stage is root only.  The agent writes this folder with a different
mode for that reason.
"""
import base64
import html as html_mod
import re

# Where rendered pages live.  Same path on every node, since one render is
# shipped to the whole fleet.
PAGES_DIR = "errorpages"

# Deliberately odd so it can't collide with a real path on the site.  The
# location is `internal`, so it is never reachable from outside.
URI_PREFIX = "/__nfm_error"

# Range nginx accepts on an error_page line.
MIN_CODE = 300
MAX_CODE = 599

# Codes a new template covers by default: what a proxied site commonly
# returns.
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

# Friendlier line under the heading, for the common codes.
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

# Accepted image types, by magic bytes.  We check the content rather than
# the declared type, which only reflects the filename.
IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
    (b"\x00\x00\x01\x00", "image/x-icon"),
)

# Per image and per template limits.  Images travel with every apply to
# every node, so keep them small (a logo and a background).
MAX_IMAGE_BYTES = 256 * 1024
MAX_IMAGES_TOTAL_BYTES = 1024 * 1024

# Limit for one rendered page, images included.  Error pages are served when
# the site is already struggling.
MAX_PAGE_BYTES = 512 * 1024

# The entire placeholder language.  Plain str.replace, no template engine,
# so nothing typed into the form can be evaluated in this process.
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
    """A template or upload problem to show the user."""


def message_for(code: int) -> str:
    return MESSAGES.get(int(code), "Error")


def explain_for(code: int) -> str:
    return EXPLANATIONS.get(int(code), "")


def valid_codes(raw) -> list:
    """
    Validate, dedupe and sort status codes.  nginx rejects codes outside
    300-599 and duplicates in one block, so catch both here rather than at
    apply time.
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
    Return the content type of an uploaded image, or raise.

    SVG is text with no magic bytes, and it can carry script.  Browsers don't
    run script in an SVG loaded via <img>, but the same file inlined into a
    page would, so SVGs with script are refused.
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
    Does the token at this offset want just the data: URI?

    True inside a quoted attribute (<img src="{{image:logo}}">), inside a CSS
    url(), or anywhere in a <style> block.  Elsewhere the token stands alone
    in the page and should become an <img> tag; a bare URI there would render
    as a screen of base64.
    """
    before = text[:pos]

    # Inside a <style> block?
    if before.count("<style") > before.count("</style"):
        return True

    # In a url(), allowing a quote and spaces after the bracket.
    if re.search(r"url\(\s*[\"']?\s*$", before):
        return True

    # Inside a tag at all?
    opened = before.rfind("<")
    if opened == -1 or before.rfind(">") > opened:
        return False

    # Inside a quoted value if the quotes so far are unbalanced.
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
    Fill in one template for one status code.  Plain string swaps; see
    PLACEHOLDER_HELP.
    """
    images_by_name = images_by_name or {}
    text = template.html or ""

    def swap_image(match):
        name = match.group(1)
        found = images_by_name.get(name)
        if not found:
            # Missing image: drop the token rather than fail the page.
            return ""
        uri = data_uri(found["content_type"], found["data"])
        if _needs_bare_uri(text, match.start()):
            return uri
        # Standalone token: emit a full <img> tag.
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
    All pages one template renders to, as {relative path: contents}.  One
    file per status code, since nginx can't fill the code in itself.
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
    Starting HTML for a new template: a working example of the
    placeholders, with no external resources.
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
