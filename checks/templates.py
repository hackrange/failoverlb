"""
Template checks for the ways a page can look finished and do nothing.

Jinja will not catch these.  A template with an unclosed block still parses,
because everything after it is simply content belonging to that block.  The
page renders, returns 200, and quietly does none of what was written into it.

    python checks/templates.py

Run from the repository root.  Reads files only, so it is safe anywhere.
"""
import pathlib
import re
import sys

TEMPLATES = pathlib.Path("app/web/templates")
problems = []


def check(name, ok, detail=""):
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if not ok:
        print(f"          {detail}")
        problems.append(name)


files = sorted(TEMPLATES.glob("*.html"))
print(f"  {len(files)} templates")
print()

# 1. Every block closes.
unbalanced = []
for p in files:
    t = p.read_text()
    opens = len(re.findall(r"\{%-?\s*block\s", t))
    closes = len(re.findall(r"\{%-?\s*endblock", t))
    if opens != closes:
        unbalanced.append(f"{p.name}: {opens} block, {closes} endblock")
check("every block is closed", not unbalanced, "; ".join(unbalanced))

# 2. A title block holding markup means its endblock is missing and the rest
#    of the file has been swallowed into the title tag, where a browser treats
#    it as text.  That is how the dashboard script stopped running: no request,
#    no error, and a panel that said Loading forever.
swallowed = []
for p in files:
    for m in re.finditer(r"\{%-?\s*block\s+title\s*-?%\}(.*?)\{%-?\s*endblock",
                         p.read_text(), re.S):
        if "<" in m.group(1):
            swallowed.append(f"{p.name}: {m.group(1).strip().splitlines()[0][:50]}")
check("no title block contains markup", not swallowed, "; ".join(swallowed))

# 3. A block the layout does not render is content that never reaches the page.
base = (TEMPLATES / "base.html").read_text()
defined = set(re.findall(r"\{%-?\s*block\s+(\w+)", base))
orphans = []
for p in files:
    t = p.read_text()
    if "extends" not in t:
        continue
    for name in set(re.findall(r"\{%-?\s*block\s+(\w+)", t)):
        if name not in defined:
            orphans.append(f"{p.name} defines '{name}'")
check("every block a page defines is one the layout renders",
      not orphans, "; ".join(orphans))

# 4. A page using the shared helpers has to wait for them.  app.js is loaded
#    after the page's own script, so touching NFM while the script is being
#    read throws before anything is wired up, and the page sits there.
#
#    Only top level use matters.  NFM inside a function or an event handler is
#    fine, because none of that runs until somebody clicks something, by which
#    time app.js has long since loaded.  Flagging those too would make this
#    check cry wolf on pages that work, and a check people learn to ignore is
#    worse than no check.
def top_level_nfm(text):
    """Lines mentioning NFM while no brace is open, inside a script block."""
    found, depth, in_script = [], 0, False
    for line in text.split("\n"):
        if "<script" in line:
            in_script, depth = True, 0
            continue
        if "</script" in line:
            in_script = False
            continue
        if not in_script:
            continue
        if depth == 0 and "NFM." in line:
            found.append(line.strip()[:50])
        depth += line.count("{") - line.count("}")
    return found

impatient = []
for p in files:
    hits = top_level_nfm(p.read_text())
    if hits:
        impatient.append(f"{p.name}: {hits[0]}")
check("no page touches NFM before the helpers are loaded",
      not impatient, "; ".join(impatient))

# 5. An id compared against something read off the DOM has to be compared as
#    a string.  Every dataset value and every getAttribute result is a string,
#    and most of these ids are integers from the database, so a strict compare
#    is false every time.  Nothing throws.  The button simply does nothing,
#    which is the hardest kind of broken to find, because there is no error
#    anywhere and the page looks fine.
#
#    This cost an afternoon on the tunnel page, where Remove silently did
#    nothing, and site_detail.html already had the String() wrapper because
#    somebody had hit it there first.
LOOSE_ID = re.compile(
    r"(?<!String\()\b[a-zA-Z_$][\w$]*\.id\s*===\s*"
    r"(?!String\()[a-zA-Z_$][\w$]*\.(?:dataset\.\w+|getAttribute\()")

loose = []
for p in files:
    for n, line in enumerate(p.read_text().split("\n"), 1):
        if LOOSE_ID.search(line):
            loose.append(f"{p.name}:{n} {line.strip()[:60]}")
check("ids compared against the DOM are compared as strings",
      not loose, "; ".join(loose))

# N. Every input type a template uses is one the stylesheet actually styles.
#
#    The stylesheet lists input types by name, which is a trap that has caught
#    this project twice.  A type that is not on the list gets no border, no
#    padding and no radius, and falls back to whatever the browser draws, so it
#    is a differently shaped box sitting next to the others.  Both times it was
#    reported as "that field looks wrong", and both times the cause was one
#    missing word in a css selector rather than anything in the template.
#
#    Types that are deliberately styled elsewhere or not at all are listed
#    here rather than found, because a checkbox is meant to look like a
#    checkbox.
STYLED_ELSEWHERE = {"checkbox", "radio", "hidden", "submit", "button", "file",
                    "range", "color"}

#    Looked for in the rule that actually draws the box, not anywhere in the
#    file.  The first version of this asked whether the type appeared in any
#    `input[type=...]` selector at all, which the pseudo element rule for the
#    search field's clear button satisfies without styling the field itself.
#    So the check passed while the bug it exists to catch was present, which is
#    the exact failure mode the README warns about.
css = pathlib.Path("app/web/static/app.css").read_text()

styled = set()
for rule in css.split("}"):
    if "{" not in rule:
        continue
    selector, body = rule.split("{", 1)
    # The canonical text field rule: the one that names input[type=text] and
    # sets a border.  Anything sharing that selector list is drawn the same.
    if "input[type=text]" in selector and "border:" in body:
        styled.update(re.findall(r"input\[type=([a-z]+)\]", selector))

used = {}
for p in files:
    for n, line in enumerate(p.read_text().split("\n"), 1):
        for kind in re.findall(r'<input[^>]*\btype="([a-z]+)"', line):
            used.setdefault(kind, f"{p.name}:{n}")

unstyled = [f"{k} ({where})" for k, where in sorted(used.items())
            if k not in styled and k not in STYLED_ELSEWHERE]
check("every input type in a template is styled by the stylesheet",
      not unstyled,
      "these fall back to the browser's own look, which is a different shaped "
      "box next to the others.  Add the type to the input selector in "
      "app.css: " + "; ".join(unstyled))


# N. The inline JavaScript parses.
#
#    This is the most expensive failure a template can have and the quietest.
#    A syntax error anywhere in an inline script means the browser runs none of
#    it, so no handler is registered, no data is fetched, and the page sits on
#    whatever the server rendered.  The Tunnel page did exactly that for
#    fourteen minutes: it said "Loading..." forever, every request for the page
#    returned 200, the API behind it was healthy, and nothing anywhere logged a
#    thing.  The cause was one character, a single quoted string closed with a
#    double quote.
#
#    There is no JavaScript engine in this repo or in the container, so this
#    does not parse the language.  It checks the one thing that actually goes
#    wrong when a person edits generated markup by hand: whether strings,
#    template literals and their ${...} interpolations balance.  That is a
#    smaller claim than "this is valid JavaScript" and it would have caught the
#    bug that prompted it.
print()
print("  the inline JavaScript balances")



# Whether a slash here starts a regular expression rather than dividing.
#
# The classic ambiguity in tokenising JavaScript, and it matters: a regex like
# /"?([^"]+)"?/ is full of quotes that are not string quotes, and reading them
# as strings turns a healthy file into a reported error.  The rule is what the
# previous meaningful token was.  After a value (name, number, closing bracket)
# a slash divides; after an operator, a comma, an opening bracket or one of a
# few keywords, it opens a regex.
_BEFORE_REGEX = set("(,=:[!&|?{};+-*%~^<>")
_KEYWORDS_BEFORE_REGEX = ("return", "typeof", "case", "in", "of", "new",
                          "delete", "void", "instanceof", "do", "else")


def _regex_here(js, i):
    if js[i + 1:i + 2] in ("", "/", "*"):
        return False
    j = i - 1
    while j >= 0 and js[j] in " \t\n\r":
        j -= 1
    if j < 0:
        return True
    if js[j] in _BEFORE_REGEX:
        return True
    k = j
    while k >= 0 and (js[k].isalnum() or js[k] == "_"):
        k -= 1
    return js[k + 1:j + 1] in _KEYWORDS_BEFORE_REGEX


def scan(js):
    """Balance of strings, template literals and interpolations."""
    i, line = 0, 1
    stack = []          # ("tpl", line) or ("interp", depth, line)
    while i < len(js):
        c = js[i]
        if c == "\n":
            line += 1; i += 1; continue
        if c == "/" and js[i+1:i+2] == "/":
            j = js.find("\n", i)
            if j < 0: break
            i = j; continue
        if c == "/" and _regex_here(js, i):
            j = i + 1
            while j < len(js):
                if js[j] == "\\": j += 2; continue
                if js[j] == "[": 
                    while j < len(js) and js[j] != "]":
                        if js[j] == "\\": j += 1
                        j += 1
                if js[j] == "\n": break
                if js[j] == "/": break
                j += 1
            if j < len(js) and js[j] == "/":
                i = j + 1
                continue
        if c == "/" and js[i+1:i+2] == "*":
            j = js.find("*/", i)
            if j < 0: return "unterminated /* */", stack
            line += js.count("\n", i, j); i = j + 2; continue
        if c in "'\"":
            q, j = c, i + 1
            while j < len(js):
                if js[j] == "\\": j += 2; continue
                if js[j] == "\n": return f"unterminated {q} string opened at line {line}", stack
                if js[j] == q: break
                j += 1
            else:
                return f"unterminated {q} string opened at line {line}", stack
            i = j + 1; continue
        if c == "`":
            stack.append(("tpl", line)); i += 1
            # scan template text until ` or ${
            while i < len(js):
                if js[i] == "\\": i += 2; continue
                if js[i] == "\n": line += 1; i += 1; continue
                if js[i] == "`":
                    stack.pop(); i += 1; break
                if js[i] == "$" and js[i+1:i+2] == "{":
                    stack.append(("interp", 0, line)); i += 2; break
                i += 1
            continue
        if stack and stack[-1][0] == "interp":
            if c == "{":
                k = stack[-1]; stack[-1] = ("interp", k[1] + 1, k[2])
            elif c == "}":
                k = stack[-1]
                if k[1] == 0:
                    stack.pop()          # end of ${ }
                    # resume the template text that opened it
                    i += 1
                    while i < len(js):
                        if js[i] == "\\": i += 2; continue
                        if js[i] == "\n": line += 1; i += 1; continue
                        if js[i] == "`":
                            if stack and stack[-1][0] == "tpl": stack.pop()
                            i += 1; break
                        if js[i] == "$" and js[i+1:i+2] == "{":
                            stack.append(("interp", 0, line)); i += 2; break
                        i += 1
                    continue
                stack[-1] = ("interp", k[1] - 1, k[2])
        i += 1
    return ("" if not stack else "unbalanced"), stack


def _js_problems(text, label):
    pos, problems = 0, []
    while True:
        try: s0 = text.index("<script", pos)
        except ValueError: break
        s1 = text.index(">", s0) + 1
        s2 = text.index("</script>", s1)
        before = text[:s1].count("\n") + 1
        msg, stack = scan(text[s1:s2])
        if msg:
            where = [f"{k[0]} opened at file line {before + k[-1] - 1}" for k in stack]
            problems.append(f"{label}: {msg}; {'; '.join(where) or 'no open context'}")
        pos = s2 + 1
    return problems


unbalanced = []
for p in files:
    unbalanced.extend(_js_problems(p.read_text(), p.name))
check("every inline script closes its strings and template literals",
      not unbalanced,
      "a parse error means the browser runs none of the script, so the page "
      "renders and then does nothing at all: " + "; ".join(unbalanced))


# N. A tab left open across an upgrade can tell.
#
#    Most of this GUI's JavaScript is inline in the templates, and a page
#    already loaded is never re-fetched however good the cache headers are.  So
#    a tab open across an upgrade keeps running the old script, and the
#    failures look like bugs in the feature rather than an old page: a form
#    missing a field that shipped, a button calling an endpoint that moved.
#    Both were reported as faults in one afternoon.
#
#    Three things have to line up for the tab to notice, and any one of them
#    quietly missing brings the whole thing back.
print()
print("  an old tab can tell it is old")

_base = (TEMPLATES / "base.html").read_text()
check("the layout stamps every page with the build it came from",
      'name="nfm-build"' in _base and "asset_version" in _base,
      "without the stamp on the page there is nothing to compare against")

_js = pathlib.Path("app/web/static/app.js").read_text()
check("the api helper compares that stamp against every answer",
      "X-NFM-Build" in _js and "checkBuild" in _js,
      "the comparison rides on requests the page already makes, so if it is "
      "not here it happens nowhere")

_sec = pathlib.Path("app/web/security.py").read_text()
check("the server puts the build on every response",
      "X-NFM-Build" in _sec,
      "the page can compare all it likes if nothing sends it the answer")

_pages = pathlib.Path("app/web/routes_pages.py").read_text()
check("the stamp covers the templates, not only the css and the js",
      "TEMPLATE_DIR.glob" in _pages,
      "this is the part that makes it work at all.  The inline script lives in "
      "the template, so a stamp built only from app.js and app.css does not "
      "change when the thing the browser is actually running changes")


print()
print(f"  {len(problems)} problem(s)")
sys.exit(1 if problems else 0)
