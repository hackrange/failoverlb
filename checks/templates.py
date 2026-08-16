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


print()
print(f"  {len(problems)} problem(s)")
sys.exit(1 if problems else 0)
