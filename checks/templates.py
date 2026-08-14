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

print()
print(f"  {len(problems)} problem(s)")
sys.exit(1 if problems else 0)
