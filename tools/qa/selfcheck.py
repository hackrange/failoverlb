"""
Check the suites before they are run against anything.

Two mistakes have already been made here that cost a run each, and both are
cheap to catch by reading the files:

  A placeholder inside a plain string.  Rewriting the suites to take the test
  domain from the environment turned "site.example.net" into "site.{qa.DOMAIN}"
  in a few strings that were not f-strings, so the literal braces went into a
  hostname and the tests looked for a site that could not exist.

  A hardcoded address.  A suite that names somebody's lab only ever runs on
  that lab, and the addresses of the machines it was written against belong in
  the environment rather than in the repository.

    python3 tools/qa/selfcheck.py
"""
import pathlib
import re
import sys

HERE = pathlib.Path(__file__).parent
PLACEHOLDER = re.compile(r"\{qa\.[A-Z_]+\}")
STRING_START = re.compile(r"""(?<![A-Za-z0-9_])(f?)(['"])""")
ADDRESS = re.compile(r"\b(?:10|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")

problems = []

for path in sorted(HERE.glob("*.py")):
    if path.name == "selfcheck.py":
        continue
    for number, line in enumerate(path.read_text().splitlines(), start=1):
        bare = line.split("#")[0]

        if PLACEHOLDER.search(bare) and "%(" not in bare:
            # Find the quote that opens the string the placeholder sits in, and
            # check it was an f-string.
            before = bare[:PLACEHOLDER.search(bare).start()]
            opens = STRING_START.findall(before)
            if opens and opens[-1][0] != "f":
                problems.append(
                    f"{path.name}:{number}  a placeholder in a plain string, so "
                    f"the braces go into the value as text")

        for found in ADDRESS.findall(bare):
            if found.startswith("127."):
                continue
            problems.append(
                f"{path.name}:{number}  the address {found} is written into the "
                f"suite; it belongs in the environment")

if problems:
    print("These need fixing before the suites are run:\n")
    for line in problems:
        print("  " + line)
    sys.exit(1)

print(f"checked {len(list(HERE.glob('*.py'))) - 1} files, nothing to fix")
