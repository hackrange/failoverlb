"""
Saving one setting must not delete the ones that were not on screen.

A settings put replaces the whole blob.  The server keeps no memory of what a
site had before, so whatever the page sends is the entire truth about that
site from then on.

That is fine as long as the page sends everything.  It did not.  The settings
tab leaves out the advanced controls unless the box is ticked, and leaves out
anything the filter box does not match, and the save collected only the
controls that existed.  So:

  turning HTTP/3 on with advanced hidden deleted the site's rewrite rules
  typing "rewrite" in the filter and saving deleted HTTP/3 straight back

Both reported from a live fleet within minutes of each other, which is how a
silent config eater usually shows up: not as one bug but as two that look
unrelated until you notice they are the same shape.

The firewall and geo panels already did this correctly, reading the site back
and merging.  The main Save button did not, in the same file.

Nothing here writes to the database or applies config.

    docker exec -i nginx-fleet-manager python < checks/settings_merge.py
"""
import inspect
import pathlib
import sys

from app.web import routes_api

results = []


def check(name, ok, detail=""):
    results.append(ok)
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:300]}")


print("\n  Saving a setting keeps the rest\n")

# ---------------------------------------------------------------------------
# The server contract the page has to live with.
# ---------------------------------------------------------------------------

# A setting that needs no module, so this says something about the contract
# rather than about how this node's nginx was built.  http3_enabled would be
# the closer match to the bug report, but it is refused outright on a node
# without the module and the point here is not validation.
kept = routes_api._validate_settings({"server_tokens": True}, "server")
check("a partial payload validates to exactly what it was given",
      kept == {"server_tokens": True},
      f"got {kept}, so the server is doing something other than taking the "
      f"payload at face value")

_apply = inspect.getsource(routes_api._apply_host_fields)
check("the host put replaces the settings blob rather than merging it",
      "host.settings = json.dumps(_validate_settings(" in _apply,
      "if this ever starts merging server side, the comment in site_detail "
      "explaining why the page merges is now wrong and should be corrected "
      "rather than left to mislead the next person")

# ---------------------------------------------------------------------------
# The page, which is where the bug was.
# ---------------------------------------------------------------------------

page = pathlib.Path("app/web/templates/site_detail.html").read_text()

# The precondition.  These two filters are why the merge is needed at all: with
# them the tab being open does not mean every control was built.
check("the settings tab can still hide controls",
      "if (f.advanced && !showAdv) return;" in page and "if (filter && !(" in page,
      "if neither filter is left, the merge below is harmless but the reason "
      "for it has gone, so say so rather than leaving a puzzle")

# The regression itself, stated as the thing that must not come back.
check("the site save does not hand the visible controls straight to the put",
      "body.settings = collectSettings(document.getElementById(\"settings-holder\"))"
      not in page,
      "this is the line that ate the rewrites: it sends only what was on "
      "screen, and the put replaces everything")

# Narrowed to the save handler rather than searched for anywhere on the page,
# and the marker is asserted first.  A split on a string that is not there
# quietly hands back the whole file, and every assertion after it then passes
# on the wrong text.  That is not hypothetical: the error page checks in
# checks/regressions.py did it for months against "__nfm_error/ {", which never
# appears because the template name sits in the middle of that path.
check("the save handler can be found to read",
      "saveBtn.disabled = true;" in page,
      "the marker below moved, so the assertions after it are reading the "
      "whole page and mean nothing")
save = page.split("saveBtn.disabled = true;")[0]
check("the site save reads the site back before building the blob",
      'fresh = await NFM.api("/hosts/" + HOST_ID);' in save,
      "without reading back there is nothing to merge onto, and a setting "
      "that was not rendered has no way of surviving the save")

check("it merges onto what came back",
      "Object.assign({}, fresh.settings || {})" in save,
      "the merge is the whole fix")

check("it only touches keys whose control was actually built",
      "[data-setting]" in save and "delete merged[key];" in save,
      "a key with no control must be left exactly as it was, and a control "
      "that was built and left empty must still clear its key, which is what "
      "collectSettings leaving it out has always meant")

check("a failed read back saves nothing at all",
      "Could not read the site back" in save,
      "saving a blob built on a guess is how the config gets eaten quietly")

# ---------------------------------------------------------------------------
# The same shape one level down, which is already safe and has to stay safe.
# ---------------------------------------------------------------------------

# A path's settings dialog builds every control in the location catalog, with
# no advanced switch and no filter, so collecting what is on screen is
# collecting everything.  If somebody ever adds a filter there, this check is
# the one that should start failing.
dialog = page.split("const showSettings = document.getElementById(\"l-show-settings\");")[-1]
dialog = dialog.split("document.getElementById(\"l-save\")")[0]
check("a path's settings dialog still builds every control",
      "f.advanced" not in dialog and "filter" not in dialog,
      "the path dialog has grown a way to hide controls, so its save now has "
      "the same hole the site save had and needs the same read back and merge")

check("the path save still refuses to send an empty blob",
      'lHolder.getAttribute("data-built") === "yes"' in page,
      "a closed section must send no settings at all rather than an empty "
      "object, which would wipe the path's settings")

failed = results.count(False)
print(f"\n  {len(results) - failed} passed, {failed} failed\n")
sys.exit(1 if failed else 0)
