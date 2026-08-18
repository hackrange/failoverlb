"""
A rollback that fails must not leave the node holding config nginx will not load.

Rollback is the oh-no button, so it is the last place that should be able to
leave a box in a state it cannot start from.  It could.  `v_rollback` unpacked
the archive straight over the live folder and only then ran `nginx -t`, and on
a failure it returned and left the bad config there.  Nothing looked wrong at
the time, because nginx carries on serving from what it already has in memory.
The node would come up broken at the next restart instead, which could be a
reboot weeks later, with nothing connecting the two events.

The apply path had always copied the folder aside first for exactly this
reason.  The rollback path had not.  Now it does, and puts it back when the
test fails.

This one runs **on the host, not in the container**, which is the opposite of
everything else in here.  The agent is the half of the system that lives
outside docker, and this loads the file the running service actually runs, so
that a node whose git is current but whose agent was never replaced is caught
rather than assumed:

    python3 checks/rollback.py

It writes into a temporary folder and nowhere else.  MANAGED_DIR and BACKUP_DIR
are pointed at scratch copies, nginx is never invoked, and the live managed
folder is not read or written at any point.
"""
import hashlib
import importlib.util
import shutil
import sys
import tarfile
import tempfile
from pathlib import Path

AGENT = Path("/opt/nginx-fleet-manager/nginx-mgr-agent.py")

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")
    return ok


def load_agent():
    """The deployed file, by path, so this says something about this box."""
    spec = importlib.util.spec_from_file_location("nfm_agent", str(AGENT))
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def tree_hash(path):
    """Every name and every byte under a folder, in a stable order."""
    digest = hashlib.sha256()
    for entry in sorted(Path(path).rglob("*")):
        digest.update(str(entry.relative_to(path)).encode())
        if entry.is_file():
            digest.update(entry.read_bytes())
    return digest.hexdigest()[:16]


print("\n  a rollback that fails leaves the node the way it was\n")

if not AGENT.is_file():
    print(f"    {AGENT} is not on this box, so this check cannot run")
    sys.exit(0)

agent = load_agent()

root = Path(tempfile.mkdtemp(prefix="nfm-rollback-check-"))
managed = root / "nginxmgr"
backups = root / "backups"
backups.mkdir()
agent.MANAGED_DIR = managed
agent.BACKUP_DIR = backups

# The set aside copy the fix makes, named the way the agent names it.
aside = managed.parent / (managed.name + ".before-rollback")

LIVE = "server { listen 80; server_name live.example; }\n"


def make_managed(text=LIVE):
    if managed.exists():
        shutil.rmtree(managed)
    (managed / "sites").mkdir(parents=True)
    (managed / "sites" / "site.conf").write_text(text)


def make_backup(name, text):
    stage = root / "stage"
    if stage.exists():
        shutil.rmtree(stage)
    (stage / "nginxmgr" / "sites").mkdir(parents=True)
    (stage / "nginxmgr" / "sites" / "site.conf").write_text(text)
    with tarfile.open(backups / name, "w:gz") as tar:
        tar.add(str(stage / "nginxmgr"), arcname="nginxmgr")


def config_test_fails(req):
    return {"ok": False, "output": 'unknown directive "wibble_directive"'}


def config_test_passes(req):
    return {"ok": True, "output": "syntax is ok"}


try:
    # ---- the archive nginx will not load, which is the whole point ----------
    make_managed()
    was = tree_hash(managed)
    make_backup("bad.tar.gz", "wibble_directive on;\n")
    agent.v_config_test = config_test_fails
    agent.v_reload = lambda req: {"ok": True, "output": "reloaded"}

    answer = agent.v_rollback({"name": "bad.tar.gz"})
    check("it is refused", answer["ok"] is False)
    check("it says the node was left alone",
          "nothing changed" in answer.get("note", ""), answer.get("note", ""))
    check("nothing is reported as restored", answer.get("restored") is None)
    check("the managed folder is byte for byte what it was",
          tree_hash(managed) == was)
    check("the bad directive is nowhere on disk",
          "wibble_directive" not in (managed / "sites" / "site.conf").read_text())
    check("the copy it set aside was cleaned up", not aside.exists())

    # ---- and a good one still rolls back, or the fix is just a block --------
    make_managed()
    make_backup("good.tar.gz", "server { listen 8080; server_name old.example; }\n")
    agent.v_config_test = config_test_passes
    reloads = []
    agent.v_reload = lambda req: (reloads.append(1), {"ok": True, "output": "reloaded"})[1]

    answer = agent.v_rollback({"name": "good.tar.gz"})
    check("a good archive still succeeds", answer["ok"] is True)
    check("it names what it put back", answer.get("restored") == "good.tar.gz")
    check("the archive's config is what is on disk now",
          "8080" in (managed / "sites" / "site.conf").read_text())
    check("nginx was reloaded once", len(reloads) == 1)
    check("the copy it set aside was cleaned up after a success",
          not aside.exists())

    # ---- a run that was killed leaves a copy behind; the next one must cope --
    # Worth checking because the fix removes the old copy before making a new
    # one, and getting that wrong turns one interrupted rollback into a node
    # that can never roll back again.
    make_managed()
    was = tree_hash(managed)
    aside.mkdir()
    (aside / "junk.conf").write_text("left behind by a run that was killed\n")
    agent.v_config_test = config_test_fails

    answer = agent.v_rollback({"name": "bad.tar.gz"})
    check("a retry after an interrupted run is still refused cleanly",
          answer["ok"] is False)
    check("and still leaves the managed folder untouched",
          tree_hash(managed) == was)
    check("the stale copy was replaced rather than kept", not aside.exists())
finally:
    shutil.rmtree(root, ignore_errors=True)

failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: a failed rollback leaves the node the way it was "
      f"({len(results)} checks)\n")
