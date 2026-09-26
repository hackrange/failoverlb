#!/usr/bin/env python3
"""
Failover LB host agent.

This runs as root on the nginx box, outside the container.  The container is
not root and cannot write to /etc/nginx or restart anything.  When it needs
something done on the host it asks this agent over a unix socket, and the agent
decides whether to do it.

That is the whole point.  The container is the big pile of code with a web
server in it, so we treat it as the thing most likely to get popped.  This file
is small enough to actually read start to finish, and it is the only thing here
running as root.

Rules this agent lives by:

  1. There is a fixed list of verbs.  Anything not on the list is refused.
     There is no "run this command" verb and there never will be.
  2. Every path gets checked against an allow list before we touch it.  We
     resolve the real path first, so symlinks and ../ do not get you out.
  3. Config changes get staged, tested with nginx -t, and only then moved into
     place.  A config that does not pass never reaches a running server.
  4. Every reload keeps a numbered backup, so putting it back is one call.
  5. Everything gets logged with the verb and the caller's uid.

Talk to it with newline delimited JSON.  One request per line, one response per
line.  See VERBS at the bottom for the list.
"""

import grp
import hashlib
import json
import logging
import logging.handlers
import os
import pwd
import re
import shutil
import signal
import socket
import socketserver
import struct
import subprocess
import sys
import tarfile
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path, PurePosixPath

# ==============================================================================
# Settings
# ==============================================================================

AGENT_VERSION = "1.0.0"


def _own_fingerprint():
    """
    A short hash of this file, as it was when the running process read it.

    AGENT_VERSION is a number somebody has to remember to change, so it says
    nothing about whether the agent running right now is the one in the repo.
    That question matters here more than in most places: the agent lives
    outside the container, so the normal upgrade of pulling and rebuilding the
    image leaves it exactly as it was, running last month's code against this
    month's manager, with nothing anywhere saying so.

    Computed once at start up on purpose.  Reading it fresh would report what
    is on disk rather than what is loaded, which is the opposite of the
    question being asked.
    """
    try:
        return hashlib.sha256(Path(__file__).read_bytes()).hexdigest()[:12]
    except Exception:
        return "unknown"


AGENT_FINGERPRINT = _own_fingerprint()

SOCKET_DIR = Path(os.environ.get("NFM_AGENT_SOCKET_DIR", "/run/nginxmgr"))
SOCKET_PATH = SOCKET_DIR / "agent.sock"
SOCKET_GROUP = os.environ.get("NFM_AGENT_GROUP", "nginxmgr")

NGINX_PREFIX = Path(os.environ.get("NFM_NGINX_PREFIX", "/etc/nginx"))
NGINX_BIN = Path(os.environ.get("NFM_NGINX_BIN", "/usr/sbin/nginx"))
LETSENCRYPT_DIR = Path("/etc/letsencrypt")
ACME_WEBROOT = Path(os.environ.get("NFM_ACME_WEBROOT", "/var/www/certbot"))

# Everything we generate lives under here.  Keeping it in one folder means we
# never have to guess whether a file is ours or something a person wrote by
# hand, and blowing away our own config never touches theirs.
MANAGED_DIR = NGINX_PREFIX / "nginxmgr"

# Where we stage a config before testing it.
STAGING_DIR = NGINX_PREFIX / ".nginxmgr-staging"

# A throwaway copy of the staging folder, used only when a staged file names
# the live bundle in a path nginx opens while loading the config.  See
# _staging_for_test.  Never applied and never moved anywhere.
TEST_DIR = NGINX_PREFIX / ".nginxmgr-test"

# The throwaway nginx.conf we test a staged config with.
#
# This has to sit in the prefix folder itself, next to the real nginx.conf, and
# that is not a style choice.  nginx resolves a relative include against the
# folder the config file is in, not against whatever you passed to -p.  The
# stock nginx.conf has "include mime.types;" in it, so a candidate written
# anywhere else looks for mime.types beside itself, does not find it, and the
# test fails for a reason that has nothing to do with the config you changed.
CANDIDATE_CONF = NGINX_PREFIX / ".nginxmgr-candidate.conf"

# Marker on the include block we add to nginx.conf.  It carries a version so a
# future release can tell an out of date block from a current one and replace
# it, rather than leaving a node quietly running an old set of includes.
INCLUDE_MARKER = "# failover lb includes, v5.  Do not reorder."

# Numbered backups of the managed folder, one per apply.
BACKUP_DIR = Path("/var/backups/nginx-fleet-manager")
BACKUP_KEEP = 30

# The installer script that builds nginx from source.  Rebuilding nginx is the
# only way to add or drop a module, since they are compiled in, so upgrading
# the version and changing the module list are the same operation.
INSTALLER = Path(os.environ.get("NFM_INSTALLER", "/opt/nginx-installer.sh"))

# Where a running build writes what it is doing.  A build takes ten to twenty
# minutes, far longer than any sensible request timeout, so it runs detached and
# the manager reads progress from here.
UPGRADE_STATE = Path("/var/lib/nginx-fleet-manager/upgrade.json")
UPGRADE_LOG = Path("/var/log/nginx-fleet-manager-upgrade.log")

# How long any host command gets before we give up on it.  Certbot gets its own
# longer budget since it waits on a remote server.
DEFAULT_TIMEOUT = 60
CERTBOT_TIMEOUT = 300

# Biggest request we will read.  A big site config is a few KB, so this is
# already generous.  It is here so a bad or hostile caller cannot make us eat
# all the memory on the box.
MAX_REQUEST_BYTES = 8 * 1024 * 1024

# Paths the agent is allowed to write.  Anything outside these is refused, and
# we check after resolving symlinks so you cannot point a link somewhere else
# and ride it out of the sandbox.
WRITE_ALLOWED = (
    MANAGED_DIR,
    STAGING_DIR,
    TEST_DIR,
    ACME_WEBROOT / ".well-known" / "acme-challenge",
    NGINX_PREFIX / "conf.d",
    NGINX_PREFIX / "snippets",
)

# Paths the agent is allowed to read.  Wider than the write list, because the
# GUI shows you the running config and the certs, but still not the whole disk.
READ_ALLOWED = (
    NGINX_PREFIX,
    LETSENCRYPT_DIR,
    ACME_WEBROOT,
    BACKUP_DIR,
)

# Inside conf.d and snippets we only get to touch our own files.  Those two
# folders are shared with whatever the installer and the admins put there, and
# clobbering somebody's hand written snippet would be a bad day.
MANAGED_FILE_PREFIX = "nginxmgr-"

log = logging.getLogger("nfm-agent")


# ==============================================================================
# Errors
# ==============================================================================

class AgentError(Exception):
    """Something the caller did wrong.  Gets reported back, not logged as a crash."""

    def __init__(self, message, code="error"):
        super().__init__(message)
        self.message = message
        self.code = code


# ==============================================================================
# Path checking
# ==============================================================================

def _resolve(path_str):
    """
    Turn whatever the caller sent into a real absolute path.

    We resolve the whole thing, including symlinks, before anybody gets to
    compare it against the allow list.  Checking the string the caller sent is
    how you end up serving /etc/shadow because someone put a symlink in a
    folder you trusted.
    """
    if not isinstance(path_str, str) or not path_str:
        raise AgentError("path has to be a non empty string", "bad_path")
    if "\x00" in path_str:
        raise AgentError("path has a null byte in it", "bad_path")

    p = Path(path_str)
    if not p.is_absolute():
        raise AgentError(f"path has to be absolute, got {path_str}", "bad_path")

    # strict=False so we can also resolve a file that does not exist yet, which
    # is the normal case when we are creating one.  The parent still has to be
    # real, and resolve() walks the symlinks that do exist.
    return p.resolve(strict=False)


def _under_any(path, roots):
    for root in roots:
        try:
            path.relative_to(root.resolve(strict=False))
            return True
        except ValueError:
            continue
    return False


def check_write_path(path_str):
    """Resolve a path and make sure we are allowed to write it."""
    p = _resolve(path_str)

    # The candidate config is the one file we write straight into the prefix
    # folder, and only this exact name.  See CANDIDATE_CONF for why it cannot
    # live in the staging folder with everything else.
    if p == CANDIDATE_CONF.resolve(strict=False):
        return p

    if not _under_any(p, WRITE_ALLOWED):
        raise AgentError(f"not allowed to write outside the managed paths: {p}", "denied")

    # conf.d and snippets are shared ground.  Only our own files there.
    for shared in (NGINX_PREFIX / "conf.d", NGINX_PREFIX / "snippets"):
        try:
            rel = p.relative_to(shared.resolve(strict=False))
        except ValueError:
            continue
        if not rel.name.startswith(MANAGED_FILE_PREFIX):
            raise AgentError(
                f"in {shared} we only touch files starting with {MANAGED_FILE_PREFIX}",
                "denied",
            )

    return p


def check_read_path(path_str):
    """Resolve a path and make sure we are allowed to read it."""
    p = _resolve(path_str)
    if not _under_any(p, READ_ALLOWED):
        raise AgentError(f"not allowed to read outside the managed paths: {p}", "denied")

    # Private keys are the one thing we hand out, and only from the place
    # certbot puts them.  If a caller can talk us into reading a key from some
    # other folder, that is a way to pull keys off the box.
    if p.name.endswith((".pem", ".key")) and "privkey" in p.name:
        if not _under_any(p, (LETSENCRYPT_DIR,)):
            raise AgentError("private keys only come out of /etc/letsencrypt", "denied")

    return p


# ==============================================================================
# Running things
# ==============================================================================

# Flags whose value must never reach a log.  The command line is only logged at
# debug level, which nobody runs by default, and "nobody runs it by default" is
# exactly the assumption that fails: somebody turns debug on to work out why a
# certificate will not issue, and the credential for the account lands in the
# journal where it stays.
SECRET_FLAGS = {
    "--eab-hmac-key",
    "--eab-kid",
}


def _safe_for_log(cmd):
    """The command with any credential replaced, for logging only."""
    out, hide_next = [], False
    for part in cmd:
        if hide_next:
            out.append("[hidden]")
            hide_next = False
            continue
        out.append(part)
        if part in SECRET_FLAGS:
            hide_next = True
    return out


def run(cmd, timeout=DEFAULT_TIMEOUT, input_text=None, env_extra=None):
    """
    Run a command and hand back what happened.

    Always a list, never a string, and shell=False.  Nothing the caller sends
    ever becomes part of a shell line, so there is no quoting bug waiting to
    turn into command injection.
    """
    log.debug("running: %s", " ".join(_safe_for_log(cmd)))

    env = None
    if env_extra:
        env = os.environ.copy()
        env.update(env_extra)

    try:
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
            input=input_text,
            shell=False,
            env=env,
        )
    except subprocess.TimeoutExpired:
        raise AgentError(f"{cmd[0]} ran longer than {timeout}s and got killed", "timeout")
    except FileNotFoundError:
        raise AgentError(f"{cmd[0]} is not installed on this box", "missing_binary")

    return {
        "rc": proc.returncode,
        "stdout": proc.stdout or "",
        "stderr": proc.stderr or "",
    }


def systemctl(*args, timeout=DEFAULT_TIMEOUT):
    return run(["systemctl", *args], timeout=timeout)


def have_systemd():
    return Path("/run/systemd/system").is_dir() and shutil.which("systemctl") is not None


# ==============================================================================
# Writing files without leaving a half written one behind
# ==============================================================================

def atomic_write(path, content, mode=0o644, owner=None):
    """
    Write a file so a reader never sees it half done.

    Write to a temp file in the same folder, fsync it, then rename over the
    target.  Rename inside one filesystem is atomic, so nginx either reads the
    old file or the new one.  It never catches us mid write, which as far as
    nginx is concerned would just be a broken config.
    """
    path.parent.mkdir(parents=True, exist_ok=True)

    fd, tmp_name = tempfile.mkstemp(dir=str(path.parent), prefix=".nfm-tmp-")
    tmp = Path(tmp_name)
    try:
        with os.fdopen(fd, "w") as fh:
            fh.write(content)
            fh.flush()
            os.fsync(fh.fileno())
        os.chmod(tmp, mode)
        if owner:
            try:
                pw = pwd.getpwnam(owner)
                os.chown(tmp, pw.pw_uid, pw.pw_gid)
            except KeyError:
                log.warning("user %s does not exist, leaving the file owned by root", owner)
        os.replace(tmp, path)

        # fsync the folder too, or the rename can still be sitting in a buffer
        # when the power goes out and you come back up to no file at all.
        dir_fd = os.open(str(path.parent), os.O_RDONLY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    except Exception:
        tmp.unlink(missing_ok=True)
        raise


# ==============================================================================
# Backups
# ==============================================================================

def make_backup(label="apply"):
    """
    Tar up the managed config folder before we change it.

    Cheap, since it is only our own files, and it means every apply has a way
    back that does not involve remembering what the config used to say.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{label}.tar.gz"
    dest = BACKUP_DIR / name

    if MANAGED_DIR.is_dir():
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(str(MANAGED_DIR), arcname="nginxmgr")
    else:
        # First run.  Still write an empty marker so rolling back to "there was
        # nothing here" is a thing you can actually do.
        with tarfile.open(dest, "w:gz"):
            pass

    prune_backups()
    return name


def prune_backups():
    if not BACKUP_DIR.is_dir():
        return
    backups = sorted(BACKUP_DIR.glob("*.tar.gz"))
    for old in backups[:-BACKUP_KEEP]:
        old.unlink(missing_ok=True)


def restore_backup(name):
    """Put a backup back.  The caller still has to test and reload after."""
    if "/" in name or ".." in name:
        raise AgentError("that is not a backup name", "bad_path")
    src = BACKUP_DIR / name
    if not src.is_file():
        raise AgentError(f"no backup called {name}", "not_found")

    tmp = Path(tempfile.mkdtemp(prefix="nfm-restore-", dir=str(BACKUP_DIR)))
    try:
        with tarfile.open(src, "r:gz") as tar:
            # Check every member before unpacking.  A tar can hold absolute
            # paths and ../ that would land outside where you told it to go.
            for member in tar.getmembers():
                target = (tmp / member.name).resolve()
                if not str(target).startswith(str(tmp.resolve())):
                    raise AgentError("that backup tries to write outside its folder", "denied")
                if member.issym() or member.islnk():
                    raise AgentError("that backup has links in it, not unpacking", "denied")
            tar.extractall(str(tmp))

        staged = tmp / "nginxmgr"
        if staged.is_dir():
            if MANAGED_DIR.exists():
                shutil.rmtree(MANAGED_DIR)
            shutil.move(str(staged), str(MANAGED_DIR))
        else:
            if MANAGED_DIR.exists():
                shutil.rmtree(MANAGED_DIR)
            MANAGED_DIR.mkdir(parents=True, exist_ok=True)
    finally:
        shutil.rmtree(tmp, ignore_errors=True)

    return {"restored": name}


# ==============================================================================
# The verbs
# ==============================================================================
#
# Each one takes the request dict and gives back a dict.  Raise AgentError for
# anything the caller got wrong.  Nothing in here builds a shell command out of
# caller input, and nothing takes a command to run.

def v_ping(req):
    return {
        "pong": True,
        "agent_version": AGENT_VERSION,
        # What is actually running, as opposed to what somebody remembered to
        # bump.  See _own_fingerprint.
        "agent_fingerprint": AGENT_FINGERPRINT,
        "hostname": socket.gethostname(),
        "time": datetime.now(timezone.utc).isoformat(),
    }


# Status asks five separate programs how they are doing, and the caller only
# waits 30 seconds for the lot.  The default subprocess timeout is 60, so one
# slow systemctl was enough to blow the whole budget and the caller got nothing
# back, not even the parts that answered.  "the agent did not answer status
# within 30s" tells you nothing about which of the five was the problem.
#
# So each one gets a short leash of its own, and a call that misses it is
# recorded as unknown rather than taken as a failure.  Status is a dashboard
# read.  Partial and quick beats complete and never.
STATUS_STEP_TIMEOUT = 5


def _status_step(out, name, fn):
    """Run one part of status, and never let it sink the whole thing."""
    started = time.monotonic()
    try:
        fn()
    except Exception as exc:
        out[f"{name}_error"] = str(exc)[:200]
        log.warning("status step %s failed: %s", name, exc)
    took = time.monotonic() - started
    if took > 1:
        # Worth knowing which one is dragging, because from the outside the
        # whole call just looks slow.
        log.warning("status step %s took %.1fs", name, took)


def v_status(req):
    """What nginx is doing right now, plus what it was built with."""
    out = {"nginx_bin": str(NGINX_BIN), "installed": NGINX_BIN.is_file()}

    if out["installed"]:
        def _version():
            ver = run([str(NGINX_BIN), "-v"], timeout=STATUS_STEP_TIMEOUT)
            # nginx prints its version banner to stderr, which trips people up.
            out["version_banner"] = (ver["stderr"] or ver["stdout"]).strip()
        _status_step(out, "version", _version)

        def _build():
            # -V gives the whole configure line.  This is how we work out which
            # modules got compiled in, so the GUI only offers settings that will
            # actually load on this box.
            build = run([str(NGINX_BIN), "-V"], timeout=STATUS_STEP_TIMEOUT)
            out["build_info"] = (build["stderr"] or build["stdout"]).strip()
        _status_step(out, "build", _build)

    if have_systemd():
        out["service_active"] = "unknown"
        out["service_enabled"] = "unknown"

        def _active():
            active = systemctl("is-active", "nginx", timeout=STATUS_STEP_TIMEOUT)
            out["service_active"] = active["stdout"].strip() or "unknown"
        _status_step(out, "is_active", _active)

        def _enabled():
            enabled = systemctl("is-enabled", "nginx", timeout=STATUS_STEP_TIMEOUT)
            out["service_enabled"] = enabled["stdout"].strip() or "unknown"
        _status_step(out, "is_enabled", _enabled)

        def _props():
            # A few useful bits without shelling out to the whole status output.
            props = systemctl(
                "show", "nginx",
                "--property=MainPID,ActiveEnterTimestamp,NRestarts,SubState",
                timeout=STATUS_STEP_TIMEOUT,
            )
            for line in props["stdout"].splitlines():
                if "=" in line:
                    k, _, val = line.partition("=")
                    out[f"svc_{k.lower()}"] = val
        _status_step(out, "properties", _props)
    else:
        out["service_active"] = "no-systemd"
        out["service_enabled"] = "no-systemd"

    # Rough idea of load without needing a stats module.
    try:
        out["load_average"] = os.getloadavg()
    except OSError:
        pass

    try:
        usage = shutil.disk_usage("/")
        out["disk_total"] = usage.total
        out["disk_free"] = usage.free
    except OSError:
        pass

    return out


def v_config_test(req):
    """Run nginx -t on whatever is live right now."""
    result = run([str(NGINX_BIN), "-t"])
    return {
        "ok": result["rc"] == 0,
        "output": (result["stderr"] + result["stdout"]).strip(),
    }


# Where a load_module line has to live, and the one file we put there.
#
# It cannot go in the config bundle.  Everything the manager renders is pulled
# in by an include inside http {}, and load_module is only legal in the main
# context, so this is written here instead and the installer puts the matching
# include above the events block.
MODULES_ENABLED = NGINX_PREFIX / "modules-enabled"
MODSEC_LOAD_CONF = MODULES_ENABLED / "50-modsecurity.conf"
MODSEC_MODULE_SO = Path("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so")


def v_waf_module(req):
    """
    Load or unload the WAF module, and prove nginx still starts either way.

    Two things have to be true before this can say yes, and they fail in
    different ways:

      * The .so has to be there, which it only is after a rebuild with
        WITH_MODSECURITY=1.  Writing a load_module line for a file that does
        not exist means nginx will not start at all, and the node that was
        serving traffic a second ago is now down.  So the file is checked
        first, and a missing one is an error the caller can act on rather than
        an outage.
      * nginx has to accept the result.  A module built against a different
        nginx loads and then fails on a version check, which nginx -t catches.

    So it writes, tests, and puts the old state back if the test fails.  The
    node is never left in a state it cannot start from, which matters more here
    than anywhere else in this file: this is the one verb that can stop nginx
    from starting rather than just serving the wrong thing.
    """
    enabled = req.get("enabled")
    if not isinstance(enabled, bool):
        raise AgentError("enabled has to be true or false", "bad_request")

    if enabled and not MODSEC_MODULE_SO.is_file():
        raise AgentError(
            f"no WAF module at {MODSEC_MODULE_SO}.  nginx has to be rebuilt "
            f"with the module before the WAF can be switched on.",
            "module_missing",
        )

    MODULES_ENABLED.mkdir(parents=True, exist_ok=True)

    had = MODSEC_LOAD_CONF.read_text() if MODSEC_LOAD_CONF.is_file() else None

    if enabled:
        atomic_write(
            MODSEC_LOAD_CONF,
            "# Written by the fleet manager.  Do not edit.\n"
            f"load_module {MODSEC_MODULE_SO};\n",
            mode=0o644,
        )
    else:
        MODSEC_LOAD_CONF.unlink(missing_ok=True)

    result = run([str(NGINX_BIN), "-t"])
    if result["rc"] != 0:
        # Put it back exactly as it was, then say what nginx objected to.
        if had is None:
            MODSEC_LOAD_CONF.unlink(missing_ok=True)
        else:
            atomic_write(MODSEC_LOAD_CONF, had, mode=0o644)
        raise AgentError(
            "nginx would not accept the WAF module, so nothing was changed: "
            + (result["stderr"] + result["stdout"]).strip()[:600],
            "config_test_failed",
        )

    log.warning("WAF module %s", "loaded" if enabled else "unloaded")
    return {"enabled": enabled, "path": str(MODSEC_LOAD_CONF)}


# Where nginx keeps config that is not ours.  Anything the manager renders
# lives under MANAGED_DIR; these are the two places a distribution or an
# installer drops server blocks of its own.
UNMANAGED_CONFIG_DIRS = (
    NGINX_PREFIX / "sites-enabled",
    NGINX_PREFIX / "conf.d",
)

# `listen 80 default_server;` and friends, in a file we did not write.
_DEFAULT_SERVER_RE = re.compile(r"^\s*listen\s+[^;#]*\bdefault_server\b", re.M)


def _default_server_files() -> list:
    """
    Config outside the managed tree that already claims default_server.

    nginx allows exactly one default server per address and port, and refuses
    to start with two.  The manager can render a perfectly good site marked as
    the default and still have every apply on the fleet refused, because the
    installer's own catch all got there first and nothing in the manager knew
    that file existed.
    """
    found = []
    for folder in UNMANAGED_CONFIG_DIRS:
        if not folder.is_dir():
            continue
        for path in sorted(folder.iterdir()):
            if path.is_dir():
                continue
            try:
                text = path.read_text(errors="replace")
            except OSError:
                continue
            if _DEFAULT_SERVER_RE.search(text):
                found.append(str(path))
    return found


# Where we remember a catch all we stood down, so it can be put back.
#
# Under /usr/local/lib and not /var/lib, because the unit runs with
# ProtectSystem=strict and only the paths it names are writable.  /var/lib is
# not one of them, so a state file there cannot be written at all: the first
# version of this put it there, the write failed with a read only filesystem,
# and by then the symlink had already been removed.  The node was left with no
# catch all and nothing recording that it ever had one.
DEFAULT_SITE_STATE = Path("/usr/local/lib/nginx-fleet-manager/default-site.json")


def _takeable(path: Path) -> bool:
    """
    Can the manager stand this one down and put it back exactly as it was.

    Only a symlink in sites-enabled.  That is how the installer enables its
    catch all, and a symlink can be removed and recreated with nothing lost,
    because the real file stays in sites-available where somebody put it.

    A regular file is not touched.  It might be somebody's own config with
    their own content in it, and moving that out of the way is not a decision
    an apply gets to make quietly.  nginx globs `sites-enabled/*`, so renaming
    in place does not hide anything either: the new name matches the glob just
    as well as the old one.
    """
    return path.is_symlink() and path.parent == (NGINX_PREFIX / "sites-enabled")


def v_default_server_conflict(req):
    """
    Who else already claims to be the default site on this box.

    Split by whether the manager could take it over, because the two need
    different answers.  A symlink we can stand down is not a reason to refuse
    somebody's setting; a file we must not touch is.
    """
    files = _default_server_files()
    takeable = [f for f in files if _takeable(Path(f))]
    return {
        "files": files,
        "takeable": takeable,
        "blocked": [f for f in files if f not in takeable],
        "stood_down": _stood_down(),
    }


def _stood_down() -> list:
    try:
        return json.loads(DEFAULT_SITE_STATE.read_text()).get("links", [])
    except Exception:
        return []


def _remember_stood_down(links):
    DEFAULT_SITE_STATE.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(DEFAULT_SITE_STATE, json.dumps({"links": links}, indent=1),
                 mode=0o640)


def reconcile_default_site(managed_wants_it: bool) -> dict:
    """
    Make room for a managed default site, or give the room back.

    nginx allows one default server per address and port.  When a managed site
    claims the role, the catch all the installer enabled has to stand down or
    nothing on the fleet can be applied at all.  When no managed site claims
    it, the catch all goes back, so unmatched traffic lands where it always did
    rather than on whichever server block happens to be first.

    Only symlinks in sites-enabled are touched, and what was removed is written
    down so putting it back is exact rather than a guess.  The caller tests
    nginx afterwards; this does not, because it runs inside a staging test that
    is about to do exactly that.
    """
    changed = {"removed": [], "restored": []}

    if managed_wants_it:
        links = _stood_down()
        going = []
        for path_str in _default_server_files():
            path = Path(path_str)
            if not _takeable(path):
                continue
            entry = {"link": str(path), "target": os.readlink(path)}
            going.append((path, entry))
            if entry not in links:
                links.append(entry)

        if not going:
            return changed

        # Write down what is about to move **before** moving it.  The other
        # order loses the box's catch all the moment anything goes wrong
        # between the two steps, and there is then nothing on disk saying what
        # used to be there.  That is not a hypothetical: it is what the first
        # version of this did.
        _remember_stood_down(links)

        for path, _entry in going:
            path.unlink()
            changed["removed"].append(str(path))
            log.warning("stood down %s so a managed site can be the default",
                        path)
        return changed

    for entry in _stood_down():
        link = Path(entry["link"])
        if link.exists() or link.is_symlink():
            continue
        link.parent.mkdir(parents=True, exist_ok=True)
        os.symlink(entry["target"], link)
        changed["restored"].append(str(link))
        log.warning("put %s back, no managed site is the default now", link)
    if changed["restored"]:
        _remember_stood_down([])
    return changed


def v_default_site(req):
    """Stand the unmanaged catch all down, or put it back, and say what moved."""
    wants = req.get("managed_default")
    if not isinstance(wants, bool):
        raise AgentError("managed_default has to be true or false", "bad_request")
    return reconcile_default_site(wants)


def v_waf_module_status(req):
    """What this node has, so the page can say rather than guess."""
    return {
        "built": MODSEC_MODULE_SO.is_file(),
        "loaded": MODSEC_LOAD_CONF.is_file(),
        "module_path": str(MODSEC_MODULE_SO),
    }


def _staged_mode(rel_path):
    """
    How readable a staged file has to be, which is not the same for all of them.

    Nearly everything we stage is config, and config is read by the nginx master
    process while it is still root, so 0640 root only is right and is what we
    want: those files carry backend tokens and htpasswd hashes.

    Error pages are different.  They are read by a worker at request time, and
    workers have already dropped to www-data, so a page written 0640 cannot be
    opened at all.  That failure is not quiet and it is not harmless: nginx
    throws away the status it was going to send and answers 403 instead.  A 502
    from a dead backend turns into a 403 about nothing, and the error log line
    is about a file rather than about the backend that actually broke.

    Worth knowing that a *missing* page does not do this.  nginx falls back to
    its own page and keeps the real status.  Only an unreadable one lies.

    The password files are the same story found a second time.  auth_basic is
    checked by a worker as well, so a 0640 htpasswd meant every site with a
    password on it answered 401, then 500 to anybody who actually typed the
    password, with "permission denied" in the error log about a file the person
    had never heard of.  Basic auth had never worked once.

    These two are the only content we stage.  Everything else here is config,
    read by the master while it is still root, and those stay 0640 because they
    carry backend tokens.  The password hashes in a htpasswd are bcrypt, which
    is what that format is for, so world readable is what the format expects.
    """
    first = Path(rel_path).parts[0] if Path(rel_path).parts else ""
    return 0o644 if first in ("errorpages", "auth") else 0o640


def v_write_staging(req):
    """
    Drop a whole set of files into the staging folder.

    The manager renders every managed file and sends the lot.  We wipe staging
    first, so a file the manager stopped generating actually disappears instead
    of hanging around and getting included forever.
    """
    files = req.get("files")
    if not isinstance(files, dict) or not files:
        raise AgentError("files has to be a non empty object of path to contents", "bad_request")

    if STAGING_DIR.exists():
        shutil.rmtree(STAGING_DIR)
    STAGING_DIR.mkdir(parents=True, exist_ok=True)

    written = []
    for rel_path, content in files.items():
        if not isinstance(content, str):
            raise AgentError(f"contents for {rel_path} has to be a string", "bad_request")
        if rel_path.startswith("/") or ".." in Path(rel_path).parts:
            raise AgentError(f"{rel_path} has to be a relative path with no ..", "bad_path")

        target = check_write_path(str(STAGING_DIR / rel_path))
        atomic_write(target, content, mode=_staged_mode(rel_path))
        written.append(rel_path)

    return {"written": written, "count": len(written)}


def _staging_for_test() -> str:
    """
    Which folder the test should include, and why it is sometimes not staging.

    Nearly every directive we render points outside the bundle or is opened
    lazily at request time, so testing the staging folder as it stands is
    fine.  `auth_basic_user_file` is the usual example: nginx -t never opens
    it, so the absolute path in a staged site file pointing at the *live*
    bundle costs nothing.

    `modsecurity_rules_file` is not like that.  nginx reads and parses it while
    loading the config, which is the whole reason a bad rule file fails the
    test rather than failing at runtime.  A staged site file pointing at the
    live bundle then tests the rules that are already there, and on a first
    apply there is no file at that path at all and the test fails on a config
    that is perfectly good.

    So when a staged file refers to the live bundle, the test runs against a
    rewritten copy instead, leaving the staging folder exactly as the manager
    sent it.  Rewriting staging itself would be worse than the bug: apply moves
    that folder into place, so the paths have to be the live ones by then.

    A config with no such reference, which is every config this project wrote
    before the firewall existed, takes the old path and copies nothing.

    **Only what staging actually holds gets rewritten.**  Certificates are the
    reason.  They live in the bundle but are put there by the certificate sync
    rather than by an apply, so they are not in the staging folder, and nginx
    opens them while loading the config exactly like it opens a rule file.
    Rewriting those too pointed them at a folder with no certificates in it and
    turned a passing test into "cannot load certificate", which is a far more
    alarming message than the bug deserved.
    """
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR, ignore_errors=True)

    live = str(MANAGED_DIR)
    staged = str(STAGING_DIR)

    # A reference is only redirected when the staging folder has the thing it
    # points at.  Anything else is a file the bundle carries but an apply does
    # not replace, and it has to keep pointing at the live copy.
    reference = re.compile(re.escape(live) + r"(/[^\s;\"']*)")

    def redirect(match, root):
        relative = match.group(1).lstrip("/")
        if relative and (STAGING_DIR / relative).exists():
            return root + match.group(1)
        return match.group(0)

    def needs(text):
        return any(redirect(m, str(TEST_DIR)) != m.group(0)
                   for m in reference.finditer(text))

    found = False
    for path in STAGING_DIR.rglob("*"):
        if not path.is_file():
            continue
        try:
            if needs(path.read_text()):
                found = True
                break
        except (OSError, UnicodeDecodeError):
            # Binary or unreadable.  Nothing we would rewrite anyway.
            continue

    if not found:
        return staged

    shutil.copytree(STAGING_DIR, TEST_DIR)
    for path in TEST_DIR.rglob("*"):
        if not path.is_file():
            continue
        try:
            text = path.read_text()
        except (OSError, UnicodeDecodeError):
            continue
        rewritten = reference.sub(lambda m: redirect(m, str(TEST_DIR)), text)
        if rewritten != text:
            path.write_text(rewritten)

    return str(TEST_DIR)


def _staging_declares_default() -> bool:
    """Does the config we are about to test claim to be the default site."""
    staging = Path(_staging_for_test())
    if not staging.is_dir():
        return False
    for path in staging.rglob("*.conf"):
        try:
            if _DEFAULT_SERVER_RE.search(path.read_text(errors="replace")):
                return True
        except OSError:
            continue
    return False


def v_test_staging(req):
    """
    Test the staged config without letting it near the running server.

    The trick is that nginx -t wants a whole config, not a folder of pieces.
    So we write a throwaway nginx.conf that is the real one with our include
    line pointed at staging instead of the live folder, and test that.  If it
    passes, the same files will load for real.
    """
    main_conf = NGINX_PREFIX / "nginx.conf"
    if not main_conf.is_file():
        raise AgentError(f"cannot find {main_conf}", "not_found")

    # Make room for a managed default site before testing, or give the room
    # back if the staged config no longer has one.
    #
    # This has to happen before the test rather than after it, because the
    # candidate config includes sites-enabled the same way the live one does.
    # Two default servers is the one clash nginx refuses outright, so leaving
    # it until the commit would mean the test passes and the apply falls over
    # on the node that already said yes.
    staged_default = _staging_declares_default()
    moved = reconcile_default_site(staged_default)

    original = main_conf.read_text()

    # Swap our include line over to staging.  If the manager has never applied
    # anything yet there is no include line, so we add one inside http.
    live_include = str(MANAGED_DIR)
    staged_include = _staging_for_test()

    if live_include in original:
        candidate = original.replace(live_include, staged_include)
    else:
        candidate = _inject_include(original, staged_include)

    atomic_write(CANDIDATE_CONF, candidate, mode=0o640)

    try:
        # -p as well, so anything that genuinely does key off the prefix, like
        # a relative access_log path, lands where it normally would.
        result = run([str(NGINX_BIN), "-t", "-p", str(NGINX_PREFIX), "-c", str(CANDIDATE_CONF)])
        output = (result["stderr"] + result["stdout"]).strip()

        # Tidy up the message before anybody reads it in the GUI.  nginx names
        # the temp file and the staging folder, and neither means anything to
        # the person who just changed a setting.  Point them at the real thing.
        output = output.replace(str(CANDIDATE_CONF), "the candidate config")
        output = output.replace(staged_include + "/", live_include + "/")

        ok = result["rc"] == 0
        if not ok and moved.get("removed"):
            # The config we made room for is not going to be applied, so give
            # the room back rather than leaving the box with its catch all
            # gone and nothing having replaced it.
            reconcile_default_site(False)

        return {"ok": ok, "output": output, "default_site": moved}
    finally:
        # Always clean up, even if nginx blew up.  Leaving this behind would
        # mean the next test reads a stale candidate.
        CANDIDATE_CONF.unlink(missing_ok=True)
        # And the rewritten copy, if this test needed one.  It is a copy of
        # config that is about to be applied anyway, but leaving it on disk
        # would give the next reader two folders that look equally live.
        shutil.rmtree(TEST_DIR, ignore_errors=True)


def _inject_include(conf_text, include_dir):
    """
    Put our include line inside the http block.

    Only used the first time, before we have ever applied.  We walk the braces
    instead of regexing for a closing one, since the http block has plenty of
    nested blocks and a regex would find the wrong brace every time.
    """
    lines = conf_text.splitlines()
    depth = 0
    in_http = False
    http_depth = None

    for i, line in enumerate(lines):
        stripped = line.split("#")[0]

        if not in_http and re.search(r"^\s*http\s*\{", stripped):
            in_http = True
            http_depth = depth

        depth += stripped.count("{") - stripped.count("}")

        # Back down to where http started means we just passed its closing
        # brace, so this is the spot.
        if in_http and http_depth is not None and depth == http_depth:
            # Order matters here and it is not cosmetic.  Anything that gets
            # referenced by name has to be defined before the thing that uses
            # it.  00-managed.conf holds the log formats, and a site saying
            # "access_log ... nfm_main" before that file is read fails with
            # "unknown log format".  Same story for maps, limit zones and cache
            # zones.  Sites go last because they use all of it.
            #
            # Globs everywhere, never a named file.  nginx treats a missing
            # named include as fatal, but a glob matching nothing is fine, so a
            # partial staging tree gives a useful error about the thing you
            # changed rather than about a file that was never there.
            block = [
                "",
                f"    {INCLUDE_MARKER}",
                f"    include {include_dir}/*.conf;",
                f"    include {include_dir}/maps/*.conf;",
                f"    include {include_dir}/limits/*.conf;",
                f"    include {include_dir}/caches/*.conf;",
                f"    include {include_dir}/upstreams/*.conf;",
                f"    include {include_dir}/sites/*.conf;",
            ]
            lines[i:i] = block

            # TCP and UDP proxying lives in its own top level block, a sibling
            # of http rather than something inside it, so it needs a second
            # include out here.  Without it the manager renders stream config
            # that nginx never reads: the files are on disk, the GUI says the
            # apply worked, and the port is not listening.
            #
            # The whole block is generated into one file rather than assembled
            # from includes here, because a bare `stream { }` with nothing in it
            # is still a block nginx has to accept, and because the strip above
            # only knows how to remove include lines.  Leaving an orphaned brace
            # in nginx.conf would be a config that will not load at all.
            #
            # A glob, like every other include we write, so no streams means the
            # line matches nothing and costs nothing.
            # After the closing brace, not before it.  lines[i] is the brace
            # that ends http, so the block above went inside it, and this has
            # to land on the other side.
            close_at = i + len(block)
            lines[close_at + 1:close_at + 1] = [
                "",
                f"{INCLUDE_MARKER.replace('includes', 'stream include')}",
                f"include {include_dir}/stream/*.conf;",
            ]
            return "\n".join(lines) + "\n"

    raise AgentError("could not find the http block in nginx.conf", "parse_error")


def v_apply(req):
    """
    Move the staged config into place and reload nginx.

    The order matters and it is the whole reason this verb exists:
      back up, test staging, swap it in, test again, reload, and if the reload
      fails put the backup back and reload again.
    """
    reload_after = bool(req.get("reload", True))
    label = req.get("label", "apply")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,64}", str(label)):
        label = "apply"

    if not STAGING_DIR.is_dir():
        raise AgentError("nothing is staged, call write_staging first", "bad_request")

    # Test before we touch anything live.
    staged = v_test_staging(req)
    if not staged["ok"]:
        return {"ok": False, "stage": "test_staging", "output": staged["output"]}

    backup_name = make_backup(label)

    # Swap the folder over.  Move the old one aside instead of deleting it, so
    # if something blows up halfway we still have the files right here.
    previous = None
    try:
        if MANAGED_DIR.exists():
            previous = MANAGED_DIR.with_name(MANAGED_DIR.name + ".previous")
            if previous.exists():
                shutil.rmtree(previous)
            os.rename(MANAGED_DIR, previous)

        os.rename(STAGING_DIR, MANAGED_DIR)
    except OSError as exc:
        if previous and previous.exists() and not MANAGED_DIR.exists():
            os.rename(previous, MANAGED_DIR)
        raise AgentError(f"could not swap the config into place: {exc}", "io_error")

    # Carry the certificates over.  They live in this folder but they are not
    # rendered config, so the manager never stages them, and swapping the folder
    # threw every one of them away.  That is a hole you cannot climb out of:
    # copy the certs to a node, apply, the apply deletes them, the next render
    # sees the files missing and leaves the https block out, and applying again
    # does the same thing forever.
    #
    # Copy rather than move, so the folder we set aside stays whole and a
    # rollback still has everything it started with.
    if previous is not None:
        old_certs = previous / "certs"
        new_certs = MANAGED_DIR / "certs"
        if old_certs.is_dir() and not new_certs.exists():
            try:
                shutil.copytree(old_certs, new_certs)
            except OSError as exc:
                # Worth stopping for.  Going on without the certificates means
                # nginx cannot load any https site, and the test below would
                # fail with a missing file rather than saying what happened.
                _rollback(previous, backup_name)
                raise AgentError(
                    f"could not carry the certificates across the apply: {exc}", "io_error"
                )

    # Make sure nginx.conf actually pulls our folder in.  Only matters on the
    # first apply, but checking every time is cheap and catches somebody
    # editing the include back out.
    _ensure_include_present()

    live = v_config_test(req)
    if not live["ok"]:
        _rollback(previous, backup_name)
        return {"ok": False, "stage": "test_live", "output": live["output"], "rolled_back": True}

    result = {"ok": True, "backup": backup_name, "output": live["output"]}

    if reload_after:
        rel = v_reload({})
        if not rel.get("ok"):
            _rollback(previous, backup_name)
            v_reload({})
            return {
                "ok": False,
                "stage": "reload",
                "output": rel.get("output", ""),
                "rolled_back": True,
            }
        result["reloaded"] = True

    if previous and previous.exists():
        shutil.rmtree(previous, ignore_errors=True)

    return result


def _rollback(previous, backup_name):
    """Undo a bad apply.  Prefer the folder we set aside, fall back to the tarball."""
    log.warning("apply went bad, rolling back")
    try:
        if MANAGED_DIR.exists():
            shutil.rmtree(MANAGED_DIR)
        if previous and previous.exists():
            os.rename(previous, MANAGED_DIR)
        else:
            restore_backup(backup_name)
    except Exception as exc:
        log.error("the rollback itself failed: %s", exc)


def _ensure_include_present():
    """
    Make sure nginx.conf pulls our folder in, with the current include list.

    Checking only for the folder name would miss the case where an older
    version of the manager wrote a shorter list of includes.  That node would
    keep running, and keep failing in a confusing way, because a file we now
    generate is never read.  So we look for the marker instead, and if it is
    missing or from an older version we strip the old block and write a new one.
    """
    main_conf = NGINX_PREFIX / "nginx.conf"
    text = main_conf.read_text()

    if INCLUDE_MARKER in text:
        return

    if str(MANAGED_DIR) in text:
        log.info("replacing an out of date include block in nginx.conf")
        kept = []
        for line in text.splitlines():
            stripped = line.strip()
            if stripped.startswith("# failover lb includes"):
                continue
            # The two names this went under before v5.  A node installed under
            # either still has that comment sitting in its nginx.conf, and the
            # block is only recognised as ours by these prefixes, so dropping
            # them would leave the old lines behind and add a second block
            # underneath.  They stay for as long as an un-upgraded node might.
            if stripped.startswith("# nginx fleet manager includes"):
                continue
            if stripped.startswith("# added by nginx fleet manager"):
                continue
            if stripped.startswith("include ") and str(MANAGED_DIR) in stripped:
                continue
            kept.append(line)
        text = "\n".join(kept)
    else:
        log.info("adding our include block to nginx.conf")

    atomic_write(main_conf, _inject_include(text, str(MANAGED_DIR)), mode=0o644)


def v_reload(req):
    """Test first, then reload.  Never reload a config we have not tested."""
    test = run([str(NGINX_BIN), "-t"])
    if test["rc"] != 0:
        return {
            "ok": False,
            "output": (test["stderr"] + test["stdout"]).strip(),
            "note": "config test failed, so we did not reload",
        }

    if have_systemd():
        result = systemctl("reload", "nginx")
        if result["rc"] != 0:
            # Not running yet is a normal thing on a fresh box.  Start it.
            active = systemctl("is-active", "nginx")
            if active["stdout"].strip() != "active":
                result = systemctl("start", "nginx")
    else:
        result = run([str(NGINX_BIN), "-s", "reload"])

    return {
        "ok": result["rc"] == 0,
        "output": (result["stderr"] + result["stdout"]).strip(),
    }


def v_service(req):
    """start, stop, restart or reload nginx.  Only nginx, only those four."""
    action = req.get("action")
    if action not in ("start", "stop", "restart", "reload"):
        raise AgentError("action has to be start, stop, restart or reload", "bad_request")

    if action in ("restart", "reload"):
        test = run([str(NGINX_BIN), "-t"])
        if test["rc"] != 0:
            return {
                "ok": False,
                "output": (test["stderr"] + test["stdout"]).strip(),
                "note": "config test failed, so we left the service alone",
            }

    if have_systemd():
        result = systemctl(action, "nginx")
        return {"ok": result["rc"] == 0, "output": (result["stderr"] + result["stdout"]).strip()}

    # No systemd.  Drive nginx directly instead of refusing.
    #
    # This is not only containers.  It matters after a rebuild: the installer
    # replaces the binary on disk, but the process already running keeps the old
    # one in memory until something restarts it.  Refusing here would leave a
    # box reporting the new version from nginx -v while still serving with the
    # old build, which is a genuinely nasty thing to be wrong about.
    if action in ("stop", "restart"):
        run([str(NGINX_BIN), "-s", "quit"])
        # Give the workers a moment to finish what they are doing.  quit is the
        # graceful one, so this is not instant by design.
        for _ in range(20):
            check = run(["pgrep", "-x", "nginx"])
            if check["rc"] != 0:
                break
            time.sleep(0.5)

    if action in ("start", "restart"):
        result = run([str(NGINX_BIN)])
        return {
            "ok": result["rc"] == 0,
            "output": (result["stderr"] + result["stdout"]).strip() or "started",
            "note": "no systemd here, so nginx was started directly",
        }

    if action == "reload":
        result = run([str(NGINX_BIN), "-s", "reload"])
        return {"ok": result["rc"] == 0, "output": (result["stderr"] + result["stdout"]).strip()}

    return {"ok": True, "output": "stopped"}


def v_read_file(req):
    p = check_read_path(req.get("path", ""))
    if not p.is_file():
        raise AgentError(f"no file at {p}", "not_found")
    if p.stat().st_size > MAX_REQUEST_BYTES:
        raise AgentError("that file is too big to send back", "too_large")
    try:
        return {"path": str(p), "content": p.read_text()}
    except UnicodeDecodeError:
        raise AgentError("that file is not text", "not_text")


def v_list_dir(req):
    p = check_read_path(req.get("path", ""))
    if not p.is_dir():
        raise AgentError(f"no folder at {p}", "not_found")

    entries = []
    for child in sorted(p.iterdir()):
        try:
            st = child.stat()
        except OSError:
            continue
        entries.append({
            "name": child.name,
            "is_dir": child.is_dir(),
            "size": st.st_size,
            "modified": st.st_mtime,
            # The permission bits, because a listing without them cannot answer
            # the question that has now bitten twice: whether a file an nginx
            # worker has to open at request time is readable by www-data.
            # Both times the symptom was a status code that lied and a log line
            # about a file nobody had heard of.
            "mode": st.st_mode & 0o7777,
        })
    return {"path": str(p), "entries": entries}


def v_acme_token_write(req):
    """
    Put an http-01 challenge token on disk.

    Every node in the cluster gets a copy of the token, not just the one asking
    for the cert.  Lets Encrypt picks which address to hit and we do not get a
    say, so if only one node had the file the check would fail whenever they
    picked a different one.
    """
    token = req.get("token", "")
    value = req.get("value", "")

    # Tokens out of the acme spec are base64url.  Pinning the shape here means
    # a token can never turn into a path.
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", str(token)):
        raise AgentError("that token does not look like an acme token", "bad_request")
    if not isinstance(value, str) or len(value) > 1024:
        raise AgentError("bad key authorization value", "bad_request")

    challenge_dir = ACME_WEBROOT / ".well-known" / "acme-challenge"
    challenge_dir.mkdir(parents=True, exist_ok=True)

    target = check_write_path(str(challenge_dir / token))
    atomic_write(target, value, mode=0o644, owner="www-data")

    try:
        www = pwd.getpwnam("www-data")
        for d in (ACME_WEBROOT, ACME_WEBROOT / ".well-known", challenge_dir):
            os.chown(d, www.pw_uid, www.pw_gid)
    except (KeyError, OSError):
        pass

    return {"written": str(target)}


def v_acme_token_delete(req):
    token = req.get("token", "")
    if not re.fullmatch(r"[A-Za-z0-9_-]{16,256}", str(token)):
        raise AgentError("that token does not look like an acme token", "bad_request")
    target = check_write_path(str(ACME_WEBROOT / ".well-known" / "acme-challenge" / token))
    target.unlink(missing_ok=True)
    return {"deleted": str(target)}


def v_certbot(req):
    """
    Ask certbot for a cert.

    We build the whole command line ourselves from a small set of choices.
    None of the caller's text goes anywhere near a shell, and there is no way
    to pass a random flag through.  Domains get checked against a hostname
    pattern first, so a domain cannot turn into an argument.
    """
    domains = req.get("domains") or []
    email = req.get("email", "")
    staging = bool(req.get("staging", False))
    challenge = req.get("challenge", "http-01")
    key_type = req.get("key_type", "ecdsa")
    dns_plugin = req.get("dns_plugin")
    dns_credentials = req.get("dns_credentials")
    force = bool(req.get("force_renewal", False))

    # Somewhere other than Lets Encrypt.  Two real uses: an internal CA like
    # step-ca or Smallstep, which plenty of places run for internal names, and
    # a local test server so the whole path can be exercised without spending
    # a public rate limit.
    acme_server = req.get("acme_server")
    ca_bundle = req.get("ca_bundle")

    if not domains or not isinstance(domains, list):
        raise AgentError("send a list of domains", "bad_request")
    if len(domains) > 100:
        raise AgentError("that is too many domains for one cert", "bad_request")

    hostname_re = re.compile(
        r"^(\*\.)?([a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,63}$"
    )
    for d in domains:
        if not isinstance(d, str) or not hostname_re.match(d):
            raise AgentError(f"{d!r} is not a valid domain name", "bad_request")

    # No email is allowed.  Lets Encrypt will register without a contact
    # address, you just get no mail before something expires.  The manager
    # watches expiry itself and warns on the dashboard, so refusing to issue
    # without one would be us inventing a rule the CA does not have.
    if email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}", str(email)):
        raise AgentError("that email address does not look right", "bad_request")

    if key_type not in ("ecdsa", "rsa"):
        raise AgentError("key_type has to be ecdsa or rsa", "bad_request")

    # The name the manager calls this certificate, falling back to the first
    # domain when it did not say.
    #
    # This has to match, and getting it wrong is quiet.  certbot puts the files
    # in a folder named after --cert-name, and the manager later looks them up
    # by the name in its own database.  Guess the name here and the two disagree
    # the moment somebody calls a certificate anything other than its first
    # domain.  Issuing then works, and the copy to the other nodes fails with
    # "no cert called ...", so one box has a certificate and the rest do not.
    cert_name = req.get("cert_name") or domains[0].replace("*.", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(cert_name)):
        raise AgentError("that certificate name is not valid", "bad_request")

    cmd = [
        "certbot", "certonly",
        "--non-interactive",
        "--agree-tos",
        "--cert-name", cert_name,
        "--key-type", key_type,
    ]

    # Which chain to ask for.
    #
    # The ISRG root is Lets Encrypt's own, so it is only asked for when no
    # other directory is in play.  Any authority that needs a particular chain
    # names it on its own profile, because that is a fact about the authority
    # rather than about this installation.
    chain = req.get("preferred_chain")
    if chain:
        if not re.fullmatch(r"[A-Za-z0-9 ._()-]{1,128}", str(chain)):
            raise AgentError("that preferred chain name is not valid", "bad_request")
        cmd += ["--preferred-chain", str(chain)]
    elif not acme_server:
        cmd += ["--preferred-chain", "ISRG Root X1"]

    if email:
        cmd += ["-m", email]
    else:
        # certbot will not register without either a contact address or being
        # told outright that you meant it.  The flag name is dramatic, but all
        # it means is nobody gets an expiry warning by mail.
        cmd.append("--register-unsafely-without-email")

    if acme_server:
        if not re.fullmatch(r"https://[A-Za-z0-9._:-]{1,253}(/[A-Za-z0-9._~/-]*)?", str(acme_server)):
            raise AgentError("that acme server url is not valid", "bad_request")
        cmd += ["--server", acme_server]
        # A custom directory and --staging together makes no sense, since
        # staging is just Lets Encrypt's own other directory.
        staging = False

    # External account binding.  A paid authority hands these out with the
    # entitlement rather than letting anybody register, so without them
    # registration is refused and the error talks about the account rather
    # than about the credentials being missing.
    eab_kid = req.get("eab_kid")
    eab_hmac = req.get("eab_hmac_key")
    if eab_kid or eab_hmac:
        if not (eab_kid and eab_hmac):
            raise AgentError(
                "external account binding needs both the key id and the hmac "
                "key.  One without the other is refused at registration.",
                "bad_request")
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,512}", str(eab_kid)):
            raise AgentError("that external account key id is not valid",
                             "bad_request")
        if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}", str(eab_hmac)):
            raise AgentError("that external account hmac key is not valid",
                             "bad_request")
        cmd += ["--eab-kid", str(eab_kid), "--eab-hmac-key", str(eab_hmac)]

    if staging:
        cmd.append("--staging")
    if force:
        cmd.append("--force-renewal")

    if challenge == "http-01":
        # The manual hooks are what let us answer on every node.  certbot calls
        # the hook, the hook calls the manager over localhost, and the manager
        # pushes the token out to the whole cluster before certbot tells Lets
        # Encrypt to go look.
        auth_hook = req.get("auth_hook")
        cleanup_hook = req.get("cleanup_hook")
        if auth_hook and cleanup_hook:
            for hook in (auth_hook, cleanup_hook):
                hp = Path(hook)
                if not hp.is_absolute() or not hp.is_file():
                    raise AgentError(f"hook {hook} is not a file on this box", "bad_request")
                if not str(hp.resolve()).startswith("/usr/local/lib/nginx-fleet-manager/"):
                    raise AgentError("hooks have to live in the manager's own folder", "denied")
            cmd += [
                "--manual",
                "--preferred-challenges", "http",
                "--manual-auth-hook", auth_hook,
                "--manual-cleanup-hook", cleanup_hook,
            ]
        else:
            cmd += ["--webroot", "-w", str(ACME_WEBROOT)]

    elif challenge == "dns-01":
        if not dns_plugin or not re.fullmatch(r"[a-z0-9-]{1,40}", str(dns_plugin)):
            raise AgentError("that dns plugin name is not valid", "bad_request")
        cmd += ["--preferred-challenges", "dns", f"--dns-{dns_plugin}"]
        if dns_credentials:
            cred_path = Path(f"/etc/letsencrypt/nfm-dns-{dns_plugin}.ini")
            atomic_write(cred_path, dns_credentials, mode=0o600)
            cmd += [f"--dns-{dns_plugin}-credentials", str(cred_path)]
        cmd += [f"--dns-{dns_plugin}-propagation-seconds", str(int(req.get("dns_propagation", 60)))]
    else:
        raise AgentError("challenge has to be http-01 or dns-01", "bad_request")

    for d in domains:
        cmd += ["-d", d]

    # An internal or test ACME server signs with a CA nothing trusts by
    # default, so certbot needs pointing at it.  Written to our own folder, not
    # somewhere that would change what the rest of the box trusts.
    env_extra = None
    if ca_bundle:
        if not isinstance(ca_bundle, str) or "BEGIN CERTIFICATE" not in ca_bundle:
            raise AgentError("that ca bundle does not look like a certificate", "bad_request")
        bundle_path = Path("/usr/local/lib/nginx-fleet-manager/acme-ca.pem")
        bundle_path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(bundle_path, ca_bundle, mode=0o644)
        env_extra = {"REQUESTS_CA_BUNDLE": str(bundle_path)}

    result = run(cmd, timeout=CERTBOT_TIMEOUT, env_extra=env_extra)
    return {
        "ok": result["rc"] == 0,
        "cert_name": cert_name,
        "output": (result["stdout"] + result["stderr"]).strip(),
    }


def v_cert_list(req):
    """Everything in /etc/letsencrypt/live, with the dates off the actual files."""
    live = LETSENCRYPT_DIR / "live"
    if not live.is_dir():
        return {"certs": []}

    certs = []
    for d in sorted(live.iterdir()):
        if not d.is_dir():
            continue
        fullchain = d / "fullchain.pem"
        if not fullchain.is_file():
            continue

        info = {"name": d.name, "path": str(d)}

        # Reading the dates with openssl instead of parsing it ourselves.  It
        # is already on the box and it is never wrong about its own format.
        out = run(["openssl", "x509", "-in", str(fullchain), "-noout",
                   "-enddate", "-startdate", "-subject", "-ext", "subjectAltName"])
        if out["rc"] == 0:
            for line in out["stdout"].splitlines():
                line = line.strip()
                if line.startswith("notAfter="):
                    info["not_after"] = line.split("=", 1)[1]
                elif line.startswith("notBefore="):
                    info["not_before"] = line.split("=", 1)[1]
                elif line.startswith("subject="):
                    info["subject"] = line.split("=", 1)[1]
                elif line.startswith("DNS:"):
                    info["sans"] = [s.strip().removeprefix("DNS:") for s in line.split(",")]

        try:
            info["modified"] = fullchain.stat().st_mtime
        except OSError:
            pass

        certs.append(info)

    return {"certs": certs}


def v_cert_export(req):
    """
    Read a cert bundle so it can go out to the other nodes.

    Yes, this hands back a private key.  That is on purpose.  Every node in the
    cluster has to serve the same cert, and only one of them can answer the
    acme challenge for a given public address.  The key only ever moves over
    mutual TLS between nodes that already trust each other.
    """
    name = req.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(name)):
        raise AgentError("that is not a valid cert name", "bad_request")

    live = LETSENCRYPT_DIR / "live" / name
    if not live.is_dir():
        raise AgentError(f"no cert called {name}", "not_found")

    bundle = {}
    for fname in ("fullchain.pem", "privkey.pem", "chain.pem", "cert.pem"):
        f = live / fname
        if f.is_file():
            bundle[fname] = f.resolve().read_text()

    if "fullchain.pem" not in bundle or "privkey.pem" not in bundle:
        raise AgentError(f"the cert for {name} is missing pieces", "incomplete")

    return {"name": name, "bundle": bundle}


def v_cert_import(req):
    """
    Write a cert bundle that came from another node.

    These go in their own folder, not in /etc/letsencrypt/live.  certbot owns
    live, and it keeps the renewal state that goes with it.  Dropping somebody
    else's files in there would leave certbot thinking it owns a cert it has no
    account for, and then renewals get weird.  Ours go somewhere obvious
    instead, and the generated config points at whichever one is real.
    """
    name = req.get("name", "")
    bundle = req.get("bundle")

    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(name)):
        raise AgentError("that is not a valid cert name", "bad_request")
    if not isinstance(bundle, dict) or "fullchain.pem" not in bundle:
        raise AgentError("that bundle is missing fullchain.pem", "bad_request")

    synced = MANAGED_DIR / "certs" / name
    synced.mkdir(parents=True, exist_ok=True)

    written = []
    for fname, content in bundle.items():
        if fname not in ("fullchain.pem", "privkey.pem", "chain.pem", "cert.pem"):
            raise AgentError(f"not writing a file called {fname}", "denied")
        if not isinstance(content, str):
            raise AgentError(f"contents of {fname} has to be a string", "bad_request")

        # The key is the sensitive one.  0600 and root only.  nginx reads its
        # certs as the master process, which is root, before it drops to
        # www-data, so the workers never need to see this.
        mode = 0o600 if fname == "privkey.pem" else 0o644
        atomic_write(synced / fname, content, mode=mode)
        written.append(fname)

    os.chmod(synced, 0o750)
    return {"name": name, "written": written, "path": str(synced)}


def v_cert_forget(req):
    """
    Take a certificate's files off this node.

    Only the folder we own, never certbot's.  certbot keeps renewal state
    alongside its copies and deleting one out from under it leaves an account
    with a lineage it can no longer complete.  `certbot delete` is the way to
    remove those and it is a person's decision, not ours.

    Worth having at all because a deleted certificate used to leave its private
    key sitting on every node forever.  Nothing pointed at it and nothing
    listed it, so the only way anybody would find out is by looking at the
    disk, which is exactly the sort of thing nobody does until an audit.
    """
    name = req.get("name", "")
    if not re.fullmatch(r"[A-Za-z0-9._-]{1,253}", str(name)):
        raise AgentError("that is not a valid cert name", "bad_request")

    folder = check_write_path(str(MANAGED_DIR / "certs" / name))
    if not folder.is_dir():
        return {"name": name, "removed": False}

    shutil.rmtree(folder)
    return {"name": name, "removed": True}


def v_list_backups(req):
    if not BACKUP_DIR.is_dir():
        return {"backups": []}
    out = []
    for f in sorted(BACKUP_DIR.glob("*.tar.gz"), reverse=True):
        st = f.stat()
        out.append({"name": f.name, "size": st.st_size, "created": st.st_mtime})
    return {"backups": out}


def v_rollback(req):
    """Put a backup back and reload.  This is the oh-no button."""
    name = req.get("name")
    if not name:
        backups = sorted(BACKUP_DIR.glob("*.tar.gz")) if BACKUP_DIR.is_dir() else []
        if not backups:
            raise AgentError("there are no backups to roll back to", "not_found")
        name = backups[-1].name

    # Set the current folder aside before unpacking anything over it.
    #
    # restore_backup deletes the managed folder and moves the unpacked one into
    # its place, and the test happens afterwards.  So a rollback to a config
    # nginx will not load used to leave the bad config sitting on disk while
    # nginx carried on running the good one from memory.  Nothing looked wrong
    # until the next restart, which could be a reboot weeks later, and then the
    # node would not come back.  This is the oh-no button, so it is the last
    # place that should be able to leave a node in a state it cannot start
    # from.  The apply path has always kept a copy for exactly this reason;
    # this one did not.
    previous = None
    if MANAGED_DIR.exists():
        previous = MANAGED_DIR.parent / (MANAGED_DIR.name + ".before-rollback")
        if previous.exists():
            shutil.rmtree(previous)
        shutil.copytree(MANAGED_DIR, previous, symlinks=True)

    try:
        restore_backup(name)
        test = v_config_test(req)
        if not test["ok"]:
            if previous is not None:
                if MANAGED_DIR.exists():
                    shutil.rmtree(MANAGED_DIR)
                os.rename(previous, MANAGED_DIR)
                previous = None
            return {"ok": False, "output": test["output"],
                    "restored": None,
                    "note": "that backup does not pass a config test, so it was "
                            "put back the way it was and nothing changed"}

        rel = v_reload({})
        return {"ok": rel["ok"], "restored": name, "output": rel.get("output", "")}
    finally:
        if previous is not None and previous.exists():
            shutil.rmtree(previous, ignore_errors=True)


def v_nginx_metrics(req):
    """
    Pull the numbers out of stub_status.

    The installer builds nginx with --with-http_stub_status_module, and the
    config we generate exposes it on localhost only.  It is basic compared to
    what the paid version reports, but it is free and it is enough to see
    connection counts moving.
    """
    port = int(req.get("port", 7081))
    if not (1 <= port <= 65535):
        raise AgentError("that is not a port number", "bad_request")

    result = run(["curl", "-fsS", "--max-time", "5",
                  f"http://127.0.0.1:{port}/nginx_status"])
    if result["rc"] != 0:
        return {"ok": False, "error": result["stderr"].strip()}

    text = result["stdout"]
    metrics = {}
    m = re.search(r"Active connections:\s*(\d+)", text)
    if m:
        metrics["active_connections"] = int(m.group(1))
    m = re.search(r"^\s*(\d+)\s+(\d+)\s+(\d+)\s*$", text, re.MULTILINE)
    if m:
        metrics["accepts"] = int(m.group(1))
        metrics["handled"] = int(m.group(2))
        metrics["requests"] = int(m.group(3))
    m = re.search(r"Reading:\s*(\d+)\s+Writing:\s*(\d+)\s+Waiting:\s*(\d+)", text)
    if m:
        metrics["reading"] = int(m.group(1))
        metrics["writing"] = int(m.group(2))
        metrics["waiting"] = int(m.group(3))

    return {"ok": True, "metrics": metrics, "raw": text}


# Our own nftables table.  A table of our own means the whole thing can be
# removed in one command without touching a rule anybody else wrote, which
# matters on a box where a firewall is somebody's job.
NFT_TABLE = "nginxmgr"


def v_dns_redirect(req):
    """
    Send port 53 to the port the manager is really listening on.

    The manager cannot bind 53.  It runs unprivileged with no-new-privileges
    set, which makes the kernel ignore file capabilities, so the usual setcap
    route does nothing.  Turning that hardening off would weaken the most
    exposed component in the system to save one rule here.

    A destination NAT rewrites where the packet is headed and leaves the source
    alone, so the DNS server still sees the real client address.  Proxying
    through nginx would have cost that, and would also have meant a node whose
    nginx was stopped could not answer a query telling the world to use the
    other node, which is exactly when the answer matters most.
    """
    address = str(req.get("address", "")).strip()
    try:
        port = int(req.get("port", 5353))
    except (TypeError, ValueError):
        raise AgentError("that is not a port", "bad_request")
    if not 1024 <= port <= 65535:
        raise AgentError("the target port has to be above 1023", "bad_request")
    if address and not re.fullmatch(r"[0-9.]{7,15}", address):
        raise AgentError("that is not an address we will write a rule for", "bad_request")

    if not shutil.which("nft"):
        raise AgentError("nftables is not installed on this box", "not_found")

    # Built fresh every time rather than added to.  Appending would stack a new
    # rule on every restart, and the last one written is not necessarily the one
    # that matches.
    # Every address this box owns, not just the one it calls itself.
    #
    # This used to be `ip daddr <node address>`, which matches only packets
    # sent to the one address in NODE_ADDRESS.  A node reached on any other
    # address it owns, which is every node behind NAT, every node with a
    # separate public and internal address, and every node with more than one
    # interface, got no redirect at all: the listener answered perfectly on its
    # own port and port 53 refused the connection.
    #
    # The shape of the failure is what makes it worth this comment.  The node
    # looks healthy, the zone is right, the listener is up, and the box answers
    # when you test it from itself using the address it calls itself by.  It
    # only fails for the outside world, and on a two node fleet it only fails
    # visibly when the other node is gone, because until then the other node
    # answers everything.
    #
    # `fib daddr type local` matches a packet addressed to any address this
    # machine holds, and nothing else.  Forwarded traffic passing through on
    # its way somewhere else is still left alone, which a bare port match would
    # not do: a load balancer that routes for other people must not quietly
    # answer their DNS.
    #
    # Loopback is cut out of it, and that exclusion is not optional.  Ubuntu
    # and most others run a stub resolver on 127.0.0.53 and point
    # /etc/resolv.conf at it, so "every local address" includes the box's own
    # resolver.  Without the exclusion this table takes every name lookup the
    # machine makes and hands it to an authoritative server that knows two
    # zones, and the box loses DNS entirely: no apt, no certificate renewal,
    # no reaching a backend by name.  Found by breaking exactly that, on the
    # first version of this fix, one command after writing it.
    daddr = "fib daddr type local ip daddr != 127.0.0.0/8 "

    # dnat rather than redirect, and the difference only shows on this box.
    #
    # `redirect` sends a packet to the local machine, and in the output chain
    # that means 127.0.0.1.  The listener binds this node's public address, so
    # a query made from the box to its own address landed on loopback where
    # nothing was listening and came back refused, while the same query from
    # anywhere else worked perfectly.  That is the worst shape of bug to leave
    # in: it works everywhere except where somebody testing it will try first.
    #
    # Naming the address explicitly sends it to the socket that exists.
    target = f"{address}:{port}" if address else f":{port}"
    verb = "dnat to" if address else "redirect to"
    ruleset = f"""table ip {NFT_TABLE} {{
    chain prerouting {{
        type nat hook prerouting priority dstnat; policy accept;
        {daddr}udp dport 53 {verb} {target}
        {daddr}tcp dport 53 {verb} {target}
    }}
    chain output {{
        type nat hook output priority dstnat; policy accept;
        {daddr}udp dport 53 {verb} {target}
        {daddr}tcp dport 53 {verb} {target}
    }}
}}
"""

    run(["nft", "delete", "table", "ip", NFT_TABLE])      # fine if it is absent
    result = run(["nft", "-f", "-"], input_text=ruleset)

    # `fib daddr type local` wants a reasonably recent nftables.  On an older
    # one the whole ruleset is rejected, and a rejected ruleset means no
    # redirect at all, which is worse than the narrow rule it replaced.  So
    # fall back to naming the address, say so plainly, and carry on.
    if result["rc"] != 0 and "fib" in ruleset and address:
        narrow = ruleset.replace("fib daddr type local ip daddr != 127.0.0.0/8 ",
                                 f"ip daddr {address} ")
        second = run(["nft", "-f", "-"], input_text=narrow)
        if second["rc"] == 0:
            log.warning(
                "this nftables would not take a match on every local address, "
                "so port 53 is redirected only for %s.  A query sent to any "
                "other address this node holds will not be answered.", address)
            return {"installed": True, "address": address, "port": port,
                    "note": "narrow rule, this nftables is too old for "
                            "fib daddr type local"}

    if result["rc"] != 0:
        raise AgentError(f"could not install the dns redirect: {result['stderr'].strip()}",
                         "io_error")

    return {"installed": True, "address": address or "any", "port": port,
            "matches": "every local address"}


def v_dns_redirect_clear(req):
    """Take the redirect away, so port 53 goes back to whatever else wants it."""
    if not shutil.which("nft"):
        return {"removed": False, "note": "nftables is not installed"}
    run(["nft", "delete", "table", "ip", NFT_TABLE])
    return {"removed": True}


def v_dns_redirect_status(req):
    """
    What rule is actually in place, as opposed to what we think we wrote.

    `installed` and `present` say the same thing.  Both are here because the
    manager asked for `installed` while this only ever returned `present`, so
    the answer was always missing and always read as false.  The manager
    therefore deleted the whole table and wrote it again every ten seconds,
    for the life of every node.

    Rebuilding means `nft delete table` and then `nft -f`, so there is a gap
    with no rule at all on every one of those cycles, on the one thing that is
    supposed to keep answering.  The manager's own comment says it asks first
    "rather than just rewritten, because writing it means dropping the table
    and rebuilding it, and doing that every few seconds would put a small hole
    in the one thing this is here to keep up".  It was doing exactly that.

    `target` and `matches_all_local` let the manager notice a rule that exists
    but is the wrong shape, which is what an agent upgrade leaves behind.
    """
    if not shutil.which("nft"):
        return {"installed": False, "present": False,
                "note": "nftables is not installed"}
    result = run(["nft", "list", "table", "ip", NFT_TABLE])
    there = result["rc"] == 0
    ruleset = result["stdout"].strip()
    found = re.search(r"dnat to ([0-9.]+):(\d+)", ruleset) if there else None
    return {
        "installed": there,
        "present": there,
        "target": f"{found.group(1)}:{found.group(2)}" if found else None,
        "matches_all_local": "fib daddr type local" in ruleset,
        "ruleset": ruleset,
    }


def v_public_ip(req):
    """
    Work out what public address this box goes out as.

    We ask a few different services and go with whatever most of them say.  Any
    one of them can be down, or wrong, or lying, and picking the wrong answer
    here sends the cert request to the wrong node.  Best of three beats trusting
    one.  DNS first since it is faster and harder to mess with, then https.
    """
    answers = []

    # OpenDNS will tell you your own address.  No http, no TLS handshake.
    dns_checks = [
        (["dig", "+short", "+time=3", "+tries=1", "myip.opendns.com",
          "@resolver1.opendns.com"], "opendns"),
        (["dig", "+short", "+time=3", "+tries=1", "-t", "txt", "o-o.myaddr.l.google.com",
          "@ns1.google.com"], "google"),
    ]
    for cmd, source in dns_checks:
        if not shutil.which(cmd[0]):
            continue
        out = run(cmd, timeout=8)
        if out["rc"] == 0:
            ip = out["stdout"].strip().strip('"')
            if _looks_like_ip(ip):
                answers.append({"ip": ip, "source": source})

    https_checks = [
        ("https://api.ipify.org", "ipify"),
        ("https://ifconfig.me/ip", "ifconfig.me"),
        ("https://icanhazip.com", "icanhazip"),
    ]
    for url, source in https_checks:
        out = run(["curl", "-fsS", "--max-time", "6", url], timeout=10)
        if out["rc"] == 0:
            ip = out["stdout"].strip()
            if _looks_like_ip(ip):
                answers.append({"ip": ip, "source": source})

    if not answers:
        return {"ok": False, "error": "could not reach anything that would tell us our IP"}

    counts = {}
    for a in answers:
        counts[a["ip"]] = counts.get(a["ip"], 0) + 1
    winner = max(counts.items(), key=lambda kv: kv[1])

    return {
        "ok": True,
        "public_ip": winner[0],
        "agreement": winner[1],
        "total_checks": len(answers),
        "all_answers": answers,
    }


def _looks_like_ip(text):
    if not text or len(text) > 45:
        return False
    try:
        socket.inet_pton(socket.AF_INET, text)
        return True
    except OSError:
        pass
    try:
        socket.inet_pton(socket.AF_INET6, text)
        return True
    except OSError:
        return False


def v_local_addresses(req):
    """
    Every address on this box.

    Used two ways.  It tells us if this node is holding a floating VIP, and it
    gives the manager the list of addresses to put in the whitelist so the
    cluster's own health checks never get blocked by an ACL somebody wrote.
    """
    addrs = []
    out = run(["ip", "-json", "addr", "show"])
    if out["rc"] == 0:
        try:
            for iface in json.loads(out["stdout"]):
                for info in iface.get("addr_info", []):
                    if info.get("family") in ("inet", "inet6"):
                        addrs.append({
                            "interface": iface.get("ifname"),
                            "address": info.get("local"),
                            "prefix": info.get("prefixlen"),
                            "family": info.get("family"),
                            "scope": info.get("scope"),
                        })
        except (json.JSONDecodeError, TypeError):
            pass

    return {"addresses": addrs, "hostname": socket.gethostname()}


def v_write_hook_scripts(req):
    """
    Write the certbot hook scripts.

    These live outside the container because certbot runs on the host and has
    to be able to exec them.  They are tiny: all they do is call back into the
    manager on localhost with a one time token.  We write them from here so the
    manager can update them without anybody hand copying files to every box.
    """
    scripts = req.get("scripts")
    if not isinstance(scripts, dict):
        raise AgentError("scripts has to be an object of name to contents", "bad_request")

    hook_dir = Path("/usr/local/lib/nginx-fleet-manager")
    hook_dir.mkdir(parents=True, exist_ok=True)
    os.chmod(hook_dir, 0o750)

    written = []
    for name, content in scripts.items():
        if not re.fullmatch(r"[a-z0-9_-]{1,64}\.sh", str(name)):
            raise AgentError(f"{name} is not a name we will write", "bad_request")
        if not isinstance(content, str):
            raise AgentError(f"contents of {name} has to be a string", "bad_request")
        atomic_write(hook_dir / name, content, mode=0o750)
        written.append(str(hook_dir / name))

    return {"written": written}


def _read_upgrade_state():
    if not UPGRADE_STATE.is_file():
        return {"state": "idle"}
    try:
        return json.loads(UPGRADE_STATE.read_text())
    except (json.JSONDecodeError, OSError):
        return {"state": "unknown"}


def _write_upgrade_state(**fields):
    UPGRADE_STATE.parent.mkdir(parents=True, exist_ok=True)
    current = _read_upgrade_state()
    current.update(fields)
    current["updated"] = datetime.now(timezone.utc).isoformat()
    atomic_write(UPGRADE_STATE, json.dumps(current, indent=1), mode=0o644)


# The build runs as its own unit rather than as a child of this agent.  See
# nginx-rebuild.service for why; the short version is that this agent runs with
# ProtectSystem=strict and a source build has to write where a package manager
# writes.  A child process inherits that sandbox, so the build has to be handed
# to systemd instead of forked from here.
REBUILD_UNIT = "nginx-rebuild.service"
REVERT_UNIT = "nginx-revert.service"

# On tmpfs, which the agent can write and which clears at reboot.  A build that
# was interrupted by a reboot did not finish, and coming back up with no marker
# is the honest answer.
REBUILD_ENV = Path("/run/nginxmgr/rebuild.env")
REBUILD_MARKER = Path("/run/nginxmgr/rebuild.started")

# Written by the unit itself as it stops.  See nginx-rebuild.service: systemd
# unloads a finished oneshot unit and every property it has resets to zero, so
# asking systemd after the event cannot tell a successful build from one that
# never happened.  This file existing is what says the build is over.
REBUILD_RESULT = Path("/run/nginxmgr/rebuild.result")


def _have_systemd():
    return Path("/run/systemd/system").is_dir()


def _unit_props(unit, names):
    """Ask systemd about a unit.  Missing properties come back as empty."""
    out = run(["systemctl", "show", unit, "-p", ",".join(names)])
    props = {}
    for line in (out["stdout"] or "").splitlines():
        key, _, value = line.partition("=")
        if key:
            props[key] = value
    return props


def _systemd_build_state():
    """
    How the build unit is doing, as the same shape the file based path returns.

    The trap here is that a unit which has never run looks exactly like one that
    ran and succeeded: ActiveState=inactive, Result=success, ExecMainStatus=0.
    Reading that as a finished build would report success for a build that was
    never started, which is the failure this whole exercise turned up in the
    first place.  So a build only counts as ours if the unit's own start
    timestamp is at or after the moment we asked for it.
    """
    marker = {}
    if REBUILD_MARKER.is_file():
        try:
            marker = json.loads(REBUILD_MARKER.read_text())
        except (json.JSONDecodeError, OSError):
            marker = {}

    if not marker:
        return {"state": "idle"}

    props = _unit_props(REBUILD_UNIT, ["LoadState", "ActiveState", "SubState"])

    if props.get("LoadState") in ("not-found", "masked", "error", "", None):
        return {
            "state": "unknown",
            "error": (
                f"{REBUILD_UNIT} is not installed on this box.  It ships in "
                f"host-agent/ and install.sh puts it in place; an install from "
                f"before it existed will not have it."
            ),
        }

    base = {
        "state": "running",
        "started": marker.get("started"),
        "nginx_version": marker.get("nginx_version"),
        "openssl_version": marker.get("openssl_version"),
    }

    if props.get("ActiveState") in ("activating", "active", "reloading", "deactivating"):
        return base

    # Not running.  Either it has finished and left its result behind, or
    # systemd has not got round to starting it yet.
    if REBUILD_RESULT.is_file():
        try:
            recorded = REBUILD_RESULT.read_text().split()
        except OSError:
            recorded = []

        result = recorded[0] if recorded else "unknown"
        status = recorded[1] if len(recorded) > 1 else ""

        return {
            **base,
            "state": "finished",
            "ok": result == "success" and status in ("0", ""),
            "finished": True,
            "result": result,
            "exit_status": status,
        }

    if props.get("ActiveState") == "failed":
        # Failed before it could write a result, which usually means it never
        # got as far as running the installer at all.
        return {
            **base,
            "state": "finished",
            "ok": False,
            "finished": True,
            "result": "failed",
            "error": f"{REBUILD_UNIT} failed to start.  See journalctl -u {REBUILD_UNIT}.",
        }

    # Asked for, not begun.  Queued behind something, or systemd is slow.
    return base


def v_nginx_upgrade(req):
    """
    Rebuild nginx from source, at a version and module list we are given.

    This is the same script an admin would run by hand, driven from here so the
    fleet can be walked one node at a time instead of somebody sshing to four
    boxes and hoping they all end up the same.

    It runs detached and writes progress to a file.  A build takes ten to
    twenty minutes, which is far longer than any request should wait, and a
    dropped connection halfway through a compile must not leave a box with half
    an nginx.

    Nothing about the caller's input becomes a shell command.  Every value is
    checked here first, the versions against a version shaped pattern and the
    WAF switch against the two strings it is allowed to be, then passed as
    environment variables, which is exactly how the installer expects to be
    told.  They go into an environment file the unit reads, so no part of the
    request is ever parsed as a shell word.
    """
    if not INSTALLER.is_file():
        raise AgentError(
            f"no installer script at {INSTALLER}.  Put nginx-installer.sh there, "
            f"or set NFM_INSTALLER on the agent.",
            "missing_installer",
        )

    current = _read_upgrade_state()
    if current.get("state") == "running":
        raise AgentError("a build is already running on this box", "busy")

    nginx_version = req.get("nginx_version")
    openssl_version = req.get("openssl_version")

    version_re = re.compile(r"^\d+\.\d+\.\d+[a-z]?$")
    for label, value in (("nginx", nginx_version), ("openssl", openssl_version)):
        if value and not version_re.match(str(value)):
            raise AgentError(f"{value!r} is not a {label} version number", "bad_request")

    # The WAF module.  Sent on every rebuild once a fleet has one, because the
    # installer rebuilds from the list it is given rather than from what is
    # already on the box: leave this out of a later version upgrade and nginx
    # comes back without the module, with every site that had the WAF on now
    # failing its config test.  So the manager always says which it wants, and
    # absent means off.
    with_modsecurity = req.get("with_modsecurity")
    if with_modsecurity is None:
        with_modsecurity = False
    if not isinstance(with_modsecurity, bool):
        raise AgentError("with_modsecurity has to be true or false", "bad_request")

    env = {}
    if nginx_version:
        env["NGINX_VERSION"] = str(nginx_version)
    if openssl_version:
        env["OPENSSL_VERSION"] = str(openssl_version)
    env["WITH_MODSECURITY"] = "1" if with_modsecurity else "0"

    if _have_systemd():
        # Hand it to systemd.  The versions go in an environment file rather
        # than on a command line, so nothing the caller sent is ever parsed as
        # a shell word, and both have already been checked against a version
        # shaped pattern above.
        REBUILD_ENV.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(
            REBUILD_ENV,
            "".join(f"{k}={v}\n" for k, v in env.items()),
            mode=0o600,
        )

        # Last build's outcome goes before this one is asked for, or the first
        # status call would read the old result and report the new build as
        # already finished.
        REBUILD_RESULT.unlink(missing_ok=True)

        # Written before the unit is asked to start, so that a build which
        # begins between these two lines still counts as ours.  The other way
        # round leaves a window where a finished build looks like it was never
        # asked for.
        atomic_write(
            REBUILD_MARKER,
            json.dumps({
                "started": datetime.now(timezone.utc).isoformat(),
                "monotonic_us": int(time.monotonic() * 1_000_000),
                "nginx_version": nginx_version,
                "openssl_version": openssl_version,
                "with_modsecurity": with_modsecurity,
            }),
            mode=0o600,
        )

        log.warning("starting an nginx rebuild through %s: %s",
                    REBUILD_UNIT, env or "same versions, module change")

        # --no-block, because a build is twenty minutes and this call has to
        # come back now.  Failures show up through the status verb.
        out = run(["systemctl", "start", "--no-block", REBUILD_UNIT])
        if out["rc"] != 0:
            REBUILD_MARKER.unlink(missing_ok=True)
            raise AgentError(
                f"could not start {REBUILD_UNIT}: "
                f"{(out['stderr'] or out['stdout']).strip()[:400]}",
                "build_start_failed",
            )

        return {"started": True, "versions": env, "unit": REBUILD_UNIT}

    # No systemd.  Nothing is sandboxing us either, so the old way still works.
    _write_upgrade_state(
        state="running",
        started=datetime.now(timezone.utc).isoformat(),
        nginx_version=nginx_version,
        openssl_version=openssl_version,
        with_modsecurity=with_modsecurity,
        finished=None,
        ok=None,
        error=None,
    )

    # Detached, with output to a log the manager can read back.  setsid means
    # it survives this connection going away, which it will, because nobody is
    # holding a socket open for twenty minutes.
    UPGRADE_LOG.parent.mkdir(parents=True, exist_ok=True)

    wrapper = f"""#!/usr/bin/env bash
# Written by the agent.  Runs the installer and records how it went.
set -o pipefail

export STATE_FILE="{UPGRADE_STATE}"

# Everything this script says goes to the log too, so a build that goes wrong
# after the installer finishes is not invisible.
exec >> "{UPGRADE_LOG}" 2>&1

echo "=== build started at $(date -Is) ==="
if "{INSTALLER}" install 2>&1; then
    result=ok
else
    result=failed
fi
echo "=== build finished $result at $(date -Is) ==="

# The installer restarts nginx through systemd.  Without systemd it says so and
# leaves it alone, which means the old binary carries on serving and the whole
# rebuild has no effect until somebody notices.  Handle that here.
if [ "$result" = "ok" ] && [ ! -d /run/systemd/system ]; then
    echo "no systemd, restarting nginx directly so the new build takes over"
    "{NGINX_BIN}" -t && {{ "{NGINX_BIN}" -s quit 2>/dev/null; sleep 2; "{NGINX_BIN}"; }}
    echo "nginx is now: $("{NGINX_BIN}" -v 2>&1)"
fi

# The result goes in through the environment, not interpolated into the
# script.
#
# The first version of this used a quoted heredoc, which means no shell
# expansion, so the python compared the literal string "$result" against "ok"
# and every build was recorded as a failure.  A successful rebuild then halted
# the walk and told you the node had not come back cleanly, while the node sat
# there perfectly happy on the new version.
#
# The heredoc stays quoted, because the alternative lets the shell expand
# things inside python source.  The value comes in as a variable instead.
BUILD_RESULT="$result" python3 - <<'PYEND'
import os, json, pathlib, datetime

p = pathlib.Path(os.environ["STATE_FILE"])
try:
    state = json.loads(p.read_text())
except Exception:
    state = {{}}

state["state"] = "finished"
state["ok"] = os.environ.get("BUILD_RESULT") == "ok"
state["finished"] = datetime.datetime.now(datetime.timezone.utc).isoformat()
p.write_text(json.dumps(state, indent=1))
PYEND
"""

    runner = Path("/usr/local/lib/nginx-fleet-manager/run-upgrade.sh")
    runner.parent.mkdir(parents=True, exist_ok=True)
    atomic_write(runner, wrapper, mode=0o750)

    full_env = os.environ.copy()
    full_env.update(env)

    log.warning("starting an nginx rebuild: %s", env or "same versions, module change")

    subprocess.Popen(
        ["setsid", "bash", str(runner)],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        stdin=subprocess.DEVNULL,
        env=full_env,
        start_new_session=True,
    )

    return {"started": True, "versions": env}


def v_nginx_upgrade_status(req):
    """How the build is going, and the tail of its output."""
    state = _systemd_build_state() if _have_systemd() else _read_upgrade_state()

    tail = ""
    if UPGRADE_LOG.is_file():
        try:
            lines = UPGRADE_LOG.read_text(errors="replace").splitlines()
            tail = "\n".join(lines[-int(req.get("lines", 40)):])
        except OSError:
            pass

    # What is actually installed right now, so the manager can tell whether the
    # build changed anything rather than trusting the exit code alone.
    version = None
    if NGINX_BIN.is_file():
        out = run([str(NGINX_BIN), "-v"])
        banner = (out["stderr"] or out["stdout"]).strip()
        m = re.search(r"nginx/(\S+)", banner)
        if m:
            version = m.group(1)

    return {**state, "log_tail": tail, "installed_version": version}


def v_nginx_revert(req):
    """
    Put the previous nginx back.

    The installer keeps a snapshot of the binary and config before every build,
    and this is its revert path.  It is the way out when a new build starts but
    misbehaves.
    """
    if not INSTALLER.is_file():
        raise AgentError(f"no installer script at {INSTALLER}", "missing_installer")

    if _have_systemd():
        # Same reasoning as the build: a revert copies a binary back over
        # /usr/sbin/nginx, which this agent's sandbox forbids.  Run it as a unit.
        # No --no-block here, because a revert is quick and the caller wants to
        # know whether it worked.
        # Where the log ends before we start, so what comes back is what the
        # revert said and not the tail of the last build.  The first version
        # returned the last forty lines of the file, which on a box that had
        # just built something was forty lines about a successful build sitting
        # under a failure, and the actual reason was nowhere to be seen.
        before = UPGRADE_LOG.stat().st_size if UPGRADE_LOG.is_file() else 0

        out = run(["systemctl", "start", REVERT_UNIT], timeout=300)

        said = ""
        if UPGRADE_LOG.is_file():
            try:
                with UPGRADE_LOG.open("r", errors="replace") as handle:
                    handle.seek(before)
                    said = handle.read()
            except OSError:
                pass

        if not said.strip():
            said = (out["stdout"] + out["stderr"])

        return {
            "ok": out["rc"] == 0,
            "output": said.strip()[-4000:],
        }

    result = run([str(INSTALLER), "revert"], timeout=300)
    return {
        "ok": result["rc"] == 0,
        "output": (result["stdout"] + result["stderr"]).strip()[-4000:],
    }




def v_acme_register_test(req):
    """
    Register an account against an ACME directory, and keep nothing.

    Asks for no certificate, so nothing is issued and nothing is spent.  All
    this proves is that the directory answers and that the external account
    credentials are accepted, which is the half that fails quietly months later
    if it is wrong.

    Uses its own config directory so a failed attempt cannot disturb the
    accounts certbot is already using for real certificates.
    """
    import shutil
    import tempfile

    acme_server = req.get("acme_server")
    if not acme_server or not re.fullmatch(
            r"https://[A-Za-z0-9._:-]{1,253}(/[A-Za-z0-9._~/-]*)?", str(acme_server)):
        raise AgentError("that acme server url is not valid", "bad_request")

    eab_kid = req.get("eab_kid")
    eab_hmac = req.get("eab_hmac_key")
    if bool(eab_kid) != bool(eab_hmac):
        raise AgentError("external account binding needs both halves", "bad_request")

    workdir = tempfile.mkdtemp(prefix="nfm-acme-test-")
    try:
        cmd = [
            "certbot", "register",
            "--non-interactive",
            "--agree-tos",
            "--register-unsafely-without-email",
            "--server", str(acme_server),
            "--config-dir", workdir,
            "--work-dir", workdir,
            "--logs-dir", workdir,
        ]
        if eab_kid:
            if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,512}", str(eab_kid)):
                raise AgentError("that external account key id is not valid",
                                 "bad_request")
            if not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,1024}", str(eab_hmac)):
                raise AgentError("that external account hmac key is not valid",
                                 "bad_request")
            cmd += ["--eab-kid", str(eab_kid), "--eab-hmac-key", str(eab_hmac)]

        result = run(cmd, timeout=90)
        if result["rc"] == 0:
            return {"ok": True}
        # certbot puts the useful sentence at the end, and the rest is noise
        # nobody can act on.
        output = ((result["stderr"] or "") + (result["stdout"] or "")).strip()
        tail = [ln for ln in output.splitlines() if ln.strip()][-4:]
        return {"ok": False, "error": "\n".join(tail) or "registration was refused"}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)




# ==============================================================================
# The tunnel
# ==============================================================================
#
# WireGuard so a backend can be reached without a public address.  The agent
# owns it for the same reason it owns nginx: bringing an interface up and
# writing firewall rules needs root, and the manager does not have it.
#
# Two rules run through all of this and neither is negotiable:
#
#   * The private key is generated here and never leaves.  Only the public half
#     is ever reported.
#   * AllowedIPs for a peer is that peer's single address and nothing wider.  A
#     tunnel that carries a route to anywhere else is a tunnel that has quietly
#     become part of somebody's network.

TUNNEL_IF = "nfm0"
# /etc/wireguard, because that is where the tools expect it.
#
# Not a style choice.  Ubuntu ships enforcing AppArmor profiles for wg and
# wg-quick that only permit reading configs from this directory.  Keeping the
# config under /etc/nginx meant wg-quick was refused with "Permission denied"
# on a file root owned and could read perfectly well by hand, which reads like
# a file permission problem and is not one.
TUNNEL_DIR = Path("/etc/wireguard")


def _wg_available():
    return shutil.which("wg") is not None


# Installing what the tunnel needs, handed to systemd for the same reason the
# nginx build is.  See nfm-tunnel-install.service.
TUNNEL_INSTALL_UNIT = "nfm-tunnel-install.service"
TUNNEL_INSTALL_SCRIPT = Path("/opt/nfm-tunnel-installer.sh")
TUNNEL_INSTALL_RESULT = Path("/run/nginxmgr/tunnel-install.result")
TUNNEL_INSTALL_LOG = Path("/var/log/nginx-fleet-manager-tunnel-install.log")


def _tunnel_ready():
    """
    Whether this node can actually run the tunnel, asked rather than assumed.

    The script is the one place that knows what the answer depends on, so it
    gets asked instead of this guessing from the presence of a binary.  A node
    with the tools and no datapath looks installed and carries nothing.
    """
    if not TUNNEL_INSTALL_SCRIPT.is_file():
        return {"ready": _wg_available(), "detail": "", "checked": False}
    out = run([str(TUNNEL_INSTALL_SCRIPT), "check"], timeout=60)
    return {"ready": out["rc"] == 0,
            "detail": (out["stdout"] or out["stderr"] or "").strip()[-1500:],
            "checked": True}


def v_tunnel_install(req):
    """
    Install what the tunnel needs on this node.

    Starts the unit and returns.  Installing takes as long as a package
    manager takes, which is longer than a request should wait, so the GUI asks
    how it is going rather than holding the connection open.
    """
    if not _have_systemd():
        raise AgentError(
            "there is no systemd here, so this has to be installed by hand: "
            "the package is wireguard-tools", "unsupported")
    if not TUNNEL_INSTALL_SCRIPT.is_file():
        raise AgentError(
            f"{TUNNEL_INSTALL_SCRIPT} is not on this node, so it was installed "
            f"before this existed.  Run install.sh --upgrade there.", "unsupported")

    state = _tunnel_ready()
    if state["ready"]:
        return {"ok": True, "already": True, "detail": state["detail"]}

    active = run(["systemctl", "is-active", "--quiet", TUNNEL_INSTALL_UNIT],
                 timeout=15)["rc"] == 0
    if active:
        return {"ok": True, "started": False, "running": True}

    # The old result, gone before the new run, so a stale one cannot be read as
    # this one finishing instantly.
    try:
        TUNNEL_INSTALL_RESULT.unlink()
    except OSError:
        pass

    out = run(["systemctl", "start", "--no-block", TUNNEL_INSTALL_UNIT], timeout=30)
    if out["rc"] != 0:
        detail = (out["stderr"] or out["stdout"] or "").strip()[:300]
        raise AgentError(f"could not start the install: {detail or 'no detail'}",
                         "failed")

    return {"ok": True, "started": True, "running": True}


def v_tunnel_install_status(req):
    """How the install is going, what it said, and whether this node is ready."""
    running = False
    if _have_systemd():
        running = run(["systemctl", "is-active", "--quiet", TUNNEL_INSTALL_UNIT],
                      timeout=15)["rc"] == 0

    result = ""
    if TUNNEL_INSTALL_RESULT.is_file():
        try:
            result = TUNNEL_INSTALL_RESULT.read_text(errors="replace").strip()
        except OSError:
            pass

    tail = ""
    if TUNNEL_INSTALL_LOG.is_file():
        try:
            lines = TUNNEL_INSTALL_LOG.read_text(errors="replace").splitlines()
            tail = "\n".join(lines[-int(req.get("lines", 40)):])
        except OSError:
            pass

    state = _tunnel_ready()
    return {"running": running, "result": result, "log_tail": tail,
            "ready": state["ready"], "detail": state["detail"],
            "installed": _wg_available()}


def v_tunnel_key(req):
    """
    This node's tunnel key pair, made once and kept.

    Reports only the public half.  The private half is written with no group or
    other access and stays on this box, so nothing that reads the API or the
    database can ever obtain it.
    """
    if not _wg_available():
        raise AgentError("wireguard is not installed on this node", "unsupported")

    TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TUNNEL_DIR, 0o700)
    private = TUNNEL_DIR / "private.key"

    if not private.exists():
        made = run(["wg", "genkey"], timeout=10)
        if made["rc"] != 0:
            raise AgentError("could not make a tunnel key", "failed")
        private.write_text(made["stdout"].strip() + "\n")
        os.chmod(private, 0o600)

    public = run(["wg", "pubkey"], input_text=private.read_text(), timeout=10)
    if public["rc"] != 0:
        raise AgentError("could not read the tunnel key", "failed")
    return {"public_key": public["stdout"].strip()}


def v_tunnel_apply(req):
    """
    Write the interface and the peers, then bring it up.

    Rewritten whole every time rather than patched, for the same reason the
    nginx config is: a file assembled from what is wanted now cannot drift from
    what was asked for, and a half applied peer list is a machine that is
    reachable when it should not be.
    """
    if not _wg_available():
        raise AgentError("wireguard is not installed on this node", "unsupported")

    address = req.get("address")
    port = int(req.get("listen_port") or 51820)
    peers = req.get("peers") or []

    if not re.fullmatch(r"[0-9.]{7,18}/\d{1,2}", str(address or "")):
        raise AgentError("that tunnel address is not valid", "bad_request")
    if not 1 <= port <= 65535:
        raise AgentError("that listen port is not valid", "bad_request")

    TUNNEL_DIR.mkdir(parents=True, exist_ok=True)
    os.chmod(TUNNEL_DIR, 0o700)
    private = TUNNEL_DIR / "private.key"
    if not private.exists():
        v_tunnel_key({})

    # The key goes in the file, not in a PostUp.
    #
    # PostUp looks tidier and is wrong.  wg-quick runs PostUp when the
    # interface comes up, so the key is set once and everything works.  Every
    # change after that is a reload, and reload is
    #
    #   wg syncconf %i <(wg-quick strip %i)
    #
    # where strip removes exactly the wg-quick only lines, PostUp among them.
    # syncconf then applies what is left as the whole truth about the
    # interface, and what is left has no key, so it takes the key away.
    #
    # Nothing complains.  The interface stays up, keeps its address, keeps its
    # peers and keeps listening.  It simply drops every handshake, because it
    # has no key to answer with, and there is no counter or log line anywhere
    # that says so.  Every tunnel was dead from its first config change
    # onwards, and both ends looked perfect.
    #
    # PrivateKey survives strip, so it survives reload.
    key_text = private.read_text().strip()
    lines = [
        "# Generated by Failover LB.  Do not edit this by hand.",
        "[Interface]",
        f"Address = {address}",
        f"ListenPort = {port}",
        f"PrivateKey = {key_text}",
        "",
    ]
    for peer in peers:
        key = str(peer.get("public_key") or "").strip()
        peer_address = str(peer.get("address") or "").strip()
        if not re.fullmatch(r"[A-Za-z0-9+/]{42,44}=", key):
            raise AgentError("a peer public key is not valid", "bad_request")
        if not re.fullmatch(r"[0-9.]{7,15}", peer_address):
            raise AgentError("a peer address is not valid", "bad_request")
        lines += [
            f"# {peer.get('name') or 'peer'}",
            "[Peer]",
            f"PublicKey = {key}",
        ]

        # The pre-shared key, when this workload has one.
        #
        # It is WireGuard's own answer to a quantum computer: 32 bytes mixed
        # into the handshake as an extra symmetric input, so breaking
        # Curve25519 is no longer enough on its own to read traffic somebody
        # recorded today.  Optional per peer on purpose, because both ends have
        # to hold the same value and adding one to a workload that is already
        # connected would drop it until the far end is updated too.
        psk = str(peer.get("psk") or "").strip()
        if psk:
            if not re.fullmatch(r"[A-Za-z0-9+/]{42,44}=", psk):
                raise AgentError("a peer pre-shared key is not valid", "bad_request")
            lines.append(f"PresharedKey = {psk}")

        lines += [
            # One address, never a range.  This is what keeps a workload from
            # being able to speak for anything but itself.
            f"AllowedIPs = {peer_address}/32",
            "",
        ]

    conf = TUNNEL_DIR / f"{TUNNEL_IF}.conf"
    conf.write_text("\n".join(lines))
    os.chmod(conf, 0o600)

    # Hand the interface to systemd rather than bringing it up from here.
    #
    # wireguard-tools ships wg-quick@.service, so the OS already knows how to
    # own this.  Driving wg-quick as a child of the agent does not work and
    # cannot be made to: the agent runs with NoNewPrivileges, and under that
    # flag the kernel refuses AppArmor profile transitions, so a confined
    # wg-quick cannot exec ip or wg at all.  It fails with "Operation not
    # permitted" on running a binary, which reads like a missing capability and
    # is not one.
    #
    # Asking systemd to start the unit sidesteps all of it.  The unit runs in
    # its own context, unconfined by this service's sandbox, which is the same
    # reason the nginx build runs from its own unit rather than from here.
    #
    # reload rather than restart when it is already up: wg-quick's reload does
    # a syncconf, so adding one workload does not drop every tunnel that was
    # already working.
    unit = f"wg-quick@{TUNNEL_IF}.service"
    active = run(["systemctl", "is-active", "--quiet", unit], timeout=15)["rc"] == 0

    if active:
        result = run(["systemctl", "reload", unit], timeout=30)
        action = "reloaded"
    else:
        run(["systemctl", "enable", unit], timeout=30)
        result = run(["systemctl", "restart", unit], timeout=45)
        action = "started"

    if result["rc"] != 0:
        detail = (result["stderr"] or result["stdout"] or "").strip()[:300]
        status = run(["systemctl", "status", unit, "--no-pager", "-n", "10"],
                     timeout=15)
        raise AgentError(
            f"systemd could not bring the tunnel up: {detail or 'no detail'} "
            f"{(status['stdout'] or '').strip()[-300:]}", "failed")

    # Prove the interface can actually answer, rather than assuming it.
    #
    # An interface with no key is up, addressed, listening and carrying its
    # full peer list, and it drops every handshake in silence.  It is the
    # exact shape of a tunnel that works, which is why it went unnoticed for a
    # day.  A cheap check here turns it into a failed apply with a reason.
    shown = run(["wg", "show", TUNNEL_IF, "public-key"], timeout=15)
    if shown["rc"] != 0 or not shown["stdout"].strip() or \
            shown["stdout"].strip() == "(none)":
        raise AgentError(
            f"the tunnel came up with no key, so it would refuse every "
            f"connection ({action}, {shown['stdout'].strip() or 'no key shown'})",
            "failed")

    return {"ok": True, "interface": TUNNEL_IF, "peers": len(peers),
            "public_key": shown["stdout"].strip()}


def v_tunnel_status(req):
    """What the tunnel is doing, including when each peer was last heard from."""
    if not _wg_available():
        return {"installed": False, "up": False, "peers": []}

    up = run(["ip", "link", "show", TUNNEL_IF], timeout=10)["rc"] == 0
    peers = []
    if up:
        dump = run(["wg", "show", TUNNEL_IF, "dump"], timeout=10)
        for line in (dump["stdout"] or "").splitlines()[1:]:
            parts = line.split("\t")
            if len(parts) < 5:
                continue
            peers.append({
                "public_key": parts[0],
                "allowed_ips": parts[3],
                "last_handshake": int(parts[4]) if parts[4].isdigit() else 0,
            })
    return {"installed": True, "up": up, "interface": TUNNEL_IF, "peers": peers}


def v_tunnel_down(req):
    """Take the interface down, for turning the whole thing off."""
    if not _wg_available():
        return {"ok": True, "note": "wireguard is not installed here"}
    unit = f"wg-quick@{TUNNEL_IF}.service"
    run(["systemctl", "disable", "--now", unit], timeout=45)
    return {"ok": True}


# ==============================================================================
# The country database
# ==============================================================================
#
# Blocking by country needs a MaxMind format database on every node, and a node
# without one refuses the whole config, so this is the half that puts it there.
#
# Two sources, and the difference is an account.  db-ip publish a free country
# database every month and ask for nothing; MaxMind's GeoLite2 is free and
# wants an account id and a licence key.  Both are the same format once
# downloaded, so nothing past this function cares which was used.
#
# The manager never sends a URL or a path.  It sends the name of a source and,
# for MaxMind, the credentials, and everything else is decided here.  A verb
# that took a URL and a destination would be a way to write any file anywhere
# as root, which is the one thing this agent exists not to be.

GEOIP_DIR = Path("/usr/share/GeoIP")
GEOIP_FILE = GEOIP_DIR / "nfm-country.mmdb"
GEOIP_SOURCE_FILE = GEOIP_DIR / ".nfm-source"

# What a MaxMind format file has near its end.  Checked before anything is put
# in place, because half a download is still a file, and nginx meeting one
# refuses to start.
MMDB_MARKER = b"\xab\xcd\xefMaxMind.com"

GEOIP_MAX_BYTES = 128 * 1024 * 1024
GEOIP_HOSTS = {"dbip": "download.db-ip.com", "maxmind": "download.maxmind.com"}


def _geoip_fetch(url, timeout=180):
    """Download one URL, with a ceiling, and refuse anything but our two hosts."""
    import urllib.error
    import urllib.parse
    import urllib.request

    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in GEOIP_HOSTS.values():
        raise AgentError(f"{host} is not a country database source", "refused")

    request = urllib.request.Request(url, headers={"User-Agent": "failover-lb"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(GEOIP_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AgentError(f"{host} answered {exc.code}", "failed")
    except Exception as exc:
        raise AgentError(f"could not reach {host}: {exc}", "failed")

    if len(data) > GEOIP_MAX_BYTES:
        raise AgentError("that download is far bigger than a country database",
                         "failed")
    return data


def _geoip_extract(data, source):
    """Get the .mmdb out of whatever the source wraps it in."""
    import gzip
    import io
    import tarfile

    if source == "dbip":
        # A single gzipped file.
        return gzip.decompress(data)

    # MaxMind ship a tarball with the database inside a dated folder.
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        for member in tar.getmembers():
            if member.isfile() and member.name.endswith(".mmdb"):
                extracted = tar.extractfile(member)
                if extracted:
                    return extracted.read()
    raise AgentError("no .mmdb file inside what MaxMind sent", "failed")


def _geoip_url(source, payload):
    """Where to get it, worked out here rather than taken from the caller."""
    if source == "dbip":
        # Published monthly, on the first.  Early in the month the new one may
        # not be up yet, so the previous month is tried as well: a database a
        # few weeks old is worth far more than a failed install.
        now = datetime.now(timezone.utc)
        months = [(now.year, now.month)]
        months.append((now.year - 1, 12) if now.month == 1
                      else (now.year, now.month - 1))
        return [f"https://download.db-ip.com/free/dbip-country-lite-"
                f"{year:04d}-{month:02d}.mmdb.gz" for year, month in months]

    account = str(payload.get("account_id") or "").strip()
    key = str(payload.get("license_key") or "").strip()
    if not key:
        raise AgentError("MaxMind needs a licence key", "invalid")
    if not re.fullmatch(r"[A-Za-z0-9_\-]{1,80}", key) or (
            account and not re.fullmatch(r"[0-9]{1,20}", account)):
        raise AgentError("that does not look like a MaxMind account id and key",
                         "invalid")
    return ["https://download.maxmind.com/app/geoip_download"
            f"?edition_id=GeoLite2-Country&license_key={key}&suffix=tar.gz"]


def v_geoip_install(req):
    """
    Put a country database on this node, from one of two known sources.

    Written to a temporary file beside the real one and renamed into place, so
    a download that dies half way leaves the old database serving rather than a
    truncated one that stops nginx.
    """
    payload = req.get("payload") or req
    source = str(payload.get("source") or "").strip()
    if source not in GEOIP_HOSTS:
        raise AgentError("the source has to be dbip or maxmind", "invalid")

    # The one folder outside /etc and /var this agent writes, and the sandbox
    # only has a hole for it if the unit file is current.  An older unit gives a
    # read only filesystem here, which as a bare OSError reads like a broken
    # disk rather than an agent that needs upgrading.
    try:
        GEOIP_DIR.mkdir(parents=True, exist_ok=True)
        probe = GEOIP_DIR / ".nfm-write-test"
        probe.write_bytes(b"")
        probe.unlink()
    except OSError as exc:
        raise AgentError(
            f"{GEOIP_DIR} is not writable by the agent ({exc.strerror}).  Run "
            "install.sh --upgrade on this node, which makes the folder and "
            "gives the agent a hole in its sandbox for it.", "failed")

    errors = []
    data = None
    used = None
    for url in _geoip_url(source, payload):
        try:
            data = _geoip_fetch(url)
            used = url
            break
        except AgentError as exc:
            errors.append(str(exc))
    if data is None:
        raise AgentError("; ".join(errors) or "nothing to download", "failed")

    mmdb = _geoip_extract(data, source)

    # Is this really a database.  The marker sits near the end of the file, so
    # a truncated download fails here rather than at the next nginx start.
    if MMDB_MARKER not in mmdb[-200000:]:
        raise AgentError("what came back is not a MaxMind format database",
                         "failed")

    temporary = GEOIP_FILE.with_suffix(".mmdb.new")
    temporary.write_bytes(mmdb)
    os.chmod(temporary, 0o644)
    os.replace(temporary, GEOIP_FILE)
    GEOIP_SOURCE_FILE.write_text(
        json.dumps({"source": source,
                    "installed": datetime.now(timezone.utc).isoformat(
                        timespec="seconds"),
                    "url": used.split("?")[0]}))

    log.warning("installed a country database from %s, %d bytes", source, len(mmdb))
    return {"ok": True, "source": source, "bytes": len(mmdb),
            "path": str(GEOIP_FILE)}


# ==============================================================================
# The OWASP Core Rule Set
# ==============================================================================
#
# The rules are the half of a WAF that people actually mean when they say
# ModSecurity.  Same problem as the country database: they have to be on every
# node or the node without them refuses the whole config, and telling somebody
# to go and unpack a tarball on each box by hand is how a feature ends up
# switched on in the GUI and broken in the fleet.
#
# So the same shape is used deliberately.  The manager names a track and the
# agent works out the version, the URL and the path.  A verb that took a URL
# would be a way to unpack any tarball anywhere as root.

CRS_DIR = NGINX_PREFIX / "modsecurity"
CRS_LINK = CRS_DIR / "crs"
CRS_STATE = CRS_DIR / ".nfm-crs"

CRS_RELEASES = "https://api.github.com/repos/coreruleset/coreruleset/releases"
CRS_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com",
             "release-assets.githubusercontent.com"}
CRS_MAX_BYTES = 32 * 1024 * 1024

# Which series is the long term support one.  CRS 4.25 was the first LTS line
# for CRS 4, and there is no field in the API that says so, so it lives here as
# a constant and needs bumping when the project names a new one.  Better a
# constant somebody can find than a guess made at run time.
CRS_LTS_SERIES = (4, 25)
CRS_TRACKS = ("lts", "latest")

# Proof that what came back is really a rule set.  This file is the first thing
# CRS loads and has been in every 3.x and 4.x release, so a tarball without it
# is not something to point nginx at.
CRS_SENTINEL = "rules/REQUEST-901-INITIALIZATION.conf"


def _crs_fetch(url, timeout=120):
    """Download one URL, with a ceiling, and refuse anything but CRS's hosts."""
    import urllib.error
    import urllib.parse
    import urllib.request

    host = urllib.parse.urlsplit(url).hostname or ""
    if host not in CRS_HOSTS:
        raise AgentError(f"{host} is not a rule set source", "refused")

    request = urllib.request.Request(url, headers={"User-Agent": "failover-lb"})
    try:
        with urllib.request.urlopen(request, timeout=timeout) as response:
            data = response.read(CRS_MAX_BYTES + 1)
    except urllib.error.HTTPError as exc:
        raise AgentError(f"{host} answered {exc.code}", "failed")
    except Exception as exc:
        raise AgentError(f"could not reach {host}: {exc}", "failed")

    if len(data) > CRS_MAX_BYTES:
        raise AgentError("that download is far bigger than a rule set", "failed")
    return data


def _crs_version(tag):
    """(4, 25, 1) out of 'v4.25.1', or None for anything else."""
    match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", str(tag or "").strip())
    return tuple(int(p) for p in match.groups()) if match else None


def _crs_pick(track):
    """
    The newest release on the track, and the asset to fetch for it.

    Only the -minimal tarball is a real asset.  The plain name exists in the
    release as a signature only, since the full source tarball is the one
    GitHub generates, and asking for it by name gets a 404.  Minimal is what is
    wanted anyway: the rules and the example setup file, without the tests and
    the tooling.
    """
    releases = json.loads(_crs_fetch(CRS_RELEASES, timeout=60).decode("utf-8"))

    best = None
    for release in releases:
        if release.get("draft") or release.get("prerelease"):
            continue
        version = _crs_version(release.get("tag_name"))
        if not version:
            continue
        if track == "lts" and version[:2] != CRS_LTS_SERIES:
            continue
        if best is None or version > best[0]:
            best = (version, release)

    if not best:
        raise AgentError(f"no {track} release of the rule set was found", "failed")

    version, release = best
    name = ".".join(str(p) for p in version)
    wanted = f"coreruleset-{name}-minimal.tar.gz"
    for asset in release.get("assets") or []:
        if asset.get("name") == wanted:
            return name, asset.get("browser_download_url")

    raise AgentError(f"release {name} has no {wanted} to download", "failed")


def _crs_unpack(data, into):
    """
    Unpack the tarball, throwing away the version folder it is wrapped in.

    Every member is checked before anything is written.  This runs as root and
    a tarball is a list of paths somebody else chose, so a name with .. in it,
    an absolute path, or a symlink pointing out of the tree would be a way to
    write anywhere on the box.  Refused rather than sanitised, because a rule
    set that needs sanitising is not one to be running.
    """
    import io
    import tarfile

    with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tar:
        members = []
        for member in tar.getmembers():
            if member.islnk() or member.issym():
                raise AgentError("the rule set tarball contains a link, refused",
                                 "refused")
            if not (member.isfile() or member.isdir()):
                raise AgentError("the rule set tarball contains something that "
                                 "is not a file or a folder, refused", "refused")

            # Drop the leading coreruleset-x.y.z/ so the layout is the same
            # whatever the version is.
            parts = PurePosixPath(member.name).parts
            if len(parts) < 2:
                continue
            relative = PurePosixPath(*parts[1:])

            if relative.is_absolute() or ".." in relative.parts:
                raise AgentError(f"refusing a tarball path: {member.name}",
                                 "refused")
            member.name = str(relative)
            members.append(member)

        if not members:
            raise AgentError("the rule set tarball was empty", "failed")

        tar.extractall(path=into, members=members)


def v_crs_install(req):
    """
    Put the rule set on this node, from the track we are told to follow.

    Unpacked beside the live one and swapped in by moving a symlink, which is a
    single atomic step.  Replacing the folder in place would leave a window
    where half the rules are the old ones and half the new, and nginx reading
    that window fails its config test for reasons nobody could reproduce
    afterwards.
    """
    payload = req.get("payload") or req
    track = str(payload.get("track") or "lts").strip().lower()
    if track not in CRS_TRACKS:
        raise AgentError("the track has to be lts or latest", "invalid")

    CRS_DIR.mkdir(parents=True, exist_ok=True)

    version, url = _crs_pick(track)
    target = CRS_DIR / f"crs-{version}"
    staging = CRS_DIR / f".crs-{version}.new"

    if staging.exists():
        shutil.rmtree(staging, ignore_errors=True)
    staging.mkdir(parents=True)

    try:
        _crs_unpack(_crs_fetch(url), staging)

        if not (staging / CRS_SENTINEL).is_file():
            raise AgentError("what came back does not look like the rule set: "
                             f"no {CRS_SENTINEL}", "failed")

        rules = sorted((staging / "rules").glob("*.conf"))
        if len(rules) < 10:
            raise AgentError(f"only {len(rules)} rule files came back, which is "
                             "not a whole rule set", "failed")

        # Config, read by the nginx master while it is still root.  Same
        # reasoning as everything else we stage.
        for path in staging.rglob("*"):
            os.chmod(path, 0o750 if path.is_dir() else 0o640)

        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        os.replace(staging, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    # The swap.  os.replace over a symlink is atomic, so nginx either sees the
    # whole old rule set or the whole new one and never a mixture.
    temporary = CRS_DIR / ".crs.swap"
    if temporary.is_symlink() or temporary.exists():
        temporary.unlink()
    temporary.symlink_to(target.name)
    os.replace(temporary, CRS_LINK)

    CRS_STATE.write_text(json.dumps({
        "version": version,
        "track": track,
        "installed": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "rules": len(rules),
    }))

    # Keep the one before, and nothing older.  A rule set is a few hundred
    # kilobytes so this is not about disk; it is so a bad update can be put
    # back by moving the symlink rather than downloading again from a box that
    # may be the reason the update went wrong.
    keep = {target.name, f"crs-{version}"}
    olds = sorted((p for p in CRS_DIR.glob("crs-*") if p.is_dir()),
                  key=lambda p: p.stat().st_mtime, reverse=True)
    for old in olds[2:]:
        if old.name not in keep:
            shutil.rmtree(old, ignore_errors=True)

    log.warning("installed CRS %s (%s track), %d rule files", version, track, len(rules))
    return {"ok": True, "version": version, "track": track,
            "rules": len(rules), "path": str(CRS_LINK)}


# ==============================================================================
# What the rules actually caught
# ==============================================================================
#
# ModSecurity writes one JSON object per transaction it thought was worth
# recording.  This reads them back, groups them, and hands the manager
# something small enough to put on a page.
#
# The grouping happens here rather than in the manager on purpose.  A site
# under a scan writes tens of thousands of these, and shipping them all across
# the cluster so the far end can count them is a way to make one busy site into
# a fleet wide problem.

WAF_LOG_DIR = Path("/var/log/nginx")

# How much of the log to read, and how many groups to hand back.  Both are
# ceilings rather than targets: nearly every read is far smaller.
WAF_READ_BYTES = 24 * 1024 * 1024
WAF_MAX_GROUPS = 500

# When the log is big enough to do something about.  A site being scanned in
# watching mode writes steadily, and filling the disk on a load balancer is a
# worse outage than anything the firewall prevents.
WAF_LOG_CAP = int(os.environ.get("NFM_WAF_LOG_CAP", 64 * 1024 * 1024))


def _waf_log(site):
    """The audit log for one site, with the name checked before it is a path."""
    name = str(site or "").strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]{1,190}", name):
        raise AgentError("that is not a site name", "invalid")
    path = (WAF_LOG_DIR / f"waf-{name}.log").resolve()
    if path.parent != WAF_LOG_DIR.resolve():
        raise AgentError("that is not a site name", "invalid")
    return path


def _waf_when(stamp):
    """
    The audit log's timestamp as epoch seconds, or None.

    ModSecurity writes "Sun Aug 16 12:48:04 2026", which sorts alphabetically
    into nonsense, so it has to be parsed rather than compared as text.
    """
    import calendar

    try:
        return calendar.timegm(time.strptime(str(stamp), "%a %b %d %H:%M:%S %Y"))
    except (ValueError, TypeError):
        return None


def v_waf_hits(req):
    """
    What fired on this node, grouped by rule and path.

    `since` and `until` bound it to a learning session.  Filtering here rather
    than in the manager means a session that ran for ten minutes does not have
    to carry a week of unrelated traffic across the wire to be thrown away at
    the far end.

    `until` exists so a session that has finished can still be looked at.
    Without it the only readable window was "since the running session began",
    so stopping a session made its own evidence unreachable even though it was
    still sitting in this file.  Somebody who stopped watching before saving a
    profile had done the work and could not get at it.

    Every client address that produced each group comes back with it, because
    deciding whether a hit is a false positive is exactly the question of who
    sent it, and a group that mixes a tester with somebody else must be
    visible as such rather than averaged into looking safe.
    """
    payload = req.get("payload") or req
    path = _waf_log(payload.get("site"))
    since = payload.get("since")
    since = float(since) if isinstance(since, (int, float)) else None
    until = payload.get("until")
    until = float(until) if isinstance(until, (int, float)) else None

    if not path.is_file():
        return {"ok": True, "present": False, "groups": [], "transactions": 0,
                "bytes": 0, "path": str(path)}

    size = path.stat().st_size

    # The tail, not the head.  An old log that has grown past the ceiling has
    # its interesting end at the bottom, and reading the first 24MB of it would
    # answer with last month.
    with path.open("rb") as handle:
        if size > WAF_READ_BYTES:
            handle.seek(size - WAF_READ_BYTES)
            handle.readline()          # drop the half line we landed in
        raw = handle.read()

    groups = {}
    transactions = 0
    skipped = 0

    for line in raw.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            entry = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            skipped += 1
            continue

        tx = entry.get("transaction") or entry
        when = _waf_when(tx.get("time_stamp"))
        if since is not None and (when is None or when < since):
            continue
        if until is not None and (when is None or when > until):
            continue

        transactions += 1
        request = tx.get("request") or {}
        uri = str(request.get("uri") or "")
        client = str(tx.get("client_ip") or "")
        blocked = bool(tx.get("is_interrupted"))

        for message in (tx.get("messages") or entry.get("messages") or []):
            details = message.get("details") or {}
            rule_id = str(details.get("ruleId") or "").strip()
            if not rule_id:
                continue

            # The path without its query string.  A rule firing on the same
            # page with fifty different query strings is one false positive,
            # not fifty, and grouping on the whole uri would bury it.
            bare = uri.split("?", 1)[0]
            key = (rule_id, bare)

            group = groups.get(key)
            if group is None:
                if len(groups) >= WAF_MAX_GROUPS:
                    continue
                group = groups[key] = {
                    "rule_id": rule_id,
                    "path": bare,
                    "message": str(message.get("message") or "")[:300],
                    "severity": str(details.get("severity") or ""),
                    "count": 0,
                    "blocked": 0,
                    "clients": {},
                    "first_seen": when,
                    "last_seen": when,
                    "sample_uri": uri[:300],
                }
            group["count"] += 1
            if blocked:
                group["blocked"] += 1
            if client:
                group["clients"][client] = group["clients"].get(client, 0) + 1
            if when is not None:
                if group["first_seen"] is None or when < group["first_seen"]:
                    group["first_seen"] = when
                if group["last_seen"] is None or when > group["last_seen"]:
                    group["last_seen"] = when

    out = sorted(groups.values(), key=lambda g: g["count"], reverse=True)
    for group in out:
        group["clients"] = sorted(group["clients"].items(),
                                  key=lambda kv: kv[1], reverse=True)[:20]

    return {
        "ok": True,
        "present": True,
        "path": str(path),
        "bytes": size,
        "truncated_read": size > WAF_READ_BYTES,
        "capped_groups": len(groups) >= WAF_MAX_GROUPS,
        "unreadable_lines": skipped,
        "transactions": transactions,
        "groups": out,
    }


def _surface_template(path):
    """
    Collapse the parts of a path that are an identifier into a wildcard.

    Learning sees what somebody exercised.  On an application with a path per
    object that is /user/12345/profile and nothing at all about the user
    created tomorrow, so a positive model built from raw paths refuses every
    object made after the testers went home.  The whole feature is unusable
    without this.

    Deliberately conservative, because the cost of the two mistakes is not the
    same.  Collapsing too little leaves extra rows somebody can merge by hand
    on the profiles page.  Collapsing too much silently widens what is allowed,
    and nobody reviewing a list of paths would spot it.  So only three shapes
    are treated as identifiers and everything else stays literal:

      * all digits, which is the common case
      * a uuid
      * a long hex string, which is what a hash or a token looks like

    A word is never collapsed, however object-like it looks.  /user/profile
    and /user/settings are two pages, not one page with a variable in it.
    """
    out = []
    for part in str(path).split("/"):
        if not part:
            out.append(part)
            continue
        if part.isdigit():
            out.append("*")
        elif re.fullmatch(r"[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}"
                          r"-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}", part):
            out.append("*")
        elif re.fullmatch(r"[0-9a-fA-F]{12,}", part):
            out.append("*")
        else:
            out.append(part)
    return "/".join(out)


def v_waf_surface(req):
    """
    What the application actually is, as seen on this node.

    The other question the audit log can answer.  `waf_hits` asks which rules
    fired, which is what a negative model needs.  This asks which paths and
    methods were used at all, which is what a positive model needs, and the two
    read the same file.

    It only sees anything because the renderer switches full audit logging on
    for the tester addresses while a surface session runs.  Outside that window
    the log holds only transactions where a rule fired, so this would answer
    with the shape of the attacks rather than the shape of the application.

    **No request bodies, ever.**  The audit log is written without part I on
    purpose, because a body is where passwords and card numbers are.  So this
    learns paths and methods and does not learn parameter names, and the
    honest version of that limit is written on the page rather than worked
    around here.
    """
    payload = req.get("payload") or req
    path = _waf_log(payload.get("site"))
    since = payload.get("since")
    since = float(since) if isinstance(since, (int, float)) else None
    until = payload.get("until")
    until = float(until) if isinstance(until, (int, float)) else None

    if not path.is_file():
        return {"ok": True, "present": False, "entries": [], "transactions": 0,
                "bytes": 0, "path": str(path)}

    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > WAF_READ_BYTES:
            handle.seek(size - WAF_READ_BYTES)
            handle.readline()
        raw = handle.read()

    entries = {}
    transactions = 0
    skipped = 0

    for line in raw.split(b"\n"):
        line = line.strip()
        if not line:
            continue
        try:
            record = json.loads(line.decode("utf-8", "replace"))
        except ValueError:
            skipped += 1
            continue

        tx = record.get("transaction") or record
        when = _waf_when(tx.get("time_stamp"))
        if since is not None and (when is None or when < since):
            continue
        if until is not None and (when is None or when > until):
            continue

        request = tx.get("request") or {}
        uri = str(request.get("uri") or "")
        method = str(request.get("method") or "").upper()
        client = str(tx.get("client_ip") or "")
        if not uri or not method:
            continue

        transactions += 1

        # The path only.  A query string is not part of the surface: /search?q=a
        # and /search?q=b are one page, and treating them as two would produce a
        # list nobody can read and a rule set that still refuses the third
        # search anybody does.
        bare = uri.split("?", 1)[0].split("#", 1)[0]

        # One trailing slash is not a different page.  nginx hands back both
        # forms depending on how somebody linked it, and a positive model that
        # allowed /about and refused /about/ would be reported as broken within
        # the hour.
        if len(bare) > 1 and bare.endswith("/"):
            bare = bare.rstrip("/") or "/"

        template = _surface_template(bare)

        entry = entries.get(template)
        if entry is None:
            if len(entries) >= WAF_MAX_GROUPS:
                continue
            entry = entries[template] = {
                "path": template,
                "methods": {},
                "count": 0,
                "clients": {},
                "sample_uri": bare,
                "first_seen": when,
                "last_seen": when,
            }
        entry["count"] += 1
        entry["methods"][method] = entry["methods"].get(method, 0) + 1
        if client:
            entry["clients"][client] = entry["clients"].get(client, 0) + 1
        if when is not None:
            if entry["first_seen"] is None or when < entry["first_seen"]:
                entry["first_seen"] = when
            if entry["last_seen"] is None or when > entry["last_seen"]:
                entry["last_seen"] = when

    out = sorted(entries.values(), key=lambda e: e["path"])
    for entry in out:
        entry["methods"] = sorted(entry["methods"].items(),
                                  key=lambda kv: kv[1], reverse=True)
        entry["clients"] = sorted(entry["clients"].items(),
                                  key=lambda kv: kv[1], reverse=True)[:20]

    return {
        "ok": True,
        "present": True,
        "path": str(path),
        "bytes": size,
        "truncated_read": size > WAF_READ_BYTES,
        "capped_groups": len(entries) >= WAF_MAX_GROUPS,
        "unreadable_lines": skipped,
        "transactions": transactions,
        "entries": out,
    }


# One access log line in the format the renderer writes.
#
#   1.2.3.4 - - [16/Aug/2026:21:14:59 +0000] "POST /users/sign_in HTTP/2.0" 200 42 "..." "..."
#
# Parsed with a regular expression rather than split(), because the request and
# the user agent are quoted fields that contain spaces, and a split on
# whitespace puts the method, the path and the protocol in different places
# depending on what somebody sent.
_ACCESS_LINE = re.compile(
    r'^(?P<addr>\S+) \S+ \S+ \[(?P<when>[^\]]+)\] '
    r'"(?P<method>[A-Z]+) (?P<path>[^ "]*)[^"]*" (?P<status>\d{3}) '
)

LOGIN_READ_BYTES = 32 * 1024 * 1024
LOGIN_MAX_ADDRESSES = 5000


def _access_log(site):
    """The access log for one site, with the name checked before it is a path."""
    name = str(site or "").strip()
    if not name or not re.fullmatch(r"[A-Za-z0-9._-]{1,190}", name):
        raise AgentError("that is not a site name", "invalid")
    path = (WAF_LOG_DIR / f"{name}.access.log").resolve()
    if path.parent != WAF_LOG_DIR.resolve():
        raise AgentError("that is not a site name", "invalid")
    return path


def _access_when(stamp):
    """
    The timestamp on an access log line, as a unix time.

    nginx writes local time with an offset, and the offset is the part that
    matters: a box on anything but UTC would otherwise report every failure as
    hours old and fall outside every window this feature has.
    """
    try:
        return datetime.strptime(
            str(stamp).strip(), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        return None


def v_login_failures(req):
    """
    Failed logins for one site, grouped by the address that made them.

    Reads the access log rather than anything the application tells us, which
    fixes what this can and cannot see.  It gets the address, the path, the
    method and the status.  **It never sees a username or a password**, so it
    cannot say which accounts were targeted, and that limit is worth stating
    rather than working around: making it see usernames would mean reading
    request bodies, which is where the passwords are.

    Which statuses count as a failure comes from the caller, because there is
    no universal answer.  A form that re-renders itself with "wrong password"
    answers 200 and answers 302 when the login worked, so for that application
    200 is the failure.  An API answers 401.  Guessing here would report every
    successful login on half the world's applications as an attack.
    """
    payload = req.get("payload") or req
    path = _access_log(payload.get("site"))

    since = payload.get("since")
    since = float(since) if isinstance(since, (int, float)) else None

    wanted_paths = [str(p) for p in (payload.get("paths") or []) if str(p).strip()]
    wanted_methods = {str(m).upper() for m in (payload.get("methods") or ["POST"])}
    fail_statuses = {int(s) for s in (payload.get("fail_statuses") or [401, 403])
                     if str(s).isdigit()}

    if not wanted_paths:
        return {"ok": True, "present": True, "addresses": [], "failures": 0,
                "note": "no login paths were given, so nothing was looked at"}

    if not path.is_file():
        return {"ok": True, "present": False, "addresses": [], "failures": 0,
                "path": str(path)}

    size = path.stat().st_size
    with path.open("rb") as handle:
        if size > LOGIN_READ_BYTES:
            handle.seek(size - LOGIN_READ_BYTES)
            handle.readline()
        raw = handle.read()

    addresses = {}
    failures = 0
    successes = 0
    scanned = 0

    for line in raw.split(b"\n"):
        if not line:
            continue
        scanned += 1
        match = _ACCESS_LINE.match(line.decode("utf-8", "replace"))
        if not match:
            continue

        got = match.group("path").split("?", 1)[0]
        if not any(got == p or got.startswith(p.rstrip("*")) for p in wanted_paths):
            continue
        if match.group("method").upper() not in wanted_methods:
            continue

        when = _access_when(match.group("when"))
        if since is not None and (when is None or when < since):
            continue

        status = int(match.group("status"))
        if status not in fail_statuses:
            successes += 1
            continue

        failures += 1
        addr = match.group("addr")
        entry = addresses.get(addr)
        if entry is None:
            if len(addresses) >= LOGIN_MAX_ADDRESSES:
                continue
            entry = addresses[addr] = {"address": addr, "count": 0,
                                       "first_seen": when, "last_seen": when,
                                       "paths": {}}
        entry["count"] += 1
        entry["paths"][got] = entry["paths"].get(got, 0) + 1
        if when is not None:
            if entry["first_seen"] is None or when < entry["first_seen"]:
                entry["first_seen"] = when
            if entry["last_seen"] is None or when > entry["last_seen"]:
                entry["last_seen"] = when

    out = sorted(addresses.values(), key=lambda a: a["count"], reverse=True)
    for entry in out:
        entry["paths"] = sorted(entry["paths"].items(),
                                key=lambda kv: kv[1], reverse=True)[:5]

    return {
        "ok": True,
        "present": True,
        "path": str(path),
        "bytes": size,
        "truncated_read": size > LOGIN_READ_BYTES,
        "capped_addresses": len(addresses) >= LOGIN_MAX_ADDRESSES,
        "lines_scanned": scanned,
        "failures": failures,
        "successes": successes,
        "addresses": out,
    }


def v_waf_hits_clear(req):
    """
    Throw away what was learned on this node, for one site.

    Truncated in place rather than removed.  nginx workers are holding this
    file open, and deleting it leaves them writing to an inode nobody can read
    any more: the page goes quiet, the disk does not, and the reason is
    invisible until somebody thinks to check for a deleted file still held
    open.
    """
    payload = req.get("payload") or req
    path = _waf_log(payload.get("site"))

    if not path.is_file():
        return {"ok": True, "cleared": 0, "path": str(path)}

    was = path.stat().st_size
    with path.open("r+b") as handle:
        handle.truncate(0)

    log.warning("cleared the WAF hits for %s, %d bytes", payload.get("site"), was)
    return {"ok": True, "cleared": was, "path": str(path)}


def _waf_rotate_one(path, cap, keep_history=True):
    """
    Rotate one audit log, keeping every open descriptor valid.

    **Renaming is not an option here and that is the whole design.**  The nginx
    master and every worker hold this file open for writing, so a rename leaves
    them all writing into the rotated file: the new one stays empty, the hits
    page goes quiet, and the disk carries on filling.  nginx's own logs survive
    a rename because a USR1 makes it reopen them, and that does not help here,
    libmodsecurity opens the audit log itself, not nginx's log module, so the
    signal never reaches it.

    So it is copy and truncate, which is what logrotate calls copytruncate and
    exists for exactly this case.  It has one known cost: anything written
    between the copy finishing and the truncate landing is lost.  For an audit
    log that is a few lines, and losing a few lines beats losing the disk.
    """
    size = path.stat().st_size
    if size < cap:
        return None

    kept = path.with_name(path.name + ".1.gz")

    # Copying doubles the space this log uses until the truncate lands, and we
    # are rotating precisely because it got big.  If the disk is too tight to
    # hold a copy, throw the history away rather than filling the disk in the
    # act of trying not to.
    if keep_history:
        try:
            free = shutil.disk_usage(str(path.parent)).free
        except OSError:
            free = 0
        # A tenth, since it compresses hard, plus a floor so a nearly full disk
        # never gets a copy at all.
        if free < max(size // 5, 256 * 1024 * 1024):
            keep_history = False

    saved = 0
    if keep_history:
        import gzip

        temporary = path.with_name(path.name + ".1.gz.new")
        try:
            with path.open("rb") as source, gzip.open(temporary, "wb") as target:
                shutil.copyfileobj(source, target, 1024 * 1024)
            os.replace(temporary, kept)
            saved = kept.stat().st_size
        except OSError as exc:
            temporary.unlink(missing_ok=True)
            log.warning("could not keep a copy of %s: %s", path.name, exc)
            keep_history = False

    with path.open("r+b") as handle:
        handle.truncate(0)

    log.warning("rotated %s at %d bytes, %s", path.name, size,
                f"kept {saved} bytes compressed" if keep_history
                else "no copy kept, the disk was too tight")
    return {"site": path.name[4:-4], "was": size, "kept_bytes": saved,
            "history_kept": bool(keep_history)}


def v_waf_log_rotate(req):
    """
    Rotate any audit log past its cap.  Cheap when there is nothing to do.

    Called on a schedule rather than left to a person.  A site being scanned in
    watching mode writes steadily and nobody is watching the disk on a load
    balancer until it is full, and filling it is a worse outage than anything
    the firewall prevents.
    """
    payload = req.get("payload") or req
    cap = payload.get("cap")
    cap = int(cap) if isinstance(cap, (int, float)) and cap > 0 else WAF_LOG_CAP

    rotated = []
    if WAF_LOG_DIR.is_dir():
        for path in sorted(WAF_LOG_DIR.glob("waf-*.log")):
            try:
                done = _waf_rotate_one(path, cap)
            except OSError as exc:
                log.warning("could not rotate %s: %s", path.name, exc)
                continue
            if done:
                rotated.append(done)

    return {"ok": True, "cap": cap, "rotated": rotated}


def v_waf_log_status(req):
    """
    How big every site's audit log is, and whether any is past its cap.

    A site under a scan in watching mode writes steadily, and filling the disk
    on a load balancer is a worse outage than anything the firewall prevents.
    Nothing is deleted here: this reports, and clearing is somebody's decision.
    """
    logs = []
    total = 0
    if WAF_LOG_DIR.is_dir():
        for path in sorted(WAF_LOG_DIR.glob("waf-*.log")):
            try:
                size = path.stat().st_size
            except OSError:
                continue
            total += size
            logs.append({
                "site": path.name[4:-4],
                "bytes": size,
                "over_cap": size >= WAF_LOG_CAP,
            })

    free = None
    try:
        usage = shutil.disk_usage(str(WAF_LOG_DIR))
        free = usage.free
    except OSError:
        pass

    return {"ok": True, "cap": WAF_LOG_CAP, "total": total,
            "free_bytes": free, "logs": logs}


def v_crs_rule_ids(req):
    """
    Every rule id the installed rule set defines.

    So an exclusion can be checked against the rules that are actually there.
    A rule set update retires and renumbers rules, and an exclusion pointing at
    one that no longer exists does nothing, says nothing, and sits in the
    profile forever because nobody dares remove what they cannot explain.

    Read from the files rather than from the engine, because there is no way to
    ask libmodsecurity what it loaded, and the files are the same thing nginx
    parses.
    """
    if not CRS_LINK.exists():
        return {"ok": True, "present": False, "ids": []}

    ids = set()
    pattern = re.compile(r"\bid\s*:\s*'?(\d{3,9})'?")
    try:
        for path in sorted((CRS_LINK / "rules").glob("*.conf")):
            try:
                ids.update(pattern.findall(path.read_text(errors="replace")))
            except OSError:
                continue
    except OSError:
        return {"ok": True, "present": False, "ids": []}

    return {"ok": True, "present": True, "ids": sorted(ids, key=int),
            "count": len(ids)}


def v_crs_status(req):
    """What rule set this node has, if any."""
    if not CRS_LINK.exists():
        return {"ok": True, "present": False, "path": str(CRS_LINK)}

    detail = {}
    if CRS_STATE.is_file():
        try:
            detail = json.loads(CRS_STATE.read_text())
        except (OSError, ValueError):
            detail = {}

    try:
        rules = len(list((CRS_LINK / "rules").glob("*.conf")))
    except OSError:
        rules = None

    return {
        "ok": True,
        "present": True,
        "path": str(CRS_LINK),
        "version": detail.get("version"),
        "track": detail.get("track"),
        "installed": detail.get("installed"),
        "rules": rules,
    }


def v_geoip_status(req):
    """What country database this node has, if any."""
    if not GEOIP_FILE.is_file():
        return {"ok": True, "present": False, "path": str(GEOIP_FILE)}

    stat = GEOIP_FILE.stat()
    detail = {}
    try:
        detail = json.loads(GEOIP_SOURCE_FILE.read_text())
    except Exception:
        pass

    return {
        "ok": True,
        "present": True,
        "path": str(GEOIP_FILE),
        "bytes": stat.st_size,
        "modified": datetime.fromtimestamp(
            stat.st_mtime, timezone.utc).isoformat(timespec="seconds"),
        "source": detail.get("source"),
        "installed": detail.get("installed"),
    }


VERBS = {
    "ping": v_ping,
    "nginx_upgrade": v_nginx_upgrade,
    "nginx_upgrade_status": v_nginx_upgrade_status,
    "nginx_revert": v_nginx_revert,
    "status": v_status,
    "config_test": v_config_test,
    "write_staging": v_write_staging,
    "test_staging": v_test_staging,
    "apply": v_apply,
    "reload": v_reload,
    "service": v_service,
    "read_file": v_read_file,
    "list_dir": v_list_dir,
    "acme_token_write": v_acme_token_write,
    "acme_token_delete": v_acme_token_delete,
    "certbot": v_certbot,
    "acme_register_test": v_acme_register_test,
    "tunnel_key": v_tunnel_key,
    "tunnel_apply": v_tunnel_apply,
    "tunnel_install": v_tunnel_install,
    "tunnel_install_status": v_tunnel_install_status,
    "tunnel_status": v_tunnel_status,
    "tunnel_down": v_tunnel_down,
    "cert_list": v_cert_list,
    "cert_export": v_cert_export,
    "cert_import": v_cert_import,
    "cert_forget": v_cert_forget,
    "list_backups": v_list_backups,
    "rollback": v_rollback,
    "nginx_metrics": v_nginx_metrics,
    "dns_redirect": v_dns_redirect,
    "dns_redirect_clear": v_dns_redirect_clear,
    "dns_redirect_status": v_dns_redirect_status,
    "public_ip": v_public_ip,
    "local_addresses": v_local_addresses,
    "write_hook_scripts": v_write_hook_scripts,
    "geoip_install": v_geoip_install,
    "geoip_status": v_geoip_status,
    "waf_module": v_waf_module,
    "default_server_conflict": v_default_server_conflict,
    "default_site": v_default_site,
    "waf_module_status": v_waf_module_status,
    "crs_install": v_crs_install,
    "crs_status": v_crs_status,
    "crs_rule_ids": v_crs_rule_ids,
    "waf_hits": v_waf_hits,
    "waf_surface": v_waf_surface,
    "login_failures": v_login_failures,
    "waf_hits_clear": v_waf_hits_clear,
    "waf_log_status": v_waf_log_status,
    "waf_log_rotate": v_waf_log_rotate,
}


# ==============================================================================
# The server
# ==============================================================================

# One apply at a time, cluster wide or not.  Two threads swapping config
# folders at the same moment is how you end up with a half applied config and a
# very confused nginx.
APPLY_LOCK = threading.Lock()
SERIALIZED_VERBS = {
    "apply", "write_staging", "rollback", "reload", "service", "certbot",
    "nginx_upgrade", "nginx_revert",
    # Two downloads racing would both be writing the same file.
    "geoip_install",
    # It writes a file and then runs nginx -t against the result.  Two of these
    # at once, or one alongside an apply, and the test proves nothing about
    # what either of them wrote.
    "waf_module",
    # Two of these would be unpacking into the same folder and racing to move
    # the same symlink.
    "crs_install",
    # Truncating a file two readers are parsing.
    "waf_hits_clear",
    "waf_surface",
    "login_failures",
    # Copying and truncating the same files a read is walking.
    "waf_log_rotate",
}


class Handler(socketserver.StreamRequestHandler):
    timeout = 600

    def handle(self):
        peer = self._peer_identity()

        for raw in self.rfile:
            if len(raw) > MAX_REQUEST_BYTES:
                self._send({"ok": False, "error": "request too big", "code": "too_large"})
                return

            line = raw.strip()
            if not line:
                continue

            started = time.monotonic()
            try:
                req = json.loads(line)
            except json.JSONDecodeError:
                self._send({"ok": False, "error": "that was not valid json", "code": "bad_json"})
                continue

            if not isinstance(req, dict):
                self._send({"ok": False, "error": "send an object", "code": "bad_request"})
                continue

            verb = req.get("verb")
            handler = VERBS.get(verb)

            if handler is None:
                log.warning("uid %s asked for unknown verb %r", peer.get("uid"), verb)
                self._send({"ok": False, "error": f"no such verb: {verb}", "code": "unknown_verb"})
                continue

            log.info("verb=%s uid=%s pid=%s", verb, peer.get("uid"), peer.get("pid"))

            try:
                if verb in SERIALIZED_VERBS:
                    got = APPLY_LOCK.acquire(timeout=120)
                    if not got:
                        self._send({
                            "ok": False,
                            "error": "another change is already running, try again",
                            "code": "busy",
                        })
                        continue
                    try:
                        data = handler(req)
                    finally:
                        APPLY_LOCK.release()
                else:
                    data = handler(req)

                elapsed = round((time.monotonic() - started) * 1000)
                self._send({"ok": True, "verb": verb, "took_ms": elapsed, "data": data})

            except AgentError as exc:
                log.warning("verb=%s refused: %s", verb, exc.message)
                self._send({"ok": False, "verb": verb, "error": exc.message, "code": exc.code})

            except Exception as exc:
                # Log the whole traceback on our side, send back something
                # short.  Stack traces going over the wire tell a caller more
                # about this box than they need to know.
                log.exception("verb=%s blew up", verb)
                self._send({
                    "ok": False,
                    "verb": verb,
                    "error": f"the agent hit an internal error: {type(exc).__name__}",
                    "code": "internal",
                })

    def _peer_identity(self):
        """
        Find out who is on the other end.

        SO_PEERCRED comes from the kernel, not from the caller, so it cannot be
        faked.  We only log it, since the socket permissions already decide who
        gets to connect, but having the uid in the log is worth a lot when you
        are trying to work out who did something.
        """
        try:
            creds = self.connection.getsockopt(
                socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
            )
            pid, uid, gid = struct.unpack("3i", creds)
            return {"pid": pid, "uid": uid, "gid": gid}
        except OSError:
            return {}

    def _send(self, payload):
        try:
            self.wfile.write((json.dumps(payload) + "\n").encode())
            self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass


class Server(socketserver.ThreadingUnixStreamServer):
    daemon_threads = True
    allow_reuse_address = True
    request_queue_size = 32


def setup_logging():
    level = os.environ.get("NFM_AGENT_LOG_LEVEL", "INFO").upper()
    log.setLevel(getattr(logging, level, logging.INFO))

    fmt = logging.Formatter("%(asctime)s %(levelname)s [nfm-agent] %(message)s")

    stream = logging.StreamHandler(sys.stdout)
    stream.setFormatter(fmt)
    log.addHandler(stream)

    # syslog too, so the agent's history outlives the journal rotation and
    # lands wherever the rest of your logs go.
    #
    # Check the socket is actually there first.  Handing SysLogHandler a path
    # that does not exist does not always fail when you build it, it fails on
    # the first message instead, and then every single log line prints a
    # traceback about the logging system rather than the thing you wanted to
    # read.  Containers usually have no /dev/log, so this comes up.
    if Path("/dev/log").exists():
        try:
            sysl = logging.handlers.SysLogHandler(address="/dev/log")
            sysl.setFormatter(logging.Formatter("nfm-agent[%(process)d]: %(message)s"))
            log.addHandler(sysl)
        except OSError:
            pass


def _dns_redirect_target():
    """Where the installed redirect points, as (address, port), or None."""
    listed = run(["nft", "list", "table", "ip", NFT_TABLE])
    if listed["rc"] != 0:
        return None
    found = re.search(r"dnat to ([0-9.]+):(\d+)", listed["stdout"])
    if found:
        return found.group(1), int(found.group(2))
    found = re.search(r"redirect to :(\d+)", listed["stdout"])
    if found:
        return "127.0.0.1", int(found.group(1))
    return None


def _dns_answers(address, port, timeout=2.0):
    """
    Is a DNS server answering here.

    Asked by sending a real query rather than by reading /proc.  The first
    version of this parsed /proc/net/udp for the port, which is exactly the
    kind of indirect evidence this project keeps getting caught by: the unit
    runs with ProtectProc=invisible, the parse came back empty on a box where
    the listener was plainly up, and the watchdog tore down a working rule
    every thirty seconds while the manager put it back.

    Asking the question directly has no such failure mode.  Any well formed
    reply counts, including a refusal: the point is whether something is there,
    not whether it likes the question.
    """
    query = (b"\x5a\x5a" + b"\x00\x00" + b"\x00\x01" + b"\x00\x00" * 3
             + b"\x00" + b"\x00\x02" + b"\x00\x01")      # root NS query
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(query, (address, port))
        data, _ = sock.recvfrom(512)
        return len(data) >= 4 and data[:2] == b"\x5a\x5a"
    except Exception:
        return False
    finally:
        sock.close()


def _dns_redirect_watchdog(interval=15, strikes=4):
    """
    Take the redirect away when there is nothing behind it any more.

    The manager clears this on its way out, and that covers a normal stop.  It
    does not cover the container being killed, the machine losing power to it,
    or the manager crashing, and those leave the rule in place pointing at a
    port with no listener.

    The box then accepts DNS on port 53 and answers none of it, which is worse
    than the box being unreachable: a resolver that gets silence waits for its
    timeout, while a resolver that cannot reach the address at all moves
    straight on to the other nameserver.  On a two node fleet that reads as DNS
    having failed everywhere when one node's container went away.

    Two strikes before acting, because the manager restarts in the ordinary
    course of an upgrade and a single miss during those few seconds is not
    worth tearing the rule down for.  The manager puts it back within ten
    seconds of coming up.
    """
    missed = 0
    while True:
        time.sleep(interval)
        try:
            target = _dns_redirect_target()
            if target is None:
                missed = 0
                continue
            address, port = target
            if _dns_answers(address, port):
                missed = 0
                continue
            missed += 1
            if missed < strikes:
                continue
            log.warning(
                "the dns redirect points at %s:%s and nothing there answers a "
                "dns query, so this box was taking port 53 and answering "
                "nothing.  Removing it so resolvers move on to another "
                "nameserver.  It goes back when the manager returns.",
                address, port)
            run(["nft", "delete", "table", "ip", NFT_TABLE])
            missed = 0
        except Exception as exc:                       # noqa: BLE001
            log.warning("the dns redirect watchdog had a problem: %s", exc)
            missed = 0


def main():
    setup_logging()

    if os.geteuid() != 0:
        log.error("this has to run as root, that is the whole job")
        sys.exit(1)

    for d in (MANAGED_DIR, BACKUP_DIR, MANAGED_DIR / "certs"):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(MANAGED_DIR / "certs", 0o750)

    # The socket is created private and then opened to the group, rather than
    # created open and closed afterwards.
    #
    # It used to be bound and then chmod'd, which left a window carrying
    # whatever umask the process inherited.  Narrow, and on a root process that
    # writes nginx configuration the thing on the other side of that window is
    # worth more than the window is small.
    #
    # **Scoped, not global.**  Setting the umask for the whole process looked
    # tidier and would have broken the fleet: nineteen directories here are
    # created with mkdir and no explicit mode, and several of them have to be
    # traversable by nginx.  The ACME challenge directory is the one that would
    # have bitten first, since a webroot nginx cannot read fails every
    # certificate issue and renewal on the box.  So it covers the bind and
    # nothing else.
    #
    # A mode on the mkdir for the same reason as the umask: a first run creates
    # this directory and the chmod below is several lines later.
    SOCKET_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    previous_umask = os.umask(0o177)
    try:
        server = Server(str(SOCKET_PATH), Handler)
    finally:
        os.umask(previous_umask)

    # This is the access control.  Group only, no world bits.  The container
    # runs with this group added, which is the entire reason it can talk to us.
    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
        os.chown(SOCKET_DIR, 0, gid)
        os.chmod(SOCKET_DIR, 0o750)
        log.info("socket is at %s, owned by root:%s mode 0660", SOCKET_PATH, SOCKET_GROUP)
    except KeyError:
        # Falling back to root only is the safe direction to fail.  The
        # container will not be able to connect and you will see why in the log,
        # which beats quietly opening the socket to everybody.
        os.chmod(SOCKET_PATH, 0o600)
        log.error("no group called %s, socket is root only.  Run install.sh.", SOCKET_GROUP)

    def shutdown(signum, frame):
        log.info("got signal %s, shutting down", signum)
        # shutdown() tells serve_forever() to stop and then waits for it to say
        # it has.  A signal handler runs on the main thread, which is the thread
        # sitting in serve_forever(), so calling it straight from here waits for
        # a loop that cannot run until the handler returns.  That is a deadlock,
        # and systemd sat through the full 90 second stop timeout and SIGKILLed
        # the agent on every single stop and restart.  Hand it to another thread
        # so the handler returns right away and the loop gets to finish.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Runs for the life of the agent.  It only ever removes a rule that has
    # nothing behind it, so the worst it can do on a healthy box is nothing.
    threading.Thread(target=_dns_redirect_watchdog, daemon=True,
                     name="dns-redirect-watchdog").start()

    log.info("failover lb agent %s (%s) is up",
             AGENT_VERSION, AGENT_FINGERPRINT)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        SOCKET_PATH.unlink(missing_ok=True)
        log.info("agent stopped")


if __name__ == "__main__":
    main()
