#!/usr/bin/env python3
"""
NGINX Fleet Manager host agent.

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
from pathlib import Path

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
INCLUDE_MARKER = "# nginx fleet manager includes, v4.  Do not reorder."

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

def run(cmd, timeout=DEFAULT_TIMEOUT, input_text=None, env_extra=None):
    """
    Run a command and hand back what happened.

    Always a list, never a string, and shell=False.  Nothing the caller sends
    ever becomes part of a shell line, so there is no quoting bug waiting to
    turn into command injection.
    """
    log.debug("running: %s", " ".join(cmd))

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

    original = main_conf.read_text()

    # Swap our include line over to staging.  If the manager has never applied
    # anything yet there is no include line, so we add one inside http.
    live_include = str(MANAGED_DIR)
    staged_include = str(STAGING_DIR)

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

        return {"ok": result["rc"] == 0, "output": output}
    finally:
        # Always clean up, even if nginx blew up.  Leaving this behind would
        # mean the next test reads a stale candidate.
        CANDIDATE_CONF.unlink(missing_ok=True)


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
        "--preferred-chain", "ISRG Root X1",
    ]

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

    restore_backup(name)
    test = v_config_test(req)
    if not test["ok"]:
        return {"ok": False, "output": test["output"], "note": "that backup does not pass a config test"}

    rel = v_reload({})
    return {"ok": rel["ok"], "restored": name, "output": rel.get("output", "")}


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

    Nothing about the caller's input becomes a shell command.  The versions are
    checked against a version shaped pattern and passed as environment
    variables, which is exactly how the installer expects to be told, and the
    module list is written to a file the installer sources.
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

    env = {}
    if nginx_version:
        env["NGINX_VERSION"] = str(nginx_version)
    if openssl_version:
        env["OPENSSL_VERSION"] = str(openssl_version)

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
    "cert_list": v_cert_list,
    "cert_export": v_cert_export,
    "cert_import": v_cert_import,
    "cert_forget": v_cert_forget,
    "list_backups": v_list_backups,
    "rollback": v_rollback,
    "nginx_metrics": v_nginx_metrics,
    "public_ip": v_public_ip,
    "local_addresses": v_local_addresses,
    "write_hook_scripts": v_write_hook_scripts,
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


def main():
    setup_logging()

    if os.geteuid() != 0:
        log.error("this has to run as root, that is the whole job")
        sys.exit(1)

    for d in (MANAGED_DIR, BACKUP_DIR, MANAGED_DIR / "certs"):
        d.mkdir(parents=True, exist_ok=True)
    os.chmod(MANAGED_DIR / "certs", 0o750)

    SOCKET_DIR.mkdir(parents=True, exist_ok=True)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    server = Server(str(SOCKET_PATH), Handler)

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

    log.info("nginx fleet manager agent %s (%s) is up",
             AGENT_VERSION, AGENT_FINGERPRINT)
    try:
        server.serve_forever()
    finally:
        server.server_close()
        SOCKET_PATH.unlink(missing_ok=True)
        log.info("agent stopped")


if __name__ == "__main__":
    main()
