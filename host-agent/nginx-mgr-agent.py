#!/usr/bin/env python3
"""
Failover LB host agent.

Runs as root on the nginx box, outside the container.  The container is
unprivileged and asks this agent over a unix socket when it needs something
done on the host.  The container is the larger attack surface, so the agent
treats its requests with suspicion and is kept small enough to read.

Rules:

  1. A fixed list of verbs; anything else is refused.  No "run a command"
     verb.
  2. Every path is resolved (symlinks, ../) and checked against an allow list.
  3. Config changes are staged and pass nginx -t before going live.
  4. Every reload keeps a numbered backup.
  5. Everything is logged with the verb and the caller's uid.

Protocol is newline delimited JSON, one request and one response per line.
See VERBS at the bottom.
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
    Short hash of this file as loaded, to tell whether the running agent
    matches the repo.  AGENT_VERSION is only bumped by hand, and rebuilding
    the container image does not touch the agent.

    Computed once at startup so it reflects the loaded code, not what is
    on disk now.
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

# Everything we generate lives here, apart from anything written by hand.
MANAGED_DIR = NGINX_PREFIX / "nginxmgr"

# Where we stage a config before testing it.
STAGING_DIR = NGINX_PREFIX / ".nginxmgr-staging"

# Throwaway copy of staging for tests that need path rewriting.  See
# _staging_for_test.  Never applied.
TEST_DIR = NGINX_PREFIX / ".nginxmgr-test"

# Throwaway nginx.conf used to test a staged config.  It must sit next to the
# real nginx.conf: nginx resolves relative includes (like "include
# mime.types;") against the config file's folder, not -p.
CANDIDATE_CONF = NGINX_PREFIX / ".nginxmgr-candidate.conf"

# Marks our include block in nginx.conf.  Versioned so an old block can be
# recognized and replaced.
INCLUDE_MARKER = "# failover lb includes, v5.  Do not reorder."

# Numbered backups of the managed folder, one per apply.
BACKUP_DIR = Path("/var/backups/nginx-fleet-manager")
BACKUP_KEEP = 30

# Builds nginx from source.  Modules are compiled in, so changing modules
# and upgrading are the same operation.
INSTALLER = Path(os.environ.get("NFM_INSTALLER", "/opt/nginx-installer.sh"))

# Build progress.  A build takes 10 to 20 minutes, so it runs detached and
# the manager polls these.
UPGRADE_STATE = Path("/var/lib/nginx-fleet-manager/upgrade.json")
UPGRADE_LOG = Path("/var/log/nginx-fleet-manager-upgrade.log")

# Command timeouts.  Certbot waits on a remote server, so it gets longer.
DEFAULT_TIMEOUT = 60
CERTBOT_TIMEOUT = 300

# Generous for configs; stops a hostile caller exhausting memory.
MAX_REQUEST_BYTES = 8 * 1024 * 1024

# Writable paths, checked after resolving symlinks.
WRITE_ALLOWED = (
    MANAGED_DIR,
    STAGING_DIR,
    TEST_DIR,
    ACME_WEBROOT / ".well-known" / "acme-challenge",
    NGINX_PREFIX / "conf.d",
    NGINX_PREFIX / "snippets",
)

# Readable paths.  Wider than the write list so the GUI can show the running
# config and certs.
READ_ALLOWED = (
    NGINX_PREFIX,
    LETSENCRYPT_DIR,
    ACME_WEBROOT,
    BACKUP_DIR,
)

# conf.d and snippets are shared with the installer and admins, so we only
# touch files with this prefix there.
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
    Resolve the caller's path, symlinks included, before any allow list
    check.  Checking the raw string would let a symlink escape.
    """
    if not isinstance(path_str, str) or not path_str:
        raise AgentError("path has to be a non empty string", "bad_path")
    if "\x00" in path_str:
        raise AgentError("path has a null byte in it", "bad_path")

    p = Path(path_str)
    if not p.is_absolute():
        raise AgentError(f"path has to be absolute, got {path_str}", "bad_path")

    # strict=False so files we are about to create still resolve.
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

    # The one file written straight into the prefix folder.  See
    # CANDIDATE_CONF.
    if p == CANDIDATE_CONF.resolve(strict=False):
        return p

    if not _under_any(p, WRITE_ALLOWED):
        raise AgentError(f"not allowed to write outside the managed paths: {p}", "denied")

    # Shared folders: only our own files.
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

    # Private keys only come from where certbot puts them.
    if p.name.endswith((".pem", ".key")) and "privkey" in p.name:
        if not _under_any(p, (LETSENCRYPT_DIR,)):
            raise AgentError("private keys only come out of /etc/letsencrypt", "denied")

    return p


# ==============================================================================
# Running things
# ==============================================================================

# Flags whose values must never be logged, even at debug level.  Debug gets
# turned on to chase certificate problems, and the journal keeps everything.
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
    Run a command and return rc, stdout and stderr.

    Always an argv list with shell=False, so caller input never reaches a
    shell.
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
    Write via a temp file in the same folder, fsync, then rename, so nginx
    only ever sees the old file or the new one.
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

        # fsync the folder too so the rename survives a power loss.
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
    Tar up the managed config folder before we change it.  Cheap, since it
    is only our own files.
    """
    BACKUP_DIR.mkdir(parents=True, exist_ok=True)
    stamp = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    name = f"{stamp}-{label}.tar.gz"
    dest = BACKUP_DIR / name

    if MANAGED_DIR.is_dir():
        with tarfile.open(dest, "w:gz") as tar:
            tar.add(str(MANAGED_DIR), arcname="nginxmgr")
    else:
        # First run.  An empty archive still lets you roll back to "nothing".
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
            # A tar can hold absolute paths and ../, so check every member.
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
# Each takes the request dict and returns a dict, raising AgentError for bad
# input.  None builds a shell command from caller input.

def v_ping(req):
    return {
        "pong": True,
        "agent_version": AGENT_VERSION,
        # See _own_fingerprint.
        "agent_fingerprint": AGENT_FINGERPRINT,
        "hostname": socket.gethostname(),
        "time": datetime.now(timezone.utc).isoformat(),
    }


# Status runs five commands and the caller waits only 30s for all of them.
# With the default 60s timeout one slow systemctl lost the whole answer, so
# each step gets a short timeout and a miss is reported as unknown.
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
        # From outside the whole call just looks slow, so name the step.
        log.warning("status step %s took %.1fs", name, took)


def v_status(req):
    """What nginx is doing right now, plus what it was built with."""
    out = {"nginx_bin": str(NGINX_BIN), "installed": NGINX_BIN.is_file()}

    if out["installed"]:
        def _version():
            ver = run([str(NGINX_BIN), "-v"], timeout=STATUS_STEP_TIMEOUT)
            # nginx prints its version to stderr.
            out["version_banner"] = (ver["stderr"] or ver["stdout"]).strip()
        _status_step(out, "version", _version)

        def _build():
            # The configure line tells the GUI which modules are compiled in.
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


# load_module is only legal in the main context, and the managed bundle is
# included inside http {}, so the WAF module line goes here instead.  The
# installer includes this folder above the events block.
MODULES_ENABLED = NGINX_PREFIX / "modules-enabled"
MODSEC_LOAD_CONF = MODULES_ENABLED / "50-modsecurity.conf"
MODSEC_MODULE_SO = Path("/usr/lib/nginx/modules/ngx_http_modsecurity_module.so")


def v_waf_module(req):
    """
    Load or unload the WAF module, and prove nginx still starts either way.

    This verb can stop nginx starting at all, so: refuse if the .so is
    missing (it only exists after a rebuild with WITH_MODSECURITY=1), then
    write, run nginx -t (catches a module built for another nginx version),
    and restore the previous state if the test fails.
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
        # Restore, then report what nginx objected to.
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


# Where distributions and installers drop their own server blocks.
UNMANAGED_CONFIG_DIRS = (
    NGINX_PREFIX / "sites-enabled",
    NGINX_PREFIX / "conf.d",
)

# `listen 80 default_server;` and friends, in a file we did not write.
_DEFAULT_SERVER_RE = re.compile(r"^\s*listen\s+[^;#]*\bdefault_server\b", re.M)


def _default_server_files() -> list:
    """
    Config outside the managed tree that already claims default_server.

    nginx refuses two default servers on one address and port, so an
    installer's catch all would make every apply with a managed default fail.
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


# Records catch all links we stood down, so they can be put back.  Under
# /usr/local/lib because /var/lib is read only under the unit's
# ProtectSystem=strict.
DEFAULT_SITE_STATE = Path("/usr/local/lib/nginx-fleet-manager/default-site.json")


def _takeable(path: Path) -> bool:
    """
    Whether we can stand this one down and restore it exactly.

    Only symlinks in sites-enabled, which is how the installer enables its
    catch all; removing one loses nothing.  Regular files may be someone's own
    config and are left alone (renaming would not help, since nginx globs
    sites-enabled/*).
    """
    return path.is_symlink() and path.parent == (NGINX_PREFIX / "sites-enabled")


def v_default_server_conflict(req):
    """
    Who else claims to be the default site, split into ones we can stand
    down and ones that block the setting.
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

    When a managed site is the default, the installer's catch all symlink is
    removed (and recorded).  When none is, the catch all is restored so
    unmatched traffic goes where it always did.  The caller runs nginx -t.
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

        # Record before removing, or a failure in between loses the catch
        # all with no record of it.
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
    File mode for a staged file.

    Config is read by the nginx master as root and may hold backend tokens,
    so it is 0640.  Error pages and htpasswd files are read by workers
    (www-data) at request time and must be 0644.  An unreadable error page
    turns the real status into a 403; an unreadable htpasswd makes basic
    auth return 500.  htpasswd hashes are bcrypt, so world readable is fine.
    """
    first = Path(rel_path).parts[0] if Path(rel_path).parts else ""
    return 0o644 if first in ("errorpages", "auth") else 0o640


def v_write_staging(req):
    """
    Replace the staging folder with the full set of rendered files.  Wiping
    it first means files the manager stopped generating really go away.
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
    The folder the test should include: usually staging itself.

    Staged files use absolute paths into the live bundle.  That is harmless
    for things opened at request time (auth_basic_user_file), but nginx -t
    reads modsecurity_rules_file while loading, so it would test the live
    rules, or fail on a first apply when none exist.  In that case the test
    runs against a copy with those paths pointed at the copy.  Staging itself
    is not rewritten because apply moves it into place as is.

    Only paths that staging actually holds are redirected.  Certificates live
    in the bundle but come from the certificate sync, not staging, and must
    keep pointing at the live copy.
    """
    if TEST_DIR.exists():
        shutil.rmtree(TEST_DIR, ignore_errors=True)

    live = str(MANAGED_DIR)
    staged = str(STAGING_DIR)

    # Redirect only references to files staging actually has.
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
            # Binary or unreadable; nothing to rewrite.
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
    Test the staged config without touching the running server.

    nginx -t needs a whole config, so we test a copy of the real nginx.conf
    with our include pointed at staging.
    """
    main_conf = NGINX_PREFIX / "nginx.conf"
    if not main_conf.is_file():
        raise AgentError(f"cannot find {main_conf}", "not_found")

    # Before the test, since the candidate includes sites-enabled too and a
    # second default server would fail it (or worse, pass here and fail at
    # apply).
    staged_default = _staging_declares_default()
    moved = reconcile_default_site(staged_default)

    original = main_conf.read_text()

    # Point our include at staging, adding one if we have never applied.
    live_include = str(MANAGED_DIR)
    staged_include = _staging_for_test()

    if live_include in original:
        candidate = original.replace(live_include, staged_include)
    else:
        candidate = _inject_include(original, staged_include)

    atomic_write(CANDIDATE_CONF, candidate, mode=0o640)

    try:
        # -p so prefix relative paths (like access_log) resolve as usual.
        result = run([str(NGINX_BIN), "-t", "-p", str(NGINX_PREFIX), "-c", str(CANDIDATE_CONF)])
        output = (result["stderr"] + result["stdout"]).strip()

        # Show the real paths in the GUI, not the temp and staging ones.
        output = output.replace(str(CANDIDATE_CONF), "the candidate config")
        output = output.replace(staged_include + "/", live_include + "/")

        ok = result["rc"] == 0
        if not ok and moved.get("removed"):
            # This config will not be applied, so restore the catch all.
            reconcile_default_site(False)

        return {"ok": ok, "output": output, "default_site": moved}
    finally:
        # Always clean up so nothing stale is left for the next test.
        CANDIDATE_CONF.unlink(missing_ok=True)
        shutil.rmtree(TEST_DIR, ignore_errors=True)


def _inject_include(conf_text, include_dir):
    """
    Put our include lines inside the http block, and the stream include
    after it.  Walks the braces, since http has nested blocks and a regex
    would find the wrong closing brace.
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

        # Back at http's depth: this line holds its closing brace.
        if in_http and http_depth is not None and depth == http_depth:
            # Order matters: log formats, maps, limit and cache zones must be
            # defined before sites use them ("unknown log format" otherwise).
            # Always globs, since a missing named include is fatal but an
            # empty glob is fine.
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

            # stream {} is a sibling of http, so it gets its own top level
            # include, after http's closing brace.  The generated file holds
            # the whole stream block, so nginx.conf only ever has include
            # lines, which is all _ensure_include_present knows how to strip.
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

    Order: test staging, back up, swap in, test again, reload, and roll
    back and reload if the reload fails.
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

    # Move the old folder aside rather than deleting it, for a quick rollback.
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

    # Certificates live in this folder but are never staged, so carry them
    # over or the swap deletes them (and the next render drops https because
    # they are missing).  Copy, so the set aside folder stays whole for a
    # rollback.
    if previous is not None:
        old_certs = previous / "certs"
        new_certs = MANAGED_DIR / "certs"
        if old_certs.is_dir() and not new_certs.exists():
            try:
                shutil.copytree(old_certs, new_certs)
            except OSError as exc:
                # Without certificates no https site loads; stop here with a
                # clear error.
                _rollback(previous, backup_name)
                raise AgentError(
                    f"could not carry the certificates across the apply: {exc}", "io_error"
                )

    # Cheap, and catches someone editing the include out.
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

    Keyed on the versioned marker, not the folder name, so a block written by
    an older release with fewer includes gets replaced.
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
            # Markers used before v5.  Keep these while older nodes may
            # still have them, or their old block would be left behind.
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
            # Normal on a fresh box: nginx is not running yet, so start it.
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

    # No systemd: drive nginx directly.  Needed after a rebuild too, or the
    # old binary keeps serving while nginx -v reports the new version.
    if action in ("stop", "restart"):
        run([str(NGINX_BIN), "-s", "quit"])
        # quit is graceful, so wait for the workers to finish.
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
            # Shows whether files workers open at request time are readable
            # by www-data.  See _staged_mode.
            "mode": st.st_mode & 0o7777,
        })
    return {"path": str(p), "entries": entries}


def v_acme_token_write(req):
    """
    Put an http-01 challenge token on disk.

    Every node gets a copy, since the CA may validate against any of them.
    """
    token = req.get("token", "")
    value = req.get("value", "")

    # ACME tokens are base64url, so a token can never become a path.
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

    The command line is built here from a fixed set of options.  Every
    caller value is validated first, so none can become an extra flag.
    """
    domains = req.get("domains") or []
    email = req.get("email", "")
    staging = bool(req.get("staging", False))
    challenge = req.get("challenge", "http-01")
    key_type = req.get("key_type", "ecdsa")
    dns_plugin = req.get("dns_plugin")
    dns_credentials = req.get("dns_credentials")
    force = bool(req.get("force_renewal", False))

    # A non Lets Encrypt directory: an internal CA such as step-ca, or a
    # local test server that avoids public rate limits.
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

    # Email is optional.  The CA allows it, and the manager warns about
    # expiry itself.
    if email and not re.fullmatch(r"[^@\s]{1,64}@[^@\s]{1,255}", str(email)):
        raise AgentError("that email address does not look right", "bad_request")

    if key_type not in ("ecdsa", "rsa"):
        raise AgentError("key_type has to be ecdsa or rsa", "bad_request")

    # Must match the manager's name for the certificate, since it later looks
    # up the files by that name.  A guessed name would issue fine and then
    # fail to sync to other nodes.
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

    # ISRG Root X1 only applies to Lets Encrypt.  Other authorities name
    # their preferred chain on their own profile.
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
        # Required by certbot without an address.  It only means no expiry
        # mail.
        cmd.append("--register-unsafely-without-email")

    if acme_server:
        if not re.fullmatch(r"https://[A-Za-z0-9._:-]{1,253}(/[A-Za-z0-9._~/-]*)?", str(acme_server)):
            raise AgentError("that acme server url is not valid", "bad_request")
        cmd += ["--server", acme_server]
        # --staging is just another Lets Encrypt directory.
        staging = False

    # External account binding, required by some commercial CAs.  Without it
    # registration fails with an unhelpful account error.
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
        # The hooks call the manager on localhost, which pushes the token to
        # every node before the CA checks.
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

    # CA for an internal or test ACME server.  Kept in our own folder so the
    # rest of the box's trust store is unchanged.
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

        # Let openssl parse the certificate rather than doing it ourselves.
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

    This returns the private key on purpose: every node serves the same cert.
    It only travels over mutual TLS between trusted nodes.
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

    Written to our own folder, not /etc/letsencrypt/live, which certbot owns
    along with the renewal state.  The generated config points at whichever
    copy exists.
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

        # Keys are root only; the nginx master reads them before dropping
        # privileges.
        mode = 0o600 if fname == "privkey.pem" else 0o644
        atomic_write(synced / fname, content, mode=mode)
        written.append(fname)

    os.chmod(synced, 0o750)
    return {"name": name, "written": written, "path": str(synced)}


def v_cert_forget(req):
    """
    Take a certificate's files off this node.

    Only our own copy, never certbot's, which carries renewal state;
    removing those is a job for `certbot delete`.  Without this, a deleted
    certificate's private key stayed on every node indefinitely.
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

    # Keep a copy of the current folder.  restore_backup replaces it before
    # the test runs, so a backup that fails nginx -t would otherwise stay on
    # disk while nginx ran the old config from memory, and the node would not
    # come back after its next restart.
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

    The installer builds in stub_status and the generated config exposes it
    on localhost only.  Basic, but enough for connection counts.
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


# Our own nftables table, so it can be dropped in one command without
# touching anyone else's rules.
NFT_TABLE = "nginxmgr"


def v_dns_redirect(req):
    """
    Send port 53 to the port the manager is really listening on.

    The manager runs unprivileged with no-new-privileges, so it cannot bind
    53 and setcap does not help.  DNAT keeps the real client address and,
    unlike proxying through nginx, still works when nginx is stopped, which
    is when failover answers matter most.
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

    # The table is rebuilt each time, never appended to.
    #
    # Match every local address, not just NODE_ADDRESS, so nodes behind NAT
    # or with several addresses still redirect.  `fib daddr type local` also
    # leaves forwarded traffic alone, so we never answer other hosts' DNS.
    #
    # Loopback must be excluded: the local stub resolver on 127.0.0.53 would
    # otherwise be redirected too, and the box would lose all name
    # resolution.
    daddr = "fib daddr type local ip daddr != 127.0.0.0/8 "

    # dnat rather than redirect: in the output chain `redirect` goes to
    # 127.0.0.1, but the listener binds the node's own address, so queries
    # from the box itself were refused.
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

    # Older nftables rejects the fib match.  Fall back to the single address
    # rather than having no redirect at all.
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
    The rule actually in place.

    `installed` and `present` are the same; the manager reads `installed`,
    and when it was missing it rebuilt the table (briefly dropping the rule)
    every few seconds.  `target` and `matches_all_local` let it spot a rule
    of an outdated shape after an agent upgrade.
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

    Asks several services and takes the majority, since any one can be
    down or wrong and a wrong answer sends the cert request to the wrong
    node.  DNS first (faster, harder to tamper with), then https.
    """
    answers = []

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

    Shows whether this node holds a floating VIP, and lets the manager
    allowlist cluster addresses so health checks are never blocked by an ACL.
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

    certbot runs on the host, so the hooks live here.  They just call the
    manager on localhost with a one time token.
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


# Builds run as their own units because a child of this agent would inherit
# its ProtectSystem=strict sandbox.  See nginx-rebuild.service.
REBUILD_UNIT = "nginx-rebuild.service"
REVERT_UNIT = "nginx-revert.service"

# On tmpfs, so a build interrupted by a reboot leaves no marker behind.
REBUILD_ENV = Path("/run/nginxmgr/rebuild.env")
REBUILD_MARKER = Path("/run/nginxmgr/rebuild.started")

# Written by the unit as it stops; its existence means the build is over.
# See nginx-rebuild.service for why systemd cannot tell us afterward.
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
    Build unit status, in the same shape the file based path returns.

    A unit that never ran looks the same as one that succeeded, so state
    comes from our start marker and the result file the unit writes, not
    from systemd's properties alone.
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

    # Not running: either finished (result file present) or not started yet.
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
        # Failed before writing a result, usually before the installer ran.
        return {
            **base,
            "state": "finished",
            "ok": False,
            "finished": True,
            "result": "failed",
            "error": f"{REBUILD_UNIT} failed to start.  See journalctl -u {REBUILD_UNIT}.",
        }

    # Requested but not begun yet.
    return base


def v_nginx_upgrade(req):
    """
    Rebuild nginx from source, at a version and module list we are given.

    Runs the same installer an admin would, so the manager can walk the
    fleet one node at a time.  Detached, since a build takes 10 to 20
    minutes and a dropped connection must not interrupt it.

    Inputs are validated here and passed as environment variables (through
    an environment file under systemd), never as shell words.
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

    # The installer builds exactly the modules it is told, so the manager
    # sends this on every rebuild; absent means off.
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
        # Values were validated above and go in an environment file.
        REBUILD_ENV.parent.mkdir(parents=True, exist_ok=True)
        atomic_write(
            REBUILD_ENV,
            "".join(f"{k}={v}\n" for k, v in env.items()),
            mode=0o600,
        )

        # Clear the old result or status would report this build finished.
        REBUILD_RESULT.unlink(missing_ok=True)

        # Write the marker before starting the unit, so a fast build is
        # never mistaken for one we did not ask for.
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

        # --no-block: return now; failures show up through the status verb.
        out = run(["systemctl", "start", "--no-block", REBUILD_UNIT])
        if out["rc"] != 0:
            REBUILD_MARKER.unlink(missing_ok=True)
            raise AgentError(
                f"could not start {REBUILD_UNIT}: "
                f"{(out['stderr'] or out['stdout']).strip()[:400]}",
                "build_start_failed",
            )

        return {"started": True, "versions": env, "unit": REBUILD_UNIT}

    # No systemd, so no sandbox either: run the build ourselves.
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

    # setsid so the build outlives this connection.
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

    # The installed version, so the manager need not trust the exit code.
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

    Uses the snapshot of binary and config the installer takes before every
    build.
    """
    if not INSTALLER.is_file():
        raise AgentError(f"no installer script at {INSTALLER}", "missing_installer")

    if _have_systemd():
        # Runs as a unit for the same sandbox reason as the build.  Blocking,
        # since a revert is quick and the caller wants the outcome.
        # Remember where the log ends so we return only what the revert
        # wrote, not the tail of the last build.
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

    Issues nothing.  Proves the directory answers and the external account
    credentials are accepted.  Uses a throwaway config directory so certbot's
    real accounts are untouched.
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
        # The useful part of certbot's output is at the end.
        output = ((result["stderr"] or "") + (result["stdout"] or "")).strip()
        tail = [ln for ln in output.splitlines() if ln.strip()][-4:]
        return {"ok": False, "error": "\n".join(tail) or "registration was refused"}
    finally:
        shutil.rmtree(workdir, ignore_errors=True)




# ==============================================================================
# The tunnel
# ==============================================================================
#
# WireGuard, so a backend can be reached without a public address.  Managed
# here because it needs root.  Two fixed rules:
#
#   * The private key is generated here and never leaves; only the public
#     half is reported.
#   * A peer's AllowedIPs is its single address, never a wider range.

TUNNEL_IF = "nfm0"
# Required: Ubuntu's AppArmor profiles for wg and wg-quick only allow configs
# from /etc/wireguard.  Elsewhere they fail with a misleading "Permission
# denied".
TUNNEL_DIR = Path("/etc/wireguard")


def _wg_available():
    return shutil.which("wg") is not None


# Installed through its own unit, like the nginx build.  See
# nfm-tunnel-install.service.
TUNNEL_INSTALL_UNIT = "nfm-tunnel-install.service"
TUNNEL_INSTALL_SCRIPT = Path("/opt/nfm-tunnel-installer.sh")
TUNNEL_INSTALL_RESULT = Path("/run/nginxmgr/tunnel-install.result")
TUNNEL_INSTALL_LOG = Path("/var/log/nginx-fleet-manager-tunnel-install.log")


def _tunnel_ready():
    """
    Whether this node can run the tunnel, per the installer's check.  Having
    the wg binary is not enough; the node also needs a datapath.
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

    Starts the unit and returns; the GUI polls the status verb.
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

    # Clear the old result so it is not read as this run finishing.
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

    Reports only the public half.  The private key is 0600 and never leaves
    this box.
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

    Rewritten whole every time rather than patched, so the file cannot
    drift from what was asked for.
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

    # The key must be in the file, not set by PostUp.  wg-quick's reload runs
    # `wg syncconf %i <(wg-quick strip %i)`, and strip drops PostUp, so the
    # key would be removed on the first reload.  The interface then stays up
    # but silently drops every handshake.  PrivateKey survives strip.
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

        # Optional pre-shared key, a symmetric input to the handshake that
        # protects recorded traffic if Curve25519 is ever broken.  Per peer,
        # since both ends need it and adding one drops a connected peer
        # until the far end is updated.
        psk = str(peer.get("psk") or "").strip()
        if psk:
            if not re.fullmatch(r"[A-Za-z0-9+/]{42,44}=", psk):
                raise AgentError("a peer pre-shared key is not valid", "bad_request")
            lines.append(f"PresharedKey = {psk}")

        lines += [
            # One address, never a range, so a peer speaks only for itself.
            f"AllowedIPs = {peer_address}/32",
            "",
        ]

    conf = TUNNEL_DIR / f"{TUNNEL_IF}.conf"
    conf.write_text("\n".join(lines))
    os.chmod(conf, 0o600)

    # Use wg-quick@.service rather than running wg-quick ourselves.  Under
    # our NoNewPrivileges the kernel refuses AppArmor profile transitions, so
    # a child wg-quick cannot exec ip or wg ("Operation not permitted").
    #
    # Reload when already up: it does a syncconf, so existing tunnels stay up.
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

    # An interface without a key looks healthy but drops every handshake, so
    # check for one and fail the apply if it is missing.
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
# Country blocking needs a MaxMind format database on every node; without one
# the config is refused.  Sources: db-ip's free monthly database (no account)
# or MaxMind GeoLite2 (account id and license key).  Same format either way.
#
# The manager only sends a source name and credentials, never a URL or path,
# so this verb cannot be used to write arbitrary files as root.

GEOIP_DIR = Path("/usr/share/GeoIP")
GEOIP_FILE = GEOIP_DIR / "nfm-country.mmdb"
GEOIP_SOURCE_FILE = GEOIP_DIR / ".nfm-source"

# Found near the end of a valid MaxMind file.  Checked before install, since
# a truncated file stops nginx from starting.
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
        # Published monthly.  Early in the month the new one may not be up,
        # so fall back to last month's.
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

    Written to a temp file and renamed into place, so a failed download
    leaves the old database in use.
    """
    payload = req.get("payload") or req
    source = str(payload.get("source") or "").strip()
    if source not in GEOIP_HOSTS:
        raise AgentError("the source has to be dbip or maxmind", "invalid")

    # Only writable with a current unit file.  Probe it so an old unit gets a
    # clear "upgrade the agent" error rather than a bare OSError.
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

    # A truncated download fails here rather than at the next nginx start.
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
# Like the country database, the rules must be on every node or the config
# is refused.  The manager names a track; the agent picks the version, URL
# and path, so this verb cannot unpack arbitrary tarballs as root.

CRS_DIR = NGINX_PREFIX / "modsecurity"
CRS_LINK = CRS_DIR / "crs"
CRS_STATE = CRS_DIR / ".nfm-crs"

CRS_RELEASES = "https://api.github.com/repos/coreruleset/coreruleset/releases"
CRS_HOSTS = {"api.github.com", "github.com", "objects.githubusercontent.com",
             "release-assets.githubusercontent.com"}
CRS_MAX_BYTES = 32 * 1024 * 1024

# The LTS series.  The API does not mark it, so bump this when the CRS
# project names a new one.  4.25 was the first LTS line for CRS 4.
CRS_LTS_SERIES = (4, 25)
CRS_TRACKS = ("lts", "latest")

# The first file CRS loads, present in every 3.x and 4.x release.  Its
# absence means the download is not a rule set.
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

    Only the -minimal tarball is a real release asset (the full one is
    GitHub generated and 404s by name).  It has the rules and example setup
    without tests and tooling, which is all we need.
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

    Every member is checked first, since this runs as root: links, ..,
    absolute paths and special files are refused outright, not sanitized.
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

            # Drop the leading coreruleset-x.y.z/ folder.
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

    Unpacked beside the live one and swapped in with an atomic symlink
    replace, so nginx never sees a mix of old and new rules.
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

        # Config read by the nginx master as root.  See _staged_mode.
        for path in staging.rglob("*"):
            os.chmod(path, 0o750 if path.is_dir() else 0o640)

        if target.exists():
            shutil.rmtree(target, ignore_errors=True)
        os.replace(staging, target)
    finally:
        shutil.rmtree(staging, ignore_errors=True)

    # Atomic swap of the symlink.
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

    # Keep the previous version so a bad update can be undone by moving the
    # symlink back, without downloading again.
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
# ModSecurity writes one JSON object per recorded transaction.  We group them
# here, not in the manager, because a scanned site writes tens of thousands
# and shipping them all across the cluster would be expensive.

WAF_LOG_DIR = Path("/var/log/nginx")

# Upper limits on how much log to read and how many groups to return.
WAF_READ_BYTES = 24 * 1024 * 1024
WAF_MAX_GROUPS = 500

# Log size at which we act.  A scanned site in watching mode writes steadily,
# and a full disk on a load balancer is worse than what the WAF prevents.
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

    ModSecurity writes "Sun Aug 16 12:48:04 2026", which does not sort as
    text.
    """
    import calendar

    try:
        return calendar.timegm(time.strptime(str(stamp), "%a %b %d %H:%M:%S %Y"))
    except (ValueError, TypeError):
        return None


def v_waf_hits(req):
    """
    What fired on this node, grouped by rule and path.

    `since` and `until` bound it to a learning session, filtered here to
    avoid shipping unrelated traffic.  `until` lets a finished session still
    be reviewed.

    Client addresses come back with each group, since judging a false
    positive depends on who sent it.
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

    # Read the tail; the recent entries are at the end.
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

            # Group on the path without the query string, so one false
            # positive does not show up as fifty.
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

    Without this, a positive model learned from /user/12345/profile would
    refuse every object created after learning ended.

    Deliberately conservative: collapsing too little leaves rows to merge
    by hand, while collapsing too much silently widens what is allowed.  Only
    all digits, UUIDs and long hex strings count as identifiers; words are
    never collapsed.
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
    Paths and methods used on this node, for building a positive model
    (waf_hits answers the negative model question from the same file).

    Only meaningful during a surface session, when the renderer enables full
    audit logging for tester addresses.  Otherwise the log holds only rule
    hits.

    The audit log never includes request bodies (no part I), since that is
    where passwords live, so parameter names are not learned.
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

        # Query strings are not part of the surface.
        bare = uri.split("?", 1)[0].split("#", 1)[0]

        # /about and /about/ are the same page.
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
# A regex rather than split(), since quoted fields contain spaces.
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

    nginx writes local time with an offset, which must be honored on
    non-UTC boxes.
    """
    try:
        return datetime.strptime(
            str(stamp).strip(), "%d/%b/%Y:%H:%M:%S %z").timestamp()
    except (ValueError, TypeError):
        return None


def v_login_failures(req):
    """
    Failed logins for one site, grouped by the address that made them.

    Reads the access log only: address, path, method and status.  It never
    sees usernames, since that would mean reading request bodies.

    The caller says which statuses mean failure, because it varies: a form
    may answer 200 on failure and 302 on success, while an API answers 401.
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

    Truncated rather than removed: nginx workers hold the file open, and
    deleting it would leave them writing to an unlinked inode.
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

    Copy and truncate, never rename.  libmodsecurity opens the audit log
    itself, so USR1 does not make nginx reopen it, and after a rename every
    process would keep writing to the rotated file.  Lines written between
    the copy and the truncate are lost, which is acceptable here.
    """
    size = path.stat().st_size
    if size < cap:
        return None

    kept = path.with_name(path.name + ".1.gz")

    # The copy needs extra space.  If the disk is too tight, drop the history
    # rather than fill the disk.
    if keep_history:
        try:
            free = shutil.disk_usage(str(path.parent)).free
        except OSError:
            free = 0
        # A fifth of the size (it compresses well), with a floor so a nearly
        # full disk never gets a copy.
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

    Called on a schedule, since nobody watches the disk until it is full.
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

    Report only; nothing is deleted here.
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

    Lets exclusions be checked against rules that still exist, since CRS
    updates retire and renumber rules.  Read from the files, because
    libmodsecurity cannot be asked what it loaded.
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

# Verbs that change state or race on shared files run one at a time.
APPLY_LOCK = threading.Lock()
SERIALIZED_VERBS = {
    "apply", "write_staging", "rollback", "reload", "service", "certbot",
    "nginx_upgrade", "nginx_revert",
    # Same target file.
    "geoip_install",
    # Writes, then runs nginx -t; must not overlap an apply.
    "waf_module",
    # Same folder and symlink.
    "crs_install",
    # Truncation must not race the readers.
    "waf_hits_clear",
    "waf_surface",
    "login_failures",
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
                # Full traceback in our log; keep the reply short.
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

        SO_PEERCRED comes from the kernel, so it cannot be faked.  Only
        logged; socket permissions decide who can connect.
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

    # syslog too, so history outlives journal rotation.  Check /dev/log
    # exists first: otherwise SysLogHandler may fail on every message instead
    # of at construction.
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

    Sends a real query rather than reading /proc, which ProtectProc=invisible
    hides.  Any well formed reply counts, including a refusal.
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

    The manager removes the rule on a clean stop, but not if it crashes or
    is killed.  A rule with no listener behind it swallows queries, which is
    worse than being unreachable: resolvers wait for a timeout instead of
    moving on to the other nameserver.

    Several consecutive misses are needed, so a manager restart during an
    upgrade does not trigger it.  The manager restores the rule when it
    comes back.
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

    # Create the socket private and then open it to the group, so there is no
    # window with the inherited umask.  The umask is scoped to the bind only:
    # a process wide umask would break directories nginx must traverse, such
    # as the ACME webroot.  The mkdir mode closes the same window for the
    # directory on first run.
    SOCKET_DIR.mkdir(parents=True, exist_ok=True, mode=0o750)
    if SOCKET_PATH.exists():
        SOCKET_PATH.unlink()

    previous_umask = os.umask(0o177)
    try:
        server = Server(str(SOCKET_PATH), Handler)
    finally:
        os.umask(previous_umask)

    # The access control: group only.  The container runs with this group.
    try:
        gid = grp.getgrnam(SOCKET_GROUP).gr_gid
        os.chown(SOCKET_PATH, 0, gid)
        os.chmod(SOCKET_PATH, 0o660)
        os.chown(SOCKET_DIR, 0, gid)
        os.chmod(SOCKET_DIR, 0o750)
        log.info("socket is at %s, owned by root:%s mode 0660", SOCKET_PATH, SOCKET_GROUP)
    except KeyError:
        # Fail closed: root only, with the reason in the log.
        os.chmod(SOCKET_PATH, 0o600)
        log.error("no group called %s, socket is root only.  Run install.sh.", SOCKET_GROUP)

    def shutdown(signum, frame):
        log.info("got signal %s, shutting down", signum)
        # shutdown() waits for serve_forever(), which runs on this same
        # thread, so calling it here deadlocks until systemd's stop timeout.
        # Call it from another thread.
        threading.Thread(target=server.shutdown, daemon=True).start()

    signal.signal(signal.SIGTERM, shutdown)
    signal.signal(signal.SIGINT, shutdown)

    # Only removes a rule with nothing behind it; harmless on a healthy box.
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
