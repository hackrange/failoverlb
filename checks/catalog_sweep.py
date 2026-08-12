"""
Render every catalog setting and make real nginx judge it.

The point is not that the renderer produces a string.  It is that nginx loads
what we wrote.  A setting that renders config nobody has ever put in front of
nginx is exactly the shape of bug this project keeps finding, so every one of
them goes through the agent's own config test on this node.

Two passes, because they fail differently:

  one at a time   catches a setting that writes a bad directive
  all together    catches settings that are each fine and argue with each other

Nothing is applied.  Everything is written to the staging folder and tested
there, and the live config is never touched.  The scratch site exists inside a
transaction that gets rolled back, so the database is the same afterwards.

Run it inside the container:
    docker exec -i nginx-fleet-manager python < test/catalog_sweep.py
"""
import json
import socket
import sys

from app.catalog import all_features
from app.core.capabilities import fleet_capabilities
from app.db import session_scope
from app.models import VirtualHost, json_set
from app.web.routes_api import render_current

SOCKET = "/run/nginxmgr/agent.sock"
SCRATCH = "catalog-sweep.subdomain.domain.tld"


def agent(request):
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(120)
    sock.connect(SOCKET)
    sock.sendall((json.dumps(request) + "\n").encode())
    buf = b""
    while not buf.endswith(b"\n"):
        chunk = sock.recv(65536)
        if not chunk:
            break
        buf += chunk
    sock.close()
    return json.loads(buf.decode())


def nginx_accepts(files):
    """Stage these files and ask nginx, the same way an apply would."""
    wrote = agent({"verb": "write_staging", "files": files})
    if not wrote.get("ok"):
        return False, f"could not stage: {wrote.get('error')}"
    result = agent({"verb": "test_staging"}).get("data", {})
    return bool(result.get("ok")), (result.get("output") or "").strip()


def sample_value(feature):
    """
    A value worth testing for this setting.

    The feature's own default first, since that is what most installs will
    actually run and what the help text promises.  Otherwise something valid
    for the type, because a setting nobody ever sets is still a setting that
    has to render.
    """
    if feature.default not in (None, "", [], {}):
        return feature.default

    kind = feature.type
    if kind == "bool":
        return True
    if kind == "int":
        return feature.min_value if feature.min_value is not None else 1
    if kind == "size":
        return "16k"
    if kind == "time":
        return "30s"
    if kind in ("select", "multiselect", "list"):
        if feature.options:
            first = feature.options[0][0]
            if first in (None, ""):
                first = feature.options[1][0] if len(feature.options) > 1 else None
            if first in (None, ""):
                return None
            return [first] if kind in ("multiselect", "list") else first
        return None
    if kind in ("string", "text"):
        return feature.placeholder or None
    return None


def render_with(settings):
    """Render the whole config with a scratch site carrying these settings."""
    with session_scope() as session:
        site = VirtualHost(
            name=SCRATCH,
            server_names=json.dumps([SCRATCH]),
            enabled=True,
            listen_http=True,
            listen_https=False,
            mode="static",
            document_root="/var/www/site1",
            settings=json_set(settings),
        )
        session.add(site)
        session.flush()
        try:
            files, _checksum, _snapshot = render_current(session)
        finally:
            session.rollback()
    return files


def main():
    caps = fleet_capabilities()
    features = [
        f for f in all_features().values()
        if f.edition == "oss"
        and "server" in f.contexts
        and f.is_available(caps.modules, caps.version_tuple)
    ]
    features.sort(key=lambda f: f.key)

    print(f"  {len(features)} settings to check, on {caps.nginx_version}")
    print()

    failures = []
    skipped = []
    together = {}

    print("  one at a time")
    for feature in features:
        value = sample_value(feature)
        if value is None:
            skipped.append((feature.key, "no sensible test value for this type"))
            continue

        together[feature.key] = value
        try:
            files = render_with({feature.key: value})
        except Exception as exc:
            failures.append((feature.key, value, f"render blew up: {exc}"))
            print(f"    FAIL {feature.key}: render blew up: {exc}")
            continue

        ok, output = nginx_accepts(files)
        if not ok:
            reason = next(
                (ln for ln in output.splitlines() if "emerg" in ln or "error" in ln),
                output.splitlines()[0] if output else "no output",
            )
            failures.append((feature.key, value, reason))
            print(f"    FAIL {feature.key} = {value!r}")
            print(f"         {reason[:150]}")

    print(f"    {len(features) - len(failures) - len(skipped)} passed, "
          f"{len(failures)} failed, {len(skipped)} skipped")
    print()

    print("  all of them together")
    try:
        files = render_with(together)
        ok, output = nginx_accepts(files)
        if ok:
            print(f"    all {len(together)} settings load together")
        else:
            print("    FAIL, they do not all load together:")
            for line in output.splitlines()[:6]:
                print(f"      {line[:150]}")
            failures.append(("<all together>", "", output.splitlines()[0] if output else ""))
    except Exception as exc:
        print(f"    FAIL, render blew up: {exc}")
        failures.append(("<all together>", "", str(exc)))

    print()
    if skipped:
        print(f"  skipped {len(skipped)}, no meaningful value to try:")
        for key, why in skipped:
            print(f"    {key}: {why}")
        print()

    print("  RESULT:", "every setting nginx was asked about loaded"
          if not failures else f"{len(failures)} PROBLEMS, listed above")
    return 1 if failures else 0


if __name__ == "__main__":
    sys.exit(main())
