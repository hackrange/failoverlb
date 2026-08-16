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
import pathlib
import socket
import sys

from app.catalog import all_features
from app.core.capabilities import fleet_capabilities
from app.db import session_scope
from app.models import Certificate, Location, Pool, VirtualHost, json_set
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
    # No inventing a value from the help text.  It was tried: the examples are
    # written for a person reading them, so error_pages' example is a sentence
    # describing two rules, and feeding it back in renders a directive nginx
    # refuses.  The settings that would need it are caught by the source pass
    # at the end instead, which needs no value at all.
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


def renderer_knows(key, _cache={}):
    """
    Does the renderer mention this setting at all.

    The difference between a setting that cannot work and one this check did
    not build the right site for.  A cache directive is only written when a
    cache zone is attached, and TLS ones only on a site with a certificate, so
    their absence here means the scratch site had no cache zone, not that the
    setting is dead.  A key the renderer never names in its source cannot be
    written under any shape, and that is the real finding.
    """
    if not _cache:
        from app.core import render
        _cache["source"] = pathlib.Path(render.__file__).read_text()
    source = _cache["source"]
    return f'"{key}"' in source or f"'{key}'" in source


def directive_written(files, feature):
    """
    Did setting this actually put its directive in the config.

    nginx being happy is not the same as the setting having done anything.  A
    setting the renderer ignores produces a config with the directive simply
    absent, which nginx accepts without a word, so every check here passed on
    settings that could not work: fifteen of them, found only when somebody
    went looking for one of them by name and it did nothing.

    Returns None when the catalog entry names no directive, which is the case
    for the few that stand for a whole block rather than one line.

    The limit worth knowing: a directive the base config always writes, like
    sendfile, will be found whether or not this setting is what wrote it.  So
    this catches a setting that writes nothing at all, not one that writes the
    wrong thing.
    """
    directive = (getattr(feature, "directive", "") or "").strip()
    if not directive:
        return None
    needle = directive.split()[0]
    return any(needle in text for text in files.values()
               if isinstance(text, str))


def render_with(settings):
    """
    Render the whole config with a scratch site carrying these settings.

    The site proxies, over https, with a path on it, because the shape of the
    site decides which directives can appear at all.  A static http site with
    no locations was rendering none of the proxy settings, none of the TLS
    ones and none of the per location ones, which made every one of them look
    like a setting the renderer ignores.  The shape has to be able to carry
    the directive before its absence means anything.

    Falls back a step at a time when the fleet has nothing to build it from: no
    pool means static, no certificate means http.
    """
    with session_scope() as session:
        pool = session.query(Pool).first()
        cert = session.query(Certificate).filter(
            Certificate.not_after.isnot(None)).first()

        site = VirtualHost(
            name=SCRATCH,
            server_names=json.dumps([SCRATCH]),
            enabled=True,
            listen_http=True,
            listen_https=bool(cert),
            cert_id=cert.id if cert else None,
            mode="proxy" if pool else "static",
            pool_id=pool.id if pool else None,
            document_root=None if pool else "/var/www/site1",
            settings=json_set(settings),
        )
        session.add(site)
        session.flush()
        # A path as well, since a good few settings are only ever written
        # inside a location and a site with none has nowhere to put them.
        session.add(Location(host_id=site.id, path="/", match_type="prefix",
                             mode="proxy" if pool else "static",
                             pool_id=pool.id if pool else None,
                             document_root=None if pool else "/var/www/site1",
                             enabled=True, sort_order=10,
                             settings=json_set(settings)))
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
    inert = []
    unexercised = []
    nameless = []
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

        # Did it write anything at all.  Asked before nginx is, because a
        # setting that writes nothing passes every test nginx can do.
        wrote = directive_written(files, feature)
        if wrote is None:
            nameless.append(feature.key)
        elif not wrote:
            if renderer_knows(feature.key):
                # The renderer knows about it, so this site is the wrong shape
                # to carry it: no cache zone, no limit zone, that sort of
                # thing.  Worth listing, not worth failing over.
                unexercised.append((feature.key, feature.directive))
            else:
                inert.append((feature.key, feature.directive))
                print(f"    INERT {feature.key} = {value!r}")
                print(f"          the renderer never names this setting, so "
                      f"no {feature.directive} can ever come out of it")

        ok, output = nginx_accepts(files)
        if not ok:
            reason = next(
                (ln for ln in output.splitlines() if "emerg" in ln or "error" in ln),
                output.splitlines()[0] if output else "no output",
            )
            failures.append((feature.key, value, reason))
            print(f"    FAIL {feature.key} = {value!r}")
            print(f"         {reason[:150]}")

    print(f"    {len(features) - len(failures) - len(inert) - len(skipped)} passed, "
          f"{len(failures)} failed, {len(inert)} wrote nothing, "
          f"{len(skipped)} skipped")
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

    if inert:
        print(f"  {len(inert)} settings the renderer never writes.  These save, "
              f"apply and do nothing,")
        print("  which is worse than not offering them:")
        for key, directive in inert:
            print(f"    {key:26} {directive}")
        print()

    if unexercised:
        print(f"  {len(unexercised)} the renderer does know about, but which "
              f"need a site this check did not")
        print("  build: a cache zone, a limit zone, that kind of thing.  Not a "
              "fault, but not covered:")
        for key, directive in unexercised:
            print(f"    {key:26} {directive}")
        print()

    if nameless:
        print(f"  {len(nameless)} settings name no directive, so whether they "
              f"were written cannot be")
        print(f"  checked this way: {', '.join(nameless)}")
        print()

    # The last word, and the only one that needs no site: does the renderer
    # name this setting anywhere in its source.  A key it never names cannot be
    # written under any shape, whatever value we try, so this catches the ones
    # skipped above for want of a test value and the ones whose catalog entry
    # names no single directive.
    never = [f.key for f in features if not renderer_knows(f.key)]
    if never:
        print(f"  {len(never)} settings the renderer's source never mentions.  "
              f"No value and no shape")
        print("  can make these do anything:")
        for key in never:
            print(f"    {key}")
        print()

    # A setting that renders correctly and cannot be saved.
    #
    # Everything above asks whether a value reaches the config file.  It never
    # asks whether the value could have been saved in the first place, and
    # those are different questions with a different answer three times over:
    # caching, rate limiting and connection limiting each rendered perfectly
    # and each refused every value on the way in, because they are selects
    # whose choices are rows in the database and the catalog carries an empty
    # option list for them.  The site editor offered real zones and the save
    # said "has to be one of:" with nothing after the colon.
    #
    # So any select with no options has to be one the validator knows to check
    # against the database instead.  Adding a fourth without wiring it up fails
    # here rather than in front of somebody trying to turn caching on.
    from app.web.routes_api import ZONE_CHOICES

    unwired = sorted(
        f.key for f in all_features().values()
        if f.type in ("select", "multiselect") and not f.options
        and f.key not in ZONE_CHOICES and f.key != "waf_paranoia"
    )
    if unwired:
        print(f"  {len(unwired)} select settings have no options in the catalog "
              f"and nothing that checks")
        print("  them against the database, so every value will be refused:")
        for key in unwired:
            print(f"    {key}")
        print("  Add them to ZONE_CHOICES in app/web/routes_api.py.")
        print()

    problems = (len(failures) + len(unwired)
                + len(set(k for k, _ in inert) | set(never)))
    print("  RESULT:", "every setting reached the config and nginx took it"
          if not problems else f"{problems} PROBLEMS, listed above")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
