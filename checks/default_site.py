"""
Marking a site as the default one must not stop the fleet applying anything.

nginx allows exactly one default server per address and port and refuses to
start with two.  An apply is all or nothing.  So a second default server does
not break the site that asked for it, it stops **every site on the fleet** from
being applied until somebody works out why.

There is always a second one waiting.  `nginx-installer.sh` writes a catch all
at `sites-enabled/default.conf` carrying `listen 80 default_server`, and the
manager had no idea that file existed.  Ticking "this is the default site" saved
cleanly, redisplayed ticked after a reload, rendered exactly the right config,
and then the apply came back:

    nginx: [emerg] a duplicate default server for 0.0.0.0:80

naming a file the person had never edited.  Reported from the field before this
check existed.

So the save is refused now, with the file named, and this proves the refusal
happens and that nothing was stored by the attempt.  Nothing is applied and no
site is changed: every request here is one that should be turned down.

    docker exec -i nginx-fleet-manager python < checks/default_site.py
"""
import pathlib
import sys

from fastapi.testclient import TestClient

from app.db import session_scope
from app.models import AuthSource, User, UserRole, VirtualHost

results = []
skipped = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {str(detail)[:300]}")
    return ok


def skip(name, why):
    skipped.append(name)
    print(f"    skip  {name}")
    print(f"          {why}")


def client():
    from app.main import create_gui_app
    from app.web import routes_pages, routes_api, security

    ghost = User(id=-1, username="check-default", role=UserRole.ADMIN,
                 source=AuthSource.LOCAL, enabled=True,
                 totp_enrolled=True, must_change_password=False)
    routes_pages.page_user = lambda request, db: ghost
    routes_pages.require_page_user = lambda request, db: ghost
    routes_api.get_user = lambda request, db: ghost
    security.client_ip = lambda request: "127.0.0.1"
    c = TestClient(create_gui_app(), raise_server_exceptions=False)
    c.get("/")
    # Header and cookie both, or the write is refused for the token and every
    # check below passes without reaching the thing it is about.
    token = c.cookies.get("nfm_csrf") or ""
    return c, {"X-CSRF-Token": token, "Cookie": f"nfm_csrf={token}"}


print("\n  a second default site is refused before it can stop the fleet\n")

with session_scope() as session:
    site = (session.query(VirtualHost)
            .filter(VirtualHost.enabled.is_(True))
            .order_by(VirtualHost.id).first())
    if site is None:
        print("    there are no sites on this box, so this check cannot run")
        sys.exit(0)
    SITE_ID, SITE_NAME = site.id, site.name
    WAS_DEFAULT = bool(site.default_server)
    OTHER_DEFAULT = (session.query(VirtualHost)
                     .filter(VirtualHost.default_server.is_(True),
                             VirtualHost.id != site.id).first())
    OTHER_NAME = OTHER_DEFAULT.name if OTHER_DEFAULT else None

client_, head = client()

# What does this node think, before anything is asked of the API.
import asyncio

from app.core.agent_client import get_agent

try:
    answer = asyncio.get_event_loop().run_until_complete(
        get_agent().call("default_server_conflict"))
    UNMANAGED = answer.get("files") or []
except Exception as exc:
    UNMANAGED = None
    print(f"    could not ask the agent: {exc}")

if UNMANAGED is None:
    skip("the node can say who else claims the default site",
         "the agent did not answer, so the rest of this cannot be judged")
else:
    check("the node can say who else claims the default site", True,
          UNMANAGED)
    print(f"          outside the managed tree: {UNMANAGED or 'nothing'}")

print()

BLOCKED = (answer.get("blocked") if isinstance(UNMANAGED, list) else None) or []
TAKEABLE = (answer.get("takeable") if isinstance(UNMANAGED, list) else None) or []
if TAKEABLE:
    print(f"          the manager can stand these down: {TAKEABLE}")

if WAS_DEFAULT:
    skip("setting the default site is refused while something else has it",
         f"{SITE_NAME} is already the default, so there is nothing to refuse")
elif UNMANAGED and not BLOCKED and not OTHER_NAME:
    # Everything in the way is a symlink the manager takes over at apply time,
    # so the setting is allowed and the catch all stands down instead.  The
    # refusal is for the files it must not touch.
    response = client_.request("PUT", f"/api/hosts/{SITE_ID}",
                               json={"default_server": True}, headers=head)
    check("a catch all the manager can take over does not block the setting",
          response.status_code == 200,
          f"{response.status_code} {response.text[:200]}")
    # Put it straight back, because this check does not change anything.
    client_.request("PUT", f"/api/hosts/{SITE_ID}",
                    json={"default_server": False}, headers=head)
    with session_scope() as session:
        again = session.get(VirtualHost, SITE_ID)
        check("and the site is left exactly as it was",
              bool(again.default_server) == WAS_DEFAULT,
              f"default_server is now {again.default_server}")
elif not UNMANAGED and not OTHER_NAME:
    skip("setting the default site is refused while something else has it",
         "nothing else claims the default on this box, so the refusal has "
         "nothing to fire on.  That is a fleet where the feature works.")
else:
    response = client_.request("PUT", f"/api/hosts/{SITE_ID}",
                               json={"default_server": True}, headers=head)
    check("the save is refused", response.status_code == 409,
          f"{response.status_code} {response.text[:200]}")
    check("and the refusal is about the default site rather than the token",
          "default" in response.text.lower() and "csrf" not in response.text.lower(),
          response.text[:200])
    if UNMANAGED:
        check("and it names the file that already has it",
              any(f in response.text for f in UNMANAGED), response.text[:300])
    elif OTHER_NAME:
        check("and it names the site that already has it",
              OTHER_NAME in response.text, response.text[:300])

    with session_scope() as session:
        again = session.get(VirtualHost, SITE_ID)
        check("and nothing was stored by the attempt",
              bool(again.default_server) == WAS_DEFAULT,
              f"default_server is now {again.default_server}")

# =============================================================================
print()
print("  and the refusal itself, which needs another site to already have it")

# The branch above only fires on a fleet where something the manager must not
# touch claims the default.  On a fleet where the only thing in the way is the
# installer's symlink, which the manager takes over, the refusal is never
# reached and this file was passing without testing the thing it is named
# after.  The mutation harness found that: taking the refusal out entirely
# changed nothing here.
#
# So the other refusal is exercised, the one that does not depend on what is
# on disk: another managed site already being the default.  Done against a
# real copy of this node's database, so a site can be marked and the API asked
# about it without writing anything live.  The backup API rather than a file
# copy, or the copy is the database as of some earlier moment.
import shutil as _shutil
import sqlite3
import tempfile

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app import db as _dbmod

_live = _dbmod.get_engine().url.database
if not _live or not pathlib.Path(_live).is_file():
    skip("a site is refused when another site already has it",
         "cannot find this node's database file to copy")
else:
    _dir = pathlib.Path(tempfile.mkdtemp(prefix="default-site-"))
    _copy = _dir / "copy.db"
    _src = sqlite3.connect(_live); _dst = sqlite3.connect(str(_copy))
    _src.backup(_dst); _src.close(); _dst.close()

    _real_engine, _real_factory = _dbmod._engine, _dbmod._SessionFactory
    _dbmod._engine = create_engine(f"sqlite:///{_copy}")
    _dbmod._SessionFactory = sessionmaker(bind=_dbmod._engine)
    try:
        with session_scope() as s:
            rows = s.query(VirtualHost).order_by(VirtualHost.id).all()
            if len(rows) < 2:
                OTHER = MINE = None
            else:
                OTHER, MINE = rows[0], rows[1]
                OTHER.default_server = True
                MINE.default_server = False
                OTHER_NAME2, MINE_ID = OTHER.name, MINE.id
                s.commit()

        if OTHER is None:
            skip("a site is refused when another site already has it",
                 "this box has fewer than two sites")
        else:
            client2, head2 = client()
            res = client2.request("PUT", f"/api/hosts/{MINE_ID}",
                                  json={"default_server": True}, headers=head2)
            check("a second site asking for the default is refused",
                  res.status_code == 409,
                  f"{res.status_code} {res.text[:200]}")
            check("and the refusal names the site that already has it",
                  OTHER_NAME2 in res.text, res.text[:250])
            check("and it is not a token error dressed up as a refusal",
                  "csrf" not in res.text.lower(), res.text[:200])
            with session_scope() as s:
                check("nothing was stored by the attempt",
                      s.get(VirtualHost, MINE_ID).default_server is not True,
                      "the second site was marked default anyway")
    finally:
        _dbmod._engine, _dbmod._SessionFactory = _real_engine, _real_factory
        _shutil.rmtree(_dir, ignore_errors=True)

print()
failed = [name for name, ok, _ in results if not ok]
print()
if failed:
    print(f"  {len(results) - len(failed)} passed, {len(failed)} failed, "
          f"{len(skipped)} skipped\n")
    for name in failed:
        print(f"    - {name}")
    sys.exit(1)

print(f"  RESULT: a second default site cannot be saved "
      f"({len(results)} checks, {len(skipped)} skipped)\n")
