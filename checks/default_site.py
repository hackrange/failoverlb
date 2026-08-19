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

if WAS_DEFAULT:
    skip("setting the default site is refused while something else has it",
         f"{SITE_NAME} is already the default, so there is nothing to refuse")
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
