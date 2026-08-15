"""
Open every page and every read only endpoint, and catch the ones that blow up.

A button that returns 500 is worse than a missing feature, and this is the
cheapest possible check for it: a handler with a typo, a wrong argument, a name
that was never imported.  One of those shipped today.  The page looked fine in
the template and the endpoint behind it raised on the first authenticated
request, which is a thing nobody notices while signed out because the redirect
to the login page happens first.

Signed in as a throwaway user that exists only inside this run.  No real account
is touched, nothing is written to the database, and nothing is applied.

    docker exec -i nginx-fleet-manager python < checks/page_sweep.py
"""
import re
import sys
from pathlib import Path

from fastapi.testclient import TestClient

from app.db import session_scope
from app.models import AuthSource, User, UserRole

# Pages the sidebar offers, plus the ones you reach from them.
PAGES = [
    "/", "/sites", "/pools", "/zones", "/error-pages", "/certificates",
    "/cluster", "/utilization", "/maps", "/streams",
    "/upgrade", "/parity", "/account", "/settings", "/users", "/audit",
    "/changes",
]

# Read only endpoints.  Anything that writes is left alone on purpose: this
# check is about handlers that raise, not about changing a live fleet.
ENDPOINTS = [
    "/api/status",
    "/api/catalog",
    "/api/catalog?context=location",
    "/api/catalog/plus",
    "/api/hosts",
    "/api/pools",
    "/api/certs",
    "/api/cluster",
    "/api/versions",
    "/api/config/pending",
    "/api/audit",
    "/api/error-pages",
    "/api/metrics",
    "/api/metrics/series?minutes=15",
    "/api/maps",
    "/api/streams",
]

results = []


def check(name, ok, detail=""):
    results.append((name, ok, detail))
    print(f"    {'pass' if ok else 'FAIL'}  {name}")
    if detail and not ok:
        print(f"          {detail[:200]}")


def main():
    from app.main import create_gui_app
    from app.web import routes_pages

    app = create_gui_app()

    # A user that never reaches the database.  Building one in memory keeps this
    # check from leaving an account behind if it dies half way, which a real row
    # would, and there is no worse thing to leave on a management box than a
    # login nobody remembers creating.
    ghost = User(
        id=-1,
        username="check-runner",
        role=UserRole.ADMIN,
        source=AuthSource.LOCAL,
        enabled=True,
        totp_enrolled=True,
        must_change_password=False,
    )

    routes_pages.page_user = lambda request, db: ghost
    routes_pages.require_page_user = lambda request, db: ghost

    from app.auth import service as auth_service
    auth_service.current_user = lambda *a, **k: ghost

    from app.web import routes_api
    routes_api.current_user = lambda *a, **k: ghost

    # The guard the API depends on, pointed at our ghost.
    original_guard = routes_api.guard

    def guard_override(request=None, db=None):
        from app.db import get_engine
        from sqlalchemy.orm import Session
        session = Session(bind=get_engine())
        return routes_api.ObjectGuard(session, ghost)

    app.dependency_overrides[original_guard] = guard_override

    # Come from loopback for the duration of the run.
    #
    # The test client's address is the literal string "testclient", which is in
    # nobody's admin allow list, so every request gets turned away with a 404
    # and every check passes without testing a thing.  A green run that touched
    # nothing is worse than a red one, so this is patched rather than worked
    # around, and the allow list has its own check elsewhere.
    from app.web import security
    security.client_ip = lambda request: "127.0.0.1"

    client = TestClient(app, raise_server_exceptions=False)

    print("  pages")
    for path in PAGES:
        try:
            response = client.get(path, follow_redirects=False)
            ok = response.status_code < 500
            detail = ""
            if not ok:
                body = response.text
                detail = next((ln for ln in body.splitlines()
                               if "Error" in ln or "error" in ln), body[:200])
            check(f"GET {path} -> {response.status_code}", ok, detail)
        except Exception as exc:
            check(f"GET {path}", False, f"{type(exc).__name__}: {exc}")

    print()
    # The detail pages, which the list above never reaches.
    #
    # A template error on one of these is a 500 on the page somebody spends
    # most of their time on, and the sweep used to open /sites and stop there,
    # so it proved nothing about the page /sites leads to.  One shipped that
    # way: a jinja filter that does not exist, which no amount of reading the
    # python would have caught.
    with session_scope() as session:
        from app.models import Pool as _Pool, VirtualHost as _VH
        detail_paths = []
        first_host = session.query(_VH).first()
        if first_host:
            detail_paths.append(f"/sites/{first_host.id}")
        first_pool = session.query(_Pool).first()
        if first_pool:
            detail_paths.append(f"/pools/{first_pool.id}")

    if not detail_paths:
        print("    skip  the detail pages, because this node has none to open")
    else:
        for path in detail_paths:
            try:
                response = client.get(path, follow_redirects=False)
                ok = response.status_code < 500
                detail = ""
                if not ok:
                    detail = next((ln for ln in response.text.splitlines()
                                   if "Error" in ln), response.text[:200])
                check(f"GET {path} -> {response.status_code}", ok, detail)
            except Exception as exc:
                check(f"GET {path}", False, f"{type(exc).__name__}: {exc}")

    print()
    print("  read only endpoints")
    for path in ENDPOINTS:
        try:
            response = client.get(path, follow_redirects=False)
            # A 404 here means the path in this list is wrong, which is a broken
            # check rather than a passing one.  Counting it as a pass is how a
            # suite quietly stops covering the thing it claims to.
            ok = response.status_code < 500 and response.status_code != 404
            detail = response.text[:200] if not ok else ""
            check(f"GET {path} -> {response.status_code}", ok, detail)
        except Exception as exc:
            check(f"GET {path}", False, f"{type(exc).__name__}: {exc}")

    print()
    # Every page's own script has to wait for the layout's script.
    #
    # app.js is the last thing in base.html, after the content block, so an
    # inline script that runs the moment the browser reaches it runs before
    # window.NFM exists.  Everything on these pages goes through NFM, so the
    # whole page silently does nothing.  It cost a page shipping with a table
    # that never stopped saying it was loading, and no server side check could
    # have seen it: the page renders, the API answers, and the only thing wrong
    # is what the browser did with them.
    #
    # Cheap to check by reading the templates, so it is checked here rather
    # than being left to somebody noticing.
    template_dir = Path(__file__).resolve().parent.parent / "app" / "web" / "templates"
    unwrapped = []
    for path in sorted(template_dir.glob("*.html")):
        text = path.read_text()
        for block in re.findall(r"<script(?![^>]*\bsrc=)[^>]*>(.*?)</script>",
                                text, re.S):
            if "NFM." not in block:
                continue
            head = block.lstrip()[:400]
            if "DOMContentLoaded" not in head:
                unwrapped.append(path.name)
                break

    check("every page waits for app.js before using NFM", not unwrapped,
          f"these run their script too early, so NFM is undefined and the page "
          f"quietly does nothing: {sorted(set(unwrapped))}")

    # An event handler written on the tag cannot run here.
    #
    # Every page is served with script-src 'self' and a nonce, and no
    # unsafe-inline, so the browser refuses to execute an onclick or an
    # onchange attribute.  The control still looks right and does nothing at
    # all: the role dropdown on this very page moved for months and never sent
    # anything, because that is what the failure looks like.
    #
    # Same shape as the check above, and the same reason for reading templates
    # rather than waiting for somebody to notice.
    inline = []
    for path in sorted(template_dir.glob("*.html")):
        for match in re.finditer(r"<[a-zA-Z][^>]*?\son([a-z]+)\s*=\s*[\"']",
                                 path.read_text()):
            inline.append(f"{path.name}: on{match.group(1)}")

    check("no page puts an event handler on the tag", not inline,
          f"the page's own CSP refuses to run these, so the control does "
          f"nothing: {sorted(set(inline))}")

    failed = [name for name, ok, _ in results if not ok]

    # Prove the run actually reached the app.  If the allow list or the session
    # turned everything away, every check "passes" while testing nothing, and
    # that reads exactly like success.
    reached = sum(1 for name, ok, _ in results if "-> 200" in name)
    if reached < 3:
        print(f"  ONLY {reached} responses were 200.  This run did not get past")
        print("  the door, so it proved nothing.  Check the admin allow list and")
        print("  that the signed in user override is still wired up.")
        failed.append("<the sweep never reached the app>")

    print(f"  {len(results) - len(failed)} of {len(results)} answered without raising")
    print()
    print("  what this does not cover:")
    print("    - whether the page is correct, only that it did not raise")
    print("    - anything behind a button that writes, which needs a browser")
    print("    - sign in, lockout and TOTP, which need a throwaway account for real")
    print()
    print("  RESULT:", "nothing raised" if not failed else f"{len(failed)} RAISED: {failed}")
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
