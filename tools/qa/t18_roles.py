"""
Suite 18: roles.

Held out of the first pass with the access lists, and for the same reason: a
permission that is not enforced looks exactly like one that is, right up until
somebody uses it.  The button being hidden proves nothing.  The page is drawn
by the server from the same `can()` the routes use, so a missing guard on a
route is invisible from every screen in the product.

So every role here is tested twice.  Once as a person sees it, by signing in as
that account in its own browser and looking at what is on the page, and once as
an attacker sees it, by calling the endpoint behind the hidden button from that
account's own signed in session.  A pass needs both: the control absent from
the page and the route refusing.

`checks/authz_sweep.py` already covers the refusal side without applying
anything, and deliberately does not test the allowed side, because a check that
has to make a real change to prove itself is one nobody runs.  This suite is
where the allowed side gets proved, because this is the pass that is allowed to
change things.

Every account here is created and removed by the suite.  Nothing touches the
account the harness itself signs in as, and nothing touches the break glass
admin.
"""
import json
import re
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t18_roles").start()

PASSWORD = "qa-round-password-9137"
NEW_PASSWORD = "qa-round-password-2288"
ACCOUNTS = {"qa-viewer": "viewer", "qa-operator": "operator", "qa-admin": "admin"}


def user_rows():
    """
    The account list, read off the table the product actually draws.

    Row by row rather than by looking for one particular form, because the
    page deliberately leaves the role dropdown, the enable button and the
    delete button off your own row.  Reading only those forms would make the
    signed in account invisible to this suite, which is the one account some
    of these tests are about.
    """
    r.goto("/users")
    return r.page.evaluate("""
      () => Array.from(document.querySelectorAll('table tbody tr')).map(tr => {
        const name = (tr.querySelector('td strong') || {}).textContent || '';
        const form = tr.querySelector('form[action*="/users/"]');
        const id = form ? (form.getAttribute('action').match(/users\\/(\\d+)\\//) || [])[1] : null;
        const sel = tr.querySelector('select[name=role]');
        // The role cell is the second one.  The first carries a "you" badge on
        // your own row, and reading the first badge in the row picked that up
        // and reported everybody's role as "you".
        const cell = tr.querySelectorAll('td')[1];
        const badge = cell ? cell.querySelector('.badge') : null;
        return {
          username: name.trim(),
          id: id,
          role: sel ? sel.value : (badge ? badge.textContent.trim() : null),
          is_you: !!tr.querySelector('.badge'),
        };
      }).filter(u => u.username)
    """)


def find_user(name):
    return next((u for u in user_rows() if u["username"] == name), None)


def post_form(path, fields):
    """
    Submit one of the user management forms from inside the signed in page.

    These are form posts rather than json endpoints, which is the reason
    authz_sweep names them by their real paths: guessing an api path gets a 404
    that reads exactly like a refusal.
    """
    return r.page.evaluate("""
      async ([path, fields]) => {
        const body = new URLSearchParams();
        const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
        const token = document.querySelector('input[name=csrf_token]');
        body.set('csrf_token', token ? token.value : (m ? decodeURIComponent(m[1]) : ''));
        for (const [k, v] of Object.entries(fields)) body.set(k, v);
        const base = document.querySelector('meta[name=nfm-base]')?.content
                  || document.querySelector('meta[name=base]')?.content || '';
        const res = await fetch(base + path, {
          method: 'POST', body, credentials: 'same-origin', redirect: 'manual',
          headers: {'X-CSRF-Token': m ? decodeURIComponent(m[1]) : ''},
        });
        return {status: res.status, url: res.url};
      }
    """, [path, fields])


class AsUser:
    """
    A second browser, signed in as somebody else.

    Its own context so it has its own cookies.  The admin session in `r` stays
    open the whole time, which is what makes it possible to change somebody's
    role in one window and watch what happens in the other.
    """

    # The secret an account enrolled with, kept for the length of the run.
    # An account only ever sees it once, at enrolment, so a second sign in as
    # the same person has to remember it or there is no way back in.
    SECRETS = {}

    # The last thirty second window a code was accepted in, per account.
    #
    # The product remembers the last step it accepted and refuses that code a
    # second time, which is right: a code read off somebody's shoulder is worth
    # nothing once they have used it.  It also means this suite cannot sign the
    # same account in twice inside one window, and the refusal looks exactly
    # like a wrong password.  So we wait for the next window rather than
    # reporting a defect that is the product working.
    LAST_STEP = {}

    def code(self):
        step = int(time.time()) // 30
        if self.LAST_STEP.get(self.username) == step:
            time.sleep(31 - (int(time.time()) % 30))
            step = int(time.time()) // 30
        self.LAST_STEP[self.username] = step
        return qa.totp(self.secret)

    def __init__(self, username, password):
        self.username = username
        self.ctx = r.browser.new_context(ignore_https_errors=True,
                                         viewport={"width": 1400, "height": 1000})
        self.ctx.set_default_timeout(30000)
        self.page = self.ctx.new_page()
        self.failed = None
        self.secret = self.SECRETS.get(username)
        self.sign_in(password)

    def sign_in(self, password):
        p = self.page
        p.goto(qa.BASE + "/login", wait_until="networkidle")
        p.fill("input[name=username]", self.username)
        p.fill("input[name=password]", password)
        p.click("button[type=submit]")
        p.wait_for_load_state("networkidle")

        # A brand new account has no second factor yet and is sent to set one
        # up before it is allowed anywhere.  The secret is on the page, which
        # is the only time it ever is.
        if "/enroll" in p.url:
            self.secret = p.locator("pre").first.inner_text().strip().replace(" ", "")
            self.SECRETS[self.username] = self.secret
            p.fill("input[name=code]", self.code())
            p.click("#enroll-form button[type=submit]")
            p.wait_for_load_state("networkidle")
            if "recovery" in p.url:
                p.click("a.btn.primary")
                p.wait_for_load_state("networkidle")
        elif p.locator("input[name=totp]").count():
            if not self.secret:
                # No secret means this run never saw the enrolment, so there is
                # no code to give.  Say so rather than crashing on None, which
                # reads as a harness fault when it is a missing precondition.
                self.failed = "asked for a code this run has no secret for"
                return
            p.fill("input[name=totp]", self.code())
            p.click("button[type=submit]")
            p.wait_for_load_state("networkidle")

        if "/change-password" in p.url or "change_password" in p.url:
            p.fill("input[name=new_password]", NEW_PASSWORD)
            p.fill("input[name=confirm_password]", NEW_PASSWORD)
            p.click("button[type=submit]")
            p.wait_for_load_state("networkidle")

    @property
    def signed_in(self):
        return "/login" not in self.page.url

    def goto(self, path):
        self.page.goto(qa.BASE + path, wait_until="networkidle")
        self.page.wait_for_timeout(300)
        return self.page

    def api(self, method, path, payload=None):
        return self.page.evaluate("""
        async ([method, path, payload]) => {
          const opt = {method, headers: {}, credentials: 'same-origin'};
          const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
          if (m) opt.headers['X-CSRF-Token'] = decodeURIComponent(m[1]);
          if (payload !== null) {
            opt.headers['Content-Type'] = 'application/json';
            opt.body = JSON.stringify(payload);
          }
          const base = document.querySelector('meta[name=base]')?.content || '';
          const res = await fetch(base + '/api' + path, opt);
          let body = null;
          const txt = await res.text();
          try { body = JSON.parse(txt); } catch (e) { body = txt; }
          return {status: res.status, body};
        }
        """, [method, path, payload])

    def close(self):
        try:
            self.ctx.close()
        except Exception:
            pass


def cleanup_accounts():
    for name in ACCOUNTS:
        row = find_user(name)
        if row and row.get("id"):
            post_form(f"/users/{row['id']}/delete", {})


cleanup_accounts()


# ---------------------------------------------------------------- ROLE-01

t = r.test("ROLE-01", "Roles", "Creating an account for each role",
           "Make one account per role from the Users page and prove each one "
           "is stored with the role that was picked.",
           "The first thing anybody does after installing this: give the other "
           "people who need it an account, and give most of them less than "
           "full access.",
           "Three accounts appear on the page with the roles they were given.")
for name, role in ACCOUNTS.items():
    t.step(f"create {name} as a {role}")
    r.goto("/users")
    r.page.click("#new-user")
    r.page.wait_for_selector("#u-name")
    r.page.fill("#u-name", name)
    r.page.fill("#u-full", f"QA {role}")
    r.page.select_option("#u-role", role)
    r.page.fill("#u-pw", PASSWORD)
    if name == "qa-viewer":
        t.shot("the-new-user-form")
    r.page.click("form[action$='/users/create'] button[type=submit]")
    r.page.wait_for_load_state("networkidle")
    r.page.wait_for_timeout(600)

rows = user_rows()
t.proof("the account list after creating three", json.dumps(rows, indent=2))
for name, role in ACCOUNTS.items():
    row = next((u for u in rows if u["username"] == name), None)
    t.ok(f"{name} exists", row is not None, rows)
    t.ok(f"{name} is a {role}", row and row["role"] == role, row)
r.goto("/users")
t.shot("the-users-page-with-the-three-accounts", full=True)
t.close()


# ---------------------------------------------------------------- ROLE-02

t = r.test("ROLE-02", "Roles", "A new account has to set up a second factor first",
           "Sign in as a brand new account and prove it is sent to enrolment "
           "before it reaches anything.",
           "A local account with a password and nothing else is the weakest "
           "way into a tool that reconfigures load balancers, so the product "
           "does not let one exist quietly.",
           "The first sign in lands on the enrolment page, and only after a "
           "code is accepted does the account reach the dashboard.")
t.step("sign in as the viewer for the first time")
viewer = AsUser("qa-viewer", PASSWORD)
t.ok("enrolment was demanded and completed", viewer.secret is not None,
     "no enrolment page appeared, which means an account without a second "
     "factor reached the product")
t.ok("and the account is signed in afterwards", viewer.signed_in, viewer.page.url)
t.proof("where the viewer landed", viewer.page.url)
t.close()


# ---------------------------------------------------------------- ROLE-03

t = r.test("ROLE-03", "Roles", "A viewer can look and cannot touch",
           "Check both halves for a viewer: the controls are not on the page, "
           "and the routes behind them refuse.",
           "The role exists so somebody on a support desk can see what the "
           "fleet is doing without being able to change it.  If the routes are "
           "open then that person, or anybody who takes their session, has the "
           "whole product.",
           "Pages render, no create buttons, and every write comes back 403.")
t.step("look at the pages as a viewer")
page = viewer.goto("/sites")
t.ok("the sites page renders for a viewer", "/login" not in page.url, page.url)
try:
    viewer.page.screenshot(path=str(r.shots / "role-03-00-sites-as-a-viewer.png"))
    t.rec["shots"].append({"label": "the sites page as a viewer",
                           "file": "role-03-00-sites-as-a-viewer.png"})
except Exception as exc:
    t.note(f"screenshot failed: {exc}")

new_site_buttons = viewer.page.locator("#new-site").count()
t.ok("there is no new site button", new_site_buttons == 0, new_site_buttons)
viewer.goto("/zones")
acl_new = viewer.page.evaluate("() => document.querySelectorAll('[data-new=\"acl\"]').length")
t.ok("and no new access list button", acl_new == 0, acl_new)
nav_users = viewer.page.evaluate("() => document.body.innerHTML.includes('/users')")
t.ok("and no link to the users page", not nav_users, nav_users)

t.step("now call the routes behind those buttons anyway")
WRITES = [
    ("POST", "/hosts", {"name": "qa-viewer-should-not-exist",
                        "server_names": ["qa-viewer.invalid"], "mode": "static",
                        "document_root": "/var/www/qa-static"}),
    ("POST", "/pools", {"name": "qa_viewer_pool"}),
    ("POST", "/access-lists", {"name": "qa_viewer_acl", "allow": ["10.0.0.0/8"]}),
    ("POST", "/apply", {"summary": "a viewer applying"}),
]
for method, path, payload in WRITES:
    res = viewer.api(method, path, payload)
    t.proof(f"viewer {method} {path}", json.dumps(res, indent=2)[:800])
    t.ok(f"a viewer {method} {path} is refused", res["status"] == 403,
         f"got {res['status']}: {str(res['body'])[:200]}")

t.step("and check nothing was made by the refused calls")
made = [h["name"] for h in r.api("GET", "/hosts")["body"]["hosts"]
        if h["name"].startswith("qa-viewer")]
t.ok("no site was created", not made, made)
t.close()


# ---------------------------------------------------------------- ROLE-04

t = r.test("ROLE-04", "Roles", "An operator can run the fleet but not the people in it",
           "Prove the allowed half of the operator role for real, then prove "
           "the admin only half is refused.",
           "The role most people running this will actually use day to day.  "
           "It has to be able to do the whole job, or everybody ends up an "
           "admin and the role means nothing.",
           "The operator creates a site, an access list and applies for real, "
           "and is refused on users, settings and the cluster.")
t.step("sign in as the operator")
operator = AsUser("qa-operator", PASSWORD)
t.ok("the operator is signed in", operator.signed_in, operator.page.url)

t.step("do a real piece of config work as the operator")
res = operator.api("POST", "/access-lists",
                   {"name": "qa_operator_acl", "allow": ["10.0.0.0/8"],
                    "default_action": "deny", "include_management": True})
t.proof("operator creating an access list", json.dumps(res, indent=2)[:600])
t.ok("an operator may create an access list", res["status"] in (200, 201), res)
OP_ACL = (res.get("body") or {}).get("id") if isinstance(res.get("body"), dict) else None

res = operator.api("POST", "/hosts",
                   {"name": "qa-operator-site",
                    "server_names": [f"qa-operator.{qa.DOMAIN}"],
                    "mode": "static", "document_root": qa.STATIC_DIR})
t.proof("operator creating a site", json.dumps(res, indent=2)[:600])
t.ok("an operator may create a site", res["status"] in (200, 201), res)

res = operator.api("POST", "/apply", {"summary": "qa: an operator applying"})
t.proof("operator applying the fleet config", json.dumps(res, indent=2)[:600])
t.ok("an operator may apply the fleet config", res["status"] == 200, res)

t.step("now the things only an admin may do")
res = operator.api("POST", "/cluster/failover", {"node": ""})
t.proof("operator asking for a failover", json.dumps(res, indent=2)[:600])
t.ok("an operator may not move the active role", res["status"] == 403, res)

# The base path comes off the nfm-base meta tag.  Reading the wrong tag gives
# undefined, the fetch asks for a path that was never a route, and the 404 that
# comes back reads exactly like a refusal.  That is the same trap authz_sweep
# has written at the top of it, and this suite fell in it on its first run.
got = operator.page.evaluate("""
  async () => {
    const base = document.querySelector('meta[name=nfm-base]')?.content ?? null;
    if (base === null) return 'no base meta tag';
    const res = await fetch(base + '/users', {credentials: 'same-origin',
                                              redirect: 'manual'});
    return res.status;
  }
""")
t.proof("operator opening the users page", str(got))
t.ok("the request reached a real route rather than a 404", got != 404, got)
t.ok("an operator cannot open the users page", got in (403, 302, 0), got)
t.close()


# ---------------------------------------------------------------- ROLE-05

t = r.test("ROLE-05", "Roles", "Changing a role ends the sessions it was using",
           "Change the viewer into an operator from the admin window and "
           "watch what happens to the viewer's own session, then sign in "
           "again and prove the new role is really in force.",
           "Somebody is promoted or, much more to the point, demoted while "
           "they are sitting in the tool.  A session that carries on with the "
           "permissions it had when it started means taking access away does "
           "not take access away until that person happens to sign out, which "
           "could be next week.",
           "The open session stops working the moment the role changes, and a "
           "fresh sign in has the new permission.")
t.step("as the viewer, be refused")
before = viewer.api("POST", "/pools", {"name": "qa_promotion_pool"})
t.proof("the viewer before anything changes", json.dumps(before, indent=2)[:400])
t.ok("the viewer is refused before the change", before["status"] == 403, before)

t.step("as the admin, change the viewer into an operator")
row = find_user("qa-viewer")
res = post_form(f"/users/{row['id']}/role", {"role": "operator"})
t.proof("changing the role", json.dumps(res, indent=2))
t.ok("and the page shows the new role",
     (find_user("qa-viewer") or {}).get("role") == "operator", find_user("qa-viewer"))

t.step("look at the viewer's session, which is still open")
during = viewer.api("POST", "/pools", {"name": "qa_promotion_pool"})
t.proof("the session that was open when the role changed",
        json.dumps(during, indent=2)[:400])
t.ok("the open session was signed out by the change", during["status"] == 401,
     f"got {during['status']}: {str(during['body'])[:200]}")
t.note("that is the product being careful rather than a fault.  The route "
       "revokes every session the account has, so a demotion takes effect at "
       "once instead of whenever they next sign out.")

t.step("sign in again and prove the new role is really in force")
viewer.close()
viewer = AsUser("qa-viewer", PASSWORD)
t.ok("the account could sign in again", viewer.signed_in,
     viewer.failed or viewer.page.url)
after = viewer.api("POST", "/pools", {"name": "qa_promotion_pool"})
t.proof("the same account after signing in again", json.dumps(after, indent=2)[:400])
t.ok("the new role is in force on a fresh session", after["status"] in (200, 201),
     f"got {after['status']}: {str(after['body'])[:200]}")

t.step("take it away again and prove that lands just as hard")
res = post_form(f"/users/{row['id']}/role", {"role": "viewer"})
t.ok("the page shows the role back at viewer",
     (find_user("qa-viewer") or {}).get("role") == "viewer", find_user("qa-viewer"))
again = viewer.api("POST", "/pools", {"name": "qa_demotion_pool"})
t.proof("the promoted session after being demoted", json.dumps(again, indent=2)[:400])
t.ok("the demotion ended that session too", again["status"] == 401,
     f"got {again['status']}")
t.close()


# ---------------------------------------------------------------- ROLE-06

t = r.test("ROLE-06", "Roles", "You cannot take your own access away",
           "As the admin the harness is signed in as, try to change your own "
           "role and delete your own account.",
           "The way a tool ends up with nobody who can administer it.  One "
           "admin, one careless click, and the only route back is the "
           "database.",
           "Both are refused and the account is untouched.")
me = find_user(qa.USER)
t.ok("the harness account is on the page", me is not None, user_rows())
res = post_form(f"/users/{me['id']}/role", {"role": "viewer"})
t.proof("changing your own role", json.dumps(res, indent=2))
still = find_user(qa.USER)
t.ok("your own role is unchanged", still and still["role"] == "admin", still)

res = post_form(f"/users/{me['id']}/delete", {})
t.proof("deleting your own account", json.dumps(res, indent=2))
t.ok("your own account is still there", find_user(qa.USER) is not None, user_rows())
t.close()


# ---------------------------------------------------------------- ROLE-07

t = r.test("ROLE-07", "Roles", "A disabled account cannot get in",
           "Switch an account off and try to sign in with the right password.",
           "The first thing done when somebody leaves, and the thing that has "
           "to work immediately rather than at the next password change.",
           "The sign in is refused while it is off, and works again when it "
           "is switched back on.")
row = find_user("qa-admin")
res = post_form(f"/users/{row['id']}/enabled", {"enabled": "false"})
t.proof("switching the account off", json.dumps(res, indent=2))
blocked = AsUser("qa-admin", PASSWORD)
t.proof("where a disabled account lands", blocked.page.url)
t.ok("a disabled account cannot sign in", not blocked.signed_in, blocked.page.url)
blocked.close()

post_form(f"/users/{row['id']}/enabled", {"enabled": "true"})
allowed = AsUser("qa-admin", PASSWORD)
t.ok("and can once it is switched back on", allowed.signed_in, allowed.page.url)
t.proof("where it lands once enabled again", allowed.page.url)
t.close()


# ---------------------------------------------------------------- ROLE-08

t = r.test("ROLE-08", "Roles", "The accounts reached the other node",
           "Check that an account made on this node exists on the other one.",
           "Accounts replicate outward from the active node, and none of the "
           "things people do to accounts change a line of nginx config, so "
           "nothing else would carry them.  A failover to a node that has "
           "never heard of you is a locked door.",
           "All three accounts are on the other node's roster too.")
if not qa.LB02:
    t.note("there is only one node in this run, so there is nothing to compare")
    t.ok("skipped, single node", True)
else:
    status = r.api("GET", "/cluster")["body"]
    t.proof("the fleet as the cluster page sees it", json.dumps(status, indent=2)[:1500])
    online = [n for n in status.get("nodes", [])
              if n.get("state") == "online" or n.get("is_self")]
    t.ok("both nodes are online", len(online) >= 2, status.get("nodes"))
    t.ok("and both are on the same config version",
         len({n.get("applied_version") for n in status.get("nodes", [])}) == 1,
         [(n.get("name"), n.get("applied_version")) for n in status.get("nodes", [])])
    t.note("whether the accounts themselves landed on the other node is read on "
           "that node, because the peer api needs a client certificate this "
           "harness does not have.  Recorded in the round's notes rather than "
           "claimed here.")
t.close()


# ---------------------------------------------------------------- ROLE-09

t = r.test("ROLE-09", "Roles", "Deleting an account ends what it could do",
           "Delete an account that is signed in, and prove its session stops "
           "working.",
           "Somebody is removed while they have the tool open.  A session that "
           "outlives the account is the whole point of removing it, undone.",
           "The account goes from the page and its open session can no longer "
           "write.")
t.step("delete the operator while its session is still open")
row = find_user("qa-operator")
res = post_form(f"/users/{row['id']}/delete", {})
t.proof("deleting the operator", json.dumps(res, indent=2))
t.ok("the account is gone from the page", find_user("qa-operator") is None, user_rows())

after = operator.api("POST", "/pools", {"name": "qa_ghost_pool"})
t.proof("the deleted account's own session, still open", json.dumps(after, indent=2)[:600])
t.ok("its session can no longer write", after["status"] in (401, 403),
     f"got {after['status']}: {str(after['body'])[:200]}")
made = [p["name"] for p in r.api("GET", "/pools")["body"]["pools"]
        if p["name"] == "qa_ghost_pool"]
t.ok("and nothing was created by it", not made, made)
t.close()


# ---------------------------------------------------------------- tidy up

print("\n  removing what this suite made")
for name in ("qa-operator-site",):
    row = next((h for h in r.api("GET", "/hosts")["body"]["hosts"]
                if h["name"] == name), None)
    if row:
        print("   ", r.api("DELETE", f"/hosts/{row['id']}")["status"], name)
zones = r.api("GET", "/zones")["body"]
for a in (zones.get("access_lists") or []):
    if a["name"].startswith("qa_"):
        print("   ", r.api("DELETE", f"/access-lists/{a['id']}")["status"], a["name"])
for p in r.api("GET", "/pools")["body"]["pools"]:
    if p["name"] in ("qa_promotion_pool", "qa_demotion_pool", "qa_ghost_pool"):
        print("   ", r.api("DELETE", f"/pools/{p['id']}")["status"], p["name"])
cleanup_accounts()
print("   accounts left:", [u["username"] for u in user_rows()])
r.apply("qa: removing what the roles suite made")

viewer.close()
operator.close()
allowed.close()
print("\nT17 DONE")
r.stop()
