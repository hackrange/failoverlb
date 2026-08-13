"""
Photograph the GUI and record where things are.

Every picture in the manual comes from a browser signed in to a running node.
Alongside each png this writes a json file giving the position of the elements
worth pointing at, found by css selector.

Positions rather than pixel coordinates typed into the manual, because a
coordinate is right until somebody adds a menu item, and then every arrow in
the book points at the wrong thing and nothing says so.  A selector either
still matches or it does not, and when it does not the build says which picture
needs looking at.

The names in the shots are substituted as the page is photographed.  The lab
really is example.invalid and the manual talks about domain.com throughout, so
the rewrite happens in the browser and the picture is of the real thing.
"""
import base64
import hashlib
import hmac
import json
import os
import pathlib
import struct
import sys
import time

from playwright.sync_api import sync_playwright

from docsconf import SUBSTITUTIONS as SUBS  # noqa: E402

BASE = os.environ.get("NFM_URL", os.environ.get("NFM_URL", ""))
USER = os.environ.get("NFM_USER", "docs")
PASSWORD = os.environ["NFM_PASSWORD"]
SECRET = os.environ.get("NFM_TOTP", "")
OUT = pathlib.Path(os.environ.get("NFM_SHOTS", "/docs/shots"))
OUT.mkdir(parents=True, exist_ok=True)


REWRITE = """
(pairs) => {
  const apply = () => {
    const walk = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    const seen = [];
    while (walk.nextNode()) seen.push(walk.currentNode);
    for (const node of seen) {
      let t = node.nodeValue;
      for (const [from, to] of pairs) { t = t.split(from).join(to); }
      if (t !== node.nodeValue) node.nodeValue = t;
    }
    for (const el of document.querySelectorAll("input")) {
      let v = el.value;
      for (const [from, to] of pairs) { v = v.split(from).join(to); }
      if (v !== el.value) el.value = v;
    }
  };
  apply();
  if (!window.__rw) {
    window.__rw = new MutationObserver(apply);
    window.__rw.observe(document.body, {childList: true, subtree: true});
  }
}
"""


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30),
                      hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


def shoot(page, name, targets=None, wait=2200, clip=None):
    page.wait_for_timeout(wait)
    page.evaluate(REWRITE, SUBS)
    page.wait_for_timeout(300)

    png = OUT / f"{name}.png"
    page.screenshot(path=str(png), clip=clip,
                    full_page=name.endswith("-detail") or name == "settings")

    found, missing = {}, []
    for key, selector in (targets or {}).items():
        loc = page.locator(selector).first
        try:
            if loc.count() == 0:
                missing.append(f"{key} ({selector})")
                continue
            box = loc.bounding_box()
            if not box:
                missing.append(f"{key} ({selector})")
                continue
            found[key] = {"x": box["x"], "y": box["y"],
                          "w": box["width"], "h": box["height"],
                          "cx": box["x"] + box["width"] / 2,
                          "cy": box["y"] + box["height"] / 2}
        except Exception:
            missing.append(f"{key} ({selector})")

    (OUT / f"{name}.json").write_text(json.dumps(found, indent=2))
    status = f"  {name}.png"
    if missing:
        status += "   MISSING: " + ", ".join(missing)
    print(status)
    if missing:
        print(f"    ^ these callouts cannot be drawn, check {name}",
              file=sys.stderr)


def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(
            executable_path=os.environ.get("NFM_CHROMIUM", "/usr/bin/chromium"),
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        ctx = browser.new_context(ignore_https_errors=True,
                                  viewport={"width": 1440, "height": 900},
                                  device_scale_factor=2)
        page = ctx.new_page()

        # ---------------------------------------------------------- signing in
        page.goto(BASE + "/login", wait_until="networkidle")
        shoot(page, "login-empty", {
            "username": "input[name=username]",
            "password": "input[name=password]",
            "continue": "button[type=submit]",
        })

        page.fill("input[name=username]", USER)
        page.fill("input[name=password]", PASSWORD)
        page.click("button[type=submit]")
        page.wait_for_load_state("networkidle")

        if SECRET and page.locator("input[name=totp]").count():
            shoot(page, "login-code", {"code": "input[name=totp]",
                                       "continue": "button[type=submit]"})
            page.fill("input[name=totp]", totp(SECRET))
            page.click("button[type=submit]")
            page.wait_for_load_state("networkidle")

        # ------------------------------------------------------------ the tour
        shoot(page, "dashboard", {
            "nav": "nav a[href$='/sites']",
            "node": ".node-chip",
            "signout": "a[href$='/logout'], a:has-text('Sign out')",
        }, wait=3000)

        pages = [
            ("sites", "/sites", {"add": "#new-site", "apply": "#apply-config"}),
            ("pools", "/pools", {"apply": "#apply-config"}),
            ("certificates", "/certificates", {
                "letsencrypt": "button:has-text('Lets Encrypt')",
                "upload": "button:has-text('Upload one')",
                "selfsigned": "button:has-text('self signed')",
                "csr": "button:has-text('signing request')",
            }),
            ("gslb", "/gslb", {
                "addzone": "button:has-text('Add a zone')",
                "listener": "#status-body",
                "delegation": ".deleg pre",
            }),
            ("cluster", "/cluster", {
                "nodes": "table tbody tr:first-child td:nth-child(2)",
                "addnode": "#join-token",
                "resync": "#resync",
            }),
            ("utilization", "/utilization", {"charts": "#charts"}),
            ("errorpages", "/error-pages", {
                "add": "#new-template",
                "apply": "#apply-config",
            }),
            ("streams", "/streams", {"add": "#new-stream"}),
            ("maps", "/maps", {"add": "#new-map"}),
            ("users", "/users", {"add": "#new-user"}),
            # /changes is deliberately not here.  It is empty unless something
            # is saved and not yet applied, which is the normal state and a
            # poor picture for the chapter about applying.  shot-changes.py
            # photographs it with a real pending change and puts it back.
            ("audit", "/audit", {"entries": "table tbody tr:first-child"}),
            # The rest of the menu.  Every page the reader can reach should
            # appear somewhere in the manual, so every page is photographed
            # whether or not a chapter points at it yet.
            # /import and /zones are not here.  Both are worth photographing
            # with real content on them, which shot-import.py and shot-zones.py
            # arrange and then undo.  Leaving them in the sweep meant an empty
            # screen quietly overwriting the good one.
                        ("nginx-build", "/upgrade", {}),
            ("parity", "/parity", {}),
            ("account", "/account", {}),
            ("settings", "/settings", {
                "acme": "[name=acme_email]",
                "staging": "[name=acme_staging]",
                "renew": "[name=acme_renew_days_before]",
                "dns": "[name=dns_resolvers]",
                "mgmt": "[name=management_networks]",
                "health": "[name=health_check_interval]",
            }),
        ]
        for name, path, targets in pages:
            try:
                page.goto(BASE + path, wait_until="networkidle")
                shoot(page, name, targets, wait=2600)
            except Exception as exc:
                print(f"  could not shoot {path}: {exc}", file=sys.stderr)

        # ------------------------------------------------- the detail screens
        # Reached by clicking into a site or a pool rather than by a fixed
        # address, so the first row is opened instead of guessing an id.
        try:
            page.goto(BASE + "/sites/1", wait_until="networkidle")
            shoot(page, "site-detail", {
                "names": "#f-names",
                "mode": "#f-mode",
                                "cert": "#f-cert",
                "addpath": "#add-path",
                "check": "#check-config",
                "delete": "#delete-site",
            }, wait=2600)
        except Exception as exc:
            print(f"  site detail: {exc}", file=sys.stderr)

        try:
            page.goto(BASE + "/pools/1", wait_until="networkidle")
            shoot(page, "pool-detail", {
                "lb": "#h-lb",
                "members": "#add-member",
                "healthcheck": "#h-hc",
                "tls": "#h-backendtls",
                "delete": "#delete-pool",
            }, wait=2600)
        except Exception as exc:
            print(f"  pool detail: {exc}", file=sys.stderr)

        # ------------------------------------------------------------- dialogs
        # The dialogs are where the actual work happens, so they matter more
        # than the list pages that lead to them.
        try:
            page.goto(BASE + "/gslb", wait_until="networkidle")
            page.wait_for_timeout(2000)
            page.click("#new-zone")
            shoot(page, "gslb-add-zone", {
                "name": "#z-name",
                "nameservers": "#z-ns",
                "save": "#z-save",
            }, wait=1200)
        except Exception as exc:
            print(f"  gslb zone dialog: {exc}", file=sys.stderr)

        try:
            page.goto(BASE + "/gslb", wait_until="networkidle")
            page.wait_for_timeout(2200)
            page.click("[data-rec]")
            shoot(page, "gslb-edit-record", {
                "ttl": "#r-ttl",
                "policy": "#r-policy",
                "answers": "#r-answers",
                "save": "#r-save",
            }, wait=1500)
        except Exception as exc:
            print(f"  gslb record dialog: {exc}", file=sys.stderr)

        try:
            page.goto(BASE + "/certificates", wait_until="networkidle")
            page.wait_for_timeout(2000)
            page.click("button:has-text('Lets Encrypt')")
            shoot(page, "cert-letsencrypt", wait=1200)
        except Exception as exc:
            print(f"  cert dialog: {exc}", file=sys.stderr)

        browser.close()


main()
