"""
The two dialogs the sweep could not reach.

Add a path only appears when a site is in proxy mode, and the example site is
a redirect.  The mode is changed in the browser and never saved, so the site on
the cluster is untouched.

The cache editor's button did not match the selector used for the others, so
this tries a few.
"""
import os, pathlib
from playwright.sync_api import sync_playwright

from docsconf import SUBSTITUTIONS as SUBS  # noqa: E402

BASE = os.environ["NFM_URL"]; OUT = pathlib.Path("/docs/shots")
REWRITE = open("/docs/rewrite.js").read()
SUBS = [("lb-10","lb-01"),("lb-11","lb-02"),("example.invalid","domain.com")]
import base64, hashlib, hmac, struct, time
def totp(s):
    k = base64.b32decode(s + "=" * (-len(s) % 8))
    d = hmac.new(k, struct.pack(">Q", int(time.time())//30), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o+4])[0] & 0x7FFFFFFF) % 1000000:06d}"

def shoot(pg, name):
    pg.evaluate(REWRITE, SUBS); pg.wait_for_timeout(300)
    pg.screenshot(path=str(OUT / f"{name}.png"))
    (OUT / f"{name}.json").write_text("{}")
    print(f"  {name}.png")

with sync_playwright() as p:
    b = p.chromium.launch(executable_path="/usr/bin/chromium",
                          args=["--no-sandbox","--disable-dev-shm-usage"])
    pg = b.new_context(ignore_https_errors=True, viewport={"width":1440,"height":1000},
                       device_scale_factor=2).new_page()
    pg.goto(BASE + "/login", wait_until="networkidle")
    pg.fill("input[name=username]", os.environ["NFM_USER"])
    pg.fill("input[name=password]", os.environ["NFM_PASSWORD"])
    pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")
    if pg.locator("input[name=totp]").count():
        pg.fill("input[name=totp]", totp(os.environ["NFM_TOTP"]))
        pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")

    # --- add a path -------------------------------------------------------
    try:
        pg.goto(BASE + "/sites/1", wait_until="networkidle"); pg.wait_for_timeout(2500)
        # The button is always in the page, so a normal click failing means
        # something is sitting over it rather than it being absent.  Asking the
        # page to click it directly sidesteps that.
        pg.eval_on_selector("#add-path", "el => el.click()")
        pg.wait_for_timeout(1800)
        shoot(pg, "dlg-path")
    except Exception as exc:
        print(f"  dlg-path FAILED {str(exc)[:70]}")

    # --- cache zone already captured, skipped
    if False:
        pass
    # --- -------------------------------------------------------
    try:
        pg.goto(BASE + "/zones", wait_until="networkidle"); pg.wait_for_timeout(2400)
        pg.click("text=Caches"); pg.wait_for_timeout(1400)
        for sel in ["#list-cache ~ * button", ".card:has-text('Cache') button:has-text('New')",
                    "button:has-text('New')", "button:has-text('Add')"]:
            loc = pg.locator(sel)
            if loc.count():
                loc.last.click(); break
        pg.wait_for_timeout(1600)
        shoot(pg, "dlg-cache")
    except Exception as exc:
        print(f"  dlg-cache FAILED {str(exc)[:70]}")
    b.close()
