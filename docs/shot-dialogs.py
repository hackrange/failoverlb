"""
Photograph every dialog.

The dialogs are where the settings actually are, so the manual needs each one.
They are opened by clicking rather than by visiting an address, so each entry
below is a page to go to and a thing to click.

Nothing is saved.  Each dialog is opened, photographed, and closed again by
moving to the next page, so this leaves no trace on the cluster.
"""
import base64, hashlib, hmac, json, os, pathlib, struct, time
from playwright.sync_api import sync_playwright

from docsconf import SUBSTITUTIONS as SUBS  # noqa: E402

BASE = os.environ["NFM_URL"]; OUT = pathlib.Path("/docs/shots")
REWRITE = open("/docs/rewrite.js").read()

def totp(s):
    k = base64.b32decode(s + "=" * (-len(s) % 8))
    d = hmac.new(k, struct.pack(">Q", int(time.time())//30), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o+4])[0] & 0x7FFFFFFF) % 1000000:06d}"

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

    for path, click, name, tab in DIALOGS:
        try:
            pg.goto(BASE + path, wait_until="networkidle")
            pg.wait_for_timeout(2200)
            if tab:
                pg.click(f"text={tab}"); pg.wait_for_timeout(1200)
            pg.click(click); pg.wait_for_timeout(1600)
            pg.evaluate(REWRITE, SUBS); pg.wait_for_timeout(300)
            pg.screenshot(path=str(OUT / f"{name}.png"))
            (OUT / f"{name}.json").write_text("{}")
            print(f"  {name}.png")
        except Exception as exc:
            print(f"  {name}: FAILED {str(exc)[:70]}")
    b.close()
