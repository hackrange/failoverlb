"""Photograph just the Changes page, while something is pending."""
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
    pg = b.new_context(ignore_https_errors=True, viewport={"width":1440,"height":900},
                       device_scale_factor=2).new_page()
    pg.goto(BASE + "/login", wait_until="networkidle")
    pg.fill("input[name=username]", os.environ["NFM_USER"])
    pg.fill("input[name=password]", os.environ["NFM_PASSWORD"])
    pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")
    if pg.locator("input[name=totp]").count():
        pg.fill("input[name=totp]", totp(os.environ["NFM_TOTP"]))
        pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")
    pg.goto(BASE + "/changes", wait_until="networkidle")
    pg.wait_for_timeout(3000)
    pg.evaluate(REWRITE, SUBS); pg.wait_for_timeout(400)
    pg.screenshot(path=str(OUT / "changes.png"))
    found = {}
    for key, sel in {"apply":"#changes-apply", "summary":"#pending-summary",
                     "diffs":"#pending-diffs"}.items():
        loc = pg.locator(sel).first
        if loc.count():
            bx = loc.bounding_box()
            if bx:
                found[key] = {"x":bx["x"],"y":bx["y"],"w":bx["width"],"h":bx["height"],
                              "cx":bx["x"]+bx["width"]/2,"cy":bx["y"]+bx["height"]/2}
    (OUT / "changes.json").write_text(json.dumps(found, indent=2))
    print("  changes.png, targets found:", ", ".join(found) or "none")
    b.close()
