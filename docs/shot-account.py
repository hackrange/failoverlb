"""
Photograph first time setup, using a throwaway account.

The enrolment and recovery code screens only exist once, on an account that
has never signed in, so they cannot be captured from a normal login.  A
temporary account is put through the flow and deleted afterwards.

The secret is read off the page and the code worked out from it, which is
exactly what an authenticator app does with the square code beside it.
"""
import base64, hashlib, hmac, json, os, pathlib, re, struct, time
from playwright.sync_api import sync_playwright

from docsconf import SUBSTITUTIONS as SUBS  # noqa: E402

BASE = os.environ["NFM_URL"]; OUT = pathlib.Path("/docs/shots")
REWRITE = open("/docs/rewrite.js").read()
SUBS = [("lb-10","lb-01"),("lb-11","lb-02"),("example.invalid","domain.com"),
        ("docs-tmp","your-name")]

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
    pg = b.new_context(ignore_https_errors=True, viewport={"width":1440,"height":1100},
                       device_scale_factor=2).new_page()
    pg.goto(BASE + "/login", wait_until="networkidle")
    pg.fill("input[name=username]", "docs-tmp")
    pg.fill("input[name=password]", os.environ["TMP_PASSWORD"])
    pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(2000)

    body = pg.content()
    shoot(pg, "acct-enrol")

    m = re.search(r"\b([A-Z2-7]{16,64})\b", pg.inner_text("body"))
    if not m:
        print("  could not find the secret on the page"); b.close(); raise SystemExit
    secret = m.group(1)

    field = None
    for sel in ["input[name=totp]", "input[name=code]", "input[type=text]"]:
        if pg.locator(sel).count(): field = sel; break
    pg.fill(field, totp(secret))
    pg.click("button[type=submit]"); pg.wait_for_load_state("networkidle")
    pg.wait_for_timeout(2000)
    shoot(pg, "acct-recovery")

    # Past setup now, so the ordinary account screens are reachable.
    for path, name in [("/account", "acct-mine")]:
        try:
            pg.goto(BASE + path, wait_until="networkidle"); pg.wait_for_timeout(1800)
            shoot(pg, name)
        except Exception as exc:
            print(f"  {name}: {str(exc)[:60]}")
    b.close()
