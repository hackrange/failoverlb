"""
Photograph the Import page, empty and with a preview on screen.

The preview writes nothing, so this needs no cleaning up afterwards.  The
config pasted in is invented for the manual: made up addresses from the range
reserved for documentation, and a made up domain.
"""
import base64, hashlib, hmac, json, os, pathlib, struct, time
from playwright.sync_api import sync_playwright

from docsconf import SUBSTITUTIONS as SUBS  # noqa: E402

BASE = os.environ["NFM_URL"]
OUT = pathlib.Path("/docs/shots")
REWRITE = open("/docs/rewrite.js").read()
SUBS = [("lb-10", "lb-01"), ("lb-11", "lb-02"), ("example.invalid", "domain.com")]

SAMPLE = """upstream shop_web {
    server 192.0.2.11:8080;
    server 192.0.2.12:8080;
}

upstream shop_api {
    server 192.0.2.21:9000;
    server 192.0.2.22:9000 backup;
}

server {
    listen 80;
    server_name shop.domain.com;
    return 301 https://$host$request_uri;
}

server {
    listen 443 ssl http2;
    server_name shop.domain.com;

    ssl_certificate     /etc/ssl/certs/shop.crt;
    ssl_certificate_key /etc/ssl/private/shop.key;

    location / {
        proxy_pass http://shop_web;
    }

    location /api {
        proxy_pass http://shop_api;
    }

    perl_modules /etc/nginx/perl;
}
"""

def totp(s):
    k = base64.b32decode(s + "=" * (-len(s) % 8))
    d = hmac.new(k, struct.pack(">Q", int(time.time())//30), hashlib.sha1).digest()
    o = d[-1] & 15
    return f"{(struct.unpack('>I', d[o:o+4])[0] & 0x7FFFFFFF) % 1000000:06d}"

def record(pg, name, targets, full=False):
    pg.evaluate(REWRITE, SUBS); pg.wait_for_timeout(300)
    pg.screenshot(path=str(OUT / f"{name}.png"), full_page=full)
    found = {}
    for key, sel in targets.items():
        loc = pg.locator(sel).first
        if loc.count():
            bx = loc.bounding_box()
            if bx:
                found[key] = {"x":bx["x"],"y":bx["y"],"w":bx["width"],"h":bx["height"],
                              "cx":bx["x"]+bx["width"]/2,"cy":bx["y"]+bx["height"]/2}
    (OUT / f"{name}.json").write_text(json.dumps(found, indent=2))
    print(f"  {name}.png  targets: {', '.join(found) or 'none'}")

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

    pg.goto(BASE + "/import", wait_until="networkidle")
    pg.wait_for_timeout(2200)
    record(pg, "import", {"config": "#config", "pickfile": "#pick-file",
                          "preview": "#preview"})

    pg.fill("#config", SAMPLE)
    pg.click("#preview")
    pg.wait_for_timeout(3000)
    record(pg, "import-preview", {"summary": "#summary", "doimport": "#do-import"},
           full=True)
    b.close()
