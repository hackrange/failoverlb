"""
Suite 3: making a website.

The site form itself: what a site does, which ports it answers on, what
certificate it uses, which names it owns, and what happens when it is switched
off.  Every one of these ends with real traffic at a real nginx.
"""
import json
import re
import ssl
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t03_sites").start()
NODE = qa.BACKEND_HOST
LB01, LB02 = qa.LB01, qa.LB02


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


def drop(kind, name):
    x = find(kind, name)
    if x:
        r.api("DELETE", f"/{kind}/{x['id']}")


def new_site(name, host, mode, pool=None, root=None, target=None,
             cert="", force=False, admin=False):
    r.goto("/sites")
    r.page.click("#new-site")
    r.page.wait_for_selector("#s-name")
    r.page.fill("#s-name", name)
    r.page.fill("#s-names", host)
    r.page.select_option("#s-mode", mode)
    if mode == "proxy" and pool:
        r.page.select_option("#s-pool", str(pool))
    if mode == "static":
        r.page.fill("#s-root", root)
    if mode == "redirect":
        r.page.fill("#s-target", target)
    r.page.select_option("#s-cert", cert)
    if force:
        r.page.check("#s-force")
    else:
        r.page.uncheck("#s-force")
    if admin:
        r.page.check("#s-admin")
    r.page.click("#s-save")
    r.page.wait_for_load_state("networkidle")
    r.page.wait_for_timeout(1200)
    return find("hosts", name)


POOL_ID = find("pools", "qa_pool")["id"]

for n in ("qa-static", "qa-redir", "qa-tls", "qa-names", "qa-off", "qa-ports",
          "qa-clone", "qa-clone-copy"):
    drop("hosts", n)

# Certificates too, or a re-run trips over the one the last run left behind.
_certs = r.api("GET", "/certs")["body"]
for c in (_certs.get("certs") or _certs.get("certificates") or []):
    if c["name"].startswith("qa-"):
        r.api("DELETE", f"/certs/{c['id']}")
        print("  removed leftover certificate", c["name"])

# ============================================================== SITE-01
t = r.test(
    "SITE-01", "Making a website",
    "A site that serves files off the disk",
    "Create a static site pointed at a directory, apply, and prove nginx "
    "returns the file that is really in that directory, with the right "
    "content type, and a 404 for one that is not.",
    "Not everything is an application.  Documentation, a holding page, a "
    "download area and the assets beside an app are all files on a disk, and "
    "putting a proxy in front of a web server to serve them is a waste.",
    "GET / returns the index.html from the directory, a css file comes back as "
    "text/css, and a missing file is a 404 rather than a 502.")

t.step("create the site through New site, choosing 'Serve files off the disk'")
r.goto("/sites")
t.shot("sites-list-before", full=True)
t.config("before")
site = new_site("qa-static", f"qa-static.{qa.DOMAIN}", "static",
                root=qa.STATIC_DIR)
t.ok("the site was created", bool(site), site)
SID = site["id"]
r.goto(f"/sites/{SID}")
t.shot("site-basics-static", full=True)
r.page.click("button[data-tab=config]")
r.page.wait_for_timeout(1200)
t.shot("config-tab-before-apply", full=True)
t.site_config("qa-static", "the config this site renders to")

t.step("apply and fetch the real files")
res = r.apply("qa: static site")
t.ok("apply succeeded", res["status"] == 200, res)
t.config("after")

index = t.probe("GET / on the static site", hostname=f"qa-static.{qa.DOMAIN}",
                path="/", ip=LB01, scheme="http")
t.ok("the index page came from the disk", index["status"] == 200
     and "QA static site" in index["body"], index["status"])
css = t.probe("GET /style.css", hostname=f"qa-static.{qa.DOMAIN}",
              path="/style.css", ip=LB01, scheme="http")
t.ok("css comes back as text/css",
     css["headers"].get("Content-Type", "").startswith("text/css"),
     css["headers"].get("Content-Type"))
sub = t.probe("GET a page in a subdirectory", hostname=f"qa-static.{qa.DOMAIN}",
              path="/sub/page.html", ip=LB01, scheme="http")
t.ok("a file in a subdirectory is served", sub["status"] == 200, sub["status"])
missing = t.probe("GET a file that is not there", hostname=f"qa-static.{qa.DOMAIN}",
                  path="/no-such-file.html", ip=LB01, scheme="http")
t.ok("a missing file is a 404, not a 502", missing["status"] == 404, missing["status"])
blob = t.probe("GET a 40k binary file", hostname=f"qa-static.{qa.DOMAIN}",
               path="/blob.bin", ip=LB01, scheme="http")
t.ok("a binary file comes back whole", blob["length"] == 40000, blob["length"])
lb02 = t.probe("the same request against the standby node",
               hostname=f"qa-static.{qa.DOMAIN}", path="/", ip=LB02, scheme="http")
t.ok("the standby serves it too", lb02["status"] == 200, lb02["status"])
t.close()

# ============================================================== SITE-02
t = r.test(
    "SITE-02", "Making a website",
    "A site that redirects somewhere else",
    "Create a redirect site and prove nginx answers with the status and "
    "Location a browser needs, keeping the path.",
    "Every domain move, every old brand name, every www to bare-domain "
    "decision ends up as one of these.  Getting the code wrong costs search "
    "ranking, and getting the path wrong sends everybody to a home page.",
    "The site answers 301 with a Location header pointing at the target, and "
    "the requested path is carried across.")

t.config("before")
site = new_site("qa-redir", f"qa-redir.{qa.DOMAIN}", "redirect",
                target=f"https://qa-static.{qa.DOMAIN}")
t.ok("the site was created", bool(site), site)
RID = site["id"]
r.goto(f"/sites/{RID}")
t.shot("site-basics-redirect", full=True)
t.site_config("qa-redir", "the config this site renders to")
res = r.apply("qa: redirect site")
t.ok("apply succeeded", res["status"] == 200, res)
t.config("after")

red = t.probe("GET / on the redirect site", hostname=f"qa-redir.{qa.DOMAIN}",
              path="/", ip=LB01, scheme="http")
t.ok("it answers 301", red["status"] == 301, red["status"])
t.ok("Location points at the target",
     red["headers"].get("Location", "").startswith(f"https://qa-static.{qa.DOMAIN}"),
     red["headers"].get("Location"))
deep = t.probe("GET a deep path on the redirect site",
               hostname=f"qa-redir.{qa.DOMAIN}", path="/some/deep/path?x=1",
               ip=LB01, scheme="http")
t.ok("the path is carried across",
     "/some/deep/path" in deep["headers"].get("Location", ""),
     deep["headers"].get("Location"))
t.close()

# ============================================================== SITE-03
t = r.test(
    "SITE-03", "Making a website",
    "A certificate, https, and the redirect from http",
    "Make a certificate from the Certificates page, attach it to a site, turn "
    "on 'Redirect http to https', and prove https serves with that certificate "
    "while http sends the browser to it.",
    "Nothing goes on the internet without this.  It is also where the classic "
    "mistake lives: turning on the redirect before the certificate exists, "
    "which leaves the site sending browsers to a port that has no server "
    "block behind it.",
    "https answers 200 with a certificate carrying the site's name, and http "
    "answers 301 to the https address.")

t.step("make a self signed certificate from the Certificates page")
r.goto("/certificates")
t.shot("certificates-before", full=True)
t.config("before")
made = r.api("POST", "/certs/self-signed",
             {"domains": [f"qa-tls.{qa.DOMAIN}"], "name": "qa-tls",
              "key_type": "ecdsa", "days": 30})
t.proof("POST /api/certs/self-signed", json.dumps(made["body"], indent=1)[:900])
t.ok("the certificate was created", made["status"] == 200, made)
CERT_ID = made["body"]["id"]
r.goto("/certificates")
t.shot("certificates-after", full=True)

t.step("create the site with that certificate and the http redirect on")
site = new_site("qa-tls", f"qa-tls.{qa.DOMAIN}", "proxy", pool=POOL_ID,
                cert=str(CERT_ID), force=True)
t.ok("the site was created", bool(site), site)
TID = site["id"]
r.goto(f"/sites/{TID}")
t.shot("site-basics-tls", full=True)
t.site_config("qa-tls", "the config this site renders to")
res = r.apply("qa: tls site")
t.ok("apply succeeded", res["status"] == 200, res)
t.config("after")

https = t.probe("GET / over https", hostname=f"qa-tls.{qa.DOMAIN}", path="/echo",
                ip=LB01, scheme="https")
t.ok("https answers 200", https["status"] == 200, https["status"])
pem = https.get("peer_cert_pem", "")
t.proof("the certificate nginx presented", pem[:900])
try:
    import subprocess
    names = subprocess.run(["openssl", "x509", "-noout", "-text"],
                           input=pem, capture_output=True, text=True).stdout
except Exception:
    names = ""
t.proof("what that certificate says", names[:1500] if names else "[openssl not available]")
t.ok("the certificate is the one for this site",
     f"qa-tls.{qa.DOMAIN}" in names or "qa-tls" in names, names[:300])

plain = t.probe("GET / over http on the same site", hostname=f"qa-tls.{qa.DOMAIN}",
                path="/anything", ip=LB01, scheme="http")
t.ok("http answers 301", plain["status"] == 301, plain["status"])
t.ok("it redirects to https on the same name",
     plain["headers"].get("Location", "").startswith(f"https://qa-tls.{qa.DOMAIN}"),
     plain["headers"].get("Location"))

t.step("check the acme challenge path is not swept into the redirect")
acme = t.probe("GET the acme challenge path over http",
               hostname=f"qa-tls.{qa.DOMAIN}",
               path="/.well-known/acme-challenge/probe", ip=LB01, scheme="http")
t.ok("the certificate challenge path is not redirected",
     acme["status"] != 301, f"{acme['status']} {acme['headers'].get('Location','')}")
t.close()

# ============================================================== SITE-04
t = r.test(
    "SITE-04", "Making a website",
    "HTTP/2",
    "Prove the http2 switch on the site decides whether a browser is offered "
    "HTTP/2, by looking at what TLS actually negotiates.",
    "HTTP/2 is most of the speed difference on a page with many assets. It is "
    "also the setting most often assumed to be on because the box was ticked "
    "once on a different site.",
    "With HTTP/2 on, the TLS handshake negotiates h2.  With it off, it "
    "negotiates http/1.1 and the site still works.")

r.goto(f"/sites/{TID}")
t.shot("http2-on", selector="#f-http2 >> xpath=ancestor::div[@class='checkline'][1]")
t.config("before")
on = qa.alpn_of(f"qa-tls.{qa.DOMAIN}", ip=LB01)
t.proof("the TLS handshake with http2 on", json.dumps(on, indent=1))
t.ok("h2 is negotiated when the box is ticked", on["negotiated"] == "h2", on)

t.step("untick HTTP/2 on the Basics tab and save")
r.goto(f"/sites/{TID}")
r.page.uncheck("#f-http2")
r.page.click("#save-site")
r.page.wait_for_timeout(1200)
r.goto(f"/sites/{TID}")
t.ok("the box reads back unticked after saving",
     not r.page.locator("#f-http2").is_checked(), "still ticked")
t.shot("http2-off", selector="#f-http2 >> xpath=ancestor::div[@class='checkline'][1]")
cfg = r.file_named("sites/qa-tls.conf")
t.proof("the config with http2 off", cfg[:1400])
t.ok("http2 on is gone from the config", "http2 on" not in cfg, cfg[:400])
r.apply("qa: http2 off")
t.config("after")
off = qa.alpn_of(f"qa-tls.{qa.DOMAIN}", ip=LB01)
t.proof("the TLS handshake with http2 off", json.dumps(off, indent=1))
t.ok("h2 is no longer offered when the box is clear",
     off["negotiated"] != "h2", off)
still = t.probe("the site over http/1.1 with http2 off",
                hostname=f"qa-tls.{qa.DOMAIN}", path="/echo", ip=LB01, scheme="https")
t.ok("the site still works over http/1.1", still["status"] == 200, still["status"])

t.step("turn it back on")
r.goto(f"/sites/{TID}")
r.page.check("#f-http2")
r.page.click("#save-site")
r.page.wait_for_timeout(1000)
r.apply("qa: http2 back on")
back = qa.alpn_of(f"qa-tls.{qa.DOMAIN}", ip=LB01)
t.proof("the TLS handshake once http2 is back on", json.dumps(back, indent=1))
t.ok("h2 comes back", back["negotiated"] == "h2", back)
t.close()

# ============================================================== SITE-05
t = r.test(
    "SITE-05", "Making a website",
    "More than one name on a site, and the canonical redirect",
    "Give the site a second name, prove both answer, then turn on the "
    "canonical redirect and prove the second name sends browsers to the first.",
    "Every site is reached by at least two names, with and without www.  "
    "Serving the same content on both splits search ranking and breaks "
    "cookies; redirecting one to the other is the fix.",
    "Both names answer while the redirect is off.  With it on, the extra name "
    "answers 301 to the first name and the first name still serves.")

r.goto(f"/sites/{TID}")
t.config("before")
t.shot("names-before")
t.step("add a second server name on the Basics tab")
r.page.fill("#f-names", f"qa-tls.{qa.DOMAIN} www.qa-tls.{qa.DOMAIN}")
r.page.click("#save-site")
r.page.wait_for_timeout(1200)
r.goto(f"/sites/{TID}")
t.ok("both names read back after saving",
     f"www.qa-tls.{qa.DOMAIN}" in r.page.locator("#f-names").input_value(),
     r.page.locator("#f-names").input_value())
t.shot("names-after")
cfg = r.file_named("sites/qa-tls.conf")
t.proof("the server_name line", "\n".join(
    l for l in cfg.splitlines() if "server_name" in l))
r.apply("qa: second name")
t.config("after")

first = t.probe("the first name", hostname=f"qa-tls.{qa.DOMAIN}", path="/echo",
                ip=LB01, scheme="https")
second = t.probe("the second name", hostname=f"www.qa-tls.{qa.DOMAIN}",
                 path="/echo", ip=LB01, scheme="https")
t.ok("the first name serves", first["status"] == 200, first["status"])
t.ok("the second name serves the same site too",
     second["status"] == 200, second["status"])

t.step("turn on the canonical redirect and save")
r.goto(f"/sites/{TID}")
if r.page.locator("#f-canonical").count():
    r.page.select_option("#f-canonical", "primary")
    r.page.click("#save-site")
    r.page.wait_for_timeout(1200)
    r.goto(f"/sites/{TID}")
    t.ok("the canonical choice reads back as 'Send the rest to the first one'",
         r.page.locator("#f-canonical").input_value() == "primary",
         r.page.locator("#f-canonical").input_value())
    t.shot("canonical-on")
    cfg = r.file_named("sites/qa-tls.conf")
    t.proof("the config with the canonical redirect on", cfg[:1800])
    r.apply("qa: canonical")
    canon = t.probe("the second name with the canonical redirect on",
                    hostname=f"www.qa-tls.{qa.DOMAIN}", path="/a/path",
                    ip=LB01, scheme="https")
    t.ok("the extra name redirects to the first",
         canon["status"] in (301, 302)
         and f"//qa-tls.{qa.DOMAIN}" in canon["headers"].get("Location", ""),
         f"{canon['status']} {canon['headers'].get('Location')}")
    still = t.probe("the first name is still served, not redirected to itself",
                    hostname=f"qa-tls.{qa.DOMAIN}", path="/echo", ip=LB01,
                    scheme="https")
    t.ok("the first name does not redirect to itself", still["status"] == 200,
         still["status"])
    r.goto(f"/sites/{TID}")
    r.page.select_option("#f-canonical", "both")
    r.page.click("#save-site")
    r.page.wait_for_timeout(1000)
    r.apply("qa: canonical off")
else:
    t.ok("the canonical redirect control exists on the page", False,
         "#f-canonical not found")
t.close()

# ============================================================== SITE-06
t = r.test(
    "SITE-06", "Making a website",
    "Switching a site off",
    "Untick Enabled, apply, and prove the site stops answering, along with "
    "what a visitor sees instead.",
    "Taking a site down for maintenance, or parking one that is not ready, "
    "has to be one action that cannot be forgotten about.  Where the traffic "
    "goes instead is the part that surprises people.",
    "The site is no longer in the config, and a request for its name lands on "
    "whichever site is the default server rather than being refused.")

r.goto(f"/sites/{SID}")
t.config("before")
t.shot("enabled-before", selector="#f-enabled >> xpath=ancestor::div[@class='checkline'][1]")
before = t.probe("the static site while it is switched on",
                 hostname=f"qa-static.{qa.DOMAIN}", path="/", ip=LB01, scheme="http")
t.ok("it serves while enabled", before["status"] == 200
     and "QA static site" in before["body"], before["status"])

t.site_config("qa-static", "the config file while the site is switched on")
t.step("untick Enabled and save")
r.page.uncheck("#f-enabled")
r.page.click("#save-site")
r.page.wait_for_timeout(1200)
r.goto(f"/sites/{SID}")
t.ok("the box reads back unticked", not r.page.locator("#f-enabled").is_checked(),
     "still ticked")
t.shot("enabled-after", full=True)
gone = r.file_named("sites/qa-static.conf")
t.proof("the site's config file once it is switched off",
        gone or "[the file is no longer rendered at all]")
t.ok("a disabled site is not written into the config", not gone, gone[:200])
r.apply("qa: site off")
t.config("after")

after = t.probe("the same request once the site is off",
                hostname=f"qa-static.{qa.DOMAIN}", path="/", ip=LB01, scheme="http")
t.ok("it no longer serves its own content",
     "QA static site" not in after["body"], after["body"][:200])
t.note(f"a visitor now gets {after['status']} from whichever site is the "
       f"default server, which is the documented behaviour")

t.step("switch it back on")
r.goto(f"/sites/{SID}")
r.page.check("#f-enabled")
r.page.click("#save-site")
r.page.wait_for_timeout(1000)
r.apply("qa: site back on")
back = t.probe("the site once it is switched back on",
               hostname=f"qa-static.{qa.DOMAIN}", path="/", ip=LB01, scheme="http")
t.ok("it serves again", back["status"] == 200 and "QA static site" in back["body"],
     back["status"])
t.close()

r.stop()
print("\nT03 DONE")
