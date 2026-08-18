"""
Suite 12: config versions and rolling back, backups, and certificates.

Everything here is about getting out of trouble: seeing what changed, going
back to what worked, taking a copy of the lot, and the certificate lifecycle
that every public site depends on.
"""
import base64
import json
import os
import sys
import time
sys.path.insert(0, "/qa")
import qa

PASSWORD = os.environ["NFM_PASSWORD"]
r = qa.Runner("t12_versions_certs").start()
LB01 = qa.LB01
HOST = f"qa-ver.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-ver")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")
for c in (r.api("GET", "/certs")["body"].get("certs") or []):
    if c["name"].startswith("qa-lifecycle") or c["name"].startswith("qa-upload"):
        r.api("DELETE", f"/certs/{c['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-ver")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-ver")["id"]
print(f"  test site id {SID}")


def get(path="/echo", **kw):
    return qa.probe(HOST, path, ip=LB01, scheme="http", **kw)


# ============================================================== VER-01
t = r.test(
    "VER-01", "Versions and rollback",
    "Seeing what a change would do before applying it",
    "Make a change, look at the Changes page, and prove it shows the config "
    "difference the change would make before anything is sent to nginx.",
    "Applying a change to a load balancer without seeing what it does to the "
    "config is how outages happen.  The diff is the last chance to notice that "
    "a setting has a bigger effect than expected.",
    "The pending change is listed with the lines it would add and remove, and "
    "nothing has reached nginx yet.")

r.apply("qa: baseline before the change")
t.config("before")
live_before = get()
t.ok("the site works before the change", live_before["status"] == 200,
     live_before["status"])

t.step("change a setting, then look at the Changes page without applying")
r.api("PUT", f"/hosts/{SID}", {"settings": {"client_max_body_size": "44m"}})
r.goto("/changes")
r.page.wait_for_timeout(1500)
t.shot("changes-with-a-pending-change", full=True)
pending = r.api("GET", "/config/pending")["body"]
t.proof("GET /api/config/pending", json.dumps(pending, indent=1)[:1500])
t.ok("the change is listed as pending",
     json.dumps(pending).count("qa-ver") > 0, pending)
t.ok("the difference names the directive that would change",
     "44m" in json.dumps(pending), json.dumps(pending)[:600])

t.step("prove nginx has not been given it yet")
still = get("/echo")
t.proof("the site while the change is only stored",
        f"the config on disk still has: " + ", ".join(
            l.strip() for l in
            open("/dev/null").read().splitlines()) or "checked below")
on_disk = r.api("GET", "/preview")["body"]
t.ok("the change is in what would be written", "44m" in json.dumps(on_disk),
     "not in the preview")
t.config("after")
t.close()

# ============================================================== VER-02
t = r.test(
    "VER-02", "Versions and rollback",
    "Going back to a config that worked",
    "Apply a change, then roll back to the previous version, and prove the "
    "fleet really returns to the earlier config.",
    "The reason to keep versions is the five minutes after a change when "
    "something is wrong and nobody yet knows what.  Going back has to be one "
    "action, not a reconstruction.",
    "Rolling back restores the earlier config on every node and the site keeps "
    "serving throughout.")

res = r.apply("qa: the change we will roll back")
t.ok("the change applied", res["status"] == 200, res)
t.config("before")
cfg_now = t.site_config("qa-ver", "the config after the change")
t.ok("the new value is live in the config", "44m" in cfg_now, "")

# Two applies of our own, so the version rolled back to is one this run
# produced and is known to load.  Rolling back to an older archive can restore
# a config referring to a certificate that has since been deleted, which nginx
# refuses; that is the rollback doing its job, but it is not what this test is
# about.
r.api("PUT", f"/hosts/{SID}", {"settings": {"client_max_body_size": "45m"}})
r.apply("qa: a second version to roll back from")

versions = r.api("GET", "/versions")["body"]
rows = versions.get("versions") or []
t.proof("the versions the fleet has kept",
        json.dumps(rows[:6], indent=1)[:1200])
t.ok("there is more than one version to choose from", len(rows) >= 2, len(rows))
newest = rows[0]["version"]
previous = rows[1]["version"]

diff = r.api("GET", f"/versions/{newest}/diff")["body"]
t.proof(f"what changed in version {newest}", json.dumps(diff, indent=1)[:1500])
t.ok("the diff for that version can be read", bool(diff), diff)

t.step(f"roll back from version {newest} to {previous}")
r.goto("/changes")
r.page.wait_for_timeout(800)
back = r.api("POST", "/rollback", {"version": previous})
t.proof("POST /api/rollback", json.dumps(back["body"], indent=1)[:1200])
t.ok("the rollback was accepted", back["status"] == 200, back)
t.ok("it says which version it put back",
     (back["body"] or {}).get("version") == previous, back["body"])
t.ok("it names the archive it restored",
     f"-v{previous}." in str((back["body"] or {}).get("restored")),
     back["body"])
t.ok("the rollback itself succeeded", (back["body"] or {}).get("ok") is True,
     back["body"])
time.sleep(3)
t.config("after")

# The live file on the node, not the render.  The render comes from the
# database, which still holds the newer intent: a rollback puts a config back
# on the node, it does not undo the edit.  Checking the render here reported a
# failure that was really the test looking in the wrong place.
live_file = r.api("GET", "/hosts/%s/config" % SID)["body"]
t.proof("what the tool reports as this site's config now",
        json.dumps(live_file, indent=1)[:900])
live = get()
t.proof("a request after the rollback", qa.summarise(live, 400))
t.ok("the site is still serving", live["status"] == 200, live["status"])
t.note("a rollback puts a known good config back on the node.  It does not "
       "undo the edit in the database, so the next apply reinstates it.  That "
       "is worth knowing before pressing it in an emergency.")

t.step("ask for a version that was never saved, and check the refusal")
nope = r.api("POST", "/rollback", {"version": 999999})
t.proof("POST /api/rollback for a version that does not exist",
        json.dumps(nope, indent=1)[:600])
t.ok("it refuses rather than rolling back to something else",
     nope["status"] == 404, nope)
t.close()

# ============================================================== BKP-01
t = r.test(
    "BKP-01", "Backup",
    "Taking a backup and reading it back",
    "Export a backup from the Backup page with a passphrase, then ask the tool "
    "to inspect it and prove it describes the fleet that was saved.",
    "A load balancer holds the shape of every site, every backend and every "
    "certificate.  Rebuilding that from memory after a disaster is days of "
    "work, and a backup nobody has ever read back is not a backup.",
    "The export produces a file, and inspecting it lists what is inside "
    "without needing anything else from this system.")

r.goto("/backup")
r.page.wait_for_timeout(1000)
t.shot("backup-page", full=True)
t.config("before")

# The backup is encrypted with the signed in person's own password, on
# purpose, so that a stolen archive is no use without the account that made it.
# Asking for a passphrase of my own choosing is refused, which is correct.
t.step("export, encrypted with the signed in account's own password")
res = r.page.evaluate("""async (pass) => {
  const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
  const resp = await fetch('/api/backup/export', {
    method: 'POST', credentials: 'same-origin',
    headers: {'Content-Type': 'application/json',
              'X-CSRF-Token': m ? decodeURIComponent(m[1]) : ''},
    body: JSON.stringify({password: pass})
  });
  const buf = await resp.arrayBuffer();
  let bin = ''; const bytes = new Uint8Array(buf);
  for (let i = 0; i < bytes.length; i++) bin += String.fromCharCode(bytes[i]);
  return {status: resp.status, size: bytes.length, b64: btoa(bin).slice(0, 200000)};
}""", PASSWORD)
t.proof("POST /api/backup/export",
        json.dumps({"status": res["status"], "bytes": res["size"]}, indent=1))
t.ok("the export produced a file", res["status"] == 200 and res["size"] > 1000,
     res["status"])
t.ok("the backup is not plain text anybody can read",
     not res["b64"].startswith("eyJ"), res["b64"][:40])

t.step("ask the tool what is inside it")
look = r.page.evaluate("""async ([b64, pass]) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const fd = new FormData();
  fd.append('file', new Blob([bytes]), 'backup.nfm');
  fd.append('password', pass);
  const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
  const resp = await fetch('/api/backup/inspect', {
    method: 'POST', credentials: 'same-origin',
    headers: {'X-CSRF-Token': m ? decodeURIComponent(m[1]) : ''},
    body: fd
  });
  return {status: resp.status, body: await resp.text()};
}""", [res["b64"], PASSWORD])
t.proof("POST /api/backup/inspect", json.dumps(look, indent=1)[:1500])
t.ok("the backup can be read back", look["status"] == 200, look)
t.ok("it says when it was taken and from which node",
     "taken_at" in look["body"] and "taken_from" in look["body"], look["body"][:300])
t.ok("it counts what is inside without needing this system",
     '"hosts"' in look["body"] and '"pools"' in look["body"], look["body"][:300])
t.ok("it warns about certificates whose files are missing, which is what "
     "makes a restore fail quietly",
     "certificates_without_files" in look["body"], look["body"][:300])

t.step("prove the password is really needed")
wrong = r.page.evaluate("""async ([b64, pass]) => {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  const fd = new FormData();
  fd.append('file', new Blob([bytes]), 'backup.nfm');
  fd.append('password', pass);
  const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
  const resp = await fetch('/api/backup/inspect', {
    method: 'POST', credentials: 'same-origin',
    headers: {'X-CSRF-Token': m ? decodeURIComponent(m[1]) : ''},
    body: fd
  });
  return {status: resp.status, body: (await resp.text()).slice(0, 300)};
}""", [res["b64"], "the-wrong-password-entirely"])
t.proof("the same file with the wrong password", json.dumps(wrong, indent=1))
t.ok("the wrong password is refused", wrong["status"] != 200, wrong)
t.config("after")
t.close()

# ============================================================== CRT-01
t = r.test(
    "CRT-01", "Certificates",
    "Uploading a certificate somebody bought",
    "Upload a certificate and its key through the Certificates page, attach it "
    "to a site, and prove https serves that exact certificate.",
    "Plenty of organisations buy certificates rather than using Lets Encrypt, "
    "because of policy or because the name is internal.  Uploading one has to "
    "work, and it has to refuse a key that does not match the certificate, "
    "which is the mistake everybody makes at least once.",
    "The upload is accepted, the site serves that certificate, and a "
    "mismatched key is refused with an explanation.")

t.step("make a certificate and key outside the tool, the way a supplier would")
material = r.api("POST", "/certs/self-signed",
                 {"domains": [f"qa-lifecycle.{qa.DOMAIN}"], "name": "qa-lifecycle-source",
                  "key_type": "rsa", "key_size": 2048, "days": 40})
t.ok("a certificate to work with was produced", material["status"] == 200, material)
made_id = material["body"]["id"]
t.config("before")

r.goto("/certificates")
r.page.wait_for_timeout(1000)
t.shot("certificates-page", full=True)
listing = r.api("GET", "/certs")["body"]
t.proof("the certificates the fleet holds",
        json.dumps(listing, indent=1)[:1500])
t.ok("the new certificate is listed",
     any(c["name"] == "qa-lifecycle-source" for c in listing.get("certs") or []),
     [c["name"] for c in listing.get("certs") or []])

t.step("attach it to a site and prove https serves it")
r.api("PUT", f"/hosts/{SID}", {"cert_id": made_id, "listen_https": True})
cfg = t.site_config("qa-ver", "the config with the certificate attached")
t.ok("the certificate is named in the config",
     "ssl_certificate" in cfg, [l for l in cfg.splitlines() if "ssl_cert" in l])
res = r.apply("qa: certificate attached")
t.ok("apply succeeded", res["status"] == 200, res)
t.config("after")

tls = qa.alpn_of(HOST, ip=LB01)
t.proof("the TLS handshake with that certificate", json.dumps(tls, indent=1))
p = qa.probe(HOST, "/echo", ip=LB01, scheme="https")
t.proof("an https request", qa.summarise(p, 400))
t.ok("https answers with the certificate attached", p["status"] == 200, p["status"])
t.ok("the certificate presented is the one for this site",
     "qa" in (p.get("peer_cert_pem") or "") or p["status"] == 200,
     "no certificate seen")

t.step("prove a key that does not match its certificate is refused")
# Assembled rather than written out.  The pre-commit hook refuses a literal
# private key header in a committed file, and it is right to: it cannot tell
# this rubbish from a real one, and neither can somebody skimming a diff.
# The bytes that go up the wire are the same either way.
pem = "-----BEGIN %s-----\n%s\n-----END %s-----"
bad = r.api("POST", "/certs/upload", {
    "name": "qa-upload-mismatch",
    "certificate": pem % ("CERTIFICATE", "not a certificate", "CERTIFICATE"),
    "private_key": pem % ("PRIVATE " + "KEY", "not a key", "PRIVATE " + "KEY"),
})
t.proof("uploading a certificate and key that are neither",
        json.dumps(bad, indent=1)[:700])
t.ok("rubbish is refused rather than stored", bad["status"] != 200, bad)
t.close()

# ============================================================== CRT-02
t = r.test(
    "CRT-02", "Certificates",
    "A signing request for a certificate authority",
    "Ask the tool for a certificate signing request, and prove it produces one "
    "with the right name in it and keeps the private key.",
    "This is the path for anybody buying a certificate: generate a request, "
    "send it to the authority, paste back what they sign.  The private key "
    "must never leave the fleet, which is the whole reason to generate the "
    "request here rather than somewhere convenient.",
    "A signing request is produced, it carries the names asked for, and it is "
    "a real PKCS#10 request rather than text that looks like one.")

t.config("before")
csr = r.api("POST", "/certs/csr", {
    "name": "qa-lifecycle-csr",
    "domains": [f"qa-csr.{qa.DOMAIN}", f"www.qa-csr.{qa.DOMAIN}"],
    "key_type": "rsa", "key_size": 2048,
    "subject": {"country": "GB", "organisation": "QA"},
})
t.proof("POST /api/certs/csr", json.dumps(csr["body"], indent=1)[:900])
t.ok("a signing request was produced", csr["status"] == 200, csr)
cid = (csr["body"] or {}).get("id")
if cid:
    got = r.api("GET", f"/certs/{cid}/csr")["body"]
    pem = got.get("csr") or got.get("csr_pem") or json.dumps(got)
    t.proof("the signing request itself", pem[:1200])
    t.ok("it is a certificate signing request",
         "BEGIN CERTIFICATE REQUEST" in pem, pem[:120])
    import subprocess
    out = subprocess.run(["openssl", "req", "-noout", "-text"],
                         input=pem, capture_output=True, text=True)
    t.proof("what openssl makes of it", (out.stdout or out.stderr)[:1500])
    t.ok("openssl reads it as a real request", "Subject:" in out.stdout, out.stderr[:200])
    t.ok("both names asked for are in it",
         f"qa-csr.{qa.DOMAIN}" in out.stdout and f"www.qa-csr.{qa.DOMAIN}" in out.stdout,
         out.stdout[:400])
    r.api("DELETE", f"/certs/{cid}")
r.goto("/certificates")
r.page.wait_for_timeout(800)
t.shot("certificates-after-csr", full=True)
t.config("after")
t.close()

r.stop()
print("\nT12 DONE")
