"""
Drive the real GUI in a real browser and write down what happened.

Every test here signs in as an ordinary admin, clicks the same buttons a person
clicks, applies config for real, and then puts real traffic through nginx to
see whether the thing the page promised actually happened.

Nothing here reads the database to decide whether a test passed.  The database
agreeing with itself is not evidence.  The evidence is a request going in one
end and the right bytes coming out the other.

Each test records: what it is for, the use case, the config before, the config
after, what was expected, and what was observed.  report.py turns that into the
document.
"""
import base64
import datetime
import hashlib
import hmac
import http.client
import ipaddress
import json
import os
import pathlib
import socket
import ssl
import struct
import subprocess
import sys
import time
import traceback

from playwright.sync_api import sync_playwright

BASE = os.environ.get("NFM_URL", "https://127.0.0.1:7443")
USER = os.environ.get("NFM_USER", "qa-runner")
PASSWORD = os.environ["NFM_PASSWORD"]
SECRET = os.environ["NFM_TOTP"]

# Where the fleet is, and what to call the sites these tests make.
#
# All of it comes from the environment, because a test suite that hardcodes
# somebody's lab addressing is a suite that only ever runs on that lab, and
# because the addresses of the machines this was written against are nobody
# else's business.
#
#   QA_LB01          the node whose GUI is driven and whose nginx is measured
#   QA_LB02          the other node, blank when there is only one
#   QA_BACKEND_HOST  where the echo backends listen, reachable from both nodes
#   QA_DOMAIN        the parent name for the sites the tests create
LB01 = os.environ.get("QA_LB01", "127.0.0.1")
LB02 = os.environ.get("QA_LB02", "")
BACKEND_HOST = os.environ.get("QA_BACKEND_HOST", LB01)
DOMAIN = os.environ.get("QA_DOMAIN", "qa.example.invalid")

# A directory of files on every node, for the tests that serve off disk.
# It has to exist on each node before those run; the README says how.
STATIC_DIR = os.environ.get("QA_STATIC_DIR", "/var/www/qa-static")

NODE_IP = os.environ.get("QA_NODE_IP", LB01)

ROOT = pathlib.Path("/qa/evidence")
ROOT.mkdir(parents=True, exist_ok=True)


def totp(secret):
    key = base64.b32decode(secret + "=" * (-len(secret) % 8))
    digest = hmac.new(key, struct.pack(">Q", int(time.time()) // 30),
                      hashlib.sha1).digest()
    off = digest[-1] & 0x0F
    code = struct.unpack(">I", digest[off:off + 4])[0] & 0x7FFFFFFF
    return f"{code % 1000000:06d}"


# ---------------------------------------------------------------- raw traffic

def probe(hostname, path="/", ip=None, scheme="https", port=None,
          method="GET", headers=None, body=None, timeout=15,
          follow=False, alpn=None, source=None):
    """
    One request straight at a node, with the Host header and SNI we choose.

    Deliberately not urllib: this has to see the exact status line and the exact
    headers, must not follow a redirect unless asked, and must be able to ask
    for a name the DNS does not point here.  A redirect followed silently is how
    a check goes green against a sign in page.

    `source` picks which of this box's addresses the connection goes out from,
    which is the only way to test a rule that decides on where somebody is
    coming from.  Every address this harness normally has is inside the fleet's
    own management networks, so without it there is no way to be an outsider
    and the refusal half of every management rule goes untested.
    """
    ip = ip or NODE_IP
    port = port or (443 if scheme == "https" else 80)
    headers = dict(headers or {})
    headers.setdefault("Host", hostname)
    headers.setdefault("User-Agent", "failover-lb-qa/1.0")
    headers.setdefault("Connection", "close")

    sock = socket.create_connection((ip, port), timeout,
                                    source_address=(source, 0) if source else None)
    negotiated = None
    if scheme == "https":
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        if alpn:
            ctx.set_alpn_protocols(alpn)
        sock = ctx.wrap_socket(sock, server_hostname=hostname)
        negotiated = sock.selected_alpn_protocol()
        peercert = sock.getpeercert(binary_form=True)
        conn = http.client.HTTPSConnection(hostname, port, timeout=timeout)
    else:
        peercert = None
        conn = http.client.HTTPConnection(hostname, port, timeout=timeout)
    conn.sock = sock

    try:
        conn.request(method, path, body=body, headers=headers)
        resp = conn.getresponse()
        raw = resp.read()
    finally:
        try:
            conn.close()
        except Exception:
            pass

    out = {
        "request": (f"{method} {path} HTTP/1.1  ->  {scheme}://{ip}:{port}  "
                    f"Host: {hostname}"
                    + (f"  from {source}" if source else "")),
        "request_headers": headers,
        "status": resp.status,
        "reason": resp.reason,
        "headers": {k: v for k, v in resp.getheaders()},
        "body": raw.decode("utf-8", "replace"),
        "length": len(raw),
        "alpn": negotiated,
    }
    if peercert:
        try:
            import ssl as _ssl
            out["peer_cert_pem"] = _ssl.DER_cert_to_PEM_cert(peercert)
        except Exception:
            pass

    if follow and resp.status in (301, 302, 303, 307, 308):
        loc = out["headers"].get("Location", "")
        out["followed"] = loc
    return out


def alpn_of(hostname, ip=None, port=443, protocols=("h2", "http/1.1"), timeout=10):
    """
    What the TLS handshake agrees to speak, and nothing more.

    Deliberately stops at the handshake.  An earlier version asked for h2 and
    then sent an HTTP/1.1 request down the connection, which nginx correctly
    refused, and the test died instead of reporting the protocol it had already
    successfully negotiated.
    """
    ip = ip or NODE_IP
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.set_alpn_protocols(list(protocols))
    with socket.create_connection((ip, port), timeout) as raw:
        with ctx.wrap_socket(raw, server_hostname=hostname) as tls:
            return {
                "offered": list(protocols),
                "negotiated": tls.selected_alpn_protocol(),
                "tls_version": tls.version(),
                "cipher": tls.cipher()[0] if tls.cipher() else None,
            }


def probe_allowing_refusal(*a, **kw):
    """
    A probe where "nothing is listening" is a valid answer.

    Used after deleting a site or closing a port, where a refused connection is
    the result the test is looking for.  Letting the exception escape turns the
    expected outcome into a crash.
    """
    try:
        return probe(*a, **kw)
    except (ConnectionRefusedError, socket.timeout, OSError) as exc:
        return {"request": f"{kw.get('scheme', 'https')}://{kw.get('ip', NODE_IP)}"
                           f":{kw.get('port', '')}{a[1] if len(a) > 1 else kw.get('path', '/')}",
                "request_headers": {}, "status": 0,
                "reason": f"connection refused ({exc.__class__.__name__})",
                "headers": {}, "body": "", "length": 0, "alpn": None}


def dns_query(name, ip, port=5353, qtype=1, timeout=5):
    """
    One real DNS question, asked over UDP, parsed by hand.

    Written out rather than pulled from a library so the test depends on
    nothing but the socket, and so the raw bytes can go in the report.  qtype 1
    is A, 2 is NS, 6 is SOA.
    """
    import struct as _struct
    qname = b"".join(bytes([len(part)]) + part.encode()
                     for part in name.rstrip(".").split(".")) + b"\x00"
    txid = 0x4a21
    header = _struct.pack(">HHHHHH", txid, 0x0100, 1, 0, 0, 0)
    packet = header + qname + _struct.pack(">HH", qtype, 1)

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(timeout)
    try:
        sock.sendto(packet, (ip, port))
        data, _ = sock.recvfrom(4096)
    except socket.timeout:
        return {"asked": name, "server": f"{ip}:{port}", "error": "no answer",
                "rcode": None, "answers": [], "raw": ""}
    finally:
        sock.close()

    rcode = data[3] & 0x0F
    counts = _struct.unpack(">HHHH", data[4:12])
    pos = 12
    # step over the question
    while data[pos] != 0:
        if data[pos] & 0xC0:
            pos += 1
            break
        pos += data[pos] + 1
    pos += 5

    answers = []
    for _ in range(counts[1]):
        if pos >= len(data):
            break
        if data[pos] & 0xC0:
            pos += 2
        else:
            while pos < len(data) and data[pos] != 0:
                pos += data[pos] + 1
            pos += 1
        if pos + 10 > len(data):
            break
        rtype, _cls, ttl, length = _struct.unpack(">HHIH", data[pos:pos + 10])
        pos += 10
        body = data[pos:pos + length]
        pos += length
        if rtype == 1 and length == 4:
            answers.append({"type": "A", "ttl": ttl,
                            "value": ".".join(str(b) for b in body)})
        else:
            answers.append({"type": rtype, "ttl": ttl,
                            "value": body.hex()})

    return {
        "asked": name,
        "server": f"{ip}:{port}",
        "rcode": {0: "NOERROR", 1: "FORMERR", 2: "SERVFAIL", 3: "NXDOMAIN",
                  5: "REFUSED"}.get(rcode, rcode),
        "answer_count": counts[1],
        "answers": answers,
        "raw": data.hex(),
    }


def covered_by(address, rules):
    """
    Would any allow line in this config let that address through.

    Asked of the config the product itself rendered, rather than of a list
    written down in a test.  A test that refuses an address has to know the
    address was not on the list, or the refusal proves nothing, and the list is
    generated from the node roster so it is not something a test can predict.
    """
    who = ipaddress.ip_address(address)
    for line in rules.splitlines():
        word = line.strip()
        if not word.startswith("allow "):
            continue
        target = word[6:].rstrip(";").strip()
        if target == "all":
            return True
        try:
            if who in ipaddress.ip_network(target, strict=False):
                return True
        except ValueError:
            continue
    return False


def server_rules(cfg):
    """
    Only the access control lines that apply to the whole server.

    Searching a whole config file is how a check passes for the wrong reason,
    and it did twice in the access list round.  Every site config already
    carries `deny all;` inside the block that hides dotfiles, so "the site
    denies everything" was true of a site that denied nobody.  The certificate
    challenge and the internal error page both say `allow all;`, so "the site
    allows nothing" was false of a site that allowed nothing.

    Server level lines sit at exactly four spaces of indent and a location's at
    eight, which is the only thing that tells them apart in a rendered file.
    """
    keep = ("allow ", "deny ", "auth_basic", "set_real_ip_from",
            "real_ip_header", "real_ip_recursive")
    return "\n".join(
        line for line in cfg.splitlines()
        if line.startswith("    ") and not line.startswith("     ")
        and line.strip().startswith(keep)
    )


def summarise(p, body_chars=400):
    """A probe rendered the way it would be read in a terminal."""
    lines = [p["request"], "", f"HTTP/1.1 {p['status']} {p['reason']}"]
    for k in sorted(p["headers"]):
        lines.append(f"{k}: {p['headers'][k]}")
    body = p["body"]
    if body:
        lines.append("")
        lines.append(body[:body_chars] + ("\n... [truncated]" if len(body) > body_chars else ""))
    return "\n".join(lines)


# ------------------------------------------------------------------ the runner

class Test:
    """One feature, with everything the document needs about it."""

    def __init__(self, runner, tid, area, feature, purpose, use_case, expected):
        self.r = runner
        self.id = tid
        self.rec = {
            "id": tid,
            "area": area,
            "feature": feature,
            "purpose": purpose,
            "use_case": use_case,
            "expected": expected,
            "steps": [],
            "shots": [],
            "proof": [],
            "config_before": None,
            "config_after": None,
            "observed": [],
            "verdict": "pass",
            "failures": [],
            "started": datetime.datetime.now().isoformat(timespec="seconds"),
        }

    # ---- narration
    def step(self, text):
        self.rec["steps"].append(text)
        print(f"      . {text}", flush=True)
        return self

    def note(self, text):
        self.rec["observed"].append(text)
        return self

    # ---- evidence
    def shot(self, label, selector=None, full=False):
        name = f"{self.id}-{len(self.rec['shots']):02d}-{label}".replace(" ", "-").lower()
        path = self.r.shots / f"{name}.png"
        try:
            if selector:
                self.r.page.locator(selector).first.screenshot(path=str(path))
            else:
                self.r.page.screenshot(path=str(path), full_page=full)
            self.rec["shots"].append({"label": label, "file": path.name})
        except Exception as exc:
            self.rec["shots"].append({"label": label, "file": None, "error": str(exc)})
        return self

    def config(self, when):
        """Freeze the config the fleet would be given right now."""
        text = self.r.rendered_config()
        self.rec[f"config_{when}"] = text
        return text

    def site_config(self, site_name, title, must_exist=True):
        """
        One site's rendered config file, recorded as proof.

        The file is named after the site's **name**, not its server name, and
        getting that wrong is how a check goes green against an empty string:
        "a disabled site is not in the config" passed here for a while because
        the filename never existed in the first place.  So this asserts the
        file is there unless the test says it should not be.
        """
        text = self.r.file_named(f"sites/{site_name}.conf")
        self.proof(title, text or f"[there is no sites/{site_name}.conf]")
        if must_exist:
            self.ok(f"the config file for {site_name} exists", bool(text),
                    "no such file in the rendered config")
        return text

    def proof(self, title, text, kind="text"):
        self.rec["proof"].append({"title": title, "kind": kind, "text": text})
        print(f"      + proof: {title}", flush=True)
        return self

    def probe(self, title, **kw):
        p = probe(**kw)
        self.proof(title, summarise(p))
        return p

    # ---- verdicts
    def ok(self, claim, condition, detail=""):
        good = bool(condition)
        self.rec["observed"].append(
            {"claim": claim, "result": "pass" if good else "FAIL", "detail": str(detail)[:2000]})
        if not good:
            self.rec["verdict"] = "fail"
            self.rec["failures"].append(f"{claim}  --  {detail}")
        print(f"      {'pass' if good else 'FAIL'}  {claim}"
              + (f"\n            {str(detail)[:300]}" if not good else ""), flush=True)
        return good

    def defect(self, title, detail, severity="medium"):
        self.rec["verdict"] = "fail"
        self.rec.setdefault("defects", []).append(
            {"title": title, "detail": detail, "severity": severity})
        print(f"      DEFECT [{severity}] {title}", flush=True)
        return self

    def close(self):
        self.rec["finished"] = datetime.datetime.now().isoformat(timespec="seconds")
        self.r.write(self.rec)


class Runner:
    def __init__(self, suite):
        self.suite = suite
        self.dir = ROOT
        self.shots = self.dir / "shots"
        self.shots.mkdir(parents=True, exist_ok=True)
        self.logfile = self.dir / f"{suite}.jsonl"
        self.pw = None
        self.browser = None
        self.page = None

    def write(self, rec):
        with self.logfile.open("a") as fh:
            fh.write(json.dumps(rec) + "\n")

    # ---- browser
    STATE = pathlib.Path("/qa/session.json")

    def start(self):
        self.pw = sync_playwright().start()
        self.browser = self.pw.chromium.launch(
            executable_path=os.environ.get("NFM_CHROMIUM", "/usr/bin/chromium"),
            args=["--no-sandbox", "--disable-dev-shm-usage"])
        # Reuse the last run's cookies when they are still good.
        #
        # Signing in on every suite ran the tool's own login rate limiter into
        # the ground, which is the limiter doing its job: ten attempts in five
        # minutes and then 429.  A suite that cannot start because the product
        # correctly refused it is a bad harness, not a finding.
        opts = dict(ignore_https_errors=True,
                    viewport={"width": 1500, "height": 1100},
                    device_scale_factor=1)
        if self.STATE.exists():
            opts["storage_state"] = str(self.STATE)
        self.ctx = self.browser.new_context(**opts)
        self.ctx.set_default_timeout(30000)
        self.js_errors = []
        self.page = self.ctx.new_page()
        self.page.on("pageerror", lambda e: self.js_errors.append(str(e)))

        self.page.goto(BASE + "/", wait_until="networkidle")
        if "/login" in self.page.url:
            self.sign_in()
            self.ctx.storage_state(path=str(self.STATE))
        else:
            print(f"    reused the signed in session, landed on {self.page.url}",
                  flush=True)
        return self

    def stop(self):
        try:
            self.ctx.close(); self.browser.close(); self.pw.stop()
        except Exception:
            pass

    def sign_in(self):
        p = self.page
        p.goto(BASE + "/login", wait_until="networkidle")
        p.fill("input[name=username]", USER)
        p.fill("input[name=password]", PASSWORD)
        p.click("button[type=submit]")
        p.wait_for_load_state("networkidle")
        if p.locator("input[name=totp]").count():
            p.fill("input[name=totp]", totp(SECRET))
            p.click("button[type=submit]")
            p.wait_for_load_state("networkidle")
        if "/login" in p.url:
            raise SystemExit(f"could not sign in: {p.url}\n{p.content()[:800]}")
        print(f"    signed in as {USER}, landed on {p.url}", flush=True)

    def goto(self, path, wait="networkidle"):
        self.page.goto(BASE + path, wait_until=wait)
        self.page.wait_for_timeout(400)
        return self.page

    # ---- talking to the API the way the pages do, through the browser
    def api(self, method, path, payload=None):
        """
        A fetch from inside the signed in page, so it carries the real session
        cookie and the real CSRF token.  This is what the pages themselves do.
        """
        js = """
        async ([method, path, payload]) => {
          const opt = {method, headers: {}, credentials: 'same-origin'};
          const m = document.cookie.match(/(?:^|; )nfm_csrf=([^;]*)/);
          if (m) opt.headers['X-CSRF-Token'] = decodeURIComponent(m[1]);
          if (payload !== null) {
            opt.headers['Content-Type'] = 'application/json';
            opt.body = JSON.stringify(payload);
          }
          const base = document.querySelector('meta[name=base]')?.content || '';
          const r = await fetch(base + '/api' + path, opt);
          let body = null;
          const txt = await r.text();
          try { body = JSON.parse(txt); } catch (e) { body = txt; }
          return {status: r.status, body};
        }
        """
        return self.page.evaluate(js, [method, path, payload])

    def rendered_config(self):
        r = self.api("GET", "/preview")
        if r["status"] != 200:
            return f"[preview failed: {r['status']} {r['body']}]"
        files = r["body"].get("files", {})
        if isinstance(files, dict):
            return "\n".join(
                f"########## {name} ##########\n{text}"
                for name, text in sorted(files.items()))
        return json.dumps(files)[:20000]

    def config_for(self, needle):
        """
        Only the files of the fleet config that mention a name.

        Returns an empty string when nothing matches, deliberately.  An earlier
        version returned the words "no file mentions ...", which is truthy, so
        `config_for(a) or config_for(b)` never reached b and three checks
        reported a fault that was not there.
        """
        r = self.api("GET", "/preview")
        if r["status"] != 200:
            return ""
        files = r["body"].get("files", {})
        hits = [f"########## {n} ##########\n{t}"
                for n, t in sorted(files.items()) if needle in n or needle in t]
        return "\n".join(hits)[:40000]

    def file_named(self, name):
        """One config file by name, or an empty string."""
        r = self.api("GET", "/preview")
        if r["status"] != 200:
            return ""
        return r["body"].get("files", {}).get(name, "")

    def apply(self, summary="qa run"):
        """
        Press Apply config the way the page does, and wait for it.

        The short settle afterwards is not politeness.  Apply returns once every
        node has written the files and told nginx to reload, and a reload is not
        instant: a request sent in that window is answered by the old workers.
        Without this, a test that applied and immediately asked for the thing it
        had just configured reported a fault that was really a race in the test.
        """
        r = self.api("POST", "/apply", {"summary": summary})
        if r["status"] != 200:
            return r

        # Wait for the nodes to have taken it, rather than sleeping and hoping.
        #
        # Two seconds was usually enough and sometimes was not, and when it was
        # not the suite measured the config that was live a moment ago.  That
        # is not a small error: the request falls through to the default
        # server, so a new site answers 200 from the wrong place with a 404 for
        # every file under it, and the suite reports a routing defect.  It
        # cost three separate false findings in one run on 19 August, one of
        # them the WAF appearing not to enforce, which took a while to pin down
        # precisely because it was intermittent.
        #
        # Every node reports the version it has applied, so that is what is
        # waited on.  The short grace afterwards is for the reload itself:
        # applied means the files are written and nginx has been told, and the
        # old workers finish what they are holding.
        version = (r.get("body") or {}).get("version")
        if version:
            began = time.time()
            while time.time() - began < 30:
                nodes = (self.api("GET", "/cluster")["body"] or {}).get("nodes") or []
                behind = [n["name"] for n in nodes
                          if n.get("applied_version", 0) < version
                          and (n.get("state") == "online" or n.get("is_self"))]
                if not behind:
                    break
                time.sleep(0.5)
            else:
                print(f"      !! {behind} never reported version {version}",
                      flush=True)
        time.sleep(1.5)
        return r

    def test(self, tid, area, feature, purpose, use_case, expected):
        print(f"\n  [{tid}] {feature}", flush=True)
        return Test(self, tid, area, feature, purpose, use_case, expected)
