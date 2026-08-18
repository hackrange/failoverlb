"""
Suite 5: every setting on the site form, and every setting on a path.

There are 97 settings a site can carry and 68 a path can carry.  Other suites
prove a setting reaches the config; this one proves the **form** is honest: that
what you type is what the page shows you next time you open it.

That is the defect this project has already shipped twice.  A setting that
saves correctly and redisplays as off is worse than one that fails outright,
because the next save writes the wrong value back and nobody touched the field.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t05_catalog").start()
HOST = f"qa-settings.{qa.DOMAIN}"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or body.get("sites") or []
    return next((x for x in rows if x["name"] == name), None)


POOL_ID = find("pools", "qa_pool")["id"]
old = find("hosts", "qa-settings")
if old:
    r.api("DELETE", f"/hosts/{old['id']}")

r.goto("/sites")
r.page.click("#new-site")
r.page.wait_for_selector("#s-name")
r.page.fill("#s-name", "qa-settings")
r.page.fill("#s-names", HOST)
r.page.select_option("#s-mode", "proxy")
r.page.select_option("#s-pool", str(POOL_ID))
r.page.select_option("#s-cert", "")
r.page.uncheck("#s-force")
r.page.click("#s-save")
r.page.wait_for_load_state("networkidle")
r.page.wait_for_timeout(1200)
SID = find("hosts", "qa-settings")["id"]
print(f"  test site id {SID}")


# --------------------------------------------------------------- test values
STATUS_KEYS = ("limit_req_status", "limit_conn_status")


# Turning on cross site credentials while the allowed origin is * is refused,
# and that refusal is correct: browsers reject that pair on purpose.  It gets
# its own test below rather than being swept, because a sweep that trips over a
# good rule reports a defect that is really a bad test.
NOT_SWEPT = {"cors_allow_credentials"}


def value_for(f):
    """
    A valid value for this setting that is not the one it already has.

    Where a sensible different value cannot be constructed the setting is
    skipped rather than guessed at, and the report says how many were skipped.
    A guessed value that the validator refuses would report a read back defect
    that is really a bad test.
    """
    key, typ, default = f["key"], f["type"], f["default"]
    if key in NOT_SWEPT:
        return None
    if typ == "bool":
        return not bool(default)
    if typ == "select":
        opts = [o[0] for o in (f.get("options") or []) if o[0] != ""]
        for o in opts:
            if str(o) != str(default):
                return o
        return None
    if typ == "multiselect":
        opts = [o[0] for o in (f.get("options") or [])]
        cur = default if isinstance(default, list) else []
        pick = [o for o in opts if o not in cur][:1] + list(cur)
        return pick or opts[:1] or None
    if typ == "int":
        if key in STATUS_KEYS:
            return 429
        try:
            return int(default) + 1 if default not in (None, "") else 7
        except (TypeError, ValueError):
            return 7
    if typ == "size":
        # 24k rather than something large.  nginx makes the proxy buffer sizes
        # depend on each other, and a big header buffer beside the default
        # 8 4k body buffers is a combination nginx will not load.  The tool
        # catches that pair, which is tested on its own in CAT-04; a sweep
        # tripping over it every time would bury everything else.
        return "24k" if default != "24k" else "20k"
    if typ == "time":
        return "37s" if default != "37s" else "41s"
    if typ in ("string", "text"):
        ph = f.get("placeholder")
        if ph:
            return ph
        return None
    if typ == "list":
        ph = f.get("placeholder")
        if ph:
            return [ph]
        if isinstance(default, list) and default:
            return list(default)[:1]
        return None
    return None


READ_JS = """
() => {
  const out = {};
  document.querySelectorAll('[data-setting]').forEach(el => {
    const key = el.getAttribute('data-setting');
    const type = el.getAttribute('data-type');
    if (type === 'bool') out[key] = el.checked;
    else if (type === 'multiselect')
      out[key] = Array.from(el.querySelectorAll('input:checked')).map(i => i.value);
    else if (type === 'list')
      out[key] = el.value.split('\\n').map(s => s.trim()).filter(Boolean);
    else out[key] = el.value;
  });
  return out;
}
"""

WRITE_JS = """
(values) => {
  const done = [];
  Object.entries(values).forEach(([key, val]) => {
    const el = document.querySelector('[data-setting="' + key + '"]');
    if (!el || el.disabled) return;
    const type = el.getAttribute('data-type');
    if (type === 'bool') { el.checked = val; }
    else if (type === 'multiselect') {
      el.querySelectorAll('input').forEach(i => { i.checked = val.includes(i.value); });
    }
    else if (type === 'list') { el.value = val.join('\\n'); }
    else { el.value = String(val); }
    el.dispatchEvent(new Event('change', {bubbles: true}));
    el.dispatchEvent(new Event('input', {bubbles: true}));
    done.push(key);
  });
  return done;
}
"""


def compare(want, got):
    """What did not come back the way it went in."""
    bad = {}
    for key, val in want.items():
        if key not in got:
            bad[key] = {"sent": val, "read back": "[control missing from the page]"}
            continue
        seen = got[key]
        if isinstance(val, bool):
            same = bool(seen) is val
        elif isinstance(val, list):
            # A multiselect draws its boxes in catalog order, so the order a
            # value comes back in is the page's, not the one it was sent in.
            # For these directives the set is what matters and the order does
            # not reach nginx, so compare as sets rather than reporting a
            # difference that is not one.
            same = sorted(str(x) for x in seen) == sorted(str(x) for x in val)
        else:
            same = str(seen).strip() == str(val).strip()
        if not same:
            bad[key] = {"sent": val, "read back": seen}
    return bad


# ============================================================== CAT-01
t = r.test(
    "CAT-01", "Settings catalog",
    "Every setting on the site form survives a save and a reload",
    "Set every setting the site form offers to a valid value that is not its "
    "current one, save from the page, reload the page, and compare each "
    "control against what was typed.",
    "This form is how every non default behaviour of a site is configured: "
    "timeouts, buffering, caching, compression, security headers, TLS.  If a "
    "control redisplays wrongly, the next save on any other field silently "
    "writes the wrong value, and the site changes behaviour with nobody having "
    "touched it.",
    "Every control reads back what was typed.")

t.step("open the Settings tab and turn on Show advanced settings")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=settings]")
r.page.wait_for_timeout(800)
r.page.check("#show-advanced")
r.page.wait_for_timeout(800)
t.shot("site-settings-before", full=True)
t.config("before")
t.site_config("qa-settings", "the site's config before any setting was changed")

cat = r.api("GET", "/catalog?context=server")["body"]
feats = cat if isinstance(cat, list) else cat.get("settings") or cat.get("features") or []
t.proof("how many settings the site form offers",
        f"{len(feats)} settings in the catalog for a site")

before = r.page.evaluate(READ_JS)
t.proof("a sample of the controls as they read before the change",
        json.dumps(dict(list(before.items())[:15]), indent=1))

want, skipped, unavailable = {}, [], []
for f in feats:
    if not f.get("available", True):
        unavailable.append(f["key"])
        continue
    v = value_for(f)
    if v is None:
        skipped.append(f["key"])
        continue
    want[f["key"]] = v

t.proof("what this test will set",
        json.dumps({"settings it will change": len(want),
                    "skipped, no safe different value could be built": skipped,
                    "not available on this nginx build": unavailable}, indent=1))
t.ok("the test is actually setting most of the form",
     len(want) >= 60, f"only {len(want)} settings")

t.step("write the values into the controls and press Save")
written = r.page.evaluate(WRITE_JS, want)
t.ok("every value found a control to write into",
     len(written) == len(want), f"wrote {len(written)} of {len(want)}")
t.shot("site-settings-typed", full=True)
saves = []
r.page.on("response", lambda resp: saves.append((resp.request.method, resp.status, resp.url))
          if "/api/hosts/" in resp.url else None)
r.page.click("#save-site")
r.page.wait_for_timeout(2500)
puts = [s for s in saves if s[0] == "PUT"]
t.proof("what the Save button actually sent",
        "\n".join(f"{m} {st} {u}" for m, st, u in puts) or "[no PUT was sent]")
t.ok("the save was accepted by the server",
     bool(puts) and all(st == 200 for _, st, _ in puts), puts)

t.step("reload the page and read every control back")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=settings]")
r.page.wait_for_timeout(900)
r.page.check("#show-advanced")
r.page.wait_for_timeout(900)
t.shot("site-settings-after", full=True)
after = r.page.evaluate(READ_JS)

bad = compare(want, after)
t.proof("every setting that did not read back the way it was saved",
        json.dumps(bad, indent=1) if bad else "none, all of them came back correctly")
t.ok(f"all {len(want)} settings read back correctly", not bad,
     f"{len(bad)} did not: {sorted(bad)}")

t.step("check the settings reached the config, not just the form")
cfg = t.site_config("qa-settings", "the site's config after the settings were saved")
t.config("after")
landed = {
    "client_max_body_size 24k": "client_max_body_size 24k" in cfg,
    "send_timeout 37s": "send_timeout 37s" in cfg,
    "keepalive_timeout 37s": "keepalive_timeout 37s" in cfg,
    "client_body_timeout 37s": "client_body_timeout 37s" in cfg,
}
t.proof("a sample of the saved settings, found in the rendered config",
        json.dumps(landed, indent=1))
t.ok("the settings reached the config and not just the form",
     all(landed.values()), landed)
t.close()

# ============================================================== CAT-02
t = r.test(
    "CAT-02", "Settings catalog",
    "The config those settings produce is config nginx will load",
    "Apply the site carrying every setting at once and prove the fleet accepts "
    "it, which means every node ran nginx -t against it.",
    "A setting that renders a directive nginx refuses takes out the whole "
    "apply, not just that site.  With ninety odd of them on one site this is "
    "the worst case, and it is the one worth proving.",
    "Apply succeeds, which means nginx tested the config on every node before "
    "any node used it.")

t.config("before")
res = r.apply("qa: every setting at once")
t.proof("POST /api/apply with every setting set", json.dumps(res["body"], indent=1)[:1500])
t.ok("the fleet accepted a site carrying every setting",
     res["status"] == 200 and res["body"].get("ok"), res)
t.config("after")
live = qa.probe(HOST, "/echo", ip="127.0.0.1", scheme="http")
t.proof("a real request to the site with every setting on", qa.summarise(live, 900))
t.ok("the site still answers", live["status"] in (200, 403, 429), live["status"])
t.close()

# ============================================================== CAT-03
t = r.test(
    "CAT-03", "Settings catalog",
    "Every setting on a path survives a save and a reload",
    "Do the same sweep on a path's own settings panel, which is a different "
    "code path from the site's and was added later.",
    "Per path settings are how one route gets a bigger upload limit or a "
    "longer timeout than the rest of a site.  The panel is built from the same "
    "catalog but saved through a different endpoint, so it can drift.",
    "Every control on the path's settings panel reads back what was typed.")

t.step("add a path and open its own settings panel")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(500)
r.page.click("#add-path")
r.page.wait_for_selector("#l-path")
r.page.fill("#l-path", "/tuned")
r.page.select_option("#l-mode", "proxy")
r.page.wait_for_timeout(300)
r.page.select_option("#l-pool", str(POOL_ID))
r.page.check("#l-show-settings")
r.page.wait_for_timeout(1500)
t.shot("path-settings-panel")
t.config("before")

cat = r.api("GET", "/catalog?context=location")["body"]
lfeats = cat if isinstance(cat, list) else cat.get("settings") or cat.get("features") or []
t.proof("how many settings a path offers",
        f"{len(lfeats)} settings in the catalog for a path")

holder = "#l-settings-holder"
lwant, lskipped = {}, []
for f in lfeats:
    if not f.get("available", True):
        continue
    v = value_for(f)
    if v is None:
        lskipped.append(f["key"])
        continue
    lwant[f["key"]] = v

written = r.page.evaluate(
    """([values, sel]) => {
        const root = document.querySelector(sel) || document;
        const done = [];
        Object.entries(values).forEach(([key, val]) => {
          const el = root.querySelector('[data-setting="' + key + '"]');
          if (!el || el.disabled) return;
          const type = el.getAttribute('data-type');
          if (type === 'bool') el.checked = val;
          else if (type === 'multiselect')
            el.querySelectorAll('input').forEach(i => { i.checked = val.includes(i.value); });
          else if (type === 'list') el.value = val.join('\\n');
          else el.value = String(val);
          el.dispatchEvent(new Event('change', {bubbles: true}));
          el.dispatchEvent(new Event('input', {bubbles: true}));
          done.push(key);
        });
        return done;
      }""", [lwant, holder])
t.proof("what this test set on the path",
        json.dumps({"set": len(written), "skipped": lskipped}, indent=1))
t.ok("the path panel offered controls for most of the catalog",
     len(written) >= 40, f"only {len(written)} controls found")
lsaves = []
r.page.on("response", lambda resp: lsaves.append((resp.request.method, resp.status, resp.url))
          if "/api/hosts/" in resp.url or "/api/locations" in resp.url else None)
r.page.click("#l-save")
r.page.wait_for_timeout(2000)
writes = [x for x in lsaves if x[0] in ("POST", "PUT")]
t.proof("what the path Save button actually sent",
        "\n".join(f"{m} {st} {u}" for m, st, u in writes) or "[nothing was sent]")
t.ok("the path save was accepted by the server",
     bool(writes) and all(st in (200, 201) for _, st, _ in writes), writes)

t.step("reopen the path and read its settings back")
r.goto(f"/sites/{SID}")
r.page.click("button[data-tab=paths]")
r.page.wait_for_timeout(500)
locs = r.api("GET", f"/hosts/{SID}/locations")
t.proof("GET /api/hosts/{id}/locations", json.dumps(locs, indent=1)[:1200])
t.ok("the path list came back", locs["status"] == 200 and "locations" in locs["body"], locs)
rows = locs["body"]["locations"]
t.ok("the path was created by the dialog", any(x["path"] == "/tuned" for x in rows),
     [x["path"] for x in rows])
tuned = next(x for x in rows if x["path"] == "/tuned")
t.proof("the path as the API hands it back",
        json.dumps(tuned, indent=1)[:2000])
r.page.click(f"button[data-edit-path='{tuned['id']}']")
r.page.wait_for_selector("#l-path")
r.page.check("#l-show-settings")
r.page.wait_for_timeout(1500)
t.shot("path-settings-reopened")
lafter = r.page.evaluate(
    """(sel) => {
        const root = document.querySelector(sel) || document;
        const out = {};
        root.querySelectorAll('[data-setting]').forEach(el => {
          const key = el.getAttribute('data-setting');
          const type = el.getAttribute('data-type');
          if (type === 'bool') out[key] = el.checked;
          else if (type === 'multiselect')
            out[key] = Array.from(el.querySelectorAll('input:checked')).map(i => i.value);
          else if (type === 'list')
            out[key] = el.value.split('\\n').map(s => s.trim()).filter(Boolean);
          else out[key] = el.value;
        });
        return out;
      }""", holder)
sent = {k: v for k, v in lwant.items() if k in written}
lbad = compare(sent, lafter)
t.proof("every path setting that did not read back the way it was saved",
        json.dumps(lbad, indent=1) if lbad else "none, all of them came back correctly")
t.ok(f"all {len(sent)} path settings read back correctly", not lbad,
     f"{len(lbad)} did not: {sorted(lbad)}")
r.page.keyboard.press("Escape")

cfg = t.site_config("qa-settings", "the config with a fully tuned path on it")
t.config("after")
res = r.apply("qa: every path setting at once")
t.proof("POST /api/apply", json.dumps(res["body"], indent=1)[:900])
t.ok("the fleet accepted a path carrying every setting",
     res["status"] == 200 and res["body"].get("ok"), res)
t.close()

# ============================================================== CAT-04
t = r.test(
    "CAT-04", "Settings catalog",
    "Values that would break the site are refused, with a reason",
    "Send four values that are wrong in four different ways and prove each is "
    "refused before it can reach nginx, with a message that says what to do.",
    "The two phase apply already stops bad config going live, but an apply "
    "that fails is a fleet with a change stuck in it and an error that names a "
    "directive rather than a setting.  Catching it at the save is the "
    "difference between a sentence and an afternoon.",
    "Each of the four is refused with a 400 and an explanation naming the "
    "setting and the fix.")

cases = [
    ("a value trying to write config of its own",
     {"proxy_cache_key": "$uri; deny all"}),
    ("a header value with a line break in it, which is header injection",
     {"content_security_policy": "default-src 'self'\nX-Injected: yes"}),
    ("cross site credentials with an origin of *, which browsers refuse",
     {"cors_enabled": True, "cors_allow_origin": ["*"], "cors_allow_credentials": True}),
    ("proxy buffer sizes that do not fit together",
     {"proxy_buffer_size": "7m", "proxy_buffers": "8 4k"}),
]
for why, payload in cases:
    res = r.api("PUT", f"/hosts/{SID}", {"settings": payload})
    t.proof(why, json.dumps({"sent": payload, "answer": res["status"],
                             "reason": res["body"]}, indent=1)[:900])
    t.ok(f"refused: {why}", res["status"] == 400, res)

t.step("and the one that used to be refused and should not be")
res = r.api("PUT", f"/hosts/{SID}",
            {"settings": {"content_security_policy":
                          "default-src 'self'; img-src 'self' data:; frame-ancestors 'self'"}})
t.proof("a real Content Security Policy, which has semicolons in it by definition",
        json.dumps({"answer": res["status"], "body": str(res["body"])[:200]}, indent=1))
t.ok("a normal policy with semicolons is accepted", res["status"] == 200, res)
cfg = t.site_config("qa-settings", "the config carrying that policy")
t.ok("the policy reached the config quoted, so the semicolons are safe",
     'add_header Content-Security-Policy "default-src' in cfg,
     [l for l in cfg.splitlines() if "Content-Security-Policy" in l])
res = r.apply("qa: csp")
t.ok("nginx loaded a config carrying a real policy",
     res["status"] == 200 and res["body"].get("ok"), res)
live = qa.probe(HOST, "/echo", ip="127.0.0.1", scheme="http")
t.proof("the header as a browser would receive it",
        f"Content-Security-Policy: {live['headers'].get('Content-Security-Policy')}")
t.ok("the browser gets the whole policy, semicolons and all",
     "frame-ancestors" in (live["headers"].get("Content-Security-Policy") or ""),
     live["headers"].get("Content-Security-Policy"))
r.api("PUT", f"/hosts/{SID}", {"settings": {}})
t.close()

r.stop()
print("\nT05 DONE")
