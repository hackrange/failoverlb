import sys
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("smoke").start()
t = r.test("SMOKE-01", "Harness", "Sign in and read the fleet",
           "Prove the rig drives the real GUI in a real browser.",
           "Every later test depends on this.",
           "Signed in, dashboard renders, /api/status answers 200.")
t.step("open the dashboard")
r.goto("/")
t.shot("dashboard")
st = r.api("GET", "/status")
t.ok("status endpoint answers", st["status"] == 200, st)
t.proof("GET /api/status", __import__("json").dumps(st["body"], indent=2)[:2000])
cfg = t.config("before")
t.ok("preview returns config text", "server" in cfg, cfg[:200])
t.proof("first 1500 chars of the rendered fleet config", cfg[:1500])
p = t.probe("https to the default site", hostname=f"test.{qa.DOMAIN}", path="/")
t.ok("nginx answers on 443", p["status"] > 0, p["status"])
t.ok("no javascript errors on the page", not r.js_errors, r.js_errors)
t.close()
r.stop()
print("\nSMOKE DONE")
