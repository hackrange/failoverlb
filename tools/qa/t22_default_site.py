"""
Suite 22: the default site, and what a request for nothing in particular gets.

Every load balancer answers on an address, and somebody always arrives at that
address without a name the fleet knows: a scanner, a health check pointed at
the wrong place, somebody typing the IP into a browser.  nginx sends that
request to the default server, and if nobody has chosen one it sends it to
whichever server block happens to be first for the port.

Two things follow, and both are tested here.

**Choosing has to work at all.**  It did not.  The installer writes a catch all
at sites-enabled/default.conf carrying default_server, the manager had no idea
that file existed, and ticking the box on a site rendered a second one.  nginx
refuses to start with two, an apply is all or nothing, so the tick box stopped
the whole fleet applying anything.  Reported from the field.

**What the chosen site answers with.**  Also reported from the field: a bogus
name on a real load balancer came back with a stock error page rather than the
site's own.  A default site that answers strangers with an unstyled page is a
default site that looks broken, and on a box carrying more than one customer
the fallback landing on somebody's branded page is worse than that.
"""
import json
import sys
import time
sys.path.insert(0, "/qa")
import qa

r = qa.Runner("t22_default_site").start()
LB01, LB02 = qa.LB01, qa.LB02
SITE = "qa-default-site"
HOST = f"{SITE}.{qa.DOMAIN}"
STRANGER = "nobody-serves-this.invalid"


def find(kind, name):
    body = r.api("GET", f"/{kind}")["body"]
    rows = body.get(kind) or body.get("hosts") or []
    return next((x for x in rows if x["name"] == name), None)


old = find("hosts", SITE)
if old:
    r.api("DELETE", f"/hosts/{old['id']}")

templates = r.api("GET", "/error-pages")["body"].get("templates") or []
TEMPLATE = templates[0]["id"] if templates else None
TEMPLATE_NAME = templates[0]["name"] if templates else None

r.api("POST", "/hosts",
      {"name": SITE, "server_names": [HOST], "mode": "static",
       "document_root": qa.STATIC_DIR, "listen_http": True,
       "listen_https": False, "force_https": False,
       "error_page_template_id": TEMPLATE})
SID = find("hosts", SITE)["id"]
print(f"  test site id {SID}, error page template {TEMPLATE_NAME!r}")


def stranger(path="/"):
    """A request carrying a name this fleet has never heard of."""
    return qa.probe(STRANGER, path, ip=LB01, scheme="http")


# ---------------------------------------------------------------- DEF-01

t = r.test("DEF-01", "Sites", "A site can be made the default one",
           "Tick the box, apply, and prove the apply is accepted and the site "
           "really is what answers a name nobody serves.",
           "The whole feature.  It was unusable: the setting saved, "
           "redisplayed, rendered the right config, and then every apply on "
           "the fleet was refused with a duplicate default server naming a "
           "file the person had never edited.",
           "Apply succeeds and a stranger gets this site.")
before = stranger("/")
t.proof("a name nobody serves, before anything is chosen",
        qa.summarise(before, body_chars=120))

res = r.api("PUT", f"/hosts/{SID}", {"default_server": True})
t.proof("ticking the box", json.dumps(res, indent=2)[:400])
t.ok("the setting was accepted", res["status"] == 200, res)
t.ok("and it reads back as set",
     r.api("GET", f"/hosts/{SID}")["body"].get("default_server") is True,
     r.api("GET", f"/hosts/{SID}")["body"].get("default_server"))

cfg = t.site_config(SITE, "the config for the default site")
t.ok("the listen line says default_server", "default_server;" in cfg,
     [l for l in cfg.splitlines() if "listen" in l])

res = r.apply("qa: a chosen default site")
t.proof("the apply", json.dumps(res["body"], indent=2)[:500])
t.ok("the apply is accepted, which it was not before this was fixed",
     res["status"] == 200, res)

after = stranger("/")
t.proof("the same request afterwards", qa.summarise(after, body_chars=120))
t.ok("a name nobody serves now gets the chosen site", after["status"] == 200,
     after["status"])
t.ok("and it is really that site's content",
     "QA static site" in (after["body"] or ""), (after["body"] or "")[:120])
t.close()


# ---------------------------------------------------------------- DEF-02

t = r.test("DEF-02", "Sites", "The default site answers with its own error page",
           "Ask the default site for something that is not there, without a "
           "name it knows, and check the error page is the template the site "
           "was given rather than the stock one.",
           "Reported from the field: a bogus name on a real load balancer came "
           "back with a stock page.  A default site that answers strangers "
           "with an unstyled nginx page looks broken, and it is the first "
           "thing a scanner or a mistyped health check ever sees.",
           "The 404 carries the site's template.")
if not TEMPLATE:
    t.note("this fleet has no error page templates, so there is nothing to "
           "adhere to")
    t.ok("skipped, no template on this fleet", True)
else:
    missing = stranger("/nothing-here-at-all")
    body = missing["body"] or ""
    t.proof("a stranger asking for something that is not there",
            qa.summarise(missing, body_chars=400))
    t.ok("it is a 404", missing["status"] == 404, missing["status"])
    # Not by the title.  The template's own 404 says "404 Not Found" too,
    # which is the right thing for it to say, so testing for the absence of
    # that text fails a page that is working.  nginx's stock page is the one
    # with no doctype, no stylesheet and a centred "nginx" on the bottom.
    stock = ("<center>" in body or "<hr>" in body) and "<style" not in body
    t.ok("and it is a real page rather than nginx's stock one", not stock,
         body[:220])
    t.ok("it is the styled template the site was given",
         "<!doctype html" in body.lower() and "<style" in body.lower(),
         body[:220])
    t.ok("and it does not sign itself nginx", "<center>nginx" not in body,
         body[:220])

    own = qa.probe(HOST, "/nothing-here-at-all", ip=LB01, scheme="http")
    t.proof("the same thing asked for by the site's real name",
            qa.summarise(own, body_chars=200))
    t.ok("a stranger and the site's own name get the same page",
         (own["body"] or "")[:200] == body[:200],
         "the default server and the named server answered differently")
t.close()


# ---------------------------------------------------------------- DEF-03

t = r.test("DEF-03", "Sites", "The installer's catch all stands down and comes back",
           "Check the file the installer enabled is out of the way while a "
           "managed site is the default, and back afterwards.",
           "nginx allows one default server per address and port.  Something "
           "has to give, and it must give back: a box left with no catch all "
           "and no managed default sends strangers to whichever site happens "
           "to be first, which on a fleet carrying more than one customer "
           "means one customer's branded page answering for another.",
           "Unmatched traffic goes to the chosen site while one is chosen, and "
           "back to the installer's page when none is.")
t.step("while a managed site is the default")
during = stranger("/")
t.ok("the chosen site answers", "QA static site" in (during["body"] or ""),
     (during["body"] or "")[:120])

if LB02:
    other = qa.probe(STRANGER, "/", ip=LB02, scheme="http")
    t.proof("and on the other node", qa.summarise(other, body_chars=120))
    t.ok("the other node agrees", "QA static site" in (other["body"] or ""),
         (other["body"] or "")[:120])

t.step("now take it back off")
r.api("PUT", f"/hosts/{SID}", {"default_server": False})
res = r.apply("qa: no chosen default any more")
t.ok("the apply is accepted", res["status"] == 200, res)
time.sleep(1)
back = stranger("/")
t.proof("a name nobody serves, once nothing is chosen",
        qa.summarise(back, body_chars=120))
t.ok("it is no longer the test site",
     "QA static site" not in (back["body"] or ""), (back["body"] or "")[:120])
t.ok("and something still answers rather than the port going quiet",
     back["status"] > 0, back["status"])
t.note("that is the installer's catch all back where it was, which is what "
       "makes this reversible rather than a one way door.")
t.close()


# ---------------------------------------------------------------- tidy up

row = find("hosts", SITE)
if row:
    print("  removing the test site:", r.api("DELETE", f"/hosts/{row['id']}")["status"])
r.apply("qa: removing the default site test")

print("\nT22 DONE")
r.stop()
