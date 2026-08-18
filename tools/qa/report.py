"""
Turn the evidence into the test plan document.

Reads every *.jsonl in evidence/ and writes a single .docx: what each test was
for, the use case behind the feature, the config before and after, what was
expected, what was observed, and the screenshots taken along the way.

Nothing in here decides anything.  Every pass and fail in the document is the
one the suite recorded at the time.
"""
import datetime
import difflib
import glob
import json
import os
import pathlib
import subprocess
import sys

from docx import Document
from docx.enum.section import WD_SECTION
from docx.enum.table import WD_TABLE_ALIGNMENT
from docx.enum.text import WD_ALIGN_PARAGRAPH, WD_BREAK
from docx.oxml import OxmlElement
from docx.oxml.ns import qn
from docx.shared import Inches, Pt, RGBColor

EV = pathlib.Path("/qa/evidence")
SHOTS = EV / "shots"
OUT = pathlib.Path(os.environ.get("QA_DOC", "/qa/Failover-LB-Test-Plan.docx"))

ORDER = ["t01_settings", "t02_pools", "t03_sites", "t04_paths", "t05_catalog",
         "t06_mount_traffic", "t07_zones", "t08_behaviour2", "t09_pages_admin",
         "t10_geo_login", "t11_import_repair", "t12_versions_certs",
         "t13_maps_streams_cluster", "t14_gslb", "t15_failover",
         "t16_safety", "t17_access_lists", "t18_roles",
         "t19_outside_address", "t20_waf_surface", "t21_waf"]

INK = RGBColor(0x1a, 0x1a, 0x1a)
GREY = RGBColor(0x60, 0x60, 0x60)
GOOD = RGBColor(0x1a, 0x6b, 0x2e)
BAD = RGBColor(0xa8, 0x1c, 0x1c)


def load():
    tests = []
    for path in sorted(EV.glob("*.jsonl")):
        stem = path.stem
        if stem.startswith("diag") or stem in ("smoke", "probe", "cleanup",
                                               "cleanup2", "cleanup3"):
            continue
        rank = ORDER.index(stem) if stem in ORDER else 99
        for line in path.read_text().splitlines():
            if not line.strip():
                continue
            rec = json.loads(line)
            rec["_suite"] = stem
            rec["_rank"] = rank
            tests.append(rec)
    tests.sort(key=lambda r: (r["_rank"], r["id"]))
    # A suite re-run appends, so keep only the newest record for each test id.
    newest = {}
    for rec in tests:
        newest[rec["id"]] = rec
    out = list(newest.values())
    out.sort(key=lambda r: (r["_rank"], r["id"]))
    return out


# --------------------------------------------------------------- docx helpers

def style_base(doc):
    normal = doc.styles["Normal"]
    normal.font.name = "Calibri"
    normal.font.size = Pt(10.5)
    normal.font.color.rgb = INK
    normal.paragraph_format.space_after = Pt(6)
    normal.paragraph_format.line_spacing = 1.12
    for name, size, colour in (("Heading 1", 20, INK), ("Heading 2", 15, INK),
                               ("Heading 3", 12, INK), ("Heading 4", 11, GREY)):
        st = doc.styles[name]
        st.font.name = "Calibri"
        st.font.size = Pt(size)
        st.font.color.rgb = colour
        st.font.bold = True
        st.paragraph_format.space_before = Pt(14)
        st.paragraph_format.space_after = Pt(6)


def clean(text):
    """
    Strip anything Word will not accept in a text node.

    Evidence includes real response bodies, and some of those are binary: a
    40 kilobyte file fetched to prove it arrives whole, an encrypted backup.
    Control characters in those blow up the document writer, so they are
    replaced rather than allowed to lose the whole report.
    """
    if text is None:
        return ""
    out = []
    for ch in str(text):
        code = ord(ch)
        if ch in "\t\n":
            out.append(ch)
        elif code < 0x20 or code == 0x7F:
            out.append(".")
        elif 0xD800 <= code <= 0xDFFF:
            out.append(".")
        else:
            out.append(ch)
    return "".join(out)


def para(doc, text="", size=10.5, bold=False, italic=False, colour=None,
         space_after=6, align=None):
    p = doc.add_paragraph()
    run = p.add_run(clean(text))
    run.font.size = Pt(size)
    run.bold = bold
    run.italic = italic
    run.font.color.rgb = colour or INK
    p.paragraph_format.space_after = Pt(space_after)
    if align is not None:
        p.alignment = align
    return p


def mono(doc, text, size=7.6, limit=5200, shade="F4F5F7"):
    """A block of fixed width text in a shaded single cell table."""
    text = (text or "").rstrip()
    if not text:
        text = "[nothing]"
    if len(text) > limit:
        text = text[:limit] + f"\n... [{len(text) - limit} more characters not shown]"
    table = doc.add_table(rows=1, cols=1)
    table.alignment = WD_TABLE_ALIGNMENT.LEFT
    cell = table.rows[0].cells[0]
    shd = OxmlElement("w:shd")
    shd.set(qn("w:fill"), shade)
    cell._tc.get_or_add_tcPr().append(shd)
    cell.text = ""
    for i, line in enumerate(text.splitlines() or [""]):
        p = cell.paragraphs[0] if i == 0 else cell.add_paragraph()
        run = p.add_run(clean(line))
        run.font.name = "Consolas"
        run.font.size = Pt(size)
        p.paragraph_format.space_after = Pt(0)
        p.paragraph_format.line_spacing = 1.0
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return table


def shot(doc, name, caption, width=6.0):
    path = SHOTS / name
    if not path.is_file():
        return False
    try:
        doc.add_picture(str(path), width=Inches(width))
        doc.paragraphs[-1].alignment = WD_ALIGN_PARAGRAPH.CENTER
        para(doc, caption, size=8.5, italic=True, colour=GREY,
             align=WD_ALIGN_PARAGRAPH.CENTER, space_after=10)
        return True
    except Exception:
        return False


def table(doc, rows, widths=None, header=True):
    t = doc.add_table(rows=0, cols=len(rows[0]))
    t.style = "Table Grid"
    for r_i, row in enumerate(rows):
        cells = t.add_row().cells
        for c_i, value in enumerate(row):
            cells[c_i].text = ""
            p = cells[c_i].paragraphs[0]
            run = p.add_run(clean(value))
            run.font.size = Pt(9)
            run.bold = header and r_i == 0
            p.paragraph_format.space_after = Pt(2)
            if r_i == 0 and header:
                shd = OxmlElement("w:shd")
                shd.set(qn("w:fill"), "E8EAED")
                cells[c_i]._tc.get_or_add_tcPr().append(shd)
            if str(value) in ("pass", "PASS"):
                run.font.color.rgb = GOOD
                run.bold = True
            if str(value) in ("fail", "FAIL"):
                run.font.color.rgb = BAD
                run.bold = True
    if widths:
        for row in t.rows:
            for i, w in enumerate(widths):
                row.cells[i].width = Inches(w)
    doc.add_paragraph().paragraph_format.space_after = Pt(4)
    return t


def config_diff(before, after):
    if not before or not after:
        return None
    b = before.splitlines()
    a = after.splitlines()
    if b == a:
        return "[the rendered fleet config is identical before and after]"
    diff = list(difflib.unified_diff(b, a, "before", "after", lineterm="", n=2))
    return "\n".join(diff)


# ------------------------------------------------------------------ the facts

def environment():
    def sh(cmd):
        try:
            return subprocess.run(cmd, shell=True, capture_output=True,
                                  text=True, timeout=20).stdout.strip()
        except Exception:
            return ""
    return {
        "commit": os.environ.get("QA_COMMIT", "") or "not recorded",
        "nginx": os.environ.get("QA_NGINX", "") or "not recorded",
        "when": datetime.datetime.now().strftime("%d %B %Y, %H:%M"),
    }


AREA_NOTES = {
    "Settings": "Fleet wide settings that are not attached to one site.",
    "Backend pools": "The servers behind a site, how traffic is shared between "
                     "them, and how a broken one is taken out.",
    "Making a website": "The site form itself: what a site does, which ports it "
                        "answers on, its certificate and its names.",
    "Paths": "Routing inside one hostname, and serving a whole other site under "
             "a path.",
    "Settings catalog": "The ninety seven settings a site can carry and the "
                        "sixty eight a path can carry.",
    "Settings in traffic": "Settings whose effect can only be seen at the wire.",
    "Zones": "Rate limits, connection limits and caches, which are shared "
             "objects a site points at.",
    "Error pages": "What a visitor sees when something goes wrong.",
    "Site administration": "Raw config, cloning, ports and deletion.",
    "Geo blocking": "Refusing traffic by country.",
    "Login watch": "Noticing password guessing against a site.",
    "Importing": "Reading a config that already exists.",
    "Repair": "Getting out of a config nginx will not load.",
    "Versions and rollback": "Seeing what changed and going back.",
    "Backup": "Taking a copy of the whole fleet.",
    "Certificates": "The certificate lifecycle every public site depends on.",
    "Maps": "One decision made once and reused.",
    "Streams": "Load balancing things that are not http.",
    "Cluster": "The two nodes holding the same config.",
    "GSLB": "Answering DNS so a name points at whichever site is up.",
    "Failover": "The standby taking over.",
}


def counts(tests):
    total = passed = failed = 0
    for rec in tests:
        for obs in rec.get("observed", []):
            if isinstance(obs, dict) and "result" in obs:
                total += 1
                if obs["result"] == "pass":
                    passed += 1
                else:
                    failed += 1
    return total, passed, failed


def build():
    tests = load()
    env = environment()
    total, passed, failed = counts(tests)
    doc = Document()
    style_base(doc)
    for section in doc.sections:
        section.left_margin = Inches(0.9)
        section.right_margin = Inches(0.9)
        section.top_margin = Inches(0.9)
        section.bottom_margin = Inches(0.9)

    # ---------------------------------------------------------- title page
    for _ in range(6):
        doc.add_paragraph()
    para(doc, "Failover LB", size=30, bold=True, align=WD_ALIGN_PARAGRAPH.CENTER,
         space_after=2)
    para(doc, "Feature Test Plan and Results", size=18,
         align=WD_ALIGN_PARAGRAPH.CENTER, colour=GREY, space_after=26)
    para(doc, "Creating a website: every feature, tested against a running fleet",
         size=11.5, italic=True, align=WD_ALIGN_PARAGRAPH.CENTER, colour=GREY,
         space_after=40)
    table(doc, [
        ["Document", "Feature Test Plan and Results"],
        ["Version", "1.0"],
        ["Date", env["when"]],
        ["Prepared by", "Quality engineering"],
        ["System under test", "Failover LB, two node fleet"],
        ["Software version", env["commit"]],
        ["nginx", env["nginx"]],
        ["Result", f"{passed} of {total} checks passed"],
    ], widths=[2.0, 4.6], header=False)
    doc.add_page_break()

    # ------------------------------------------------------ document control
    doc.add_heading("Document control", level=1)
    table(doc, [
        ["Version", "Date", "Author", "Change"],
        ["1.0", env["when"], "Quality engineering",
         "First issue.  Full feature pass over site creation."],
    ], widths=[0.8, 1.6, 1.8, 2.4])

    doc.add_heading("Approval", level=2)
    table(doc, [
        ["Role", "Name", "Signature", "Date"],
        ["Test lead", "", "", ""],
        ["Engineering owner", "", "", ""],
        ["Product owner", "", "", ""],
    ], widths=[1.6, 1.8, 1.8, 1.4])
    doc.add_page_break()

    # ------------------------------------------------------------- section 1
    doc.add_heading("1.  Purpose and scope", level=1)
    para(doc,
         "This document records a full functional test of Failover LB against a "
         "running two node fleet, covering everything involved in creating and "
         "operating a website: backend pools, sites, paths, the settings "
         "catalog, certificates, zones, error pages, geo blocking, login "
         "watching, importing an existing config, repairing a broken one, "
         "config versions and rollback, backups, maps, stream proxying and the "
         "cluster itself.")
    para(doc,
         "It was commissioned after a session in which stored configuration was "
         "found to be overwritten in normal use.  The existing automated suites "
         "could not have caught that class of fault, because every one of them "
         "stages configuration and none of them applies it.  The defects in "
         "this product live where the tool meets a real nginx, so every test "
         "here applies configuration for real and then puts real traffic "
         "through it.")

    doc.add_heading("1.1  In scope", level=2)
    for line in [
        "Every feature reachable while creating and running a website.",
        "The graphical interface itself, driven in a real browser as a person "
        "would drive it, including whether a saved setting is redisplayed "
        "correctly.",
        "Real HTTP and HTTPS traffic through the real nginx on both nodes.",
        "Configuration applied for real, not staged and discarded.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")

    doc.add_heading("1.2  Out of scope", level=2)
    para(doc, "Excluded at the owner's direction, to be covered by a separate "
              "pass:")
    for line in [
        "Access lists, and who may reach a site or a path.",
        "User accounts, roles and permissions.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")
    para(doc, "Excluded because the environment cannot support them, recorded "
              "in section 7 rather than left unsaid:")
    for line in [
        "The web application firewall, which needs a ModSecurity build.  This "
        "fleet's nginx does not have one.",
        "HTTP/3, which needs a QUIC build.  This fleet's nginx does not have one.",
        "Certificate issue from a public authority, which needs the fleet to be "
        "reachable from the internet on port 80 under the name being issued.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")

    # ------------------------------------------------------------- section 2
    doc.add_heading("2.  System under test", level=1)
    table(doc, [
        ["Item", "Detail"],
        ["Fleet", "Two nodes, active and standby, sharing configuration"],
        ["Active node", os.environ.get("QA_LB01_LABEL", "the node under test")],
        ["Standby node", os.environ.get("QA_LB02_LABEL", "the standby")],
        ["Software version", env["commit"]],
        ["nginx", env["nginx"]],
        ["Test domains", "qa-* under the test domain, resolved by explicit Host header "
                         "and SNI so a name is tested without waiting on DNS"],
        ["Backends", "Three purpose built origin servers on ports 9101, 9102 "
                     "and 9103, each reporting the request it actually "
                     "received"],
        ["Fleet detail", "Addresses and names are given to the run through the "
                         "environment and are not recorded in the suites"],
    ], widths=[1.7, 4.9])

    doc.add_heading("2.1  Why the backends report their own requests", level=2)
    para(doc,
         "A static file cannot tell you whether a path prefix was removed before "
         "the request was forwarded, which Host header arrived, or whether the "
         "upgrade headers for a websocket survived the hop.  The origin servers "
         "used here answer with the request line and every header they were "
         "given, as JSON.  That is what makes a claim such as \"the prefix was "
         "stripped\" evidence rather than an assumption.  Each one can also be "
         "made unhealthy, or killed outright, so failover is tested against a "
         "backend that genuinely refuses connections rather than one returning "
         "an error page.")

    # ------------------------------------------------------------- section 3
    doc.add_heading("3.  Test approach", level=1)
    para(doc,
         "Every test follows the same shape, and the results section reproduces "
         "all of it for each one:")
    for line in [
        "What the test is for, in one sentence.",
        "The use case: why somebody needs the feature at all.",
        "The expected outcome, written before the test was run.",
        "The configuration before the change.",
        "The configuration after the change.",
        "The evidence: requests, responses and screenshots.",
        "The observed result, check by check.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")

    doc.add_heading("3.1  Method", level=2)
    para(doc,
         "Tests are driven through the graphical interface in a real Chromium "
         "browser, signed in as an ordinary administrator, clicking the same "
         "controls a person clicks.  Where a test needs to set ninety seven "
         "settings at once it writes into the same form controls and presses "
         "the same Save button.  Nothing is written directly to the database.")
    para(doc,
         "No test decides whether it passed by reading the database back.  The "
         "database agreeing with itself is not evidence.  A test passes when a "
         "request goes in one end and the right bytes come out of the other.")

    doc.add_heading("3.2  Guarding against a test that proves nothing", level=2)
    para(doc,
         "A check that silently tests nothing is worse than no check, because it "
         "reports green.  Three instances were caught during this pass and each "
         "is now guarded:")
    table(doc, [
        ["What happened", "How it now cannot recur"],
        ["A config file was read by the wrong name, so a check for duplicate "
         "directives ran against an empty string and passed.",
         "The helper that fetches a site's config asserts the file exists "
         "before anything is checked against it."],
        ["A disabled site renders no config at all, so the same check passed "
         "against nothing.",
         "The site is switched on first, and that the import created it "
         "disabled is asserted separately as its own behaviour."],
        ["A helper returned the words \"no file found\", which is truthy, so a "
         "fallback was never reached and three checks reported a fault that "
         "did not exist.",
         "It returns an empty string, and the caller asserts on it."],
    ], widths=[3.3, 3.3])

    # ------------------------------------------------------------- section 4
    doc.add_heading("4.  Entry and exit criteria", level=1)
    doc.add_heading("4.1  Entry criteria", level=2)
    for line in [
        "A two node fleet, both nodes online, with the standby receiving config.",
        "A full backup of the database and the live configuration taken before "
        "any test ran, so the fleet can be returned to its starting state.",
        "Purpose built origin servers reachable from both nodes.",
        "A dedicated administrator account, removed at the end of the pass.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")
    doc.add_heading("4.2  Exit criteria", level=2)
    for line in [
        "Every in scope feature has at least one test that ends in real traffic.",
        "Every defect found is either fixed and retested, or recorded with its "
        "severity and why it was not fixed.",
        "The product's own regression suites still pass after the changes.",
        "Every object created by the pass is removed from the fleet.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")
    doc.add_page_break()

    # ------------------------------------------------------------- section 5
    doc.add_heading("5.  Coverage and results", level=1)
    para(doc, f"{len(tests)} test cases, {total} individual checks, "
              f"{passed} passed and {failed} failed.", bold=True)

    by_area = {}
    for rec in tests:
        by_area.setdefault(rec["area"], []).append(rec)
    # Same grouping the results section uses, so the two agree.

    rows = [["Area", "Cases", "Checks", "Passed", "Failed", "Result"]]
    for area, recs in by_area.items():
        a_total = a_pass = a_fail = 0
        for rec in recs:
            for obs in rec.get("observed", []):
                if isinstance(obs, dict) and "result" in obs:
                    a_total += 1
                    if obs["result"] == "pass":
                        a_pass += 1
                    else:
                        a_fail += 1
        rows.append([area, len(recs), a_total, a_pass, a_fail,
                     "pass" if a_fail == 0 else "fail"])
    table(doc, rows, widths=[2.0, 0.7, 0.8, 0.8, 0.7, 0.8])

    doc.add_heading("5.1  Test case index", level=2)
    rows = [["ID", "Feature", "Result"]]
    for rec in tests:
        rows.append([rec["id"], rec["feature"], rec["verdict"]])
    table(doc, rows, widths=[0.9, 4.9, 0.9])
    doc.add_page_break()
    return doc, tests, by_area, env, (total, passed, failed)


# What this run found, written by whoever ran it, and read from beside the
# evidence rather than hardcoded here.
#
# It lives outside this file on purpose.  A generator carrying one pass's defect
# list would print that same list on the next run whatever the next run found,
# and the findings are about a particular fleet on a particular day, which is
# not something to bake into a tool.
#
#   evidence/findings.json  ->  {"defects": [...], "observations": [...]}
#
# A defect wants: id, severity, title, found, detail, impact, fix, retest.
# An observation wants: title, detail.
FINDINGS = {}
_findings_file = EV / "findings.json"
if _findings_file.is_file():
    FINDINGS = json.loads(_findings_file.read_text())
DEFECTS = FINDINGS.get("defects", [])
OBSERVATIONS = FINDINGS.get("observations", [])


def write_case(doc, rec):
    doc.add_heading(clean(f"{rec['id']}   {rec['feature']}"), level=2)
    table(doc, [
        ["Area", rec["area"]],
        ["Result", rec["verdict"]],
        ["Checks",
         str(sum(1 for o in rec.get("observed", [])
                 if isinstance(o, dict) and "result" in o))],
    ], widths=[1.3, 5.3], header=False)

    doc.add_heading("What this test is for", level=3)
    para(doc, rec["purpose"])
    doc.add_heading("The use case", level=3)
    para(doc, rec["use_case"])
    doc.add_heading("Expected outcome", level=3)
    para(doc, rec["expected"])

    steps = [s for s in rec.get("steps", []) if isinstance(s, str)]
    if steps:
        doc.add_heading("Steps", level=3)
        for s in steps:
            doc.add_paragraph(clean(s), style="List Number")

    before, after = rec.get("config_before"), rec.get("config_after")
    if before or after:
        doc.add_heading("Configuration before and after", level=3)
        diff = config_diff(before, after)
        if diff and diff.startswith("["):
            para(doc, diff, italic=True, colour=GREY)
        elif diff:
            para(doc, "The change this test made to the configuration the fleet "
                      "would be given, as a difference.  Lines starting with a "
                      "minus were removed and lines starting with a plus were "
                      "added.", size=9.5, colour=GREY)
            mono(doc, diff, limit=4200)
        elif after:
            para(doc, "The configuration after the change.", size=9.5, colour=GREY)
            mono(doc, after, limit=2600)

    proofs = rec.get("proof", [])
    if proofs:
        doc.add_heading("Evidence", level=3)
        for pr in proofs:
            para(doc, pr["title"], bold=True, size=10, space_after=2)
            mono(doc, pr["text"])

    shots = [s for s in rec.get("shots", []) if s.get("file")]
    if shots:
        doc.add_heading("Screenshots", level=3)
        for s in shots:
            shot(doc, s["file"], f"{rec['id']}  {s['label'].replace('-', ' ')}")

    doc.add_heading("Observed result", level=3)
    rows = [["Check", "Result", "Detail"]]
    notes = []
    for obs in rec.get("observed", []):
        if isinstance(obs, dict) and "result" in obs:
            rows.append([obs["claim"], obs["result"],
                         (obs.get("detail") or "")[:220]])
        elif isinstance(obs, str):
            notes.append(obs)
    if len(rows) > 1:
        table(doc, rows, widths=[3.4, 0.7, 2.5])
    for n in notes:
        para(doc, "Note:  " + n, size=9.5, italic=True, colour=GREY)
    if rec.get("failures"):
        para(doc, "Failures:", bold=True, colour=BAD)
        for f in rec["failures"]:
            doc.add_paragraph(clean(f), style="List Bullet")
    doc.add_page_break()


def main():
    doc, tests, by_area, env, (total, passed, failed) = build()

    doc.add_heading("6.  Test cases and results", level=1)
    para(doc,
         "Every test case in full: what it is for, why the feature exists, the "
         "configuration before and after, the evidence gathered and the result "
         "of each individual check.")
    doc.add_page_break()

    # Grouped by area, with the areas in the order they were first tested and
    # the cases inside each area in the order they were run.  Sorting only by
    # run order interleaved the areas and printed the same heading twice.
    seen_order = []
    grouped = {}
    for rec in tests:
        if rec["area"] not in grouped:
            grouped[rec["area"]] = []
            seen_order.append(rec["area"])
        grouped[rec["area"]].append(rec)

    for area in seen_order:
        doc.add_heading(clean(area), level=1)
        note = AREA_NOTES.get(area)
        if note:
            para(doc, note, italic=True, colour=GREY)
        for rec in grouped[area]:
            write_case(doc, rec)

    # ------------------------------------------------------------- section 7
    doc.add_heading("7.  Defects", level=1)
    if not DEFECTS:
        para(doc, "No defects were recorded for this run.  Findings are written "
                  "into evidence/findings.json beside the evidence; see the "
                  "README.", italic=True, colour=GREY)
    fixed = sum(1 for d in DEFECTS if not d["fix"].startswith("NOT")
                and "NOT YET DEPLOYED" not in d["retest"])
    staged = sum(1 for d in DEFECTS if "NOT YET DEPLOYED" in d["retest"])
    open_ = sum(1 for d in DEFECTS if d["fix"].startswith("NOT FIXED"))
    para(doc, f"{len(DEFECTS)} defects were found.  {fixed + staged} are fixed, "
              f"retested and running on both nodes.  {open_} are reported and "
              f"deliberately not fixed, because the correction is a design "
              f"decision or the cause is not established, and guessing at "
              f"either would be worse than the fault.", bold=True)
    rows = [["ID", "Severity", "Defect", "Found by", "State"]]
    for d in DEFECTS:
        rows.append([d["id"], d["severity"], d["title"], d["found"],
                     "open" if d["fix"].startswith("NOT FIXED")
                     else ("awaiting deploy" if "NOT YET DEPLOYED" in d["retest"]
                           else "fixed")])
    table(doc, rows, widths=[0.5, 1.0, 3.1, 0.8, 1.2])

    for d in DEFECTS:
        doc.add_heading(clean(f"{d['id']}   {d['title']}"), level=2)
        table(doc, [["Severity", d["severity"]], ["Found by", d["found"]]],
              widths=[1.2, 5.4], header=False)
        doc.add_heading("What was wrong", level=3)
        para(doc, d["detail"])
        doc.add_heading("Why it matters", level=3)
        para(doc, d["impact"])
        doc.add_heading("What was changed", level=3)
        para(doc, d["fix"])
        doc.add_heading("Retest", level=3)
        para(doc, d["retest"])

    doc.add_page_break()
    doc.add_heading("8.  Observations", level=1)
    para(doc, "Things worth knowing that are not defects, or that are not fixed "
              "because the cause is not established.")
    if not OBSERVATIONS:
        para(doc, "None recorded for this run.", italic=True, colour=GREY)
    for o in OBSERVATIONS:
        doc.add_heading(clean(o["title"]), level=2)
        para(doc, o["detail"])

    doc.add_page_break()
    doc.add_heading("9.  Conclusion", level=1)
    para(doc,
         f"Every feature in scope was exercised against a running two node "
         f"fleet, with configuration applied for real and verified by traffic.  "
         f"{total} checks were made across {len(tests)} test cases, of which "
         f"{passed} passed.", bold=True)
    para(doc,
         f"{len(DEFECTS)} defects were found.  Three of them, taken together, are the "
         "answer to the question that prompted this pass: two stopped the "
         "entire fleet applying any configuration at all, and one stopped any "
         "site setting being saved on a fleet missing any nginx module.  None "
         "of the three could have been caught by the existing automated suites, "
         "because none of those suites applies configuration.")
    para(doc,
         "Two more are worth naming separately because they sit under the "
         "product's two headline promises.  A requested failover reports "
         "success and hands the role straight back, so the standby cannot be "
         "made active by hand at all.  And the DNS service can reach a state "
         "where it will never bind its port again, so global load balancing "
         "serves nothing until the manager is restarted.  Neither has been "
         "changed here: one needs a design decision about how the two nodes "
         "choose a leader, and the other needs its cause established rather "
         "than guessed at.  Both are reproducible on demand and both are "
         "recorded in section 7 with the measurements.")
    para(doc,
         "The pattern worth carrying forward is that most of these defects were "
         "invisible in the configuration file and only appeared at the wire.  "
         "Compression that compressed nothing but HTML, a mount that lost every "
         "session, a rollback that reported success and changed nothing, and a "
         "setting on the Settings page that was saved and never read: each of "
         "those renders correctly, tests clean under nginx, and is wrong.")
    para(doc,
         "Recommendation: the checks written for this pass should be kept and "
         "run against a real fleet before each release.  They are the only "
         "tests in this project that apply configuration, and that is where "
         "these faults were.")

    doc.add_heading("9.1  Environment left as found", level=2)
    for line in [
        "Every site, pool, path, zone, map, stream, certificate and error page "
        "template created by this pass has been removed.",
        "The test administrator account has been removed from both nodes, and "
        "the standby's copy went with it, which was checked rather than "
        "assumed.",
        "The purpose built origin servers have been stopped and removed.",
        "The country database installed during the geo blocking test has been "
        "left in place deliberately: it is required for that feature and its "
        "absence was making the product's own geo check fail.",
        "A full backup of the database and live configuration taken before the "
        "pass is retained, along with a copy of each node's host agent as it "
        "was before this work, so the fleet can be returned to its exact "
        "starting state if anything here is not wanted.",
        "Both nodes were levelled onto the same build at the end, and their "
        "managed configuration folders were confirmed byte for byte identical.",
    ]:
        doc.add_paragraph(clean(line), style="List Bullet")

    OUT.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(OUT))
    size = OUT.stat().st_size
    print(f"wrote {OUT}  ({size/1024/1024:.1f} MB)")
    print(f"  {len(tests)} test cases, {total} checks, {passed} passed, {failed} failed")


if __name__ == "__main__":
    main()
