#!/usr/bin/env python3
"""Build docs/e2e_test_report.md (+ .html) from local/e2e/run*.jsonl and local/e2e/fixes.json."""
import glob
import json
import os
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
E2E = os.path.join(ROOT, "local", "e2e")
OUT = os.path.join(ROOT, "docs", "e2e_test_report.md")
PARTS = [("1", "Before the call"), ("2", "Step 2: two signals in Splunk"), ("3", "Step 3: one finding, one brief"), ("4", "Step 4: approve the quarantine (Mode B)"),
         ("5", "Step 5: verify and prove it"), ("6", "After the call"), ("A", "Mode A: the same incident through SOAR"), ("T", "Live generator triggers")]


def cell(s):
    return str(s).replace("|", "\\|").replace("\n", " ")


def load(run):
    with open(os.path.join(E2E, run + ".jsonl")) as fh:
        rows = [json.loads(line) for line in fh if line.strip()]
    last = {}
    for r in rows:  # a re-checked step replaces the earlier entry
        last[r["step"]] = r
    return rows, last


def section(run, title):
    rows, last = load(run)
    final = list(last.values())
    counts = {k: sum(1 for r in final if r["result"] == k) for k in ("PASS", "FAIL", "BLOCKED", "INFO")}
    out = ["## %s" % title, "",
           "%s to %s UTC. %d steps: %d passed, %d failed, %d blocked, %d notes." % (rows[0]["utc"], rows[-1]["utc"][11:], len(final), counts["PASS"], counts["FAIL"], counts["BLOCKED"], counts["INFO"]), ""]
    for key, name in PARTS:
        part = [r for r in final if r["step"].split(".")[0] == key]
        if not part:
            continue
        out += ["### %s" % name, "", "| Step | Time (UTC) | Action | Result | Observed |", "|---|---|---|---|---|"]
        for r in part:
            out.append("| %s | %s | %s | **%s** | %s |" % (r["step"], r["utc"][11:], cell(r["action"]), r["result"], cell(r["observed"])))
        out.append("")
    return out


def main(argv):
    runs = sorted(os.path.basename(p)[:-6] for p in glob.glob(os.path.join(E2E, "run*.jsonl")))
    fixes = json.load(open(os.path.join(E2E, "fixes.json"))) if os.path.exists(os.path.join(E2E, "fixes.json")) else []
    md = ["# End-to-end test of the demo flow", "",
          "Every step of `docs/demo_script.md` executed against the Splunk Cloud stack and SOAR Cloud, as a presenter would: the live generator page in a browser for fire, reset, mode and triggers; the searches and pages of the Zero Trust Incident app; Enterprise Security, Agent Launchpad and SOAR through the same searches and REST calls their pages use. Each run starts from a reset. A defect is fixed, then the test restarts from the beginning.", "",
          "The one step not performed by hand is signing in to Splunk Web or SOAR as `j.chen`: I do not type passwords into sign-in forms. j.chen's approval was sent to the same endpoint the Approve button calls (`POST /services/zt_incident_demo/approvals`, Mode B) and to the prompt API the SOAR Approve button uses (`POST /rest/approval/<id>`, Mode A), with j.chen's credentials.", ""]
    titles = {"run1": "Run 1", "run2": "Run 2 (after the fixes)", "run3": "Run 3"}
    for run in runs:
        md += section(run, titles.get(run, run))
    if fixes:
        md += ["## Defects found and fixed", "", "| Steps | Defect | Fix | Deployed through |", "|---|---|---|---|"]
        md += ["| %s | %s | %s | %s |" % (cell(f["steps"]), cell(f["defect"]), cell(f["fix"]), cell(f["where"])) for f in fixes]
        md.append("")
    with open(OUT, "w") as fh:
        fh.write("\n".join(md) + "\n")
    subprocess.run([sys.executable, os.path.join(ROOT, "tools", "md2html.py"), OUT], check=False, capture_output=True)
    print("wrote %s and %s" % (OUT, OUT[:-3] + ".html"))


if __name__ == "__main__":
    main(sys.argv[1:])
