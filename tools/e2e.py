#!/usr/bin/env python3
"""End-to-end test log. `e2e.py log RUN STEP RESULT "action" "observed"` appends one step (RESULT: PASS, FAIL, INFO,
BLOCKED) to local/e2e/RUN.jsonl; `e2e.py q "SPL" [earliest]` prints search rows as JSON for evidence;
`e2e.py show RUN` prints the run as a table."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

DIR = os.path.join(ztrest.ROOT, "local", "e2e")


def log(run, step, result, action, observed):
    os.makedirs(DIR, exist_ok=True)
    rec = {"t": time.time(), "utc": time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), "step": step, "result": result.upper(), "action": action, "observed": observed}
    with open(os.path.join(DIR, run + ".jsonl"), "a") as fh:
        fh.write(json.dumps(rec) + "\n")
    print("%s  %-6s %-6s %s" % (rec["utc"], step, rec["result"], observed[:150]))


def query(spl, earliest="-24h"):
    rows = ztrest.Splunk().search(spl, earliest=earliest, latest="now", timeout=300)
    print(json.dumps(rows, indent=1)[:6000])


def show(run):
    with open(os.path.join(DIR, run + ".jsonl")) as fh:
        for line in fh:
            r = json.loads(line)
            print("%s  %-6s %-7s %-60s | %s" % (r["utc"][11:], r["step"], r["result"], r["action"][:60], r["observed"][:110]))


if __name__ == "__main__":
    a = sys.argv[1:]
    if a and a[0] == "log" and len(a) >= 6:
        log(a[1], a[2], a[3], a[4], a[5])
    elif a and a[0] == "q":
        query(a[1], a[2] if len(a) > 2 else "-24h")
    elif a and a[0] == "show":
        show(a[1])
    else:
        print(__doc__)
