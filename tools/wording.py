#!/usr/bin/env python3
"""Acceptance criterion 11: no banned words in text a viewer can see.

Scanned: dashboards and navigation, every .conf of both apps (labels, descriptions, finding titles, annotations),
the agent prompt and schema, the playbook and its custom function, lookups, and the string literals of the app's
Python that produce notes, audit messages and approval text. "demo" is allowed inside object names
(zt_incident_demo, ztdemo, zt_demo_state ...) and in app.conf descriptions; README/docs are out of scope by design.
"""
import glob
import re
import sys

BANNED = re.compile(r"\b(sample|mock|mockup|fake|synthetic|illustrative|demo)\b", re.I)
IDENT_WITH_DEMO = re.compile(r"[A-Za-z0-9_\-\.]*demo[A-Za-z0-9_\-\.]*", re.I)

FILES = (
    glob.glob("zt_incident_demo/default/data/ui/**/*.xml", recursive=True)
    + glob.glob("zt_incident_demo/default/*.conf")
    + glob.glob("DA-ESS-zt_incident_demo/default/*.conf")
    + glob.glob("agent/*.md") + glob.glob("agent/*.json") + glob.glob("agent/mcp_tools/*.json")
    + glob.glob("soar/zt_quarantine_workload/*.py") + glob.glob("soar/zt_quarantine_workload/custom_functions/*")
    + glob.glob("zt_incident_demo/lookups/*.csv")
    + glob.glob("zt_incident_demo/bin/*.py") + glob.glob("zt_incident_demo/bin/ztgen/*.py")
)


def visible_hit(path, line):
    m = BANNED.search(line)
    if not m:
        return None
    word = m.group(1).lower()
    if word == "demo":
        if path.endswith("app.conf"):
            return None
        if not re.search(r"\bdemo\b", IDENT_WITH_DEMO.sub("", line), re.I):
            return None
        if path.endswith(".py") and not re.search(r"""["'].*\bdemo\b.*["']""", IDENT_WITH_DEMO.sub("", line), re.I):
            return None  # code comments and identifiers are not visible text
    elif path.endswith(".py") and line.lstrip().startswith("#"):
        return None
    return word


def main():
    hits = 0
    for path in sorted(set(FILES)):
        with open(path, errors="replace") as fh:
            for n, line in enumerate(fh, 1):
                word = visible_hit(path, line)
                if word:
                    hits += 1
                    print("%s:%d: [%s] %s" % (path, n, word, line.strip()[:140]))
    print("wording: %d file(s) scanned, %d hit(s) -> %s" % (len(set(FILES)), hits, "PASS" if hits == 0 else "FAIL"))
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main())
