#!/usr/bin/env python3
"""Run every data source of every Dashboard Studio view on the stack and report errors and row counts.

Tokens are filled with realistic values: $incident$ = the newest incident (from the timeline's own incident search),
the posture inputs with their defaults. Use after `make sync-objects`; exit code 1 when any query fails."""
import glob
import json
import os
import re
import sys

sys.path.insert(0, os.path.dirname(__file__))
import ztrest  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
TOKENS = {"time.earliest": "-24h", "time.latest": "now", "store": "*", "ns": ""}


def fill(text, tokens):
    return re.sub(r"\$([A-Za-z0-9_.]+)\$", lambda m: tokens.get(m.group(1), m.group(0)), text)


def main(argv):
    s = ztrest.Splunk()
    tokens = dict(TOKENS)
    inc = s.search('index=zero_trust sourcetype=ci:job:event build_id=88213 build_status=running | stats count by _time | sort 0 - _time | streamstats current=f last(_time) as next_start | eval start=_time-60, end=if(isnotnull(next_start), tostring(next_start-60), "now"), value="earliest=".start." latest=".end | head 1 | table value', earliest="-30d", latest="now")
    tokens["incident"] = inc[0]["value"] if inc else "earliest=0 latest=1"
    print("incident token: %s" % tokens["incident"])
    failed = 0
    for path in sorted(glob.glob(os.path.join(ROOT, "zt_incident_demo", "default", "data", "ui", "views", "*.xml"))):
        x = open(path).read()
        m = re.search(r"<definition><!\[CDATA\[(.*)\]\]></definition>", x, re.S)
        if not m:
            continue  # Simple XML views are exercised by the smoke run
        d = json.loads(m.group(1))
        print("\n%s (%d data sources)" % (os.path.basename(path), len(d["dataSources"])))
        for name, ds in d["dataSources"].items():
            q = fill(ds["options"]["query"], tokens)
            qp = ds["options"].get("queryParameters", {})
            earliest = fill(qp.get("earliest", "-24h"), tokens)
            latest = fill(qp.get("latest", "now"), tokens)
            if "$" in q and re.search(r"\$[A-Za-z0-9_.]+\$", q):
                print("  %-22s SKIP  unresolved token %s" % (name, re.findall(r"\$[A-Za-z0-9_.]+\$", q)[:3]))
                continue
            try:
                rows = s.search(q if q.lstrip().startswith("|") else ("search " + q if not q.lstrip().startswith("search ") else q), earliest=earliest, latest=latest, timeout=300)
                first = {k: (v[:60] if isinstance(v, str) else v) for k, v in (rows[0].items() if rows else [])}
                print("  %-22s ok    %3d rows  %s" % (name, len(rows), json.dumps(first, ensure_ascii=False)[:150]))
            except Exception as e:  # noqa: BLE001
                failed += 1
                print("  %-22s FAIL  %s" % (name, str(e)[:300]))
    print("\n%d failing data source(s)" % failed)
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
