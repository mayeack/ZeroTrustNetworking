#!/usr/bin/env python3
"""Run | ztdemo actions on the stack and print the result. Usage: ztctl.py status|fire|reset|backfill|tick|speed <v>|config k=v"""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

sys.path.insert(0, os.path.join(ztrest.ROOT, "zt_incident_demo", "bin"))
from ztgen import schedule as S  # noqa: E402


def run(s, spl, timeout=1800):
    rows = s.search(spl, earliest="-1m", latest="now", timeout=timeout)
    for r in rows:
        for k in sorted(r):
            if not k.startswith("_") or k == "_time":
                print("%-24s %s" % (k, r[k]))
    return rows


def counts_table(s, earliest, latest):
    rows = s.search("search index=zero_trust earliest=%s latest=%s | stats count by sourcetype" % (earliest, latest), earliest=earliest, latest=latest, timeout=600)
    got = {r["sourcetype"]: int(r["count"]) for r in rows}
    exp = S.daily_expectations()
    out = []
    ok = True
    for st, n in exp.items():
        g = got.get(st, 0)
        if n is None:
            state = "ok" if g > 0 else "MISSING"
        else:
            state = "ok" if g == n else "MISMATCH"
        ok = ok and state == "ok"
        out.append((state, st, g, n if n is not None else "2 or 3 per job"))
    print(ztrest.table(out, ["", "sourcetype", "got", "expected"]))
    return ok


def main(argv):
    s = ztrest.Splunk()
    act = argv[0] if argv else "status"
    if act in ("status", "fire", "reset", "tick"):
        run(s, "| ztdemo action=%s" % act, timeout=900)
    elif act == "backfill":
        rows = run(s, "| ztdemo action=backfill hours=%s%s" % (os.environ.get("HOURS", "24"), " force=true" if os.environ.get("FORCE") else ""), timeout=3600)
        st = s.entry("services/search/jobs") and None
        time.sleep(20)
        cp = float(s.kv_get("zt_demo_state", "global").get("stream_checkpoint") or time.time())
        print("\ncounts over [checkpoint-24h, checkpoint] (checkpoint %s)" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(cp)))
        counts_table(s, str(cp - 86400), str(cp))
    elif act == "speed":
        run(s, "| ztdemo action=speed value=%s" % argv[1])
    elif act == "config":
        run(s, "| ztdemo action=config " + " ".join(argv[1:]))
    elif act == "counts":
        cp = float(s.kv_get("zt_demo_state", "global").get("stream_checkpoint") or time.time())
        counts_table(s, str(cp - 86400), str(cp))
    else:
        print("unknown action", act)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
