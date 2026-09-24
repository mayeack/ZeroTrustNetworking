#!/usr/bin/env python3
"""make reset-hard: empty the zero_trust and zt_summary indexes on the stack (delete + re-create), clear the demo state and
backfill again. Asks for confirmation. Splunk Cloud has no `splunk clean eventdata`; recreating the indexes is the equivalent."""
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402
from indexes import INDEXES, MGR  # noqa: E402


def main(argv):
    if "--yes" not in argv:
        ans = input("This deletes and re-creates zero_trust and zt_summary on %s and backfills 24 hours. Type YES to continue: " % ztrest.env("SPLUNK_URL"))
        if ans.strip() != "YES":
            print("aborted")
            return 1
    s = ztrest.Splunk()
    s.search("| ztdemo action=reset", earliest="-1m", latest="now", timeout=300)
    for name in INDEXES:
        try:
            s.delete(MGR + "/" + name)
            print("index %s deleted" % name)
        except ztrest.RestError as e:
            print("delete %s: %s" % (name, str(e)[:120]))
    time.sleep(20)
    for name, settings in INDEXES.items():
        data = {"name": name, "datatype": "event"}
        data.update(settings)
        s.post(MGR, data=data)
        print("index %s created" % name)
    st = s.kv_get("zt_demo_state", "global") or {"_key": "global"}
    st.update({"backfill_done": 0, "stream_checkpoint": 0, "backfill_lock_epoch": 0, "backfill_lock_owner": ""})
    s.kv_upsert("zt_demo_state", st)
    print("state cleared; the next stream tick backfills 24 hours (or run make backfill)")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
