#!/usr/bin/env python3
"""make indexes: create zero_trust and zt_summary on Splunk Cloud (idempotent)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

# Splunk Cloud sizes indexes by raw data (maxGlobalRawDataSizeMB, 0 = unlimited); maxTotalDataSizeMB is managed by the platform.
INDEXES = {
    "zero_trust": {"frozenTimePeriodInSecs": 1209600, "maxGlobalRawDataSizeMB": 20000},
    "zt_summary": {"frozenTimePeriodInSecs": 7776000, "maxGlobalRawDataSizeMB": 5000},
}
MGR = "services/cluster_blaster_indexes/sh_indexes_manager"


def main():
    s = ztrest.Splunk()
    existing = {e["name"]: e["content"] for e in s.entries(MGR)}
    for name, settings in INDEXES.items():
        if name in existing:
            print("index %-12s present (frozen %ss, max raw %s MB)" % (name, existing[name].get("frozenTimePeriodInSecs"), existing[name].get("maxGlobalRawDataSizeMB")))
            continue
        data = {"name": name, "datatype": "event"}
        data.update(settings)
        s.post(MGR, data=data)
        print("index %-12s created" % name)
    return 0


if __name__ == "__main__":
    sys.exit(main())
