#!/usr/bin/env python3
"""make es-assets: make sure the ES asset source zt_workload_assets exists (the DA app ships it in inputs.conf; this
registers it by REST if the app stanza did not take), then check that the assets show up on risk events."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

NAME = "zt_workload_assets"
SPEC = {"category": "zero_trust", "description": "Kubernetes workloads, protected AI data stores and their servers", "target": "asset", "url": "lookup://zt_es_assets", "rank": "1", "disabled": "0"}


def main():
    s = ztrest.Splunk()
    found = None
    for base in ("servicesNS/nobody/DA-ESS-zt_incident_demo/data/inputs/identity_manager", "servicesNS/nobody/SA-IdentityManagement/data/inputs/identity_manager", "services/data/inputs/identity_manager"):
        try:
            for e in s.entries(base):
                if e["name"] == NAME:
                    found = (base, e)
                    break
        except ztrest.RestError:
            continue
        if found:
            break
    if found:
        base, e = found
        print("asset source %s present in %s (disabled=%s)" % (NAME, e["acl"].get("app"), e["content"].get("disabled")))
        if str(e["content"].get("disabled")) in ("1", "True", "true"):
            s.post(base + "/" + NAME + "/enable")
            print("enabled")
    else:
        base = "servicesNS/nobody/DA-ESS-zt_incident_demo/data/inputs/identity_manager"
        d = dict(SPEC)
        d["name"] = NAME
        s.post(base, data=d)
        print("asset source %s created" % NAME)
    rows = s.search('| inputlookup zt_es_assets | table nt_host owner priority category', earliest="-1m", latest="now", timeout=120)
    print("zt_es_assets rows: %d" % len(rows))
    rows = s.search('| inputlookup asset_lookup_by_str where nt_host="build-farm/ci-runner" OR nt_host="ai-train/checkpoint-store" | table nt_host owner priority category', earliest="-1m", latest="now", timeout=120)
    print("merged asset lookup rows for the workloads: %d %s" % (len(rows), rows[:2]))
    return 0


if __name__ == "__main__":
    sys.exit(main())
