#!/usr/bin/env python3
"""Generate the CSV lookups of the main app and the ES asset lookup from the estate model."""
import csv
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "zt_incident_demo", "bin"))
from ztgen import canon, estate as E  # noqa: E402

APP_LOOKUPS = os.path.join(ROOT, "zt_incident_demo", "lookups")
DA_LOOKUPS = os.path.join(ROOT, "DA-ESS-zt_incident_demo", "lookups")


def write(path, header, rows):
    with open(path, "w", newline="") as fh:
        w = csv.writer(fh, lineterminator="\n")
        w.writerow(header)
        w.writerows(rows)


def main():
    e = E.get_estate()
    for name, (header, rows) in E.lookup_rows(e).items():
        write(os.path.join(APP_LOOKUPS, name + ".csv"), header, rows)
        print("%-24s %5d rows" % (name + ".csv", len(rows)))
    # ES assets (ES asset header)
    header = ["ip", "mac", "nt_host", "dns", "owner", "priority", "lat", "long", "city", "country", "bunit", "category", "pci_domain", "is_expected", "should_timesync", "should_update", "requires_av"]
    rows = []
    prio = {"ai-train/checkpoint-store": "critical", "ai-train/dataset-cache": "high", "ai-infer/model-registry": "high", "ai-infer/vector-index": "high"}
    for key, meta in e.stores.items():
        w = e.workloads[key]
        cat = "k8s_workload|ai_data_store" + ("|crown_jewel" if meta["data_class"] == "crown-jewel" else "")
        rows.append(["", "", key, "%s.%s.svc" % (w.name, w.namespace), meta["owner"], prio[key], "", "", "", "", w.team, cat, "untrust", "true", "false", "false", "false"])
    rows.append(["", "", canon.RUNNER_WORKLOAD, "ci-runner.build-farm.svc", canon.RUNNER_OWNER, "medium", "", "", "", "", "platform-build", "k8s_workload|ci_runner", "untrust", "true", "false", "false", "false"])
    for nname in (canon.RUNNER_NODE, canon.STORE_NODE):
        n = e.nodes[nname]
        rows.append([n.ip, n.mac, n.name, n.name + ".corp.internal", "platform", "high" if nname == canon.STORE_NODE else "medium", "", "", "", "", "platform", "kubernetes_node|" + n.role, "untrust", "true", "true", "false", "false"])
    write(os.path.join(DA_LOOKUPS, "zt_es_assets.csv"), header, rows)
    print("%-24s %5d rows" % ("zt_es_assets.csv", len(rows)))


if __name__ == "__main__":
    main()
