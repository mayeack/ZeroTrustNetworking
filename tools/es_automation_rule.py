#!/usr/bin/env python3
"""make es-automation-rule: ES 8.7 automation rule 'Zero Trust Protected Paths' that starts the SOAR playbook
zt_quarantine_workload when the ZT finding-based detection creates a finding (Mode A). Idempotent."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

RULE = "Zero Trust Protected Paths"
DETECTION = "ZT - Workload Exceeded Risk Threshold on Protected-Path Signals - Rule"
APP = "DA-ESS-zt_incident_demo"
PLAYBOOK = "zt_quarantine_workload"
EP = "servicesNS/nobody/missioncontrol/v1/automation_rule"


def main(argv):
    s = ztrest.Splunk()
    rules = s.get(EP, params={"output_mode": None})
    existing = rules.get(RULE) if isinstance(rules, dict) else None
    # ES assigns the per-detection ids itself; the existing rule keeps its ids
    det_id = None
    if existing:
        for d in existing.get("detections") or []:
            if d.get("detection_name") == DETECTION:
                det_id = d.get("id")
    det = {"detection_name": DETECTION, "app_name": APP}
    if det_id:
        det["id"] = det_id
    body = {"name": RULE, "status": "on", "trigger": "finding_created", "detections": [det], "ingestions": {"soar_assets": []}, "playbooks": [{"repo": "local", "playbook_name": PLAYBOOK}]}
    if "--dry-run" in argv:
        print(json.dumps(body, indent=1))
        return 0
    if existing:
        try:
            s.request("PUT", EP + "/" + ztrest.urllib.parse.quote(RULE, safe=""), json_body=body)
            print("automation rule %s updated (detection id %s)" % (RULE, det_id))
        except ztrest.RestError:
            s.post(EP + "/" + ztrest.urllib.parse.quote(RULE, safe=""), json_body=body)
            print("automation rule %s updated via POST" % RULE)
    else:
        s.post(EP, json_body=body)
        print("automation rule %s created (detection id %s)" % (RULE, det_id))
    rules = s.get(EP, params={"output_mode": None})
    print(json.dumps(rules.get(RULE), indent=1)[:600] if isinstance(rules, dict) else rules)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
