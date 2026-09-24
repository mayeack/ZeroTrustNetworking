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


DET_COLLECTION = "detection_automation_rules"   # in SA-ThreatIntelligence: {detection_id, detection_name, app_name, automation_rule_name}
DETECTION_ID = "8b3e3a2a-5c4d-4f3e-9d8a-4b7c9e0f1a23"  # action.correlationsearch.metadata.detection_id of the ZT finding-based detection


def main(argv):
    s = ztrest.Splunk()
    # the add call takes playbooks as {"scm", "playbook"} (the GET reports {"repo", "playbook_name"})
    body = {"automation_rule_name": RULE, "action": "add", "detections": [{"detection_name": DETECTION, "app_name": APP}], "playbooks": [{"scm": "local", "playbook": PLAYBOOK}]}
    if "--dry-run" in argv:
        print(json.dumps(body, indent=1))
        return 0
    if "--off" in argv or "--on" in argv:
        state = "off" if "--off" in argv else "on"
        out = s.post(EP, json_body={"automation_rule_name": RULE, "action": state})
        print("automation rule %s -> %s: %s" % (RULE, state, json.dumps(out)[:200]))
        return 0
    # 1. the detection side: one KV record per detection in the rule (ES 8.7 stores the mapping here)
    recs = s.kv_list(DET_COLLECTION, app="SA-ThreatIntelligence", query={"automation_rule_name": RULE, "detection_name": DETECTION})
    if recs:
        print("detection mapping present (id %s)" % recs[0]["_key"])
    else:
        out = s.post(s.kv_path(DET_COLLECTION, app="SA-ThreatIntelligence"), json_body={"detection_id": DETECTION_ID, "detection_name": DETECTION, "app_name": APP, "automation_rule_name": RULE}, params={"output_mode": None})
        print("detection mapping created (id %s)" % (out.get("_key") if isinstance(out, dict) else out))
    # 2. the playbook side: the mapping call (idempotent) turns the rule on in SOAR and attaches the playbook
    out = s.post(EP, json_body=body)
    res = out.get("results", {}) if isinstance(out, dict) else {}
    print("playbook mapping: %s | playbooks ok=%s failed=%s" % (out.get("message") if isinstance(out, dict) else out, res.get("playbooks", {}).get("success"), res.get("playbooks", {}).get("failed")))
    rules = s.get(EP, params={"output_mode": None})
    data = rules.get("data", rules) if isinstance(rules, dict) else {}
    print("rule as ES lists it:", json.dumps(data.get(RULE), indent=1)[:700] if isinstance(data, dict) and data.get(RULE) else "NOT LISTED")
    soar_side = s.get("servicesNS/nobody/missioncontrol/v1/soar/automation_rule", params={"output_mode": None})
    print("rule as SOAR lists it:", json.dumps((soar_side.get("message") or {}).get(RULE)) if isinstance(soar_side, dict) else soar_side)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
