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
    # ES 8.7: POST v1/automation_rule with action=add creates or updates the mappings of a rule (name, trigger, detections, playbooks)
    body = {"automation_rule_name": RULE, "action": "add", "name": RULE, "status": "on", "trigger": "finding_created",
            "detections": [{"detection_name": DETECTION, "app_name": APP}], "ingestions": {"soar_assets": []}, "playbooks": [{"repo": "local", "playbook_name": PLAYBOOK}]}
    if "--dry-run" in argv:
        print(json.dumps(body, indent=1))
        return 0
    out = s.post(EP, json_body=body)
    res = out.get("results", {}) if isinstance(out, dict) else {}
    print("automation rule %s %s: %s" % (RULE, "updated" if existing else "created", out.get("message") if isinstance(out, dict) else out))
    for kind in ("detections", "playbooks"):
        r = res.get(kind, {})
        print("  %-10s ok=%s failed=%s" % (kind, r.get("success"), r.get("failed")))
    rules = s.get(EP, params={"output_mode": None})
    print(json.dumps(rules.get(RULE), indent=1)[:600] if isinstance(rules, dict) and rules.get(RULE) else "rule not listed yet by v1/automation_rule")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
