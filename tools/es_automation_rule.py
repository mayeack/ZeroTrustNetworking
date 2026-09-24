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
    # the detection id used by other rules is the correlationsearches KV key
    det_id = None
    for r in s.kv_list("correlationsearches", app="SA-ThreatIntelligence"):
        if r.get("_key") and (r.get("name") == DETECTION or r.get("search_name") == DETECTION or r.get("rule_name") == DETECTION):
            det_id = r["_key"]
            break
    if det_id is None:
        rows = s.search('| rest /servicesNS/nobody/SA-ThreatIntelligence/storage/collections/data/correlationsearches count=0 | search value="*%s*" | head 1' % DETECTION, earliest="-1m", latest="now")
        det_id = rows[0].get("_key") if rows else None
    body = {"name": RULE, "status": "on", "trigger": "finding_created", "detections": [{"detection_name": DETECTION, "app_name": APP, "id": det_id or DETECTION}],
            "ingestions": {"soar_assets": []}, "playbooks": [{"repo": "local", "playbook_name": PLAYBOOK}]}
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
