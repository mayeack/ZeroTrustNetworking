#!/usr/bin/env python3
"""| ztevidence : inline agent mode. For the newest zero trust finding group without a brief, run the five evidence
searches and return one row with the packed JSON field `evidence` (under 12 KB) plus the finding's identifiers."""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import GeneratingCommand, Configuration, dispatch  # noqa: E402
from ztgen import canon, es_api, response as R, state as ST  # noqa: E402
from ztgen.restclient import Splunkd, RestError  # noqa: E402

LIMIT = 12000


def pack(sections):
    """Trim rows until the JSON fits."""
    while True:
        text = json.dumps(sections, separators=(",", ":"))
        if len(text) <= LIMIT:
            return text
        biggest = max(sections, key=lambda k: len(json.dumps(sections[k])))
        if not sections[biggest]:
            return text[:LIMIT]
        sections[biggest] = sections[biggest][:-1]


@Configuration(type="reporting")
class ZtEvidenceCommand(GeneratingCommand):
    def generate(self):
        si = self._metadata.searchinfo
        sd = Splunkd(si.splunkd_uri, session_key=si.session_key)
        now = time.time()
        try:
            st = ST.load(sd)
            if st["agent_mode"] != "inline":
                return
            finding = es_api.newest_zt_finding(sd, canon.RULE_FBD, float(st["last_reset_epoch"] or 0))
            if not finding or sd.kv_get(R.BRIEFS, finding["event_id"]):
                return
            workload = finding.get("normalized_risk_object") or canon.RUNNER_WORKLOAD
            pod, node = canon.RUNNER_POD if workload == canon.RUNNER_WORKLOAD else "*", canon.RUNNER_NODE if workload == canon.RUNNER_WORKLOAD else "*"
            calls = [("zt_finding_context", 'ZT Agent - Finding Context', {"workload": workload}), ("zt_flow_evidence", 'ZT Agent - Flow Evidence', {"workload": workload, "dest": "*"}),
                     ("zt_process_evidence", 'ZT Agent - Process Evidence', {"pod": pod}), ("zt_ci_job_context", 'ZT Agent - CI Job Context', {"pod": pod}),
                     ("zt_workload_server_context", 'ZT Agent - Workload and Server Context', {"workload": workload, "node": node})]
            sections = {}
            for key, name, args in calls:
                spl = '| savedsearch "%s" %s' % (name, " ".join('%s="%s"' % (k, v) for k, v in args.items()))
                rows = sd.search(spl, earliest="-24h", latest="now", timeout=180)
                sections[key] = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows[:20]]
            if node == "*" and sections["zt_finding_context"]:
                fc = sections["zt_finding_context"][0]
                if fc.get("node") or fc.get("pod"):
                    pod2, node2 = fc.get("pod", pod).split(",")[0], fc.get("node", node).split(",")[0]
                    for key, name, args in calls[2:]:
                        args = {k: (pod2 if k == "pod" else node2 if k == "node" else v) for k, v in args.items()}
                        rows = sd.search('| savedsearch "%s" %s' % (name, " ".join('%s="%s"' % (k, v) for k, v in args.items())), earliest="-24h", latest="now", timeout=180)
                        sections[key] = [{k: v for k, v in r.items() if not k.startswith("_")} for r in rows[:20]]
            yield {"_time": now, "finding_id": finding["event_id"], "entity": workload, "evidence": pack(sections)}
        except RestError as e:
            yield {"_time": now, "error": str(e)[:400]}


dispatch(ZtEvidenceCommand, sys.argv, sys.stdin, sys.stdout, __name__)
