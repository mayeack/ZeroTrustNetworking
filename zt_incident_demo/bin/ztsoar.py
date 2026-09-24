#!/usr/bin/env python3
"""| ztsoar action=request|approve|reject|verify|status [request_id=...] [comment="..."]  (Mode B: local approvals)"""
import json
import os
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import GeneratingCommand, Configuration, Option, dispatch  # noqa: E402
from ztgen import response as R, state as ST  # noqa: E402
from ztgen.restclient import Splunkd, RestError  # noqa: E402
from ztgen.streamer import make_hec, setup_logging  # noqa: E402


@Configuration(type="reporting")
class ZtSoarCommand(GeneratingCommand):
    action = Option(require=True)
    request_id = Option(require=False, default=None)
    comment = Option(require=False, default="")

    def _sd(self):
        si = self._metadata.searchinfo
        return Splunkd(si.splunkd_uri, session_key=si.session_key)

    def generate(self):
        setup_logging()
        sd = self._sd()
        act = (self.action or "").lower()
        now = time.time()
        try:
            if act == "request":
                for row in self.request(sd, now):
                    yield row
            elif act in ("approve", "reject"):
                yield self.decide(sd, act)
            elif act == "verify":
                for row in self.verify(sd, now):
                    yield row
            elif act == "status":
                for r in sd.kv_query(R.REQUESTS):
                    yield {"_time": r.get("requested_epoch") or now, "request_id": r.get("request_id"), "status": r.get("status"), "finding_id": r.get("finding_id"),
                           "investigation_id": r.get("investigation_id"), "workload": r.get("workload"), "pod": r.get("pod"), "enforcement_point": r.get("enforcement_point"),
                           "action": r.get("action"), "policy_name": r.get("policy_name"), "approvals": r.get("approvals"), "approver_labels": r.get("approver_labels"),
                           "applied_epoch": r.get("applied_epoch"), "verified_epoch": r.get("verified_epoch"), "last_error": r.get("last_error")}
            else:
                yield {"_time": now, "action": act, "result": "unknown action; use request|approve|reject|verify|status"}
        except (RestError, ValueError) as e:
            yield {"_time": now, "action": act, "result": "error", "message": str(e)[:500]}

    def request(self, sd, now):
        st = ST.load(sd)
        if st["response_mode"] != "local":
            yield {"_time": now, "action": "request", "result": "skipped: response_mode=%s" % st["response_mode"]}
            return
        cfg = ST.config(sd)
        hec = None
        existing = {r.get("finding_id") for r in sd.kv_query(R.REQUESTS)}
        made = 0
        for brief in sd.kv_query(R.BRIEFS, {"disposition": "true_positive"}):
            if not brief.get("finding_id") or brief["finding_id"] in existing or float(brief.get("run_epoch") or 0) < float(st["last_reset_epoch"] or 0):
                continue
            hec = hec or make_hec(sd, cfg)
            req = R.create_request(sd, hec, brief, now)
            made += 1
            yield {"_time": now, "action": "request", "result": "requested", "request_id": req["request_id"], "finding_id": req["finding_id"], "investigation_id": req["investigation_id"],
                   "policy_name": req["policy_name"], "approvers_needed": req["approver_labels"], "message": R.approval_message(req)}
        if not made:
            yield {"_time": now, "action": "request", "result": "nothing new (%d request(s) on file)" % len(existing)}

    def decide(self, sd, act):
        if not self.request_id:
            raise ValueError("request_id is required")
        si = self._metadata.searchinfo
        st, body = sd.request("POST", "services/zt_incident_demo/approvals", json_body={"action": act, "request_id": self.request_id, "comment": self.comment or ""}, raw=True)
        try:
            data = json.loads(body)
        except ValueError:
            data = {"message": body[:400]}
        return dict({"_time": time.time(), "action": act, "request_id": self.request_id, "http_status": st, "user": si.username}, **{k: v for k, v in data.items() if k != "request"})

    def verify(self, sd, now):
        cfg = ST.config(sd)
        hec = None
        rows = 0
        for req in sd.kv_query(R.REQUESTS, {"status": "applied"}):
            hec = hec or make_hec(sd, cfg)
            state, msg = R.verify(sd, hec, req, now)
            rows += 1
            yield {"_time": now, "action": "verify", "request_id": req["request_id"], "result": state, "message": msg}
        if not rows:
            yield {"_time": now, "action": "verify", "result": "nothing to verify"}


dispatch(ZtSoarCommand, sys.argv, sys.stdin, sys.stdout, __name__)
