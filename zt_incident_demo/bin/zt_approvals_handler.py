#!/usr/bin/env python3
"""POST /services/zt_incident_demo/approvals  {"action": "approve"|"reject", "request_id": "...", "comment": "..."}
The approver is the authenticated caller; the decision is checked against the approval matrix and recorded, and the
quarantine is applied with system privileges through the Kubernetes API emulator. GET lists pending requests."""
import json
import os
import sys
import threading
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402
from ztgen import response as R, state as ST  # noqa: E402
from ztgen.restclient import Splunkd, RestError, local_splunkd_uri  # noqa: E402
from ztgen.streamer import make_hec, setup_logging  # noqa: E402


class ApprovalsHandler(PersistentServerConnectionApplication):
    def __init__(self, command_line, command_arg):
        super().__init__()
        self.log = setup_logging()

    def _reply(self, status, payload):
        return {"status": status, "payload": json.dumps(payload), "headers": {"Content-Type": "application/json"}}

    def handle(self, in_string):
        try:
            req = json.loads(in_string)
        except ValueError:
            return self._reply(400, {"message": "invalid request"})
        method = (req.get("method") or "GET").upper()
        session = req.get("session") or {}
        user = session.get("user") or ""
        system_key = req.get("system_authtoken") or session.get("authtoken")
        uri = ((req.get("server") or {}).get("rest_uri") or local_splunkd_uri()).rstrip("/")
        sd = Splunkd(uri, session_key=system_key)
        try:
            if method == "GET":
                roles = R.user_roles(sd, user) if user else []
                return self._reply(200, {"user": user, "role_label": R.user_label(user, roles), "roles": roles,
                                         "pending": [{k: r.get(k) for k in ("request_id", "finding_id", "investigation_id", "workload", "pod", "enforcement_point", "action", "policy_name", "approver_labels", "requested_epoch")} for r in R.pending_requests(sd)]})
            if method != "POST":
                return self._reply(405, {"message": "method not allowed"})
            payload = req.get("payload") or ""
            try:
                body = json.loads(payload) if payload else {}
            except ValueError:
                body = {}
            form = dict(req.get("form") or [])
            action = (body.get("action") or form.get("action") or "").lower()
            request_id = body.get("request_id") or form.get("request_id") or ""
            comment = body.get("comment") or form.get("comment") or ""
            if action not in ("approve", "reject") or not request_id:
                return self._reply(400, {"message": "action (approve|reject) and request_id are required"})
            recs = sd.kv_query(R.REQUESTS, {"request_id": request_id})
            if not recs:
                return self._reply(404, {"message": "request %s not found" % request_id})
            request = recs[0]
            cfg = ST.config(sd)
            hec = make_hec(sd, cfg)
            roles = R.user_roles(sd, user)
            status, message, request = R.decide(sd, hec, request, user, roles, action, comment)
            out = {"message": message, "request_id": request_id, "status": request.get("status"), "approver": user, "approver_role": R.user_label(user, roles)}
            if status == 200 and request.get("status") == "approved":
                ok, msg = R.apply(sd, hec, cfg, request, user_agent="zt-approvals/1.0")
                out["apply"] = msg
                out["status"] = request.get("status")
                if ok:
                    threading.Thread(target=self._poll_verify, args=(uri, system_key, request["request_id"]), daemon=True).start()
            return self._reply(status, out)
        except RestError as e:
            self.log.error("approvals handler: %s", e)
            return self._reply(502, {"message": str(e)[:500]})
        except Exception as e:  # noqa: BLE001
            self.log.exception("approvals handler failed")
            return self._reply(500, {"message": str(e)[:500]})

    def _poll_verify(self, uri, system_key, request_id):
        """15-second verification poll for up to 3 minutes after apply."""
        sd = Splunkd(uri, session_key=system_key)
        try:
            cfg = ST.config(sd)
            hec = make_hec(sd, cfg)
            deadline = time.time() + R.VERIFY_TIMEOUT + 20
            while time.time() < deadline:
                time.sleep(15)
                recs = sd.kv_query(R.REQUESTS, {"request_id": request_id})
                if not recs or recs[0].get("status") != "applied":
                    return
                state, msg = R.verify(sd, hec, recs[0])
                self.log.info("verify %s: %s %s", request_id, state, msg)
                if state != "applied":
                    return
        except Exception as e:  # noqa: BLE001
            self.log.error("verification poll failed: %s", e)
