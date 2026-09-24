"""Mode B enforcement flow shared by the ztsoar command and the approvals REST handler:
request, approve/reject (with the approval matrix), apply through the Kubernetes API emulator, verify, resolve."""
import csv
import json
import os
import time

from . import canon, cnp, es_api, builders as B
from .k8s_client import K8s, K8sError
from .restclient import RestError

REQUESTS = "zt_enforcement_requests"
BRIEFS = "zt_agent_briefs"
APP_DIR = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
ROLE_LABELS = {"zt_soc_tier2": "SOC tier 2", "zt_netops": "NetOps", "zt_platform": "platform"}
VERIFY_TIMEOUT = 180


def _csv(name):
    path = os.path.join(APP_DIR, "lookups", name + ".csv")
    with open(path, newline="") as fh:
        return list(csv.DictReader(fh))


def approvers_for(point):
    for row in _csv("zt_approvers"):
        if row["enforcement_point"] == point:
            return [r.strip() for r in row["approver_roles"].split(",")], row["approver_labels"], int(row["approvals_required"])
    return ["zt_soc_tier2"], "SOC tier 2", 1


def user_label(user, roles):
    for row in _csv("zt_role_labels"):
        if row["user"] == user:
            return row["role_label"]
    for r in roles:
        if r in ROLE_LABELS:
            return ROLE_LABELS[r]
    return roles[0] if roles else "user"


def user_roles(splunkd, user):
    d = splunkd.get("services/authentication/users/%s" % user)
    ent = d.get("entry") or []
    return list(ent[0]["content"].get("roles") or []) if ent else []


def next_request_id(splunkd, now):
    day = time.strftime("%Y%m%d", time.gmtime(now))
    todays = splunkd.kv_query(REQUESTS, {"request_id": {"$regex": "^ZTR-%s-" % day}})
    return "ZTR-%s-%04d" % (day, 16 + len(todays) + 1)


def audit(hec, now, req, state, approved_by="", approver_role="", approved_at="", audit_ids=None, comment=None, status="ok", executed_by="splunk"):
    ev = B.enforcement_audit(now, request_id=req.get("request_id", ""), finding_id=req.get("finding_id", ""), investigation_id=req.get("investigation_id", ""), state=state,
                             enforcement_point=req.get("enforcement_point", "kernel"), action=req.get("action", ""), target="%s/%s" % (canon.RUNNER_NS, req.get("pod", "")),
                             workload=req.get("workload", ""), policy_name=req.get("policy_name", ""), approved_by=approved_by, approver_role=approver_role, approved_at=approved_at or "",
                             executed_by=executed_by, playbook=canon.PLAYBOOK, run_id=req.get("request_id", ""), k8s_audit_ids=audit_ids or [], comment=comment if comment is not None else req.get("comment", ""),
                             status=status)
    hec.send([ev])
    return ev


# --------------------------------------------------------------------------- request
def create_request(splunkd, hec, brief, now=None):
    """Open a request for a true-positive brief. Returns the KV record."""
    now = now or time.time()
    workload = brief.get("workload") or canon.RUNNER_WORKLOAD
    ns = workload.split("/")[0]
    pod = brief.get("pod") or canon.RUNNER_POD
    job_id = brief.get("job_id") or str(canon.CI_JOB_ID)
    finding_id = brief.get("finding_id") or ""
    built = cnp.build(ns, pod, workload, job_id, finding_id)
    point = brief.get("enforcement_point") or "kernel"
    roles, labels, required = approvers_for(point)
    req = {"_key": brief.get("_key") or finding_id, "request_id": next_request_id(splunkd, now), "finding_id": finding_id, "investigation_id": brief.get("investigation_id", ""),
           "investigation_guid": brief.get("investigation_guid", ""), "workload": workload, "pod": pod, "job_id": str(job_id), "enforcement_point": point,
           "action": brief.get("action") or "CNP %s" % built["policy_name"], "policy_name": built["policy_name"], "policy_yaml": built["policy_yaml"],
           "label_patch_json": json.dumps(built["label_patch_json"]), "cnp_json": json.dumps(built["cnp_json"]), "approvals_required": required, "approver_roles": ",".join(roles),
           "approver_labels": labels, "approvals": "[]", "status": "pending", "requested_epoch": now, "approved_epoch": 0, "applied_epoch": 0, "verified_epoch": 0,
           "k8s_audit_ids": "[]", "comment": brief.get("comment") or "Contractor merge request; not approved for checkpoint access", "last_error": "",
           "dest_workload": brief.get("dest_workload", ""), "data_class": brief.get("data_class", ""), "disposition": brief.get("disposition", ""), "confidence": brief.get("confidence", ""),
           "what_happened": brief.get("what_happened", ""), "blast_radius": brief.get("blast_radius", "")}
    splunkd.kv_save(REQUESTS, req)
    audit(hec, now, req, "requested")
    if req["investigation_guid"]:
        try:
            es_api.add_note(splunkd, req["investigation_guid"], "Quarantine requested", "Quarantine requested (%s); waiting for %s approval.\n\nPolicy to apply:\n%s" % (req["request_id"], labels, built["policy_yaml"]))
            es_api.update_investigation(splunkd, req["investigation_guid"], status=es_api.STATUS_IN_PROGRESS)
        except RestError as e:
            req["last_error"] = "ES note failed: %s" % str(e)[:200]
            splunkd.kv_save(REQUESTS, req)
    return req


def approval_message(req):
    return cnp.approval_message(req["finding_id"], req["workload"], req.get("dest_workload", ""), req.get("data_class", ""), req.get("disposition", ""), req.get("confidence", ""),
                                req.get("what_happened", ""), req["action"], req["enforcement_point"], req.get("blast_radius", ""), req["policy_yaml"], req["pod"], req["job_id"], req["policy_name"])


# --------------------------------------------------------------------------- decide
def decide(splunkd, hec, req, user, roles, action, comment, now=None):
    """Record an approval or a rejection by `user` (roles from splunkd). Returns (http status, message, req)."""
    now = now or time.time()
    if req.get("status") != "pending":
        return 409, "request %s is %s, not pending" % (req["request_id"], req.get("status")), req
    required_roles = [r for r in (req.get("approver_roles") or "zt_soc_tier2").split(",") if r]
    label = user_label(user, roles)
    approvals = json.loads(req.get("approvals") or "[]")
    satisfied = {a["role"] for a in approvals}
    usable = [r for r in required_roles if r in roles and r not in satisfied]
    if not usable:
        audit(hec, now, req, "refused", approved_by=user, approver_role=label, comment="%s is not an approver for the %s enforcement point (needs %s)" % (user, req["enforcement_point"], req.get("approver_labels")), status="refused")
        return 403, "%s is not an approver for the %s enforcement point (needs %s)" % (user, req["enforcement_point"], req.get("approver_labels")), req
    if action == "reject":
        req["status"] = "rejected"
        req["comment"] = comment or req.get("comment", "")
        splunkd.kv_save(REQUESTS, req)
        audit(hec, now, req, "rejected", approved_by=user, approver_role=label, approved_at=now, comment=comment or "rejected")
        if req.get("investigation_guid"):
            try:
                es_api.add_note(splunkd, req["investigation_guid"], "Quarantine rejected", "Quarantine %s rejected by %s (%s). %s" % (req["request_id"], user, label, comment or ""))
            except RestError:
                pass
        return 200, "request %s rejected by %s (%s)" % (req["request_id"], user, label), req
    approvals.append({"user": user, "role": usable[0], "role_label": label, "time": now, "comment": comment or ""})
    req["approvals"] = json.dumps(approvals)
    if len(approvals) < int(req.get("approvals_required") or 1):
        splunkd.kv_save(REQUESTS, req)
        return 202, "approval by %s (%s) recorded; %d more needed" % (user, label, int(req["approvals_required"]) - len(approvals)), req
    req["status"] = "approved"
    req["approved_epoch"] = now
    req["comment"] = comment or req.get("comment", "")
    splunkd.kv_save(REQUESTS, req)
    by = " + ".join(a["user"] for a in approvals)
    role = " + ".join(a["role_label"] for a in approvals)
    audit(hec, now, req, "approved", approved_by=by, approver_role=role, approved_at=now)
    return 200, "request %s approved by %s (%s)" % (req["request_id"], by, role), req


def approved_by_fields(req):
    approvals = json.loads(req.get("approvals") or "[]")
    return " + ".join(a["user"] for a in approvals), " + ".join(a["role_label"] for a in approvals)


# --------------------------------------------------------------------------- apply
def apply(splunkd, hec, cfg, req, user_agent="zt-approvals/1.0", now=None):
    """Label the pod and create the policy through the emulator with the enforcer token. Returns (ok, message)."""
    now = now or time.time()
    token = splunkd.password("zt_incident_demo", "k8s_enforcer")
    if not token:
        req["status"], req["last_error"] = "failed", "no k8s_enforcer token in storage/passwords"
        splunkd.kv_save(REQUESTS, req)
        audit(hec, now, req, "failed", *approved_by_fields(req), approved_at=req.get("approved_epoch"), comment=req["last_error"], status="failed")
        return False, req["last_error"]
    k8s = K8s(cfg["emulator"]["url"], token, verify=cfg["emulator"]["verify_tls"], user_agent=user_agent)
    ns = req["workload"].split("/")[0]
    audit_ids = []
    try:
        st, body = k8s.patch_pod_labels(ns, req["pod"], json.loads(req["label_patch_json"])["metadata"]["labels"])
        if st != 200:
            raise K8sError(st, json.dumps(body))
        audit_ids.append(((body.get("metadata") or {}).get("annotations") or {}).get("zt/auditID", ""))
        st, body = k8s.create_cnp(ns, json.loads(req["cnp_json"]))
        if st == 409:
            pass  # already there (retry after a partial apply): keep going
        elif st != 201:
            raise K8sError(st, json.dumps(body))
        else:
            audit_ids.append(((body.get("metadata") or {}).get("annotations") or {}).get("zt/auditID", ""))
    except K8sError as e:
        req["status"], req["last_error"] = "failed", str(e)[:300]
        splunkd.kv_save(REQUESTS, req)
        audit(hec, now, req, "failed", *approved_by_fields(req), approved_at=req.get("approved_epoch"), comment=req["last_error"], status="failed")
        return False, req["last_error"]
    applied_at = time.time()
    req["status"], req["applied_epoch"], req["k8s_audit_ids"] = "applied", applied_at, json.dumps([a for a in audit_ids if a])
    splunkd.kv_save(REQUESTS, req)
    by, role = approved_by_fields(req)
    audit(hec, applied_at, req, "applied", approved_by=by, approver_role=role, approved_at=req.get("approved_epoch"), audit_ids=[a for a in audit_ids if a])
    if req.get("investigation_guid"):
        try:
            es_api.add_note(splunkd, req["investigation_guid"], "Quarantine applied", "Approved by %s (%s) at %s. Pod %s labeled %s=%s; CiliumNetworkPolicy %s created (Kubernetes audit %s). Verifying the next attempts." %
                            (by, role, B.iso_s(float(req.get("approved_epoch") or applied_at)), req["pod"], canon.QUARANTINE_LABEL_KEY, req["job_id"], req["policy_name"], ", ".join(a for a in audit_ids if a)))
        except RestError:
            pass
    return True, "applied %s (audit %s)" % (req["policy_name"], ", ".join(a for a in audit_ids if a))


# --------------------------------------------------------------------------- verify
def verify(splunkd, hec, req, now=None):
    """One verification pass for an applied request. Returns (state, message) where state is applied|verified|failed."""
    now = now or time.time()
    applied = float(req.get("applied_epoch") or 0)
    spl = 'search index=zero_trust sourcetype=cilium:hubble:flow src_pod="%s" verdict=DROPPED policy_denied="%s" | head 1 | table _time src_identity policy_denied drop_reason' % (req["pod"], req["policy_name"])
    rows = splunkd.search(spl, earliest=str(int(applied) - 5), latest="now", timeout=120)
    by, role = approved_by_fields(req)
    if rows:
        t = float(rows[0]["_time"]) if str(rows[0]["_time"]).replace(".", "").isdigit() else now
        req["status"], req["verified_epoch"] = "verified", now
        splunkd.kv_save(REQUESTS, req)
        audit(hec, now, req, "verified", approved_by=by, approver_role=role, approved_at=req.get("approved_epoch"), audit_ids=json.loads(req.get("k8s_audit_ids") or "[]"),
              comment="first DROPPED flow by %s at %s (source identity %s)" % (req["policy_name"], B.iso_s(t), rows[0].get("src_identity", "")))
        if req.get("investigation_guid"):
            try:
                es_api.resolve(splunkd, req["investigation_guid"], "Quarantine verified",
                               "Verified: the runner's next attempt was DROPPED by %s at %s (source identity %s, POLICY_DENY). Applied by %s after approval by %s (%s) at %s. Request %s." %
                               (req["policy_name"], B.iso_s(t), rows[0].get("src_identity", ""), "Splunk", by, role, B.iso_s(float(req.get("approved_epoch") or now)), req["request_id"]))
            except RestError as e:
                req["last_error"] = "ES resolve failed: %s" % str(e)[:200]
                splunkd.kv_save(REQUESTS, req)
        return "verified", "verified: DROPPED by %s" % req["policy_name"]
    if now - applied > VERIFY_TIMEOUT:
        req["status"], req["last_error"] = "failed", "no DROPPED flow within %d s of apply" % VERIFY_TIMEOUT
        splunkd.kv_save(REQUESTS, req)
        audit(hec, now, req, "failed", approved_by=by, approver_role=role, approved_at=req.get("approved_epoch"), comment=req["last_error"], status="failed")
        if req.get("investigation_guid"):
            try:
                es_api.add_note(splunkd, req["investigation_guid"], "Quarantine not verified", req["last_error"])
            except RestError:
                pass
        return "failed", req["last_error"]
    return "applied", "no DROPPED flow yet (%d s since apply)" % int(now - applied)


def pending_requests(splunkd):
    return splunkd.kv_query(REQUESTS, {"status": "pending"})
