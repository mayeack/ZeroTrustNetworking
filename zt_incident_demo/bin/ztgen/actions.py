"""Actions shared by the ztdemo command and the live generator: fire, reset, status."""
import time

from . import attacks as A, canon, plan as P, state as ST, builders as B
from .k8s_client import K8s
from .estate import get_estate
from .restclient import RestError
from .streamer import Streamer


def fire(splunkd, hec, cfg, now=None):
    t0 = Streamer(splunkd, hec, cfg).fire(now)
    return {"result": "incident started", "t0": t0, "t0_iso": B.iso_ms(t0), "job_id": canon.CI_JOB_ID, "pod": canon.RUNNER_POD,
            "next": "attempts every %ds; detections at the next scheduled run" % canon.ATTEMPT_INTERVAL}


def reset(splunkd, hec, cfg, now=None, user_agent="ztdemo-reset/1.0"):
    """Release every quarantine (the CI runner's and any path attack's), cancel open requests, stamp the reset."""
    now = now or time.time()
    released, audit_ids, note = [], [], ""
    token = splunkd.password("zt_incident_demo", "k8s_platform")
    # only pods that still carry a quarantine label (policy state) or belong to a running attack: one emulator call each
    estate = get_estate()
    found = {(canon.RUNNER_NS, canon.RUNNER_POD): canon.RUNNER_WORKLOAD}
    try:
        for r in splunkd.kv_query("zt_policy_state"):
            key = r.get("_key", "")
            if "/Pod/" in key and canon.QUARANTINE_LABEL_KEY in (r.get("labels_json") or ""):
                ns, pod = key.split("/Pod/", 1)
                found.setdefault((ns, pod), estate.pods[pod].workload if pod in estate.pods else ns + "/" + pod)
    except RestError:
        pass
    for rec in A.running(splunkd):
        found.setdefault((rec["src_workload"].split("/")[0], rec["src_pod"]), rec["src_workload"])
    targets = [(ns, pod, wl) for (ns, pod), wl in found.items()]
    if token:
        try:
            k8s = K8s(cfg["emulator"]["url"], token, verify=cfg["emulator"]["verify_tls"], user_agent=user_agent)
            for ns, pod, wl in targets:
                rel, ids = k8s.release_quarantine(ns, pod)
                if rel:
                    hec.send([B.enforcement_audit(now, request_id="", finding_id="", investigation_id="", state="released", enforcement_point="kernel",
                                                  action="CNP %s" % ",".join(rel), target="%s/%s" % (ns, pod), workload=wl, policy_name=",".join(rel),
                                                  approved_by=canon.PLATFORM_USER, approver_role=canon.PLATFORM_ROLE, approved_at=now, executed_by="splunk", playbook="ztdemo",
                                                  run_id="", k8s_audit_ids=ids, comment="merge request reverted" if pod == canon.RUNNER_POD else "attack contained, policy retired")])
                    released.extend(rel)
                    audit_ids.extend(ids)
        except Exception as e:  # noqa: BLE001
            note = "emulator unreachable: %s" % str(e)[:160]
    else:
        note = "no k8s_platform token in storage/passwords (run make secrets)"
    st = ST.load(splunkd)
    cancelled = 0
    for r in splunkd.kv_query("zt_enforcement_requests", {"status": {"$in": ["pending", "approved"]}}):
        r["status"] = "cancelled"
        splunkd.kv_save("zt_enforcement_requests", r)
        cancelled += 1
    Streamer(splunkd, hec, cfg).reset(now)
    return {"result": "plan idle, reset stamped", "released_policies": ",".join(released) or "none", "cancelled_requests": cancelled,
            "previous_plan_status": st["plan_status"], "last_reset_epoch": now, "note": note}


def status(splunkd, cfg, with_counts=True):
    st = ST.load(splunkd)
    now = time.time()
    row = {"checkpoint_age_s": int(now - float(st["stream_checkpoint"])) if st["stream_checkpoint"] else None,
           "backfill_done": bool(st["backfill_done"]), "plan_status": st["plan_status"], "plan_attempt": st["plan_attempt"], "plan_t0": st["plan_t0"],
           "plan_dropped_attempts": st["plan_dropped_attempts"], "last_reset_epoch": st["last_reset_epoch"], "last_fire_epoch": st["last_fire_epoch"],
           "speed": st["speed"], "agent_mode": st["agent_mode"], "response_mode": st["response_mode"], "last_tick_epoch": st["last_tick_epoch"],
           "last_tick_events": st["last_tick_events"], "last_error": st["last_error"], "stream_owner": st.get("stream_owner", ""), "stream_owner_epoch": st.get("stream_owner_epoch", 0),
           "hec_url": cfg["hec"]["url"], "emulator_url": cfg["emulator"]["url"]}
    try:
        recs = splunkd.kv_query("zt_policy_state")
        row["quarantine_policies"] = ",".join(P.policy_names_selecting(recs)) or "none"
        row["quarantine_applied_at"] = P.quarantine_applied_at(recs)
    except RestError as e:
        row["quarantine_policies"] = "kv error: %s" % e
    if with_counts:
        try:
            rows = splunkd.search("search index=zero_trust earliest=-60m | stats count by sourcetype", earliest="-60m", latest="now", timeout=120)
            row["events_last_hour"] = "; ".join("%s=%s" % (r["sourcetype"], r["count"]) for r in rows) or "0"
        except RestError as e:
            row["events_last_hour"] = "search error: %s" % str(e)[:120]
    return row
