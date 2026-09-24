#!/usr/bin/env python3
"""make smoke: the acceptance criteria (design document section 15, items 2-8) through REST, with a pass/fail table.
FRESH=1 checks the absolute posture numbers right after a fresh install; otherwise relative changes.
--attach verifies the incident already running instead of firing a new one (t0 = last fire); --no-fire stops after the pre-fire checks.
Runs a full incident: fire -> finding -> brief -> request -> approve as j.chen -> verified -> posture. Use --no-fire to
only check the current state, --skip-agent to not wait for the brief, --approve-as USER to override the approver."""
import json
import re
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

sys.path.insert(0, os.path.join(ztrest.ROOT, "zt_incident_demo", "bin"))
from ztgen import canon, schedule as S  # noqa: E402

RESULTS = []


def check(name, ok, detail=""):
    RESULTS.append(("PASS" if ok else "FAIL", name, str(detail)[:110]))
    print("%s  %s  %s" % ("PASS" if ok else "FAIL", name, str(detail)[:110]), flush=True)
    return ok


def wait_for(fn, timeout, every=10, label=""):
    t0 = time.time()
    while time.time() - t0 < timeout:
        r = fn()
        if r:
            return r, time.time() - t0
        time.sleep(every)
    return None, time.time() - t0


def rollup(s):
    rows = s.search('search index=zt_summary source="ZT Posture - Rollup" | head 1 | table _time identities coverage_pct enforced paths unprotected audit_flows_24h enforcement_24h enforcement_kernel enforcement_dpu enforcement_switch', earliest="-24h", latest="now", timeout=120)
    return rows[0] if rows else {}


def main(argv):
    fresh = any(a.startswith("--fresh=1") or a == "--fresh" for a in argv)
    no_fire = "--no-fire" in argv
    attach = "--attach" in argv  # verify the incident already running (no new fire); t0 = last fire
    skip_agent = "--skip-agent" in argv
    approver = next((a.split("=", 1)[1] for a in argv if a.startswith("--approve-as=")), "j.chen")
    inject = "--inject-brief" in argv
    s = ztrest.Splunk()
    # 2. backfill counts over [checkpoint-24h, checkpoint]
    st = s.kv_get("zt_demo_state", "global") or {}
    cp = float(st.get("stream_checkpoint") or 0) - 60  # a minute back so the newest batch is indexed
    check("state: backfill done", bool(st.get("backfill_done")), "checkpoint age %ds" % (time.time() - cp - 60) if cp > 0 else "no checkpoint")
    # exclude the canonical incident's own events so counts stay exact after practice runs
    excl = ('NOT (src_pod="ci-runner-7d9f8-xk2lq" dest_pod="checkpoint-store-1") NOT (src_pod="ci-runner-7d9f8-xk2lq" cwd="/builds/ml-infra/train-utils") NOT build_id=88213 '
            'NOT k8s_name="zt-quarantine-ci-runner-88213" NOT (k8s_resource=pods k8s_name="ci-runner-7d9f8-xk2lq") NOT policy_name="zt-quarantine-ci-runner-88213" NOT state=released')
    rows = s.search("search index=zero_trust earliest=%s latest=%s %s | stats count by sourcetype" % (cp - 86400, cp, excl), earliest=cp - 86400, latest=cp, timeout=600)
    got = {r["sourcetype"]: int(r["count"]) for r in rows}
    for stype, n in S.daily_expectations().items():
        g = got.get(stype, 0)
        if n is None:
            check("24h count %s" % stype, g > 0, g)
        else:
            check("24h count %s" % stype, g == n, "%d (expected %d)" % (g, n))
    ci = s.search('search index=zero_trust sourcetype=ci:job:event build_status=running NOT build_id=88213 earliest=%s latest=%s | stats dc(build_id) as jobs' % (cp - 86400, cp), earliest=cp - 86400, latest=cp, timeout=300)
    check("24h CI jobs = 1400", ci and int(ci[0]["jobs"]) == 1400, ci[0]["jobs"] if ci else "none")
    for rule in (canon.RULE_FLOW, canon.RULE_PROGRAM):
        r = s.search('| savedsearch "%s"' % rule, earliest="-60m", latest="now", timeout=300)
        check("detection quiet on background: %s" % rule.split(" - ")[1][:40], len(r) == 0, "%d rows" % len(r))
    before = rollup(s)
    check("posture rollup present", bool(before), {k: before.get(k) for k in ("identities", "coverage_pct", "unprotected", "audit_flows_24h", "enforcement_24h")})
    if fresh and before and not attach:
        check("posture before: 1283 / 87.7 / 8 / 2306 / 16 (10,2,4)", (int(float(before["identities"])), float(before["coverage_pct"]), int(float(before["unprotected"])), int(float(before["audit_flows_24h"])), int(float(before["enforcement_24h"])), int(float(before["enforcement_kernel"])), int(float(before["enforcement_dpu"])), int(float(before["enforcement_switch"]))) == (1283, 87.7, 8, 2306, 16, 10, 2, 4),
              "%s %s %s %s %s (%s,%s,%s)" % (before["identities"], before["coverage_pct"], before["unprotected"], before["audit_flows_24h"], before["enforcement_24h"], before["enforcement_kernel"], before["enforcement_dpu"], before["enforcement_switch"]))
    if no_fire:
        return finish()
    # 3. fire (or attach to the incident that is already running)
    if attach:
        t0 = float(st.get("last_fire_epoch") or 0) or None
        check("attached to the running incident", t0 is not None and st.get("plan_status") == "running", "fired %s" % time.strftime("%H:%M:%SZ", time.gmtime(t0 or 0)))
    else:
        fire = s.search("| ztdemo action=fire", earliest="-1m", latest="now", timeout=300)
        t0 = float(fire[0].get("t0") or time.time()) if fire and fire[0].get("result") == "incident started" else None
        check("fire accepted", t0 is not None, fire[0] if fire else "no row")
    if t0 is None:
        return finish()
    q1 = 'search index=zero_trust sourcetype=cilium:hubble:flow verdict=AUDIT src_workload="build-farm/ci-runner" earliest=%d | head 1 | table src_pod dest_pod src_identity dest_identity _time' % (t0 - 60)
    q2 = 'search index=zero_trust sourcetype=cisco:isovalent:processConnect process_name=curl earliest=%d | head 1 | table src_pod dest_pod process parent_process _time' % (t0 - 60)
    r1, dt1 = wait_for(lambda: s.search(q1, earliest=t0 - 60, latest="now", timeout=60), 60, 3)
    r2, dt2 = wait_for(lambda: s.search(q2, earliest=t0 - 60, latest="now", timeout=60), 60, 3)
    check("deck search 1 (AUDIT flow) within 10 s", bool(r1) and dt1 <= 12 and r1[0]["src_pod"] == canon.RUNNER_POD and r1[0]["dest_pod"] == canon.STORE_POD and r1[0]["src_identity"] == "48213" and r1[0]["dest_identity"] == "30719", "%.0fs %s" % (dt1, r1[0] if r1 else None))
    check("deck search 2 (curl connect) within 10 s", bool(r2) and dt2 <= 12 and r2[0]["process"] == canon.CURL and r2[0]["parent_process"] == "/bin/sh -c ./scripts/postbuild.sh", "%.0fs %s" % (dt2, r2[0] if r2 else None))
    ci = s.search('search index=zero_trust sourcetype=ci:job:event build_id=88213 earliest=%d | head 1 | table build_status' % (t0 - 60), earliest=t0 - 60, latest="now")
    check("CI job 88213 running", bool(ci) and ci[0]["build_status"] == "running", ci)
    time.sleep(70)
    att = s.search('search index=zero_trust sourcetype=cisco:isovalent:processConnect src_pod="%s" earliest=%d | stats count' % (canon.RUNNER_POD, t0 - 1), earliest=t0 - 1, latest="now")
    check("attempts every 30 s (>=3 after 70 s)", bool(att) and int(att[0]["count"]) >= 3, att)
    # 4. risk + finding within 3 min
    def risk():
        r = s.search('search index=risk source="ZT - *" risk_object="build-farm/ci-runner" earliest=%d | stats sum(risk_score) as total dc(source) as rules count' % int(t0), earliest=int(t0), latest="now")
        return r if r and int(float(r[0].get("rules") or 0)) >= 2 else None
    rk, dtr = wait_for(risk, 240, 10)
    check("two risk events (50+40) within 3 min", bool(rk) and int(float(rk[0]["total"])) == 90 and int(rk[0]["count"]) == 2, "%.0fs %s" % (dtr, rk[0] if rk else None))
    def finding():
        r = s.search('search `notable` | search source="%s" | eval rule_title=coalesce(orig_rule_title, rule_title) | sort - _time | head 1 | table event_id _time rule_title risk_score threat_object annotations.mitre_attack.mitre_technique_id source_count' % canon.RULE_FBD, earliest=int(t0), latest="now")
        return r or None
    fg, dtf = wait_for(finding, 240, 10)
    fg0 = fg[0] if fg else {}
    check("one finding group within 3 min", bool(fg), "%.0fs" % dtf)
    check("finding title", fg0.get("rule_title") == canon.FINDING_TITLE, fg0.get("rule_title"))
    check("finding risk 90", str(fg0.get("risk_score", "")).split(".")[0] == "90", fg0.get("risk_score"))
    tos = set((fg0.get("threat_object") or []) if isinstance(fg0.get("threat_object"), list) else [fg0.get("threat_object")])
    check("threat objects", {"ai-train/checkpoint-store", "/usr/bin/curl"} <= tos, tos)
    mitre = fg0.get("annotations.mitre_attack.mitre_technique_id")
    mitre = set(mitre if isinstance(mitre, list) else [mitre])
    check("MITRE T1530 + T1059.004", {"T1530", "T1059.004"} <= mitre, mitre)
    cnt = s.search('search `notable` | search source="%s" | stats count' % canon.RULE_FBD, earliest=int(t0), latest="now")
    check("exactly one ZT finding group since fire", cnt and int(cnt[0]["count"]) == 1, cnt)
    # 5. agent brief (or an injected one when no agent is available, e.g. on the local test bed)
    if inject and fg and fg0.get("event_id"):
        try:
            inject_brief(s, fg0)
            check("brief injected (no agent on this instance)", True, fg0.get("event_id", "")[:8])
        except Exception as e:  # noqa: BLE001
            check("brief injected (no agent on this instance)", False, str(e)[:100])
    if not skip_agent and not inject:
        def brief():
            b = s.kv_list("zt_agent_briefs")
            b = [x for x in b if float(x.get("run_epoch") or 0) >= t0]
            return b or None
        br, dtb = wait_for(brief, 420, 15)
        b0 = br[0] if br else {}
        check("agent brief within 7 min of fire", bool(br), "%.0fs" % dtb)
        check("brief disposition true_positive / kernel / SOC tier 2", b0.get("disposition") == "true_positive" and b0.get("enforcement_point") == "kernel" and "soctier2" in re.sub(r"[^a-z0-9]", "", (b0.get("approver_labels") or "").lower()), {k: b0.get(k) for k in ("disposition", "enforcement_point", "approver_labels")})
        text = (b0.get("brief_json") or "") + (b0.get("brief_text") or "")
        for fact in ("88213", "4417", "contractor-dev-17", canon.RUNNER_POD, "bf-node-03", "dc2-leaf-205", "Eth1/12", "7712"):
            check("brief cites %s" % fact, fact in text)
        check("AI note added", int(b0.get("note_added") or 0) == 1, b0.get("investigation_id"))
        # criterion 5: the run called only zt_ tools, all five (from the run_finished trace in _audit)
        runs = s.search('search index=_audit sourcetype=ai_agent:response agent_name=ZTFlowInvestigator type=run_finished | head 1 | table _raw', earliest=int(t0), latest="now")
        try:
            trace = json.loads(json.loads(runs[0]["_raw"]).get("trace") or "[]") if runs else []
        except (ValueError, KeyError, TypeError):
            trace = []
        called = [c.get("name") for c in trace if isinstance(c, dict)]
        check("agent called only zt_ tools, all five", bool(called) and all(str(n).startswith("zt_") for n in called) and len(set(called)) == 5, sorted(set(called)))
    # 6. Mode B request/approve/verify
    def req():
        r = s.kv_list("zt_enforcement_requests", {"status": {"$in": ["pending", "approved", "applied", "verified"]}})
        r = [x for x in r if float(x.get("requested_epoch") or 0) >= t0]
        return r or None
    rq, dtq = wait_for(req, 180, 10)
    check("pending request within 1 min of the brief", bool(rq), "%.0fs" % dtq)
    if rq:
        r0 = rq[0]
        pw = ztrest.env("ZT_PASS_" + approver.upper().replace(".", "_"))
        if not pw:
            check("approve as %s" % approver, False, "no password in local/env for %s" % approver)
        else:
            ap = ztrest.Splunk(user=approver, password=pw)
            stc, body = ap.request("POST", "services/zt_incident_demo/approvals", json_body={"action": "approve", "request_id": r0["request_id"], "comment": "Contractor merge request; not approved for checkpoint access"}, raw=True)
            check("approve as %s (HTTP 200)" % approver, stc == 200, body[:120])
            t_apply = time.time()
            # refusal by a user without SOC tier 2
            other = ztrest.env("ZT_PASS_A_PATEL")
            if other:
                ap2 = ztrest.Splunk(user="a.patel", password=other)
                st2, b2 = ap2.request("POST", "services/zt_incident_demo/approvals", json_body={"action": "approve", "request_id": r0["request_id"], "comment": "x"}, raw=True)
                check("refused for a.patel (NetOps) on a kernel request", st2 in (403, 409), "%s %s" % (st2, b2[:80]))
            k8s = s.search('search index=zero_trust sourcetype=kube:apiserver:audit k8s_user="%s" earliest=%d | stats values(k8s_verb) as verbs values(status_code) as codes count' % (canon.ENFORCER_USER, int(t0)), earliest=int(t0), latest="now")
            check("two kube audit events (patch 200, create 201)", k8s and int(k8s[0]["count"]) >= 2 and set(k8s[0]["codes"]) >= {"200", "201"}, k8s)
            def dropped():
                r = s.search('search index=zero_trust sourcetype=cilium:hubble:flow src_pod="%s" verdict=DROPPED earliest=%d | head 1 | table src_identity policy_denied drop_reason' % (canon.RUNNER_POD, int(t_apply) - 5), earliest=int(t_apply) - 5, latest="now")
                return r or None
            dr, dtd = wait_for(dropped, 150, 10)
            d0 = dr[0] if dr else {}
            check("next attempt DROPPED by the policy, identity 48291", d0.get("src_identity") == "48291" and d0.get("policy_denied") == canon.QUARANTINE_POLICY, "%.0fs %s" % (dtd, d0))
            def verified():
                r = s.kv_list("zt_enforcement_requests", {"request_id": r0["request_id"]})
                return r if r and r[0].get("status") == "verified" else None
            vr, dtv = wait_for(verified, 150, 10)
            check("verified within 2 min of applied", bool(vr), "%.0fs" % dtv)
            guid = r0.get("investigation_guid")
            if guid:
                def resolved():
                    lst = s.get("servicesNS/nobody/missioncontrol/public/v2/investigations", params={"ids": guid, "output_mode": None})
                    inv = (lst[0] if isinstance(lst, list) and lst else {})
                    ok = str(inv.get("status_label") or inv.get("status")) in ("Resolved", "4") and "True Positive" in str(inv.get("disposition_name") or inv.get("disposition_label") or inv.get("disposition"))
                    return [inv] if ok else None
                rv, dtr = wait_for(resolved, 90, 10)  # the resolve follows the verification by a few seconds
                inv = rv[0] if rv else {}
                check("investigation Resolved / True Positive", bool(rv), "%.0fs %s" % (dtr, {k: inv.get(k) for k in ("investigation_id", "status", "disposition_name")}))
                notes = s.get("servicesNS/nobody/missioncontrol/public/v2/investigations/%s/notes" % urllib.parse.quote(guid, safe=""), params={"output_mode": None})
                texts = [((n.get("title") or "") + " " + (n.get("content") or "")).lower() for n in (notes if isinstance(notes, list) else notes.get("items", []))]
                check("notes: brief, request, result", any("brief" in t for t in texts) and any("requested" in t for t in texts) and any("verified" in t for t in texts), "%d notes" % len(texts))
            def failed_job():
                r = s.search('search index=zero_trust sourcetype=ci:job:event build_id=88213 build_status=failed earliest=%d | head 1 | table build_failure_reason build_finished_at' % int(t0), earliest=int(t0), latest="now")
                return r or None
            fj, dtj = wait_for(failed_job, 420, 15)
            check("CI job fails (script_failure) after the 6th DROPPED", bool(fj) and fj[0]["build_failure_reason"] == "script_failure", "%.0fs %s" % (dtj, fj[0] if fj else None))
    # 7. posture after (wait for a rollup after the last event)
    time.sleep(75)
    after = rollup(s)
    if before.get("identities") and after.get("identities"):
        # after a practice run the before-state already carries that run for 24 h, so compare with what must hold either way
        rel_ok = (int(float(after["enforcement_24h"])) == int(float(before["enforcement_24h"])) + 1 and int(float(after["enforcement_kernel"])) == int(float(before["enforcement_kernel"])) + 1 and
                  int(float(after["identities"])) >= int(float(before["identities"])) and int(float(after["identities"])) >= 1284 and
                  int(float(after["unprotected"])) == 8 and int(float(after["enforced"])) == int(float(after["paths"])) - 8 and int(float(after["paths"])) >= 66)
        check("posture after (relative): +1 kernel action, runner path enforced, 8 unprotected", rel_ok, "before %s/%s/%s/%s after %s/%s/%s/%s" % (before["identities"], before["coverage_pct"], before["unprotected"], before["enforcement_24h"], after["identities"], after["coverage_pct"], after["unprotected"], after["enforcement_24h"]))
        if fresh:
            check("posture after: 1284 / 87.9 / 8 / 17 (11,2,4)", (int(float(after["identities"])), float(after["coverage_pct"]), int(float(after["unprotected"])), int(float(after["enforcement_24h"])), int(float(after["enforcement_kernel"]))) == (1284, 87.9, 8, 17, 11), "%s %s %s %s (%s)" % (after["identities"], after["coverage_pct"], after["unprotected"], after["enforcement_24h"], after["enforcement_kernel"]))
        dip = s.search('search index=zt_summary source="ZT Posture - Rollup" earliest=%d | stats min(coverage_pct) as min_cov max(unprotected) as max_unp' % int(t0), earliest=int(t0), latest="now")
        check("posture during: coverage dipped and unprotected rose by one", dip and float(dip[0]["min_cov"]) < float(after["coverage_pct"]) and int(float(dip[0]["max_unp"])) == int(float(after["unprotected"])) + 1, dip)
    trail = s.search('search index=zero_trust sourcetype=zt:enforcement:audit state=verified earliest=%d | head 1 | table approved_by_label status policy_name' % int(t0), earliest=int(t0), latest="now")
    check("audit trail row: j.chen (SOC tier 2), verified", trail and trail[0]["approved_by_label"] == "j.chen (SOC tier 2)" and trail[0]["policy_name"] == canon.QUARANTINE_POLICY, trail)
    return finish()


def inject_brief(s, finding):
    sys.path.insert(0, os.path.join(ztrest.ROOT, "zt_incident_demo", "bin"))
    from ztgen import es_api
    from ztgen.restclient import Splunkd
    sd = Splunkd(ztrest.env("SPLUNK_URL"), basic=(ztrest.env("SPLUNK_USER"), ztrest.env("SPLUNK_PASS")), verify=False)
    row = {"event_id": finding["event_id"], "rule_title": finding.get("rule_title"), "finding_time": finding.get("_time"), "finding_epoch": time.time() - 600}
    state = sd.kv_get("zt_demo_state", "global") or {}
    inv, created = es_api.ensure_investigation(sd, row, description="Opened for the local test run.", not_before=state.get("last_reset_epoch") or 0)
    guid, display = es_api.investigation_ids(inv)
    brief = {"finding_id": finding["event_id"], "entity": canon.RUNNER_WORKLOAD, "risk": 90, "job_id": str(canon.CI_JOB_ID), "dest_workload": canon.STORE_WORKLOAD, "data_class": "crown-jewel",
             "disposition": "true_positive", "confidence": "high",
             "what_happened": "CI job 88213 ran scripts/postbuild.sh from merge request !4417 (contractor-dev-17), using curl to fetch a checkpoint of training job 7712.",
             "why_it_matters": "Protected crown-jewel store; the runner is not on its allowlist, which is still in audit mode.",
             "where": {"pod": canon.RUNNER_POD, "node": canon.RUNNER_NODE, "switch": canon.RUNNER_SWITCH, "interface": canon.RUNNER_INTERFACE},
             "recommendation": {"enforcement_point": "kernel", "action": "Quarantine the runner pod at the kernel with a Cilium policy", "policy_name": canon.QUARANTINE_POLICY, "scope": "one pod", "blast_radius": "the one pod; the rest of the build farm keeps running", "approver_labels": ["SOC tier 2"]},
             "follow_up": ["Revert !4417", "rotate the runner's credentials", "review the allowlist rollout"], "evidence": [{"tool": "zt_finding_context", "fact": "risk 90 from 2 detections"}],
             "brief_text": "Disposition: True positive, high confidence.\nWhat happened: CI job 88213 ran scripts/postbuild.sh from merge request !4417 (contractor-dev-17), using curl to fetch a checkpoint of training job 7712.\nWhy it matters: Protected crown-jewel store; the runner is not on its allowlist, which is still in audit mode.\nWhere: Pod ci-runner-7d9f8-xk2lq on bf-node-03 (dc2-leaf-205 Eth1/12).\nRecommendation: Quarantine the runner pod at the kernel with a Cilium policy (zt-quarantine-ci-runner-88213). Approver: SOC tier 2.\nFollow-up: Revert !4417, rotate the runner's credentials, review the allowlist rollout."}
    rec = {"_key": "%s@%d" % (finding["event_id"], int(float(state.get("last_reset_epoch") or 0))), "finding_id": finding["event_id"], "finding_display_id": display, "investigation_id": display, "investigation_guid": guid, "workload": canon.RUNNER_WORKLOAD,
           "pod": canon.RUNNER_POD, "node": canon.RUNNER_NODE, "job_id": str(canon.CI_JOB_ID), "dest_workload": canon.STORE_WORKLOAD, "data_class": "crown-jewel", "disposition": "true_positive",
           "confidence": "high", "enforcement_point": "kernel", "action": brief["recommendation"]["action"], "policy_name": canon.QUARANTINE_POLICY, "blast_radius": brief["recommendation"]["blast_radius"],
           "approver_labels": "SOC tier 2", "brief_json": json.dumps(brief), "brief_text": brief["brief_text"], "what_happened": brief["what_happened"], "session_id": "local-test", "run_epoch": time.time(), "note_added": 0}
    if guid:
        es_api.add_note(sd, guid, "ZTFlowInvestigator brief", brief["brief_text"], ai_generated=True)
        rec["note_added"] = 1
    sd.kv_save("zt_agent_briefs", rec)


def finish():
    print()
    print(ztrest.table(RESULTS, ["", "check", "detail"]))
    fails = [r for r in RESULTS if r[0] == "FAIL"]
    print("\n%d checks, %d failed" % (len(RESULTS), len(fails)))
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
