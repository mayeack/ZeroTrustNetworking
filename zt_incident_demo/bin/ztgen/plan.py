"""The incident plan (generating prompt 7.2): the T0 batch, the 30-second attempts, AUDIT or DROPPED from the
emulator's policy state, and the CI job outcome."""
import json
from collections import OrderedDict

from . import canon, builders as B

CANONICAL_INGRESS_UUID = "4a0f6b8e-9f3d-4a51-b2c7-1e8d5c0a9b21"
JOB_SHELL_PID, GIT_PID, SH_PID, CURL_PID = 22077, 22091, 22098, 22104


def attempt_path(k):
    """Manifest: attempts 0-7 model shards of step-184000, 8-11 optimizer shards, then step-186000 and so on."""
    cycle, i = divmod(k, 12)
    step = 184000 + 2000 * cycle
    if i < 8:
        return "step-%d/model-%05d-of-00008.safetensors" % (step, i + 1)
    return "step-%d/optimizer-%05d-of-00004.pt" % (step, i - 7)


def attempt_time(t0, k):
    return t0 + canon.ATTEMPT_INTERVAL * k


def _runner(estate):
    return estate.pods[canon.RUNNER_POD], estate.pods[canon.STORE_POD]


def _job_shell(estate, rp, t0):
    return B.tetragon_process(estate, rp, "/bin/bash", "-e -o pipefail /scripts/job-%d.sh" % canon.CI_JOB_ID, JOB_SHELL_PID, t0 + canon.T_CI_RUNNING + 0.35, canon.RUNNER_NODE,
                              uid=canon.RUNNER_UID, cwd="/builds", full=False)


def _sh(estate, rp, t0):
    return B.tetragon_process(estate, rp, canon.SH, canon.SH_ARGS, SH_PID, t0 + canon.T_SH_EXEC, canon.RUNNER_NODE, uid=canon.RUNNER_UID, cwd=canon.CWD, full=False)


def _curl(estate, rp, t0, k, parent):
    t = attempt_time(t0, k) + canon.T_CURL_EXEC
    return B.tetragon_process(estate, rp, canon.CURL, canon.CURL_ARGS_TMPL.format(path=attempt_path(k)), CURL_PID + 7 * k, t, canon.RUNNER_NODE, parent=parent,
                              uid=canon.RUNNER_UID, cwd=canon.CWD, container_name="build", container_start=t0 + canon.T_CI_RUNNING - 2.0, container_pid=211)


def src_port(k):
    return 51724 + 37 * k


def ci_common(t0):
    return dict(build_id=canon.CI_JOB_ID, name=canon.CI_JOB_NAME, stage=canon.CI_JOB_STAGE, created_at=t0 + canon.T_CI_RUNNING - 9, started_at=t0 + canon.T_CI_RUNNING,
                pipeline_id=canon.CI_PIPELINE_ID, project_id=canon.CI_PROJECT_ID, project_path=canon.CI_PROJECT, project_name=canon.CI_PROJECT_NAME, user=canon.CI_AUTHOR,
                sha=canon.CI_COMMIT, commit_message=canon.CI_MR_TITLE, runner_id=canon.CI_RUNNER_ID, runner_pod=canon.RUNNER_POD, ref=canon.CI_BRANCH,
                mr={"iid": canon.CI_MR_IID, "title": canon.CI_MR_TITLE, "source_branch": canon.CI_BRANCH, "target_branch": "main", "url": canon.CI_MR_URL}, job_script=canon.CI_SCRIPT)


def fire_events(estate, t0):
    """Everything sent at once by `| ztdemo action=fire`, backdated: CI running, git and sh execs, attempt 0."""
    B.set_zones(estate)
    rp, sp = _runner(estate)
    shell = _job_shell(estate, rp, t0)
    git1 = B.tetragon_process(estate, rp, "/usr/bin/git", "fetch --depth 50 origin postbuild-cache", GIT_PID, t0 + canon.T_GIT_EXEC, canon.RUNNER_NODE, parent=shell,
                              uid=canon.RUNNER_UID, cwd=canon.CWD, container_name="build", container_start=t0 + canon.T_CI_RUNNING - 2.0, container_pid=211)
    git2 = B.tetragon_process(estate, rp, "/usr/bin/git", "checkout -f %s" % canon.CI_COMMIT, GIT_PID + 3, t0 + canon.T_GIT_EXEC + 0.9, canon.RUNNER_NODE, parent=shell,
                              uid=canon.RUNNER_UID, cwd=canon.CWD, container_name="build", container_start=t0 + canon.T_CI_RUNNING - 2.0, container_pid=211)
    sh = _sh(estate, rp, t0)
    sh_full = B.tetragon_process(estate, rp, canon.SH, canon.SH_ARGS, SH_PID, t0 + canon.T_SH_EXEC, canon.RUNNER_NODE, parent=shell, uid=canon.RUNNER_UID, cwd=canon.CWD,
                                 container_name="build", container_start=t0 + canon.T_CI_RUNNING - 2.0, container_pid=211)
    events = [B.ci_job_event(t0 + canon.T_CI_RUNNING, status="running", **ci_common(t0)),
              B.tetragon_exec(estate, t0 + canon.T_GIT_EXEC, canon.RUNNER_NODE, git1, shell),
              B.tetragon_exec(estate, t0 + canon.T_GIT_EXEC + 0.9, canon.RUNNER_NODE, git2, shell),
              B.tetragon_exec(estate, t0 + canon.T_SH_EXEC, canon.RUNNER_NODE, sh_full, shell)]
    events.extend(attempt_events(estate, t0, 0, dropped=False))
    return events


def attempt_events(estate, t0, k, dropped):
    """The events of attempt k: curl exec and connect, then egress FORWARDED + ingress AUDIT, or egress DROPPED."""
    B.set_zones(estate)
    rp, sp = _runner(estate)
    t = attempt_time(t0, k)
    sh = _sh(estate, rp, t0)
    curl = _curl(estate, rp, t0, k, sh)
    port = src_port(k)
    events = [B.tetragon_exec(estate, t + canon.T_CURL_EXEC, canon.RUNNER_NODE, curl, sh),
              B.tetragon_connect(estate, t, canon.RUNNER_NODE, curl, sh, rp.ip, port, sp, canon.STORE_PORT,
                                 sock_cookie="18446623345829913216" if k == 0 else None)]
    if not dropped:
        events.append(B.hubble_flow(estate, t + canon.T_EGRESS, rp, sp, canon.STORE_PORT, port, "FORWARDED", "EGRESS", canon.RUNNER_NODE,
                                    allowed_by=[B.policy_ref(canon.RUNNER_EGRESS_POLICY, canon.RUNNER_NS, canon.RUNNER_EGRESS_POLICY_REVISION)], policy_match_type=2))
        events.append(B.hubble_flow(estate, t + canon.T_INGRESS, rp, sp, canon.STORE_PORT, port, "AUDIT", "INGRESS", canon.STORE_NODE, policy_match_type=0,
                                    flow_uuid=CANONICAL_INGRESS_UUID if k == 0 else None))
    else:
        labels = list(canon.RUNNER_LABELS) + ["k8s:%s=%d" % (canon.QUARANTINE_LABEL_KEY, canon.CI_JOB_ID)]
        events.append(B.hubble_flow(estate, t + canon.T_EGRESS, rp, sp, canon.STORE_PORT, port, "DROPPED", "EGRESS", canon.RUNNER_NODE, src_identity=canon.RUNNER_IDENTITY_QUARANTINED,
                                    src_labels=labels, drop_reason=181, drop_desc="POLICY_DENY", event_type=OrderedDict([("type", 1), ("sub_type", 181)]),
                                    denied_by=[B.policy_ref(canon.QUARANTINE_POLICY, canon.RUNNER_NS, "42")]))
    return events


def ci_final_event(t0, t_finish, failed):
    common = ci_common(t0)
    dur = int(round(t_finish - common["started_at"]))
    return B.ci_job_event(t_finish, status="failed" if failed else "success", finished_at=t_finish, duration=dur, failure_reason="script_failure" if failed else None, **common)


# --------------------------------------------------------------------------- policy state -> quarantine time
def quarantine_applied_at(records, namespace=canon.RUNNER_NS, pod=canon.RUNNER_POD):
    """From zt_policy_state records: the epoch when both the pod label and a CNP selecting it were in place, else None."""
    overlay = next((r for r in records if r.get("_key") == "%s/Pod/%s" % (namespace, pod)), None)
    if not overlay:
        return None
    labels = json.loads(overlay.get("labels_json") or "{}")
    epochs = json.loads(overlay.get("label_epochs_json") or "{}")
    best = None
    for r in records:
        if r.get("kind") != "CiliumNetworkPolicy" or r.get("namespace") != namespace:
            continue
        sel = json.loads(r.get("selector_json") or "{}")
        if not sel or any(labels.get(k) != v for k, v in sel.items()):
            continue
        t_label = max((float(epochs.get(k, 0)) for k in sel), default=0.0)
        t_cnp = float(r.get("created_epoch") or 0)
        t = max(t_label, t_cnp)
        if best is None or t < best:
            best = t
    return best


def policy_names_selecting(records, namespace=canon.RUNNER_NS, pod=canon.RUNNER_POD):
    overlay = next((r for r in records if r.get("_key") == "%s/Pod/%s" % (namespace, pod)), None)
    labels = json.loads(overlay.get("labels_json") or "{}") if overlay else {}
    out = []
    for r in records:
        if r.get("kind") == "CiliumNetworkPolicy" and r.get("namespace") == namespace:
            sel = json.loads(r.get("selector_json") or "{}")
            if sel and all(labels.get(k) == v for k, v in sel.items()):
                out.append(r.get("name"))
    return out
