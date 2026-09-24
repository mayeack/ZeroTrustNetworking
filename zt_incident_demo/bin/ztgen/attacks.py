"""Path attacks and single-shot triggers started from the live generator (the search head streamer advances them too).

A path attack is the generic form of the canonical incident: a workload's program reaches a protected store every
30 seconds; each attempt is an exec, a connect and two flows (egress FORWARDED, ingress AUDIT) until a quarantine
policy selects the pod, then the egress flow is DROPPED. Records live in the zt_demo_state collection under
`attack:<id>` (rec_kind=attack), next to the global state record."""
import hashlib
import json
import time
from collections import OrderedDict

from . import canon, builders as B, plan as P, state as ST
from .estate import STORES, _program_for
from .schedule import ARGS_BY_PROGRAM, egress_policy

REC_KIND = "attack"
MAX_ATTEMPTS = 40           # 20 minutes of attempts when nothing is enforced
DROPS_TO_COMPLETE = canon.DROPPED_ATTEMPTS_BEFORE_FAIL
ARGS = dict(ARGS_BY_PROGRAM)
ARGS.update({"/usr/bin/curl": "-sS --retry 5 -o /tmp/.cache/m.bin http://{svc}:{port}/{path}",
             "/usr/bin/rsync": "-a rsync://{svc}:{port}/ckpt/ /tmp/ckpt/",
             "/usr/bin/wget": "-q -O /tmp/m.bin http://{svc}:{port}/{path}",
             "/usr/bin/scp": "-P {port} {svc}:/ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors /tmp/",
             "/usr/local/bin/aws": "s3 --endpoint-url http://{svc}:{port} cp s3://ckpt/llm-7712/ /tmp/ckpt --recursive"})
PROGRAMS = sorted(ARGS)


class _Fmt(dict):
    def __missing__(self, key):
        return "{" + key + "}"


def program_args(program, dest_workload, k=0):
    store = STORES.get(dest_workload, {})
    svc = "%s.%s.svc" % (dest_workload.split("/")[1], dest_workload.split("/")[0])
    return ARGS.get(program, "").format_map(_Fmt(job=7690 + k % 30, svc=svc, port=store.get("port", 443), path=P.attempt_path(k).replace("step-", "ckpt/llm-7712/step-")))


def running(splunkd):
    return splunkd.kv_query(ST.COLLECTION, {"rec_kind": REC_KIND, "status": "running"})


def all_attacks(splunkd):
    recs = splunkd.kv_query(ST.COLLECTION, {"rec_kind": REC_KIND})
    return sorted(recs, key=lambda r: -float(r.get("t0") or 0))


def _parent(estate, pod, t0):
    return B.tetragon_process(estate, pod, "/usr/bin/tini", "-- /entrypoint.sh", 1, t0 - 3737, pod.node, uid=0, cwd="/", full=False)


def attempt_events(estate, rec, k, dropped, policy_names=None, label_value=None):
    """The events of attempt k of a path attack (same shape as the canonical attempts)."""
    B.set_zones(estate)
    src = estate.workloads[rec["src_workload"]]
    sp, dp = estate.pods[rec["src_pod"]], estate.pods[rec["dest_pod"]]
    port, t0 = int(rec["port"]), float(rec["t0"])
    t = P.attempt_time(t0, k)
    src_port = 40000 + (int(rec["seed"]) + 37 * k) % 20000
    parent = _parent(estate, sp, t0)
    proc = B.tetragon_process(estate, sp, rec["program"], program_args(rec["program"], rec["dest_workload"], k), 6100 + 7 * k, t + canon.T_CURL_EXEC, sp.node,
                              parent=parent, uid=1000 if src.namespace != "platform" else 0, cwd="/app", container_name="main")
    events = [B.tetragon_exec(estate, t + canon.T_CURL_EXEC, sp.node, proc, parent),
              B.tetragon_connect(estate, t, sp.node, proc, parent, sp.ip, src_port, dp, port)]
    if not dropped:
        events.append(B.hubble_flow(estate, t + canon.T_EGRESS, sp, dp, port, src_port, "FORWARDED", "EGRESS", sp.node, allowed_by=egress_policy(src.namespace), policy_match_type=2))
        events.append(B.hubble_flow(estate, t + canon.T_INGRESS, sp, dp, port, src_port, "AUDIT", "INGRESS", dp.node, policy_match_type=0))
    else:
        label = label_value if label_value is not None else rec.get("job_id", "")
        names = policy_names or ["zt-quarantine-%s-%s" % (src.name, label)]
        labels = list(src.labels) + ["k8s:%s=%s" % (canon.QUARANTINE_LABEL_KEY, label)]
        events.append(B.hubble_flow(estate, t + canon.T_EGRESS, sp, dp, port, src_port, "DROPPED", "EGRESS", sp.node, src_identity=int(rec["identity_quarantined"]), src_labels=labels,
                                    drop_reason=181, drop_desc="POLICY_DENY", event_type=OrderedDict([("type", 1), ("sub_type", 181)]),
                                    denied_by=[B.policy_ref(n, src.namespace, "42") for n in names]))
    return events


def advance(splunkd, hec, estate, now=None):
    """Send every due attempt of every running attack; returns the number of events sent."""
    now = now or time.time()
    recs = running(splunkd)
    if not recs:
        return 0
    policy = splunkd.kv_query("zt_policy_state")
    sent = 0
    for rec in recs:
        ns, pod = rec["src_workload"].split("/")[0], rec["src_pod"]
        applied_at = P.quarantine_applied_at(policy, ns, pod)
        names = P.policy_names_selecting(policy, ns, pod)
        overlay = next((r for r in policy if r.get("_key") == "%s/Pod/%s" % (ns, pod)), None)
        label = (json.loads(overlay.get("labels_json") or "{}").get(canon.QUARANTINE_LABEL_KEY) if overlay else None)
        k, t0, changed = int(rec["attempt"]) + 1, float(rec["t0"]), False
        while P.attempt_time(t0, k) <= now and rec["status"] == "running":
            dropped = applied_at is not None and P.attempt_time(t0, k) >= applied_at
            sent += hec.send(attempt_events(estate, rec, k, dropped, names, label))
            rec["attempt"], changed = k, True
            if dropped:
                rec["dropped_attempts"] = int(rec["dropped_attempts"]) + 1
            if int(rec["dropped_attempts"]) >= DROPS_TO_COMPLETE or k + 1 >= int(rec["max_attempts"]):
                rec["status"], rec["completed_epoch"] = "completed", now
            k += 1
        if changed:
            splunkd.kv_save(ST.COLLECTION, rec)
    return sent


def start(splunkd, hec, estate, src_workload, dest_workload, program=None, max_attempts=MAX_ATTEMPTS, now=None, started_by="live"):
    """Start a path attack and send its first attempt. Returns (record, events_sent)."""
    now = now or time.time()
    if dest_workload not in STORES:
        raise ValueError("%s is not a protected store; choose one of %s" % (dest_workload, ", ".join(STORES)))
    if src_workload not in estate.workloads:
        raise ValueError("unknown workload %s" % src_workload)
    if src_workload == canon.RUNNER_WORKLOAD:
        raise ValueError("the CI runner has its own incident: use fire")
    src, dest = estate.workloads[src_workload], estate.workloads[dest_workload]
    sp, dp = src.pods[0], dest.pods[-1]
    for r in running(splunkd):
        if r["src_pod"] == sp.name:
            raise ValueError("an attack from %s is already running (%s)" % (sp.name, r["_key"]))
    program = program or _program_for(src_workload, dest_workload)
    seed = int(hashlib.sha256(("%s|%s|%d" % (src_workload, dest_workload, int(now))).encode()).hexdigest()[:6], 16)
    attack_id = "%s-%d" % (src.name, int(now))
    rec = {"_key": "attack:" + attack_id, "rec_kind": REC_KIND, "attack_id": attack_id, "src_workload": src_workload, "src_pod": sp.name, "src_node": sp.node,
           "dest_workload": dest_workload, "dest_pod": dp.name, "port": int(STORES[dest_workload]["port"]), "program": program, "t0": now, "attempt": -1,
           "max_attempts": int(max_attempts), "status": "running", "dropped_attempts": 0, "identity_quarantined": int(src.identity) + 78,
           "job_id": str(7000 + seed % 1000), "seed": seed, "started_by": started_by, "completed_epoch": 0}
    splunkd.kv_save(ST.COLLECTION, rec)
    return rec, advance(splunkd, hec, estate, now)


def stop(splunkd, attack_key, now=None):
    rec = splunkd.kv_get(ST.COLLECTION, attack_key)
    if not rec:
        raise ValueError("no attack %s" % attack_key)
    rec["status"], rec["completed_epoch"] = "stopped", now or time.time()
    splunkd.kv_save(ST.COLLECTION, rec)
    return rec


# --------------------------------------------------------------------------- single-shot triggers
def audit_flow(estate, hec, src_workload, dest_workload, now=None):
    """One audit-mode connection (egress FORWARDED, ingress AUDIT), no process events: risk rule 1 only."""
    now = now or time.time()
    B.set_zones(estate)
    src, dest = estate.workloads[src_workload], estate.workloads[dest_workload]
    sp, dp = src.pods[0], dest.pods[-1]
    port = int(STORES[dest_workload]["port"])
    src_port = 40000 + int(now) % 20000
    return hec.send([B.hubble_flow(estate, now + canon.T_EGRESS, sp, dp, port, src_port, "FORWARDED", "EGRESS", sp.node, allowed_by=egress_policy(src.namespace), policy_match_type=2),
                     B.hubble_flow(estate, now + canon.T_INGRESS, sp, dp, port, src_port, "AUDIT", "INGRESS", dp.node, policy_match_type=0)])


def program_connect(estate, hec, src_workload, dest_workload, program, now=None):
    """One Tetragon exec and connect from an unapproved program, no flows: risk rule 2 only."""
    now = now or time.time()
    B.set_zones(estate)
    src, dest = estate.workloads[src_workload], estate.workloads[dest_workload]
    sp, dp = src.pods[0], dest.pods[-1]
    port = int(STORES[dest_workload]["port"])
    parent = _parent(estate, sp, now)
    proc = B.tetragon_process(estate, sp, program, program_args(program, dest_workload), 6200 + int(now) % 500, now + canon.T_CURL_EXEC, sp.node, parent=parent, uid=1000, cwd="/app", container_name="main")
    return hec.send([B.tetragon_exec(estate, now + canon.T_CURL_EXEC, sp.node, proc, parent),
                     B.tetragon_connect(estate, now, sp.node, proc, parent, sp.ip, 40000 + int(now) % 20000, dp, port)])


LIVEPROTECT_ADVISORIES = [("cisco-sa-nxos-bgp-dos-3fzrsx", "bgp"), ("cisco-sa-nxos-ospf-memleak-4qkw3", "ospf"), ("cisco-sa-nxos-nxapi-rce-9pwbe", "nxapi")]


def liveprotect(estate, hec, switch, advisory=None, component=None, now=None):
    now = now or time.time()
    adv, comp = LIVEPROTECT_ADVISORIES[int(now) % len(LIVEPROTECT_ADVISORIES)]
    return hec.send([B.nexus_liveprotect(now, switch, advisory or adv, component or comp)])


def nexus_config(estate, hec, device, user, change, ticket="", now=None):
    now = now or time.time()
    return hec.send([B.nexus_config(now, device, user, change, "+ " + change, ticket=ticket)])


ENFORCEMENT_KINDS = {
    "kernel": ("CNP quarantine: {wl}", "cnp", "SOC tier 2"),
    "dpu": ("Hypershield DPU rule: block egress {wl}", "dpu", "SOC tier 2 + NetOps"),
    "switch": ("Hypershield deny: {ns} segment", "nexus", "NetOps + SOC tier 2"),
}


def enforcement(estate, hec, splunkd, point, target_workload, approved_by, comment, now=None):
    """A completed enforcement action on a workload (requested, approved, applied, verified) with its platform events,
    dated a minute back so the audit trail reads as finished. Returns (request_id, events_sent)."""
    from .response import next_request_id
    now = now or time.time()
    B.set_zones(estate)
    if point not in ENFORCEMENT_KINDS:
        raise ValueError("enforcement point must be kernel, dpu or switch")
    wl = estate.workloads[target_workload]
    pod = wl.pods[0]
    action_tmpl, platform, role = ENFORCEMENT_KINDS[point]
    action = action_tmpl.format(wl=target_workload, ns=wl.namespace)
    T = now - 50
    req_id = next_request_id(splunkd, now)
    fid = "ES-L%d" % (int(now) % 100000)
    policy = {"cnp": "zt-quarantine-%s-%d" % (wl.name, int(now) % 10000), "dpu": "hs-dpu-egress-%s" % wl.name, "nexus": "nexus-%s-deny" % wl.namespace}[platform]
    audit_ids = [B.det_uuid("livepatch", req_id), B.det_uuid("livecnp", req_id)] if platform == "cnp" else []
    common = dict(request_id=req_id, finding_id=fid, investigation_id="", enforcement_point=point, action=action, target="%s/%s" % (wl.namespace, pod.name), workload=target_workload,
                  policy_name=policy, approved_by=approved_by, approver_role=role, approved_at=T - 2, executed_by="splunk", playbook="live-generator", run_id="", k8s_audit_ids=audit_ids, comment=comment)
    events = [B.enforcement_audit(T + off, state=state, **common) for state, off in (("requested", -95), ("approved", -2), ("applied", 0), ("verified", 45))]
    if platform == "cnp":
        events.append(B.k8s_audit(T - 0.4, audit_id=audit_ids[0], verb="patch", uri="/api/v1/namespaces/%s/pods/%s" % (wl.namespace, pod.name), resource="pods", namespace=wl.namespace, name=pod.name,
                                  api_group="", api_version="v1", code=200, user=canon.ENFORCER_USER, groups=canon.ENFORCER_GROUPS, source_ip=canon.ENFORCER_SOURCE_IP, user_agent="zt-quarantine-workload/1.0", reason=B.ENFORCER_REASON))
        events.append(B.k8s_audit(T, audit_id=audit_ids[1], verb="create", uri="/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies" % wl.namespace, resource="ciliumnetworkpolicies", namespace=wl.namespace, name=policy,
                                  api_group="cilium.io", api_version="v2", code=201, user=canon.ENFORCER_USER, groups=canon.ENFORCER_GROUPS, source_ip=canon.ENFORCER_SOURCE_IP, user_agent="zt-quarantine-workload/1.0", reason=B.ENFORCER_REASON))
    elif platform == "nexus":
        node = estate.nodes[pod.node]
        change = "hypershield policy deny segment %s to segment ai" % wl.namespace
        events.append(B.nexus_config(T, node.switch, "soar-nxapi", change, "+ " + change, ticket=fid))
    return req_id, hec.send(events)
