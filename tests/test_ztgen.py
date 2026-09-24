#!/usr/bin/env python3
"""Unit checks for the estate, the daily schedule and the incident plan. Run: python3 tests/test_ztgen.py"""
import collections
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "zt_incident_demo", "bin"))
from ztgen import attacks as A, canon, cnp, estate as E, plan as P, schedule as S  # noqa: E402

BANNED = ("sample", "mock", "fake", "synthetic", "illustrative", "demo")


def test_estate():
    e = E.get_estate()
    assert len(e.workloads) == 1283 and len(e.nodes) == 92 and len(e.identities) == 1283
    assert e.workloads[canon.RUNNER_WORKLOAD].identity == 48213 and e.workloads[canon.STORE_WORKLOAD].identity == 30719
    assert 48291 not in e.identities
    assert e.pods[canon.RUNNER_POD].ip == "10.42.3.17" and e.pods[canon.RUNNER_POD].node == "bf-node-03"
    assert e.pods[canon.STORE_POD].ip == "10.42.7.21" and e.pods[canon.STORE_POD].node == "ai-train-stor-02"
    assert (e.nodes["bf-node-03"].switch, e.nodes["bf-node-03"].interface) == ("dc2-leaf-205", "Eth1/12")
    assert (e.nodes["ai-train-stor-02"].switch, e.nodes["ai-train-stor-02"].interface) == ("dc2-leaf-207", "Eth1/05")
    assert len(e.enforced_paths) == 57 and len(e.gap_paths) == 8
    assert sum(e.paths[k]["count"] for k in e.gap_paths) == 2306
    assert sum(e.paths[k]["count"] for k in e.enforced_paths) == 11400
    assert not [k for k in e.workloads if any(b in k for b in BANNED)]
    ports = collections.Counter((n.switch, n.interface) for n in e.nodes.values())
    assert max(ports.values()) == 1, "switch port collision"


def test_full_day():
    e = E.get_estate()
    day = 20718
    c = collections.Counter()
    v = collections.Counter()
    ids = set()
    jobs = set()
    for ev in S.background_events(e, day * 86400, (day + 1) * 86400):
        c[ev["sourcetype"]] += 1
        if ev["sourcetype"] == "cilium:hubble:flow":
            f = ev["event"]["flow"]
            v[(f["verdict"], f["traffic_direction"])] += 1
            for side in ("source", "destination"):
                if f[side]["identity"] >= 256:
                    ids.add(f[side]["identity"])
            assert not (f["verdict"] == "DROPPED" and f["destination"].get("workloads") and "%s/%s" % (f["destination"]["namespace"], f["destination"]["workloads"][0]["name"]) in e.stores)
        elif ev["sourcetype"] == "ci:job:event" and ev["event"]["build_status"] == "running":
            jobs.add(ev["event"]["build_id"])
        text = json.dumps(ev)
        assert not any(b in text.lower() for b in BANNED), text[:200]
    exp = S.daily_expectations()
    for st, n in exp.items():
        if n is not None:
            assert c[st] == n, (st, c[st], n)
    assert v[("AUDIT", "INGRESS")] == 2306 and v[("FORWARDED", "INGRESS")] == 11400 and v[("DROPPED", "EGRESS")] == 1400
    assert v[("FORWARDED", "EGRESS")] == 13706 + 55000
    assert len(ids) == 1283
    assert len(jobs) == 1400
    assert c["cisco:isovalent:processConnect"] == 13706


def test_ticks_equal_one_shot():
    e = E.get_estate()
    start = 20718 * 86400 + 3000
    end = start + 3600
    one = collections.Counter(ev["sourcetype"] + "|" + str(ev["time"]) for ev in S.background_events(e, start, end))
    ticks = collections.Counter()
    t = start
    while t < end:
        for ev in S.background_events(e, t, min(t + 15, end)):
            ticks[ev["sourcetype"] + "|" + str(ev["time"])] += 1
        t += 15
    assert one == ticks and max(ticks.values()) == 1


def test_plan():
    e = E.get_estate()
    t0 = 1790088727.402
    evs = P.fire_events(e, t0)
    kinds = [(x["sourcetype"], round(x["time"] - t0, 3)) for x in evs]
    assert kinds[0] == ("ci:job:event", -27.0) and kinds[-1] == ("cilium:hubble:flow", 0.029)
    ing = evs[-1]["event"]["flow"]
    assert ing["verdict"] == "AUDIT" and ing["source"]["identity"] == 48213 and ing["destination"]["identity"] == 30719 and ing["destination"]["ID"] == 944
    assert ing["uuid"] == P.CANONICAL_INGRESS_UUID
    con = [x for x in evs if x["sourcetype"] == "cisco:isovalent:processConnect"][0]["event"]["process_connect"]
    assert con["process"]["binary"] == "/usr/bin/curl" and con["parent"]["binary"] == "/bin/sh" and con["parent"]["arguments"] == "-c ./scripts/postbuild.sh"
    assert con["source_port"] == 51724 and con["destination_port"] == 9000
    d = P.attempt_events(e, t0, 12, True)
    f = d[-1]["event"]["flow"]
    assert f["verdict"] == "DROPPED" and f["drop_reason"] == 181 and f["source"]["identity"] == 48291 and f["egress_denied_by"][0]["name"] == canon.QUARANTINE_POLICY
    assert "k8s:zt-quarantine=88213" in f["source"]["labels"]
    assert P.attempt_path(7) == "step-184000/model-00008-of-00008.safetensors" and P.attempt_path(8) == "step-184000/optimizer-00001-of-00004.pt"
    assert P.attempt_path(12).startswith("step-186000/")
    fail = P.ci_final_event(t0, t0 + 30 * 17 + 15, True)["event"]
    assert fail["build_status"] == "failed" and fail["build_failure_reason"] == "script_failure" and fail["build_duration"] == 30 * 17 + 15 + 27


def test_cnp():
    b = cnp.build("build-farm", canon.RUNNER_POD, canon.RUNNER_WORKLOAD, 88213, "ES-1842")
    assert b["policy_name"] == canon.QUARANTINE_POLICY
    assert b["cnp_json"]["spec"]["endpointSelector"]["matchLabels"] == {"zt-quarantine": "88213"}
    assert b["label_patch_json"] == {"metadata": {"labels": {"zt-quarantine": "88213"}}}
    assert 'zt-quarantine: "88213"' in b["policy_yaml"]


def test_attacks():
    """A path attack attempt has the canonical shape; DROPPED carries the quarantine identity and the denying policy."""
    e = E.get_estate()
    src, dest = "ml-notebooks/jupyter", "ai-train/checkpoint-store"
    sp, dp = e.workloads[src].pods[0], e.workloads[dest].pods[-1]
    rec = {"src_workload": src, "src_pod": sp.name, "dest_workload": dest, "dest_pod": dp.name, "port": 9000, "program": "/usr/bin/curl", "t0": 1790000000.0,
           "seed": 1234, "identity_quarantined": e.workloads[src].identity + 78, "job_id": "7412"}
    evs = A.attempt_events(e, rec, 0, dropped=False)
    assert [x["sourcetype"] for x in evs] == ["cisco:isovalent:processExec", "cisco:isovalent:processConnect", "cilium:hubble:flow", "cilium:hubble:flow"]
    flows = [x["event"]["flow"] for x in evs[2:]]
    assert [f["verdict"] for f in flows] == ["FORWARDED", "AUDIT"] and flows[1]["destination"]["pod_name"] == dp.name and flows[1]["l4"]["TCP"]["destination_port"] == 9000
    assert evs[1]["event"]["process_connect"]["process"]["binary"] == "/usr/bin/curl" and evs[1]["event"]["process_connect"]["destination_pod"]["name"] == dp.name
    assert "checkpoint-store.ai-train.svc:9000" in evs[1]["event"]["process_connect"]["process"]["arguments"]
    d = A.attempt_events(e, rec, 3, dropped=True, policy_names=["zt-quarantine-jupyter-7412"], label_value="7412")
    assert [x["sourcetype"] for x in d] == ["cisco:isovalent:processExec", "cisco:isovalent:processConnect", "cilium:hubble:flow"]
    f = d[2]["event"]["flow"]
    assert f["verdict"] == "DROPPED" and f["source"]["identity"] == e.workloads[src].identity + 78 and f["egress_denied_by"][0]["name"] == "zt-quarantine-jupyter-7412"
    assert "k8s:zt-quarantine=7412" in f["source"]["labels"]
    # timing follows the canonical cadence and the program args know every store
    assert abs((d[2]["time"] - rec["t0"]) - (3 * canon.ATTEMPT_INTERVAL + canon.T_EGRESS)) < 1e-6
    for store in E.STORES:
        assert A.program_args("/usr/bin/curl", store).startswith("-sS") and store.split("/")[1] in A.program_args("/usr/bin/curl", store)
    for text in json.dumps(evs):
        pass
    assert not any(w in json.dumps(evs).lower() for w in BANNED)


def test_state_merge():
    """A tick that loaded the state before a fire must not undo the fire when it saves."""
    from ztgen import state as ST

    class KV:
        def __init__(self):
            self.rec = {}

        def kv_get(self, coll, key):
            return dict(self.rec) if self.rec else None

        def kv_save(self, coll, rec):
            self.rec = dict(rec)

    kv = KV()
    ST.save(kv, ST.load(kv))
    tick = ST.load(kv)
    snap = dict(tick)
    fire = ST.load(kv)
    fsnap = dict(fire)
    fire.update({"plan_status": "running", "plan_t0": 123.0})
    ST.save_changes(kv, fire, fsnap)
    tick["stream_checkpoint"] = 456.0
    ST.save_changes(kv, tick, snap)
    now = ST.load(kv)
    assert now["plan_status"] == "running" and now["plan_t0"] == 123.0 and now["stream_checkpoint"] == 456.0


def test_brief_approver_labels():
    sys.path.insert(0, os.path.join(ROOT, "zt_incident_demo", "bin", "lib"))
    import ztbrief
    flat = ztbrief.normalize({"approver_labels": ["soc-tier-2"], "recommendation_policy_name": "zt-quarantine-ci-runner-88213"})
    assert flat["recommendation"]["approver_labels"] == ["SOC tier 2"]
    assert ztbrief.normalize({"approver_labels": "zt_netops, SOC tier 2"})["recommendation"]["approver_labels"] == ["NetOps", "SOC tier 2"]
    nested = ztbrief.normalize({"recommendation": {"approver_labels": "soc_tier_2"}, "where": {}})
    assert nested["recommendation"]["approver_labels"] == ["SOC tier 2"]
    assert ztbrief.approver_label("Security architect") == "Security architect"


if __name__ == "__main__":
    import time
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            t = time.time()
            fn()
            print("PASS %-26s %.1fs" % (name, time.time() - t))
    print("all tests passed")
