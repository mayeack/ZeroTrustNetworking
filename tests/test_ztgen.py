#!/usr/bin/env python3
"""Unit checks for the estate, the daily schedule and the incident plan. Run: python3 tests/test_ztgen.py"""
import collections
import json
import os
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "zt_incident_demo", "bin"))
from ztgen import canon, cnp, estate as E, plan as P, schedule as S  # noqa: E402

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


if __name__ == "__main__":
    import time
    for name, fn in list(globals().items()):
        if name.startswith("test_"):
            t = time.time()
            fn()
            print("PASS %-26s %.1fs" % (name, time.time() - t))
    print("all tests passed")
