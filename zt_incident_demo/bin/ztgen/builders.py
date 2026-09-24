"""Event builders: one function per sourcetype, each returning an HEC envelope
{"time": epoch, "host": ..., "source": ..., "sourcetype": ..., "index": ..., "event": {...}} with the exact
JSON shape and key order of generating prompt section 6.3. Compact JSON is produced by the HEC client."""
import base64
import hashlib
import math
import uuid
from collections import OrderedDict

from . import SEED, canon

INDEX = "zero_trust"


def _hx(*parts):
    return hashlib.sha256((SEED + "|" + "|".join(str(p) for p in parts)).encode()).hexdigest()


def det_uuid(*parts):
    return str(uuid.UUID(_hx("uuid", *parts)[:32]))


def iso_ns(t, tail=None):
    """RFC3339 with nanoseconds. t is float seconds; the last digits come from a deterministic tail."""
    whole = int(math.floor(t))
    frac = t - whole
    nanos = int(round(frac * 1e6)) * 1000  # microsecond precision from the float
    if tail is not None:
        nanos += int(_hx("ns", tail)[:3], 16) % 1000
    if nanos >= 1_000_000_000:
        nanos = 999_999_999
    import time as _time
    return _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(whole)) + ".%09dZ" % nanos


def iso_ms(t):
    import time as _time
    whole = int(math.floor(t))
    return _time.strftime("%Y-%m-%dT%H:%M:%S", _time.gmtime(whole)) + ".%03dZ" % int(round((t - whole) * 1000))


def iso_s(t):
    import time as _time
    return _time.strftime("%Y-%m-%dT%H:%M:%SZ", _time.gmtime(int(math.floor(t))))


def iso_space(t):
    import time as _time
    return _time.strftime("%Y-%m-%d %H:%M:%S UTC", _time.gmtime(int(math.floor(t))))


def envelope(t, host, source, sourcetype, event, index=INDEX):
    return {"time": round(t, 3), "host": host, "source": source, "sourcetype": sourcetype, "index": index, "event": event}


def exec_id(node, t, pid):
    return base64.b64encode(("%s:%d:%d" % (node, int(t * 1e9) % 100000000000, pid)).encode()).decode()


def policy_ref(name, namespace, revision):
    return OrderedDict([("name", name), ("namespace", namespace),
                        ("labels", ["k8s:io.cilium.k8s.policy.derived-from=CiliumNetworkPolicy", "k8s:io.cilium.k8s.policy.name=%s" % name,
                                    "k8s:io.cilium.k8s.policy.namespace=%s" % namespace]),
                        ("revision", str(revision)), ("kind", "CiliumNetworkPolicy")])


# --------------------------------------------------------------------------- Hubble
def hubble_flow(estate, t, src_pod, dest_pod, dest_port, src_port, verdict, direction, node, *, src_identity=None, src_labels=None,
                allowed_by=None, denied_by=None, drop_reason=None, drop_desc=None, event_type=None, policy_match_type=None,
                reply=False, dest_ip=None, dest_identity=None, dest_labels=None, dest_namespace=None, dest_workload=None, dest_pod_name=None,
                tail=None, protocol="TCP", flow_uuid=None):
    """src_pod and dest_pod are estate Pod objects (dest_pod may be None for non-pod destinations)."""
    sw = estate.workloads[src_pod.workload]
    dw = estate.workloads[dest_pod.workload] if dest_pod is not None else None
    ts = iso_ns(t, tail or (src_pod.name, dest_port, src_port, t))
    flow = OrderedDict()
    flow["time"] = ts
    flow["uuid"] = flow_uuid or det_uuid("flow", src_pod.name, src_port, dest_port, direction, round(t, 3))
    flow["verdict"] = verdict
    if drop_reason is not None:
        flow["drop_reason"] = drop_reason
        flow["drop_reason_desc"] = drop_desc
    flow["IP"] = OrderedDict([("source", src_pod.ip), ("destination", dest_ip or dest_pod.ip), ("ipVersion", "IPv4")])
    l4 = OrderedDict([("source_port", src_port), ("destination_port", dest_port)])
    if protocol == "TCP":
        l4["flags"] = OrderedDict([("SYN", True)]) if not reply else OrderedDict([("SYN", True), ("ACK", True)])
    flow["l4"] = OrderedDict([(protocol, l4)])
    src = OrderedDict()
    if direction == "EGRESS" or node == src_pod.node:
        src["ID"] = src_pod.endpoint_id
    src["identity"] = src_identity if src_identity is not None else sw.identity
    src["cluster_name"] = canon.CLUSTER
    src["namespace"] = sw.namespace
    src["labels"] = list(src_labels) if src_labels is not None else list(sw.labels)
    src["pod_name"] = src_pod.name
    src["workloads"] = [OrderedDict([("name", sw.name), ("kind", sw.kind)])]
    flow["source"] = src
    dst = OrderedDict()
    if dest_pod is not None and direction == "INGRESS":
        dst["ID"] = dest_pod.endpoint_id
    dst["identity"] = dest_identity if dest_identity is not None else (dw.identity if dw else 2)  # reserved:world = 2
    dst["cluster_name"] = canon.CLUSTER
    dst["namespace"] = dest_namespace or (dw.namespace if dw else "")
    dst["labels"] = list(dest_labels) if dest_labels is not None else (list(dw.labels) if dw else ["reserved:world"])
    if dest_pod is not None:
        dst["pod_name"] = dest_pod.name
        dst["workloads"] = [OrderedDict([("name", dw.name), ("kind", dw.kind)])]
    elif dest_workload:
        dst["pod_name"] = dest_pod_name or ""
        dst["workloads"] = [OrderedDict([("name", dest_workload.split("/")[-1]), ("kind", "Deployment")])]
    flow["destination"] = dst
    flow["Type"] = "L3_L4"
    flow["node_name"] = "%s/%s" % (canon.CLUSTER, node)
    flow["node_labels"] = ["kubernetes.io/hostname=%s" % node, "topology.kubernetes.io/zone=%s" % estate.nodes[node].zone]
    if event_type is None:
        event_type = OrderedDict([("type", 1), ("sub_type", drop_reason)]) if verdict == "DROPPED" else OrderedDict([("type", 5)]) if (allowed_by or verdict == "AUDIT") else OrderedDict([("type", 4), ("sub_type", 3)])
    flow["event_type"] = event_type
    if allowed_by:
        flow["%s_allowed_by" % direction.lower()] = allowed_by
    if denied_by:
        flow["%s_denied_by" % direction.lower()] = denied_by
    flow["traffic_direction"] = direction
    if policy_match_type is not None:
        flow["policy_match_type"] = policy_match_type
    flow["is_reply"] = reply
    flow["Summary"] = "TCP Flags: SYN" + (", ACK" if reply else "") if protocol == "TCP" else "UDP"
    ev = OrderedDict([("flow", flow), ("node_name", "%s/%s" % (canon.CLUSTER, node)), ("time", ts)])
    return envelope(t, node, "hubble-exporter", "cilium:hubble:flow", ev)


# --------------------------------------------------------------------------- Tetragon
def tetragon_process(estate, pod, binary, arguments, pid, start_t, node, *, parent=None, uid=1000, cwd="/", flags="execve clone", container_name="app", container_start=None, container_pid=1, full=True):
    """Build the Tetragon process object. `full` adds the container/image/labels block (used for the process, not the parent)."""
    w = estate.workloads[pod.workload]
    p = OrderedDict()
    p["exec_id"] = exec_id(node, start_t, pid)
    p["pid"] = pid
    p["uid"] = uid
    p["cwd"] = cwd
    p["binary"] = binary
    p["arguments"] = arguments
    p["flags"] = flags
    p["start_time"] = iso_ns(start_t, (pod.name, pid))
    if full:
        p["auid"] = 4294967295
    podblock = OrderedDict([("namespace", w.namespace), ("name", pod.name)])
    if full:
        podblock["container"] = OrderedDict([("id", pod.container_id), ("name", container_name),
                                             ("image", OrderedDict([("id", canon.RUNNER_IMAGE_ID if pod.name == canon.RUNNER_POD else w.image.split(":")[0] + "@sha256:" + _hx("img", w.key)),
                                                                    ("name", w.image)])),
                                             ("start_time", iso_s(container_start if container_start else start_t - 3600)), ("pid", container_pid)])
        labels = OrderedDict()
        for lab in w.labels:
            if lab.startswith("k8s:") and "io.cilium" not in lab and "io.kubernetes" not in lab:
                k, v = lab[4:].split("=", 1)
                labels[k] = v
        podblock["pod_labels"] = labels
    podblock["workload"] = w.name
    podblock["workload_kind"] = w.kind
    p["pod"] = podblock
    if full:
        p["docker"] = pod.container_id.split("://")[-1]
        if parent is not None:
            p["parent_exec_id"] = parent["exec_id"]
        p["tid"] = pid
    return p


def _tetragon_envelope(kind, body, node, t, tail):
    ev = OrderedDict([(kind, body), ("node_name", node), ("time", iso_ns(t, tail)), ("cluster_name", canon.CLUSTER),
                      ("node_labels", OrderedDict([("kubernetes.io/hostname", node), ("topology.kubernetes.io/zone", _zone_of(node))]))])
    return ev


_ZONES = {}


def _zone_of(node):
    return _ZONES.get(node, "dc2-row-1")


def set_zones(estate):
    _ZONES.update({n.name: n.zone for n in estate.nodes.values()})


def tetragon_exec(estate, t, node, process, parent):
    body = OrderedDict([("process", process), ("parent", parent)])
    return envelope(t, node, "tetragon", "cisco:isovalent:processExec", _tetragon_envelope("process_exec", body, node, t, (process["exec_id"], "exec")))


def tetragon_connect(estate, t, node, process, parent, src_ip, src_port, dest_pod, dest_port, sock_cookie=None):
    dw = estate.workloads[dest_pod.workload]
    labels = OrderedDict()
    for lab in dw.labels:
        if lab.startswith("k8s:") and "io.cilium" not in lab and "io.kubernetes" not in lab:
            k, v = lab[4:].split("=", 1)
            labels[k] = v
    body = OrderedDict([("process", process), ("parent", parent), ("source_ip", src_ip), ("source_port", src_port),
                        ("destination_ip", dest_pod.ip), ("destination_port", dest_port),
                        ("sock_cookie", sock_cookie or str(18446623345829913216 + int(_hx("sock", process["exec_id"], src_port)[:6], 16))), ("protocol", "TCP"),
                        ("destination_pod", OrderedDict([("namespace", dw.namespace), ("name", dest_pod.name), ("pod_labels", labels), ("workload", dw.name), ("workload_kind", dw.kind)]))])
    return envelope(t, node, "tetragon", "cisco:isovalent:processConnect", _tetragon_envelope("process_connect", body, node, t, (process["exec_id"], "connect", src_port)))


def tetragon_kprobe_sigkill(estate, t, node, process, parent, policy_name, function_name="security_bprm_check"):
    body = OrderedDict([("process", process), ("parent", parent), ("function_name", function_name),
                        ("args", [OrderedDict([("file_arg", OrderedDict([("path", process["binary"])]))])]),
                        ("action", "KPROBE_ACTION_SIGKILL"), ("policy_name", policy_name)])
    return envelope(t, node, "tetragon", "cisco:isovalent", _tetragon_envelope("process_kprobe", body, node, t, (process["exec_id"], "kprobe")))


# --------------------------------------------------------------------------- CI
def ci_job_event(t, *, status, build_id, name, stage, created_at, started_at, finished_at=None, duration=None, failure_reason=None,
                 pipeline_id, project_id, project_path, project_name, user, sha, commit_message, runner_id, runner_pod, ref, mr=None, job_script=None, tags=None):
    ev = OrderedDict()
    ev["object_kind"] = "build"
    ev["ref"] = ref
    ev["tag"] = False
    ev["sha"] = sha
    ev["build_id"] = build_id
    ev["build_name"] = name
    ev["build_stage"] = stage
    ev["build_status"] = status
    ev["build_created_at"] = iso_space(created_at)
    ev["build_started_at"] = iso_space(started_at) if started_at is not None else None
    ev["build_finished_at"] = iso_space(finished_at) if finished_at is not None else None
    ev["build_duration"] = duration
    ev["build_failure_reason"] = failure_reason
    ev["pipeline_id"] = pipeline_id
    ev["project_id"] = project_id
    ev["project_name"] = project_name
    ev["project"] = OrderedDict([("path_with_namespace", project_path), ("web_url", "https://git.corp.internal/" + project_path)])
    ev["user"] = OrderedDict([("username", user), ("name", user)])
    ev["commit"] = OrderedDict([("sha", sha), ("message", commit_message), ("author_name", user)])
    ev["runner"] = OrderedDict([("id", runner_id), ("description", runner_pod), ("runner_type", "group_type"), ("tags", tags or ["k8s", "build-farm"])])
    if mr:
        ev["merge_request"] = OrderedDict([("iid", mr["iid"]), ("title", mr["title"]), ("source_branch", mr["source_branch"]), ("target_branch", mr["target_branch"]), ("url", mr["url"])])
    if job_script:
        ev["job_script"] = job_script
    return envelope(t, canon.CI_HOST, "ci:job_hook", "ci:job:event", ev)


# --------------------------------------------------------------------------- Nexus
def nexus_endpoint(t, node, snapshot_t):
    ev = OrderedDict([("timestamp", iso_ms(snapshot_t)), ("source", "nexus-dashboard"), ("fabric", canon.FABRIC), ("switch", node.switch), ("interface", node.interface),
                      ("hostname", node.name), ("endpoint_ip", node.ip), ("endpoint_mac", node.mac), ("vlan", 200 + int(node.switch[-1])), ("vrf", node.vrf), ("learned", "lldp"), ("state", "up")])
    return envelope(t, node.switch, "nexus-dashboard", "cisco:nexus:endpoint", ev)


def nexus_liveprotect(t, switch, advisory_id, component, shield="active", status="protected"):
    ev = OrderedDict([("timestamp", iso_ms(t)), ("source", "nexus-dashboard"), ("fabric", canon.FABRIC), ("switch", switch), ("feature", "live_protect"),
                      ("advisory_id", advisory_id), ("component", component), ("shield", shield), ("status", status)])
    return envelope(t, switch, "nexus-dashboard", "cisco:nexus:liveprotect", ev)


def nexus_config(t, device, user, change, diff_summary, change_type="config", ticket=""):
    ev = OrderedDict([("timestamp", iso_ms(t)), ("source", "nexus"), ("fabric", canon.FABRIC), ("device", device), ("user", user), ("change_type", change_type),
                      ("change", change), ("diff_summary", diff_summary), ("ticket", ticket)])
    return envelope(t, device, "nexus", "cisco:nexus:config", ev)


# --------------------------------------------------------------------------- Nexus Dashboard (Cisco DC Networking app schema)
# cisco:dc:nd:advisories and cisco:dc:nd:anomalies as the Cisco DC Networking app (Splunkbase 7777) indexes them from
# Nexus Dashboard: JSON with the time in endTs, severity as Nexus Dashboard reports it (the app derives
# calculated_severity), nodeNames as a list. Secure Networking Essentials reads them for its data center cards.
def nd_advisory(t, advisory, first_seen):
    ev = OrderedDict([("advisoryId", advisory["id"]), ("title", advisory["title"]), ("advisoryStr", advisory["text"]), ("category", advisory["category"]),
                      ("severity", advisory["severity"]), ("resourceType", "node"), ("nodeNames", list(advisory["nodes"])), ("fabricName", canon.FABRIC),
                      ("insights_group", canon.ND_INSIGHTS_GROUP), ("nd_host", canon.ND_HOST), ("vendor", "CISCO_NX-OS"),
                      ("startTs", iso_ms(first_seen)), ("endTs", iso_ms(t)), ("clearTs", ""), ("cleared", False),
                      ("acknowledged", advisory["acknowledged"]), ("verificationStatus", "VERIFIED" if advisory["acknowledged"] else "NOT_VERIFIED"),
                      ("assignee", advisory.get("assignee", ""))])
    return envelope(t, canon.ND_HOST, "nexus-dashboard", "cisco:dc:nd:advisories", ev)


def nd_anomaly(t, anomaly, start_t, clear_t=None):
    cleared = clear_t is not None and t >= clear_t
    ev = OrderedDict([("anomalyId", det_uuid("nd-anomaly", anomaly["type"], anomaly["node"], int(start_t))), ("anomalyType", anomaly["type"]),
                      ("anomalyStr", anomaly["text"]), ("category", anomaly["category"]), ("severity", anomaly["severity"]),
                      ("anomalyScore", anomaly["score"]), ("entityName", anomaly["entity"]), ("resourceType", anomaly["resource"]),
                      ("nodeNames", [anomaly["node"]]), ("fabricName", canon.FABRIC), ("insights_group", canon.ND_INSIGHTS_GROUP), ("nd_host", canon.ND_HOST),
                      ("vendor", "CISCO_NX-OS"), ("mnemonicTitle", anomaly["mnemonic"]), ("mnemonicNum", anomaly["mnemonic_num"]),
                      ("startTs", iso_ms(start_t)), ("endTs", iso_ms(t)), ("clearTs", iso_ms(clear_t) if cleared else ""), ("cleared", cleared),
                      ("acknowledged", cleared), ("verificationStatus", "VERIFIED" if cleared else "NOT_VERIFIED"), ("assignee", anomaly.get("assignee", "") if cleared else "")])
    return envelope(t, canon.ND_HOST, "nexus-dashboard", "cisco:dc:nd:anomalies", ev)


# --------------------------------------------------------------------------- Kubernetes audit
def k8s_audit(t, *, audit_id, verb, uri, resource, namespace, name, api_group, api_version, code, user, groups, source_ip, user_agent, reason, received_t=None):
    ev = OrderedDict()
    ev["kind"] = "Event"
    ev["apiVersion"] = "audit.k8s.io/v1"
    ev["level"] = "Metadata"
    ev["auditID"] = audit_id
    ev["stage"] = "ResponseComplete"
    ev["requestURI"] = uri
    ev["verb"] = verb
    ev["user"] = OrderedDict([("username", user), ("groups", list(groups))])
    ev["sourceIPs"] = [source_ip]
    ev["userAgent"] = user_agent
    ref = OrderedDict([("resource", resource), ("namespace", namespace), ("name", name)])
    if api_group:
        ref["apiGroup"] = api_group
    ref["apiVersion"] = api_version
    ev["objectRef"] = ref
    ev["responseStatus"] = OrderedDict([("metadata", OrderedDict()), ("code", code)])
    ev["requestReceivedTimestamp"] = iso_ns(received_t if received_t is not None else t - 0.0177, (audit_id, "r"))[:-4] + "Z"
    ev["stageTimestamp"] = iso_ns(t, (audit_id, "s"))[:-4] + "Z"
    ev["annotations"] = OrderedDict([("authorization.k8s.io/decision", "allow"), ("authorization.k8s.io/reason", reason)])
    return envelope(t, "kube-apiserver", "k8s-audit", "kube:apiserver:audit", ev)


ENFORCER_REASON = 'RBAC: allowed by ClusterRoleBinding "zt-enforcer" of ClusterRole "zt-quarantine-writer" to ServiceAccount "zt-enforcer/soar"'
PLATFORM_REASON = 'RBAC: allowed by ClusterRoleBinding "platform-admins" of ClusterRole "cluster-admin" to Group "platform-admins"'
ARGOCD_REASON = 'RBAC: allowed by ClusterRoleBinding "argocd-application-controller" of ClusterRole "argocd-application-controller" to ServiceAccount "argocd-application-controller/argocd"'


# --------------------------------------------------------------------------- enforcement audit trail
def enforcement_audit(t, *, request_id, finding_id, investigation_id, state, enforcement_point, action, target, workload, policy_name,
                      approved_by, approver_role, approved_at, executed_by, playbook, run_id, k8s_audit_ids, comment, status="ok", host=None):
    ev = OrderedDict([("time", iso_ms(t)), ("request_id", request_id), ("finding_id", finding_id), ("investigation_id", investigation_id), ("state", state),
                      ("enforcement_point", enforcement_point), ("action", action), ("target", target), ("workload", workload), ("policy_name", policy_name),
                      ("approved_by", approved_by), ("approver_role", approver_role), ("approved_at", iso_s(approved_at) if isinstance(approved_at, (int, float)) else approved_at),
                      ("executed_by", executed_by), ("playbook", playbook), ("run_id", run_id), ("k8s_audit_ids", list(k8s_audit_ids or [])), ("comment", comment), ("status", status)])
    return envelope(t, host or ("soar" if executed_by == "soar" else "splunk"), canon.PLAYBOOK, "zt:enforcement:audit", ev)
