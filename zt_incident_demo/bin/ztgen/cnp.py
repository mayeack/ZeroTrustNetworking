"""The quarantine request bodies (generating prompt 12.1). The same logic ships in the SOAR custom function
zt_build_cnp; keep both identical."""
from collections import OrderedDict

LABEL_KEY = "zt-quarantine"


def build(namespace, pod, workload, job_id, finding_id):
    """Return dict(policy_name, label_patch_json, cnp_json, policy_yaml, label_key, label_value).
    A CI job behind the connection names the policy zt-quarantine-<workload>-<job id> and is the label value; without
    one (a notebook, a service) the pod itself does: zt-quarantine-<pod>, label zt-quarantine=<pod>."""
    wl = workload.split("/")[-1]
    job_id = str(job_id if job_id is not None else "").strip()
    if job_id.isdigit():
        policy_name = "zt-quarantine-%s-%s" % (wl, job_id)
    else:
        job_id = pod
        policy_name = "zt-quarantine-%s" % pod
    label_patch = OrderedDict([("metadata", OrderedDict([("labels", OrderedDict([(LABEL_KEY, job_id)]))]))])
    cnp = OrderedDict([
        ("apiVersion", "cilium.io/v2"), ("kind", "CiliumNetworkPolicy"),
        ("metadata", OrderedDict([("name", policy_name), ("namespace", namespace),
                                  ("labels", OrderedDict([("app.kubernetes.io/managed-by", "zt-quarantine-workload"), ("zt/finding", str(finding_id))]))])),
        ("spec", OrderedDict([("endpointSelector", OrderedDict([("matchLabels", OrderedDict([(LABEL_KEY, job_id)]))])),
                              ("egressDeny", [OrderedDict([("toEntities", ["all"])])]),
                              ("ingressDeny", [OrderedDict([("fromEntities", ["all"])])])]))])
    yaml_text = ("apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  endpointSelector:\n    matchLabels:\n"
                 "      %s: \"%s\"\n  egressDeny:\n  - toEntities: [ all ]\n  ingressDeny:\n  - fromEntities: [ all ]\n") % (policy_name, namespace, LABEL_KEY, job_id)
    return {"policy_name": policy_name, "label_patch_json": label_patch, "cnp_json": cnp, "policy_yaml": yaml_text, "label_key": LABEL_KEY, "label_value": job_id, "pod": pod, "namespace": namespace}


def approval_message(finding_id, workload, dest_workload, data_class, disposition, confidence, what_happened, action, enforcement_point, blast_radius, policy_yaml, pod, job_id, policy_name, request_id=""):
    """finding_id may be the ES investigation (ES-00004) or the finding group id; job_id is the label value."""
    def clean(x):
        return str(x or "").strip().rstrip(".")
    return ("Quarantine request {request_id}for {finding_id}: {workload} reached {dest_workload} ({data_class}).\n"
            "Agent brief: {disposition}, {confidence} confidence. {what_happened}\n"
            "Recommended: {action} at the {enforcement_point}. Blast radius: {blast_radius}.\n"
            "Policy to apply:\n{policy_yaml}\n"
            "Approve to label pod {pod} with zt-quarantine={job_id} and create {policy_name}. Reject to close without action.").format(
        request_id=(request_id + " ") if request_id else "", finding_id=finding_id, workload=workload, dest_workload=dest_workload, data_class=data_class,
        disposition=clean(disposition).replace("_", " "), confidence=clean(confidence), what_happened=str(what_happened or "").strip(), action=clean(action),
        enforcement_point=enforcement_point, blast_radius=clean(blast_radius) or "this pod only", policy_yaml=policy_yaml.rstrip("\n"),
        pod=pod, job_id=job_id, policy_name=policy_name)
