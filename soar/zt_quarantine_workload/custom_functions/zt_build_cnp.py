def zt_build_cnp(namespace=None, pod=None, workload=None, job_id=None, finding_id=None, **kwargs):
    """
    Build the quarantine request bodies for one workload: the pod label patch, the CiliumNetworkPolicy and the
    YAML shown to the approver. Naming: zt-quarantine-<workload>-<job id>; the label value is the job id.
    The same logic lives in the Splunk app (ztgen/cnp.py, build()); keep both identical.
    
    Args:
        namespace (CEF type: *): Namespace of the pod, for example build-farm
        pod (CEF type: *): Pod name, for example ci-runner-7d9f8-xk2lq
        workload (CEF type: *): Workload as namespace/name or name, for example build-farm/ci-runner
        job_id (CEF type: *): CI job id; becomes the label value, for example 88213
        finding_id (CEF type: *): Finding id carried in the policy label zt/finding
    
    Returns a JSON-serializable object that implements the configured data paths:
        policy_name: zt-quarantine-<workload>-<job id>
        label_patch_json: JSON body for PATCH .../pods/<pod> (Content-Type application/merge-patch+json)
        label_key: the label key (zt-quarantine)
        label_value: the label value (the job id)
        cnp_json: JSON body for POST .../ciliumnetworkpolicies
        policy_yaml: the policy as shown to the approver
        pod: the pod name, passed through
        namespace: the namespace, passed through
    """
    ############################ Custom Code Goes Below This Line #################################
    import json
    from collections import OrderedDict
    import phantom.rules as phantom

    LABEL_KEY = "zt-quarantine"

    outputs = {}

    namespace = (namespace or "").strip()
    pod = (pod or "").strip()
    workload = (workload or "").strip()
    job_id = str(job_id if job_id is not None else "").strip()
    finding_id = str(finding_id if finding_id is not None else "").strip()

    wl = workload.split("/")[-1]
    policy_name = "zt-quarantine-%s-%s" % (wl, job_id)
    label_patch = OrderedDict([("metadata", OrderedDict([("labels", OrderedDict([(LABEL_KEY, job_id)]))]))])
    cnp = OrderedDict([
        ("apiVersion", "cilium.io/v2"), ("kind", "CiliumNetworkPolicy"),
        ("metadata", OrderedDict([("name", policy_name), ("namespace", namespace),
                                  ("labels", OrderedDict([("app.kubernetes.io/managed-by", "zt-quarantine-workload"), ("zt/finding", finding_id)]))])),
        ("spec", OrderedDict([("endpointSelector", OrderedDict([("matchLabels", OrderedDict([(LABEL_KEY, job_id)]))])),
                              ("egressDeny", [OrderedDict([("toEntities", ["all"])])]),
                              ("ingressDeny", [OrderedDict([("fromEntities", ["all"])])])]))])
    yaml_text = ("apiVersion: cilium.io/v2\nkind: CiliumNetworkPolicy\nmetadata:\n  name: %s\n  namespace: %s\nspec:\n  endpointSelector:\n    matchLabels:\n"
                 "      %s: \"%s\"\n  egressDeny:\n  - toEntities: [ all ]\n  ingressDeny:\n  - fromEntities: [ all ]\n") % (policy_name, namespace, LABEL_KEY, job_id)

    outputs = {
        "policy_name": policy_name,
        "label_patch_json": json.dumps(label_patch),
        "label_key": LABEL_KEY,
        "label_value": job_id,
        "cnp_json": json.dumps(cnp),
        "policy_yaml": yaml_text,
        "pod": pod,
        "namespace": namespace,
    }
    phantom.debug("zt_build_cnp: %s for %s/%s (job %s)" % (policy_name, namespace, pod, job_id))

    # Return a JSON-serializable object
    assert json.dumps(outputs)  # Will raise an exception if the :outputs: object is not JSON-serializable
    return outputs
