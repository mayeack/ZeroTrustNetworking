"""
zt_quarantine_workload

Quarantine a workload after the ZT finding-based detection fires: read the ZTFlowInvestigator brief, build the
Cilium quarantine policy, ask SOC tier 2 (and NetOps for the DPU and switch enforcement points) for approval,
apply through the Kubernetes API, verify the first DROPPED flow in Splunk, and write the zt:enforcement:audit
trail while resolving the Enterprise Security investigation.

Full-code playbook for Splunk SOAR 8.7 (playbook type "es", Python 3.13). The eight blocks of the generating
prompt (section 12.2) keep their names: start_from_finding, read_brief, pick_point, build_policy, ask_approval,
apply, verify, record_and_resolve. Helper blocks carry the parent block's name as a prefix.

Started by the Enterprise Security automation rule "Zero Trust Protected Paths" (ES 8.7 uses automation rules,
not label activation) and runnable by hand from the finding's container.
"""

import phantom.rules as phantom
import json
import time
import uuid

# ------------------------------------------------------------------------------------------------ settings
PLAYBOOK_NAME = "zt_quarantine_workload"
RULE_NAME = "ZT - Workload Exceeded Risk Threshold on Protected-Path Signals - Rule"
FINDING_TITLE_PREFIX = "Unprotected path:"

ASSET_SPLUNK = "zt_splunk"              # Splunk app: run query
ASSET_K8S = "zt_k8s_api"                # HTTP app: Kubernetes API
ASSET_HEC = "zt_hec"                    # HTTP app: HTTP Event Collector
ASSET_HYPERSHIELD = "zt_hypershield"    # HTTP app: DPU rules endpoint
ASSET_NEXUS = "zt_nexus_nxapi"          # HTTP app: NX-API JSON-RPC endpoint
ASSET_ES = "builtin_mc_connector"       # Enterprise Security connector (created by the pairing)
ASSET_PHANTOM = "phantom"               # VERIFY: name of the Phantom utility app asset used for "no op"

ROLE_SOC = "SOC tier 2"
ROLE_NETOPS = "NetOps"
APPROVER_LABELS = {"kernel": "SOC tier 2", "dpu": "SOC tier 2, NetOps", "switch": "SOC tier 2, NetOps"}
PROMPT_MINUTES = 30

BRIEF_WAIT_SECONDS = 30
BRIEF_MAX_ATTEMPTS = 12                 # 12 x 30 s = 6 minutes
VERIFY_WAIT_SECONDS = 15
VERIFY_MAX_ATTEMPTS = 12                # 12 x 15 s = 3 minutes

HEC_PATH = "/services/collector/event"
HEC_INDEX = "zero_trust"
HEC_SOURCETYPE = "zt:enforcement:audit"
HEC_HOST = "soar"

ES_STATUS_IN_PROGRESS = "In Progress"
ES_STATUS_RESOLVED = "Resolved"
ES_DISPOSITION_TP = "True Positive - Suspicious Activity"
DEFAULT_COMMENT = "Contractor merge request; not approved for checkpoint access"

BRIEF_FIELDS = ["finding_id", "finding_display_id", "investigation_id", "investigation_guid", "workload", "pod", "node", "job_id",
                "dest_workload", "data_class", "disposition", "confidence", "enforcement_point", "action", "policy_name",
                "blast_radius", "approver_labels", "brief_text", "what_happened", "run_epoch"]


# ------------------------------------------------------------------------------------------------ helpers
def _get(key, default=None):
    """Run-scoped state (phantom run data), JSON encoded under the zt: prefix."""
    raw = phantom.get_run_data(key="zt:" + key)
    return json.loads(raw) if raw else default


def _set(key, value):
    phantom.save_run_data(key="zt:" + key, value=json.dumps(value))


def _state():
    return _get("state", {})


def _update(**fields):
    state = _state()
    state.update(fields)
    _set("state", state)
    return state


def _publish(block, **outputs):
    """Publish code block outputs the way the visual editor does: run data under <block>:<name>, read back through
    the datapath <block>:custom_function:<name>."""
    for name, value in outputs.items():
        phantom.save_run_data(key="%s:%s" % (block, name), value=json.dumps(value))


def _iso_ms(t):
    whole = int(t)
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(whole)) + ".%03dZ" % int(round((t - whole) * 1000))


def _iso_s(t):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(int(t)))


def _first(values):
    """First non-empty value of a collect2 column."""
    for v in values:
        if v not in (None, "", [], {}):
            return v
    return None


def _rows(container, name, fields, results=None):
    """Result rows of an action as dicts, from the action_result.data.* datapaths of the named block."""
    datapaths = ["%s:action_result.data.*.%s" % (name, f) for f in fields]
    if results:
        collected = phantom.collect2(container=container, datapath=datapaths, action_results=results)
    else:
        collected = phantom.collect2(container=container, datapath=datapaths)
    return [dict(zip(fields, item)) for item in collected if any(v not in (None, "") for v in item)]


def _status_code(container, name, results):
    codes = phantom.collect2(container=container, datapath=["%s:action_result.summary.status_code" % name], action_results=results)
    code = _first([c[0] for c in codes])
    try:
        return int(code)
    except (TypeError, ValueError):
        return 0


def _audit_id(container, name, results):
    """Audit-Id response header of an HTTP action, or metadata.annotations["zt/auditID"] from the body."""
    data = phantom.collect2(container=container, datapath=["%s:action_result.data.*.response_headers" % name,
                                                           "%s:action_result.data.*.parsed_response_body" % name], action_results=results)
    for headers, body in data:
        if isinstance(headers, dict):
            for k, v in headers.items():
                if str(k).lower() == "audit-id" and v:
                    return str(v)
        if isinstance(body, dict):
            annotations = (body.get("metadata") or {}).get("annotations") or {}
            if annotations.get("zt/auditID"):
                return str(annotations["zt/auditID"])
    return ""


def _playbook_run_id():
    try:
        info = phantom.get_playbook_info()
        if info and info[0].get("run_id"):
            return str(info[0]["run_id"])
    except Exception as e:  # noqa: BLE001
        phantom.debug("get_playbook_info failed: %s" % e)
    return _state().get("run_id") or ""


def _finding_time(data):
    """The finding's time as ES wants it in finding_times (string form)."""
    for key in ("finding_time", "_time", "notable_time", "orig_time", "info_max_time"):
        v = data.get(key)
        if v not in (None, ""):
            return str(v)
    return ""

# ------------------------------------------------------------------------------------------------ start
@phantom.playbook_block()
def on_start(container):
    phantom.debug("on_start() called")

    _set("state", {"run_id": str(uuid.uuid4()), "started_epoch": time.time(), "k8s_audit_ids": [], "approvals": []})
    _set("brief_attempts", 0)
    _set("verify_attempts", 0)

    # call 'start_from_finding' block
    start_from_finding(container=container)

    return


# ------------------------------------------------------------------------------------------------ 1 start_from_finding
@phantom.playbook_block()
def start_from_finding(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Read the finding from the container; stop unless it is the ZT finding-based detection."""
    phantom.debug("start_from_finding() called")

    data = container.get("data") or {}
    if isinstance(data, str):
        try:
            data = json.loads(data)
        except ValueError:
            data = {}

    finding_id = str(data.get("id") or container.get("source_data_identifier") or "")
    event_id = str(data.get("event_id") or container.get("external_id") or finding_id)
    rule = str(data.get("search_name") or data.get("source") or data.get("rule_name") or data.get("orig_rule_name") or "")
    title = str(data.get("name") or data.get("rule_title") or container.get("name") or "")
    entity = str(data.get("normalized_risk_object") or data.get("risk_object") or data.get("entity") or "")

    if rule != RULE_NAME and not title.startswith(FINDING_TITLE_PREFIX):
        phantom.comment(container=container, comment="%s: not the ZT finding-based detection (rule %r, title %r); nothing to do." % (PLAYBOOK_NAME, rule, title))
        return

    _update(finding_id=finding_id, event_id=event_id, rule=rule, finding_title=title, entity=entity, finding_time=_finding_time(data),
            risk_score=data.get("risk_score"), container_id=container.get("id"))
    # code block outputs, addressable as start_from_finding:custom_function:<name> in phantom.format and phantom.decision
    _publish("start_from_finding", finding_id=finding_id, event_id=event_id, entity=entity, rule=rule, finding_title=title, playbook=PLAYBOOK_NAME,
             min_brief_epoch=int(time.time()) - 900)
    phantom.debug("finding %s (event %s) for %s: %s" % (finding_id, event_id, entity, title))

    # The brief is read first: when the agent ran, its capture already opened the investigation and the brief carries
    # the guid. The ES connector lookups run only when the brief has no investigation.
    read_brief(container=container)

    return


@phantom.playbook_block()
def start_from_finding_investigations(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Look for an investigation that already holds the finding."""
    phantom.debug("start_from_finding_investigations() called")

    state = _state()
    parameters = [{
        "id": state["finding_id"],
        "limit": 10,
        "include_all_fields": False,
    }]
    if state.get("finding_time"):
        parameters[0]["notable_time"] = state["finding_time"]  # VERIFY: notable_time format expected by the ES connector

    phantom.act("get related investigations for finding", parameters=parameters, name="start_from_finding_investigations", assets=[ASSET_ES], callback=start_from_finding_investigations_check)

    return


@phantom.playbook_block()
def start_from_finding_investigations_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("start_from_finding_investigations_check() called")

    # VERIFY: output field names of "get related investigations for finding" (investigation_guid, investigation_id, name, status)
    rows = _rows(container, "start_from_finding_investigations", ["investigation_guid", "investigation_id", "id", "name", "status"], results)
    open_rows = [r for r in rows if str(r.get("status") or "") not in ("Closed",)]
    if open_rows:
        inv = open_rows[0]
        _update(investigation_guid=str(inv.get("investigation_guid") or inv.get("id") or ""), investigation_id=str(inv.get("investigation_id") or inv.get("investigation_guid") or inv.get("id") or ""))
        phantom.debug("using investigation %s (%s)" % (_state()["investigation_id"], _state()["investigation_guid"]))
        pick_point(container=container)
        return

    start_from_finding_new_investigation(container=container)

    return


@phantom.playbook_block()
def start_from_finding_new_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """No investigation yet: start one from the finding."""
    phantom.debug("start_from_finding_new_investigation() called")

    state = _state()
    parameters = [{
        "name": state.get("finding_title") or "Zero trust finding",
        "finding_ids": state["finding_id"],                 # VERIFY: comma-separated list form of finding_ids
        "status": "New",
        "urgency": "high",
        "description": "Opened by %s for %s." % (PLAYBOOK_NAME, state.get("entity") or state["finding_id"]),
        "ensure_enriched": False,
    }]
    if state.get("finding_time"):
        parameters[0]["finding_times"] = state["finding_time"]  # VERIFY: finding_times format (string time of the finding)

    phantom.act("start investigations", parameters=parameters, name="start_from_finding_new_investigation", assets=[ASSET_ES], callback=start_from_finding_record_investigation)

    return


@phantom.playbook_block()
def start_from_finding_record_investigation(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("start_from_finding_record_investigation() called")

    # VERIFY: output field names of "start investigations" (investigation_guid, investigation_id)
    rows = _rows(container, "start_from_finding_new_investigation", ["investigation_guid", "investigation_id", "id"], results)
    if rows:
        inv = rows[0]
        _update(investigation_guid=str(inv.get("investigation_guid") or inv.get("id") or ""), investigation_id=str(inv.get("investigation_id") or inv.get("investigation_guid") or inv.get("id") or ""))
        phantom.debug("started investigation %s (%s)" % (_state()["investigation_id"], _state()["investigation_guid"]))
    else:
        phantom.comment(container=container, comment="%s: could not start an investigation for finding %s; continuing without ES notes." % (PLAYBOOK_NAME, _state()["finding_id"]))
        _update(investigation_guid="", investigation_id="")

    pick_point(container=container)

    return


# ------------------------------------------------------------------------------------------------ 2 read_brief
@phantom.playbook_block()
def read_brief(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Read the agent brief for this finding from the KV store lookup (polled every 30 s for up to 6 minutes)."""
    phantom.debug("read_brief() called")

    query_formatted_string = phantom.format(
        container=container,
        # ES reuses a finding group's id on every fire, so only a brief of this run counts: its key ends with the reset
        # stamp of the run (ztbrief's run key) and it was captured after this playbook started, less a margin
        template="""zt_agent_briefs_lookup where finding_id="{0}" OR finding_id="{1}" | eval zt_run=tonumber(mvindex(split(_key,"@"),-1)) | where zt_run>=[| inputlookup zt_demo_state_lookup | where _key="global" | eval r=floor(tonumber(last_reset_epoch)) | return $r] AND tonumber(run_epoch)>={2} | sort - run_epoch | head 1""",
        parameters=[
            "start_from_finding:custom_function:event_id",
            "start_from_finding:custom_function:finding_id",
            "start_from_finding:custom_function:min_brief_epoch"
        ])

    parameters = [{
        "query": query_formatted_string,
        "command": "| inputlookup",
        "display": ",".join(BRIEF_FIELDS),
    }]

    phantom.act("run query", parameters=parameters, name="read_brief", assets=[ASSET_SPLUNK], callback=read_brief_check)

    return


@phantom.playbook_block()
def read_brief_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_brief_check() called")

    rows = _rows(container, "read_brief", BRIEF_FIELDS, results)
    if rows:
        brief = {k: ("" if v is None else v) for k, v in rows[0].items()}
        brief["enforcement_point"] = str(brief.get("enforcement_point") or "none").lower()
        brief["disposition"] = str(brief.get("disposition") or "").lower()
        state = _update(brief=brief)
        if brief.get("investigation_guid") and not state.get("investigation_guid"):
            _update(investigation_guid=brief["investigation_guid"], investigation_id=brief.get("investigation_id") or brief["investigation_guid"])
        phantom.debug("brief: %s at the %s (%s)" % (brief["disposition"], brief["enforcement_point"], brief.get("approver_labels")))
        if _state().get("investigation_guid"):
            pick_point(container=container)
        else:
            start_from_finding_investigations(container=container)
        return

    attempts = _get("brief_attempts", 0) + 1
    _set("brief_attempts", attempts)
    if attempts >= BRIEF_MAX_ATTEMPTS:
        _update(comment="no agent brief within %d minutes" % (BRIEF_WAIT_SECONDS * BRIEF_MAX_ATTEMPTS // 60))
        read_brief_missing(container=container)
        return

    read_brief_wait(container=container)

    return


@phantom.playbook_block()
def read_brief_wait(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("read_brief_wait() called")

    parameters = [{"sleep_seconds": BRIEF_WAIT_SECONDS}]

    phantom.act("no op", parameters=parameters, name="read_brief_wait", assets=[ASSET_PHANTOM], callback=read_brief)

    return


@phantom.playbook_block()
def read_brief_missing(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """No brief arrived: leave a note on the investigation and end."""
    phantom.debug("read_brief_missing() called")

    state = _state()
    target = state.get("investigation_guid") or state.get("finding_id")
    parameters = [{
        "id": target,
        "title": "Quarantine not requested",
        "content": "No ZTFlowInvestigator brief for finding %s after %d minutes; no enforcement requested by %s." % (state.get("event_id"), BRIEF_WAIT_SECONDS * BRIEF_MAX_ATTEMPTS // 60, PLAYBOOK_NAME),
        "ai_generated": False,
    }]

    phantom.act("add finding or investigation note", parameters=parameters, name="read_brief_missing", assets=[ASSET_ES])

    return


# ------------------------------------------------------------------------------------------------ 3 pick_point
@phantom.playbook_block()
def pick_point(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """True positive at the kernel, DPU or switch? Anything else ends with a note."""
    phantom.debug("pick_point() called")

    # check for 'if' condition 1: true positive, kernel
    found_match_1 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["read_brief:action_result.data.*.disposition", "==", "true_positive"],
            ["read_brief:action_result.data.*.enforcement_point", "==", "kernel"]
        ],
        delimiter=None)

    # call connected blocks if condition 1 matched
    if found_match_1:
        build_policy(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 2: true positive, DPU
    found_match_2 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["read_brief:action_result.data.*.disposition", "==", "true_positive"],
            ["read_brief:action_result.data.*.enforcement_point", "==", "dpu"]
        ],
        delimiter=None)

    # call connected blocks if condition 2 matched
    if found_match_2:
        build_policy(action=action, success=success, container=container, results=results, handle=handle)
        return

    # check for 'elif' condition 3: true positive, switch
    found_match_3 = phantom.decision(
        container=container,
        logical_operator="and",
        conditions=[
            ["read_brief:action_result.data.*.disposition", "==", "true_positive"],
            ["read_brief:action_result.data.*.enforcement_point", "==", "switch"]
        ],
        delimiter=None)

    # call connected blocks if condition 3 matched
    if found_match_3:
        build_policy(action=action, success=success, container=container, results=results, handle=handle)
        return

    # else: no enforcement
    pick_point_no_action(action=action, success=success, container=container, results=results, handle=handle)

    return


@phantom.playbook_block()
def pick_point_no_action(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """The brief does not call for enforcement: note it on the investigation and end."""
    phantom.debug("pick_point_no_action() called")

    state = _state()
    brief = state.get("brief") or {}
    content_formatted_string = phantom.format(
        container=container,
        template="""No enforcement by {0}: the agent brief says {1} ({2} confidence) with enforcement point {3}.\n\n{4}""",
        parameters=[
            "start_from_finding:custom_function:playbook",
            "read_brief:action_result.data.*.disposition",
            "read_brief:action_result.data.*.confidence",
            "read_brief:action_result.data.*.enforcement_point",
            "read_brief:action_result.data.*.brief_text"
        ])

    parameters = [{
        "id": state.get("investigation_guid") or state.get("finding_id"),
        "title": "No enforcement",
        "content": content_formatted_string or "No enforcement by %s: %s at the %s." % (PLAYBOOK_NAME, brief.get("disposition"), brief.get("enforcement_point")),
        "ai_generated": False,
    }]

    phantom.act("add finding or investigation note", parameters=parameters, name="pick_point_no_action", assets=[ASSET_ES])

    return


# ------------------------------------------------------------------------------------------------ 4 build_policy
@phantom.playbook_block()
def build_policy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Policy name, request bodies and YAML from the custom function zt_build_cnp (same logic as the Splunk app)."""
    phantom.debug("build_policy() called")

    brief = _state()["brief"]
    workload = brief.get("workload") or ""
    namespace = workload.split("/")[0] if "/" in workload else ""

    parameters = []
    parameters.append({
        "namespace": namespace,
        "pod": brief.get("pod") or "",
        "workload": workload,
        "job_id": str(brief.get("job_id") or ""),
        "finding_id": brief.get("finding_id") or _state()["event_id"],
    })

    phantom.custom_function(custom_function="local/zt_build_cnp", parameters=parameters, name="build_policy", callback=build_policy_done)

    return


@phantom.playbook_block()
def build_policy_done(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_policy_done() called")

    outputs = phantom.collect2(container=container, datapath=[
        "build_policy:custom_function_result.data.policy_name",
        "build_policy:custom_function_result.data.label_patch_json",
        "build_policy:custom_function_result.data.cnp_json",
        "build_policy:custom_function_result.data.policy_yaml",
        "build_policy:custom_function_result.data.namespace",
        "build_policy:custom_function_result.data.pod",
    ])
    if not outputs or not outputs[0][0]:
        phantom.error("build_policy: the custom function returned nothing")
        return
    policy_name, label_patch_json, cnp_json, policy_yaml, namespace, pod = outputs[0]
    brief = _state()["brief"]
    _update(policy_name=policy_name, label_patch_json=label_patch_json, cnp_json=cnp_json, policy_yaml=policy_yaml, namespace=namespace, pod=pod,
            workload=brief.get("workload") or "", job_id=str(brief.get("job_id") or ""), enforcement_point=brief["enforcement_point"],
            action=("CNP %s" % policy_name) if brief.get("enforcement_point") == "kernel" else (brief.get("action") or "CNP %s" % policy_name), target="%s/%s" % (namespace, pod), approver_labels=APPROVER_LABELS.get(brief["enforcement_point"], ROLE_SOC),
            comment=DEFAULT_COMMENT, audit_finding_id=brief.get("finding_id") or _state()["event_id"])

    build_policy_request_id(container=container)

    return


@phantom.playbook_block()
def build_policy_request_id(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Number this request one above the highest request ID of the day, from the audit trail and the local request store."""
    phantom.debug("build_policy_request_id() called")

    day = time.strftime("%Y%m%d", time.gmtime())
    _publish("build_policy_request_id", day=day)
    query_formatted_string = phantom.format(
        container=container,
        template="""index=zero_trust sourcetype=zt:enforcement:audit request_id="ZTR-{0}-*" earliest=-26h latest=now | fields request_id | append [| inputlookup zt_enforcement_requests_lookup | search request_id="ZTR-{0}-*" | fields request_id] | rex field=request_id "-(?<seq>\\d{{4}})$" | stats max(seq) as incident_requests""",
        parameters=[
            "build_policy_request_id:custom_function:day"
        ])

    parameters = [{
        "query": query_formatted_string,
        "command": "search",
        "display": "incident_requests",
    }]

    phantom.act("run query", parameters=parameters, name="build_policy_request_id", assets=[ASSET_SPLUNK], callback=build_policy_request_id_done)

    return


@phantom.playbook_block()
def build_policy_request_id_done(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("build_policy_request_id_done() called")

    rows = _rows(container, "build_policy_request_id", ["incident_requests"], results)
    try:
        todays = int(float(rows[0]["incident_requests"])) if rows else 0
    except (TypeError, ValueError):
        todays = 0
    day = time.strftime("%Y%m%d", time.gmtime())
    request_id = "ZTR-%s-%04d" % (day, max(16, todays) + 1)  # one above the highest ID of the day (local, SOAR and routine)
    _update(request_id=request_id, requested_epoch=time.time())
    phantom.debug("request %s" % request_id)

    record_and_resolve_state(container=container, state="requested", next_block="ask_approval")

    return


# ------------------------------------------------------------------------------------------------ 5 ask_approval
def _prompt_answer(container, name, results):
    """(decision, comment, responding user) of a prompt block; decision is "" when nobody answered in time."""
    data = phantom.collect2(container=container, datapath=["%s:action_result.summary.responses.0" % name,
                                                           "%s:action_result.summary.responses.1" % name,
                                                           "%s:action_result.status" % name], action_results=results)
    decision, comment = "", ""
    for d, c, status in data:
        if d:
            decision, comment = str(d).strip(), str(c or "").strip()
            break
    user = ""
    # VERIFY: which summary field carries the responding user for an in-product prompt (summary.user holds the SAML
    # user of an external prompt); fall back to the action result message, then to the role name.
    for key in ("user", "responding_user", "responder", "username"):
        found = phantom.collect2(container=container, datapath=["%s:action_result.summary.%s" % (name, key)], action_results=results)
        value = _first([f[0] for f in found])
        if value:
            user = str(value)
            break
    if not user:
        for result in results or []:
            for ar in result.get("action_results", []) if isinstance(result, dict) else []:
                message = str(ar.get("message") or "")
                for marker in ("responded by ", "response from ", "by user "):
                    if marker in message.lower():
                        user = message.lower().split(marker, 1)[1].split()[0].strip(".,'\"")
                        break
                if user:
                    break
            if user:
                break
    return decision, comment, user


def _approval_message(container):
    """The approval message of section 12.1, from this run's brief and the policy built for it."""
    st = _state()
    b = st.get("brief") or {}

    def clean(x):
        return str(x or "").strip().rstrip(".")

    job = str(st.get("job_id") or "")
    label = job if job.isdigit() else st.get("pod", "")
    ref = st.get("investigation_id") or st.get("event_id") or ""
    return ("Quarantine request %s for %s: %s reached %s (%s).\n"
            "Agent brief: %s, %s confidence. %s\n"
            "Recommended: %s at the %s. Blast radius: %s.\n"
            "Policy to apply:\n%s"
            "Approve to label pod %s with zt-quarantine=%s and create %s. Reject to close without action.") % (
        st.get("request_id", ""), ref, b.get("workload", ""), b.get("dest_workload", ""), b.get("data_class", ""),
        clean(b.get("disposition")).replace("_", " "), clean(b.get("confidence")), str(b.get("what_happened") or "").strip(),
        clean(st.get("action")), st.get("enforcement_point", ""), clean(b.get("blast_radius")) or "this pod only",
        st.get("policy_yaml", ""), st.get("pod", ""), label, st.get("policy_name", ""))


@phantom.playbook_block()
def ask_approval(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Ask the SOC tier 2 role to approve or reject, with a comment; 30 minutes."""
    phantom.debug("ask_approval() called")

    # set user and message variables for phantom.prompt call
    user = None
    role = ROLE_SOC
    message = _approval_message(container)

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Approve or reject the quarantine",
            "options": {
                "type": "list",
                "choices": [
                    "Approve",
                    "Reject"
                ]
            },
        },
        {
            "prompt": "Comment",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=PROMPT_MINUTES, name="ask_approval", parameters=parameters, response_types=response_types, callback=ask_approval_decision)

    return


@phantom.playbook_block()
def ask_approval_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ask_approval_decision() called")

    decision, comment, user = _prompt_answer(container, "ask_approval", results)
    if not decision:
        _update(comment="no %s decision within %d minutes" % (ROLE_SOC, PROMPT_MINUTES))
        record_and_resolve_state(container=container, state="failed", next_block="")
        return

    approvals = _state().get("approvals", [])
    approvals.append({"user": user or ROLE_SOC, "role_label": ROLE_SOC, "time": time.time(), "comment": comment, "decision": decision})
    state = _update(approvals=approvals, comment=comment or _state().get("comment") or DEFAULT_COMMENT)

    # check for 'if' condition 1: approved
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ask_approval:action_result.summary.responses.0", "==", "Approve"]
        ],
        delimiter=None)

    if found_match_1 and state["enforcement_point"] in ("dpu", "switch"):
        ask_approval_netops(action=action, success=success, container=container, results=results, handle=handle)
        return

    if found_match_1:
        record_and_resolve_state(container=container, state="approved", next_block="apply")
        return

    # rejected
    record_and_resolve_state(container=container, state="rejected", next_block="")

    return


@phantom.playbook_block()
def ask_approval_netops(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """DPU and switch enforcement points need NetOps as the second approver."""
    phantom.debug("ask_approval_netops() called")

    # set user and message variables for phantom.prompt call
    user = None
    role = ROLE_NETOPS
    message = _approval_message(container)

    # parameter list for template variable replacement
    parameters = []

    # responses
    response_types = [
        {
            "prompt": "Approve or reject the quarantine (NetOps)",
            "options": {
                "type": "list",
                "choices": [
                    "Approve",
                    "Reject"
                ]
            },
        },
        {
            "prompt": "Comment",
            "options": {
                "type": "message",
            },
        }
    ]

    phantom.prompt2(container=container, user=user, role=role, message=message, respond_in_mins=PROMPT_MINUTES, name="ask_approval_netops", parameters=parameters, response_types=response_types, callback=ask_approval_netops_decision)

    return


@phantom.playbook_block()
def ask_approval_netops_decision(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("ask_approval_netops_decision() called")

    decision, comment, user = _prompt_answer(container, "ask_approval_netops", results)
    if not decision:
        _update(comment="no %s decision within %d minutes" % (ROLE_NETOPS, PROMPT_MINUTES))
        record_and_resolve_state(container=container, state="failed", next_block="")
        return

    approvals = _state().get("approvals", [])
    approvals.append({"user": user or ROLE_NETOPS, "role_label": ROLE_NETOPS, "time": time.time(), "comment": comment, "decision": decision})
    _update(approvals=approvals, comment=comment or _state().get("comment") or DEFAULT_COMMENT)

    # check for 'if' condition 1: approved
    found_match_1 = phantom.decision(
        container=container,
        conditions=[
            ["ask_approval_netops:action_result.summary.responses.0", "==", "Approve"]
        ],
        delimiter=None)

    if found_match_1:
        record_and_resolve_state(container=container, state="approved", next_block="apply")
        return

    record_and_resolve_state(container=container, state="rejected", next_block="")

    return


def _approved_by(state):
    """("j.chen", "SOC tier 2") or ("j.chen + a.patel", "SOC tier 2 + NetOps") from the recorded approvals."""
    approvals = [a for a in state.get("approvals", []) if a.get("decision") == "Approve"]
    by = " + ".join(a["user"] for a in approvals)
    role = " + ".join(a["role_label"] for a in approvals)
    approved_at = max([a["time"] for a in approvals] or [0])
    return by, role, approved_at


# ------------------------------------------------------------------------------------------------ 6 apply
@phantom.playbook_block()
def apply(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Label the pod (PATCH, merge patch) and then create the CiliumNetworkPolicy (POST) on the Kubernetes API."""
    phantom.debug("apply() called")

    state = _state()
    location_formatted_string = phantom.format(
        container=container,
        template="""/api/v1/namespaces/{0}/pods/{1}""",
        parameters=[
            "build_policy:custom_function_result.data.namespace",
            "build_policy:custom_function_result.data.pod"
        ])

    parameters = [{
        "location": location_formatted_string,
        "body": state["label_patch_json"],
        "headers": json.dumps({"Content-Type": "application/merge-patch+json", "User-Agent": "zt-quarantine-workload/1.0"}),
        "verify_certificate": False,
    }]

    phantom.act("patch data", parameters=parameters, name="apply", assets=[ASSET_K8S], callback=apply_policy)

    return


@phantom.playbook_block()
def apply_policy(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("apply_policy() called")

    code = _status_code(container, "apply", results)
    if not success or code != 200:
        _update(comment="pod label patch failed (HTTP %s)" % (code or "error"))
        record_and_resolve_state(container=container, state="failed", next_block="")
        return
    audit_ids = _state().get("k8s_audit_ids", [])
    audit_id = _audit_id(container, "apply", results)
    if audit_id:
        audit_ids.append(audit_id)
    state = _update(k8s_audit_ids=audit_ids)

    location_formatted_string = phantom.format(
        container=container,
        template="""/apis/cilium.io/v2/namespaces/{0}/ciliumnetworkpolicies""",
        parameters=[
            "build_policy:custom_function_result.data.namespace"
        ])

    parameters = [{
        "location": location_formatted_string,
        "body": state["cnp_json"],
        "headers": json.dumps({"Content-Type": "application/json", "User-Agent": "zt-quarantine-workload/1.0"}),
        "verify_certificate": False,
    }]

    phantom.act("post data", parameters=parameters, name="apply_policy", assets=[ASSET_K8S], callback=apply_policy_check)

    return


@phantom.playbook_block()
def apply_policy_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("apply_policy_check() called")

    code = _status_code(container, "apply_policy", results)
    if code == 409:
        phantom.debug("policy already exists (retry after a partial apply); keeping going")
    elif not success or code != 201:
        _update(comment="policy create failed (HTTP %s)" % (code or "error"))
        record_and_resolve_state(container=container, state="failed", next_block="")
        return
    else:
        audit_ids = _state().get("k8s_audit_ids", [])
        audit_id = _audit_id(container, "apply_policy", results)
        if audit_id:
            audit_ids.append(audit_id)
        _update(k8s_audit_ids=audit_ids)

    point = _state()["enforcement_point"]
    if point == "dpu":
        apply_dpu(container=container)
    elif point == "switch":
        apply_switch(container=container)
    else:
        apply_done(container=container)

    return


@phantom.playbook_block()
def apply_dpu(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """DPU enforcement point: push the same deny to the Hypershield rules endpoint."""
    phantom.debug("apply_dpu() called")

    state = _state()
    rule = {
        "name": state["policy_name"],
        "enforcement_point": "dpu",
        "match": {"namespace": state["namespace"], "pod": state["pod"], "labels": {"zt-quarantine": state["job_id"]}},
        "action": "deny",
        "direction": "both",
        "finding_id": state["audit_finding_id"],
        "request_id": state["request_id"],
    }
    parameters = [{
        "location": "/hypershield/v1/rules",
        "body": json.dumps(rule),
        "headers": json.dumps({"Content-Type": "application/json", "User-Agent": "zt-quarantine-workload/1.0"}),
        "verify_certificate": False,
    }]

    phantom.act("post data", parameters=parameters, name="apply_dpu", assets=[ASSET_HYPERSHIELD], callback=apply_stub_check)

    return


@phantom.playbook_block()
def apply_switch(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Switch enforcement point: NX-API JSON-RPC to the leaf that serves the node."""
    phantom.debug("apply_switch() called")

    state = _state()
    brief = state.get("brief") or {}
    device = brief.get("switch") or "dc2-leaf-205"
    commands = ["configure terminal", "ip access-list zt-quarantine-%s" % state["job_id"],
                "10 deny ip any any log", "interface %s" % (brief.get("interface") or "Eth1/12"), "ip access-group zt-quarantine-%s in" % state["job_id"]]
    body = [{"jsonrpc": "2.0", "method": "cli", "params": {"cmd": cmd, "version": 1}, "id": i + 1} for i, cmd in enumerate(commands)]
    parameters = [{
        "location": "/ins",
        "body": json.dumps(body),
        "headers": json.dumps({"Content-Type": "application/json-rpc", "X-Nexus-Device": device, "User-Agent": "zt-quarantine-workload/1.0"}),
        "verify_certificate": False,
    }]

    phantom.act("post data", parameters=parameters, name="apply_switch", assets=[ASSET_NEXUS], callback=apply_stub_check)

    return


@phantom.playbook_block()
def apply_stub_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("apply_stub_check() called")

    if not success:
        _update(comment="%s enforcement call failed" % _state()["enforcement_point"])
        record_and_resolve_state(container=container, state="failed", next_block="")
        return

    apply_done(container=container)

    return


@phantom.playbook_block()
def apply_done(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("apply_done() called")

    _update(applied_epoch=time.time())
    _set("verify_attempts", 0)
    record_and_resolve_state(container=container, state="applied", next_block="verify")

    return


# ------------------------------------------------------------------------------------------------ 7 verify
@phantom.playbook_block()
def verify(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Poll Splunk every 15 s for the first flow DROPPED by the quarantine policy (up to 3 minutes after apply)."""
    phantom.debug("verify() called")

    state = _state()
    _publish("apply_done", applied_epoch=int(state["applied_epoch"]) - 5)
    query_formatted_string = phantom.format(
        container=container,
        template="""index=zero_trust sourcetype=cilium:hubble:flow src_pod="{0}" verdict=DROPPED policy_denied="{1}" earliest={2} latest=now | head 1 | table _time src_identity policy_denied drop_reason""",
        parameters=[
            "build_policy:custom_function_result.data.pod",
            "build_policy:custom_function_result.data.policy_name",
            "apply_done:custom_function:applied_epoch"
        ])

    parameters = [{
        "query": query_formatted_string,
        "command": "search",
        "display": "_time,src_identity,policy_denied,drop_reason",
    }]

    phantom.act("run query", parameters=parameters, name="verify", assets=[ASSET_SPLUNK], callback=verify_check)

    return


@phantom.playbook_block()
def verify_check(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("verify_check() called")

    rows = _rows(container, "verify", ["_time", "src_identity", "policy_denied", "drop_reason"], results)
    if rows:
        row = rows[0]
        raw_time = str(row.get("_time") or "")
        try:
            dropped_at = float(raw_time)
        except ValueError:
            dropped_at = time.time()
        _update(verified_epoch=time.time(), dropped_at=dropped_at, dropped_identity=str(row.get("src_identity") or ""),
                comment="first DROPPED flow by %s at %s (source identity %s)" % (_state()["policy_name"], _iso_s(dropped_at), row.get("src_identity") or ""))
        record_and_resolve_state(container=container, state="verified", next_block="")
        return

    attempts = _get("verify_attempts", 0) + 1
    _set("verify_attempts", attempts)
    if attempts >= VERIFY_MAX_ATTEMPTS or time.time() - _state()["applied_epoch"] > VERIFY_WAIT_SECONDS * VERIFY_MAX_ATTEMPTS:
        _update(comment="no DROPPED flow within %d s of apply" % (VERIFY_WAIT_SECONDS * VERIFY_MAX_ATTEMPTS))
        record_and_resolve_state(container=container, state="failed", next_block="")
        return

    verify_wait(container=container)

    return


@phantom.playbook_block()
def verify_wait(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    phantom.debug("verify_wait() called")

    parameters = [{"sleep_seconds": VERIFY_WAIT_SECONDS}]

    phantom.act("no op", parameters=parameters, name="verify_wait", assets=[ASSET_PHANTOM], callback=verify)

    return


# ------------------------------------------------------------------------------------------------ 8 record_and_resolve
def record_and_resolve_state(container, state, next_block):
    """Queue one audit state (requested, approved, rejected, applied, verified, failed) and run block 8."""
    _set("record", {"state": state, "next": next_block, "time": time.time()})
    record_and_resolve(container=container)


def _audit_event(state, audit_state, t):
    """The zt:enforcement:audit event of section 6.3, in key order, for one state."""
    by, role, approved_at = _approved_by(state)
    comment = state.get("comment") or DEFAULT_COMMENT
    status = "ok"
    if audit_state == "requested":
        by, role, approved_at = "", "", ""
        comment = DEFAULT_COMMENT
    elif audit_state == "rejected":
        last = (state.get("approvals") or [{}])[-1]
        by, role, approved_at = last.get("user", ""), last.get("role_label", ""), t
        comment = last.get("comment") or "rejected"
    elif audit_state == "failed":
        status = "failed"
    return {
        "time": _iso_ms(t),
        "request_id": state.get("request_id", ""),
        "finding_id": state.get("audit_finding_id") or state.get("event_id", ""),
        "investigation_id": state.get("investigation_id", ""),
        "state": audit_state,
        "enforcement_point": state.get("enforcement_point", "kernel"),
        "action": state.get("action", ""),
        "target": state.get("target", ""),
        "workload": state.get("workload", ""),
        "policy_name": state.get("policy_name", ""),
        "approved_by": by,
        "approver_role": role,
        "approved_at": _iso_s(approved_at) if isinstance(approved_at, (int, float)) and approved_at else (approved_at or ""),
        "executed_by": "soar",
        "playbook": PLAYBOOK_NAME,
        "run_id": _playbook_run_id(),
        "k8s_audit_ids": list(state.get("k8s_audit_ids") or []),
        "comment": comment,
        "status": status,
    }


@phantom.playbook_block()
def record_and_resolve(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Write the audit event for the queued state over HEC, then the ES note and status for that state."""
    phantom.debug("record_and_resolve() called")

    record = _get("record") or {}
    state = _state()
    audit_state = record.get("state", "")
    event = _audit_event(state, audit_state, record.get("time") or time.time())
    envelope = {"time": round(record.get("time") or time.time(), 3), "host": HEC_HOST, "source": PLAYBOOK_NAME, "sourcetype": HEC_SOURCETYPE, "index": HEC_INDEX, "event": event}
    phantom.debug("audit %s: %s" % (audit_state, json.dumps(event)))

    parameters = [{
        "location": HEC_PATH,
        "body": json.dumps(envelope, separators=(",", ":")),
        "headers": json.dumps({"Content-Type": "application/json"}),
        "verify_certificate": True,
    }]

    phantom.act("post data", parameters=parameters, name="record_and_resolve_%s" % audit_state, assets=[ASSET_HEC], callback=record_and_resolve_note)

    return


@phantom.playbook_block()
def record_and_resolve_note(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """The ES note for the state just recorded (none for approved)."""
    phantom.debug("record_and_resolve_note() called")

    if not success:
        phantom.comment(container=container, comment="%s: audit event for state %s was not accepted by HEC" % (PLAYBOOK_NAME, (_get("record") or {}).get("state")))

    record = _get("record") or {}
    state = _state()
    audit_state = record.get("state", "")
    by, role, approved_at = _approved_by(state)
    target = state.get("investigation_guid") or state.get("finding_id")

    if audit_state == "requested":
        title = "Quarantine requested"
        content = "Quarantine requested; waiting for %s approval.\n\nRequest %s for %s (%s at the %s).\nPolicy to apply:\n%s" % (
            state.get("approver_labels") or ROLE_SOC, state.get("request_id"), state.get("workload"), state.get("action"), state.get("enforcement_point"), state.get("policy_yaml", ""))
    elif audit_state == "rejected":
        last = (state.get("approvals") or [{}])[-1]
        title = "Quarantine rejected"
        content = "Quarantine %s rejected by %s (%s). %s" % (state.get("request_id"), last.get("user", ""), last.get("role_label", ""), last.get("comment") or "")
    elif audit_state == "applied":
        title = "Quarantine applied"
        content = "Approved by %s (%s) at %s. Pod %s labeled zt-quarantine=%s; CiliumNetworkPolicy %s created (Kubernetes audit %s). Verifying the next attempts." % (
            by, role, _iso_s(approved_at or state.get("applied_epoch") or time.time()), state.get("pod"), state.get("job_id"), state.get("policy_name"), ", ".join(state.get("k8s_audit_ids") or []))
    elif audit_state == "verified":
        title = "Quarantine verified"
        content = "Verified: the runner's next attempt was DROPPED by %s at %s (source identity %s, POLICY_DENY). Applied by SOAR after approval by %s (%s) at %s. Request %s." % (
            state.get("policy_name"), _iso_s(state.get("dropped_at") or time.time()), state.get("dropped_identity", ""), by, role, _iso_s(approved_at or time.time()), state.get("request_id"))
    elif audit_state == "failed":
        title = "Quarantine not verified" if state.get("applied_epoch") else "Quarantine failed"
        content = "%s. Request %s (%s at the %s)." % (state.get("comment") or "failed", state.get("request_id"), state.get("action"), state.get("enforcement_point"))
    else:
        title, content = "", ""

    if not title or not target:
        record_and_resolve_status(container=container)
        return

    parameters = [{
        "id": target,
        "title": title,
        "content": content,
        "ai_generated": False,
    }]

    phantom.act("add finding or investigation note", parameters=parameters, name="record_and_resolve_note_%s" % audit_state, assets=[ASSET_ES], callback=record_and_resolve_status)

    return


@phantom.playbook_block()
def record_and_resolve_status(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Investigation status: In Progress at request, Resolved with the true-positive disposition on verified."""
    phantom.debug("record_and_resolve_status() called")

    record = _get("record") or {}
    state = _state()
    audit_state = record.get("state", "")
    target = state.get("investigation_guid")

    if audit_state == "requested" and target:
        parameters = [{"id": target, "status": ES_STATUS_IN_PROGRESS}]
    elif audit_state == "verified" and target:
        parameters = [{"id": target, "status": ES_STATUS_RESOLVED, "disposition": ES_DISPOSITION_TP}]  # VERIFY: disposition accepts the label
    else:
        record_and_resolve_next(container=container)
        return

    phantom.act("update finding or investigation", parameters=parameters, name="record_and_resolve_status_%s" % audit_state, assets=[ASSET_ES], callback=record_and_resolve_next)

    return


@phantom.playbook_block()
def record_and_resolve_next(action=None, success=None, container=None, results=None, handle=None, filtered_artifacts=None, filtered_results=None, custom_function=None, loop_state_json=None, **kwargs):
    """Continue with the block that follows the recorded state."""
    phantom.debug("record_and_resolve_next() called")

    record = _get("record") or {}
    next_block = record.get("next") or ""
    _set("record", {})
    if next_block == "ask_approval":
        ask_approval(container=container)
    elif next_block == "apply":
        apply(container=container)
    elif next_block == "verify":
        verify(container=container)

    return


# ------------------------------------------------------------------------------------------------ finish
@phantom.playbook_block()
def on_finish(container, summary):
    phantom.debug("on_finish() called")

    state = _state()
    if state.get("request_id"):
        outcome = "verified" if state.get("verified_epoch") else "applied" if state.get("applied_epoch") else "ended"
        phantom.comment(container=container, comment="%s: request %s %s (%s at the %s; run %s)." % (
            PLAYBOOK_NAME, state["request_id"], outcome, state.get("policy_name") or state.get("action"), state.get("enforcement_point"), _playbook_run_id()))

    return
