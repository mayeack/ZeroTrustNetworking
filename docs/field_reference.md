# Field reference

Every sourcetype, raw key, normalized field, CIM mapping, eventtype, tag, lookup and KV collection of the Zero Trust Incident demo, as defined in `zt_incident_demo/default/props.conf`, `transforms.conf`, `eventtypes.conf`, `tags.conf`, `collections.conf`, `macros.conf` and the lookups. Canonical values are those of the story (design document section 3).

## Index and envelope

All events are JSON, sent to HTTP Event Collector's `/services/collector/event` endpoint by the generator (`bin/ztgen/builders.py`), the emulator and the response code. The envelope carries `time` (epoch seconds with milliseconds), `host`, `source`, `sourcetype` and `index`. The index is `zero_trust` for every event sourcetype; `zt_summary` receives the posture rollup (source `ZT Posture - Rollup`, `stash` sourcetype through `collect`). The scripted input's own sourcetype `zt:stream` (index `main`) never carries events: the input prints nothing to stdout.

Props common to every sourcetype: `KV_MODE = json`, `TRUNCATE = 0`, `SHOULD_LINEMERGE = false`, `LINE_BREAKER = ([\r\n]+)`, and `TIME_PREFIX` / `TIME_FORMAT` as a fallback for raw ingestion of the same JSON (the HEC envelope time is authoritative). Hubble and Tetragon timestamps are nanoseconds (`%Y-%m-%dT%H:%M:%S.%9NZ`); Tetragon's `TIME_PREFIX` is anchored to `},\s*"time":\s*"` so the process `start_time` never matches.

## Sourcetypes

| Sourcetype | What it is | In production it arrives through | host / source | Per 24 h (background) |
|---|---|---|---|---|
| `cilium:hubble:flow` | Hubble flow, exporter JSON | Hubble exporter → collector → HEC | node / `hubble-exporter` | 83,812: 11,400 ingress FORWARDED at protected stores, 2,306 ingress AUDIT on the eight known gaps, 13,706 egress FORWARDED for those connections, 55,000 other egress, 1,400 DROPPED (default deny between tenant namespaces) |
| `cisco:isovalent:processExec` | Tetragon process execution | Cisco Security Cloud App (Isovalent Runtime Security) | node / `tetragon` | 12,000 |
| `cisco:isovalent:processConnect` | Tetragon socket connect with the program behind it | Cisco Security Cloud App | node / `tetragon` | 13,706 (one per protected-path connection) |
| `cisco:isovalent` | Tetragon kprobe (enforcement actions, `KPROBE_ACTION_SIGKILL`) | Cisco Security Cloud App | node / `tetragon` | 2 |
| `ci:job:event` | CI job webhook (GitLab job hook format plus `merge_request`) | CI webhooks → HEC | `git.corp.internal` / `ci:job_hook` | 1,400 jobs, 2 or 3 events each |
| `cisco:nexus:endpoint` | Nexus Dashboard endpoint inventory: which server is on which switch port | Cisco data center networking add-on | switch / `nexus-dashboard` | 2,208 (one snapshot per node per hour, 92 nodes) |
| `cisco:nexus:liveprotect` | Live Protect status per switch | Nexus Dashboard export | switch / `nexus-dashboard` | 6 |
| `cisco:nexus:config` | Switch configuration change | Cisco data center networking add-on | switch / `nexus` | 10 (4 enforcement, 6 routine) |
| `kube:apiserver:audit` | Kubernetes API audit event (`audit.k8s.io/v1`) | API server audit log → HEC; live ones from the emulator | `kube-apiserver` / `k8s-audit` | about 37 |
| `zt:enforcement:audit` | The enforcement audit trail, one event per state change | SOAR playbook (Mode A) or the app's response code (Mode B) | `soar` or `splunk` / `zt_quarantine_workload` | 64 (16 actions × 4 states) |

The Tetragon sourcetype names are the Cisco Security Cloud App's; their props sit in a marked block of `props.conf` to be removed if that app is installed. The `cisco:nexus:*` names may differ from the real add-on.

## Raw JSON keys, summarised

**`cilium:hubble:flow`** — `{"flow": {...}, "node_name": "<cluster>/<node>", "time": "<RFC 3339 ns>"}`. Inside `flow`: `time`, `uuid`, `verdict` (`FORWARDED`, `AUDIT`, `DROPPED`), `IP.source`, `IP.destination`, `IP.ipVersion`, `l4.TCP.source_port`, `l4.TCP.destination_port`, `l4.TCP.flags` (or `l4.UDP.*`), `source` and `destination` objects (`ID` on the local endpoint only, `identity`, `cluster_name`, `namespace`, `labels[]` in `k8s:key=value` form, `pod_name`, `workloads[].name`, `workloads[].kind`), `Type` (`L3_L4`), `node_name`, `node_labels[]`, `event_type.type` (5 for policy verdicts, 1 for drops) and `event_type.sub_type`, `traffic_direction` (`INGRESS`, `EGRESS`), `policy_match_type`, `is_reply`, `Summary`, and, when present, `egress_allowed_by[]`, `ingress_allowed_by[]`, `egress_denied_by[]`, `ingress_denied_by[]` (each with `name`, `namespace`, `labels[]`, `revision`, `kind`), `drop_reason` (181) and `drop_reason_desc` (`POLICY_DENY`). The incident's ingress AUDIT flow at the store has identities 48213 → 30719; the DROPPED flows after the quarantine carry source identity 48291 and the label `k8s:zt-quarantine=88213`.

**`cisco:isovalent:processExec`**, **`cisco:isovalent:processConnect`**, **`cisco:isovalent`** — `{"process_exec" | "process_connect" | "process_kprobe": {...}, "node_name", "time", "cluster_name", "node_labels": {...}}`. The `process` and `parent` objects carry `exec_id`, `pid`, `uid`, `cwd`, `binary`, `arguments`, `flags`, `start_time`, `auid`, `pod` (`namespace`, `name`, `container.id`, `container.name`, `container.image.id`, `container.image.name`, `container.start_time`, `container.pid`, `pod_labels`, `workload`, `workload_kind`), `docker`, `parent_exec_id`, `tid`. `process_connect` adds `source_ip`, `source_port`, `destination_ip`, `destination_port`, `sock_cookie`, `protocol` and `destination_pod` (`namespace`, `name`, `pod_labels`, `workload`, `workload_kind`). `process_kprobe` adds `function_name` (`security_bprm_check`), `action` (`KPROBE_ACTION_SIGKILL`) and `policy_name`.

**`ci:job:event`** — `object_kind` (`build`), `ref`, `tag`, `sha`, `build_id`, `build_name`, `build_stage`, `build_status` (`running`, `success`, `failed`), `build_created_at`, `build_started_at`, `build_finished_at`, `build_duration`, `build_failure_reason` (`script_failure`), `pipeline_id`, `project_id`, `project_name`, `project.path_with_namespace`, `project.web_url`, `user.username`, `user.name`, `commit.sha`, `commit.message`, `commit.author_name`, `runner.id`, `runner.description` (the pod), `runner.runner_type`, `runner.tags[]`, `merge_request.iid`, `merge_request.title`, `merge_request.source_branch`, `merge_request.target_branch`, `merge_request.url`, `job_script`.

**`cisco:nexus:endpoint`** — `timestamp`, `source` (`nexus-dashboard`), `fabric`, `switch`, `interface`, `hostname`, `endpoint_ip`, `endpoint_mac`, `vlan`, `vrf`, `learned`, `state`.

**`cisco:nexus:liveprotect`** — `timestamp`, `source`, `fabric`, `switch`, `feature` (`live_protect`), `advisory_id` (`NX-LP-00nn`), `component`, `shield`, `status`.

**`cisco:nexus:config`** — `timestamp`, `device`, `user`, `change`, `diff_summary`, `source` (`nexus`), plus `change_type` and `ticket` on every change (`ticket` is the finding id for enforcement changes, a change number otherwise).

**`kube:apiserver:audit`** — `kind` (`Event`), `apiVersion` (`audit.k8s.io/v1`), `level`, `auditID`, `stage` (`ResponseComplete`), `requestURI`, `verb` (`create`, `patch`, `delete`), `user.username`, `user.groups[]`, `sourceIPs[]`, `userAgent`, `objectRef` (`resource`, `namespace`, `name`, `apiGroup`, `apiVersion`), `responseStatus.code`, `requestReceivedTimestamp`, `stageTimestamp`, `annotations` (`authorization.k8s.io/decision`, `authorization.k8s.io/reason`). The quarantine produces a `patch` on `pods/ci-runner-7d9f8-xk2lq` (200) and a `create` of `ciliumnetworkpolicies/zt-quarantine-ci-runner-88213` (201) by `system:serviceaccount:soar:zt-enforcer`; the reset produces a `delete` and a `patch` by `k.osei`.

**`zt:enforcement:audit`** — `time`, `request_id` (`ZTR-<yyyymmdd>-<nnnn>`), `finding_id`, `investigation_id`, `state` (`requested`, `approved`, `rejected`, `refused`, `applied`, `verified`, `failed`, `released`), `enforcement_point` (`kernel`, `dpu`, `switch`), `action`, `target` (`namespace/pod`), `workload` (`namespace/workload`), `policy_name`, `approved_by`, `approver_role`, `approved_at`, `executed_by` (`soar` or `splunk`), `playbook`, `run_id`, `k8s_audit_ids[]`, `comment`, `status`.

## Normalized fields per sourcetype

All are `EVAL-` calculated fields or automatic lookups in `props.conf`. Lookups run after the evals, so they can use them.

### `cilium:hubble:flow`

| Field | Source expression | Meaning |
|---|---|---|
| `verdict` | `flow.verdict` | `FORWARDED`, `AUDIT` or `DROPPED` |
| `traffic_direction` | `flow.traffic_direction` | `INGRESS` (observed at the destination's node) or `EGRESS` (at the source's node) |
| `direction` | `lower(flow.traffic_direction)` | CIM direction |
| `src_ip`, `dest_ip` | `flow.IP.source`, `flow.IP.destination` | Pod IPs |
| `src_port`, `dest_port` | `coalesce(flow.l4.TCP.*, flow.l4.UDP.*)` | Ports |
| `transport` | `udp` if a UDP block exists, else `tcp` | CIM transport |
| `src_identity`, `dest_identity` | `flow.source.identity`, `flow.destination.identity` | Cilium security identities (48213, 30719; 48291 after the quarantine label) |
| `src_namespace`, `src_pod`, `dest_namespace`, `dest_pod` | `flow.source.namespace`, `flow.source.pod_name`, … | Kubernetes namespace and pod on each side |
| `src_workload`, `dest_workload` | `namespace + "/" + first workloads{}.name`, null without a workload | The entity used everywhere: `build-farm/ci-runner`, `ai-train/checkpoint-store` |
| `src_labels`, `dest_labels` | `flow.source.labels{}`, `flow.destination.labels{}` | Multivalue `k8s:` labels |
| `node` | `node_name` without the `cluster/` prefix | The observing node (`bf-node-03`, `ai-train-stor-02`) |
| `cluster` | `flow.source.cluster_name` | `ai-platform-dc2` |
| `policy_allowed` | `mvdedup(egress_allowed_by{}.name + ingress_allowed_by{}.name)` | Names of the allowing policies (`build-farm-egress-internal`) |
| `policy_denied` | `mvdedup(egress_denied_by{}.name + ingress_denied_by{}.name)` | Names of the denying policies (`zt-quarantine-ci-runner-88213`) |
| `drop_reason` | `flow.drop_reason_desc` | `POLICY_DENY` on drops |
| `would_deny` | `1` if verdict is `AUDIT`, else `0` | The allowlist would have denied it |
| `action` | `blocked` if `DROPPED`, else `allowed` | CIM action |
| `src`, `dest` | the IPs | CIM |
| `dvc` | the node | CIM |
| `app` | destination workload name, or `unknown` | CIM |
| `flow_uuid` | `flow.uuid` | Exporter UUID of the flow |
| `dest_protected`, `dest_data_class`, `allowlist_policy`, `allowlist_mode`, `dest_owner` | lookup `zt_protected_stores` on `dest_workload` | `true`, `crown-jewel`, `checkpoint-store-ingress-allowlist`, `audit`, `ml-platform` for the store |
| `src_owner`, `src_team`, `src_kind` | lookup `zt_workload_inventory` on `src_workload` | Owner, team and kind of the source workload |

### `cisco:isovalent:processExec`

| Field | Source expression | Meaning |
|---|---|---|
| `process`, `process_path` | `process_exec.process.binary` | Full path of the program (`/usr/bin/curl`) |
| `process_name`, `process_exec` | basename of the binary | `curl` |
| `process_args` | `process_exec.process.arguments` | Arguments (the checkpoint URL) |
| `process_id` | `process_exec.process.pid` | PID |
| `parent_process` | parent `binary + " " + arguments` | `/bin/sh -c ./scripts/postbuild.sh` |
| `parent_process_name`, `parent_process_id` | parent basename, parent pid | |
| `container_image`, `container_id` | `…pod.container.image.name`, `…pod.container.id` | `registry.corp.internal/ci/build-base:2026.09` |
| `src_namespace`, `src_pod`, `src_workload` | `…process.pod.namespace`, `…pod.name`, `namespace/workload` | |
| `node`, `cluster` | `node_name`, `cluster_name` | |
| `dest` | `node_name` | CIM Endpoint host |
| `user` | `"uid:" + uid` | CIM user |
| `exec_id`, `cwd` | `…process.exec_id`, `…process.cwd` | Tetragon execution ID; working directory (`/builds/ml-infra/train-utils`) |
| `src_owner`, `src_team`, `src_kind` | lookup `zt_workload_inventory` on `src_workload` | |

### `cisco:isovalent:processConnect`

All the `processExec` fields, read from `process_connect.*`, plus:

| Field | Source expression | Meaning |
|---|---|---|
| `src_ip`, `src_port`, `dest_ip`, `dest_port` | `process_connect.source_ip`, `source_port`, `destination_ip`, `destination_port` | The socket |
| `transport` | `lower(process_connect.protocol)` | `tcp` |
| `dest_namespace`, `dest_pod`, `dest_workload` | `process_connect.destination_pod.*` | `ai-train`, `checkpoint-store-1`, `ai-train/checkpoint-store` |
| `src`, `dest`, `dvc` | the IPs; `node_name` | CIM Network Traffic |
| `action` | `allowed` | CIM |
| `dest_protected`, `dest_data_class`, `allowlist_policy`, `allowlist_mode`, `dest_owner` | lookup `zt_protected_stores` on `dest_workload` | |
| `process_approved` | lookup `zt_process_allowlist` on `src_workload`, `dest_workload`, `process` | `true` when the program is approved for that store; empty otherwise |

### `cisco:isovalent` (kprobe)

| Field | Source expression | Meaning |
|---|---|---|
| `process`, `process_name`, `process_args`, `parent_process` | `process_kprobe.process.*`, parent | The killed program |
| `src_namespace`, `src_pod`, `src_workload`, `node`, `cluster` | as above | |
| `kprobe_action` | `process_kprobe.action` | `KPROBE_ACTION_SIGKILL` |
| `policy_name` | `process_kprobe.policy_name` | The Tetragon tracing policy |
| `dest` | `node_name` | CIM |
| `action` | `blocked` on SIGKILL, else `allowed` | CIM |

### `ci:job:event`

| Field | Source expression | Meaning |
|---|---|---|
| `job_id` | `build_id` | 88213 |
| `job_name`, `job_stage`, `job_status` | `build_name`, `build_stage`, `build_status` | `package`, `post-build`, `running` / `failed` |
| `pod` | `runner.description` | `ci-runner-7d9f8-xk2lq` |
| `project` | `project.path_with_namespace` | `ml-infra/train-utils` |
| `mr`, `mr_title`, `mr_url` | `merge_request.iid`, `.title`, `.url` | 4417, "postbuild: cache model shards for integration tests" |
| `author` | `user.username` | `contractor-dev-17` |
| `commit`, `commit_short` | `commit.sha`, first 7 characters | `9f1c2ab` |
| `failure_reason`, `duration`, `script` | `build_failure_reason`, `build_duration`, `job_script` | `script_failure`, seconds, `scripts/postbuild.sh` |

### `cisco:nexus:endpoint`, `cisco:nexus:liveprotect`, `cisco:nexus:config`

| Sourcetype | Field | Source expression | Meaning |
|---|---|---|---|
| endpoint | `node`, `node_ip` | `hostname`, `endpoint_ip` | The server on the port |
| endpoint, liveprotect | `dvc` | `switch` | CIM device |
| config | `dvc`, `object` | `device` | The switch |
| config | `action`, `object_category`, `status` | constants `modified`, `network device`, `success` | CIM Change |
| config | `command` | `change` | The configuration line |

### `kube:apiserver:audit`

| Field | Source expression | Meaning |
|---|---|---|
| `k8s_verb`, `k8s_user`, `k8s_resource`, `k8s_name`, `k8s_namespace` | `verb`, `user.username`, `objectRef.*` | The call |
| `status_code`, `audit_id` | `responseStatus.code`, `auditID` | 200 for the patch, 201 for the create |
| `user` | `user.username` | CIM |
| `action` | `created` / `deleted` / `modified` from `verb` | CIM Change |
| `object`, `object_category` | `namespace/name`, `objectRef.resource` | `build-farm/zt-quarantine-ci-runner-88213`, `ciliumnetworkpolicies` |
| `status` | `success` below 300, else `failure` | CIM |
| `command` | `verb + " " + requestURI` | |
| `src` | first of `sourceIPs{}` | `10.40.2.18` for the enforcer |

### `zt:enforcement:audit`

| Field | Source expression | Meaning |
|---|---|---|
| `approved_by_label` | `approved_by (approver_role)` | `j.chen (SOC tier 2)`, as shown on the posture dashboard |
| `finding` | `finding_id` | |
| `at` | `enforcement_point` | `kernel`, `dpu`, `switch` |
| `user` | `approved_by` | CIM |
| `object`, `object_category` | `target`, `workload` | CIM Change |
| `command` | `action` | |

## CIM mapping

| Data model | Eventtype and tags | Sourcetypes | Fields provided |
|---|---|---|---|
| Network Traffic | `zt_flow` (`network`, `communicate`) | `cilium:hubble:flow` | `src`, `dest`, `src_ip`, `dest_ip`, `src_port`, `dest_port`, `transport`, `action`, `direction`, `dvc`, `app` |
| Endpoint (Processes) | `zt_process` (`process`, `report`) | `cisco:isovalent:processExec`, `cisco:isovalent:processConnect`, `cisco:isovalent` | `process`, `process_name`, `process_path`, `process_exec`, `process_id`, `process_args`, `parent_process`, `parent_process_name`, `parent_process_id`, `user`, `dest`, `action` |
| Change | `zt_enforcement` (`change`) | `zt:enforcement:audit`, `kube:apiserver:audit`, `cisco:nexus:config` with `change_type=config` | `action`, `object`, `object_category`, `status`, `command`, `user`, `dvc`, `src` |

`cisco:isovalent:processConnect` also carries the Network Traffic fields (`src`, `dest`, ports, `transport`, `action=allowed`) although it is tagged as a process event. `zt_ci` (tag `ci`) and `zt_fabric` (tags `network`, `inventory`) group the CI and Nexus data for searches; they do not feed a CIM data model.

## Eventtypes and tags

| Eventtype | Search | Tags |
|---|---|---|
| `zt_flow` | `index=zero_trust sourcetype=cilium:hubble:flow` | `network`, `communicate` |
| `zt_process` | `index=zero_trust sourcetype=cisco:isovalent:processExec OR sourcetype=cisco:isovalent:processConnect OR sourcetype=cisco:isovalent` | `process`, `report` |
| `zt_ci` | `index=zero_trust sourcetype=ci:job:event` | `ci` |
| `zt_fabric` | `index=zero_trust sourcetype=cisco:nexus:endpoint OR sourcetype=cisco:nexus:liveprotect OR sourcetype=cisco:nexus:config` | `network`, `inventory` |
| `zt_enforcement` | `index=zero_trust sourcetype=zt:enforcement:audit OR sourcetype=kube:apiserver:audit OR (sourcetype=cisco:nexus:config change_type=config)` | `change` |

## Lookups

CSV lookups in `zt_incident_demo/lookups/`, generated from the estate model by `make lookups` (`tools/gen_lookups.py`), except `zt_node_fabric`, which `ZT Lookup - Node Fabric` rebuilds hourly from `cisco:nexus:endpoint`.

| Lookup | Columns | Meaning |
|---|---|---|
| `zt_workload_inventory` (1,283 rows) | `workload`, `namespace`, `kind`, `owner`, `team`, `tier`, `data_class`, `description` | Every workload of the cluster; automatic lookup on `src_workload` |
| `zt_protected_stores` (4 rows) | `dest_workload`, `port`, `protected`, `data_class`, `owner`, `allowlist_policy`, `mode`, `description` | The protected AI data stores: `ai-train/checkpoint-store` 9000 (crown-jewel), `ai-train/dataset-cache` 8443, `ai-infer/model-registry` 443, `ai-infer/vector-index` 6333; all allowlists in `audit` mode |
| `zt_store_allowlist` (57 rows) | `dest_workload`, `src_workload`, `port`, `policy` | The members of each store's ingress allowlist (the 57 enforced paths) |
| `zt_process_allowlist` (65 rows) | `src_workload`, `dest_workload`, `process`, `approved` | Programs approved per path; used by the program detection and `process_approved` |
| `zt_known_gaps` (8 rows) | `src_workload`, `dest_workload`, `dest_port`, `ticket`, `owner`, `status` | The eight audit-mode paths with an open ticket (`ZT-231` … `ZT-258`); excluded from the flow detection and counted as the 8 unprotected paths |
| `zt_protected_data` (8 rows, `WILDCARD(path_prefix)`) | `dest_workload`, `path_prefix`, `dataset`, `training_job_id`, `job_name`, `scheduler`, `gpus`, `owner` | What lies behind a request path: `/ckpt/llm-7712/` = checkpoints of training job 7712 (Slurm, 512 GPUs, owner `ml-research`) |
| `zt_node_fabric` (92 rows) | `node`, `node_ip`, `fabric`, `switch`, `interface`, `vrf`, `last_seen` | Node to switch port: `bf-node-03` → `dc2-leaf-205 Eth1/12`, `ai-train-stor-02` → `dc2-leaf-207 Eth1/05` |
| `zt_approvers` (3 rows) | `enforcement_point`, `approver_roles`, `approver_labels`, `approvals_required` | The approval matrix: kernel needs one `zt_soc_tier2` (SOC tier 2); dpu and switch need `zt_soc_tier2,zt_netops` (SOC tier 2, NetOps), two approvals |
| `zt_role_labels` (4 rows) | `user`, `role_label` | Display labels: `j.chen` and `m.ruiz` SOC tier 2, `a.patel` NetOps, `k.osei` platform |
| `zt_es_assets` (7 rows, in `DA-ESS-zt_incident_demo`) | ES asset header `ip, mac, nt_host, dns, owner, priority, lat, long, city, country, bunit, category, pci_domain, is_expected, should_timesync, should_update, requires_av` | Asset source `zt_workload_assets`: the four stores (`ai-train/checkpoint-store` critical, category `k8s_workload\|ai_data_store\|crown_jewel`), `build-farm/ci-runner` (medium, `k8s_workload\|ci_runner`) and the servers `bf-node-03` (10.40.12.33) and `ai-train-stor-02` (10.40.17.52) |

## KV store collections

Defined in `collections.conf`; each has a `_lookup` definition in `transforms.conf` for `inputlookup`.

| Collection (lookup) | Fields | Used by |
|---|---|---|
| `zt_demo_state` (`zt_demo_state_lookup`), one record `_key=global` | `stream_checkpoint`, `backfill_done`, `last_reset_epoch`, `speed`, `response_mode`, `agent_mode`, `plan_t0`, `plan_attempt`, `plan_status`, `plan_dropped_attempts`, `plan_fail_at`, `plan_completed_epoch`, `last_fire_epoch`, `last_tick_epoch`, `last_tick_events`, `last_error` (plus the backfill lock fields) | The stream, `ztdemo`, the macros (`last_reset_epoch`) |
| `zt_policy_state` (`zt_policy_state_lookup`) | `kind`, `namespace`, `name`, `spec_json`, `selector_json`, `labels_json`, `label_epochs_json`, `created_by`, `created_epoch`, `resource_version`, `uid` | The emulator (pods' labels with the epoch of each label change, CiliumNetworkPolicies); the plan reads it to decide AUDIT or DROPPED |
| `zt_agent_briefs` (`zt_agent_briefs_lookup`) | `finding_id`, `finding_display_id`, `investigation_id`, `investigation_guid`, `workload`, `pod`, `node`, `job_id`, `what_happened`, `dest_workload`, `data_class`, `disposition`, `confidence`, `enforcement_point`, `action`, `policy_name`, `blast_radius`, `approver_labels`, `brief_json`, `brief_text`, `session_id`, `run_epoch`, `note_added` | `ztbrief` writes; the playbook and `ZT Response - Request Enforcement` read |
| `zt_enforcement_requests` (`zt_enforcement_requests_lookup`) | `request_id`, `finding_id`, `investigation_id`, `investigation_guid`, `workload`, `pod`, `job_id`, `enforcement_point`, `action`, `policy_name`, `policy_yaml`, `label_patch_json`, `cnp_json`, `approvals_required`, `approver_roles`, `approver_labels`, `approvals`, `status` (`pending`, `approved`, `applied`, `verified`, `failed`, `rejected`, `cancelled`), `dest_workload`, `data_class`, `disposition`, `confidence`, `what_happened`, `blast_radius`, `requested_epoch`, `approved_epoch`, `applied_epoch`, `verified_epoch`, `k8s_audit_ids`, `comment`, `last_error` | Mode B: `ztsoar`, the approvals endpoint, the Enforcement Approvals dashboard |

## Macros

| Macro | Meaning |
|---|---|
| `zt_index` | `index=zero_trust` |
| `zt_since_reset` | Detection window: the last 60 minutes, or since the last reset if that is later (a subsearch returning `earliest`) |
| `zt_risk_window` | The same window as `earliest` and `latest` for the finding-based detection's `tstats` |
| `zt_last_reset` | The epoch of the last reset (0 if never), for use inside `eval` |
| `zt_not_already_risked(rule, object_field, threat_field)` | Excludes object/threat pairs that the named rule has already risked since the last reset, so each detection adds risk once per path or program |
| `zt_incident_since_reset` | The incident's own events since the last reset (the pod, job 88213, the enforcement and Kubernetes audit records) |

## Live generator records

`zt_demo_state` holds, next to the `global` record, one record per path attack started from the live generator (`_key = attack:<workload>-<epoch>`, `rec_kind = attack`): `src_workload`, `src_pod`, `dest_workload`, `dest_pod`, `port`, `program`, `t0`, `attempt`, `max_attempts`, `status` (running, completed, stopped), `dropped_attempts`, `identity_quarantined`, `job_id` (the quarantine label value), `started_by`. The global record carries the streaming lease: `stream_owner` (`splunk` or `live:<host>:<pid>`) and `stream_owner_epoch`.

Risk detections add `zt_run` (the reset epoch) to every result and throttle on it, so a reset starts a new run for the two risk rules as well as for the finding rule.
