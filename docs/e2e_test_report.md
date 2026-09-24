# End-to-end test of the demo flow

Every step of `docs/demo_script.md` executed against the Splunk Cloud stack and SOAR Cloud, as a presenter would: the live generator page in a browser for fire, reset, mode and triggers; the searches and pages of the Zero Trust Incident app; Enterprise Security, Agent Launchpad and SOAR through the same searches and REST calls their pages use. Each run starts from a reset. A defect is fixed, then the test restarts from the beginning.

The one step not performed by hand is signing in to Splunk Web or SOAR as `j.chen`: I do not type passwords into sign-in forms. j.chen's approval was sent to the same endpoint the Approve button calls (`POST /services/zt_incident_demo/approvals`, Mode B) and to the prompt API the SOAR Approve button uses (`POST /rest/approval/<id>`, Mode A), with j.chen's credentials.

## Run 1

2026-09-24 15:40:51 to 16:22:06 UTC. 70 steps: 51 passed, 16 failed, 1 blocked, 2 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 15:40:51 | Live generator: launchd agent com.zt-incident-demo.live, http://127.0.0.1:8890 | **PASS** | pid 5999, holds the streaming lease; search head input logs 'streaming is owned by live:...' and skips; 0 duplicate flow uuids in 5 min |
| 1.1 | 15:40:54 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "5", "plan_status": "completed", "quarantine_policies": "zt-quarantine-ci-runner-88213", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.1b | 15:40:54 | Read plan and quarantine state | **INFO** | previous Mode A run left plan completed and policy zt-quarantine-ci-runner-88213 in place: reset needed before the fire |
| 1.2 | 15:41:12 | make emulator-status | **PASS** | local /version HTTP 200; public https://zt-k8s.yeackbot.com HTTP 200 v1.31.2 |
| 1.3 | 15:42:30 | Live generator page: Reset (two clicks) | **PASS** | plan idle, reset stamped · released zt-quarantine-ci-runner-88213 · cancelled 1 (the stale request ZTR-20260924-0019); about 12 s through the emulator tunnel |
| 1.4 | 15:43:25 | Posture before-state (rollup) and status after the reset | **PASS** | posture 15:43:00: identities 1284, coverage 87.9% (58 of 66), unprotected 8, audit flows 2386, enforcement 19 (kernel 13, DPU 2, switch 4); plan idle, quarantine none |
| 1.5 | 15:43:55 | Splunk Web pre-steps: open Posture, sign in as j.chen in a private window, open Agent Launchpad and the Analyst Queue | **BLOCKED** | The Chrome tab driven by Claude opens on the Splunk login page; I do not type passwords into sign-in forms. The same data is checked through the searches and REST calls the pages use; the UI pass follows once the tab is signed in |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 15:45:06 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T15:44:05.056Z · attempts every 30s'; state plan running, attempt 0; red incident dots on the timeline |
| 2.1b | 15:45:06 | Live generator timeline colours | **FAIL** | background CI jobs on pod ci-runner-7d9f8-xk2lq (other build IDs) are drawn as incident events before the fire (cosmetic; classifier matches the pod name) |
| 2.2 | 15:45:06 | Search 1: index=zero_trust sourcetype=cilium:hubble:flow verdict=AUDIT src_workload="build-farm/ci-runner" | **PASS** | first try: dest_pod checkpoint-store-1, dest_port 9000, identities 48213 -> 30719, allowlist_policy checkpoint-store-ingress-allowlist, allowlist_mode audit, src_owner platform-build (15:44:05.085) |
| 2.3 | 15:45:06 | Search 2: index=zero_trust sourcetype=cisco:isovalent:processConnect process_name=curl | **PASS** | first try: process /usr/bin/curl, process_args .../ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors, parent /bin/sh -c ./scripts/postbuild.sh, src_pod ci-runner-7d9f8-xk2lq, node bf-node-03 (15:44:05.056) |
| 2.4 | 15:45:23 | Compare _time of the first Tetragon connect and the first Hubble AUDIT flow | **PASS** | connect 1790264645.056, AUDIT 1790264645.085: 29 ms apart; indexed 4.944 s and 4.915 s after the event time |
| 2.5 | 15:47:01 | Context (corrected fields): ci:job:event build_id=88213; zt_node_fabric bf-node-03 | **PASS** | job 88213 build_name package, build_stage post-build, mr 4417, author contractor-dev-17, build_status running, project ml-infra/train-utils; fabric dc2-leaf-205 Eth1/12 (vrf k8s-build). First check used wrong field names (test error) |
| 2.5b | 15:47:01 | Field sidebar on CI events | **INFO** | tag=error comes from Splunk_SA_CIM eventtype err0r matching the token 'failure' in build_failure_reason; not this app's object, left as is |
| 2.5c | 15:47:01 | Context search: index=zero_trust sourcetype=ci:job:event pod="ci-runner-7d9f8-xk2lq" | **FAIL** | the story's runner pod also carries 241 background CI jobs per day (several concurrent); the pod search lists them next to 88213, and after the quarantine the generator keeps background flows and jobs on a pod that egressDeny all should isolate |
| 2.6 | 15:47:47 | Rerun search 1 thirty seconds apart | **PASS** | AUDIT flows since fire: 7, then 8 (one attempt every 30 s) |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 15:47:49 | Risk events for build-farm/ci-runner since the fire | **PASS** | 15:45:11 ZT - Unapproved Program Connected to Protected AI Data Store +40.0; 15:45:10 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 (total 90) |
| 3.1 | 15:50:03 | Analyst Queue data: the ZT finding group since the fire | **PASS** | 15:46:07 (T0+2m02s): orig title 'Unprotected path: build-farm/ci-runner reached a protected AI data store', risk 90 from 2 detections, severity high, urgency medium, domain network, threat objects /usr/bin/curl,ai-train/checkpoint-store, MITRE T1059.004,T1530, status New |
| 3.1b | 15:50:03 | Finding title and drilldowns as ES renders them | **FAIL** | ES keeps rule_title as the template 'Unprotected path: $risk_object$ ...' and fills tokens after add_normalized_risk_object, so the queue and drilldowns can show ci-runner.build-farm.svc (the asset name) instead of build-farm/ci-runner; last run's SOAR container was named with the asset name |
| 3.2 | 15:50:17 | Run the three drilldowns (token filled with the risk object) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 24 events; Tetragon events for build-farm/ci-runner: 29 events; CI jobs on build-farm/ci-runner pods: 59 events |
| 3.3 | 15:50:35 | Agent run history (ZTFlowInvestigator, run_finished in _audit) | **PASS** | 5 tool calls: zt_finding_context(success) > zt_flow_evidence(success) > zt_process_evidence(success) > zt_ci_job_context(success) > zt_workload_server_context(success); run 60.24347639083862 s |
| 3.4 | 15:50:35 | Read the brief (six parts) | **FAIL** | disposition true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommendation Create a Cilium quarantine policy to blo ci-runner-checkpoint-store-quarantine at the kernel, approvers ['SOC tier 2']; missing facts: ['zt-quarantine-ci-runner-88213'] |
| 3.4b | 15:51:58 | Brief recommendation vs. what gets applied | **FAIL** | brief recommends policy 'ci-runner-checkpoint-store-quarantine' blocking port 9000; the request applies zt-quarantine-ci-runner-88213 (deny all egress and ingress). Cause: ZT Agent - Workload and Server Context ends with head 20 and lists one row per checkpoint file, pushing the approval-matrix and naming rows out |
| 3.5 | 15:52:42 | ES investigation ES-00004 notes (re-read content; the list API keeps titles inside content) | **PASS** | 2 notes: 'ZTFlowInvestigator brief ...' ai_generated=true; 'Quarantine requested (ZTR-20260924-0020); waiting for SOC tier 2 approval' with the policy YAML |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 15:52:43 | Enforcement Approvals data: pending request ZTR-20260924-0020 | **PASS** | status pending, finding 9cd16705..., investigation ES-00004, build-farm/ci-runner pod ci-runner-7d9f8-xk2lq, kernel, approvers SOC tier 2 (1 approval), requested 15:49:01 (brief + 102 s) |
| 4.1b | 15:52:43 | Request action text | **FAIL** | action = the agent's sentence ('block ... on port 9000') instead of the applied policy; audit trail and approvals page would describe a narrower policy than zt-quarantine-ci-runner-88213 |
| 4.2 | 15:52:43 | Read the policy YAML of the request | **PASS** | name zt-quarantine-ci-runner-88213, namespace build-farm, endpointSelector zt-quarantine: "88213", egressDeny toEntities all, ingressDeny fromEntities all |
| 4.3 | 15:52:54 | Approve as a.patel (NetOps) through the approvals endpoint | **PASS** | HTTP 403: {"message": "a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)", "request_id": "ZTR-20260924-0020", "status": "; refusal audited: {'_time': '2026-09-24 15:52:44.027 UTC', 'approved_by_label': 'a.patel (NetOps)', 'comment': 'a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)', 'status': 'refused'} |
| 4.4 | 15:53:13 | Approve as j.chen (SOC tier 2) with a comment, through POST /services/zt_incident_demo/approvals (what the Approve button runs) | **PASS** | HTTP 200 in 5.9 s: {"message": "request ZTR-20260924-0020 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0020", "status": "applied", "approver": "j.chen", "approver_role": "SOC tier 2" |
| 4.5 | 15:53:25 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 15:53:08.305 patch pods/ci-runner-7d9f8-xk2lq 200; 15:53:10.473 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 15:54:55 | First retry after the approval | **PASS** | 15:53:35.063 ci-runner-7d9f8-xk2lq -> checkpoint-store-1 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 28 s) |
| 5.1 | 15:54:56 | Request status after the first DROPPED | **PASS** | status verified, verified 33 s after apply, last_error '' |
| 5.2 | 15:55:10 | ES investigation ES-00004 after verification | **PASS** | status 4 (4 = Resolved), disposition True Positive - Suspicious Activity; 4 notes in order: ZTFlowInvestigator brief \| Quarantine requested \| Quarantine applied \| Quarantine verified |
| 5.3 | 15:56:45 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED retries (last 15:56:05); job failed at 15:56:20 with script_failure after 762 s; plan completed |
| 5.4 | 15:59:16 | Zero Trust Fabric Posture KPIs after the quarantine | **PASS** | identities 1284, coverage 87.9 (58 of 66 paths enforced; up from 86.4% · target 95%), unprotected 8 (down from 9), audit flows 2405, enforcement 20 (kernel 14 · DPU 2 · switch 4); before-state was 87.9%/8/19 |
| 5.5 | 15:59:18 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 (last 30 min) | **PASS** | series ['AUDIT (would deny)', 'DROPPED (quarantine policy)']: AUDIT 19 then DROPPED 6 |
| 5.6 | 15:59:20 | Enforcement Audit Trail, first row | **PASS** | {"_time": "2026-09-24 15:53:44.436 UTC", "finding": "9cd167050a60ecdc18f4f23160662892@@notable@@a6cd42e6dc582a1bb", "action": "Create a Cilium quarantine policy to block ci-runner-7d9f8-x", "at": "kernel", "approved_by": "j.chen (SOC tier 2)", "status": "verified", "request_id": "ZTR-20260924-0020"} |
| 5.6b | 15:59:35 | Audit trail row wording | **FAIL** | finding column shows the ES event_id (9cd16705...@@notable@@...) instead of ES-00004, and the action column carries the agent's sentence instead of 'CNP zt-quarantine-ci-runner-88213' |
| 5.7 | 15:59:35 | Incident Timeline wording and scope | **FAIL** | Decide card quotes the agent's port-9000 sentence; Verify card and grid cell 11 compare before-fire with after (87.9% -> 87.9% after a practice run) instead of during -> after (86.4% -> 87.9%); incident table lists 11 CI events of other builds on the pod; enforcement and Kubernetes rows are not scoped to the runner workload |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 16:00:20 | Live generator page: Reset (two clicks); then \| ztdemo action=status | **PASS** | page: 'plan idle, reset stamped · released zt-quarantine-ci-runner-88213 · cancelled 0'; audit: released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); status plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.0 | 16:01:11 | Switching to Mode A | **FAIL** | make mode-soar and the live generator's SOAR button change response_mode only; the ES automation rule that starts the playbook stays as it was, so a presenter can end up with no playbook (rule off) or both paths (rule on in Mode B) |
| A.1 | 16:01:11 | Live generator page › Settings › Response mode: SOAR | **PASS** | page: now {"response_mode":"soar","agent_mode":"mcp"} |
| A.2 | 16:01:14 | make es-automation-rule RULE=on; read the state | **PASS** | rule 'Zero Trust Protected Paths' on; state response_mode soar, plan idle |
| A.3 | 16:01:48 | Live generator page: Fire the incident (Mode A) | **PASS** | page: 'incident started at 2026-09-24T16:01:26.697Z · attempts every 30s' |
| A.4 | 16:04:36 | ES finding group and automation rule (Mode A) | **PASS** | risk 50+40 at 16:02:07-08; finding 16:03:10 risk 90; playbook zt_quarantine_workload run 497 started 16:03:28 (finding + 18 s); no local request created (Mode B stays quiet) |
| A.4b | 16:04:36 | Playbook start on a re-fired finding | **FAIL** | ES reuses the finding group event_id on every fire, so SOAR reuses container 556 (named with this morning's asset-name title) and read_brief matched an earlier brief with the same finding id: the prompt went out before this run's agent brief existed |
| A.5 | 16:04:48 | SOAR prompt ask_approval (role SOC tier 2): read the message | **PASS** | to SOC tier 2 (copies for J. Chen and M. Ruiz), due in 30 min; message has the finding, workload and store, disposition, action, blast radius and the policy YAML (endpointSelector zt-quarantine "88213", egressDeny/ingressDeny all) |
| A.6 | 16:04:49 | Answer the prompt as j.chen: Approve with a comment (POST /rest/approval/3, what the SOAR Approve button sends) | **PASS** | status approved, responses ['Approve', 'Contractor merge request; not approved for checkpoint access'] |
| A.5b | 16:05:05 | SOAR prompt wording | **FAIL** | message quotes the 05:11:31Z brief (stale), names the finding by the ES event_id instead of the investigation (ES-0000x), repeats the agent's port-9000 sentence as the action and has doubled full stops ('... port 9000. at the kernel', '...workloads..') |
| A.7 | 16:06:08 | Playbook applies the quarantine after the approval | **PASS** | SOAR actions after the prompt: record_and_resolve_approved=success, apply=success, apply_policy=success, record_and_resolve_applied=success, record_and_resolve_note_applied=success, verify=success, verify_wait=success, verify=success; kube audit: 16:04:55 patch pods/ci-runner-7d9f8-xk2lq 200; 16:04:59 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| A.8 | 16:06:44 | Enforcement audit trail and runner retries (Mode A) | **PASS** | ZTR-20260924-0021 requested 16:03:41, approved 16:04:49 by j.chen (SOC tier 2), applied 16:05:01, verified 16:05:39, executed_by soar, playbook zt_quarantine_workload run 497; DROPPED from 16:05:26 with identity 48291 |
| A.9 | 16:06:44 | ES investigation of this run after the playbook | **FAIL** | ES-00005 status 1, disposition Undetermined; the playbook noted and resolved ES-00001 (this morning's investigation, taken from the stale brief) instead |
| A.10 | 16:08:47 | CI job 88213 outcome (Mode A), re-checked after the 15 s delay | **PASS** | 6 DROPPED; job failed at 16:08:11 with script_failure (the first check ran 2 s before the scheduled failure) |
| A.11 | 16:09:53 | Live generator page: Reset, then Settings › Response mode: Local; make es-automation-rule RULE=off | **PASS** | state plan idle, response_mode local; rule off; the page's confirmation lines rendered a few seconds after the clicks |
| A.12 | 16:09:53 | Live generator service log | **FAIL** | the request logger crashes on send_error(404) (e.g. the browser's /favicon.ico) because it treats the first log argument as text; the browser gets a dropped connection instead of a 404 |

### Live generator triggers

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| T.1 | 16:12:20 | Triggers › Audit-mode flow: data-eng/spark-driver -> ai-train/checkpoint-store | **PASS** | page: 'audit-mode connection sent (2 events)'; risk: 16:11:05 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 |
| T.2 | 16:12:20 | Triggers › Unapproved program: observability/log-shipper, /usr/bin/curl -> ai-train/checkpoint-store | **PASS** | page: 'unapproved program connect sent (2 events)'; risk: 16:11:05 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 |
| T.4 | 16:12:25 | Triggers › Nexus Live Protect: dc2-leaf-201 | **PASS** | indexed: [{'_time': '2026-09-24 16:11:06.587 UTC', 'switch': 'dc2-leaf-201', 'advisory_id': 'cisco-sa-nxos-bgp-dos-3fzrsx', 'status': 'protected'}] |
| T.5 | 16:12:25 | Triggers › Nexus configuration change | **PASS** | indexed: [{'_time': '2026-09-24 16:11:07.108 UTC', 'device': 'dc2-leaf-201', 'user': 'netops-cli', 'change': 'interface Eth1/12 description zt-live'}] |
| T.6 | 16:12:26 | Triggers › Enforcement action: kernel, platform/jump-host, j.chen | **PASS** | request ZTR-20260924-0021, states: verified 16:11:06 (platform/jump-host), applied 16:10:21 (platform/jump-host), approved 16:10:19 (platform/jump-host), requested 16:08:46 (platform/jump-host) |
| T.6b | 16:12:37 | Request IDs across paths | **FAIL** | the enforcement trigger reused ZTR-20260924-0021, already used by the SOAR playbook's request at 16:03: the local counter only counts requests in the KV store, the playbook's IDs live only in the audit trail |
| T.3a | 16:13:16 | Triggers › Path attack: ml-notebooks/jupyter -> ai-train/checkpoint-store, program of the workload, 40 attempts | **PASS** | page: 'attack started (4 events) · attempts every 30s' |
| T.3b | 16:18:58 | Path attack detected | **PASS** | risk 50 + 40 on ml-notebooks/jupyter at 16:13:08 (attack start + 17 s); finding 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' risk 90 at 16:14:06 |
| T.3c | 16:18:58 | Agent brief for the attack | **PASS** | agent 16:14:13-16:15:35; brief ES-00006 true_positive, kernel, pod jupyter-75e4a-11141 (job_id empty: no CI job behind a notebook) |
| T.3d | 16:18:58 | Quarantine request for the attack | **FAIL** | ZTR-20260924-0021 created 16:16:52 (my manual \| ztsoar action=request, 10 s before the scheduled run): third use of 0021 (stack still on 1.0.3 numbering), and with no job id the request fell back to 88213: policy zt-quarantine-jupyter-88213 and label zt-quarantine=88213 on the notebook pod |
| T.3e | 16:19:05 | Approve the attack's request as j.chen | **PASS** | HTTP 200: {"message": "request ZTR-20260924-0021 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0021", "status": "applied", "approver": "j.chen", "approver_role": "SOC tier 2", "apply": "applied  |
| T.3f | 16:20:29 | Attack retries after the approval | **PASS** | 3 DROPPED from 16:19:10 by zt-quarantine-jupyter-88213, identity 25317; request verified 17 s after apply |
| T.3g | 16:20:43 | ES investigation of the attack | **PASS** | ES-00006 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' status 4, True Positive - Suspicious Activity |
| T.7 | 16:21:31 | Live generator page: Reset after the triggers | **PASS** | released: ml-notebooks/jupyter-75e4a-11141 zt-quarantine-jupyter-88213 ('attack contained, policy retired'); attacks: attack:jupyter-1790266360 stopped; plan idle |
| T.7b | 16:22:06 | Reset duration | **FAIL** | the reset took over 20 s: it asks the emulator to release every attack record ever created, one call through the tunnel each |

## Defects found and fixed

| Steps | Defect | Fix | Deployed through |
|---|---|---|---|
| 2.1b | Live generator timeline coloured background CI jobs on the story's runner pod as incident events | Incident colour only for job 88213, the runner's connections to the checkpoint store and the quarantine records (live/ztlive/engine.py) | live generator |
| 2.5c | The story's runner pod also ran about 240 background CI jobs a day and a few background flows, so the context search and incident table mixed in other builds, and background traffic continued after the quarantine | Background jobs, flows and processes use the other ci-runner replicas; the story's pod only runs job 88213 (ztgen/schedule.py _bg_pod). Daily counts unchanged | generator (1.0.4, live generator now) |
| 3.1b | ES renders the finding title and drilldowns from the template with $risk_object$ after normalising it to the asset name ci-runner.build-farm.svc | The finding rule sets zt_workload = the raw risk object and the title, description and drilldowns use $zt_workload$ | DA-ESS saved search (pushed) |
| 3.4b | The brief recommended an invented policy (ci-runner-checkpoint-store-quarantine, port 9000 only) | The server-context tool returned one row per checkpoint file and head 20 cut off the approval matrix and the naming row; it now returns one row per dataset, an explicit naming row and head 40, and the prompt spells out the kernel recommendation | saved search and agent prompt (pushed) |
| 4.1b, 5.6b | The request, approvals page and audit trail carried the agent's sentence as the action | Kernel requests use 'CNP <policy name>' (request builder and playbook); the agent's text is kept as agent_action | 1.0.4 and playbook (imported) |
| 5.6b | The posture audit trail showed the ES event id instead of the investigation number, and releases collapsed into one row | Finding column shows the investigation (ES-0000n) for live incidents; rows without a request id are left out | Posture dashboard (pushed) |
| 5.7 | Incident Timeline: Decide card quoted the agent's sentence, Verify card compared before-fire with after, incident table and enforcement rows were not scoped to the incident, brief lookups picked another workload's brief, evidence links broke on the incident token | Decide shows the policy and approver; Verify shows during -> after; CI, enforcement, Kubernetes and brief rows are scoped to the runner; links use $incident\|u$ | Incident Timeline (pushed) |
| A.0 | make mode-soar and the live generator's SOAR button did not switch the ES automation rule | Both switch the rule on for SOAR and off for Local | Makefile, live generator |
| A.4b, A.9 | On a re-fired finding (ES reuses the finding group id) the playbook read an earlier run's brief, prompted before this run's brief existed, and resolved the earlier investigation | read_brief only accepts a brief whose run key matches the current reset stamp and that was captured after the playbook started, less 15 minutes; the reused container was renamed | playbook (imported), SOAR container 556 |
| A.5b | SOAR prompt used the internal finding id, the agent's sentence and doubled full stops | Message built from the run state: request id, ES investigation, 'CNP <policy>', cleaned punctuation (playbook and app) | playbook (imported), 1.0.4 |
| A.12 | Live generator's request logger crashed on 404s and dropped the connection | Logger formats the arguments; inline favicon | live generator |
| T.6b, T.3d | Request ids collided across the local path, the SOAR playbook and the enforcement trigger (ZTR-20260924-0021 three times) | Both paths number one above the highest id of the day across the audit trail and the request store | 1.0.4, playbook (imported) |
| T.3d | A workload without a CI job was quarantined under job 88213 (zt-quarantine-jupyter-88213) | Without a CI job the pod names the policy and the label (zt-quarantine-<pod>); 88213 only for the story's pod; same rule in the SOAR custom function | 1.0.4, custom function (imported) |
| T.7b | Reset took over 20 s: one emulator call per attack record ever created | Reset releases only pods that still carry a quarantine label, plus running attacks | 1.0.4, live generator |
| review | A tick that overlaps a fire, reset or mode change could undo it (full-record save) | Every writer of the state record saves only the fields it changed, on top of the current record | 1.0.4, live generator |

