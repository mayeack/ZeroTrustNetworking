# End-to-end test of the demo flow

Every step of `docs/demo_script.md` executed against the Splunk Cloud stack and SOAR Cloud, as a presenter would: the live generator page in a browser for fire, reset, mode and triggers; the searches and pages of the Zero Trust Incident app; Enterprise Security, Agent Launchpad and SOAR through the same searches and REST calls their pages use. Each run starts from a reset. A defect is fixed, then the test restarts from the beginning.

Splunk Web pages were opened in the signed-in tab of the desktop app's built-in browser and read from the page. Values in tables that the hidden browser pane does not draw were read through the search API with the same searches.

The one step not performed by hand is signing in to Splunk Web or SOAR as `j.chen`: I do not type passwords into sign-in forms. j.chen's approval was sent to the same endpoint the Approve button calls (`POST /services/zt_incident_demo/approvals`, Mode B) and to the prompt API the SOAR Approve button uses (`POST /rest/approval/<id>`, Mode A), with j.chen's credentials.

## Summary

| Run | UTC | Steps | Passed | Failed | Notes | Result |
|---|---|---|---|---|---|---|
| Run 1 | 2026-09-24 15:40 to 16:22 | 70 | 51 | 16 | 2 | 16 failed, 1 blocked |
| Run 2 | 2026-09-24 16:44 to 17:26 | 65 | 56 | 8 | 1 | 8 failed |
| Run 3 | 2026-09-24 17:48 to 18:20 | 57 | 54 | 2 | 1 | 2 failed |
| Run 4 | 2026-09-24 18:41 to 19:14 | 41 | 38 | 1 | 2 | 1 failed |
| Run 5 | 2026-09-24 19:15 to 19:47 | 61 | 57 | 1 | 3 | 1 failed |
| Run 6 | 2026-09-24 19:47 to 20:18 | 61 | 58 | 1 | 2 | 1 failed |

Not counted: `run2-aborted`, `run4-stopped`, restarted after a fix found in their first steps.

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

## Run 2

2026-09-24 16:44:40 to 17:26:48 UTC. 65 steps: 56 passed, 8 failed, 0 blocked, 1 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 16:44:40 | Live generator (launchd) and stack versions | **PASS** | owner live:MYEACK-M-P9QJ:72185 holds the lease; search head input logs 'streaming is owned by live:...'; apps {'DA-ESS-zt_incident_demo': '1.0.4', 'zt_incident_demo': '1.0.4'} |
| 1.1 | 16:44:43 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "3", "plan_status": "idle", "quarantine_policies": "none", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.2 | 16:44:43 | make emulator-status | **PASS** | local /version HTTP 200; public https://zt-k8s.yeackbot.com HTTP 200 v1.31.2 |
| 1.3 | 16:44:44 | Live generator page: Reset (two clicks) | **PASS** | reset stamped 16:43:36 UTC, plan idle, nothing to release |
| 1.4 | 16:44:45 | Posture before-state (rollup) | **PASS** | identities 1285, coverage 86.8% (59 of 68), unprotected 9, audit flows 2427, enforcement 23 (kernel 17, DPU 2, switch 4); includes run 1's trigger paths for 24 h |
| 1.5 | 16:46:46 | Splunk Web (built-in browser, signed in by the user): Zero Trust Incident home | **PASS** | cards: Posture 86.8 protected-path coverage, Incident Timeline 5 incidents last 24h, Enforcement Approvals 0 pending; scoreboard 1,285 / 86.8 / 9 / 2 / 23 |
| 1.5b | 16:46:46 | Home scoreboard wording | **INFO** | 'Findings, last 24h' = 2 counts distinct finding groups (ES reuses one group per workload across fires); relabel to 'Finding groups, last 24h' |
| 1.6 | 16:47:26 | Splunk Web: Zero Trust Fabric Posture before the fire | **PASS** | KPIs 1,285 / 86.8% 'up from 85.3% · target 95%' / 9 'down from 10' / 2,427 / 23 (kernel 17 · DPU 2 · switch 4); verdict chart shows its empty state after the reset; unprotected paths table lists the 8 ticketed gaps plus run 1's trigger path |
| 1.6b | 16:47:26 | Posture wording | **FAIL** | the audit trail panel is titled 'Enforcement Audit Trail (SOAR)' and the description says 'SOAR audit trail' although local approvals appear too; routine playbook rows read 'playbook (policy) (policy)' |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 16:47:48 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T16:47:33.634Z · attempts every 30s' |
| 2.2 | 16:49:13 | Splunk Web Search: index=zero_trust sourcetype=cilium:hubble:flow verdict=AUDIT src_workload="build-farm/ci-runner" | **PASS** | 1 event 16:47:33.663: ci-runner-7d9f8-xk2lq -> checkpoint-store-1:9000, identities 48213 -> 30719, allowlist checkpoint-store-ingress-allowlist (audit), src_owner platform-build |
| 2.3 | 16:49:13 | Splunk Web Search: index=zero_trust sourcetype=cisco:isovalent:processConnect process_name=curl | **PASS** | 2 events (attempts 0 and 1, 30 s apart): /usr/bin/curl from /bin/sh -c ./scripts/postbuild.sh on bf-node-03, .../ckpt/llm-7712/step-184000/model-00001 then model-00002 -> checkpoint-store-1 |
| 2.4 | 16:49:13 | Compare _time of the two sensors | **PASS** | Tetragon connect 16:47:33.634, Hubble AUDIT 16:47:33.663: 29 ms apart |
| 2.5 | 16:49:13 | Splunk Web Search: ci:job:event pod="ci-runner-7d9f8-xk2lq"; \| inputlookup zt_node_fabric where node="bf-node-03" | **PASS** | only job 88213 on the pod (package, post-build, MR 4417, contractor-dev-17, running, ml-infra/train-utils): the background fix works; fabric dc2-leaf-205 Eth1/12 |
| 2.6 | 16:49:50 | Rerun search 1 (attempt count) | **PASS** | 5 AUDIT flows since the fire, one per 30 s attempt |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 16:49:51 | Risk events for build-farm/ci-runner since the fire | **PASS** | 16:48:09 ZT - Unapproved Program Connected to Protected AI Data Store +40.0; 16:48:08 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 (total 90) |
| 3.1 | 16:53:08 | ES Analyst Queue (Splunk Web): the ZT finding group | **PASS** | queue row title 'Unprotected path: build-farm/ci-runner reached a protected AI data store' (template $zt_workload$ now renders the workload); finding 16:49:06 (T0+1m32s) risk 90 from 2 detections, severity high, domain network, threat objects /usr/bin/curl,ai-train/checkpoint-store, MITRE T1059.004,T1530 |
| 3.2 | 16:53:15 | Run the three drilldowns (token $zt_workload$ = build-farm/ci-runner) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 74; Tetragon events for build-farm/ci-runner: 94; CI jobs on build-farm/ci-runner pods: 44 |
| 3.3 | 16:53:16 | Agent run history (ZTFlowInvestigator) | **PASS** | 5 tool calls: zt_finding_context > zt_flow_evidence > zt_process_evidence > zt_ci_job_context > zt_workload_server_context; run 80.19491624832153 s |
| 3.4 | 16:53:17 | Read the brief | **PASS** | true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommends zt-quarantine-ci-runner-88213 at the kernel, approvers ['SOC tier 2']; missing facts: none |
| 3.5 | 16:53:18 | ES investigation ES-00008 notes | **PASS** | [('ZTFlowInvestigator brief', True), ('Quarantine requested', False)] |
| 3.1c | 17:26:47 | Analyst Queue: extra notebook investigation | **FAIL** | ES-00007 (16:21) duplicated ES-00006: a brief capture whose window predated run 1's last reset re-keyed the old agent run as a new run (ztbrief reads the reset stamp but never compared the run's time with it); resolved by hand with a note |
| 3.1d | 17:26:47 | Analyst Queue: entity name | **FAIL** | the Entity column shows ci-runner.build-farm.svc (the asset's DNS name, which ES prefers) while the title says build-farm/ci-runner |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 16:55:51 | Enforcement Approvals (Splunk Web): pending request ZTR-20260924-0022 | **PASS** | pending, ES-00008, build-farm/ci-runner pod ci-runner-7d9f8-xk2lq, kernel, action 'CNP zt-quarantine-ci-runner-88213', approvers SOC tier 2, requested 16:52:01 (brief + 85 s) |
| 4.2 | 16:55:51 | Select the row: the brief and the policy YAML panels | **PASS** | panels show what the agent found and 'Policy to apply · zt-quarantine-ci-runner-88213 (pending)' with endpointSelector zt-quarantine: "88213", egressDeny/ingressDeny all |
| 4.3 | 16:55:53 | Type a comment and click Approve as the signed-in admin (not SOC tier 2) | **PASS** | Last decision panel: 'admin is not an approver for the kernel enforcement point (needs SOC tier 2)'; refusal audited: {'approved_by_label': 'admin (admin)', 'comment': 'admin is not an approver for the kernel enforcement point (needs SOC tier 2)'} |
| 4.4 | 16:55:58 | Approve as j.chen (SOC tier 2) through POST /services/zt_incident_demo/approvals (the Approve button's call) | **PASS** | HTTP 200 in 4.7 s: {"message": "request ZTR-20260924-0022 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0022", "status": "applied", "approver": "j.chen", |
| 4.5 | 16:56:08 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 16:55:54.920 patch pods/ci-runner-7d9f8-xk2lq 200; 16:55:56.921 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| 4.6 | 16:56:23 | Enforcement Approvals › Request history | **FAIL** | applied_epoch and verified_epoch show '1970-01-01 00:00:00' until they are set (cosmetic) |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 16:57:15 | First retry after the approval | **PASS** | 16:56:03.641 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 10 s) |
| 5.1 | 16:57:16 | Request status after the first DROPPED | **PASS** | status verified, verified 15 s after apply |
| 5.2 | 17:04:10 | ES investigation ES-00008 after verification | **PASS** | status 4 (Resolved), True Positive - Suspicious Activity; notes: ZTFlowInvestigator brief \| Quarantine requested \| Quarantine applied \| Quarantine verified |
| 5.3 | 17:04:13 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED; job failed at 16:58:48 with script_failure |
| 5.4 | 17:04:13 | Splunk Web: Incident Timeline (selector on the newest incident) | **PASS** | selector opens on '2026-09-24 16:47:06 UTC · CI job 88213 · MR !4417'; five cards ticked (Decide: ES-00008, recommends zt-quarantine-ci-runner-88213, approver SOC tier 2; Enforce: approved by j.chen, applied through the approvals endpoint; Verify: 6 retries dropped, verified 16:56:13, coverage 85.3% during -> 86.8% now); 12 grid cells ticked with times; raw JSON of the first AUDIT flow and Tetragon connect; incident table newest first: CI job 88213 failed, six DROPPED rows by zt-quarantine-ci-runner-88213, verified CNP (j.chen (SOC tier 2)) |
| 5.5 | 17:05:01 | Splunk Web: Zero Trust Fabric Posture after the quarantine | **PASS** | KPIs 1,285 / 86.8% 'up from 85.3%' / 9 'down from 10' / 2,444 / 24 (kernel 18 · DPU 2 · switch 4): enforcement +1 kernel against the before-state 23 (kernel 17) |
| 5.6 | 17:05:01 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 | **PASS** | AUDIT 17 then DROPPED 6 in the last 30 minutes |
| 5.7 | 17:05:01 | Enforcement Audit Trail, first row | **PASS** | 2026-09-24 16:56:13 \| ES-00008 \| CNP zt-quarantine-ci-runner-88213 \| kernel \| j.chen (SOC tier 2) \| verified |
| 5.4b | 17:26:47 | Incident Timeline: incident selector (fixed during this run) | **FAIL** | the dropdown's dynamic options referenced label/value/statics without declaring them, so it listed nothing and every panel waited for a token; context added and pushed, the page then opened on the newest incident |
| 5.4c | 17:26:47 | Incident Timeline: load time (fixed during this run) | **FAIL** | the grid search (13 appended searches, 15 s) and the step cards showed raw $ds_...$ tokens for about 30 s; grid rebuilt to 7 searches (7.8 s, same output) and cards hidden until their data arrives |
| 5.4d | 17:26:48 | Incident Timeline: incident table order (fixed during this run) | **FAIL** | oldest first, 20 per page: the outcome (failed job, drops, verification) was on page 5; now newest first and dropped rows name the denying policy |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 17:05:42 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | page within 10 s: 'plan idle, reset stamped · released zt-quarantine-ci-runner-88213 · cancelled 0'; audit released by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.1 | 17:06:33 | Live generator page › Settings › Response mode: SOAR (one click) | **PASS** | state response_mode soar; ES automation rule 'Zero Trust Protected Paths' on (ES and SOAR sides both report on) |
| A.2 | 17:07:12 | Live generator page: Fire the incident (Mode A) | **PASS** | page: 'incident started at 2026-09-24T17:06:47.944Z · attempts every 30s' |
| A.3 | 17:11:38 | ES finding and automation rule (Mode A) | **PASS** | finding 17:08:10; playbook run 524 on the renamed container 556 at 17:08:18; read_brief polled until this run's brief existed (17:10:47, ES-00009) instead of taking an earlier one; no local request created |
| A.4 | 17:11:38 | SOAR prompt ask_approval (role SOC tier 2): read the message | **PASS** | first line: 'Quarantine request ZTR-20260924-0023 for ES-00009: build-farm/ci-runner reached ai-train/checkpoint-store (crown-jewel).'; recommends 'CNP zt-quarantine-ci-runner-88213 at the kernel'; policy YAML included; no stale brief text |
| A.5 | 17:11:39 | Answer the prompt as j.chen: Approve with a comment (POST /rest/approval/5) | **PASS** | status approved, responses ['Approve', 'Contractor merge request; not approved for checkpoint access'] |
| A.6 | 17:13:12 | Playbook applies the quarantine after the approval | **PASS** | 17:11:45 patch pods/ci-runner-7d9f8-xk2lq 200; 17:11:49 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| A.7 | 17:13:14 | Enforcement audit trail (Mode A) | **PASS** | requested 17:11:00, approved 17:11:39, applied 17:11:52, verified 17:12:29; executed_by soar, playbook run 524, j.chen (SOC tier 2), investigation ES-00009, action 'CNP zt-quarantine-ci-runner-88213' |
| A.8 | 17:14:13 | ES investigation of this run after the playbook | **PASS** | ES-00009 status 4, True Positive - Suspicious Activity (the playbook resolved this run's investigation) |
| A.9 | 17:15:33 | Runner retries and CI job outcome (Mode A), re-checked after the sixth drop | **PASS** | 6 DROPPED; job failed at 17:15:02 with script_failure (first check ran before the sixth drop) |
| A.10 | 17:17:07 | Live generator page: Reset; Settings › Response mode: Local (one click) | **PASS** | reset stamped 17:15:50 (released zt-quarantine-ci-runner-88213); page: now {response_mode: local, agent_mode: mcp, automation_rule: off} |
| A.11 | 17:17:07 | Live generator service log | **FAIL** | a browser closing an idle keep-alive connection is logged as a full traceback (ConnectionResetError); harmless noise |

### Live generator triggers

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| T.1 | 17:19:31 | Triggers › Audit-mode flow: data-eng/spark-driver -> ai-train/checkpoint-store | **PASS** | page 'audit-mode connection sent (2 events)'; risk: 17:18:08 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 |
| T.2 | 17:19:31 | Triggers › Unapproved program: observability/log-shipper, /usr/bin/curl | **PASS** | page 'unapproved program connect sent (2 events)'; risk: 17:18:09 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 |
| T.4 | 17:19:38 | Triggers › Nexus Live Protect | **PASS** | indexed: [{'_time': '2026-09-24 17:17:40.010 UTC', 'switch': 'dc2-leaf-201', 'advisory_id': 'cisco-sa-nxos-ospf-memleak-4qkw3', 'status': 'protected'}] |
| T.5 | 17:19:38 | Triggers › Nexus configuration change | **PASS** | indexed: [{'_time': '2026-09-24 17:17:43.696 UTC', 'device': 'dc2-leaf-201', 'user': 'netops-cli', 'change': 'interface Eth1/12 description zt-live'}] |
| T.6 | 17:19:38 | Triggers › Enforcement action (kernel, platform/jump-host, j.chen) | **PASS** | request ZTR-20260924-0024 (one above the playbook's 0023, no collision): verified 17:17:39, applied 17:16:54, approved 17:16:52, requested 17:15:19 |
| T.3a | 17:23:25 | Triggers › Path attack: ml-notebooks/jupyter -> ai-train/checkpoint-store | **PASS** | page: 'attack started (4 events) · attempts every 30s' |
| T.3b | 17:23:25 | Path attack detected | **PASS** | risk 50 + 40 on ml-notebooks/jupyter at 17:18:08-09; finding 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' at 17:19:08 |
| T.3c | 17:23:25 | Agent brief for the attack | **PASS** | agent 17:19:18-17:20:59; brief ES-00010, job_id empty (no CI job), recommends zt-quarantine-jupyter-75e4a-11141 (pod naming) |
| T.3d | 17:23:25 | Quarantine request for the attack (scheduled search) | **PASS** | ZTR-20260924-0025 (next free id), pending, policy zt-quarantine-jupyter-75e4a-11141, action 'CNP zt-quarantine-jupyter-75e4a-11141' |
| T.3e | 17:23:29 | Approve the attack's request as j.chen | **PASS** | HTTP 200: {"message": "request ZTR-20260924-0025 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0025", "status": "applied", "approver": "j.chen", "approver |
| T.3f | 17:25:44 | Attack retries after the approval (re-checked after the next verification run) | **PASS** | 4 DROPPED from 17:23:58 by zt-quarantine-jupyter-75e4a-11141, identity 25317; pod label patch 200 and policy create 201 in ml-notebooks; request verified 94 s after apply (the first check ran before the first drop was searchable; my manual \| ztsoar action=verify ran a minute ahead of the schedule) |
| T.3g | 17:25:45 | ES investigation of the attack (after verification) | **PASS** | ES-00010 status 4, True Positive - Suspicious Activity |
| T.7 | 17:26:47 | Live generator page: Reset after the triggers | **PASS** | reset stamped 17:26:03, about 6 s after the click (was over 20 s in run 1): released zt-quarantine-jupyter-75e4a-11141 only; attack stopped |

## Run 3

2026-09-24 17:48:07 to 18:20:18 UTC. 57 steps: 54 passed, 2 failed, 0 blocked, 1 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 17:48:07 | Live generator (launchd) and stack versions | **PASS** | owner live:MYEACK-M-P9QJ:47110 holds the lease; search head input: '261, 'skipped': 'streaming is owned by live:MYEACK-M-P9QJ:47110 (lease 2s old)'}'; apps {'DA-ESS-zt_incident_demo': '1.0.5', 'zt_incident_demo': '1.0.5'} |
| 1.1 | 17:48:11 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "2", "plan_status": "idle", "quarantine_policies": "none", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.2 | 17:49:03 | make emulator-status | **PASS** | local /version HTTP 200; public https://zt-k8s.yeackbot.com HTTP 200 v1.31 |
| 1.3 | 17:49:43 | Live generator page: Reset (two clicks) | **PASS** | page: 'plan idle, reset stamped · released none · cancelled 0' within 10 s |
| 1.4 | 17:49:45 | Posture before-state (rollup) | **PASS** | identities 1285, coverage 86.8% (59 of 68), unprotected 9, audit flows 2468, enforcement 27 (kernel 21, DPU 2, switch 4); carries runs 1-2 and their trigger paths for 24 h |
| 1.5 | 17:50:58 | Splunk Web: Zero Trust Incident home | **PASS** | cards: 86.8 protected-path coverage · 7 incidents fired, last 24h · 0 pending approvals; scoreboard 1,285 / 86.8 / 9 / 2 finding groups, last 24h / 28 enforcements verified |
| 1.6 | 17:50:58 | Splunk Web: Zero Trust Fabric Posture before the fire | **PASS** | panel 'Enforcement Audit Trail' (no '(SOAR)'); routine rows read 'playbook (policy)'; KPIs as the rollup: 1,285 / 86.8% / 9 / 27 |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 17:52:49 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T17:51:06.634Z · attempts every 30s' |
| 2.2 | 17:52:52 | Search 1 (Splunk Web showed '1 event, Statistics (1)'; values read by search API because the hidden pane does not draw the table) | **PASS** | 17:52:36.663 checkpoint-store-1:9000, 48213 -> 30719, checkpoint-store-ingress-allowlist (audit), owner platform-build |
| 2.3 | 17:52:53 | Search 2: processConnect process_name=curl | **PASS** | 17:51:06.634 /usr/bin/curl from /bin/sh -c ./scripts/postbuild.sh on bf-node-03 -> checkpoint-store-1 (0/ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors) |
| 2.4 | 17:53:12 | Compare _time of the first Tetragon connect and the first Hubble AUDIT flow (re-checked: the first check compared the newest AUDIT flow) | **PASS** | cisco:isovalent:processConnect then cilium:hubble:flow: 29 ms apart |
| 2.5 | 17:52:57 | Context: ci:job:event pod="ci-runner-7d9f8-xk2lq" (last 15 min); zt_node_fabric bf-node-03 | **PASS** | jobs on the pod: 1 (88213) package/post-build MR 4417 by contractor-dev-17; fabric dc2-leaf-205 Eth1/12 |
| 2.6 | 17:53:14 | Rerun search 1 (attempt count) | **PASS** | 5 AUDIT flows since the fire, one per 30 s attempt |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 17:53:28 | Risk events for build-farm/ci-runner since the fire | **PASS** | 17:52:07 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 (normalized build-farm/ci-runner); 17:52:07 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 (normalized build-farm/ci-runner) (total 90) |
| 3.1 | 17:54:15 | Splunk Web: ES Analyst Queue | **PASS** | top row 'Unprotected path: build-farm/ci-runner reached a protected AI data store', entity build-farm/ci-runner (ES now names it by the workload), score 90, 5:53 PM, New; finding 17:53:11 (T0+2m05s), risk 90 from 2 detections, severity high, threat objects /usr/bin/curl,ai-train/checkpoint-store, MITRE T1059.004,T1530 |
| 3.1b | 17:54:16 | Analyst Queue: ES's own 24-hour threshold | **INFO** | after several runs in a day, ES's 'Risk - 24 Hour Risk Threshold Exceeded' rule also opens a finding for build-farm/ci-runner (score 180); Enterprise Security content, not changed; the talk track should mention it or filter the queue on 'Unprotected path' |
| 3.2 | 17:54:38 | Run the three drilldowns of the finding rule ($zt_workload$ = build-farm/ci-runner) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 66; Tetragon events for build-farm/ci-runner: 85; CI jobs on build-farm/ci-runner pods: 4 |
| 3.3 | 17:54:58 | Agent run history (ZTFlowInvestigator) | **PASS** | 5 tool calls: zt_finding_context > zt_flow_evidence > zt_process_evidence > zt_ci_job_context > zt_workload_server_context; run 60 s |
| 3.4 | 17:54:58 | Read the brief | **FAIL** | true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommends zt-quarantine-ci-runner-88213 at the kernel; missing facts: ['SOC tier 2'] |
| 3.5 | 17:56:12 | ES investigation ES-00011 notes | **PASS** | [('ZTFlowInvestigator brief', True), ('Quarantine requested', False)] |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 17:56:12 | Pending request (Enforcement Approvals data) | **PASS** | ZTR-20260924-0026 pending, ES-00011, action 'CNP zt-quarantine-ci-runner-88213', approvers 'SOC tier 2' (from the approval matrix, not the brief), requested 17:56:01 |
| 4.2 | 17:56:12 | The request's policy YAML | **PASS** | zt-quarantine-ci-runner-88213, endpointSelector zt-quarantine: "88213", egressDeny/ingressDeny all |
| 4.3 | 17:56:42 | Approve as a.patel (NetOps) through the approvals endpoint (the page's Approve button was clicked as admin in run 2; this session's pane is not on screen) | **PASS** | HTTP 403: {"message": "a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)", "request_id": "Z; refusal audited: {'approved_by_label': 'a.patel (NetOps)', 'comment': 'a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)'} |
| 4.4 | 17:56:47 | Approve as j.chen (SOC tier 2) through POST /services/zt_incident_demo/approvals | **PASS** | HTTP 200 in 5.1 s: {"message": "request ZTR-20260924-0026 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0026", "status": "a |
| 4.5 | 17:56:57 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 17:56:43 patch pods/ci-runner-7d9f8-xk2lq 200; 17:56:45 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 18:00:20 | First retry after the approval | **PASS** | 17:57:06.641 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 24 s) |
| 5.1 | 18:00:21 | Request status after the first DROPPED | **PASS** | ZTR-20260924-0026 verified 34 s after apply |
| 5.2 | 18:00:24 | ES investigation ES-00011 after verification | **PASS** | status 4 (Resolved), True Positive - Suspicious Activity |
| 5.3 | 18:00:29 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED; job failed at 17:59:51 with script_failure |
| 5.4 | 18:01:34 | Splunk Web: Incident Timeline (selector on the newest incident) | **PASS** | selector '2026-09-24 17:50:39 UTC · CI job 88213 · MR !4417'; five cards ticked; grid 12/12 ticked (1:17:51:06 2:17:51:06 3:17:51:10 4:17:52:07 5:17:53:11 6:17:54:21 7:17:56:46 8:17:56:45 9:17:56:43 10:17:57:06 11:17:57:00 12:17:57:20); Decide names ES-00011 and zt-quarantine-ci-runner-88213; Verify: coverage 85.3% during -> 86.8% now; incident table newest first: six DROPPED rows by zt-quarantine-ci-runner-88213, verified CNP (j.chen (SOC tier 2)) |
| 5.4b | 18:01:34 | Incident Timeline: Decide card approver | **FAIL** | reads 'approver soc-tier-2' because this run's brief returned the approver as a slug (run 2's said 'SOC tier 2'); the request itself takes approvers from the approval matrix |
| 5.5 | 18:02:10 | Splunk Web: Zero Trust Fabric Posture after the quarantine | **PASS** | identities 1285, coverage 86.8% 'up from 85.3%', unprotected 9 'down from 10', enforcement 28 (kernel 22 · DPU 2 · switch 4) = before-state 27 + 1 kernel |
| 5.6 | 18:02:12 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 | **PASS** | AUDIT 12 then DROPPED 6 in the last 30 minutes |
| 5.7 | 18:02:15 | Enforcement Audit Trail, first row | **PASS** | 2026-09-24 17:57:20 \| ES-00011 \| CNP zt-quarantine-ci-runner-88213 \| kernel \| j.chen (SOC tier 2) \| verified |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 18:02:58 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | page: 'plan idle, reset stamped · released zt-quarantine-ci-runner-88213 · cancelled 0'; released by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.1 | 18:03:44 | Live generator page › Settings › Response mode: SOAR (one click); Dashboard › Fire the incident | **PASS** | page: now {response_mode: soar, agent_mode: mcp, automation_rule: on}; 'incident started at 2026-09-24T18:03:24.235Z' |
| A.2 | 18:08:23 | ES finding and automation rule (Mode A) | **PASS** | finding 18:05:12 (entity build-farm/ci-runner); playbook run 545 on a new container 1067 named 'Unprotected path: build-farm/ci-runner reached a protected AI data store' at 18:05:23; read_brief polled until this run's brief existed (18:07:16, ES-00012); no local request |
| A.3 | 18:08:24 | SOAR prompt ask_approval (role SOC tier 2) | **PASS** | 'Quarantine request ZTR-20260924-0027 for ES-00012: build-farm/ci-runner reached ai-train/checkpoint-store (crown-jewel).'; recommends CNP zt-quarantine-ci-runner-88213 at the kernel; this run's brief (18:03:24-18:05:24 UTC) |
| A.4 | 18:08:25 | Answer the prompt as j.chen: Approve with a comment (POST /rest/approval/7) | **PASS** | status approved, responses ['Approve', 'Contractor merge request; not approved for checkpoint access'] |
| A.5 | 18:12:02 | Playbook applies the quarantine | **PASS** | 18:08:30 patch pods/ci-runner-7d9f8-xk2lq 200; 18:08:34 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| A.6 | 18:12:06 | Enforcement audit trail (Mode A) | **PASS** | requested 18:07:29, approved 18:08:25, applied 18:08:36, verified 18:09:11; executed_by soar, playbook run 545, j.chen (SOC tier 2), ES-00012, 'CNP zt-quarantine-ci-runner-88213' |
| A.7 | 18:12:09 | ES investigation of this run after the playbook | **PASS** | ES-00012 status 4, True Positive - Suspicious Activity |
| A.8 | 18:12:13 | Runner retries and CI job outcome (Mode A) | **PASS** | 6 DROPPED; job failed at 18:11:39 with script_failure |
| A.9 | 18:12:51 | Live generator page: Reset; Settings › Response mode: Local (one click) | **PASS** | page: 'plan idle, reset stamped · released zt-quarantine-ci-runner-88213 · cancelled 0'; then now {response_mode: local, agent_mode: mcp, automation_rule: off} |

### Live generator triggers

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| T.1 | 18:16:10 | Triggers › Audit-mode flow: data-eng/spark-driver -> ai-train/checkpoint-store | **PASS** | page 'audit-mode connection sent (2 events)'; risk: 18:13:08 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 on data-eng/spark-driver |
| T.2 | 18:16:10 | Triggers › Unapproved program: observability/log-shipper, /usr/bin/curl | **PASS** | page 'unapproved program connect sent (2 events)'; risk: 18:14:06 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 on observability/log-shipper |
| T.4 | 18:16:10 | Triggers › Nexus Live Protect | **PASS** | page 'Live Protect event sent (1 events)'; indexed 18:13:10 cisco:nexus:liveprotect dc2-leaf-201 cisco-sa-nxos-ospf-memleak-4qkw3 protected |
| T.5 | 18:16:10 | Triggers › Nexus configuration change | **PASS** | page 'Nexus config change sent (1 events)'; indexed 18:13:14 cisco:nexus:config dc2-leaf-201 netops-cli 'interface Eth1/12 description zt-live' success |
| T.6 | 18:16:37 | Triggers › Enforcement action (kernel, platform/jump-host, j.chen) | **PASS** | page 'enforcement ZTR-20260924-0028 recorded (6 events)'; audit trail: requested 18:10:50, approved 18:12:23, applied 18:12:25, verified 18:13:10; one above the playbook's 0027, no collision |
| T.3a | 18:18:43 | Triggers › Path attack: ml-notebooks/jupyter -> ai-train/checkpoint-store | **PASS** | page 'attack started (4 events) · attempts every 30s'; attack jupyter-1790273601 started 18:13:21 |
| T.3b | 18:18:43 | Path attack detected | **PASS** | risk 50 + 40 on ml-notebooks/jupyter at 18:14:06; finding 18:15:12 (ZT - Workload Exceeded Risk Threshold on Protected-Path Signals, zt_workload ml-notebooks/jupyter, risk 90, 2 sources) |
| T.3c | 18:18:43 | Agent brief for the attack | **PASS** | brief 18:16:44, ES-00013, job_id empty (no CI job), true_positive (high), recommends CNP zt-quarantine-jupyter-75e4a-11141 at the kernel, approver 'SOC tier 2' (verbatim, no slug) |
| T.3d | 18:18:43 | Quarantine request for the attack (scheduled search) | **PASS** | ZTR-20260924-0029 (next free id after the trigger's 0028), pending 18:18:02, ES-00013, action 'CNP zt-quarantine-jupyter-75e4a-11141' |
| T.3e | 18:19:25 | Approve the attack's request as j.chen (POST /services/zt_incident_demo/approvals) | **PASS** | HTTP 200 in 6.4 s: 'request ZTR-20260924-0029 approved by j.chen (SOC tier 2)', status applied |
| T.3f | 18:19:25 | Attack retries after the approval | **PASS** | kube: patch pods/jupyter-75e4a-11141 200 (18:18:44), create ciliumnetworkpolicies/zt-quarantine-jupyter-75e4a-11141 201 (18:18:46) in ml-notebooks; first DROPPED 18:18:51, identity 25317, denied by zt-quarantine-jupyter-75e4a-11141; request verified 17 s after apply (run 2: 94 s) |
| T.3g | 18:19:25 | ES investigation of the attack | **PASS** | ES-00013 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' status 4 (Resolved), True Positive - Suspicious Activity |
| T.7 | 18:20:18 | Live generator page: Reset (two clicks) after the triggers | **PASS** | page 'plan idle, reset stamped · released zt-quarantine-jupyter-75e4a-11141 · cancelled 0'; reset stamped 18:19:40, a few seconds after the click; attack jupyter-1790273601 stopped (12 attempts, 2 dropped); no quarantine left in zt_policy_state |

## Run 4

2026-09-24 18:41:36 to 19:14:33 UTC. 41 steps: 38 passed, 1 failed, 0 blocked, 2 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 18:41:36 | Live generator (launchd) and stack versions | **PASS** | owner live:MYEACK-M-P9QJ:40412 holds the lease (age 5s), 5 ticks; page shows stack app 1.0.5; stack apps {'zt_incident_demo': '1.0.5', 'DA-ESS-zt_incident_demo': '1.0.5'} |
| 1.1 | 18:41:39 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "3", "plan_status": "idle", "quarantine_policies": "none", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.2 | 18:41:39 | make emulator-status | **PASS** | local  : HTTP 200 public : https://zt-k8s.yeackbot.com -> HTTP 200 {"major": "1", "minor": "31", "gitVersion": "v1.31.2", "platform": "linux/amd64" |
| 1.3 | 18:42:17 | Live generator page: Reset (two clicks) | **PASS** | page: 'plan idle, reset stamped · released none · cancelled 0' within 10 s; Settings shows stack app 1.0.5 |
| 1.4 | 18:42:19 | Posture before-state (rollup) | **PASS** | identities 1285, coverage 86.8% (59 of 68), unprotected 9, audit flows 2503, enforcement 31 (kernel 25, DPU 2, switch 4) |
| 1.5 | 18:43:22 | Splunk Web (built-in browser, signed-in tab): Zero Trust Incident home | **PASS** | cards: 86.8 protected-path coverage · 9 incidents fired, last 24h · 0 pending approvals; scoreboard 1,285 / 86.8 / 9 / 3 finding groups, last 24h / 33 enforcements verified, last 24h |
| 1.6 | 18:43:22 | Splunk Web: Zero Trust Fabric Posture before the fire | **PASS** | KPIs as the rollup: 1,285 / 86.8% 'up from 85.3%' / 9 'down from 10' / 2,503 / 31 (kernel 25 · DPU 2 · switch 4); verdict chart shows 'No incident since the last reset'; panel 'Enforcement Audit Trail', routine rows 'playbook (policy)', run 3 rows ES-00011..ES-00013 with j.chen (SOC tier 2) |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 18:43:42 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T18:43:29.345Z · attempts every 30s' |
| 2.2 | 18:44:26 | Search 1: hubble AUDIT flows from build-farm/ci-runner | **PASS** | 18:43:29.374 checkpoint-store-1:9000, 48213 -> 30719, checkpoint-store-ingress-allowlist (audit), owner platform-build |
| 2.3 | 18:44:28 | Search 2: processConnect process_name=curl | **PASS** | 18:43:29.345 /usr/bin/curl from /bin/sh -c ./scripts/postbuild.sh on bf-node-03 -> checkpoint-store-1 (0/ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors) |
| 2.4 | 18:44:28 | Compare _time of the first Tetragon connect and the first Hubble AUDIT flow | **PASS** | connect 18:43:29.345, AUDIT 18:43:29.374: 29 ms apart |
| 2.5 | 18:44:31 | Context: ci:job:event pod="ci-runner-7d9f8-xk2lq" (last 15 min); zt_node_fabric bf-node-03 | **PASS** | jobs on the pod: 1 (88213) package/post-build MR 4417 by contractor-dev-17; fabric dc2-leaf-205 Eth1/12 |
| 2.6 | 18:44:42 | Rerun search 1 (attempt count) | **PASS** | 3 AUDIT flows since the fire, one per 30 s attempt (73 s after the fire) |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 18:45:39 | Risk events for build-farm/ci-runner since the fire | **PASS** | 18:44:06 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0; 18:44:06 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 (total 90) |
| 3.2 | 18:45:48 | Run the three drilldowns of the finding rule ($zt_workload$ = build-farm/ci-runner) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 68; Tetragon events for build-farm/ci-runner: 89; CI jobs on build-farm/ci-runner pods: 5 |
| 3.1 | 18:46:26 | Splunk Web: ES Analyst Queue | **PASS** | top row 'Unprotected path: build-farm/ci-runner reached a protected AI data store', entity build-farm/ci-runner, 2 intermediate findings, score 90, New; notable 18:45:13 (T0+1m44s), severity high, threat objects /usr/bin/curl and ai-train/checkpoint-store, MITRE T1059.004 and T1530 |
| 3.1b | 18:46:26 | Analyst Queue: time of a re-fired finding group | **INFO** | the row's time reads 5:53 PM, when this finding group was first created (run 3): ES reuses the group for the same rule and entity and keeps its first time; a fresh stack shows the fire time. ES's own 24-hour threshold rule also lists build-farm/ci-runner after several runs a day (run 3 note) |
| 3.3 | 18:47:09 | Agent run history (ZTFlowInvestigator) | **PASS** | 6 tool calls: zt_finding_context > zt_flow_evidence > zt_process_evidence > zt_ci_job_context > zt_workload_server_context > zt_workload_server_context; run 100 s |
| 3.4 | 18:47:10 | Read the brief | **PASS** | true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommends zt-quarantine-ci-runner-88213 at the kernel; approver_labels ["SOC tier 2"]; missing facts: none |
| 3.5 | 18:49:18 | ES investigation ES-00014 notes | **PASS** | [('ZTFlowInvestigator brief', True), ('Quarantine requested', False)]; brief KV approver_labels 'SOC tier 2' |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 18:49:18 | Pending request (Enforcement Approvals data) | **PASS** | ZTR-20260924-0030 pending, ES-00014, action 'CNP zt-quarantine-ci-runner-88213', approvers 'SOC tier 2', requested 18:49:02 |
| 4.2 | 18:49:18 | The request's policy YAML | **PASS** | zt-quarantine-ci-runner-88213, endpointSelector zt-quarantine: "88213", egressDeny/ingressDeny all |
| 4.0 | 18:49:52 | Splunk Web: Enforcement Approvals with the request pending | **PASS** | pending row ZTR-20260924-0030 · ES-00014 · build-farm/ci-runner · ci-runner-7d9f8-xk2lq · kernel · CNP zt-quarantine-ci-runner-88213 · SOC tier 2 · 18:49:02; history lists it as pending with applied/verified blank; the finding_id column shows ES's internal finding group id next to the investigation number |
| 4.3 | 18:50:05 | Approve as a.patel (NetOps) through the approvals endpoint | **PASS** | HTTP 403: {"message": "a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)", "request_id": "Z; refusal audited: {'approved_by_label': 'a.patel (NetOps)', 'comment': 'a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)'} |
| 4.4 | 18:50:14 | Approve as j.chen (SOC tier 2) through POST /services/zt_incident_demo/approvals | **PASS** | HTTP 200 in 9.1 s: {"message": "request ZTR-20260924-0030 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0030", "status": "a |
| 4.5 | 18:50:25 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 18:50:07 patch pods/ci-runner-7d9f8-xk2lq 200; 18:50:09 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 18:53:30 | First retry after the approval | **PASS** | 18:50:29.352 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 24 s) |
| 5.1 | 18:53:31 | Request status after the first DROPPED | **PASS** | ZTR-20260924-0030 verified 35 s after apply |
| 5.2 | 18:53:33 | ES investigation ES-00014 after verification | **PASS** | status 4 (Resolved), True Positive - Suspicious Activity |
| 5.3 | 18:53:35 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED; job failed at 18:53:14 with script_failure |
| 5.4 | 18:54:32 | Incident Timeline data (selector's newest incident, journey grid) | **PASS** | selector '2026-09-24 18:43:02 UTC · CI job 88213 · MR !4417'; grid 12/12 ticked (1:18:43:29 2:18:43:29 3:18:43:32 4:18:44:06 5:18:45:13 6:18:47:06 7:18:50:11 8:18:50:09 9:18:50:07 10:18:50:29 11:18:51:00 12:18:50:46) |
| 5.4b | 18:54:35 | Incident Timeline: Decide card | **PASS** | Risk events 18:44:06 → 18:44:06 · 2 signals · 90.0 risk on build-farm/ci-runner / Finding group ES-00014 18:45:13 · risk 90 from 2 detections, over the threshold of 80 / Agent brief 18:47:06 · true positive (high) · recommends zt-quarantine-ci-runner-88213 at the kernel, approver SOC tier 2 |
| 5.5 | 18:54:59 | Zero Trust Fabric Posture after the quarantine (KPI search) | **PASS** | identities 1285, coverage 86.8%, unprotected 9, enforcement 32 (kernel 26 · DPU 2 · switch 4); before-state 1285 / 86.8% / 9 / 31 |
| 5.6 | 18:55:01 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 | **PASS** | AUDIT 14 then DROPPED 6 in the last 30 minutes |
| 5.7 | 18:55:08 | Enforcement Audit Trail, first row | **PASS** | 2026-09-24 18:50:46 \| ES-00014 \| CNP zt-quarantine-ci-runner-88213 \| kernel \| j.chen (SOC tier 2) \| verified |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 18:55:48 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.1 | 18:56:34 | Live generator page › Settings › Response mode: SOAR (one click); Dashboard › Fire the incident | **PASS** | page: now {response_mode: soar, agent_mode: mcp, automation_rule: on}; 'incident started at 2026-09-24T18:56:20.451Z' |
| A.2 | 19:06:44 | ES finding and automation rule (Mode A) | **FAIL** | finding 18:58:12 (entity build-farm/ci-runner); playbook run 569 on container 1067 'Unprotected path: build-farm/ci-runner reached a protected AI data store' started 18:58:31; brief - (-); local requests: 0 |
| A.2b | 19:13:40 | Root cause of A.2 | **INFO** | the agent ran (18:58:22-19:00:07, 5 tools, success), but its run_finished event in _audit is 10,656 characters and its type field starts at character 10,371; Splunk extracts search-time fields from the first 10,240 characters only, so 'type=run_finished' in ZT Agent - Capture Brief missed it, no brief was stored, and the playbook noted 'no agent brief within 6 minutes' and stopped (Mode B's event was 10,247 characters with type at 9,962, just inside the limit) |
| A.2c | 19:13:40 | Fix check: capture search on raw terms, pushed to the stack | **PASS** | the next Capture Brief run stored the missed brief: run 19:00:07, ES-00015, approver 'SOC tier 2', note added; ztbrief now also reads the type from the whole event (1.0.6) |
| A.9 | 19:14:33 | Live generator page: Reset; Settings › Response mode: Local (one click) | **PASS** | page: 'plan idle, reset stamped · released none · cancelled 0' (no quarantine in this Mode A attempt); then now {response_mode: local, agent_mode: mcp, automation_rule: off} |

## Run 5

2026-09-24 19:15:38 to 19:47:24 UTC. 61 steps: 57 passed, 1 failed, 0 blocked, 3 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 19:15:38 | Live generator (launchd) and stack versions | **PASS** | owner live:MYEACK-M-P9QJ:40412 holds the lease (age 2s), 482 ticks; page shows stack app 1.0.5; stack apps {'zt_incident_demo': '1.0.5', 'DA-ESS-zt_incident_demo': '1.0.5'} |
| 1.1 | 19:15:41 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "4", "plan_status": "idle", "quarantine_policies": "none", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.2 | 19:15:42 | make emulator-status | **PASS** | local  : HTTP 200 public : https://zt-k8s.yeackbot.com -> HTTP 200 {"major": "1", "minor": "31", "gitVersion": "v1.31.2", "platform": "linux/amd64" |
| 1.3 | 19:16:16 | Live generator page: Reset (two clicks) | **PASS** | reset stamped 19:15:49, a few seconds after the second click; page: 'plan idle, reset stamped · released none · cancelled 0' |
| 1.4 | 19:16:18 | Posture before-state (rollup) | **PASS** | identities 1285, coverage 85.3% (58 of 68), unprotected 10, audit flows 2552, enforcement 32 (kernel 26, DPU 2, switch 4) |
| 1.5 | 19:17:15 | Splunk Web (built-in browser): Zero Trust Incident home | **PASS** | cards: 85.3 protected-path coverage · 11 incidents fired, last 24h · 0 pending approvals; scoreboard 1,285 / 85.3 / 10 / 3 finding groups / 34 enforcements verified (run 4's stopped Mode A left the runner's path in audit) |
| 1.6 | 19:17:15 | Splunk Web: Zero Trust Fabric Posture before the fire | **PASS** | KPIs as the rollup: 1,285 / 85.3% 'target 95%' / 10 / 32 (kernel 26 · DPU 2 · switch 4); verdict chart 'No incident since the last reset'; panel 'Enforcement Audit Trail' |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 19:17:33 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T19:17:20.224Z · attempts every 30s' |
| 2.2 | 19:17:35 | Search 1: hubble AUDIT flows from build-farm/ci-runner | **PASS** | 19:17:20.253 checkpoint-store-1:9000, 48213 -> 30719, checkpoint-store-ingress-allowlist (audit), owner platform-build |
| 2.3 | 19:17:36 | Search 2: processConnect process_name=curl | **PASS** | 19:17:20.224 /usr/bin/curl from /bin/sh -c ./scripts/postbuild.sh on bf-node-03 -> checkpoint-store-1 (0/ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors) |
| 2.4 | 19:17:36 | Compare _time of the first Tetragon connect and the first Hubble AUDIT flow | **PASS** | connect 19:17:20.224, AUDIT 19:17:20.253: 29 ms apart |
| 2.5 | 19:17:39 | Context: ci:job:event pod="ci-runner-7d9f8-xk2lq" (last 15 min); zt_node_fabric bf-node-03 | **PASS** | jobs on the pod: 1 (88213) package/post-build MR 4417 by contractor-dev-17; fabric dc2-leaf-205 Eth1/12 |
| 2.3b | 19:18:41 | Splunk Web: Search 2 over the last 10 minutes | **INFO** | Events (13): the runner's curl connects to checkpoint-store-1, this fire's plus the unquarantined retries of run 4's stopped Mode A attempt (every 30 s until its reset at 19:13); a presenter who searches since the fire sees this incident only |
| 2.6 | 19:18:43 | Rerun search 1 (attempt count) | **PASS** | 3 AUDIT flows since the fire, one per 30 s attempt (84 s after the fire) |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 19:19:22 | Risk events for build-farm/ci-runner since the fire | **PASS** | 19:18:09 ZT - Unapproved Program Connected to Protected AI Data Store +40.0; 19:18:09 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 (total 90) |
| 3.2 | 19:19:30 | Run the three drilldowns of the finding rule ($zt_workload$ = build-farm/ci-runner) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 112; Tetragon events for build-farm/ci-runner: 127; CI jobs on build-farm/ci-runner pods: 4 |
| 3.1 | 19:20:09 | Splunk Web: ES Analyst Queue | **PASS** | top row 'Unprotected path: build-farm/ci-runner reached a protected AI data store', entity build-farm/ci-runner, 2 intermediate findings, score 90, New, urgency High; notable 19:19:07 (T0+1m47s), threat objects /usr/bin/curl and ai-train/checkpoint-store, MITRE T1059.004 and T1530; the reused group carries run 4's investigation number ES-00015 until this run's brief opens a new one |
| 3.3 | 19:20:38 | Agent run history (ZTFlowInvestigator) | **PASS** | 5 tool calls: zt_finding_context > zt_flow_evidence > zt_process_evidence > zt_ci_job_context > zt_workload_server_context; run 60 s |
| 3.4 | 19:20:38 | Read the brief | **PASS** | true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommends zt-quarantine-ci-runner-88213 at the kernel; approver_labels ["SOC tier 2"]; missing facts: none |
| 3.5 | 19:22:16 | ES investigation ES-00016 notes | **FAIL** | [('Quarantine not requested', False), ('ZTFlowInvestigator brief', True), ('Quarantine requested', False)]; brief KV approver_labels 'SOC tier 2' |
| 3.5b | 19:25:47 | Notes on ES-00016 | **INFO** | the first note is 'Quarantine not requested' from 19:05 UTC, written by the SOAR playbook in run 4's stopped Mode A attempt onto the finding group itself (no investigation existed); ES reuses that finding group for every run on build-farm/ci-runner, so the note reappears in each new investigation; playbook fixed to keep such notes on the SOAR container (imported as 250); the existing note must be removed in ES by the user |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 19:22:16 | Pending request (Enforcement Approvals data) | **PASS** | ZTR-20260924-0031 pending, ES-00016, action 'CNP zt-quarantine-ci-runner-88213', approvers 'SOC tier 2', requested 19:22:01 |
| 4.2 | 19:22:16 | The request's policy YAML | **PASS** | zt-quarantine-ci-runner-88213, endpointSelector zt-quarantine: "88213", egressDeny/ingressDeny all |
| 4.0 | 19:25:47 | Splunk Web: Enforcement Approvals with the request pending | **PASS** | ZTR-20260924-0031 listed as pending (ES-00016, CNP zt-quarantine-ci-runner-88213, SOC tier 2) and in the request history |
| 4.3 | 19:25:56 | Approve as a.patel (NetOps) through the approvals endpoint | **PASS** | HTTP 403: {"message": "a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)", "request_id": "Z; refusal audited: {'approved_by_label': 'a.patel (NetOps)', 'comment': 'a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)'} |
| 4.4 | 19:26:05 | Approve as j.chen (SOC tier 2) through POST /services/zt_incident_demo/approvals | **PASS** | HTTP 200 in 9.8 s: {"message": "request ZTR-20260924-0031 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0031", "status": "a |
| 4.5 | 19:26:16 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 19:25:57 patch pods/ci-runner-7d9f8-xk2lq 200; 19:25:58 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 19:29:26 | First retry after the approval | **PASS** | 19:26:20.231 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 24 s) |
| 5.1 | 19:29:26 | Request status after the first DROPPED | **PASS** | ZTR-20260924-0031 verified 37 s after apply |
| 5.2 | 19:29:28 | ES investigation ES-00016 after verification | **PASS** | status 4 (Resolved), True Positive - Suspicious Activity |
| 5.3 | 19:29:30 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED; job failed at 19:29:05 with script_failure |
| 5.4 | 19:31:29 | Incident Timeline data (selector's newest incident, journey grid) | **PASS** | selector '2026-09-24 19:16:53 UTC · CI job 88213 · MR !4417'; grid 12/12 ticked (1:19:17:20 2:19:17:20 3:19:17:26 4:19:18:09 5:19:19:07 6:19:20:18 7:19:26:00 8:19:25:58 9:19:25:57 10:19:26:20 11:19:27:00 12:19:26:37) |
| 5.4b | 19:31:33 | Incident Timeline: Decide card | **PASS** | Risk events 19:18:09 → 19:18:09 · 2 signals · 90.0 risk on build-farm/ci-runner / Finding group ES-00016 19:19:07 · risk 90 from 2 detections, over the threshold of 80 / Agent brief 19:20:18 · true positive (high) · recommends zt-quarantine-ci-runner-88213 at the kernel, approver SOC tier 2 |
| 5.5 | 19:31:35 | Zero Trust Fabric Posture after the quarantine (KPI search) | **PASS** | identities 1285, coverage 86.8%, unprotected 9, enforcement 33 (kernel 27 · DPU 2 · switch 4); before-state 1285 / 85.3% / 10 / 32 |
| 5.6 | 19:31:37 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 | **PASS** | AUDIT 42 then DROPPED 6 in the last 30 minutes |
| 5.7 | 19:31:38 | Enforcement Audit Trail, first row | **PASS** | 2026-09-24 19:26:37 \| ES-00016 \| CNP zt-quarantine-ci-runner-88213 \| kernel \| j.chen (SOC tier 2) \| verified |
| 5.5b | 19:32:21 | Splunk Web: Zero Trust Fabric Posture after the quarantine | **PASS** | coverage 'up from 85.3% · target 95%', unprotected 'down from 10', audit trail lists ES-00016 |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 19:32:25 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.1 | 19:32:57 | Live generator page › Settings › Response mode: SOAR (one click); Dashboard › Fire the incident | **PASS** | page: now {response_mode: soar, agent_mode: mcp, automation_rule: on}; 'incident started at 2026-09-24T19:32:42.969Z' |
| A.2 | 19:36:52 | ES finding and automation rule (Mode A) | **PASS** | finding 19:34:09 (entity build-farm/ci-runner); playbook run 570 on container 1067 'Unprotected path: build-farm/ci-runner reached a protected AI data store' started 19:34:26; brief 19:35:41 (ES-00017); local requests: 0 |
| A.3 | 19:36:53 | SOAR prompt ask_approval (role SOC tier 2) | **PASS** | 'Quarantine request ZTR-20260924-0032 for ES-00017: build-farm/ci-runner reached ai-train/checkpoint-store (crown-jewel). Agent brief: true positive, high confidence. Pod ci-runner-7d9f8-xk2lq executed /usr/bin/curl to download 4 model shard files from checkpoint-store.ai-train.svc:9000/ckpt/llm-7712/step-184000/ between 19:32:42' |
| A.4 | 19:36:54 | Answer the prompt as j.chen: Approve with a comment (POST /rest/approval/9) | **PASS** | status approved, responses ['Approve', 'Contractor merge request; not approved for checkpoint access'] |
| A.5 | 19:40:14 | Playbook applies the quarantine | **PASS** | 19:37:00 patch pods/ci-runner-7d9f8-xk2lq 200; 19:37:05 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| A.6 | 19:40:17 | Enforcement audit trail (Mode A) | **PASS** | requested 19:36:31, approved 19:36:54, applied 19:37:07, verified 19:37:42; executed_by soar, playbook run 570, j.chen (SOC tier 2), ES-00017, ZTR-20260924-0032, 'CNP zt-quarantine-ci-runner-88213' |
| A.7 | 19:40:18 | ES investigation of this run after the playbook | **PASS** | ES-00017 status 4, True Positive - Suspicious Activity |
| A.8 | 19:40:21 | Runner retries and CI job outcome (Mode A) | **PASS** | 6 DROPPED; job failed at 19:39:57 with script_failure |
| A.9 | 19:41:12 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Live generator triggers

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| T.1 | 19:43:07 | Triggers › Audit-mode flow: data-eng/spark-driver -> ai-train/checkpoint-store | **PASS** | page 'audit-mode connection sent (2 events)'; risk: 19:42:06 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 |
| T.2 | 19:43:07 | Triggers › Unapproved program: observability/log-shipper, /usr/bin/curl | **PASS** | page 'unapproved program connect sent (2 events)'; risk: 19:42:07 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 |
| T.4 | 19:43:11 | Triggers › Nexus Live Protect | **PASS** | page 'Live Protect event sent (1 events)'; indexed {"t": "19:41:38", "sourcetype": "cisco:nexus:liveprotect", "switch": "dc2-leaf-201", "advisory_id": "cisco-sa-nxos-nxapi-rce-9pwbe", "status": "protected"} |
| T.5 | 19:43:11 | Triggers › Nexus configuration change | **PASS** | page 'Nexus config change sent (1 events)'; indexed {"t": "19:41:39", "sourcetype": "cisco:nexus:config", "device": "dc2-leaf-201", "status": "success", "user": "netops-cli", "change": "interface Eth1/12 description zt-live"} |
| T.6 | 19:43:13 | Triggers › Enforcement action (kernel, platform/jump-host, j.chen) | **PASS** | ZTR-20260924-0033 ['applied', 'approved', 'requested', 'verified'] 19:39:18-19:41:38 platform/jump-host j.chen (SOC tier 2) |
| T.6b | 19:43:25 | T.6 first check | **INFO** | the first T.6 check returned nothing because my query named a field 'by' (a search keyword); the corrected query found the four states; not an app defect |
| T.3a | 19:43:26 | Triggers › Path attack: ml-notebooks/jupyter -> ai-train/checkpoint-store | **PASS** | page 'attack started (4 events) · attempts every 30s'; attack jupyter-1790278910 started 19:41:50 |
| T.3b | 19:43:29 | Path attack detected | **PASS** | risk 19:42:06 +50.0; 19:42:07 +40.0; finding 19:43:11 risk 90 from 2 sources |
| T.3c | 19:45:22 | Agent brief for the attack | **PASS** | brief 19:44:41, ES-00018, job_id '', true_positive (high), recommends zt-quarantine-jupyter-75e4a-11141 at the kernel, approver 'SOC tier 2' |
| T.3d | 19:46:11 | Quarantine request for the attack (scheduled search) | **PASS** | ZTR-20260924-0034 pending 19:46:02, ES-00018, action 'CNP zt-quarantine-jupyter-75e4a-11141' |
| T.3e | 19:46:16 | Approve the attack's request as j.chen (POST /services/zt_incident_demo/approvals) | **PASS** | HTTP 200 in 4.6 s: {"message": "request ZTR-20260924-0034 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0034", "s |
| T.3f | 19:46:41 | Attack retries after the approval | **PASS** | kube: 19:46:12 patch pods/jupyter-75e4a-11141 200; 19:46:14 create ciliumnetworkpolicies/zt-quarantine-jupyter-75e4a-11141 201; drops from 19:46:20 by zt-quarantine-jupyter-75e4a-11141, identity 25317; verified 15 s after apply |
| T.3g | 19:46:42 | ES investigation of the attack | **PASS** | ES-00018 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' status 4, True Positive - Suspicious Activity |
| T.7 | 19:47:24 | Live generator page: Reset (two clicks) after the triggers | **PASS** | reset stamped 19:46:58; page lists 'released CNP zt-quarantine-jupyter-75e4a-11141 (k.osei)'; attack jupyter-1790278910 stopped (10 attempts, 2 dropped); no quarantine left in zt_policy_state |

## Run 6

2026-09-24 19:47:44 to 20:18:04 UTC. 61 steps: 58 passed, 1 failed, 0 blocked, 2 notes.

### Before the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 1.0 | 19:47:44 | Live generator (launchd) and stack versions | **PASS** | owner live:MYEACK-M-P9QJ:40412 holds the lease (age 3s), 925 ticks; page shows stack app 1.0.5; stack apps {'zt_incident_demo': '1.0.5', 'DA-ESS-zt_incident_demo': '1.0.5'} |
| 1.1 | 19:47:47 | Search: \| ztdemo action=status | **PASS** | {"backfill_done": "1", "checkpoint_age_s": "2", "plan_status": "idle", "quarantine_policies": "none", "speed": "fast", "response_mode": "local", "agent_mode": "mcp"} |
| 1.2 | 19:47:48 | make emulator-status | **PASS** | local  : HTTP 200 public : https://zt-k8s.yeackbot.com -> HTTP 200 {"major": "1", "minor": "31", "gitVersion": "v1.31.2", "platform": "linux/amd64" |
| 1.3 | 19:48:15 | Live generator page: Reset (two clicks) | **PASS** | reset stamped 19:47:54; page: 'plan idle, reset stamped · released none · cancelled 0' |
| 1.4 | 19:48:18 | Posture before-state (rollup) | **PASS** | identities 1285, coverage 86.8% (59 of 68), unprotected 9, audit flows 2589, enforcement 36 (kernel 30, DPU 2, switch 4) |
| 1.5 | 19:49:02 | Splunk Web (built-in browser): Zero Trust Incident home | **PASS** | cards: 86.8 protected-path coverage · 13 incidents fired, last 24h · 0 pending approvals; scoreboard 1,285 / 86.8 / 9 / 3 finding groups / 38 enforcements verified |
| 1.6 | 19:49:02 | Splunk Web: Zero Trust Fabric Posture before the fire | **PASS** | KPIs as the rollup: 1,285 / 86.8% 'up from 85.3% · target 95%' / 9 / 36 (kernel 30 · DPU 2 · switch 4); verdict chart 'No incident since the last reset' |

### Step 2: two signals in Splunk

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 2.1 | 19:49:23 | Live generator page: Fire the incident | **PASS** | page: 'incident started at 2026-09-24T19:49:08.677Z · attempts every 30s' |
| 2.2 | 19:49:25 | Search 1: hubble AUDIT flows from build-farm/ci-runner | **PASS** | 19:49:08.706 checkpoint-store-1:9000, 48213 -> 30719, checkpoint-store-ingress-allowlist (audit), owner platform-build |
| 2.3 | 19:49:27 | Search 2: processConnect process_name=curl | **PASS** | 19:49:08.677 /usr/bin/curl from /bin/sh -c ./scripts/postbuild.sh on bf-node-03 -> checkpoint-store-1 (0/ckpt/llm-7712/step-184000/model-00001-of-00008.safetensors) |
| 2.4 | 19:49:27 | Compare _time of the first Tetragon connect and the first Hubble AUDIT flow | **PASS** | connect 19:49:08.677, AUDIT 19:49:08.706: 29 ms apart |
| 2.5 | 19:49:30 | Context: ci:job:event pod="ci-runner-7d9f8-xk2lq" (last 15 min); zt_node_fabric bf-node-03 | **PASS** | jobs on the pod: 1 (88213) package/post-build MR 4417 by contractor-dev-17; fabric dc2-leaf-205 Eth1/12 |
| 2.6 | 19:51:47 | Rerun search 1 (attempt count) | **PASS** | 6 AUDIT flows since the fire, one per 30 s attempt (159 s after the fire) |
| 2.6b | 19:52:01 | 2.6 first check | **INFO** | the first attempt count ran 24 s after the fire (my check started too early), before the second attempt; re-checked at 159 s: 6 AUDIT flows, one per 30 s |

### Step 3: one finding, one brief

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 3.0 | 19:51:24 | Risk events for build-farm/ci-runner since the fire | **PASS** | 19:50:14 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0; 19:50:13 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 (total 90) |
| 3.2 | 19:51:34 | Run the three drilldowns of the finding rule ($zt_workload$ = build-farm/ci-runner) | **PASS** | Raw Hubble flows for build-farm/ci-runner: 156; Tetragon events for build-farm/ci-runner: 186; CI jobs on build-farm/ci-runner pods: 7 |
| 3.1 | 19:52:53 | Splunk Web: ES Analyst Queue | **PASS** | the build-farm/ci-runner rows (entity build-farm/ci-runner, 2 intermediate findings, score 90) carry this run's finding (notable 19:51:07, T0+1m58s, risk 90 from 2 detections, severity high); ES shows the reused finding group under its latest investigation number until this run's brief opens a new one |
| 3.1c | 19:52:53 | Analyst Queue: an open investigation from run 4 | **INFO** | ES-00015 is still New/Undetermined: run 4's brief was stored late (after the capture fix), after the playbook had given up, so nothing resolved it; close it in ES or leave it |
| 3.3 | 19:52:57 | Agent run history (ZTFlowInvestigator) | **PASS** | 5 tool calls: zt_finding_context > zt_flow_evidence > zt_process_evidence > zt_ci_job_context > zt_workload_server_context; run 80 s |
| 3.4 | 19:52:57 | Read the brief | **PASS** | true_positive (high); where ci-runner-7d9f8-xk2lq on bf-node-03, dc2-leaf-205 Eth1/12; recommends zt-quarantine-ci-runner-88213 at the kernel; approver_labels ["SOC tier 2"]; missing facts: none |
| 3.5 | 19:54:21 | ES investigation ES-00019 notes | **FAIL** | this run: [('ZTFlowInvestigator brief', True), ('Quarantine requested', False)]; inherited from before the reset: [('Quarantine not requested', 1790276720.1210823)]; brief KV approver_labels 'SOC tier 2' |

### Step 4: approve the quarantine (Mode B)

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 4.1 | 19:54:21 | Pending request (Enforcement Approvals data) | **PASS** | ZTR-20260924-0035 pending, ES-00019, action 'CNP zt-quarantine-ci-runner-88213', approvers 'SOC tier 2', requested 19:54:02 |
| 4.2 | 19:54:21 | The request's policy YAML | **PASS** | zt-quarantine-ci-runner-88213, endpointSelector zt-quarantine: "88213", egressDeny/ingressDeny all |
| 4.0 | 19:54:59 | Splunk Web: Enforcement Approvals with the request pending | **PASS** | ZTR-20260924-0035 listed as pending (ES-00019, CNP zt-quarantine-ci-runner-88213, SOC tier 2) and in the request history |
| 4.3 | 19:55:11 | Approve as a.patel (NetOps) through the approvals endpoint | **PASS** | HTTP 403: {"message": "a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)", "request_id": "Z; refusal audited: {'approved_by_label': 'a.patel (NetOps)', 'comment': 'a.patel is not an approver for the kernel enforcement point (needs SOC tier 2)'} |
| 4.4 | 19:55:18 | Approve as j.chen (SOC tier 2) through POST /services/zt_incident_demo/approvals | **PASS** | HTTP 200 in 7.1 s: {"message": "request ZTR-20260924-0035 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0035", "status": "a |
| 4.5 | 19:55:29 | index=zero_trust sourcetype=kube:apiserver:audit (zt-enforcer) | **PASS** | 19:55:13 patch pods/ci-runner-7d9f8-xk2lq 200; 19:55:15 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |

### Step 5: verify and prove it

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 5.0 | 19:58:32 | First retry after the approval | **PASS** | 19:55:38.684 DROPPED (POLICY_DENY), identity 48291, egress_denied_by zt-quarantine-ci-runner-88213 (apply + 27 s) |
| 5.1 | 19:58:33 | Request status after the first DROPPED | **PASS** | ZTR-20260924-0035 verified 34 s after apply |
| 5.2 | 19:58:35 | ES investigation ES-00019 after verification | **PASS** | status 4 (Resolved), True Positive - Suspicious Activity |
| 5.3 | 19:58:37 | Runner retries and CI job 88213 outcome | **PASS** | 6 DROPPED; job failed at 19:58:23 with script_failure |
| 5.4 | 19:58:48 | Incident Timeline data (selector's newest incident, journey grid) | **PASS** | selector '2026-09-24 19:48:41 UTC · CI job 88213 · MR !4417'; grid 12/12 ticked (1:19:49:08 2:19:49:08 3:19:49:14 4:19:50:13 5:19:51:07 6:19:52:38 7:19:55:16 8:19:55:15 9:19:55:13 10:19:55:38 11:19:56:00 12:19:55:50) |
| 5.4b | 19:58:52 | Incident Timeline: Decide card | **PASS** | Risk events 19:50:13 → 19:50:14 · 2 signals · 90.0 risk on build-farm/ci-runner / Finding group ES-00019 19:51:07 · risk 90 from 2 detections, over the threshold of 80 / Agent brief 19:52:38 · true positive (high) · recommends zt-quarantine-ci-runner-88213 at the kernel, approver SOC tier 2 |
| 5.5 | 19:58:53 | Zero Trust Fabric Posture after the quarantine (KPI search) | **PASS** | identities 1285, coverage 86.8%, unprotected 9, enforcement 37 (kernel 31 · DPU 2 · switch 4); before-state 1285 / 86.8% / 9 / 36 |
| 5.6 | 19:58:55 | Verdict chart build-farm/ci-runner -> ai-train/checkpoint-store:9000 | **PASS** | AUDIT 22 then DROPPED 12 in the last 30 minutes |
| 5.7 | 19:58:57 | Enforcement Audit Trail, first row | **PASS** | 2026-09-24 19:55:50 \| ES-00019 \| CNP zt-quarantine-ci-runner-88213 \| kernel \| j.chen (SOC tier 2) \| verified |
| 5.4c | 19:59:53 | Splunk Web: Incident Timeline (built-in browser) | **PASS** | selector on '2026-09-24 19:48:41 UTC · CI job 88213 · MR !4417'; Verify card 'Verified 19:55:50 · quarantine confirmed, ES investigation resolved' |
| 5.5b | 19:59:53 | Splunk Web: Zero Trust Fabric Posture after the quarantine | **PASS** | enforcement 'kernel 31 · DPU 2 · switch 4'; audit trail lists ES-00019 |

### After the call

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| 6.1 | 20:00:21 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Mode A: the same incident through SOAR

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| A.1 | 20:00:53 | Live generator page › Settings › Response mode: SOAR (one click); Dashboard › Fire the incident | **PASS** | page: now {response_mode: soar, agent_mode: mcp, automation_rule: on}; 'incident started at 2026-09-24T20:00:38.530Z' |
| A.2 | 20:06:14 | ES finding and automation rule (Mode A) | **PASS** | finding 20:02:10 (entity build-farm/ci-runner); playbook run 597 on container 1067 'Unprotected path: build-farm/ci-runner reached a protected AI data store' started 20:02:32; brief 20:04:03 (ES-00020); local requests: 0 |
| A.3 | 20:06:15 | SOAR prompt ask_approval (role SOC tier 2) | **PASS** | 'Quarantine request ZTR-20260924-0036 for ES-00020: build-farm/ci-runner reached ai-train/checkpoint-store (crown-jewel). Agent brief: true positive, high confidence. The ci-runner pod executed /usr/bin/curl to download 4 model shard files from the checkpoint-store protected data store on port 9000, triggered by a merge request t' |
| A.4 | 20:06:16 | Answer the prompt as j.chen: Approve with a comment (POST /rest/approval/11) | **PASS** | status approved, responses ['Approve', 'Contractor merge request; not approved for checkpoint access'] |
| A.5 | 20:09:47 | Playbook applies the quarantine | **PASS** | 20:06:21 patch pods/ci-runner-7d9f8-xk2lq 200; 20:06:25 create ciliumnetworkpolicies/zt-quarantine-ci-runner-88213 201 |
| A.6 | 20:09:49 | Enforcement audit trail (Mode A) | **PASS** | requested 20:05:52, approved 20:06:16, applied 20:06:27, verified 20:07:00; executed_by soar, playbook run 597, j.chen (SOC tier 2), ES-00020, ZTR-20260924-0036, 'CNP zt-quarantine-ci-runner-88213' |
| A.7 | 20:09:51 | ES investigation of this run after the playbook | **PASS** | ES-00020 status 4, True Positive - Suspicious Activity |
| A.8 | 20:09:52 | Runner retries and CI job outcome (Mode A) | **PASS** | 6 DROPPED; job failed at 20:09:23 with script_failure |
| A.9 | 20:10:45 | Live generator page: Reset (two clicks); \| ztdemo action=status | **PASS** | released zt-quarantine-ci-runner-88213 by k.osei (platform) ('merge request reverted'); plan idle, quarantine none |

### Live generator triggers

| Step | Time (UTC) | Action | Result | Observed |
|---|---|---|---|---|
| T.1 | 20:11:36 | Triggers › Audit-mode flow: data-eng/spark-driver -> ai-train/checkpoint-store | **PASS** | page 'audit-mode connection sent (2 events)'; risk: 20:11:06 ZT - Audit-Mode Flow Into Protected AI Data Store +50.0 |
| T.2 | 20:11:36 | Triggers › Unapproved program: observability/log-shipper, /usr/bin/curl | **PASS** | page 'unapproved program connect sent (2 events)'; risk: 20:11:06 ZT - Unapproved Program Connected to Protected AI Data Store +40.0 |
| T.4 | 20:11:38 | Triggers › Nexus Live Protect | **PASS** | page 'Live Protect event sent (1 events)'; indexed {"t": "20:11:03", "sourcetype": "cisco:nexus:liveprotect", "switch": "dc2-leaf-201", "advisory_id": "cisco-sa-nxos-bgp-dos-3fzrsx", "status": "protected"} |
| T.5 | 20:11:38 | Triggers › Nexus configuration change | **PASS** | page 'Nexus config change sent (1 events)'; indexed {"t": "20:11:07", "sourcetype": "cisco:nexus:config", "device": "dc2-leaf-201", "status": "success", "user": "netops-cli", "change": "interface Eth1/12 description zt-live"} |
| T.6 | 20:11:40 | Triggers › Enforcement action (kernel, platform/jump-host, j.chen) | **PASS** | ZTR-20260924-0037 ['applied', 'approved', 'requested', 'verified'] 20:08:43-20:11:03 platform/jump-host j.chen (SOC tier 2) |
| T.3a | 20:11:40 | Triggers › Path attack: ml-notebooks/jupyter -> ai-train/checkpoint-store | **PASS** | page 'attack started (4 events) · attempts every 30s'; attack jupyter-1790280675 started 20:11:15 |
| T.3b | 20:13:29 | Path attack detected | **PASS** | risk 20:12:06 +40.0; 20:12:06 +50.0; finding 20:13:12 risk 90 from 2 sources |
| T.3c | 20:15:23 | Agent brief for the attack | **PASS** | brief 20:14:43, ES-00021, job_id '', true_positive (high), recommends zt-quarantine-jupyter-75e4a-11141 at the kernel, approver 'SOC tier 2' |
| T.3d | 20:16:12 | Quarantine request for the attack (scheduled search) | **PASS** | ZTR-20260924-0038 pending 20:16:01, ES-00021, action 'CNP zt-quarantine-jupyter-75e4a-11141' |
| T.3e | 20:16:18 | Approve the attack's request as j.chen (POST /services/zt_incident_demo/approvals) | **PASS** | HTTP 200 in 5.7 s: {"message": "request ZTR-20260924-0038 approved by j.chen (SOC tier 2)", "request_id": "ZTR-20260924-0038", "s |
| T.3f | 20:17:14 | Attack retries after the approval | **PASS** | kube: 20:16:15 create ciliumnetworkpolicies/zt-quarantine-jupyter-75e4a-11141 201; 20:16:13 patch pods/jupyter-75e4a-11141 200; drops from 20:16:45 by zt-quarantine-jupyter-75e4a-11141, identity 25317; verified 45 s after apply |
| T.3g | 20:17:15 | ES investigation of the attack | **PASS** | ES-00021 'Unprotected path: ml-notebooks/jupyter reached a protected AI data store' status 4, True Positive - Suspicious Activity |
| T.7 | 20:18:04 | Live generator page: Reset (two clicks) after the triggers | **PASS** | reset stamped 20:17:34; released zt-quarantine-jupyter-75e4a-11141 by k.osei (platform); attack jupyter-1790280675 stopped (12 attempts, 2 dropped); no quarantine left in zt_policy_state |

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
| run 2: 5.4b | Incident selector listed no incidents (dynamic options without their label/value context), so the timeline opened empty | Declared the dropdown's context; it opens on the newest incident | Incident Timeline (pushed) |
| run 2: 5.4c | Timeline took about 30 s and showed raw $ds_...$ tokens meanwhile | Grid search from 13 appended searches to 7 (15.4 s to 7.8 s, same output); cards hidden until their data arrives; notable index read directly | Incident Timeline (pushed) |
| run 2: 5.4d | Incident table listed oldest first, putting the outcome on page 5 | Newest first; dropped rows name the denying policy | Incident Timeline (pushed) |
| run 2: 3.1c | A brief capture whose window predated a reset re-keyed an old agent run as a new run (duplicate investigation ES-00007); briefs were matched to the newest ZT finding of any workload | ztbrief skips agent runs older than the reset stamp it reads and matches each brief to the newest finding of its own workload | 1.0.5 |
| run 2: 3.1d | Analyst Queue entity read ci-runner.build-farm.svc (asset DNS name) next to the title build-farm/ci-runner | Workload rows of the ES asset list carry no DNS name, so ES names the entity by the workload | DA-ESS lookup (pushed), 1.0.5 |
| run 2: 1.6b, 1.5b | Posture audit trail titled '(SOAR)' though it lists local approvals; routine rows read 'playbook (policy) (policy)'; home label 'Findings, last 24h' counted finding groups | Panel and description reworded; approver label adds the role only once (search time, fixes existing events); 'Finding groups, last 24h', 'incidents fired, last 24h' | dashboards and props (pushed), 1.0.5 |
| run 2: 4.6 | Request history showed 1970-01-01 for times not reached yet | Blank until applied or verified | Enforcement Approvals (pushed) |
| run 2: A.11, restart | Live generator logged client disconnects as tracebacks; a restart left the old process's lease in place for up to 45 s | Disconnects are quiet; the lease is handed back first on shutdown and a dead local holder is cleared at start | live generator |
| run 3: 3.4, 5.4b | The brief returned the approver as a slug (soc-tier-2), so the Incident Timeline's Decide card read 'approver soc-tier-2'; the request itself took its approvers from the approval matrix and was right | Agent prompt asks for the matrix labels verbatim; the Decide card maps slugs to the matrix label; ztbrief normalizes labels when it stores a brief | agent prompt and Incident Timeline (pushed), 1.0.6 |
| run 4: 1.0 | The live generator page showed the stack app version read at its start (1.0.4) after 1.0.5 had been installed | The engine reads the version again every five minutes and resumes the search head input if an upgrade makes it lease-aware | live generator |
| run 4: A.2 | Mode A stopped: the agent's brief was never captured, because a long agent run puts the type field of its _audit event past the 10,240 characters Splunk extracts at search time, so 'type=run_finished' matched nothing; the playbook waited six minutes and stopped without a request | ZT Agent - Capture Brief matches the raw terms ZTFlowInvestigator and run_finished; ztbrief reads the type and agent from the whole event and skips anything else; smoke does the same | saved search (pushed), 1.0.6 |

