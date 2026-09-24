# Demo script: one incident, end to end

The live section of the deck, in six parts, at fast cadence (every ZT scheduled search runs every minute). One line to say per click. Dashboard and panel names match the installed dashboards (Zero Trust Fabric Posture, Incident Timeline, Enforcement Approvals).

## Timings at fast cadence

| When | What you will see |
|---|---|
| T0 | `\| ztdemo action=fire`; the deck's two searches return the canonical events within 10 seconds |
| T0 + 30 s, 60 s, … | A new `curl` attempt every 30 seconds: Tetragon exec and connect, Hubble egress FORWARDED and ingress AUDIT |
| T0 + 1 to 2 min | Two risk events on `build-farm/ci-runner`: 50 (audit-mode flow) and 40 (unapproved program) |
| T0 + 2 to 3 min | One finding group, `Unprotected path: build-farm/ci-runner reached a protected AI data store`, risk 90, in the Analyst Queue |
| Finding + 1 to 5 min | The agent runs (five tool calls); the brief is captured within a minute of the response and added as a note on the investigation |
| Brief + up to 1 min | Mode B: a pending request on Enforcement Approvals. Mode A: the SOAR playbook (started by the automation rule, dispatch every 10 s) reads the brief and prompts the SOC tier 2 role |
| Your click | Approval; the pod label and the policy are applied about 2 seconds later |
| Apply + 20 to 90 s | The next attempt is DROPPED; `verified`; the investigation is Resolved, True Positive - Suspicious Activity |
| 6th DROPPED + 15 s (about apply + 3 min) | CI job 88213 fails (`script_failure`) |
| Within a minute of each change | The posture rollup updates the KPIs |

About ten minutes from fire to the final posture. If you need to talk longer, the runner keeps trying every 30 seconds until a quarantine arrives (45 minutes at most).

## 1. Before the call

- Start the live generator on the presenter Mac (`make live-run`, then open `http://127.0.0.1:8890`). It takes over the streaming from the search head while it runs, shows every event on a ten-minute timeline, and has the Fire and Reset buttons plus triggers for single events (audit-mode flow, unapproved program, a path attack for any workload, Live Protect, a Nexus change, an enforcement action). Stop it after the call (`make live-stop`) so the search head streams again.

1. `make status` (or `| ztdemo action=status` in the Zero Trust Incident app): `backfill_done` true, checkpoint age under a minute, `plan_status` idle, no quarantine, `speed` fast, `response_mode` and `agent_mode` as you want them. If a practice run is on file, `| ztdemo action=reset` was run and the before-state of the posture shows that run for 24 hours (say "up from 87.7%" becomes the previous run's number).
2. `make emulator-status`: the emulator answers `/version` locally and at `https://zt-k8s.yeackbot.com`.
3. `make fast` if unsure of the cadence; `make mode-soar` or `make mode-local` (or the Local and SOAR buttons on the live generator's Settings page), which also switch the Enterprise Security automation rule on for SOAR and off for Local; `make agent-mcp`.
4. Open the Zero Trust Fabric Posture dashboard (Zero Trust Incident › Zero Trust Fabric Posture) and note the before-state: identities 1,283, coverage 87.7% (57 of 65), unprotected paths 8, audit-mode flows 2,306, enforcement actions 16 (kernel 10 · DPU 2 · switch 4) on a fresh install.
5. Sign in as `j.chen` in a private browser window (Mode A: SOAR; Mode B: Splunk Web, Enforcement Approvals).
6. Open the agent's page in the AI Toolkit (Agent Launchpad › `ZTFlowInvestigator`) and the ES Analyst Queue.
7. Have the two searches ready in the search bar (they are also in the deck).

## 2. Step 2: two signals in Splunk (slide "Step 2 in Splunk")

Fire from the live generator page (the CI runner incident dots turn red on the timeline and the "incident in Splunk" panel fills in step by step) or from Search with `| ztdemo action=fire`. The Incident Timeline dashboard selects the newest incident by default; older runs stay selectable.

1. Run `| ztdemo action=fire`. Say: "The build job just ran its post-build script; here is what landed in Splunk in the same second."
2. Run the first search:

   `index=zero_trust sourcetype=cilium:hubble:flow verdict=AUDIT src_workload="build-farm/ci-runner"`

   Point at `dest_pod` `checkpoint-store-1`, `dest_port` 9000, identities 48213 → 30719, `allowlist_policy` `checkpoint-store-ingress-allowlist`, `allowlist_mode` `audit`. Say: "Hubble at the store saw the connection; the allowlist would have denied it, but it is in audit mode, so it went through."
3. Run the second search:

   `index=zero_trust sourcetype=cisco:isovalent:processConnect process_name=curl`

   Point at `process_args` (the checkpoint URL under `/ckpt/llm-7712/`), `parent_process` `/bin/sh -c ./scripts/postbuild.sh`, `src_pod` `ci-runner-7d9f8-xk2lq`, `node` `bf-node-03`. Say: "Tetragon on the runner's node saw which program made it: curl, started by the post-build script."
4. Expand one event of each and compare `_time`: same pod, same destination, same second (14:52:07.402 and .431 in the story; live, T0 and T0 + 29 ms). Say: "Two sensors, one connection, two independent proofs."
5. Then the context, one click each: `src_owner` `platform-build` on the flow; `index=zero_trust sourcetype=ci:job:event pod="ci-runner-7d9f8-xk2lq"` for job 88213 (`package`, `post-build`, merge request `!4417` by `contractor-dev-17`, `running`); `| inputlookup zt_node_fabric where node="bf-node-03"` for `dc2-leaf-205 Eth1/12`. Say: "Owner, CI job, server: everything the analyst would otherwise ask three teams for."
6. While talking, attempts keep arriving every 30 seconds (rerun the first search to show the count growing).

## 3. Step 3: one finding, one brief (slides "Two signals, one finding" and "The agent pulls the evidence together")

1. Open Enterprise Security › Analyst Queue (about 2 to 3 minutes after the fire). Say: "Two detections added risk to the same workload; the third opened one finding when the total crossed 80."
2. Open the finding group `Unprotected path: build-farm/ci-runner reached a protected AI data store`: risk 90, severity high, domain network. Point at the two contributing detections (`ZT - Audit-Mode Flow Into Protected AI Data Store`, +50, and `ZT - Unapproved Program Connected to Protected AI Data Store`, +40), the threat objects `ai-train/checkpoint-store` and `/usr/bin/curl`, MITRE ATT&CK T1530 and T1059.004. Say: "One finding, not two alerts; the risk objects are the workload, not an IP."
3. Click a drilldown ("Raw Hubble flows for build-farm/ci-runner", "Tetragon events for build-farm/ci-runner", "CI jobs on build-farm/ci-runner pods"). Say: "Every claim in the finding drills to the raw events."
4. Switch to the AI Toolkit, Agent Launchpad, `ZTFlowInvestigator`, run history: the five tool calls in order (`zt_finding_context`, then `zt_flow_evidence`, `zt_process_evidence`, `zt_ci_job_context`, `zt_workload_server_context`). Say: "The agent may only use these five read-only tools; every sentence of its brief comes from one of them."
5. Back in ES, open the investigation's notes: "ZTFlowInvestigator brief" (AI-generated). Read the six lines: disposition true positive, high confidence; what happened (job 88213, `scripts/postbuild.sh`, `!4417`, `contractor-dev-17`, curl, training job 7712); why it matters (crown-jewel store, allowlist in audit mode); where (pod `ci-runner-7d9f8-xk2lq` on `bf-node-03`, `dc2-leaf-205 Eth1/12`); recommendation (quarantine at the kernel, `zt-quarantine-ci-runner-88213`, approver SOC tier 2); follow-up. Say: "The wording is the model's; the facts are the tools'. It recommends the narrowest action and names who must approve it. It never acts."

## 4. Step 4: approve the quarantine

Mode A (SOAR):

1. In the private window, signed in to SOAR as `j.chen`, open the pending prompt from playbook `zt_quarantine_workload`. Say: "The playbook waited for the brief, built the policy and asked the SOC tier 2 role."
2. Read the message: the finding, the workload and store, the brief's disposition, the recommended action, the blast radius (one pod), and the policy YAML (`endpointSelector zt-quarantine: "88213"`, `egressDeny` and `ingressDeny` to all). Say: "Approving means: label this one pod, create this one policy; nothing else changes."
3. Add a comment and click Approve. Say: "Two seconds later the API server has the label and the policy; the audit record names the service account, not a person with cluster-admin."

Mode B (local approvals):

1. In the private window, signed in to Splunk Web as `j.chen`, open Zero Trust Incident › Enforcement Approvals. The pending request shows the finding, workload, pod, enforcement point kernel, the action, approver needed SOC tier 2 and the request time.
2. Select it; read the brief and the policy YAML. Say the same line as above.
3. Type a comment and click Approve (it runs `| ztsoar action=approve request_id=… comment="…"`). Say: "The approval runs with system privileges after checking my role; an analyst without SOC tier 2 is refused and the refusal is audited."

Either mode: `index=zero_trust sourcetype=kube:apiserver:audit` now shows the `patch` (200) and the `create` (201) by `system:serviceaccount:soar:zt-enforcer`.

## 5. Step 5: verify and prove it

1. Open Zero Trust Incident › Incident Timeline (it opens on the newest incident; the cards appear within about 15 seconds). Walk the five step cards left to right: Connect (job start, first connection), Observe (first AUDIT flow and Tetragon event, both identities, the program), Decide (the two risk events, the finding ID and risk, the brief's time and recommendation), Enforce (who approved, when, the policy applied), Verify (the first DROPPED flow, `verified`, posture before and after). Say: "Every cell has a timestamp and drills to its evidence; this is the audit story for the incident review."
2. Point at the journey grid (Workloads, Cisco Isovalent, Splunk platform, Enterprise Security, Agent Launchpad, SOAR and people × Connect, Observe, Decide, Enforce, Verify) and at the "Getting data in" tiles (Hubble, Tetragon, Nexus switch data, Live Protect: events in 24 hours and the age of the last event). Say: "Four data sources, all over HTTP Event Collector and the Cisco add-ons."
3. Scroll to the incident event table (newest first): the DROPPED attempts with `egress_denied_by` `zt-quarantine-ci-runner-88213` and source identity 48291; the `verified` audit row; a little later the CI job `failed` with `script_failure`. Say: "The runner tried six more times and got nothing; the job failed in the pipeline, which is where the developer finds out."
4. Open Zero Trust Incident › Zero Trust Fabric Posture. Read the KPIs: Protected-Path Coverage 87.9%, "up from 86.4%"; Unprotected Paths 8, "down from 9"; Workload Identities 1,284; Enforcement Actions (24h) 17 (kernel 11 · DPU 2 · switch 4). Say: "During the incident the fabric had one more unprotected path; now it has one more enforced path and one more kernel action."
5. Point at the verdict chart "build-farm/ci-runner → ai-train/checkpoint-store:9000, flows by verdict": AUDIT columns, then DROPPED. Say: "This is the verdict flip: the same path, the same program, now denied at the source node."
6. Point at the first row of the Enforcement Audit Trail: the finding, `CNP zt-quarantine-ci-runner-88213`, `kernel`, `j.chen (SOC tier 2)`, `verified` in green. Say: "Who approved what, when, and that it worked, in the same index as the flows."
7. Close on the coverage line: 87.7% before, 86.4% during, 87.9% after, target 95%. Say: "Coverage is a number you can report, and every point of it is one closed path."

## 6. After the call

1. Click Reset twice on the live generator page (or run `| ztdemo action=reset`, or `make reset`). It releases the quarantine through the emulator (audit user `k.osei`), writes a `released` audit event ("merge request reverted"), cancels open requests and sets the plan to idle. The next fire uses the same canonical IDs; the detections and searches ignore everything before the reset.
2. `| ztdemo action=status` to confirm `plan_status` idle and no quarantine.
3. The posture's before-state will show this run for 24 hours; for the absolute numbers of a fresh install, `make reset-hard` (asks first, empties `zero_trust` and `zt_summary` and backfills).
4. `make normal` if the stack should not run every minute until the next call.
