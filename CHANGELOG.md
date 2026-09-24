# Changelog

## 1.0.8 (2026-09-24)

- Nexus Dashboard data in the Cisco DC Networking app's schema: `cisco:dc:nd:advisories` (16 a day: four advisories for the NX-OS components that Live Protect shields, polled every six hours) and `cisco:dc:nd:anomalies` (10 a day: five anomalies raised and cleared, matching the day's Nexus changes). With the DC Networking app installed, its props map the severity and the switch list, and Secure Networking Essentials shows them: Fabric Operations › Critical Security Advisories, Infrastructure Posture › Data Center Signals and Critical Advisories. The live generator page lists the two sourcetypes.
- `ZT Agent - Recover Brief` (every minute): when the AI Toolkit fails to write the agent's result to `_audit` (its `mltk/hec_operations` handler answers HTTP 500 now and then), no brief arrives and the demo stops at the brief step. The search runs the agent once more inline, at most twice per finding group, when a result write failed after the run started or no brief arrived seven minutes after the finding, and stores the brief from the command's output with `ztbrief`.
- Zero Trust Fabric Posture: the verdict chart starts at the last reset (or 30 minutes ago, whichever is later), so it is empty until the incident starts, as its placeholder says.
- `props.conf`: the Tetragon block stays with the Cisco Security Cloud App installed; the comment says what that app adds and what it does not.
- SOAR playbook (imported, not part of the app): waits up to 10 minutes for the brief, which covers a recovered one.

## Docs and collateral: handoff pass (2026-09-24, no app change)

- The handoff checklist of the collateral review was worked through: Secure Networking Essentials wording after 1.0.7 (Runtime Detections 2, the fields as calculated fields, the noise counts), the fact corrections F1 to F5 in both decks, the talk track, the co-sell and One Incident PDFs and the review, a slide 19 posture image rendered by Splunk, and a review section on other dCloud demos and Isovalent labs.
- `sync_collateral.py` replaces a picture only when it changed; `verify_collateral.py` checks the collateral against the stack and the checklist.
- After the Cisco DC Networking and Cisco Security Cloud apps were installed: the talk track (§3, Beat 5, the data-path answer, §7 and §8), the demo script and the review say what those apps show and why the demo app keeps its Tetragon parsing.

## Docs and collateral (2026-09-24, no app change)

- `docs/collateral/collateral.yaml` follows the 22-slide One Incident deck (initiatives slide at 3, "What ships, and what we build for you" at 13, live steps at 14 to 19) and the ten-beat talk track (beats 5 to 8 kept here, §3 "Before the lab phase" column added).
- `sync_collateral.py` keeps the bold lead-in on Who and Say lines and plain bullets, adds table rows as copies of a styled row, and can add missing §3 items.
- `docs/demo_script.md`: Secure Networking Essentials pre-call item and a "Before the fire: what ships" section; the data-sources line no longer claims the Cisco add-ons are installed.
- `docs/collateral/pdf/`: HTML sources and `render_pdfs.py` for the three collateral PDFs.
- Stack: Splunk Secure Networking Essentials setup completed (Searchbase installed; only `index_security` changed, to `zero_trust`).

## 1.0.7 (2026-09-24)

- Splunk Security Content: `pod_name`, `pod_namespace` and `pod_image_name` on `cisco:isovalent:processExec` and `cisco:isovalent:processConnect`, the names its ten Cisco Isovalent detections read. The detections stay disabled: over four hours of this estate, Non Allowlisted Image Use returns 2,413 rows, Shell Execution 402, Late Process Execution 293 and Access To Cloud Metadata Service 68, so they need allowlists and filters before they run next to the zero trust detections.
- Secure Networking Essentials: a Tetragon SIGKILL (`cisco:isovalent`, `process_kprobe.action=KPROBE_ACTION_SIGKILL`) gets `event_sourcetype=cisco:isovalent:alert`, so the Runtime Detections card lists the day's runtime policy alerts (`block-reverse-shell`, `block-unapproved-binaries`) instead of zero. No change to the data or its daily counts.
- SOAR playbook (imported, not part of the app): notes go only on this run's ES investigation. With no investigation, the message goes to the SOAR container, because ES reuses the finding group for every run on the same workload and a note on the group reappears in every later investigation.

## 1.0.6 (2026-09-24)

- Agent brief capture: `ZT Agent - Capture Brief` matches the raw terms `ZTFlowInvestigator` and `run_finished`, and `ztbrief` reads the run type and agent from the whole event. A long agent run put the `type` field past the 10,240 characters Splunk extracts at search time, so the brief was never stored and Mode A stopped before the approval.
- `ztbrief` writes the approval matrix labels as the matrix does (`SOC tier 2`, `NetOps`) when the agent returns them as slugs (`soc-tier-2`), for the flat and the nested brief shapes. The agent prompt now asks for the labels verbatim, and the Incident Timeline maps any slug already stored.
- `DA-ESS-zt_incident_demo` is unchanged and stays at 1.0.5.

## 1.0.5 (2026-09-24)

- Incident Timeline: the incident selector declares its option context, so it lists every incident and opens on the newest; the journey grid runs as seven appended searches instead of thirteen (about 15 s to 8 s); cards stay hidden until their data arrives; the incident table lists the newest first and dropped rows name the denying policy.
- `ztbrief` skips agent runs older than the reset stamp and matches each brief to the newest finding for its own workload.
- ES asset list: workload rows carry no DNS name, so the Analyst Queue names the entity by the workload (DA-ESS 1.0.5).
- Posture and home wording: the audit trail panel is no longer titled for SOAR only, the approver label adds the role once, and the home card counts finding groups.
- Enforcement Approvals: request history leaves applied and verified times blank until they happen.
- Live generator: client disconnects are quiet; on shutdown the streaming lease is handed back first, and a dead local holder is cleared at start.

## 1.0.4 (2026-09-24)

- State writers save only the fields they changed, on top of the current record, so a tick can no longer undo a fire, reset or mode change.
- Background CI jobs, flows and processes run on the other ci-runner replicas; the story's runner pod carries only job 88213.
- The finding rule sets `zt_workload` to the raw risk object; the title, description and drilldowns use it.
- Agent tools: the server-context search returns one row per dataset, an explicit naming row and 40 rows, so the approval matrix and the policy naming reach the agent.
- Kernel requests carry the action `CNP <policy name>`; the agent's sentence is kept as `agent_action`.
- Request ids number one above the highest id of the day across the request store and the audit trail, in the app and in the playbook.
- Without a CI job the pod names the policy and the label (`zt-quarantine-<pod>`); job 88213 applies only to the story's pod; same rule in the SOAR custom function.
- Reset releases only pods that still carry a quarantine label, plus running attacks (from over 20 s to a few seconds).
- The playbook reads only a brief of the current run, captured after the finding, and resolves that run's investigation; its prompt names the request, the ES investigation and `CNP <policy>`.
- Mode switch (`make mode-soar`, `make mode-local`, the live generator's settings) also switches the ES automation rule on or off.

## 1.0.3 (2026-09-24)

- Live generator on the workstation (`live/`): browser page with a ten-minute timeline, live tail, counts, the incident's progress in Splunk and triggers (fire, reset, path attack for any workload, audit-mode flow, unapproved program, Live Protect, Nexus configuration change, enforcement action). Streams through the same `ztgen` code; a streaming lease in `zt_demo_state` keeps the search head input quiet while it runs.
- `ztgen.attacks`: generic path attacks (any workload to any protected store) advanced by whichever streamer holds the lease; the reset releases their quarantines.
- `ztgen.actions`: fire, reset and status shared by `ztdemo` and the live generator.
- Incident Timeline: incident selector (newest first), every panel scoped to the chosen incident, pending wording per step, rebuilt evidence links; new macro `zt_incident_window(1)`.
- Homepage `zt_home` (default view): one card per dashboard with a live number, scoreboard row.
- Enforcement Approvals: the comment box sits with Approve and Reject in the decision row.
- `ztbrief` runs on the search head (`distributed=False`, `local = true`, `| localop` in the capture search): Splunk Cloud sends streaming commands to the indexers, where the KV store is off.
- Risk detections throttle per run (`zt_run`), so a reset and a new fire within the hour produce new risk events; finding title from `risk_object` (ES normalised the entity through the asset lookup).
- Agent output schema: switch and interface are required fields.
- Tools: `verify_views.py`, `wording.py`, `live.py`; named User-Agent for the emulator probe (Cloudflare 1010).

## 1.0.0 (2026-09-23)

First release of the Zero Trust Incident demo for the deck "One incident, end to end", built for Splunk Cloud Platform (stack `prd-shw-39d7bab80b2f9d`) with Enterprise Security 8.7, AI Toolkit 6.1 (Agent Launchpad), MCP Server 2.0 and Splunk SOAR Cloud 8.7.

### `zt_incident_demo` 1.0.0 (main app, display name *Zero Trust Incident*)

- Generator: scripted input `bin/zt_stream.py` (every 15 seconds) and the `bin/ztgen/` package (standard library only): seeded estate model (`ai-platform-dc2`, 1,283 workloads, 92 nodes, four protected stores, eight known gaps, enforcement history), one event builder per sourcetype with the exact JSON of the design, daily schedules at exact counts (about 115,000 events a day), the incident plan (T0 batch, attempts every 30 seconds, AUDIT or DROPPED from the emulator's policy state by timestamp, CI job outcome), HEC client with batching and backoff, KV client, one-time backfill with a lock.
- Sourcetypes and knowledge: `cilium:hubble:flow`, `cisco:isovalent:processExec`, `cisco:isovalent:processConnect`, `cisco:isovalent`, `ci:job:event`, `cisco:nexus:endpoint`, `cisco:nexus:liveprotect`, `cisco:nexus:config`, `kube:apiserver:audit`, `zt:enforcement:audit`; normalized fields as calculated fields and automatic lookups; eventtypes and tags for CIM Network Traffic, Endpoint and Change.
- Lookups: `zt_workload_inventory`, `zt_protected_stores`, `zt_store_allowlist`, `zt_process_allowlist`, `zt_known_gaps`, `zt_protected_data`, `zt_node_fabric`, `zt_approvers`, `zt_role_labels`, generated from the estate model (`make lookups`).
- KV store collections: `zt_demo_state`, `zt_policy_state`, `zt_agent_briefs`, `zt_enforcement_requests`, with lookup definitions.
- Macros: `zt_index`, `zt_since_reset`, `zt_risk_window`, `zt_last_reset`, `zt_not_already_risked(3)`, `zt_incident_since_reset`.
- Commands: `ztdemo` (status, fire, reset, backfill, speed, config, tick), `ztsoar` (request, approve, reject, verify, status), `ztbrief` (capture the agent's brief, ES note, investigation), `ztevidence` (inline agent mode evidence packer).
- REST endpoint `POST /services/zt_incident_demo/approvals` (persistent handler, system privileges, approval matrix, `refused` audit).
- Kubernetes API emulator `bin/zt_k8s_emulator.py`: `/version`, pod label patch, CiliumNetworkPolicy create and delete, Hypershield and Nexus NX-API stubs, bearer tokens `k8s_enforcer` and `k8s_platform`, state in the stack's KV store, `kube:apiserver:audit` events over HEC, `Audit-Id` header; runs on the Mac behind the Cloudflare tunnel `zt-k8s` under launchd.
- Saved searches: `ZT Posture - Rollup`, `ZT Lookup - Node Fabric`, the five evidence searches `ZT Agent - Finding Context`, `ZT Agent - Flow Evidence`, `ZT Agent - Process Evidence`, `ZT Agent - CI Job Context`, `ZT Agent - Workload and Server Context`, `ZT Agent - Capture Brief`, `ZT Agent - Inline Triage`, `ZT Response - Request Enforcement`, `ZT Response - Verify Enforcement`.
- Dashboards (Dashboard Studio, absolute layout, dark): Zero Trust Fabric Posture, Incident Timeline with the one-pager journey grid, Enforcement Approvals.
- Settings `zt_demo.conf` (`[hec]`, `[emulator]`, `[stream]`, `[modes]`) with spec; response mode local or soar, agent mode mcp or inline, cadence fast or normal.

### `DA-ESS-zt_incident_demo` 1.0.0 (Enterprise Security content)

- Risk detections `ZT - Audit-Mode Flow Into Protected AI Data Store - Rule` (+50, MITRE ATT&CK T1530) and `ZT - Unapproved Program Connected to Protected AI Data Store - Rule` (+40, T1059.004), once per path or program since the last reset.
- Finding-based detection `ZT - Workload Exceeded Risk Threshold on Protected-Path Signals - Rule` (risk ≥ 80 from ≥ 2 detections; finding title `Unprotected path: $normalized_risk_object$ reached a protected AI data store`; severity high; three drilldowns; Run AI Agent action for `ZTFlowInvestigator`), built on the ES 8.7 template.
- Asset source `zt_workload_assets` (`lookups/zt_es_assets.csv`).

### Agent (`agent/`)

- `ZTFlowInvestigator`: system prompt, task prompt, structured output schema, LLM and MCP settings (`ZTFlowInvestigator.json`), the five MCP tool definitions under `mcp_tools/` (required arguments with patterns, `| savedsearch` templates), `setup_agent.py`.

### SOAR (`soar/zt_quarantine_workload/`)

- Playbook `zt_quarantine_workload`, custom function `zt_build_cnp` (identical logic to `ztgen/cnp.py`), build sheet and asset list; started by the ES automation rule "Zero Trust Protected Paths".

### Tooling (`tools/`, `Makefile`)

- Idempotent REST setup: `check`, `indexes`, `hec`, `secrets`, `configure`, `users`, `lookups`, `package` (with AppInspect cloud and private_victoria tags), `sync-objects`, `backfill`, `fire`, `reset`, `status`, `fast`, `normal`, `mode-local`, `mode-soar`, `agent-mcp`, `agent-inline`, `mcp-tools`, `agent`, `es-assets`, `es-automation-rule`, `soar-setup`, `soar-package`, `emulator-start|stop|status|install`, `tunnel-install`, `smoke`, `reset-hard`, `collateral`, `local-install`, `local-test`, `test`, `clean`.
- Unit tests `tests/test_ztgen.py`: estate, full-day counts, tick equivalence, plan, quarantine bodies.

### Documentation

- `README.md`, `docs/field_reference.md`, `docs/demo_script.md`, this changelog, each with an HTML rendering.
