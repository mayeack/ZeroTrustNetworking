# Zero trust incident demo on Splunk Cloud + SOAR Cloud. Credentials come from local/env (git-ignored) or the environment.
PY ?= python3
APP := zt_incident_demo
DA := DA-ESS-zt_incident_demo
VERSION := 1.0.8
DA_VERSION := 1.0.5
LOCAL_SPLUNK ?= /opt/splunk104
SPL := $(LOCAL_SPLUNK)/bin/splunk
FRESH ?= 0
PACKAGE_DIR ?= /Users/myeack/Library/CloudStorage/OneDrive-Cisco/Projects/Sales Plays/Zero Trust Networking/Splunk App Packages

.PHONY: help check indexes hec secrets configure users lookups package appinspect sync-objects backfill fire reset status fast normal \
        mode-local mode-soar agent-mcp agent-inline mcp-tools agent es-assets es-automation-rule soar-setup soar-package \
        emulator-start emulator-stop emulator-status emulator-install tunnel-install smoke reset-hard collateral pdfs local-install local-test test clean

help:
	@grep -E '^[a-z-]+:.*## ' $(MAKEFILE_LIST) | sed 's/:.*## /  /' | column -t -s'  '

check: ## Verify the stack, SOAR, HEC, tooling and the emulator
	$(PY) tools/check.py
indexes: ## Create zero_trust and zt_summary on the stack (idempotent)
	$(PY) tools/indexes.py
hec: ## Create the HEC token (idempotent) and keep it in local/env for the emulator
	$(PY) tools/hec.py
secrets: ## Emulator certificate and bearer tokens (local/env and storage/passwords on the stack)
	$(PY) tools/gen_secrets.py
configure: ## Write the HEC and emulator URLs into the installed app's local/zt_demo.conf (REST)
	$(PY) tools/configure.py
users: ## Roles and users on the stack (asks first; passwords generated into local/env)
	$(PY) tools/users.py
lookups: ## Rebuild the CSV lookups from the estate model
	$(PY) tools/gen_lookups.py
test: ## Unit tests of the estate, schedule and plan
	$(PY) tests/test_ztgen.py
package: lookups test ## Build both .tgz packages and run AppInspect with the cloud checks
	$(PY) tools/package.py $(APP) $(VERSION)
	$(PY) tools/package.py $(DA) $(DA_VERSION)
	$(MAKE) appinspect
	@mkdir -p "$(PACKAGE_DIR)" && cp $(APP)-$(VERSION).tgz $(DA)-$(DA_VERSION).tgz "$(PACKAGE_DIR)/" && echo "packages copied to $(PACKAGE_DIR)"
appinspect: ## AppInspect (cloud + private_victoria tags) on the built packages
	@for p in $(APP)-$(VERSION).tgz $(DA)-$(DA_VERSION).tgz; do echo "== $$p"; splunk-appinspect inspect $$p --mode precert --included-tags cloud --included-tags private_victoria --output-file local/appinspect-$$p.json > local/appinspect-$$p.txt 2>&1; $(PY) -c "import json,sys; d=json.load(open(sys.argv[1])); print({k: v for k, v in d['summary'].items() if k != 'not_applicable'})" local/appinspect-$$p.json; done
sync-objects: ## Push knowledge objects (saved searches, macros, views, lookups) into the installed apps by REST
	$(PY) tools/sync_objects.py
backfill: ## | ztdemo action=backfill, then a count table by sourcetype
	$(PY) tools/ztctl.py backfill
fire: ## | ztdemo action=fire
	$(PY) tools/ztctl.py fire
reset: ## | ztdemo action=reset
	$(PY) tools/ztctl.py reset
status: ## | ztdemo action=status
	$(PY) tools/ztctl.py status
fast: ## Every ZT scheduled search every minute
	$(PY) tools/ztctl.py speed fast
normal: ## Every ZT scheduled search every 5 minutes
	$(PY) tools/ztctl.py speed normal
mode-local: ## Mode B: local approvals (also switches the ES automation rule off)
	$(PY) tools/ztctl.py config response_mode=local
	$(PY) tools/es_automation_rule.py --off
mode-soar: ## Mode A: SOAR playbook (also switches the ES automation rule on)
	$(PY) tools/ztctl.py config response_mode=soar
	$(PY) tools/es_automation_rule.py --on
agent-mcp: ## Agent uses the MCP tools
	$(PY) tools/agent_mode.py mcp
agent-inline: ## Agent gets the evidence inline
	$(PY) tools/agent_mode.py inline
mcp-tools: ## Create or update the five MCP tools and test them
	$(PY) tools/mcp_tools.py
agent: ## Create or update the SplunkMCP connection and the ZTFlowInvestigator agent by REST (needs the LLM connection)
	$(PY) agent/setup_agent.py
es-assets: ## Register the ES asset source
	$(PY) tools/es_assets.py
es-automation-rule: ## ES automation rule that starts the SOAR playbook from the ZT finding (RULE=on|off toggles it)
	$(PY) tools/es_automation_rule.py $(if $(RULE),--$(RULE),)
soar-setup: ## SOAR roles, users, assets, custom function and playbook (asks first)
	$(PY) tools/soar_setup.py
soar-package: ## Validate the SOAR package folder
	$(PY) tools/soar_setup.py --package-only
emulator-start: ## Start the Kubernetes API emulator on this Mac
	$(PY) tools/emulator.py start
emulator-stop: ## Stop it
	$(PY) tools/emulator.py stop
emulator-status: ## Status through the local and the public URL
	$(PY) tools/emulator.py status
emulator-install: ## launchd agents for the emulator and its tunnel (shows the config first)
	$(PY) tools/emulator.py install
tunnel-install: ## Create the zt-k8s Cloudflare tunnel and DNS route (shows the config first)
	$(PY) tools/tunnel.py install
smoke: ## Acceptance checks with a pass/fail table (FRESH=1 right after a fresh install)
	$(PY) tools/smoke.py --fresh=$(FRESH)
smoke-soar: ## Mode A acceptance: fire, then approve the playbook prompt in SOAR as j.chen and verify executed_by=soar (criterion 9)
	$(PY) tools/smoke.py --soar
smoke-attach: ## Verify the incident already running (no new fire); add SOAR=1 for Mode A
	$(PY) tools/smoke.py --attach $(if $(SOAR),--soar,)
wording: ## Acceptance criterion 11: banned words in visible text of both apps, the agent and the playbook
	$(PY) tools/wording.py
verify-views: ## Run every Dashboard Studio data source on the stack with the newest incident selected
	$(PY) tools/verify_views.py
live-run: ## Live generator in the foreground (http://127.0.0.1:8890): streams from this Mac, live timeline, triggers
	$(PY) tools/live.py run
live-start: ## Live generator in the background (pid in local/live.pid)
	$(PY) tools/live.py start
live-stop: ## Stop the background live generator (the search head streamer resumes)
	$(PY) tools/live.py stop
live-status: ## Process and API status of the live generator
	$(PY) tools/live.py status
live-install: ## launchd agent com.zt-incident-demo.live (starts at login, restarts on failure)
	$(PY) tools/live.py install
live-uninstall: ## Remove the launchd agent
	$(PY) tools/live.py uninstall
reset-hard: ## Empty zero_trust and zt_summary on the stack and backfill again (asks first)
	$(PY) tools/reset_hard.py
collateral: ## Update the deck and the talk track from docs/collateral/collateral.yaml
	$(PY) docs/collateral/sync_collateral.py
pdfs: ## Print the three collateral PDFs from docs/collateral/pdf/*.html into docs/collateral/pdf/out (copy them to OneDrive after review)
	$(PY) docs/collateral/pdf/render_pdfs.py
local-install: lookups ## Copy both apps into the local Splunk (test bed) and restart it
	rsync -a --delete --exclude local/ $(APP)/ $(LOCAL_SPLUNK)/etc/apps/$(APP)/
	rsync -a --delete --exclude local/ $(DA)/ $(LOCAL_SPLUNK)/etc/apps/$(DA)/
	$(SPL) restart
local-test: ## Full incident on the local test Splunk (injected brief, approval as j.chen); needs local/env.local
	ZT_ENV_FILE=local/env.local $(PY) tools/smoke.py --inject-brief
clean:
	rm -f *.tgz; find . -name __pycache__ -prune -exec rm -rf {} \; 2>/dev/null; true
