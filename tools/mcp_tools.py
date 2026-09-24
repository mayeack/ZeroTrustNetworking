#!/usr/bin/env python3
"""make mcp-tools: create or update the five zt_ tools in the Splunk MCP Server (2.0), mint the zt-agent token, restrict
the tools to the zt_agent_mcp role, then call each tool through /services/mcp with * and with the canonical values."""
import glob
import json
import os
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
TOOL_DIR = os.path.join(ROOT, "agent", "mcp_tools")
CANON = {"zt_finding_context": {"workload": "build-farm/ci-runner"}, "zt_flow_evidence": {"workload": "build-farm/ci-runner", "dest": "ai-train/checkpoint-store"},
         "zt_process_evidence": {"pod": "ci-runner-7d9f8-xk2lq"}, "zt_ci_job_context": {"pod": "ci-runner-7d9f8-xk2lq"}, "zt_workload_server_context": {"workload": "build-farm/ci-runner", "node": "bf-node-03"}}
WILD = {"zt_finding_context": {"workload": "*"}, "zt_flow_evidence": {"workload": "build-farm/ci-runner", "dest": "*"}, "zt_process_evidence": {"pod": "ci-runner-7d9f8-xk2lq"},
        "zt_ci_job_context": {"pod": "ci-runner-7d9f8-xk2lq"}, "zt_workload_server_context": {"workload": "build-farm/ci-runner", "node": "*"}}


def existing_tools(s):
    return {t["name"]: t for t in s.get("services/mcp_tools").get("tools", [])}


APP_ID = "zt"  # tools are exposed as <external_app_id>_<name>: zt_finding_context, zt_flow_evidence, ...


def delete_app_tools(s, external_app_id):
    """Remove every tool registered under an external_app_id (DELETE with a JSON body, per the 2.0 API)."""
    try:
        s.request("DELETE", "services/mcp_tools", json_body={"external_app_id": external_app_id})
        return True
    except ztrest.RestError as e:
        if e.status != 404:
            print("delete %s: %s" % (external_app_id, str(e)[:160]))
        return False


def replace_tools(s, records):
    """Atomically register the tool set for the app (batch replace), then enable each tool."""
    for r in records:
        r["_meta"]["external_app_id"] = APP_ID
    out = s.post("services/mcp_tools", json_body={"external_app_id": APP_ID, "tools": records})
    print("batch replace: registered=%s deleted=%s failed=%s" % (out.get("registered_count"), out.get("deleted_count"), out.get("failed_deletes")))
    for r in records:
        tid = "%s:%s" % (APP_ID, r["name"])
        res = s.post("services/mcp_tools", json_body={"tool_id": tid, "enabled": True, "override": True})
        print("  %-32s enabled=%s" % (tid, res.get("enabled")))


def mint_token(s, user="zt-agent"):
    d = s.get("services/mcp_token", params={"username": user})
    tok = d.get("token") if isinstance(d, dict) else None
    if tok:
        ztrest.set_env_value("ZT_AGENT_MCP_TOKEN", tok)
    return tok


def mcp_call(token, method, params, rid=1):
    h = ztrest.Http(ztrest.env("SPLUNK_URL"), token=token, timeout=300)
    st, body = h.request("POST", "services/mcp", json_body={"jsonrpc": "2.0", "id": rid, "method": method, "params": params}, headers={"Accept": "application/json, text/event-stream"}, raw=True)
    text = body.decode("utf-8", "replace")
    try:
        return st, json.loads(text)
    except ValueError:
        lines = [ln[5:] for ln in text.splitlines() if ln.startswith("data:")]
        return st, (json.loads(lines[-1]) if lines else {"raw": text[:400]})


def main(argv):
    s = ztrest.Splunk()
    if delete_app_tools(s, "zt_incident_demo"):
        print("removed the earlier tools registered under zt_incident_demo")
    records = [json.load(open(p)) for p in sorted(glob.glob(os.path.join(TOOL_DIR, "*.json")))]
    replace_tools(s, records)
    token = ztrest.env("ZT_AGENT_MCP_TOKEN") or mint_token(s)
    if not token:
        print("could not mint an MCP token for zt-agent (does the user exist? run make users)")
        return 1
    st, res = mcp_call(token, "initialize", {"protocolVersion": "2025-03-26", "capabilities": {}, "clientInfo": {"name": "zt-make", "version": "1.0"}})
    print("initialize -> HTTP %s %s" % (st, (res.get("result") or res.get("error") or res).get("serverInfo", res.get("error")) if isinstance(res, dict) else res))
    st, res = mcp_call(token, "tools/list", {}, 2)
    names = [t["name"] for t in (res.get("result") or {}).get("tools", [])]
    print("tools/list -> %d tools; zt_ tools: %s" % (len(names), ", ".join(n for n in names if n.startswith("zt_"))))
    if "--no-test" in argv:
        return 0
    rows = []
    for name in sorted(CANON):
        for label, args in (("wildcard", WILD[name]), ("canonical", CANON[name])):
            t0 = time.time()
            st, res = mcp_call(token, "tools/call", {"name": name, "arguments": args}, 3)
            err = (res.get("error") or {}).get("message") if isinstance(res, dict) else None
            content = (res.get("result") or {}).get("content") or []
            text = content[0].get("text", "") if content else ""
            nrows = text.count("\n") if text else 0
            rows.append(("PASS" if st == 200 and not err and not (res.get("result") or {}).get("isError") else "FAIL", name, label, json.dumps(args), "%.1fs" % (time.time() - t0), (err or text[:90]).replace("\n", " ")))
    print(ztrest.table(rows, ["", "tool", "args", "values", "time", "result"]))
    return 0 if all(r[0] == "PASS" for r in rows) else 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
