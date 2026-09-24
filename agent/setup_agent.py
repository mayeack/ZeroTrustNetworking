#!/usr/bin/env python3
"""make agent: create or update the ZTFlowInvestigator agent and its SplunkMCP connection in Agent Launchpad through
the AI Toolkit 6.1 REST layer (servicesNS/<admin user>/Splunk_ML_Toolkit/mltk/...), then wait until it is Available.
The LLM connection must already exist (created in AI Toolkit > Connections). Idempotent."""
import json
import os
import sys
import time

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
sys.path.insert(0, os.path.join(ROOT, "tools"))
import ztrest  # noqa: E402

TOOLS = ["zt_finding_context", "zt_flow_evidence", "zt_process_evidence", "zt_ci_job_context", "zt_workload_server_context"]
LLM_CONNECTION = os.environ.get("ZT_LLM_CONNECTION", "Anthropic")


def ns(path):
    return "servicesNS/%s/Splunk_ML_Toolkit/mltk/%s" % (ztrest.env("SPLUNK_USER"), path)


def call(s, method, path, body=None):
    st, resp = s.request(method, path, json_body=body, raw=True)
    text = resp.decode("utf-8", "replace") if isinstance(resp, bytes) else resp
    try:
        return st, json.loads(text)
    except ValueError:
        return st, {"raw": text[:300]}


def fields_from_schema(schema):
    out = {}
    for k, v in schema["properties"].items():
        t = v.get("type") or "string"
        f = {"type": (v.get("items") or {}).get("type", "string"), "is_array": True} if t == "array" else {"type": t}
        f["required"] = k in schema["required"]
        f["description"] = v.get("description", "")
        out[k] = f
    return out


def ensure_mcp_connection(s):
    token = ztrest.env("ZT_AGENT_MCP_TOKEN")
    if not token:
        sys.exit("no ZT_AGENT_MCP_TOKEN in local/env; run make mcp-tools first")
    body = {"name": "SplunkMCP", "type": "SPLUNK", "description": "Splunk MCP Server on this stack; zero trust evidence tools only",
            "details": {"url": ztrest.env("SPLUNK_URL") + "/services/mcp", "token": token}, "tools": [{"name": t, "description": ""} for t in TOOLS]}
    existing = {r.get("name") for r in s.kv_list("aitk_mcp_collection", app="Splunk_ML_Toolkit")}
    st, d = call(s, "PUT" if "SplunkMCP" in existing else "POST", ns("mcp_connection"), body)
    print("MCP connection SplunkMCP: HTTP %s %s" % (st, d.get("message") or d.get("error_message") or d))


def ensure_agent(s):
    cfg = json.load(open(os.path.join(HERE, "ZTFlowInvestigator.json")))
    llm = {r.get("name"): r for r in s.kv_list("aitk_llm_connection", app="Splunk_ML_Toolkit")}.get(LLM_CONNECTION)
    if not llm:
        sys.exit("LLM connection %s not found in the AI Toolkit; create it in Connections first" % LLM_CONNECTION)
    update = {"name": cfg["name"], "description": cfg["description"], "is_enabled": True,
              "llm": {"connection_name": LLM_CONNECTION, "provider": llm.get("provider"), "model": llm.get("model"), "response_variability": cfg["llm"]["temperature"],
                      "max_tokens": cfg["llm"]["max_tokens"], "reasoning_effort": "NONE"},
              "system_prompt": open(os.path.join(HERE, cfg["system_prompt_file"])).read(), "task_prompt": cfg["task_prompt"],
              "mcps": [{"name": "SplunkMCP", "tools": TOOLS}], "knowledge_bases": [], "skills": [], "agent_timeout": cfg["agent_timeout"],
              "structured_output": {"fields": fields_from_schema(json.load(open(os.path.join(HERE, cfg["structured_output_file"]))))},
              "acl": {"sharing": "app", "perms": {"read": ["*"], "write": ["admin", "mltk_admin", "sc_admin"]}}}
    st, d = call(s, "GET", ns("agents/%s" % cfg["name"]))
    if st != 200:
        st, d = call(s, "POST", ns("agents"), {"name": cfg["name"]})
        print("agent created: HTTP %s %s" % (st, d))
    st, d = call(s, "PUT", ns("agents"), update)
    print("agent configured: HTTP %s %s" % (st, d.get("message") or d.get("error_message") or d))
    for _ in range(40):
        st, d = call(s, "GET", ns("agents/%s" % cfg["name"]))
        state = (d.get("versions") or [{}])[0].get("state")
        if state == "Available":
            print("agent state: Available")
            return 0
        if state in ("Failed", "Error"):
            print("agent state: %s %s" % (state, d))
            return 1
        time.sleep(15)
    print("agent still not Available; check AI Toolkit > Agents")
    return 1


def main(argv):
    s = ztrest.Splunk()
    ensure_mcp_connection(s)
    return ensure_agent(s)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
