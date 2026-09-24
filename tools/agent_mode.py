#!/usr/bin/env python3
"""make agent-mcp | agent-inline: switch the agent mode. mcp: the finding-based detection runs the agent (Run AI Agent
action on) and the inline triage search is off. inline: the action is off, ZT Agent - Inline Triage runs every minute."""
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

FBD = "ZT - Workload Exceeded Risk Threshold on Protected-Path Signals - Rule"
INLINE = "ZT Agent - Inline Triage"


def main(argv):
    mode = argv[0] if argv else "mcp"
    if mode not in ("mcp", "inline"):
        sys.exit("usage: agent_mode.py mcp|inline")
    s = ztrest.Splunk()
    fbd = "servicesNS/nobody/DA-ESS-zt_incident_demo/saved/searches/" + urllib.parse.quote(FBD, safe="")
    inline = "servicesNS/nobody/zt_incident_demo/saved/searches/" + urllib.parse.quote(INLINE, safe="")
    s.post(fbd, data={"action.run_aiagent": "1" if mode == "mcp" else "0"})
    s.post(inline + ("/enable" if mode == "inline" else "/disable"))
    rows = s.search("| ztdemo action=config agent_mode=%s" % mode, earliest="-1m", latest="now", timeout=120)
    print("agent mode %s: run_aiagent=%s on the detection, inline triage %s; %s" % (mode, "on" if mode == "mcp" else "off", "enabled" if mode == "inline" else "disabled", rows[0].get("result") if rows else ""))
    print("note: in inline mode remove the MCP tools from the agent in Agent Launchpad; in mcp mode add them back")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
