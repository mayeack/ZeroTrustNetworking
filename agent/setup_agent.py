#!/usr/bin/env python3
"""make agent: print the Agent Launchpad steps for ZTFlowInvestigator (UI is the primary path). With --rest it tries
the AI Toolkit REST endpoints discovered from the UI (filled in after the first UI-driven creation)."""
import json
import os
import sys

HERE = os.path.dirname(os.path.abspath(__file__))
cfg = json.load(open(os.path.join(HERE, "ZTFlowInvestigator.json")))
print("Agent Launchpad (AI Toolkit > Agents > + Agent > Create an agent):")
print("  Name: %s" % cfg["name"])
print("  Description: %s" % cfg["description"])
print("  LLM connection: %s (temperature %s, max tokens %s, reasoning %s)" % (cfg["llm"]["connection"], cfg["llm"]["temperature"], cfg["llm"]["max_tokens"], cfg["llm"]["reasoning_effort"]))
print("  Then Edit agent: Default prompt = %s" % cfg["task_prompt"])
print("  System prompt = agent/system_prompt.md (verbatim)")
print("  MCP connection %s (%s) with tools: %s" % (cfg["mcp"]["connection"], cfg["mcp"]["url"], ", ".join(cfg["mcp"]["tools"])))
print("  Structured output = agent/output_schema.json; timeout %s s" % cfg["agent_timeout"])
print("  Invocation: %s" % cfg["invocation"]["alert_action"])
