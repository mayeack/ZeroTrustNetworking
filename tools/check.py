#!/usr/bin/env python3
"""make check: verify the cloud stack, SOAR, HEC, the Mac tooling and the emulator."""
import json
import os
import shutil
import socket
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

APPS = ["SplunkEnterpriseSecuritySuite", "missioncontrol", "SA-ThreatIntelligence", "Splunk_SA_CIM", "Splunk_ML_Toolkit",
        "Splunk_MCP_Server", "splunk-dashboard-studio", "zt_incident_demo", "DA-ESS-zt_incident_demo"]


def main():
    rows = []
    ok = True

    def add(name, state, good=True):
        nonlocal ok
        rows.append((("PASS" if good else "FAIL"), name, state))
        ok = ok and good

    s = ztrest.Splunk()
    try:
        info = s.entry("services/server/info")["content"]
        add("Splunk stack", "%s %s (%s)" % (info["serverName"].split(".")[0], info["version"], ", ".join(info.get("server_roles", []))))
    except Exception as e:  # noqa: BLE001
        add("Splunk stack", str(e)[:120], False)
        print(ztrest.table(rows, ["", "check", "state"]))
        return 1
    ctx = s.entry("services/authentication/current-context")["content"]
    add("REST user", "%s roles=%s" % (ctx["username"], ",".join(ctx["roles"])))
    apps = {e["name"]: e["content"].get("version") for e in s.entries("services/apps/local")}
    for a in APPS:
        present = a in apps
        add("app %s" % a, apps.get(a, "not installed"), present or a.endswith("zt_incident_demo"))
    kv = s.entry("services/kvstore/status")["content"]["current"]["status"]
    add("KV store", kv, kv == "ready")
    idx = {e["name"] for e in s.entries("services/data/indexes")}
    for name in ("zero_trust", "zt_summary"):
        add("index %s" % name, "present" if name in idx else "missing (make indexes)", True)
    toks = {e["name"] for e in s.entries("services/data/inputs/http")}
    add("HEC token zt_incident_demo", "present" if "http://zt_incident_demo" in toks else "missing (make hec)", True)
    hec_url = ztrest.env("SPLUNK_HEC_URL")
    st, body = ztrest.Http(hec_url).request("GET", "services/collector/health", raw=True)
    add("HEC endpoint", "%s -> HTTP %s" % (hec_url, st), st == 200)
    pairing = s.entry("servicesNS/nobody/missioncontrol/configs/conf-essoar/pairing_state")
    add("ES-SOAR pairing", pairing["content"].get("pairing_status") if pairing else "no pairing stanza", bool(pairing))
    mcp = s.get("services/mcp_tools")
    add("MCP Server tools", "%d tools" % len(mcp.get("tools", [])))
    try:
        soar = ztrest.Soar()
        ver = soar.get("rest/version")["version"]
        sapps = {a["name"]: a.get("app_version") for a in soar.get("rest/app", params={"page_size": 300})["data"]}
        add("SOAR", "%s; Splunk app %s, HTTP app %s, ES connector %s" % (ver, sapps.get("Splunk"), sapps.get("HTTP"), sapps.get("Enterprise Security")))
    except Exception as e:  # noqa: BLE001
        add("SOAR", str(e)[:120], False)
    # Mac side
    py = subprocess.run([sys.executable, "--version"], capture_output=True, text=True).stdout.strip()
    add("Python (tooling)", py)
    add("splunk-appinspect", shutil.which("splunk-appinspect") or "missing", bool(shutil.which("splunk-appinspect")))
    add("cloudflared", shutil.which("cloudflared") or "missing", bool(shutil.which("cloudflared")))
    port = int(ztrest.env("ZT_EMULATOR_PORT", "6443"))
    with socket.socket() as sock:
        sock.settimeout(1)
        bound = sock.connect_ex(("127.0.0.1", port)) == 0
    if bound:
        st, body = ztrest.Http("https://127.0.0.1:%d" % port, verify=False).request("GET", "version", raw=True)
        add("emulator 127.0.0.1:%d" % port, "answers /version HTTP %s" % st, st == 200)
    else:
        add("emulator 127.0.0.1:%d" % port, "port free (make emulator-start)", True)
    pub = ztrest.env("ZT_EMULATOR_PUBLIC_URL")
    if pub:
        try:
            st, body = ztrest.Http(pub, timeout=15).request("GET", "version", raw=True, retries=0)
            add("emulator public %s" % pub, "HTTP %s" % st, True)
        except Exception as e:  # noqa: BLE001
            add("emulator public %s" % pub, "unreachable (%s)" % str(e)[:60], True)
    print(ztrest.table(rows, ["", "check", "state"]))
    return 0 if ok else 1


if __name__ == "__main__":
    sys.exit(main())
