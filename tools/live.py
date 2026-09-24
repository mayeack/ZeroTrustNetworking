#!/usr/bin/env python3
"""make live-run|live-start|live-stop|live-status|live-install|live-uninstall: the live generator on this Mac
(http://127.0.0.1:8890; launchd agent com.zt-incident-demo.live for install)."""
import json
import os
import plistlib
import signal
import subprocess
import sys
import time
import urllib.request

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
RUN = os.path.join(ROOT, "live", "run.py")
PID = os.path.join(ROOT, "local", "live.pid")
LOG = os.path.join(ROOT, "local", "logs", "live.log")
LABEL = "com.zt-incident-demo.live"
LAUNCH_AGENTS = os.path.expanduser("~/Library/LaunchAgents")
PORT = int(ztrest.env("ZT_LIVE_PORT", "8890"))
URL = "http://127.0.0.1:%d" % PORT


def running_pid():
    if not os.path.exists(PID):
        return None
    try:
        pid = int(open(PID).read().strip() or 0)
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def _env():
    env = dict(os.environ)
    env.update(ztrest.ENV)
    env["ZT_ENV_FILE"] = ztrest.ENV_FILE
    return env


def run():
    os.execvpe(sys.executable, [sys.executable, RUN], _env())


def start():
    if running_pid():
        print("already running (pid %s) at %s" % (running_pid(), URL))
        return 0
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    with open(LOG, "ab") as out:
        p = subprocess.Popen([sys.executable, RUN], env=_env(), stdout=out, stderr=subprocess.STDOUT, cwd=ROOT, start_new_session=True)
    open(PID, "w").write(str(p.pid))
    time.sleep(2.5)
    print("started pid %d at %s (log %s)" % (p.pid, URL, LOG))
    return status()


def stop():
    pid = running_pid()
    if not pid:
        print("not running (launchd may own it: make live-uninstall)")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(40):
        if not running_pid():
            break
        time.sleep(0.25)
    if os.path.exists(PID):
        os.remove(PID)
    print("stopped")
    return 0


def status():
    pid = running_pid()
    print("process: %s" % ("pid %d" % pid if pid else "not running (launchd may own it)"))
    try:
        with urllib.request.urlopen(URL + "/api/status", timeout=8) as r:
            s = json.loads(r.read().decode())
        print("api    : %s -> owner %s, ticks %s, events %s, lease %s, search head input %s" % (URL, s["owner"], s["tick_count"], s["events_total"], s["lease"]["holder"] or "(none)", "paused" if s["search_head_input_paused"] else "active"))
        if s.get("last_error"):
            print("error  : %s" % s["last_error"])
    except Exception as e:  # noqa: BLE001
        print("api    : %s -> unreachable (%s)" % (URL, str(e)[:80]))
    return 0


def plist():
    env = {k: ztrest.env(k) for k in ("SPLUNK_URL", "SPLUNK_USER", "SPLUNK_PASS", "SPLUNK_VERIFY", "SPLUNK_HEC_TOKEN", "ZT_K8S_ENFORCER_TOKEN", "ZT_LIVE_PORT", "ZT_LIVE_BIND") if ztrest.env(k)}
    return {"Label": LABEL, "ProgramArguments": [sys.executable, RUN], "RunAtLoad": True, "KeepAlive": True, "WorkingDirectory": ROOT,
            "EnvironmentVariables": dict(env, ZT_ENV_FILE=ztrest.ENV_FILE), "StandardOutPath": LOG + ".out", "StandardErrorPath": LOG + ".err"}


def install():
    os.makedirs(LAUNCH_AGENTS, exist_ok=True)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    stop()
    path = os.path.join(LAUNCH_AGENTS, LABEL + ".plist")
    subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), LABEL)], capture_output=True)
    with open(path, "wb") as fh:
        plistlib.dump(plist(), fh)
    os.chmod(path, 0o600)
    r = subprocess.run(["launchctl", "bootstrap", "gui/%d" % os.getuid(), path], capture_output=True, text=True)
    print("launchd %s: %s" % (LABEL, "loaded" if r.returncode == 0 else r.stderr.strip()))
    time.sleep(3)
    return status()


def uninstall():
    subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), LABEL)], capture_output=True)
    path = os.path.join(LAUNCH_AGENTS, LABEL + ".plist")
    if os.path.exists(path):
        os.remove(path)
    print("launchd %s removed" % LABEL)
    return 0


if __name__ == "__main__":
    cmd = sys.argv[1] if len(sys.argv) > 1 else "status"
    sys.exit({"run": run, "start": start, "stop": stop, "status": status, "install": install, "uninstall": uninstall}.get(cmd, status)())
