#!/usr/bin/env python3
"""make emulator-start|stop|status|install: run the Kubernetes API emulator on this Mac (launchd for install)."""
import os
import plistlib
import signal
import subprocess
import sys
import time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
BIN = os.path.join(ROOT, "zt_incident_demo", "bin", "zt_k8s_emulator.py")
PID = os.path.join(ROOT, "local", "emulator.pid")
LOG = os.path.join(ROOT, "local", "logs", "emulator.log")
LABEL_EMU = "com.zt-incident-demo.emulator"
LABEL_TUN = "com.zt-incident-demo.tunnel"
LAUNCH_AGENTS = os.path.expanduser("~/Library/LaunchAgents")


def running_pid():
    if not os.path.exists(PID):
        return None
    pid = int(open(PID).read().strip() or 0)
    try:
        os.kill(pid, 0)
        return pid
    except (OSError, ValueError):
        return None


def start():
    if running_pid():
        print("already running (pid %s)" % running_pid())
        return 0
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    env = dict(os.environ)
    env.update({k: v for k, v in ztrest.ENV.items()})
    env["ZT_EMULATOR_LOG"] = LOG
    env["ZT_ENV_FILE"] = ztrest.ENV_FILE
    p = subprocess.Popen([sys.executable, BIN], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, start_new_session=True)
    open(PID, "w").write(str(p.pid))
    for _ in range(20):
        time.sleep(0.5)
        st = local_status()
        if st == 200:
            print("up (pid %d): https://127.0.0.1:%s/version -> 200" % (p.pid, ztrest.env("ZT_EMULATOR_PORT", "6443")))
            return 0
    print("not answering after 10s; see %s" % LOG)
    return 1


def stop():
    pid = running_pid()
    if not pid:
        print("not running")
        return 0
    os.kill(pid, signal.SIGTERM)
    for _ in range(20):
        time.sleep(0.5)
        if not running_pid():
            break
    os.remove(PID) if os.path.exists(PID) else None
    print("stopped (pid %d)" % pid)
    return 0


def local_status():
    try:
        st, _ = ztrest.Http("https://127.0.0.1:%s" % ztrest.env("ZT_EMULATOR_PORT", "6443"), verify=False, timeout=5).request("GET", "version", raw=True, retries=0)
        return st
    except Exception:  # noqa: BLE001
        return 0


def status():
    pid = running_pid()
    print("process: %s" % ("pid %d" % pid if pid else "not running (launchd may own it)"))
    print("local  : HTTP %s" % local_status())
    pub = ztrest.env("ZT_EMULATOR_PUBLIC_URL")
    try:
        st, body = ztrest.Http(pub, timeout=15).request("GET", "version", raw=True, retries=0)
        print("public : %s -> HTTP %s %s" % (pub, st, body[:80].decode("utf-8", "replace")))
    except Exception as e:  # noqa: BLE001
        print("public : %s -> unreachable (%s)" % (pub, str(e)[:80]))
    return 0


def plist_emulator():
    env = {k: ztrest.env(k) for k in ("SPLUNK_URL", "SPLUNK_USER", "SPLUNK_PASS", "SPLUNK_HEC_URL", "SPLUNK_HEC_TOKEN", "ZT_K8S_ENFORCER_TOKEN", "ZT_K8S_PLATFORM_TOKEN",
                                     "ZT_EMULATOR_BIND", "ZT_EMULATOR_PORT", "ZT_EMULATOR_CERT", "ZT_EMULATOR_KEY", "ZT_EMULATOR_SPLUNK_TOKEN") if ztrest.env(k)}
    return {"Label": LABEL_EMU, "ProgramArguments": [sys.executable, BIN], "RunAtLoad": True, "KeepAlive": True, "WorkingDirectory": ROOT,
            "EnvironmentVariables": dict(env, ZT_EMULATOR_LOG=LOG, ZT_ENV_FILE=ztrest.ENV_FILE), "StandardOutPath": LOG + ".out", "StandardErrorPath": LOG + ".err"}


def plist_tunnel():
    cf = "/opt/homebrew/bin/cloudflared"
    cfg = os.path.expanduser("~/.cloudflared/zt-k8s.yml")
    return {"Label": LABEL_TUN, "ProgramArguments": [cf, "--config", cfg, "tunnel", "run", "zt-k8s"], "RunAtLoad": True, "KeepAlive": True,
            "StandardOutPath": os.path.expanduser("~/.cloudflared/zt-k8s-tunnel.log"), "StandardErrorPath": os.path.expanduser("~/.cloudflared/zt-k8s-tunnel.log")}


def install():
    os.makedirs(LAUNCH_AGENTS, exist_ok=True)
    os.makedirs(os.path.dirname(LOG), exist_ok=True)
    stop()
    for label, pl in ((LABEL_EMU, plist_emulator()), (LABEL_TUN, plist_tunnel())):
        path = os.path.join(LAUNCH_AGENTS, label + ".plist")
        subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), label)], capture_output=True)
        with open(path, "wb") as fh:
            plistlib.dump(pl, fh)
        os.chmod(path, 0o600)
        r = subprocess.run(["launchctl", "bootstrap", "gui/%d" % os.getuid(), path], capture_output=True, text=True)
        print("launchd %s: %s" % (label, "loaded" if r.returncode == 0 else r.stderr.strip()))
    time.sleep(3)
    return status()


def uninstall():
    for label in (LABEL_EMU, LABEL_TUN):
        subprocess.run(["launchctl", "bootout", "gui/%d/%s" % (os.getuid(), label)], capture_output=True)
        path = os.path.join(LAUNCH_AGENTS, label + ".plist")
        if os.path.exists(path):
            os.remove(path)
        print("launchd %s removed" % label)
    return 0


if __name__ == "__main__":
    sys.exit({"start": start, "stop": stop, "status": status, "install": install, "uninstall": uninstall}[sys.argv[1] if len(sys.argv) > 1 else "status"]())
