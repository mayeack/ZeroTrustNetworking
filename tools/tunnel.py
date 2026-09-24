#!/usr/bin/env python3
"""make tunnel-install: dedicated Cloudflare tunnel `zt-k8s` publishing the emulator at the public hostname.
Prints the config it is about to write; --apply creates the tunnel, the config and the DNS route."""
import os
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

CF = "/opt/homebrew/bin/cloudflared"
CFDIR = os.path.expanduser("~/.cloudflared")
CFG = os.path.join(CFDIR, "zt-k8s.yml")
NAME = "zt-k8s"


def tunnel_id():
    out = subprocess.run([CF, "tunnel", "list", "--output", "json"], capture_output=True, text=True).stdout
    import json
    for t in json.loads(out or "[]"):
        if t.get("name") == NAME:
            return t["id"]
    return None


def config_text(tid):
    host = ztrest.env("ZT_EMULATOR_PUBLIC_URL").split("//")[-1].split("/")[0]
    port = ztrest.env("ZT_EMULATOR_PORT", "6443")
    return ("tunnel: %s\ncredentials-file: %s/%s.json\nprotocol: http2\nmetrics: 127.0.0.1:20251\n\n"
            "ingress:\n  # The Kubernetes API emulator only. Nothing else on this Mac is routed.\n"
            "  - hostname: %s\n    service: https://127.0.0.1:%s\n    originRequest:\n      noTLSVerify: true\n  - service: http_status:404\n") % (tid or "<created on apply>", CFDIR, tid or "<id>", host, port)


def main(argv):
    apply = "--apply" in argv or (argv and argv[0] == "install")
    tid = tunnel_id()
    host = ztrest.env("ZT_EMULATOR_PUBLIC_URL").split("//")[-1].split("/")[0]
    print("== %s (tunnel %s)" % (CFG, tid or "not created yet"))
    print(config_text(tid))
    if not apply:
        print("dry run; use --apply")
        return 0
    if not tid:
        r = subprocess.run([CF, "tunnel", "create", NAME], capture_output=True, text=True)
        print(r.stdout.strip() or r.stderr.strip())
        tid = tunnel_id()
        if not tid:
            sys.exit("tunnel creation failed")
    with open(CFG, "w") as fh:
        fh.write(config_text(tid))
    print("wrote %s" % CFG)
    r = subprocess.run([CF, "--config", CFG, "tunnel", "route", "dns", "--overwrite-dns", NAME, host], capture_output=True, text=True)
    print((r.stdout + r.stderr).strip())
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
