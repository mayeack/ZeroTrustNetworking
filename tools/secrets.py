#!/usr/bin/env python3
"""make secrets: emulator certificate (local/certs) and the two bearer tokens. Tokens go to local/env for the Mac
process and to storage/passwords (realm zt_incident_demo) on the stack once the app is installed. Idempotent."""
import os
import secrets
import subprocess
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

ROOT = ztrest.ROOT
CERT_DIR = os.path.join(ROOT, "local", "certs")


def ensure_cert():
    os.makedirs(CERT_DIR, exist_ok=True)
    crt, key = os.path.join(CERT_DIR, "kube-apiserver.crt"), os.path.join(CERT_DIR, "kube-apiserver.key")
    if os.path.exists(crt) and os.path.exists(key):
        print("certificate present: %s" % crt)
    else:
        host = ztrest.env("ZT_EMULATOR_PUBLIC_URL", "https://zt-k8s.yeackbot.com").split("//")[-1].split("/")[0]
        cfg = os.path.join(CERT_DIR, "openssl.cnf")
        with open(cfg, "w") as fh:
            fh.write("[req]\ndistinguished_name=dn\nx509_extensions=ext\nprompt=no\n[dn]\nCN=kube-apiserver\n[ext]\nsubjectAltName=DNS:localhost,DNS:host.docker.internal,DNS:%s,IP:127.0.0.1\nbasicConstraints=CA:FALSE\nkeyUsage=digitalSignature,keyEncipherment\nextendedKeyUsage=serverAuth\n" % host)
        subprocess.run(["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "825", "-keyout", key, "-out", crt, "-config", cfg], check=True, capture_output=True)
        os.chmod(key, 0o600)
        print("certificate created: %s (CN kube-apiserver, SAN %s)" % (crt, host))
    ztrest.set_env_value("ZT_EMULATOR_CERT", crt)
    ztrest.set_env_value("ZT_EMULATOR_KEY", key)


def ensure_tokens():
    for name in ("ZT_K8S_ENFORCER_TOKEN", "ZT_K8S_PLATFORM_TOKEN"):
        if not ztrest.env(name):
            ztrest.set_env_value(name, secrets.token_urlsafe(32))
            print("%s generated" % name)
        else:
            print("%s present" % name)


def push_to_stack():
    s = ztrest.Splunk()
    if not s.exists("services/apps/local/zt_incident_demo"):
        print("app zt_incident_demo not installed on the stack yet; tokens stay in local/env (rerun make secrets after the upload)")
        return
    for realm_name, envkey in (("k8s_enforcer", "ZT_K8S_ENFORCER_TOKEN"), ("k8s_platform", "ZT_K8S_PLATFORM_TOKEN")):
        s.password_set("zt_incident_demo", realm_name, ztrest.env(envkey))
        print("storage/passwords zt_incident_demo:%s set" % realm_name)


def main():
    ensure_cert()
    ensure_tokens()
    push_to_stack()
    return 0


if __name__ == "__main__":
    sys.exit(main())
