#!/usr/bin/env python3
"""Kubernetes API emulator: the part of the API a quarantine playbook uses (generating prompt section 8).

Runs outside Splunk (on the Mac, published through a Cloudflare tunnel). State lives in the stack's KV collection
zt_policy_state so the generator decides AUDIT or DROPPED from the same records. Every mutating call writes a
kube:apiserver:audit event over HTTP Event Collector and returns the Audit-Id header like a real API server.

Settings come from the environment (or the git-ignored local/env file): SPLUNK_URL, SPLUNK_USER/SPLUNK_PASS or
ZT_EMULATOR_SPLUNK_TOKEN, SPLUNK_HEC_URL, SPLUNK_HEC_TOKEN, ZT_K8S_ENFORCER_TOKEN, ZT_K8S_PLATFORM_TOKEN,
ZT_EMULATOR_BIND, ZT_EMULATOR_PORT, ZT_EMULATOR_CERT, ZT_EMULATOR_KEY, ZT_EMULATOR_LOG.
"""
import json
import logging
import os
import socket
import ssl
import sys
import threading
import time
import uuid
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from ztgen import canon, builders as B  # noqa: E402
from ztgen.estate import get_estate  # noqa: E402
from ztgen.restclient import Hec, Splunkd, RestError  # noqa: E402

log = logging.getLogger("zt_k8s_emulator")
COLLECTION = "zt_policy_state"
ALLOWED_RULES = {"egressDeny", "ingressDeny", "egress", "ingress"}
ALLOWED_RULE_KEYS = {"toEntities", "fromEntities", "toEndpoints", "fromEndpoints", "toPorts"}


def load_env():
    path = os.environ.get("ZT_ENV_FILE") or os.path.join(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__)))), "local", "env")
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.strip()
                if line and not line.startswith("#") and "=" in line:
                    k, v = line.split("=", 1)
                    os.environ.setdefault(k.strip(), v.strip())


def status_body(code, reason, message, details=None):
    return {"kind": "Status", "apiVersion": "v1", "metadata": {}, "status": "Failure", "message": message, "reason": reason, "details": details or {}, "code": code}


class State:
    """Pod overlays and CiliumNetworkPolicies in KV; the estate's pods as the base."""

    def __init__(self, splunkd, hec):
        self.sd, self.hec = splunkd, hec
        self.estate = get_estate()
        self.lock = threading.Lock()

    def records(self):
        return self.sd.kv_query(COLLECTION)

    def pod_overlay(self, ns, name):
        return self.sd.kv_get(COLLECTION, "%s/Pod/%s" % (ns, name)) or {"_key": "%s/Pod/%s" % (ns, name), "kind": "Pod", "namespace": ns, "name": name,
                                                                          "labels_json": "{}", "label_epochs_json": "{}", "resource_version": 1000, "updated_by": "", "updated_epoch": 0}

    def pod(self, ns, name):
        p = self.estate.pods.get(name)
        if p is None or self.estate.workloads[p.workload].namespace != ns:
            return None, None
        w = self.estate.workloads[p.workload]
        overlay = self.pod_overlay(ns, name)
        labels = {}
        for lab in w.labels:
            if lab.startswith("k8s:") and "io.cilium" not in lab and "io.kubernetes" not in lab:
                k, v = lab[4:].split("=", 1)
                labels[k] = v
        labels["pod-template-hash"] = name.split("-")[-2] if w.kind == "Deployment" else ""
        if w.kind != "Deployment":
            labels.pop("pod-template-hash", None)
        labels.update(json.loads(overlay.get("labels_json") or "{}"))
        body = {"kind": "Pod", "apiVersion": "v1",
                "metadata": {"name": name, "namespace": ns, "uid": B.det_uuid("poduid", name), "resourceVersion": str(overlay.get("resource_version", 1000)),
                             "creationTimestamp": B.iso_s(time.time() - 86400 * 3), "labels": labels},
                "spec": {"nodeName": p.node, "serviceAccountName": w.service_account, "containers": [{"name": "build" if w.namespace == "build-farm" else "main", "image": w.image}]},
                "status": {"phase": "Running", "podIP": p.ip, "hostIP": self.estate.nodes[p.node].ip}}
        return body, overlay

    def patch_pod(self, ns, name, patch, user, ua, ip):
        body, overlay = self.pod(ns, name)
        if body is None:
            return 404, status_body(404, "NotFound", 'pods "%s" not found' % name, {"name": name, "kind": "pods"}), None
        labels = json.loads(overlay.get("labels_json") or "{}")
        epochs = json.loads(overlay.get("label_epochs_json") or "{}")
        now = time.time()
        for k, v in ((patch.get("metadata") or {}).get("labels") or {}).items():
            if v is None:
                labels.pop(k, None)
                epochs.pop(k, None)
            else:
                labels[k] = str(v)
                epochs[k] = now
        overlay.update({"labels_json": json.dumps(labels), "label_epochs_json": json.dumps(epochs), "resource_version": int(overlay.get("resource_version", 1000)) + 1,
                        "updated_by": user, "updated_epoch": now})
        self.sd.kv_save(COLLECTION, overlay)
        audit_id = self.audit(now, "patch", "/api/v1/namespaces/%s/pods/%s" % (ns, name), "pods", ns, name, "", "v1", 200, user, ua, ip)
        body, _ = self.pod(ns, name)
        body["metadata"].setdefault("annotations", {})["zt/auditID"] = audit_id
        return 200, body, audit_id

    def list_cnp(self, ns):
        items = [self._cnp_body(r) for r in self.records() if r.get("kind") == "CiliumNetworkPolicy" and r.get("namespace") == ns]
        return {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicyList", "metadata": {"resourceVersion": str(int(time.time()))}, "items": items}

    def _cnp_body(self, r):
        spec = json.loads(r.get("spec_json") or "{}")
        return {"apiVersion": "cilium.io/v2", "kind": "CiliumNetworkPolicy",
                "metadata": {"name": r["name"], "namespace": r["namespace"], "uid": r.get("uid"), "resourceVersion": str(r.get("resource_version")),
                             "creationTimestamp": B.iso_s(float(r.get("created_epoch") or 0)), "labels": json.loads(r.get("labels_json") or "{}")}, "spec": spec}

    def validate_cnp(self, ns, body):
        if not isinstance(body, dict):
            return "body must be a JSON object"
        if body.get("apiVersion") != "cilium.io/v2":
            return "apiVersion must be cilium.io/v2"
        if body.get("kind") != "CiliumNetworkPolicy":
            return "kind must be CiliumNetworkPolicy"
        meta = body.get("metadata") or {}
        if not meta.get("name"):
            return "metadata.name is required"
        if meta.get("namespace") not in (None, ns):
            return "metadata.namespace does not match the request namespace"
        spec = body.get("spec") or {}
        if not isinstance(spec.get("endpointSelector"), dict):
            return "spec.endpointSelector is required"
        for key in spec:
            if key not in ALLOWED_RULES | {"endpointSelector", "description"}:
                return "spec.%s is not supported" % key
            if key in ALLOWED_RULES:
                rules = spec[key]
                if not isinstance(rules, list):
                    return "spec.%s must be a list" % key
                for rule in rules:
                    if not isinstance(rule, dict) or any(k not in ALLOWED_RULE_KEYS for k in rule):
                        return "spec.%s rules may only use %s" % (key, ", ".join(sorted(ALLOWED_RULE_KEYS)))
        return None

    def create_cnp(self, ns, body, user, ua, ip):
        err = self.validate_cnp(ns, body)
        name = ((body or {}).get("metadata") or {}).get("name", "")
        if err:
            return 422, status_body(422, "Invalid", 'CiliumNetworkPolicy.cilium.io "%s" is invalid: %s' % (name, err), {"name": name, "kind": "ciliumnetworkpolicies"}), None
        key = "%s/CiliumNetworkPolicy/%s" % (ns, name)
        if self.sd.kv_get(COLLECTION, key) is not None:
            return 409, status_body(409, "AlreadyExists", 'ciliumnetworkpolicies.cilium.io "%s" already exists' % name, {"name": name, "kind": "ciliumnetworkpolicies"}), None
        now = time.time()
        rec = {"_key": key, "kind": "CiliumNetworkPolicy", "namespace": ns, "name": name, "spec_json": json.dumps(body["spec"]),
               "selector_json": json.dumps((body["spec"]["endpointSelector"] or {}).get("matchLabels") or {}), "labels_json": json.dumps(body["metadata"].get("labels") or {}),
               "created_by": user, "created_epoch": now, "resource_version": int(now), "uid": str(uuid.uuid4())}
        self.sd.kv_save(COLLECTION, rec)
        audit_id = self.audit(now, "create", "/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies" % ns, "ciliumnetworkpolicies", ns, name, "cilium.io", "v2", 201, user, ua, ip)
        out = self._cnp_body(rec)
        out["metadata"]["annotations"] = {"zt/auditID": audit_id}
        return 201, out, audit_id

    def get_cnp(self, ns, name):
        r = self.sd.kv_get(COLLECTION, "%s/CiliumNetworkPolicy/%s" % (ns, name))
        if r is None:
            return 404, status_body(404, "NotFound", 'ciliumnetworkpolicies.cilium.io "%s" not found' % name, {"name": name, "kind": "ciliumnetworkpolicies"})
        return 200, self._cnp_body(r)

    def delete_cnp(self, ns, name, user, ua, ip):
        key = "%s/CiliumNetworkPolicy/%s" % (ns, name)
        r = self.sd.kv_get(COLLECTION, key)
        if r is None:
            return 404, status_body(404, "NotFound", 'ciliumnetworkpolicies.cilium.io "%s" not found' % name, {"name": name, "kind": "ciliumnetworkpolicies"}), None
        self.sd.kv_delete(COLLECTION, key)
        now = time.time()
        audit_id = self.audit(now, "delete", "/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies/%s" % (ns, name), "ciliumnetworkpolicies", ns, name, "cilium.io", "v2", 200, user, ua, ip)
        body = {"kind": "Status", "apiVersion": "v1", "metadata": {"annotations": {"zt/auditID": audit_id}}, "status": "Success", "details": {"name": name, "kind": "ciliumnetworkpolicies", "uid": r.get("uid")}, "code": 200}
        return 200, body, audit_id

    def audit(self, now, verb, uri, resource, ns, name, group, version, code, user, ua, ip):
        audit_id = str(uuid.uuid4())
        groups = canon.ENFORCER_GROUPS if user == canon.ENFORCER_USER else ["platform-admins", "system:authenticated"]
        reason = B.ENFORCER_REASON if user == canon.ENFORCER_USER else B.PLATFORM_REASON
        ev = B.k8s_audit(now, audit_id=audit_id, verb=verb, uri=uri, resource=resource, namespace=ns, name=name, api_group=group, api_version=version, code=code, user=user,
                         groups=groups, source_ip=ip, user_agent=ua, reason=reason)
        try:
            self.hec.send([ev])
        except RestError as e:
            log.error("audit event not sent: %s", e)
        return audit_id

    def nexus_config(self, now, device, command, user, ua):
        try:
            self.hec.send([B.nexus_config(now, device, user, command, "+ " + command, ticket="")])
        except RestError as e:
            log.error("nexus config event not sent: %s", e)


def safe(verb):
    """Turn an unexpected exception into a 500 Status response instead of a dropped connection."""
    def wrapper(self):
        try:
            verb(self)
        except Exception as e:  # noqa: BLE001
            log.exception("%s %s failed", self.command, self.path)
            try:
                self._send(500, status_body(500, "InternalError", "%s: %s" % (type(e).__name__, str(e)[:300])))
            except Exception:  # noqa: BLE001
                pass
    return wrapper


class Handler(BaseHTTPRequestHandler):
    server_version = "kube-apiserver/v1.31.2"
    protocol_version = "HTTP/1.1"
    state = None
    tokens = {}

    def log_message(self, fmt, *args):
        log.info("%s %s", self.address_string(), fmt % args)

    # ---- helpers -----------------------------------------------------------
    def _send(self, code, body, audit_id=None):
        data = json.dumps(body).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-cache, private")
        if audit_id:
            self.send_header("Audit-Id", audit_id)
        self.end_headers()
        self.wfile.write(data)

    def _body(self):
        n = int(self.headers.get("Content-Length") or 0)
        raw = self.rfile.read(n) if n else b""
        if not raw:
            return None
        try:
            return json.loads(raw.decode("utf-8"))
        except ValueError:
            return "invalid"

    def _auth(self):
        auth = self.headers.get("Authorization") or ""
        token = auth.split(" ", 1)[1].strip() if auth.lower().startswith("bearer ") else ""
        ident = self.tokens.get(token) if token else None
        if not ident:
            self._send(401, status_body(401, "Unauthorized", "Unauthorized"))
            return None
        return ident

    def _ua(self):
        return self.headers.get("User-Agent") or "unknown"

    def _path(self):
        return self.path.split("?", 1)[0].rstrip("/")

    # ---- verbs --------------------------------------------------------------
    @safe
    def do_GET(self):
        p = self._path()
        if p in ("/version", "/healthz", "/readyz", "/livez"):
            if p == "/version":
                self._send(200, {"major": "1", "minor": "31", "gitVersion": "v1.31.2", "platform": "linux/amd64", "emulator": "zt_incident_demo"})
            else:
                self.send_response(200)
                self.send_header("Content-Type", "text/plain")
                self.send_header("Content-Length", "2")
                self.end_headers()
                self.wfile.write(b"ok")
            return
        ident = self._auth()
        if not ident:
            return
        parts = p.strip("/").split("/")
        if len(parts) == 6 and parts[:2] == ["api", "v1"] and parts[2] == "namespaces" and parts[4] == "pods":
            body, _ = self.state.pod(parts[3], parts[5])
            return self._send(200, body) if body else self._send(404, status_body(404, "NotFound", 'pods "%s" not found' % parts[5]))
        if len(parts) in (6, 7) and parts[:3] == ["apis", "cilium.io", "v2"] and parts[3] == "namespaces" and parts[5] == "ciliumnetworkpolicies":
            if len(parts) == 6:
                return self._send(200, self.state.list_cnp(parts[4]))
            code, body = self.state.get_cnp(parts[4], parts[6])
            return self._send(code, body)
        self._send(404, status_body(404, "NotFound", "the server could not find the requested resource"))

    @safe
    def do_PATCH(self):
        ident = self._auth()
        if not ident:
            return
        parts = self._path().strip("/").split("/")
        body = self._body()
        ctype = (self.headers.get("Content-Type") or "").split(";")[0].strip()
        if ctype not in ("application/merge-patch+json", "application/strategic-merge-patch+json", "application/json"):
            return self._send(415, status_body(415, "UnsupportedMediaType", "the body of the request was in an unknown format - accepted media types include: application/merge-patch+json, application/strategic-merge-patch+json"))
        if body == "invalid" or not isinstance(body, dict):
            return self._send(400, status_body(400, "BadRequest", "invalid patch body"))
        if len(parts) == 6 and parts[:2] == ["api", "v1"] and parts[2] == "namespaces" and parts[4] == "pods":
            code, out, audit_id = self.state.patch_pod(parts[3], parts[5], body, ident["user"], self._ua(), ident["ip"])
            return self._send(code, out, audit_id)
        self._send(404, status_body(404, "NotFound", "the server could not find the requested resource"))

    @safe
    def do_POST(self):
        p = self._path()
        ident = self._auth()
        if not ident:
            return
        body = self._body()
        parts = p.strip("/").split("/")
        if len(parts) == 6 and parts[:3] == ["apis", "cilium.io", "v2"] and parts[3] == "namespaces" and parts[5] == "ciliumnetworkpolicies":
            if body == "invalid":
                return self._send(400, status_body(400, "BadRequest", "invalid JSON body"))
            code, out, audit_id = self.state.create_cnp(parts[4], body, ident["user"], self._ua(), ident["ip"])
            return self._send(code, out, audit_id)
        if p == "/hypershield/v1/rules":
            rule_id = "hs-rule-%s" % uuid.uuid4().hex[:12]
            return self._send(201, {"id": rule_id, "status": "applied", "enforcement_point": "dpu", "rule": body if isinstance(body, dict) else {}})
        if p == "/ins":
            cmds = []
            if isinstance(body, list):
                cmds = [c.get("params", {}).get("cmd", "") for c in body if isinstance(c, dict)]
            elif isinstance(body, dict):
                cmds = [body.get("params", {}).get("cmd", "")]
            device = self.headers.get("X-Nexus-Device") or "dc2-leaf-205"
            for c in cmds:
                if c:
                    self.state.nexus_config(time.time(), device, c, "soar-nxapi", self._ua())
            return self._send(200, [{"jsonrpc": "2.0", "result": {"body": {}, "msg": "Success", "code": "200"}, "id": i + 1} for i in range(max(1, len(cmds)))])
        self._send(404, status_body(404, "NotFound", "the server could not find the requested resource"))

    @safe
    def do_DELETE(self):
        ident = self._auth()
        if not ident:
            return
        parts = self._path().strip("/").split("/")
        if len(parts) == 7 and parts[:3] == ["apis", "cilium.io", "v2"] and parts[3] == "namespaces" and parts[5] == "ciliumnetworkpolicies":
            code, out, audit_id = self.state.delete_cnp(parts[4], parts[6], ident["user"], self._ua(), ident["ip"])
            return self._send(code, out, audit_id)
        self._send(404, status_body(404, "NotFound", "the server could not find the requested resource"))


def port_in_use(bind, port):
    with socket.socket() as s:
        s.settimeout(1)
        return s.connect_ex((bind, port)) == 0


def main():
    load_env()
    bind = os.environ.get("ZT_EMULATOR_BIND", "127.0.0.1")
    port = int(os.environ.get("ZT_EMULATOR_PORT", "6443"))
    logpath = os.environ.get("ZT_EMULATOR_LOG")
    handlers = [logging.FileHandler(logpath)] if logpath else [logging.StreamHandler()]
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s", handlers=handlers)
    if port_in_use(bind, port):
        log.info("port %s:%d already served; exiting", bind, port)
        return 0
    cert, key = os.environ.get("ZT_EMULATOR_CERT"), os.environ.get("ZT_EMULATOR_KEY")
    if not (cert and key and os.path.exists(cert) and os.path.exists(key)):
        log.error("certificate/key missing (ZT_EMULATOR_CERT / ZT_EMULATOR_KEY); run make secrets")
        return 1
    enforcer, platform = os.environ.get("ZT_K8S_ENFORCER_TOKEN"), os.environ.get("ZT_K8S_PLATFORM_TOKEN")
    if not (enforcer and platform):
        log.error("bearer tokens missing (ZT_K8S_ENFORCER_TOKEN / ZT_K8S_PLATFORM_TOKEN); run make secrets")
        return 1
    Handler.tokens = {enforcer: {"user": canon.ENFORCER_USER, "ip": canon.ENFORCER_SOURCE_IP}, platform: {"user": canon.PLATFORM_USER, "ip": "10.40.2.44"}}
    token = os.environ.get("ZT_EMULATOR_SPLUNK_TOKEN")
    verify = os.environ.get("SPLUNK_VERIFY", "1").lower() not in ("0", "false", "no")
    sd = Splunkd(os.environ["SPLUNK_URL"], token=token, basic=None if token else (os.environ.get("SPLUNK_USER"), os.environ.get("SPLUNK_PASS")), verify=verify)
    hec = Hec(os.environ["SPLUNK_HEC_URL"], os.environ["SPLUNK_HEC_TOKEN"], verify=verify)
    Handler.state = State(sd, hec)
    srv = ThreadingHTTPServer((bind, port), Handler)
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(cert, key)
    srv.socket = ctx.wrap_socket(srv.socket, server_side=True)
    log.info("Kubernetes API emulator listening on https://%s:%d", bind, port)
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass
    return 0


if __name__ == "__main__":
    sys.exit(main())
