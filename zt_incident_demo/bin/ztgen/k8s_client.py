"""Client for the Kubernetes API emulator (the same calls a playbook makes against a real API server)."""
import json
import ssl
import urllib.error
import urllib.request

from . import canon


class K8sError(Exception):
    def __init__(self, status, body):
        super().__init__("Kubernetes API %s: %s" % (status, (body or "")[:300]))
        self.status, self.body = status, body


class K8s:
    def __init__(self, url, token, verify=True, user_agent="ztdemo/1.0", timeout=30):
        self.url = url.rstrip("/")
        self.token, self.user_agent, self.timeout = token, user_agent, timeout
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def call(self, method, path, body=None, content_type="application/json"):
        data = json.dumps(body).encode() if body is not None else None
        headers = {"Authorization": "Bearer " + self.token, "Accept": "application/json", "User-Agent": self.user_agent}
        if data is not None:
            headers["Content-Type"] = content_type
        req = urllib.request.Request(self.url + path, data=data, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                text = resp.read().decode("utf-8", "replace")
                return resp.status, (json.loads(text) if text else {})
        except urllib.error.HTTPError as e:
            text = e.read().decode("utf-8", "replace")
            try:
                return e.code, json.loads(text)
            except ValueError:
                return e.code, {"message": text}
        except urllib.error.URLError as e:
            raise K8sError(0, str(e))

    def version(self):
        return self.call("GET", "/version")

    def get_pod(self, ns, name):
        return self.call("GET", "/api/v1/namespaces/%s/pods/%s" % (ns, name))

    def patch_pod_labels(self, ns, name, labels):
        return self.call("PATCH", "/api/v1/namespaces/%s/pods/%s" % (ns, name), {"metadata": {"labels": labels}}, "application/merge-patch+json")

    def list_cnp(self, ns):
        return self.call("GET", "/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies" % ns)

    def create_cnp(self, ns, cnp):
        return self.call("POST", "/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies" % ns, cnp)

    def delete_cnp(self, ns, name):
        return self.call("DELETE", "/apis/cilium.io/v2/namespaces/%s/ciliumnetworkpolicies/%s" % (ns, name))

    def release_quarantine(self, ns=canon.RUNNER_NS, pod=canon.RUNNER_POD, label_key=canon.QUARANTINE_LABEL_KEY):
        """Delete every CNP selecting the quarantine label and remove the label. Returns (deleted policy names, audit ids)."""
        deleted, audit_ids = [], []
        st, lst = self.list_cnp(ns)
        for item in (lst.get("items") or []) if st == 200 else []:
            sel = ((item.get("spec") or {}).get("endpointSelector") or {}).get("matchLabels") or {}
            if label_key in sel:
                st2, body = self.delete_cnp(ns, item["metadata"]["name"])
                if st2 in (200, 202):
                    deleted.append(item["metadata"]["name"])
                    audit_ids.append((body.get("metadata") or {}).get("annotations", {}).get("zt/auditID") or body.get("auditID", ""))
        st3, pod_body = self.patch_pod_labels(ns, pod, {label_key: None})
        if st3 == 200:
            audit_ids.append((pod_body.get("metadata") or {}).get("annotations", {}).get("zt/auditID", ""))
        return deleted, [a for a in audit_ids if a]
