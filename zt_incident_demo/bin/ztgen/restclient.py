"""Minimal splunkd / KV store / HEC client for code running inside Splunk (scripted input, custom commands,
REST handler) and for the standalone emulator. Standard library only."""
import json
import logging
import ssl
import time
import urllib.error
import urllib.parse
import urllib.request

log = logging.getLogger("ztgen.rest")


class RestError(Exception):
    def __init__(self, status, body, url):
        super().__init__("HTTP %s from %s: %s" % (status, url, (body or "")[:500]))
        self.status, self.body, self.url = status, body, url


class Splunkd:
    """splunkd REST with a session key or a bearer token. app = namespace for KV, conf and passwords."""

    def __init__(self, uri="https://127.0.0.1:8089", session_key=None, token=None, basic=None, app="zt_incident_demo", verify=False, timeout=60):
        self.uri = uri.rstrip("/")
        self.session_key, self.token, self.basic, self.app, self.timeout = session_key, token, basic, app, timeout
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _headers(self):
        if self.session_key:
            return {"Authorization": "Splunk " + self.session_key}
        if self.token:
            return {"Authorization": "Bearer " + self.token}
        if self.basic:
            import base64
            return {"Authorization": "Basic " + base64.b64encode(("%s:%s" % self.basic).encode()).decode()}
        return {}

    def request(self, method, path, params=None, data=None, json_body=None, raw=False, retries=2):
        url = self.uri + "/" + path.lstrip("/")
        params = dict(params or {})
        if not raw and json_body is None and "output_mode" not in params:
            params["output_mode"] = "json"
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        headers = self._headers()
        body = None
        if json_body is not None:
            body = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode() if isinstance(data, dict) else data
            headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
        req = urllib.request.Request(url, data=body, method=method, headers=headers)
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    payload = resp.read().decode("utf-8", "replace")
                    if raw:
                        return resp.status, payload
                    return json.loads(payload) if payload else {}
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if raw:
                    return e.code, text
                if e.code in (502, 503, 504) and attempt < retries:
                    attempt += 1
                    time.sleep(1.5 * attempt)
                    continue
                raise RestError(e.code, text, url)
            except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
                if attempt < retries:
                    attempt += 1
                    time.sleep(1.5 * attempt)
                    continue
                raise RestError(0, str(e), url)

    def get(self, path, params=None, **kw):
        return self.request("GET", path, params=params, **kw)

    def post(self, path, data=None, json_body=None, params=None, **kw):
        return self.request("POST", path, params=params, data=data, json_body=json_body, **kw)

    def delete(self, path, params=None, **kw):
        return self.request("DELETE", path, params=params, **kw)

    def ns(self, path, owner="nobody", app=None):
        return "servicesNS/%s/%s/%s" % (owner, app or self.app, path.lstrip("/"))

    # --- conf ---------------------------------------------------------------
    def conf(self, conf, stanza):
        try:
            d = self.get(self.ns("configs/conf-%s/%s" % (conf, urllib.parse.quote(stanza, safe=""))))
        except RestError as e:
            if e.status == 404:
                return {}
            raise
        ent = d.get("entry") or []
        return {k: v for k, v in (ent[0]["content"].items() if ent else []) if not k.startswith("eai:")}

    def conf_set(self, conf, stanza, values):
        base = self.ns("configs/conf-%s" % conf)
        st, _ = self.request("GET", base + "/" + urllib.parse.quote(stanza, safe=""), raw=True)
        if st == 404:
            d = dict(values)
            d["name"] = stanza
            return self.post(base, data=d)
        return self.post(base + "/" + urllib.parse.quote(stanza, safe=""), data=values)

    # --- KV ----------------------------------------------------------------
    def kv_path(self, collection):
        return self.ns("storage/collections/data/%s" % collection)

    def kv_get(self, collection, key):
        st, body = self.request("GET", self.kv_path(collection) + "/" + urllib.parse.quote(key, safe=""), raw=True)
        if st == 404:
            return None
        if st >= 400:
            raise RestError(st, body, collection)
        return json.loads(body)

    def kv_query(self, collection, query=None, **params):
        p = dict(params)
        if query is not None:
            p["query"] = json.dumps(query)
        return self.get(self.kv_path(collection), params=p)

    def kv_save(self, collection, record):
        """Insert or replace by _key."""
        key = record.get("_key")
        if key is not None:
            st, body = self.request("POST", self.kv_path(collection) + "/" + urllib.parse.quote(key, safe=""), json_body=record, raw=True)
            if st == 404:
                st, body = self.request("POST", self.kv_path(collection), json_body=record, raw=True)
        else:
            st, body = self.request("POST", self.kv_path(collection), json_body=record, raw=True)
        if st >= 400:
            raise RestError(st, body, collection)
        return json.loads(body) if body else {}

    def kv_delete(self, collection, key=None, query=None):
        if key is not None:
            st, body = self.request("DELETE", self.kv_path(collection) + "/" + urllib.parse.quote(key, safe=""), raw=True)
        else:
            p = {"query": json.dumps(query)} if query is not None else None
            st, body = self.request("DELETE", self.kv_path(collection), params=p, raw=True)
        if st >= 400 and st != 404:
            raise RestError(st, body, collection)

    # --- passwords ----------------------------------------------------------
    def password(self, realm, name):
        st, body = self.request("GET", self.ns("storage/passwords/%s" % urllib.parse.quote("%s:%s:" % (realm, name), safe="")), raw=True, params={"output_mode": "json"})
        if st != 200:
            return None
        ent = json.loads(body).get("entry") or []
        return ent[0]["content"].get("clear_password") if ent else None

    # --- HEC token ----------------------------------------------------------
    def hec_token(self, name="zt_incident_demo"):
        d = self.get("services/data/inputs/http", params={"count": 0})
        for e in d.get("entry", []):
            if e["name"] == "http://" + name:
                return e["content"]["token"]
        return None

    # --- search ----------------------------------------------------------
    def search(self, spl, earliest="-24h", latest="now", timeout=300):
        if not spl.lstrip().startswith("|") and not spl.lstrip().lower().startswith("search "):
            spl = "search " + spl
        old = self.timeout
        self.timeout = timeout
        try:
            st, body = self.request("POST", "services/search/jobs/export", data={"search": spl, "earliest_time": earliest, "latest_time": latest, "output_mode": "json", "preview": "false"}, raw=True)
        finally:
            self.timeout = old
        if st >= 400:
            raise RestError(st, body, "search/jobs/export")
        rows = []
        for line in body.splitlines():
            if line.strip():
                obj = json.loads(line)
                if "result" in obj:
                    rows.append(obj["result"])
        return rows


class Hec:
    def __init__(self, url, token, verify=True, timeout=60):
        self.url = url.rstrip("/") + "/services/collector/event"
        self.token = token
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE
        self.sent = 0

    def send(self, events, batch=500, retries=5):
        """events: iterable of envelopes. Compact JSON, batches of 500, exponential backoff. Returns count sent."""
        buf = []
        n = 0
        for ev in events:
            buf.append(json.dumps(ev, separators=(",", ":")))
            if len(buf) >= batch:
                n += self._post(buf, retries)
                buf = []
        if buf:
            n += self._post(buf, retries)
        self.sent += n
        return n

    def _post(self, lines, retries):
        payload = "\n".join(lines).encode()
        attempt = 0
        while True:
            req = urllib.request.Request(self.url, data=payload, method="POST", headers={"Authorization": "Splunk " + self.token, "Content-Type": "application/json"})
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    resp.read()
                    return len(lines)
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if e.code in (429, 502, 503, 504) and attempt < retries:
                    attempt += 1
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise RestError(e.code, text, self.url)
            except (urllib.error.URLError, ConnectionError, TimeoutError) as e:
                if attempt < retries:
                    attempt += 1
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise RestError(0, str(e), self.url)
