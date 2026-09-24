#!/usr/bin/env python3
"""Small REST client for the demo tooling: Splunk (stack), SOAR and HEC.

Standard library only. Credentials come from the environment or from the
git-ignored local/env file (KEY=VALUE lines). Nothing is ever written back.
"""
import base64
import json
import os
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ENV_FILE = os.environ.get("ZT_ENV_FILE") or os.path.join(ROOT, "local", "env")
if not os.path.isabs(ENV_FILE):
    ENV_FILE = os.path.join(ROOT, ENV_FILE)


def load_env(path=ENV_FILE):
    env = {}
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                line = line.rstrip("\n")
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                env[k.strip()] = v.strip()
    env.update({k: v for k, v in os.environ.items() if k.startswith(("SPLUNK_", "SOAR_", "ZT_"))})
    return env


ENV = load_env()


def env(key, default=None, required=False):
    val = ENV.get(key, default)
    if required and not val:
        sys.exit("missing setting %s (put it in local/env or the environment)" % key)
    return val


def set_env_value(key, value, path=ENV_FILE):
    """Persist a generated value into local/env (0600, git-ignored)."""
    lines = []
    found = False
    if os.path.exists(path):
        with open(path) as fh:
            for line in fh:
                if line.startswith(key + "="):
                    lines.append("%s=%s\n" % (key, value))
                    found = True
                else:
                    lines.append(line)
    if not found:
        lines.append("%s=%s\n" % (key, value))
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, "w") as fh:
        fh.writelines(lines)
    ENV[key] = value


class RestError(Exception):
    def __init__(self, status, body, url):
        super().__init__("HTTP %s from %s: %s" % (status, url, body[:800]))
        self.status = status
        self.body = body
        self.url = url


class Http:
    def __init__(self, base, user=None, password=None, token=None, token_scheme="Bearer", verify=True, timeout=120):
        self.base = base.rstrip("/")
        self.user, self.password, self.token, self.token_scheme = user, password, token, token_scheme
        self.timeout = timeout
        self.ctx = ssl.create_default_context()
        if not verify:
            self.ctx.check_hostname = False
            self.ctx.verify_mode = ssl.CERT_NONE

    def _auth_header(self):
        if self.token:
            return "%s %s" % (self.token_scheme, self.token)
        if self.user is not None:
            raw = ("%s:%s" % (self.user, self.password)).encode()
            return "Basic " + base64.b64encode(raw).decode()
        return None

    def request(self, method, path, params=None, data=None, json_body=None, headers=None, raw=False, retries=2):
        url = path if path.startswith("http") else self.base + "/" + path.lstrip("/")
        if params:
            url += ("&" if "?" in url else "?") + urllib.parse.urlencode(params, doseq=True)
        body = None
        hdrs = {"Accept": "application/json"}
        auth = self._auth_header()
        if auth:
            hdrs["Authorization"] = auth
        if json_body is not None:
            body = json.dumps(json_body).encode()
            hdrs["Content-Type"] = "application/json"
        elif data is not None:
            body = urllib.parse.urlencode(data, doseq=True).encode() if isinstance(data, dict) else (data.encode() if isinstance(data, str) else data)
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
        if headers:
            hdrs.update(headers)
        req = urllib.request.Request(url, data=body, method=method, headers=hdrs)
        attempt = 0
        while True:
            try:
                with urllib.request.urlopen(req, timeout=self.timeout, context=self.ctx) as resp:
                    payload = resp.read()
                    if raw:
                        return resp.status, payload
                    text = payload.decode("utf-8", "replace")
                    if not text:
                        return {}
                    try:
                        return json.loads(text)
                    except ValueError:
                        return text
            except urllib.error.HTTPError as e:
                text = e.read().decode("utf-8", "replace")
                if raw:
                    return e.code, text.encode()
                if e.code in (502, 503, 504) and attempt < retries:
                    attempt += 1
                    time.sleep(2 * attempt)
                    continue
                raise RestError(e.code, text, url)
            except (urllib.error.URLError, TimeoutError, ConnectionError) as e:
                if attempt < retries:
                    attempt += 1
                    time.sleep(2 * attempt)
                    continue
                raise RestError(0, str(e), url)

    def get(self, path, params=None, **kw):
        return self.request("GET", path, params=params, **kw)

    def post(self, path, data=None, json_body=None, params=None, **kw):
        return self.request("POST", path, params=params, data=data, json_body=json_body, **kw)

    def delete(self, path, params=None, **kw):
        return self.request("DELETE", path, params=params, **kw)


class Splunk(Http):
    """Splunk management REST. Defaults to output_mode=json on GET/POST."""

    def __init__(self, base=None, user=None, password=None, token=None, verify=None, app="zt_incident_demo"):
        if verify is None:
            verify = str(env("SPLUNK_VERIFY", "1")).lower() not in ("0", "false", "no")
        super().__init__(base or env("SPLUNK_URL", required=True), user or env("SPLUNK_USER"), password or env("SPLUNK_PASS"), token, "Bearer", verify)
        self.app = app

    def request(self, method, path, params=None, **kw):
        params = dict(params or {})
        if "output_mode" not in params and not kw.get("raw") and "json_body" not in kw:
            params["output_mode"] = "json"
        return super().request(method, path, params=params, **kw)

    def ns(self, path, app=None, owner="nobody"):
        return "servicesNS/%s/%s/%s" % (owner, app or self.app, path.lstrip("/"))

    def entries(self, path, params=None, **kw):
        params = dict(params or {})
        params.setdefault("count", 0)
        data = self.get(path, params=params, **kw)
        return data.get("entry", []) if isinstance(data, dict) else []

    def entry(self, path, params=None):
        ents = self.entries(path, params)
        return ents[0] if ents else None

    def exists(self, path):
        try:
            self.get(path)
            return True
        except RestError as e:
            if e.status == 404:
                return False
            raise

    def search(self, spl, earliest="-24h", latest="now", timeout=600, **params):
        """Blocking search through search/jobs/export; returns a list of result dicts."""
        spl = spl.strip()
        if not spl.startswith("|") and not spl.lower().startswith("search "):
            spl = "search " + spl
        body = {"search": spl, "earliest_time": earliest, "latest_time": latest, "output_mode": "json", "preview": "false"}
        body.update(params)
        old = self.timeout
        self.timeout = timeout
        try:
            status, payload = super().request("POST", "services/search/jobs/export", data=body, raw=True)
        finally:
            self.timeout = old
        text = payload.decode("utf-8", "replace")
        if status >= 400:
            raise RestError(status, text, "search/jobs/export")
        rows = []
        for line in text.splitlines():
            line = line.strip()
            if not line:
                continue
            obj = json.loads(line)
            if "result" in obj:
                rows.append(obj["result"])
            elif obj.get("messages") and any(m.get("type") in ("ERROR", "FATAL") for m in obj["messages"]):
                raise RestError(400, json.dumps(obj["messages"]), spl)
        return rows

    # KV store helpers -----------------------------------------------------
    def kv_path(self, collection, app=None, owner="nobody"):
        return "servicesNS/%s/%s/storage/collections/data/%s" % (owner, app or self.app, collection)

    def kv_list(self, collection, query=None, app=None, **params):
        p = dict(params)
        if query is not None:
            p["query"] = json.dumps(query)
        return self.get(self.kv_path(collection, app), params=p)

    def kv_get(self, collection, key, app=None):
        try:
            return self.get(self.kv_path(collection, app) + "/" + urllib.parse.quote(key, safe=""))
        except RestError as e:
            if e.status == 404:
                return None
            raise

    def kv_upsert(self, collection, record, app=None):
        key = record.get("_key")
        if key and self.kv_get(collection, key, app) is not None:
            return self.post(self.kv_path(collection, app) + "/" + urllib.parse.quote(key, safe=""), json_body=record, params={"output_mode": None})
        return self.post(self.kv_path(collection, app), json_body=record, params={"output_mode": None})

    def kv_batch_save(self, collection, records, app=None):
        out = []
        for i in range(0, len(records), 500):
            out.extend(self.post(self.kv_path(collection, app) + "/batch_save", json_body=records[i:i + 500], params={"output_mode": None}))
        return out

    def kv_delete(self, collection, key=None, query=None, app=None):
        if key is not None:
            return self.delete(self.kv_path(collection, app) + "/" + urllib.parse.quote(key, safe=""))
        p = {"query": json.dumps(query)} if query is not None else None
        return self.delete(self.kv_path(collection, app), params=p)

    # storage/passwords ----------------------------------------------------
    def password_get(self, realm, name, app=None):
        ent = self.entry(self.ns("storage/passwords/%s" % urllib.parse.quote("%s:%s:" % (realm, name), safe=""), app))
        return ent["content"].get("clear_password") if ent else None

    def password_set(self, realm, name, value, app=None):
        path = self.ns("storage/passwords", app)
        key = urllib.parse.quote("%s:%s:" % (realm, name), safe="")
        if self.exists(path + "/" + key):
            return self.post(path + "/" + key, data={"password": value})
        return self.post(path, data={"realm": realm, "name": name, "password": value})


class Soar(Http):
    def __init__(self, base=None, user=None, password=None, verify=True):
        super().__init__(base or env("SOAR_URL", required=True), user or env("SOAR_USER"), password or env("SOAR_PASS"), None, "Bearer", verify)

    def find(self, path, **filters):
        params = {"page_size": 100}
        for k, v in filters.items():
            params["_filter_" + k] = json.dumps(v)
        return self.get("rest/" + path, params=params).get("data", [])


class Hec:
    def __init__(self, base=None, token=None, verify=None):
        if verify is None:
            verify = str(env("SPLUNK_VERIFY", "1")).lower() not in ("0", "false", "no")
        self.base = (base or env("SPLUNK_HEC_URL", required=True)).rstrip("/")
        self.token = token or env("SPLUNK_HEC_TOKEN", required=True)
        self.http = Http(self.base, token=self.token, token_scheme="Splunk", verify=verify, timeout=60)

    def send(self, events, retries=4):
        """events: list of HEC envelopes. Sends in batches of 500 with backoff."""
        sent = 0
        for i in range(0, len(events), 500):
            batch = events[i:i + 500]
            payload = "\n".join(json.dumps(e, separators=(",", ":")) for e in batch)
            attempt = 0
            while True:
                status, body = self.http.request("POST", "services/collector/event", data=payload, headers={"Content-Type": "application/json"}, raw=True, retries=0)
                if status == 200:
                    sent += len(batch)
                    break
                if status in (429, 502, 503, 504, 0) and attempt < retries:
                    attempt += 1
                    time.sleep(min(30, 2 ** attempt))
                    continue
                raise RestError(status, body.decode("utf-8", "replace"), "collector/event")
        return sent


def table(rows, headers):
    widths = [max(len(str(h)), *(len(str(r[i])) for r in rows)) if rows else len(str(h)) for i, h in enumerate(headers)]
    line = "  ".join(str(h).ljust(w) for h, w in zip(headers, widths))
    out = [line, "  ".join("-" * w for w in widths)]
    for r in rows:
        out.append("  ".join(str(c).ljust(w) for c, w in zip(r, widths)))
    return "\n".join(out)


if __name__ == "__main__":
    s = Splunk()
    info = s.entry("services/server/info")["content"]
    print(info["serverName"], info["version"])
