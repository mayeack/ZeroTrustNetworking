"""Threaded HTTP server (standard library): JSON API, server-sent events for the live feed, static UI."""
import json
import logging
import mimetypes
import os
import queue
import time
import urllib.parse
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

log = logging.getLogger("ztlive.http")
STATIC = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "static")


def make_handler(engine):
    class Handler(BaseHTTPRequestHandler):
        server_version = "zt-live/1.0"

        def log_message(self, fmt, *args):  # quieter access log; errors arrive as ("code %d, message %s", code, text)
            line = (fmt % args) if args else str(fmt)
            if "/api/stream" not in line:
                log.debug(line)

        # ---- helpers
        def _json(self, code, obj):
            body = json.dumps(obj, default=str).encode()
            self.send_response(code)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)

        def _body(self):
            n = int(self.headers.get("Content-Length") or 0)
            raw = self.rfile.read(n) if n else b""
            if not raw:
                return {}
            try:
                return json.loads(raw.decode("utf-8"))
            except ValueError:
                return {"_raw": raw.decode("utf-8", "replace")}

        def _static(self, path):
            path = "/index.html" if path in ("", "/") else path
            full = os.path.normpath(os.path.join(STATIC, path.lstrip("/")))
            if not full.startswith(STATIC) or not os.path.isfile(full):
                self.send_error(404)
                return
            ctype = mimetypes.guess_type(full)[0] or "application/octet-stream"
            with open(full, "rb") as fh:
                data = fh.read()
            self.send_response(200)
            self.send_header("Content-Type", ctype + ("; charset=utf-8" if ctype.startswith("text/") or "javascript" in ctype else ""))
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-cache")
            self.end_headers()
            self.wfile.write(data)

        # ---- routes
        def do_GET(self):
            u = urllib.parse.urlsplit(self.path)
            q = dict(urllib.parse.parse_qsl(u.query))
            try:
                if u.path == "/api/status":
                    return self._json(200, engine.status(with_health=q.get("health") == "1"))
                if u.path == "/api/events":
                    return self._json(200, engine.recent(int(q.get("since") or 0), int(q.get("limit") or 500)))
                if u.path == "/api/pipeline":
                    return self._json(200, dict(engine.pipeline, at=engine.pipeline_at))
                if u.path == "/api/catalog":
                    return self._json(200, engine.catalog())
                if u.path == "/api/attacks":
                    return self._json(200, engine.attacks())
                if u.path == "/api/state":
                    return self._json(200, engine.state())
                if u.path == "/api/stream":
                    return self._stream()
                if u.path.startswith("/api/"):
                    return self._json(404, {"error": "no such endpoint"})
                return self._static(u.path)
            except Exception as e:  # noqa: BLE001
                log.exception("GET %s failed", u.path)
                return self._json(500, {"error": str(e)[:400]})

        def do_POST(self):
            u = urllib.parse.urlsplit(self.path)
            body = self._body()
            try:
                if u.path == "/api/fire":
                    return self._json(200, engine.fire())
                if u.path == "/api/reset":
                    return self._json(200, engine.reset())
                if u.path == "/api/speed":
                    return self._json(200, engine.set_speed(body.get("value", "fast")))
                if u.path == "/api/config":
                    return self._json(200, engine.set_config(**{k: v for k, v in body.items() if k in ("response_mode", "agent_mode")}))
                if u.path.startswith("/api/trigger/"):
                    return self._json(200, engine.trigger(u.path.split("/")[3], body))
                if u.path.startswith("/api/attacks/") and u.path.endswith("/stop"):
                    key = urllib.parse.unquote(u.path[len("/api/attacks/"):-len("/stop")])
                    return self._json(200, engine.stop_attack(key))
                return self._json(404, {"error": "no such endpoint"})
            except ValueError as e:
                return self._json(400, {"error": str(e)})
            except Exception as e:  # noqa: BLE001
                log.exception("POST %s failed", u.path)
                return self._json(500, {"error": str(e)[:400]})

        def _stream(self):
            q = engine.subscribe()
            try:
                self.send_response(200)
                self.send_header("Content-Type", "text/event-stream")
                self.send_header("Cache-Control", "no-cache")
                self.send_header("Connection", "keep-alive")
                self.end_headers()
                self.wfile.write(b"retry: 3000\n\n")
                self.wfile.flush()
                last = time.time()
                while True:
                    try:
                        line = q.get(timeout=1.0)
                        self.wfile.write(("data: %s\n\n" % line).encode())
                        self.wfile.flush()
                    except queue.Empty:
                        if time.time() - last > 15:
                            self.wfile.write(b": keepalive\n\n")
                            self.wfile.flush()
                            last = time.time()
            except (BrokenPipeError, ConnectionResetError, OSError):
                pass
            finally:
                engine.unsubscribe(q)

    return Handler


def serve(engine, host="127.0.0.1", port=8890):
    httpd = ThreadingHTTPServer((host, port), make_handler(engine))
    httpd.daemon_threads = True
    log.info("listening on http://%s:%d", host, port)
    try:
        httpd.serve_forever()
    finally:
        httpd.server_close()
