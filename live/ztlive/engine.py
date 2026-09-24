"""The live generator engine: streams the estate's background and the incident from this machine through the same
ztgen code the search head runs, taps every event for the browser, runs triggers, and follows the incident in Splunk."""
import json
import logging
import os
import queue
import socket
import ssl
import threading
import time
import urllib.parse
import urllib.request
from collections import deque

from ztgen import actions, attacks as A, canon, state as ST
from ztgen.estate import STORES, ROLE_LABELS, get_estate
from ztgen.k8s_client import K8s
from ztgen.restclient import Hec, RestError, Splunkd
from ztgen.streamer import Streamer

log = logging.getLogger("ztlive")
TICK_SECONDS = 4
PIPELINE_SECONDS = 20
LEASE_APP_VERSION = (1, 0, 3)     # the search head streamer honours the lease from this app version on
SCRIPT_INPUT = "$SPLUNK_HOME/etc/apps/zt_incident_demo/bin/zt_stream.py"
SUMMARY_LIMIT = 3000


def summarize(env):
    """One line for the browser from an event envelope."""
    st, ev = env.get("sourcetype", ""), env.get("event", {})
    try:
        if st == "cilium:hubble:flow":
            f = ev["flow"]
            src, dst = f.get("source", {}), f.get("destination", {})
            l4 = next(iter(f.get("l4", {}).values()), {})
            return "%s %s %s/%s -> %s/%s:%s" % (f.get("verdict"), f.get("traffic_direction", "")[:3], src.get("namespace"), src.get("pod_name"), dst.get("namespace"), dst.get("pod_name") or "world", l4.get("destination_port"))
        if st == "cisco:isovalent:processExec":
            p = ev["process_exec"]["process"]
            return "exec %s %s (%s)" % (p.get("binary"), (p.get("arguments") or "")[:60], p.get("pod", {}).get("name"))
        if st == "cisco:isovalent:processConnect":
            b = ev["process_connect"]
            return "connect %s -> %s:%s (%s)" % (b["process"].get("binary"), b.get("destination_pod", {}).get("name"), b.get("destination_port"), b["process"].get("pod", {}).get("name"))
        if st == "cisco:isovalent":
            b = ev["process_kprobe"]
            return "kprobe %s %s policy %s" % (b.get("action"), b["process"].get("binary"), b.get("policy_name"))
        if st == "ci:job:event":
            return "CI job %s %s (%s)" % (ev.get("build_id"), ev.get("build_status"), ev.get("project_path"))
        if st == "cisco:nexus:endpoint":
            return "endpoint snapshot %s %s" % (ev.get("switch") or ev.get("device"), ev.get("interface") or "")
        if st == "cisco:nexus:liveprotect":
            return "Live Protect %s %s %s" % (ev.get("switch") or ev.get("device"), ev.get("advisory_id") or ev.get("advisory"), ev.get("status") or "")
        if st == "cisco:nexus:config":
            return "config %s by %s: %s" % (ev.get("device"), ev.get("user"), (ev.get("change") or "")[:70])
        if st == "kube:apiserver:audit":
            return "k8s %s %s/%s %s" % (ev.get("verb"), ev.get("objectRef", {}).get("resource"), ev.get("objectRef", {}).get("name"), ev.get("responseStatus", {}).get("code"))
        if st == "zt:enforcement:audit":
            return "%s %s %s (%s)" % (ev.get("state"), ev.get("request_id"), (ev.get("action") or "")[:50], ev.get("approved_by_label") or ev.get("approved_by") or "")
    except (KeyError, TypeError, AttributeError):
        pass
    return json.dumps(ev)[:90]


class TapHec(Hec):
    """HEC client that hands every sent event to the engine after it has been accepted."""
    def __init__(self, url, token, verify, tap):
        super().__init__(url, token, verify=verify)
        self.tap = tap

    def send(self, events, batch=500, retries=5):
        evs = list(events)
        n = super().send(evs, batch, retries)
        self.tap(evs)
        return n


class Engine:
    def __init__(self, env):
        self.env = env
        self.started = time.time()
        self.owner = "live:%s:%d" % (socket.gethostname().split(".")[0], os.getpid())
        verify = str(env.get("SPLUNK_VERIFY", "1")).lower() not in ("0", "false", "no")
        self.sd = Splunkd(env["SPLUNK_URL"], basic=(env["SPLUNK_USER"], env["SPLUNK_PASS"]), verify=verify)
        self.cfg = ST.config(self.sd)
        token = self.sd.hec_token(self.cfg["hec"]["token_name"]) or env.get("SPLUNK_HEC_TOKEN")
        if not token:
            raise RestError(404, "HEC token not found", "data/inputs/http")
        self.hec = TapHec(self.cfg["hec"]["url"], token, self.cfg["hec"]["verify_tls"], self._tap)
        self.estate = get_estate()
        self.streamer = Streamer(self.sd, self.hec, self.cfg)
        self.events = deque(maxlen=SUMMARY_LIMIT)
        self.seq = 0
        self.subscribers = []
        self.lock = threading.Lock()
        self.state_lock = threading.Lock()  # a tick loads the state at its start and saves it at its end
        self.last_tick = {}
        self.last_error = ""
        self.tick_count = 0
        self.pipeline = {"incident": None, "attacks": []}
        self.pipeline_at = 0
        self.stack_version = self._stack_version()
        self.paused_input = False
        self.stop_flag = threading.Event()
        self.threads = []
        self.counts = {}
        self.attack_pods = set()

    # ---- lifecycle -------------------------------------------------------------
    def start(self):
        if self.stack_version < LEASE_APP_VERSION:
            self._set_input(disabled=True)
        self.threads = [threading.Thread(target=self._tick_loop, name="tick", daemon=True), threading.Thread(target=self._pipeline_loop, name="pipeline", daemon=True)]
        for t in self.threads:
            t.start()
        log.info("engine started as %s (stack app %s)", self.owner, ".".join(map(str, self.stack_version)))

    def stop(self):
        self.stop_flag.set()
        for t in self.threads:
            t.join(timeout=10)
        try:
            self.streamer.release_lease(self.owner)
        except Exception as e:  # noqa: BLE001
            log.warning("lease release failed: %s", e)
        if self.paused_input:
            self._set_input(disabled=False)
        log.info("engine stopped")

    def _stack_version(self):
        try:
            e = self.sd.get("services/apps/local/zt_incident_demo", params={"output_mode": "json"})
            v = e["entry"][0]["content"].get("version", "0")
            return tuple(int(x) for x in v.split(".")[:3])
        except Exception:  # noqa: BLE001
            return (0, 0, 0)

    def _set_input(self, disabled):
        path = "servicesNS/nobody/zt_incident_demo/data/inputs/script/%s/%s" % (urllib.parse.quote(SCRIPT_INPUT, safe=""), "disable" if disabled else "enable")
        try:
            self.sd.post(path)
            self.paused_input = disabled
            log.info("search head streamer %s", "paused" if disabled else "resumed")
        except RestError as e:
            log.warning("could not %s the search head input: %s", "disable" if disabled else "enable", e)

    # ---- streaming --------------------------------------------------------------
    def _tick_loop(self):
        while not self.stop_flag.is_set():
            t = time.time()
            try:
                with self.state_lock:
                    self.last_tick = self.streamer.tick(owner=self.owner)
                self.tick_count += 1
                self.last_error = ""
            except Exception as e:  # noqa: BLE001
                self.last_error = str(e)[:300]
                log.error("tick failed: %s", e)
            self.stop_flag.wait(max(0.5, TICK_SECONDS - (time.time() - t)))

    def _kind(self, env):
        ev = env.get("event", {})
        text = json.dumps(ev)[:4000] if ev else ""
        if canon.RUNNER_POD in text or '"build_id": %d' % canon.CI_JOB_ID in text or '"build_id":%d' % canon.CI_JOB_ID in text:
            return "incident"
        for pod in self.attack_pods:
            if pod in text:
                return "attack"
        return "background"

    def _tap(self, envs):
        kind_override = getattr(threading.current_thread(), "zt_kind", None)
        now = time.time()
        with self.lock:
            for env in envs:
                self.seq += 1
                st = env.get("sourcetype", "")
                item = {"seq": self.seq, "t": float(env.get("time", now)), "sent": now, "sourcetype": st, "host": env.get("host", ""), "kind": kind_override or self._kind(env), "summary": summarize(env)}
                self.events.append(item)
                self.counts[st] = self.counts.get(st, 0) + 1
                line = json.dumps(item)
                for q in list(self.subscribers):
                    try:
                        q.put_nowait(line)
                    except queue.Full:
                        pass

    def subscribe(self):
        q = queue.Queue(maxsize=5000)
        with self.lock:
            self.subscribers.append(q)
        return q

    def unsubscribe(self, q):
        with self.lock:
            if q in self.subscribers:
                self.subscribers.remove(q)

    def recent(self, since=0, limit=500):
        with self.lock:
            items = [e for e in self.events if e["seq"] > since]
        return items[-limit:]

    # ---- actions ------------------------------------------------------------------
    def _run(self, kind, fn, *args, **kw):
        threading.current_thread().zt_kind = kind
        try:
            with self.state_lock:
                return fn(*args, **kw)
        finally:
            threading.current_thread().zt_kind = None

    def fire(self):
        return self._run("incident", actions.fire, self.sd, self.hec, self.cfg)

    def reset(self):
        out = self._run("incident", actions.reset, self.sd, self.hec, self.cfg, user_agent="zt-live-reset/1.0")
        self.attack_pods = set()
        return out

    def state(self):
        return ST.load(self.sd)

    def set_config(self, **values):
        allowed = {"response_mode": ("local", "soar"), "agent_mode": ("mcp", "inline")}
        for k, v in values.items():
            if k not in allowed or v not in allowed[k]:
                raise ValueError("%s must be one of %s" % (k, ", ".join(allowed.get(k, ()))))
        with self.state_lock:
            st = ST.load(self.sd)
            st.update(values)
            ST.save(self.sd, st)
        self.sd.conf_set("zt_demo", "modes", {k: v for k, v in values.items()})
        return {k: st[k] for k in allowed}

    def set_speed(self, value):
        rows = self.sd.search("| ztdemo action=speed value=%s" % ("fast" if value == "fast" else "normal"), earliest="-1m", latest="now", timeout=120)
        return rows[0] if rows else {"result": "no answer"}

    def trigger(self, kind, params):
        p = params or {}
        src, dest = p.get("src_workload"), p.get("dest_workload") or canon.STORE_WORKLOAD
        if kind == "path_attack":
            rec, n = self._run("attack", A.start, self.sd, self.hec, self.estate, src, dest, program=p.get("program") or None, max_attempts=int(p.get("max_attempts") or A.MAX_ATTEMPTS))
            self.attack_pods.add(rec["src_pod"])
            return {"result": "attack started", "attack": rec, "events": n, "next": "attempts every %ds; risk events at the next detection run, then the finding, the brief and a quarantine request" % canon.ATTEMPT_INTERVAL}
        if kind == "audit_flow":
            n = self._run("trigger", A.audit_flow, self.estate, self.hec, src, dest)
            return {"result": "audit-mode connection sent", "events": n, "next": "one risk event (50) for %s at the next run of the audit-flow detection; the path shows as unprotected on the posture dashboard" % src}
        if kind == "program_connect":
            n = self._run("trigger", A.program_connect, self.estate, self.hec, src, dest, p.get("program") or "/usr/bin/curl")
            return {"result": "unapproved program connect sent", "events": n, "next": "one risk event (40) for %s at the next run of the program detection" % src}
        if kind == "liveprotect":
            n = self._run("trigger", A.liveprotect, self.estate, self.hec, p.get("switch") or canon.RUNNER_SWITCH)
            return {"result": "Live Protect event sent", "events": n, "next": "counts on the Incident Timeline's Live Protect tile"}
        if kind == "nexus_config":
            n = self._run("trigger", A.nexus_config, self.estate, self.hec, p.get("device") or canon.RUNNER_SWITCH, p.get("user") or "netops-cli", p.get("change") or "interface Eth1/12 description zt-live", ticket=p.get("ticket") or "")
            return {"result": "Nexus config change sent", "events": n, "next": "counts on the Nexus switch data tile"}
        if kind == "enforcement":
            req_id, n = self._run("trigger", A.enforcement, self.estate, self.hec, self.sd, p.get("point") or "kernel", p.get("target_workload") or src, p.get("approved_by") or "j.chen", p.get("comment") or "Sent from the live generator")
            return {"result": "enforcement %s recorded" % req_id, "events": n, "next": "shows in the enforcement audit trail and adds one to the posture's enforcement actions"}
        raise ValueError("unknown trigger %s" % kind)

    def attacks(self):
        recs = A.all_attacks(self.sd)[:20]
        self.attack_pods = {r["src_pod"] for r in recs if r.get("status") == "running"} | self.attack_pods
        return recs

    def stop_attack(self, key):
        with self.state_lock:
            return A.stop(self.sd, key)

    # ---- catalog / status / pipeline ---------------------------------------------------
    def catalog(self):
        wl = []
        for key, w in sorted(self.estate.workloads.items()):
            if key in STORES or key == canon.RUNNER_WORKLOAD or not w.pods:
                continue
            wl.append({"key": key, "pod": w.pods[0].name, "node": w.pods[0].node, "identity": w.identity})
        switches = sorted({n.switch for n in self.estate.nodes.values()})
        return {"workloads": wl, "stores": [{"key": k, "port": v["port"], "data_class": v["data_class"]} for k, v in STORES.items()],
                "programs": A.PROGRAMS, "switches": switches, "approvers": [{"user": u, "label": l} for u, l in ROLE_LABELS], "points": ["kernel", "dpu", "switch"],
                "known_gaps": [k for k in []]}

    def health(self):
        out = {}
        try:
            k = K8s(self.cfg["emulator"]["url"], self.env.get("ZT_K8S_ENFORCER_TOKEN", ""), verify=self.cfg["emulator"]["verify_tls"], user_agent="zt-live/1.0", timeout=8)
            st, body = k.call("GET", "/version")
            out["emulator"] = "HTTP %s %s" % (st, body.get("gitVersion", ""))
        except Exception as e:  # noqa: BLE001
            out["emulator"] = "unreachable: %s" % str(e)[:80]
        try:
            ctx = ssl.create_default_context()
            req = urllib.request.Request(self.cfg["hec"]["url"].rstrip("/") + "/services/collector/health", headers={"User-Agent": "zt-live/1.0"})
            with urllib.request.urlopen(req, timeout=8, context=ctx) as r:
                out["hec"] = "HTTP %s" % r.status
        except Exception as e:  # noqa: BLE001
            out["hec"] = "unreachable: %s" % str(e)[:80]
        return out

    def status(self, with_health=False):
        st = ST.load(self.sd)
        now = time.time()
        with self.lock:
            minute = [e for e in self.events if e["sent"] >= now - 60]
            per_min = {}
            for e in minute:
                per_min[e["sourcetype"]] = per_min.get(e["sourcetype"], 0) + 1
            counts = dict(self.counts)
        holder, held = st.get("stream_owner") or "", float(st.get("stream_owner_epoch") or 0)
        out = {"now": now, "owner": self.owner, "uptime_s": int(now - self.started), "tick_count": self.tick_count, "last_tick": self.last_tick, "last_error": self.last_error,
               "stack_version": ".".join(map(str, self.stack_version)), "search_head_input_paused": self.paused_input, "lease": {"holder": holder, "age_s": int(now - held) if held else None, "mine": holder == self.owner},
               "state": {k: st.get(k) for k in ("plan_status", "plan_attempt", "plan_dropped_attempts", "plan_t0", "last_fire_epoch", "last_reset_epoch", "speed", "response_mode", "agent_mode", "stream_checkpoint", "backfill_done", "last_error")},
               "checkpoint_age_s": int(now - float(st.get("stream_checkpoint") or now)), "events_total": sum(counts.values()), "counts_total": counts, "counts_last_minute": per_min,
               "subscribers": len(self.subscribers), "hec_url": self.cfg["hec"]["url"], "emulator_url": self.cfg["emulator"]["url"], "splunk_url": self.env["SPLUNK_URL"], "pipeline_at": self.pipeline_at}
        if with_health:
            out["health"] = self.health()
        return out

    def _pipeline_loop(self):
        while not self.stop_flag.is_set():
            try:
                self.pipeline = {"incident": self._incident_pipeline(), "attacks": [self._attack_pipeline(r) for r in A.all_attacks(self.sd)[:3]]}
                self.pipeline_at = time.time()
            except Exception as e:  # noqa: BLE001
                log.warning("pipeline poll failed: %s", e)
            self.stop_flag.wait(PIPELINE_SECONDS)

    def _milestones(self, t0, workload, pod, job_filter):
        t = int(t0) - 60
        spl = ('| makeresults | eval k=1 | fields k'
               ' | appendcols [search index=risk earliest=%d source="ZT - *" risk_object="%s" | stats count as risk_count sum(risk_score) as risk_total min(_time) as risk_at]'
               ' | appendcols [search earliest=%d `notable` | search source="%s" risk_object="%s" | stats count as finding_count min(_time) as finding_at latest(risk_score) as finding_risk]'
               ' | appendcols [| inputlookup zt_agent_briefs_lookup | where run_epoch>=%d AND workload="%s" | stats count as brief_count min(run_epoch) as brief_at latest(investigation_id) as investigation_id latest(disposition) as disposition]'
               ' | appendcols [| inputlookup zt_enforcement_requests_lookup | where requested_epoch>=%d AND pod="%s" | sort - requested_epoch | head 1 | table request_id status requested_epoch applied_epoch verified_epoch approvals]'
               ' | appendcols [search index=zero_trust earliest=%d sourcetype=cilium:hubble:flow src_pod="%s" verdict=DROPPED | stats count as dropped min(_time) as first_drop]'
               '%s') % (t, workload, t, canon.RULE_FBD, workload, int(t0), workload, int(t0), pod, t, pod, job_filter)
        rows = self.sd.search(spl, earliest="-24h", latest="now", timeout=120)
        return rows[0] if rows else {}

    def _incident_pipeline(self):
        st = ST.load(self.sd)
        t0 = float(st.get("last_fire_epoch") or 0)
        if not t0 or t0 < float(st.get("last_reset_epoch") or 0):
            return None
        row = self._milestones(t0, canon.RUNNER_WORKLOAD, canon.RUNNER_POD, ' | appendcols [search index=zero_trust earliest=%d sourcetype=ci:job:event build_id=%d | stats latest(build_status) as job_status latest(build_failure_reason) as job_failure]' % (int(t0) - 60, canon.CI_JOB_ID))
        row.update({"t0": t0, "workload": canon.RUNNER_WORKLOAD, "pod": canon.RUNNER_POD, "plan_status": st.get("plan_status"), "attempt": st.get("plan_attempt"), "dropped_attempts": st.get("plan_dropped_attempts")})
        return row

    def _attack_pipeline(self, rec):
        row = self._milestones(float(rec["t0"]), rec["src_workload"], rec["src_pod"], "")
        row.update({"t0": float(rec["t0"]), "workload": rec["src_workload"], "pod": rec["src_pod"], "dest_workload": rec["dest_workload"], "status": rec.get("status"), "attempt": rec.get("attempt"), "dropped_attempts": rec.get("dropped_attempts"), "key": rec["_key"]})
        return row
