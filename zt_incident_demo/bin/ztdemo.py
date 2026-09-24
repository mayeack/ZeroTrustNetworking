#!/usr/bin/env python3
"""| ztdemo action=status|fire|reset|backfill|speed|config|tick [value=fast|normal] [hours=24] [force=true]
   [agent_mode=mcp|inline] [response_mode=local|soar]"""
import json
import os
import sys
import time
import urllib.parse

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import GeneratingCommand, Configuration, Option, dispatch  # noqa: E402
from ztgen import canon, plan as P, state as ST, builders as B  # noqa: E402
from ztgen.k8s_client import K8s  # noqa: E402
from ztgen.restclient import Splunkd, RestError  # noqa: E402
from ztgen.streamer import Streamer, make_hec, setup_logging  # noqa: E402

FAST = {"default": "* * * * *", "offset": "* * * * *"}
NORMAL = {"default": "*/5 * * * *", "offset": "1-59/5 * * * *"}
OFFSET_SEARCHES = (canon.RULE_FBD, "ZT Response - Request Enforcement", "ZT Response - Verify Enforcement", "ZT Agent - Capture Brief", "ZT Agent - Inline Triage")
ZT_APPS = ("zt_incident_demo", "DA-ESS-zt_incident_demo")


@Configuration(type="reporting")
class ZtDemoCommand(GeneratingCommand):
    action = Option(require=True, validate=None)
    value = Option(require=False, default=None)
    hours = Option(require=False, default="24")
    force = Option(require=False, default="false")
    agent_mode = Option(require=False, default=None)
    response_mode = Option(require=False, default=None)

    def _sd(self):
        si = self._metadata.searchinfo
        return Splunkd(si.splunkd_uri, session_key=si.session_key)

    def generate(self):
        setup_logging()
        sd = self._sd()
        act = (self.action or "").lower()
        try:
            if act == "status":
                yield self.status(sd)
            elif act == "fire":
                yield self.fire(sd)
            elif act == "reset":
                yield self.reset(sd)
            elif act == "backfill":
                yield self.backfill(sd)
            elif act == "tick":
                yield self.tick(sd)
            elif act == "speed":
                yield self.speed(sd, (self.value or "fast").lower())
            elif act == "config":
                yield self.config(sd)
            else:
                yield {"_time": time.time(), "action": act, "result": "unknown action; use status|fire|reset|backfill|speed|config|tick"}
        except (RestError, ValueError) as e:
            yield {"_time": time.time(), "action": act, "result": "error", "message": str(e)}

    # ----------------------------------------------------------------------
    def status(self, sd):
        st = ST.load(sd)
        cfg = ST.config(sd)
        now = time.time()
        row = {"_time": now, "action": "status", "checkpoint_age_s": int(now - float(st["stream_checkpoint"])) if st["stream_checkpoint"] else None,
               "backfill_done": bool(st["backfill_done"]), "plan_status": st["plan_status"], "plan_attempt": st["plan_attempt"], "plan_t0": st["plan_t0"],
               "plan_dropped_attempts": st["plan_dropped_attempts"], "last_reset_epoch": st["last_reset_epoch"], "last_fire_epoch": st["last_fire_epoch"],
               "speed": st["speed"], "agent_mode": st["agent_mode"], "response_mode": st["response_mode"], "last_tick_epoch": st["last_tick_epoch"],
               "last_tick_events": st["last_tick_events"], "last_error": st["last_error"], "hec_url": cfg["hec"]["url"], "emulator_url": cfg["emulator"]["url"]}
        try:
            recs = sd.kv_query("zt_policy_state")
            row["quarantine_policies"] = ",".join(P.policy_names_selecting(recs)) or "none"
            row["quarantine_applied_at"] = P.quarantine_applied_at(recs)
        except RestError as e:
            row["quarantine_policies"] = "kv error: %s" % e
        try:
            rows = sd.search("search index=zero_trust earliest=-60m | stats count by sourcetype", earliest="-60m", latest="now", timeout=120)
            row["events_last_hour"] = "; ".join("%s=%s" % (r["sourcetype"], r["count"]) for r in rows) or "0"
        except RestError as e:
            row["events_last_hour"] = "search error: %s" % str(e)[:120]
        return row

    def fire(self, sd):
        cfg = ST.config(sd)
        s = Streamer(sd, make_hec(sd, cfg), cfg)
        t0 = s.fire()
        return {"_time": t0, "action": "fire", "result": "incident started", "t0": t0, "t0_iso": B.iso_ms(t0), "job_id": canon.CI_JOB_ID, "pod": canon.RUNNER_POD,
                "next": "attempts every %ds; detections at the next scheduled run" % canon.ATTEMPT_INTERVAL}

    def reset(self, sd):
        cfg = ST.config(sd)
        hec = make_hec(sd, cfg)
        now = time.time()
        released, audit_ids, note = [], [], ""
        token = sd.password("zt_incident_demo", "k8s_platform")
        if token:
            try:
                k8s = K8s(cfg["emulator"]["url"], token, verify=cfg["emulator"]["verify_tls"], user_agent="ztdemo-reset/1.0")
                released, audit_ids = k8s.release_quarantine()
            except Exception as e:  # noqa: BLE001
                note = "emulator unreachable: %s" % str(e)[:160]
        else:
            note = "no k8s_platform token in storage/passwords (run make secrets)"
        st = ST.load(sd)
        if released:
            hec.send([B.enforcement_audit(now, request_id="", finding_id="", investigation_id="", state="released", enforcement_point="kernel",
                                          action="CNP %s" % ",".join(released), target="%s/%s" % (canon.RUNNER_NS, canon.RUNNER_POD), workload=canon.RUNNER_WORKLOAD,
                                          policy_name=",".join(released), approved_by=canon.PLATFORM_USER, approver_role=canon.PLATFORM_ROLE, approved_at=now,
                                          executed_by="splunk", playbook="ztdemo", run_id="", k8s_audit_ids=audit_ids, comment="merge request reverted")])
        cancelled = 0
        for r in sd.kv_query("zt_enforcement_requests", {"status": {"$in": ["pending", "approved"]}}):
            r["status"] = "cancelled"
            sd.kv_save("zt_enforcement_requests", r)
            cancelled += 1
        Streamer(sd, hec, cfg).reset(now)
        return {"_time": now, "action": "reset", "result": "plan idle, reset stamped", "released_policies": ",".join(released) or "none", "cancelled_requests": cancelled,
                "previous_plan_status": st["plan_status"], "last_reset_epoch": now, "note": note}

    def backfill(self, sd):
        cfg = ST.config(sd)
        st = ST.load(sd)
        force = str(self.force).lower() in ("1", "true", "yes")
        if st["backfill_done"] and not force:
            return {"_time": time.time(), "action": "backfill", "result": "already done", "checkpoint": st["stream_checkpoint"], "hint": "use force=true only after make reset-hard emptied the index"}
        s = Streamer(sd, make_hec(sd, cfg), cfg)
        summary = s.tick(force_backfill=True, backfill_hours=int(self.hours or 24))
        return dict({"_time": time.time(), "action": "backfill"}, **summary)

    def tick(self, sd):
        cfg = ST.config(sd)
        summary = Streamer(sd, make_hec(sd, cfg), cfg).tick()
        return dict({"_time": time.time(), "action": "tick"}, **summary)

    def speed(self, sd, value):
        if value not in ("fast", "normal"):
            raise ValueError("value must be fast or normal")
        crons = FAST if value == "fast" else NORMAL
        changed = []
        for app in ZT_APPS:
            try:
                d = sd.get("servicesNS/nobody/%s/saved/searches" % app, params={"count": 0, "search": "name=ZT*"})
            except RestError:
                continue
            for e in d.get("entry", []):
                name = e["name"]
                if not name.startswith("ZT") or not e["content"].get("cron_schedule"):
                    continue
                cron = crons["offset"] if name in OFFSET_SEARCHES else crons["default"]
                if e["content"].get("cron_schedule") != cron:
                    sd.post("servicesNS/nobody/%s/saved/searches/%s" % (app, urllib.parse.quote(name, safe="")), data={"cron_schedule": cron})
                    changed.append(name)
        st = ST.load(sd)
        st["speed"] = value
        ST.save(sd, st)
        return {"_time": time.time(), "action": "speed", "result": value, "changed": ", ".join(changed) or "none"}

    def config(self, sd):
        st = ST.load(sd)
        out = {"_time": time.time(), "action": "config"}
        if self.agent_mode:
            if self.agent_mode not in ("mcp", "inline"):
                raise ValueError("agent_mode must be mcp or inline")
            st["agent_mode"] = self.agent_mode
            out["agent_mode"] = self.agent_mode
        if self.response_mode:
            if self.response_mode not in ("local", "soar"):
                raise ValueError("response_mode must be local or soar")
            st["response_mode"] = self.response_mode
            out["response_mode"] = self.response_mode
        ST.save(sd, st)
        out["result"] = "saved" if (self.agent_mode or self.response_mode) else "no change"
        out["state"] = json.dumps({k: st[k] for k in ("agent_mode", "response_mode", "speed")})
        return out


dispatch(ZtDemoCommand, sys.argv, sys.stdin, sys.stdout, __name__)
