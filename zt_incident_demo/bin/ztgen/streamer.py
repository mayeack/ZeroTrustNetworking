"""One generator tick: backfill once, emit the background events due since the checkpoint, advance the incident plan,
move the checkpoint only after HEC accepted the batch. Shared by the scripted input, the standalone CLI and `ztdemo`."""
import logging
import os
import socket
import time

from . import attacks as A, canon, plan as P, schedule as S, state as ST
from .estate import get_estate
from .restclient import Hec, RestError

log = logging.getLogger("ztgen.stream")
LOCK_TTL = 900


LEASE_TTL = 45  # seconds a streaming lease stays valid without a heartbeat


class Streamer:
    def __init__(self, splunkd, hec, cfg=None):
        self.splunkd = splunkd
        self.hec = hec
        self.cfg = cfg or ST.config(splunkd)
        self.estate = get_estate()
        self.tz = self.cfg["stream"]["day_shape_tz"]
        self.chunk = self.cfg["stream"]["chunk_minutes"] * 60

    # ---- background --------------------------------------------------------
    def _send_window(self, start, end, st):
        """Send background events in chunks; checkpoint advances after each accepted chunk."""
        total = 0
        cur = start
        while cur < end:
            nxt = min(end, cur + self.chunk)
            n = self.hec.send(S.background_events(self.estate, cur, nxt, self.tz))
            total += n
            st["stream_checkpoint"] = nxt
            ST.save(self.splunkd, st)
            cur = nxt
        return total

    def _policy_records(self):
        return self.splunkd.kv_query("zt_policy_state")

    # ---- plan ----------------------------------------------------------------
    def _advance_plan(self, st, now):
        if st["plan_status"] != "running":
            return 0
        sent = 0
        t0 = float(st["plan_t0"])
        records = None
        k = int(st["plan_attempt"]) + 1
        while P.attempt_time(t0, k) <= now and st["plan_status"] == "running":
            if records is None:
                records = self._policy_records()
            applied_at = P.quarantine_applied_at(records)
            t_att = P.attempt_time(t0, k)
            dropped = applied_at is not None and t_att >= applied_at
            self.hec.send(P.attempt_events(self.estate, t0, k, dropped))
            sent += 4 if not dropped else 3
            st["plan_attempt"] = k
            if dropped:
                st["plan_dropped_attempts"] = int(st["plan_dropped_attempts"]) + 1
                if st["plan_dropped_attempts"] == canon.DROPPED_ATTEMPTS_BEFORE_FAIL:
                    st["plan_fail_at"] = t_att + canon.FAIL_DELAY_AFTER_LAST_DROP
            ST.save(self.splunkd, st)
            k += 1
        if st["plan_status"] == "running":
            if float(st["plan_fail_at"]) and now >= float(st["plan_fail_at"]):
                self.hec.send([P.ci_final_event(t0, float(st["plan_fail_at"]), failed=True)])
                sent += 1
                st["plan_status"] = "completed"
                st["plan_completed_epoch"] = now
            elif now - t0 >= canon.NO_QUARANTINE_TIMEOUT and int(st["plan_dropped_attempts"]) == 0:
                self.hec.send([P.ci_final_event(t0, t0 + canon.NO_QUARANTINE_TIMEOUT, failed=False)])
                sent += 1
                st["plan_status"] = "completed"
                st["plan_completed_epoch"] = now
            ST.save(self.splunkd, st)
        return sent

    # ---- tick -----------------------------------------------------------------
    def tick(self, now=None, force_backfill=False, backfill_hours=None, owner=None):
        """One streaming step. `owner` names the streamer ("splunk" for the search head input, "live:<host>:<pid>" for the
        live generator on a workstation): a fresh lease held by another owner makes this tick a no-op, and a live
        generator always takes the lease over from the search head, so only one side streams at a time."""
        now = now or time.time()
        st = ST.load(self.splunkd)
        lock_owner = "%s:%d" % (socket.gethostname(), os.getpid())
        sent = 0
        summary = {"backfill": "done" if st["backfill_done"] else "pending", "background_events": 0, "plan_events": 0, "attack_events": 0, "checkpoint": st["stream_checkpoint"]}
        if owner:
            holder, held_at = st.get("stream_owner") or "", float(st.get("stream_owner_epoch") or 0)
            live_takes_over = owner.startswith("live:") and not holder.startswith("live:")
            if holder and holder != owner and now - held_at < LEASE_TTL and not live_takes_over:
                summary["skipped"] = "streaming is owned by %s (lease %.0fs old)" % (holder, now - held_at)
                return summary
            st["stream_owner"], st["stream_owner_epoch"] = owner, now
        try:
            if not st["backfill_done"] or force_backfill:
                if st["backfill_lock_epoch"] and now - float(st["backfill_lock_epoch"]) < LOCK_TTL and st["backfill_lock_owner"] != owner and not force_backfill:
                    summary["backfill"] = "running elsewhere (%s)" % st["backfill_lock_owner"]
                else:
                    st["backfill_lock_epoch"], st["backfill_lock_owner"] = now, owner
                    ST.save(self.splunkd, st)
                    hours = backfill_hours or self.cfg["stream"]["backfill_hours"]
                    start = now - hours * 3600
                    log.info("backfill %s hours from %s", hours, time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(start)))
                    sent += self._send_window(start, now, st)
                    st["backfill_done"], st["backfill_lock_epoch"], st["backfill_lock_owner"] = 1, 0.0, ""
                    summary["backfill"] = "completed (%d events)" % sent
            else:
                start = max(float(st["stream_checkpoint"]), now - 24 * 3600)
                if start < now:
                    n = self._send_window(start, now, st)
                    sent += n
                    summary["background_events"] = n
            summary["plan_events"] = self._advance_plan(st, now)
            sent += summary["plan_events"]
            summary["attack_events"] = A.advance(self.splunkd, self.hec, self.estate, now)
            sent += summary["attack_events"]
            st["last_error"] = ""
        except RestError as e:
            st["last_error"] = str(e)[:400]
            log.error("tick failed: %s", e)
            summary["error"] = str(e)[:400]
        st["last_tick_epoch"] = now
        st["last_tick_events"] = sent
        ST.save(self.splunkd, st)
        summary["checkpoint"] = st["stream_checkpoint"]
        summary["sent"] = sent
        return summary

    # ---- fire / reset ------------------------------------------------------------
    def fire(self, now=None):
        now = now or time.time()
        st = ST.load(self.splunkd)
        if st["plan_status"] == "running":
            raise ValueError("an incident is in progress (fired %s); run `| ztdemo action=reset` first" % time.strftime("%H:%M:%S", time.gmtime(float(st["plan_t0"]))))
        if P.policy_names_selecting(self._policy_records()):
            raise ValueError("a quarantine policy still selects %s; run `| ztdemo action=reset` first" % canon.RUNNER_POD)
        t0 = now
        self.hec.send(P.fire_events(self.estate, t0))
        st.update({"plan_t0": t0, "plan_attempt": 0, "plan_status": "running", "plan_dropped_attempts": 0, "plan_fail_at": 0.0, "plan_completed_epoch": 0.0, "last_fire_epoch": t0})
        ST.save(self.splunkd, st)
        return t0

    def reset(self, now=None):
        now = now or time.time()
        st = ST.load(self.splunkd)
        st.update({"plan_status": "idle", "plan_attempt": -1, "plan_dropped_attempts": 0, "plan_fail_at": 0.0, "last_reset_epoch": now})
        ST.save(self.splunkd, st)
        for rec in A.running(self.splunkd):
            A.stop(self.splunkd, rec["_key"], now)
        return st

    def release_lease(self, owner):
        st = ST.load(self.splunkd)
        if st.get("stream_owner") == owner:
            st["stream_owner"], st["stream_owner_epoch"] = "", 0.0
            ST.save(self.splunkd, st)


def make_hec(splunkd, cfg):
    token = splunkd.hec_token(cfg["hec"]["token_name"])
    if not token:
        raise RestError(404, "HEC token %s not found (run make hec)" % cfg["hec"]["token_name"], "data/inputs/http")
    return Hec(cfg["hec"]["url"], token, verify=cfg["hec"]["verify_tls"])


def setup_logging(name="zt_incident_demo"):
    home = os.environ.get("SPLUNK_HOME")
    logger = logging.getLogger("ztgen")
    if logger.handlers:
        return logger
    logger.setLevel(logging.INFO)
    if home:
        from logging.handlers import RotatingFileHandler
        path = os.path.join(home, "var", "log", "splunk", name + ".log")
        h = RotatingFileHandler(path, maxBytes=5_000_000, backupCount=3)
    else:
        h = logging.StreamHandler()
    h.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(h)
    return logger
