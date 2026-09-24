"""The demo state record (KV zt_demo_state, _key=global) and the app configuration (zt_demo.conf)."""
import time

COLLECTION = "zt_demo_state"
KEY = "global"
DEFAULTS = {"_key": KEY, "stream_checkpoint": 0.0, "backfill_done": 0, "backfill_lock_epoch": 0.0, "backfill_lock_owner": "", "last_reset_epoch": 0.0,
            "speed": "fast", "response_mode": "local", "agent_mode": "mcp", "plan_t0": 0.0, "plan_attempt": -1, "plan_status": "idle",
            "plan_dropped_attempts": 0, "plan_fail_at": 0.0, "plan_completed_epoch": 0.0, "last_fire_epoch": 0.0, "last_tick_epoch": 0.0,
            "last_tick_events": 0, "last_error": "", "stream_owner": "", "stream_owner_epoch": 0.0}


def load(splunkd):
    rec = splunkd.kv_get(COLLECTION, KEY) or {}
    out = dict(DEFAULTS)
    for k, v in rec.items():
        if k in out and not isinstance(v, type(out[k])) and out[k] is not None:
            try:
                v = type(out[k])(v)
            except (TypeError, ValueError):
                pass
        out[k] = v
    return out


def save(splunkd, rec):
    rec = dict(rec)
    rec["_key"] = KEY
    splunkd.kv_save(COLLECTION, rec)
    return rec


def config(splunkd):
    """zt_demo.conf merged (default + local) as {stanza: {key: value}} with typed values."""
    out = {}
    for stanza in ("hec", "emulator", "stream", "modes"):
        out[stanza] = splunkd.conf("zt_demo", stanza)
    out.setdefault("hec", {}).setdefault("url", "https://127.0.0.1:8088")
    out["hec"].setdefault("token_name", "zt_incident_demo")
    out["hec"]["verify_tls"] = str(out["hec"].get("verify_tls", "0")).lower() in ("1", "true", "yes")
    out.setdefault("emulator", {}).setdefault("url", "https://127.0.0.1:6443")
    out["emulator"]["verify_tls"] = str(out["emulator"].get("verify_tls", "1")).lower() in ("1", "true", "yes")
    out.setdefault("stream", {})
    out["stream"]["day_shape_tz"] = out["stream"].get("day_shape_tz") or "America/New_York"
    out["stream"]["backfill_hours"] = int(out["stream"].get("backfill_hours") or 24)
    out["stream"]["chunk_minutes"] = int(out["stream"].get("chunk_minutes") or 30)
    return out


def now():
    return time.time()
