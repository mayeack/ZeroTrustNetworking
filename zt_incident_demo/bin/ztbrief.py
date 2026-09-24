#!/usr/bin/env python3
"""| ztbrief : parse ZTFlowInvestigator responses (ai_agent:response events), upsert zt_agent_briefs, resolve the ES
investigation and add the brief as one AI-generated note. Idempotent."""
import json
import os
import re
import sys
import time

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunklib.searchcommands import StreamingCommand, Configuration, dispatch  # noqa: E402
from ztgen import canon, es_api, response as R, state as ST  # noqa: E402
from ztgen.restclient import Splunkd, RestError  # noqa: E402
from ztgen.streamer import setup_logging  # noqa: E402

FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.S)


def extract_brief(text):
    """Find the brief JSON in free text (code fences or surrounding prose tolerated)."""
    if not text:
        return None
    if isinstance(text, dict):
        return text if "disposition" in text else None
    text = str(text)
    for m in FENCE.finditer(text):
        try:
            obj = json.loads(m.group(1))
            if "disposition" in obj:
                return obj
        except ValueError:
            pass
    # scan for balanced braces containing "disposition"
    for start in [m.start() for m in re.finditer(r"\{", text)]:
        depth = 0
        for i in range(start, len(text)):
            if text[i] == "{":
                depth += 1
            elif text[i] == "}":
                depth -= 1
                if depth == 0:
                    chunk = text[start:i + 1]
                    if '"disposition"' in chunk:
                        try:
                            obj = json.loads(chunk)
                            if "disposition" in obj:
                                return obj
                        except ValueError:
                            try:
                                obj = json.loads(chunk.encode().decode("unicode_escape"))
                                if "disposition" in obj:
                                    return obj
                            except Exception:  # noqa: BLE001
                                pass
                    break
    return None


def candidate_texts(record):
    for key in ("response", "agent_response", "result", "output", "final_response", "message", "content"):
        if record.get(key):
            yield record[key]
    raw = record.get("_raw")
    if raw:
        try:
            obj = json.loads(raw)
            for key in ("response", "agent_response", "result", "output", "final_response", "message", "content", "data"):
                if isinstance(obj, dict) and obj.get(key):
                    yield obj[key] if not isinstance(obj[key], dict) else json.dumps(obj[key])
        except ValueError:
            pass
        yield raw


@Configuration()
class ZtBriefCommand(StreamingCommand):
    def stream(self, records):
        setup_logging()
        si = self._metadata.searchinfo
        sd = Splunkd(si.splunkd_uri, session_key=si.session_key)
        st = ST.load(sd)
        since = float(st.get("last_reset_epoch") or 0)
        finding = None
        for rec in records:
            brief = None
            for text in candidate_texts(rec):
                brief = extract_brief(text)
                if brief:
                    break
            out = dict(rec)
            if not brief:
                out["ztbrief"] = "no brief JSON in this event"
                yield out
                continue
            try:
                if finding is None:
                    finding = es_api.newest_zt_finding(sd, canon.RULE_FBD, since)
                out["ztbrief"] = self.store(sd, brief, finding, rec)
            except RestError as e:
                out["ztbrief"] = "error: %s" % str(e)[:300]
            yield out

    def store(self, sd, brief, finding, rec):
        finding_id = (finding or {}).get("event_id") or brief.get("finding_id") or ""
        if not finding_id:
            return "no ZT finding group since the last reset; brief not stored"
        existing = sd.kv_get(R.BRIEFS, finding_id) or {}
        inv, created = es_api.ensure_investigation(sd, finding, description="Opened from the zero trust finding group by ZTFlowInvestigator.") if finding else (None, False)
        guid, display = es_api.investigation_ids(inv) if inv else ("", "")
        reco = brief.get("recommendation") or {}
        where = brief.get("where") or {}
        record = {"_key": finding_id, "finding_id": finding_id, "finding_display_id": display, "investigation_id": display, "investigation_guid": guid,
                  "workload": brief.get("entity") or canon.RUNNER_WORKLOAD, "pod": where.get("pod") or "", "node": where.get("node") or "",
                  "job_id": str(brief.get("job_id") or ""), "dest_workload": brief.get("dest_workload") or "", "data_class": brief.get("data_class") or "",
                  "disposition": brief.get("disposition") or "", "confidence": brief.get("confidence") or "", "enforcement_point": reco.get("enforcement_point") or "",
                  "action": reco.get("action") or "", "policy_name": reco.get("policy_name") or "", "blast_radius": reco.get("blast_radius") or "",
                  "approver_labels": ", ".join(reco.get("approver_labels") or []), "brief_json": json.dumps(brief), "brief_text": brief.get("brief_text") or "",
                  "what_happened": brief.get("what_happened") or "", "session_id": rec.get("session_id") or "", "run_epoch": float(rec.get("_time") or time.time()),
                  "note_added": int(existing.get("note_added") or 0)}
        if not record["pod"]:
            record["pod"] = canon.RUNNER_POD if record["workload"] == canon.RUNNER_WORKLOAD else ""
        if not record["job_id"] and record["workload"] == canon.RUNNER_WORKLOAD:
            record["job_id"] = str(canon.CI_JOB_ID)
        note_status = "note already added"
        if guid and not record["note_added"]:
            evidence = "\n".join("- %s: %s" % (e.get("tool", ""), e.get("fact", "")) for e in (brief.get("evidence") or []) if isinstance(e, dict))
            content = (record["brief_text"] or json.dumps(brief, indent=1)) + ("\n\nEvidence:\n" + evidence if evidence else "")
            es_api.add_note(sd, guid, "ZTFlowInvestigator brief", content, ai_generated=True)
            record["note_added"] = 1
            note_status = "note added to %s" % display
        sd.kv_save(R.BRIEFS, record)
        return "brief stored for %s (%s, %s at %s); %s%s" % (finding_id[:8], record["disposition"], record["enforcement_point"], record["approver_labels"], note_status, "; investigation created" if created else "")


dispatch(ZtBriefCommand, sys.argv, sys.stdin, sys.stdout, __name__)
