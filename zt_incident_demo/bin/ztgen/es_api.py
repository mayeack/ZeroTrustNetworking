"""Enterprise Security 8.x public API helpers (missioncontrol /public/v2): findings, investigations, notes."""
import json
import time
import urllib.parse

from .restclient import RestError

BASE = "servicesNS/nobody/missioncontrol/public/v2"
STATUS_RESOLVED = "Resolved"
STATUS_IN_PROGRESS = "In Progress"
DISPOSITION_TP = "True Positive - Suspicious Activity"


def newest_zt_finding(splunkd, rule, earliest=0):
    """Newest finding group of the ZT finding-based detection since `earliest` (epoch), from index=notable."""
    spl = ('search `notable` | search source="%s" | eval finding_epoch=_time, rule_title=coalesce(orig_rule_title, rule_title) | sort - _time | head 1 | table event_id _time finding_epoch rule_title normalized_risk_object risk_object risk_score source_count '
           'orig_source threat_object annotations.mitre_attack.mitre_technique_id status_label disposition_label investigation_ids owner' % rule)
    rows = splunkd.search(spl, earliest=str(int(earliest)) if earliest else "-24h", latest="now", timeout=120)
    if not rows:
        return None
    row = rows[0]
    row["finding_time"] = row.get("_time")  # the string form is what POST /investigations accepts in finding_times
    return row


def list_investigations(splunkd, count=50):
    try:
        d = splunkd.get(BASE + "/investigations", params={"count": count, "output_mode": None})
    except RestError:
        return []
    if isinstance(d, dict):
        d = d.get("items") or d.get("investigations") or []
    return d if isinstance(d, list) else []


def find_investigation_for_finding(splunkd, finding_event_id, name=None, not_before=0):
    """Match on any id list ES exposes; fall back to the finding title created after the finding."""
    for inv in list_investigations(splunkd, 100):
        ids = []
        for key in ("finding_id", "finding_ids", "findings", "implicit_finding_ids", "intermediate_finding_ids", "consolidated_findings", "incident_ids", "notable_ids", "event_ids"):
            v = inv.get(key)
            for item in (v if isinstance(v, list) else [v] if v else []):
                if isinstance(item, dict):
                    ids.extend(str(x) for x in (item.get("event_id"), item.get("id"), item.get("finding_id")) if x)
                else:
                    ids.append(str(item))
        if finding_event_id in ids:
            return inv
    if name:
        for inv in list_investigations(splunkd, 100):
            if inv.get("name") == name and float(inv.get("create_time") or 0) >= float(not_before or 0) - 1:
                return inv
    return None


def get_investigation(splunkd, inv_id):
    """The list endpoint filtered by ids (a single-record GET is not allowed on every ES version)."""
    try:
        d = splunkd.get(BASE + "/investigations", params={"ids": str(inv_id), "output_mode": None})
    except RestError:
        return None
    items = d if isinstance(d, list) else (d.get("items") or d.get("investigations") or []) if isinstance(d, dict) else []
    return items[0] if items else None


def create_investigation(splunkd, name, finding_event_id, finding_time, description="", urgency="high", status=None):
    body = {"name": name, "finding_ids": [finding_event_id], "finding_times": [str(finding_time)], "description": description, "urgency": urgency}
    if status:
        body["status"] = status
    d = splunkd.post(BASE + "/investigations", json_body=body, params={"output_mode": None})
    guid = d.get("investigation_guid") or d.get("id") if isinstance(d, dict) else None
    return get_investigation(splunkd, guid) or {"id": guid, "investigation_guid": guid}


def ensure_investigation(splunkd, finding, description=""):
    """Return (investigation dict, created bool) for a ZT finding row from newest_zt_finding."""
    inv = find_investigation_for_finding(splunkd, finding["event_id"], finding.get("rule_title"), finding.get("finding_epoch"))
    if inv:
        return inv, False
    inv = create_investigation(splunkd, finding.get("rule_title") or "Zero trust finding", finding["event_id"], finding.get("finding_time") or time.strftime("%Y-%m-%d %H:%M:%S", time.gmtime()), description)
    return inv, True


def investigation_ids(inv):
    """(guid for API calls, display id such as INV-12 for people)."""
    guid = inv.get("investigation_guid") or inv.get("id") or ""
    display = inv.get("investigation_id") or inv.get("display_id") or guid
    return guid, display


def add_note(splunkd, inv_guid, title, content, ai_generated=False):
    return splunkd.post(BASE + "/investigations/%s/notes" % urllib.parse.quote(str(inv_guid), safe=""), json_body={"title": title, "content": content[:9900], "ai_generated": bool(ai_generated)}, params={"output_mode": None})


def list_notes(splunkd, inv_guid):
    try:
        d = splunkd.get(BASE + "/investigations/%s/notes" % urllib.parse.quote(str(inv_guid), safe=""), params={"output_mode": None})
    except RestError:
        return []
    if isinstance(d, dict):
        d = d.get("items") or d.get("notes") or []
    return d if isinstance(d, list) else []


def update_investigation(splunkd, inv_guid, **fields):
    return splunkd.post(BASE + "/investigations/%s" % urllib.parse.quote(str(inv_guid), safe=""), json_body=fields, params={"output_mode": None})


def resolve(splunkd, inv_guid, note_title, note_content):
    add_note(splunkd, inv_guid, note_title, note_content)
    return update_investigation(splunkd, inv_guid, status=STATUS_RESOLVED, disposition=DISPOSITION_TP)
