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
    spl = ('search index=notable source="%s" | eval finding_time=_time | head 1 | table event_id finding_time rule_title normalized_risk_object risk_object risk_score source_count '
           'orig_source threat_object annotations.mitre_attack.mitre_technique_id status_label disposition_label investigation_ids owner' % rule)
    rows = splunkd.search(spl, earliest=str(int(earliest)) if earliest else "-24h", latest="now", timeout=120)
    return rows[0] if rows else None


def list_investigations(splunkd, count=50):
    try:
        d = splunkd.get(BASE + "/investigations", params={"count": count, "output_mode": None})
    except RestError:
        return []
    if isinstance(d, dict):
        d = d.get("items") or d.get("investigations") or []
    return d if isinstance(d, list) else []


def find_investigation_for_finding(splunkd, finding_event_id):
    for inv in list_investigations(splunkd, 100):
        ids = inv.get("finding_ids") or inv.get("incident_ids") or []
        if finding_event_id in ids:
            return inv
    return None


def get_investigation(splunkd, inv_id):
    try:
        d = splunkd.get(BASE + "/investigations/" + urllib.parse.quote(str(inv_id), safe=""), params={"output_mode": None})
    except RestError:
        return None
    return d if isinstance(d, dict) else None


def create_investigation(splunkd, name, finding_event_id, finding_time, description="", urgency="high", status=None):
    body = {"name": name, "finding_ids": [finding_event_id], "finding_times": [str(finding_time)], "description": description, "urgency": urgency}
    if status:
        body["status"] = status
    d = splunkd.post(BASE + "/investigations", json_body=body, params={"output_mode": None})
    guid = d.get("investigation_guid") or d.get("id") if isinstance(d, dict) else None
    return get_investigation(splunkd, guid) or {"id": guid, "investigation_guid": guid}


def ensure_investigation(splunkd, finding, description=""):
    """Return (investigation dict, created bool) for a ZT finding row from newest_zt_finding."""
    inv = find_investigation_for_finding(splunkd, finding["event_id"])
    if inv:
        return inv, False
    inv = create_investigation(splunkd, finding.get("rule_title") or "Zero trust finding", finding["event_id"], finding.get("finding_time") or time.time(), description)
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
    return splunkd.post(BASE + "/investigations/%s" % urllib.parse.quote(str(inv_guid), safe=""), json_body=fields, params={"output_mode": None, "inherit_fields": "true"})


def resolve(splunkd, inv_guid, note_title, note_content):
    add_note(splunkd, inv_guid, note_title, note_content)
    return update_investigation(splunkd, inv_guid, status=STATUS_RESOLVED, disposition=DISPOSITION_TP)
