#!/usr/bin/env python3
"""Answer a SOAR playbook prompt by REST as a named user: `soar_prompt.py list` | `answer <approval_id> Approve|Reject "comment" --as j.chen`.
The prompt of zt_quarantine_workload has two response types: a list (Approve / Reject) and a message (comment)."""
import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402


def client(user=None):
    if user:
        return ztrest.Soar(user=user, password=ztrest.env("SOAR_PASS_" + user.upper().replace(".", "_"), required=True))
    return ztrest.Soar()


def pending(soar):
    st, body = soar.request("GET", "rest/approval", params={"_filter_status": '"pending"', "page_size": 20, "sort": "id", "order": "desc"}, raw=True)
    data = json.loads(body.decode()) if st == 200 else {"data": []}
    return data.get("data", [])


def user_id(soar, username):
    st, body = soar.request("GET", "rest/ph_user", params={"_filter_username": '"%s"' % username}, raw=True)
    rows = json.loads(body.decode()).get("data", []) if st == 200 else []
    return rows[0]["id"] if rows else None


def approvals_for(soar, username, since=0, names=("ask_approval", "ask_approval_netops")):
    """The user's copies of the playbook prompts created after `since` (epoch), newest first, any status."""
    import datetime as dt
    uid = user_id(soar, username)
    st, body = soar.request("GET", "rest/approval", params={"page_size": 30, "sort": "id", "order": "desc"}, raw=True)
    rows = json.loads(body.decode()).get("data", []) if st == 200 else []
    out = []
    for a in rows:
        if a.get("owner") != uid or a.get("name") not in names:
            continue
        try:
            started = dt.datetime.strptime(a.get("start_time", "")[:19], "%Y-%m-%dT%H:%M:%S").replace(tzinfo=dt.timezone.utc).timestamp()
        except ValueError:
            started = 0
        if started >= since - 60:
            out.append(a)
    return out


def mine(soar, username, name=None):
    """A role prompt creates one approval record per user in the role; only the owner can answer their copy."""
    uid = user_id(soar, username)
    return [a for a in pending(soar) if a.get("owner") == uid and (name is None or a.get("name") == name)]


def answer(soar, approval_id, choice, comment):
    """SOAR accepts the response as a list ordered like the prompt's response types; the payload shape differs by
    release, so the known shapes are tried until one is accepted."""
    resolution = "approve" if choice.lower() == "approve" else "deny"
    candidates = [
        {"status": resolution, "type": "manual", "action": "prompt", "responses": [choice, comment], "message": comment},  # accepted by SOAR Cloud 8.7
        {"resolution": resolution, "responses": [choice, comment], "message": comment},
        {"resolution": resolution, "response": [choice, comment], "message": comment},
        {"resolution": resolution, "responses": [{"response": choice}, {"response": comment}], "message": comment},
    ]
    tried = []
    for body in candidates:
        st, out = soar.request("POST", "rest/approval/%s" % approval_id, json_body=body, raw=True, retries=0)
        tried.append((st, out[:200].decode("utf-8", "replace")))
        if st in (200, 201):
            st2, cur = soar.request("GET", "rest/approval/%s" % approval_id, raw=True)
            rec = json.loads(cur.decode()) if st2 == 200 else {}
            if rec.get("status") != "pending":
                return {"ok": True, "payload": body, "status": rec.get("status"), "responses": rec.get("responses")}
    return {"ok": False, "tried": tried}


def main(argv):
    user = None
    if "--as" in argv:
        i = argv.index("--as")
        user = argv[i + 1]
        argv = argv[:i] + argv[i + 2:]
    soar = client(user)
    if not argv or argv[0] == "list":
        for a in pending(soar):
            print(a["id"], a.get("name"), a.get("status"), "playbook_run", a.get("playbook_run"), "due", a.get("due_time"), "owner_type", a.get("owner_type"))
        return 0
    if argv[0] == "answer":
        print(json.dumps(answer(soar, argv[1], argv[2], argv[3] if len(argv) > 3 else ""), indent=1))
        return 0
    if argv[0] == "mine":
        for a in mine(soar, user):
            print(a["id"], a.get("name"), a.get("status"), "playbook_run", a.get("playbook_run"), "due", a.get("due_time"))
        return 0
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
