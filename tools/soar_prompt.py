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


def answer(soar, approval_id, choice, comment):
    """SOAR accepts the response as a list ordered like the prompt's response types; the payload shape differs by
    release, so the known shapes are tried until one is accepted."""
    candidates = [
        {"status": "approved" if choice.lower() == "approve" else "rejected", "responses": [choice, comment]},
        {"responses": [choice, comment]},
        {"status": "approved", "responses": [{"prompt": "Approve or reject the quarantine", "response": choice}, {"prompt": "Comment", "response": comment}]},
        {"response": [choice, comment], "status": "approved"},
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
    print(__doc__)
    return 1


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
