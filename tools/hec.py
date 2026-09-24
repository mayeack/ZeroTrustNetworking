#!/usr/bin/env python3
"""make hec: create the zt_incident_demo HEC token (idempotent), verify it, keep it in local/env for the Mac emulator."""
import os
import sys
import urllib.parse

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402

NAME = "zt_incident_demo"


def main():
    s = ztrest.Splunk()
    path = "services/data/inputs/http"
    def find():  # entries are listed as http://<token name>; direct GETs on the name are unreliable on Cloud
        return next((e for e in s.entries(path) if e["name"] == "http://" + NAME), None)
    ent = find()
    if ent is None:
        s.post(path, data={"name": NAME, "index": "zero_trust", "indexes": "zero_trust,zt_summary", "description": "Zero trust incident demo (Hubble, Tetragon, CI, Nexus, Kubernetes audit, enforcement audit)", "useACK": 0})
        ent = find()
        print("HEC token %s created" % NAME)
    else:
        print("HEC token %s present" % NAME)
    token = ent["content"]["token"]
    ztrest.set_env_value("SPLUNK_HEC_TOKEN", token)
    hec = ztrest.Http(ztrest.env("SPLUNK_HEC_URL"), token=token, token_scheme="Splunk", verify=str(ztrest.env("SPLUNK_VERIFY","1")).lower() not in ("0","false","no"))
    st, body = hec.request("POST", "services/collector/event", data="{}", headers={"Content-Type": "application/json"}, raw=True, retries=0)
    text = body.decode()
    accepted = st == 400 and "Event field" in text  # token accepted, empty event rejected: nothing indexed
    print("HEC check: HTTP %s %s -> %s" % (st, text.strip()[:80], "token accepted" if accepted else "UNEXPECTED"))
    return 0 if accepted else 1


if __name__ == "__main__":
    sys.exit(main())
