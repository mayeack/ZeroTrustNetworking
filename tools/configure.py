#!/usr/bin/env python3
"""make configure: point the installed app at this stack's HEC and at the emulator (local/zt_demo.conf via REST)."""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import ztrest  # noqa: E402


def main():
    s = ztrest.Splunk()
    if not s.exists("services/apps/local/zt_incident_demo"):
        sys.exit("zt_incident_demo is not installed on the stack yet")
    base = "servicesNS/nobody/zt_incident_demo/configs/conf-zt_demo"
    for stanza, values in (("hec", {"url": ztrest.env("SPLUNK_HEC_URL"), "verify_tls": "1", "token_name": "zt_incident_demo"}),
                           ("emulator", {"url": ztrest.env("ZT_EMULATOR_PUBLIC_URL"), "verify_tls": "1"})):
        if s.exists(base + "/" + stanza):
            s.post(base + "/" + stanza, data=values)
        else:
            d = dict(values)
            d["name"] = stanza
            s.post(base, data=d)
        print("zt_demo.conf [%s] %s" % (stanza, values))
    # No app reload here: every stream tick and command reads zt_demo.conf through REST, and an app reload would
    # restart the scripted input in the middle of a backfill.
    return 0


if __name__ == "__main__":
    sys.exit(main())
