#!/usr/bin/env python3
"""Scripted input (interval 15): stream the background and the incident plan to HTTP Event Collector.
Prints nothing; logs to $SPLUNK_HOME/var/log/splunk/zt_incident_demo.log."""
import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)), "lib"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from ztgen import state as ST  # noqa: E402
from ztgen.restclient import Splunkd  # noqa: E402
from ztgen.streamer import Streamer, make_hec, setup_logging  # noqa: E402


def main():
    log = setup_logging()
    session_key = sys.stdin.readline().strip()
    if not session_key:
        log.error("no session key on stdin (passAuth missing?)")
        return 1
    uri = os.environ.get("SPLUNKD_URI") or "https://127.0.0.1:8089"
    sd = Splunkd(uri, session_key=session_key)
    try:
        cfg = ST.config(sd)
        hec = make_hec(sd, cfg)
        summary = Streamer(sd, hec, cfg).tick()
        log.info("tick %s", summary)
    except Exception as e:  # noqa: BLE001
        log.exception("stream tick failed: %s", e)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
