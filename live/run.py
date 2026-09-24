#!/usr/bin/env python3
"""Zero trust live generator: `python3 live/run.py` (settings from local/env or the environment).
Open http://127.0.0.1:8890 in a browser."""
import logging
import os
import signal
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, os.path.join(ROOT, "zt_incident_demo", "bin"))
sys.path.insert(0, os.path.join(ROOT, "tools"))
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import ztrest  # noqa: E402
from ztlive.engine import Engine  # noqa: E402
from ztlive.server import serve  # noqa: E402


def main():
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s %(message)s")
    env = dict(ztrest.ENV)
    env.update({k: v for k, v in os.environ.items() if k.startswith(("SPLUNK_", "ZT_", "SOAR_"))})
    for key in ("SPLUNK_URL", "SPLUNK_USER", "SPLUNK_PASS"):
        if not env.get(key):
            sys.exit("missing %s (local/env)" % key)
    engine = Engine(env)
    engine.start()

    def bye(*_):
        engine.stop()
        os._exit(0)

    signal.signal(signal.SIGTERM, bye)
    signal.signal(signal.SIGINT, bye)
    try:
        serve(engine, env.get("ZT_LIVE_BIND", "127.0.0.1"), int(env.get("ZT_LIVE_PORT", "8890")))
    finally:
        engine.stop()


if __name__ == "__main__":
    main()
