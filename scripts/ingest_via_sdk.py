#!/usr/bin/env python
"""
PhishNet AI - Ingest synthetic alerts via the Splunk SDK (no HEC token needed)

Submits each generated alert as a JSON event into index=phishing using the
authenticated REST API. Uses current time for _time so events fall inside any
default dashboard time window.

Usage:
    set PHISHNET_SPLUNK_PW=...
    python scripts/ingest_via_sdk.py
"""

import json
import os
import sys

import splunklib.client as client

DATA = os.path.join(os.path.dirname(os.path.abspath(__file__)),
                    "..", "data", "generated", "alerts.json")


def main():
    pw = os.environ.get("PHISHNET_SPLUNK_PW")
    user = os.environ.get("PHISHNET_SPLUNK_USER", "VineetLoyer")
    if not pw:
        print("Set PHISHNET_SPLUNK_PW")
        return 1

    with open(os.path.normpath(DATA), "r", encoding="utf-8") as fh:
        alerts = json.load(fh)

    s = client.connect(host="localhost", port=8089, scheme="https",
                       username=user, password=pw, app="phishnet_ai")
    idx = s.indexes["phishing"]

    # Batch submit over a single streaming connection (fast; one-by-one submit
    # opens a fresh HTTP call per event and can stall).
    with idx.attached_socket(sourcetype="phishnet:alert", source="phishnet:generator") as sock:
        for a in alerts:
            line = (json.dumps(a) + "\n").encode("utf-8")
            sock.send(line)
    print(f"Ingested {len(alerts)} alerts into index=phishing via SDK (batch).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
