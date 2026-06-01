#!/usr/bin/env python
"""
PhishNet AI - Ingest synthetic alerts into Splunk via HTTP Event Collector (HEC)

Reads the generated alerts JSON (from generate_demo_data.py) and sends each alert
as an event to Splunk's HEC endpoint, into index=phishing with sourcetype
phishnet:alert.

Prerequisites in Splunk (one-time, see setup_hec() instructions printed by
--help-setup):
  1. Enable HTTP Event Collector (Settings > Data Inputs > HTTP Event Collector)
  2. Create a token, allow index 'phishing'
  3. Pass the token via --token or env var PHISHNET_HEC_TOKEN

Usage:
    python scripts/ingest_to_splunk.py --token <HEC_TOKEN>
    python scripts/ingest_to_splunk.py --token <HEC_TOKEN> --count 300
    set PHISHNET_HEC_TOKEN=xxxx  &&  python scripts/ingest_to_splunk.py

Notes:
  - HEC default port is 8088 (https). Local dev uses a self-signed cert, so we
    pass verify=False and silence the warning. This is acceptable for localhost
    dev only — never disable TLS verification against a real server.
"""

import argparse
import json
import os
import sys
import time

try:
    import requests
    import urllib3
    urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
except ImportError:
    print("This script needs 'requests'. Install with: pip install requests")
    sys.exit(1)


DEFAULT_DATA = os.path.join("data", "generated", "alerts.json")
SETUP_HELP = """
=== One-time Splunk HEC setup ===

1. In Splunk Web (http://localhost:8000):
   Settings > Data inputs > HTTP Event Collector > Global Settings
     - All Tokens: Enabled
     - Disable SSL? (leave SSL on; this script handles the self-signed cert)
     - Default port: 8088

2. Settings > Data inputs > HTTP Event Collector > New Token
     - Name: phishnet-hec
     - Source type: phishnet:alert  (or leave automatic)
     - Allowed indexes: phishing  (create the index first if missing)
     - Default index: phishing
     - Copy the generated token value.

3. Create the 'phishing' index if it doesn't exist:
     Settings > Indexes > New Index > Name: phishing

4. Run this script:
     python scripts/ingest_to_splunk.py --token <PASTE_TOKEN_HERE>
"""


def load_alerts(path, limit):
    if not os.path.exists(path):
        print(f"Alerts file not found: {path}")
        print("Generate it first:  python scripts/generate_demo_data.py --count 50")
        sys.exit(1)
    with open(path, "r", encoding="utf-8") as fh:
        alerts = json.load(fh)
    if limit:
        alerts = alerts[:limit]
    return alerts


def parse_event_time(alert):
    """Convert the alert's received_at ISO string to an epoch for HEC 'time'."""
    from datetime import datetime, timezone
    raw = alert.get("received_at")
    if not raw:
        return time.time()
    try:
        dt = datetime.strptime(raw, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except ValueError:
        return time.time()


def ingest(host, port, token, index, sourcetype, alerts, scheme="https"):
    url = f"{scheme}://{host}:{port}/services/collector/event"
    headers = {"Authorization": f"Splunk {token}"}
    sent, failed = 0, 0

    for alert in alerts:
        payload = {
            "time": parse_event_time(alert),
            "host": "phishnet-demo",
            "source": "phishnet:generator",
            "sourcetype": sourcetype,
            "index": index,
            "event": alert,
        }
        try:
            resp = requests.post(url, headers=headers, json=payload,
                                 verify=False, timeout=15)
            if resp.status_code == 200:
                sent += 1
            else:
                failed += 1
                if failed <= 3:
                    print(f"  HEC error {resp.status_code}: {resp.text.strip()}")
        except requests.RequestException as exc:
            failed += 1
            if failed <= 3:
                print(f"  Request failed: {exc}")

    return sent, failed


def main():
    parser = argparse.ArgumentParser(description="Ingest synthetic alerts into Splunk via HEC")
    parser.add_argument("--token", default=os.environ.get("PHISHNET_HEC_TOKEN"),
                        help="HEC token (or set env PHISHNET_HEC_TOKEN)")
    parser.add_argument("--host", default="localhost")
    parser.add_argument("--port", type=int, default=8088)
    parser.add_argument("--index", default="phishing")
    parser.add_argument("--sourcetype", default="phishnet:alert")
    parser.add_argument("--data", default=DEFAULT_DATA)
    parser.add_argument("--count", type=int, default=0, help="Max alerts (0 = all)")
    parser.add_argument("--help-setup", action="store_true",
                        help="Print one-time Splunk HEC setup instructions and exit")
    args = parser.parse_args()

    if args.help_setup:
        print(SETUP_HELP)
        return 0

    if not args.token:
        print("No HEC token provided. Use --token <token> or set PHISHNET_HEC_TOKEN.")
        print("Run with --help-setup for one-time setup instructions.")
        return 1

    alerts = load_alerts(args.data, args.count)
    print(f"Ingesting {len(alerts)} alerts into index={args.index} "
          f"via HEC at {args.host}:{args.port} ...")
    sent, failed = ingest(args.host, args.port, args.token,
                          args.index, args.sourcetype, alerts)
    print(f"Done. Sent: {sent}, Failed: {failed}")
    if sent:
        print(f"\nVerify in Splunk:  index={args.index} sourcetype={args.sourcetype} | stats count")
    return 0 if failed == 0 else 1


if __name__ == "__main__":
    raise SystemExit(main())
