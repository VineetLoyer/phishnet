#!/usr/bin/env python
"""
PhishNet AI - Demo reset

Returns Splunk to a clean, known-good demo state:
  1. Clears the phishnet_actions index (investigation reports)
  2. Clears the phishnet_decisions KV Store collection
  3. (Optionally) re-runs the agent over all alerts to repopulate

This makes the dashboards deterministic for demos and removes duplicate
records from repeated agent runs.

Usage:
    set PHISHNET_SPLUNK_USER=VineetLoyer
    set PHISHNET_SPLUNK_PW=...
    python scripts/reset_demo.py            # clear only
    python scripts/reset_demo.py --repopulate   # clear + re-run agent (mock, auto)
    python scripts/reset_demo.py --enrich       # backfill KV fields from index=phishing
"""

import argparse
import os
import sys

import splunklib.client as client

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishnet_ai", "bin")
SCRIPTS = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.normpath(BIN))
sys.path.insert(0, SCRIPTS)


def connect():
    user = os.environ.get("PHISHNET_SPLUNK_USER", "VineetLoyer")
    pw = os.environ.get("PHISHNET_SPLUNK_PW")
    if not pw:
        print("Set PHISHNET_SPLUNK_PW (and optionally PHISHNET_SPLUNK_USER).")
        print("  PowerShell:  $env:PHISHNET_SPLUNK_PW = 'your-password'")
        print("  CMD:         set PHISHNET_SPLUNK_PW=your-password")
        sys.exit(1)
    return client.connect(host="localhost", port=8089, scheme="https",
                          username=user, password=pw, app="phishnet_ai")


def clear(service):
    # Clear the actions index by piping to the 'delete' command.
    print("Clearing index=phishnet_actions ...")
    job = service.jobs.oneshot(
        "search index=phishnet_actions | delete",
        output_mode="json", count=0, earliest_time="0", latest_time="now",
    )
    list(__import__("splunklib.results", fromlist=["JSONResultsReader"]).JSONResultsReader(job))

    # Clear the decisions KV Store collection.
    print("Clearing KV Store phishnet_decisions ...")
    try:
        service.kvstore["phishnet_decisions"].data.delete()
    except Exception as exc:  # noqa: BLE001
        print(f"  (kvstore clear note: {exc})")
    print("Clear complete.")


def repopulate():
    from phishnet_lib.config import AgentConfig
    from phishnet_lib.pipeline import run_once
    print("Repopulating via agent (mock classifier, auto mode) ...")
    cfg = AgentConfig(
        backend="sdk", classifier="mock", mode="auto",
        splunk_username=os.environ.get("PHISHNET_SPLUNK_USER", "VineetLoyer"),
        splunk_password=os.environ["PHISHNET_SPLUNK_PW"],
    )
    summary = run_once(cfg, verbose=True)
    print(summary.as_text())


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--repopulate", action="store_true",
                   help="Re-run the agent over all alerts after clearing.")
    p.add_argument("--enrich", action="store_true",
                   help="Backfill KV blast-radius fields from index=phishing (no clear).")
    args = p.parse_args()

    service = connect()

    if args.enrich and not args.repopulate:
        import enrich_kv_from_index as ekv
        raise SystemExit(ekv.enrich(service))

    clear(service)
    if args.repopulate:
        repopulate()
        print("Warming threat-intel KV cache ...")
        import seed_threat_intel as sti
        sti.seed(service)
        print("Backfilling KV alert fields from index=phishing ...")
        import enrich_kv_from_index as ekv
        ekv.enrich(service)
    print("Demo reset done.")


if __name__ == "__main__":
    main()
