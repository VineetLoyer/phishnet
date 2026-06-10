#!/usr/bin/env python
"""
PhishNet AI - Seed weekly ROI metrics for the Manager dashboard.

Populates the phishnet_metrics KV Store collection with an 8-week trend for
the Manager ROI dashboard (throughput, threats caught, hours saved, accuracy,
escalation rate). Hours saved assumes 25 minutes per auto-closed false positive.

Usage (PowerShell):
    $env:PHISHNET_SPLUNK_USER = "VineetLoyer"
    $env:PHISHNET_SPLUNK_PW = "your-password"
    python scripts/seed_roi_metrics.py
"""

import json
import os
import sys
import time
from datetime import datetime, timedelta, timezone

import splunklib.client as client

WEEKS = 8
MIN_PER_ALERT = 25  # analyst minutes saved per auto-closed false positive


def connect():
    user = os.environ.get("PHISHNET_SPLUNK_USER", "VineetLoyer")
    pw = os.environ.get("PHISHNET_SPLUNK_PW")
    if not pw:
        print("Set PHISHNET_SPLUNK_PW (and optionally PHISHNET_SPLUNK_USER).")
        print("  PowerShell:  $env:PHISHNET_SPLUNK_PW = 'your-password'")
        sys.exit(1)
    return client.connect(
        host="localhost", port=8089, scheme="https",
        username=user, password=pw, app="phishnet_ai",
    )


def build_weeks():
    """8 weeks ending this week, oldest first."""
    today = datetime.now(timezone.utc).date()
    monday = today - timedelta(days=today.weekday())
    rows = []
    for i in range(WEEKS - 1, -1, -1):
        week_start = (monday - timedelta(weeks=i)).strftime("%Y-%m-%d")
        # Volume rises slightly week over week.
        processed = 230 + (WEEKS - 1 - i) * 12 + (i % 3) * 7
        threats = 1 + ((WEEKS - 1 - i) % 3)            # 1-3 real threats / week
        auto_closed = int(processed * 0.82)            # ~82% obvious FPs auto-closed
        minutes_saved = auto_closed * MIN_PER_ALERT
        accuracy = round(92.0 + (WEEKS - 1 - i) * 0.8, 1)        # 92% -> ~98%
        accuracy = min(accuracy, 98.5)
        escalation = round(14.0 - (WEEKS - 1 - i) * 1.1, 1)      # 14% -> ~6%
        escalation = max(escalation, 5.5)
        rows.append({
            "week_start": week_start,
            "alerts_processed": processed,
            "threats_caught": threats,
            "minutes_saved": minutes_saved,
            "accuracy_pct": accuracy,
            "escalation_rate": escalation,
        })
    return rows


def main():
    service = connect()
    if "phishnet_metrics" not in service.kvstore:
        print("phishnet_metrics collection not found — deploy the app first "
              "(collections.conf creates it).")
        return 1

    coll = service.kvstore["phishnet_metrics"].data
    now = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    n = 0
    for row in build_weeks():
        row["_key"] = row["week_start"]
        row["updated"] = now
        try:
            coll.insert(json.dumps(row))
            n += 1
        except Exception:
            try:
                coll.update(row["_key"], json.dumps(row))
                n += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  failed {row['week_start']}: {exc}")
    total_hours = sum(r["minutes_saved"] for r in build_weeks()) / 60.0
    print(f"Seeded {n} weeks of ROI metrics. Cumulative hours saved: {round(total_hours)}.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
