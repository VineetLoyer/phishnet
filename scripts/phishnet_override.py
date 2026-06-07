#!/usr/bin/env python
"""
PhishNet AI - Analyst decision / override CLI (human-in-the-loop)

Lets an analyst act on the agent's recommendation and records the decision in
the audit trail. Every participant in our discovery interviews rejected silent
auto-remediation, so every action here is explicit and logged.

Actions:
  approve   - accept the agent's recommendation, mark the decision confirmed
  override  - disagree with the agent; set a new verdict/action, flag override
  reopen    - re-open an auto-closed alert for another look
  remediate - record an approved remediation (block sender, quarantine, reset)

Each action:
  1. Writes an event to index=phishnet_audit (sourcetype=phishnet:audit)
  2. Updates the phishnet_decisions KV Store record

Usage (PowerShell):
    $env:PHISHNET_SPLUNK_USER = "VineetLoyer"
    $env:PHISHNET_SPLUNK_PW = "your-password"
    python scripts/phishnet_override.py approve   --alert PH-0050 --analyst maya
    python scripts/phishnet_override.py override  --alert PH-0050 --analyst maya --verdict legitimate --action close --note "known vendor"
    python scripts/phishnet_override.py remediate --alert PH-0286 --analyst maya --note "blocked sender, reset creds"
    python scripts/phishnet_override.py reopen     --alert PH-0010 --analyst maya
"""

import argparse
import json
import os
import sys
import time

import splunklib.client as client


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


def write_audit(service, action, alert_id, analyst, detail):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event = {
        "action": action,
        "alert_id": alert_id,
        "analyst": analyst,
        "detail": detail,
        "ts": ts,
    }
    # Real audit trail: event index.
    index = service.indexes["phishnet_audit"]
    index.submit(json.dumps(event), sourcetype="phishnet:audit", source="phishnet:override")
    # Dashboard-readable mirror: KV (event searches render empty in Simple XML here).
    try:
        rec = dict(event)
        rec["_key"] = f"{action}-{alert_id}-{ts}".replace(":", "")
        service.kvstore["phishnet_audit_log"].data.insert(json.dumps(rec))
    except Exception:  # noqa: BLE001 - non-fatal mirror
        pass
    print(f"audit: [{action}] {alert_id} by {analyst} — {detail}")


def update_decision(service, alert_id, patch):
    coll = service.kvstore["phishnet_decisions"].data
    rows = coll.query(query=json.dumps({"alert_id": alert_id}))
    if not rows:
        print(f"No KV record for {alert_id}; audit written, decision not updated.")
        return
    record = rows[0]
    record.update(patch)
    coll.update(alert_id, json.dumps(record))
    print(f"decision: {alert_id} -> {patch}")


def main():
    p = argparse.ArgumentParser(description="PhishNet AI analyst override / decision CLI")
    p.add_argument("action", choices=["approve", "override", "reopen", "remediate"])
    p.add_argument("--alert", required=True, help="Alert ID, e.g. PH-0286")
    p.add_argument("--analyst", default="analyst", help="Analyst name for the audit trail")
    p.add_argument("--verdict", default=None, help="(override) new verdict label")
    p.add_argument("--action-set", dest="action_set", default=None,
                   help="(override) new recommended_action, e.g. close|escalate|remediate")
    p.add_argument("--note", default="", help="Free-text note for the audit trail")
    args = p.parse_args()

    service = connect()
    alert_id = args.alert

    if args.action == "approve":
        write_audit(service, "approve", alert_id, args.analyst,
                    args.note or "Approved agent recommendation")
        update_decision(service, alert_id, {"status": "confirmed"})

    elif args.action == "override":
        patch = {"status": "overridden", "analyst_override": True}
        if args.verdict:
            patch["verdict"] = args.verdict
        if args.action_set:
            patch["recommended_action"] = args.action_set
        detail = args.note or f"Analyst override -> verdict={args.verdict}, action={args.action_set}"
        write_audit(service, "override", alert_id, args.analyst, detail)
        update_decision(service, alert_id, patch)

    elif args.action == "reopen":
        write_audit(service, "reopen", alert_id, args.analyst,
                    args.note or "Re-opened for re-investigation")
        update_decision(service, alert_id, {"status": "pending", "recommended_action": "review"})

    elif args.action == "remediate":
        write_audit(service, "remediate", alert_id, args.analyst,
                    args.note or "Approved remediation (block sender, quarantine, reset creds)")
        update_decision(service, alert_id, {"status": "confirmed", "recommended_action": "remediate"})

    print("Done.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
