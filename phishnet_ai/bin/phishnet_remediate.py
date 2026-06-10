#!/usr/bin/env python
"""
PhishNet AI - Modular Alert Action: Remediation

Triggered when an analyst approves a recommended action from the Command Center
(e.g. block sender domain, quarantine emails, force credential reset). Splunk
invokes this script with `--execute` and the alert payload as JSON on stdin.

This is analyst-approved (human-in-the-loop) by design — all remediation
actions require explicit approval and are logged to the audit index.

On execution it:
  1. Writes an audit event to index=phishnet_audit (sourcetype=phishnet:audit)
  2. Flips the phishnet_decisions KV Store record to status=confirmed
"""

import json
import sys
import time

try:
    import splunklib.client as client
except ImportError:
    client = None


def _connect(session_key):
    """Connect to splunkd using the session key Splunk passes to alert actions."""
    if client is None or not session_key:
        return None
    try:
        return client.connect(
            host="localhost", port=8089, scheme="https",
            token=session_key, owner="nobody", app="phishnet_ai",
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"phishnet_remediate: connect failed: {exc}\n")
        return None


def _write_audit(service, action, alert_id, analyst, detail):
    ts = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
    event = {
        "action": action, "alert_id": alert_id, "analyst": analyst,
        "detail": detail, "ts": ts,
    }
    try:
        service.indexes["phishnet_audit"].submit(
            json.dumps(event), sourcetype="phishnet:audit", source="phishnet:remediate",
        )
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"phishnet_remediate: audit write failed: {exc}\n")
    # Dashboard-readable mirror in KV.
    try:
        rec = dict(event)
        rec["_key"] = f"{action}-{alert_id}-{ts}".replace(":", "")
        service.kvstore["phishnet_audit_log"].data.insert(json.dumps(rec))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"phishnet_remediate: audit KV mirror failed: {exc}\n")


def _confirm_decision(service, alert_id, action):
    try:
        coll = service.kvstore["phishnet_decisions"].data
        rows = coll.query(query=json.dumps({"alert_id": alert_id}))
        if not rows:
            return
        record = rows[0]
        record.update({"status": "confirmed", "recommended_action": action})
        coll.update(alert_id, json.dumps(record))
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"phishnet_remediate: KV update failed: {exc}\n")


def main():
    if len(sys.argv) < 2 or sys.argv[1] != "--execute":
        sys.stderr.write("phishnet_remediate: must be run as an alert action (--execute)\n")
        return 1

    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}

    config = payload.get("configuration", {})
    action = config.get("action", "remediate")
    alert_id = config.get("alert_id", payload.get("result", {}).get("alert_id", "unknown"))
    analyst = config.get("analyst", "command_center")
    detail = config.get("detail", "Approved remediation via Command Center")
    session_key = payload.get("session_key", "")

    service = _connect(session_key)
    if service is None:
        sys.stderr.write("phishnet_remediate: no Splunk session; nothing persisted.\n")
        return 1

    _write_audit(service, action, alert_id, analyst, detail)
    _confirm_decision(service, alert_id, action)
    sys.stderr.write(f"phishnet_remediate: {action} recorded for {alert_id}\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
