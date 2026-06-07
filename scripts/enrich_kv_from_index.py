#!/usr/bin/env python
"""
PhishNet AI - Backfill phishnet_decisions KV from index=phishing alert JSON.

Dashboards read blast-radius fields via | inputlookup phishnet_decisions |.
Run this after ingest or whenever KV rows are missing sender/subject/timeline.

Usage (PowerShell):
    $env:PHISHNET_SPLUNK_USER = "VineetLoyer"
    $env:PHISHNET_SPLUNK_PW = "your-password"
    python scripts/enrich_kv_from_index.py
"""

import json
import os
import sys

import splunklib.client as client
import splunklib.results as results

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib import investigation as playbook  # noqa: E402
from phishnet_lib import threat_intel  # noqa: E402
from phishnet_lib.config import AgentConfig  # noqa: E402
from phishnet_lib.models import Alert  # noqa: E402

# Reused for threat-intel enrichment so steps_text reflects the KV intel cache.
_CONFIG = AgentConfig()


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


def _timeline_text(timeline):
    if not timeline:
        return ""
    return " || ".join(
        "{}\t{}".format(
            t.get("time", ""),
            str(t.get("event", "")).replace("\t", " "),
        )
        for t in timeline
    )


def _endpoint_text(raw):
    """Endpoint CPU/network series for the affected host.

    Uses raw.endpoint_metrics if present (new generator output); otherwise
    synthesizes the baseline->spike->C2 series for hosts that executed a payload,
    so already-ingested demo data still drives the Blast Radius metrics panel.
    """
    metrics = raw.get("endpoint_metrics")
    if not metrics:
        if not raw.get("payload_executed"):
            return ""
        hosts = raw.get("affected_hosts", [])
        if not hosts:
            return ""
        import random as _r
        from datetime import datetime, timedelta, timezone

        def _ts(mins):
            return (datetime.now(timezone.utc) - timedelta(minutes=mins)).strftime("%Y-%m-%dT%H:%M:%SZ")

        metrics = []
        for minutes in range(50, 39, -1):
            if minutes >= 46:
                cpu, net = _r.randint(8, 16), _r.randint(2, 8)
            elif minutes >= 44:
                cpu, net = _r.randint(88, 96), _r.randint(120, 240)
            else:
                cpu, net = _r.randint(60, 80), _r.randint(500, 820)
            metrics.append({"time": _ts(minutes), "cpu_pct": cpu, "net_out_kb": net})

    return " || ".join(
        "{}\t{}\t{}".format(m.get("time", ""), m.get("cpu_pct", ""), m.get("net_out_kb", ""))
        for m in metrics
    )


def _steps_text(raw):
    """Run the deterministic playbook to reconstruct the agent's reasoning steps."""
    alert = Alert(
        alert_id=raw.get("alert_id", ""),
        received_at=raw.get("received_at", ""),
        sender=raw.get("sender", ""),
        sender_domain=raw.get("sender_domain", ""),
        subject=raw.get("subject", ""),
        recipients=raw.get("recipients", []),
        urls=raw.get("urls", []),
        attachments=raw.get("attachments", []),
        raw=raw,
    )
    threat_intel.attach_intel(alert, _CONFIG)
    steps = playbook.investigate(alert)
    return " || ".join(
        "{}\t{}\t{}\t{}".format(
            s.signal,
            s.name,
            s.tool,
            str(s.finding).replace("\t", " ").replace("||", "/"),
        )
        for s in steps
    )


def load_alerts_from_index(service):
    spl = (
        "search index=phishing sourcetype=phishnet:alert "
        "| fields _raw"
    )
    job = service.jobs.oneshot(
        spl, output_mode="json", count=0, earliest_time="0", latest_time="now",
    )
    alerts = {}
    for item in results.JSONResultsReader(job):
        if not isinstance(item, dict) or "_raw" not in item:
            continue
        try:
            record = json.loads(item["_raw"])
        except (TypeError, ValueError):
            continue
        alert_id = record.get("alert_id")
        if alert_id:
            alerts[alert_id] = record
    return alerts


def enrich(service):
    coll = service.kvstore["phishnet_decisions"].data
    alerts = load_alerts_from_index(service)
    if not alerts:
        print("No alerts found in index=phishing. Run ingest first.")
        return 1

    updated, inserted = 0, 0
    for alert_id, raw in alerts.items():
        timeline = raw.get("blast_timeline", [])
        hosts = raw.get("affected_hosts", [])
        patch = {
            "_key": alert_id,
            "alert_id": alert_id,
            "payload_executed": bool(raw.get("payload_executed", False)),
            "affected_host": hosts[0] if hosts else "",
            "recipient_count": len(raw.get("recipients", [])),
            "sender": raw.get("sender", ""),
            "subject": raw.get("subject", ""),
            "users_clicked": len(raw.get("clicked_users", [])),
            "creds_submitted": len(raw.get("cred_submitted_users", [])),
            "blast_timeline_json": json.dumps(timeline) if timeline else "",
            "blast_timeline_text": _timeline_text(timeline),
            "steps_text": _steps_text(raw),
            "endpoint_metrics_text": _endpoint_text(raw),
        }

        existing = coll.query(query=json.dumps({"alert_id": alert_id}))
        if existing:
            record = existing[0]
            record.update(patch)
            try:
                coll.update(alert_id, json.dumps(record))
                updated += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  update failed {alert_id}: {exc}")
        else:
            record = {
                **patch,
                "verdict": raw.get("label_truth", "unknown"),
                "confidence": 0.0,
                "reasoning": "",
                "status": "pending",
                "recommended_action": "review",
                "analyst_override": False,
            }
            try:
                coll.insert(json.dumps(record))
                inserted += 1
            except Exception as exc:  # noqa: BLE001
                print(f"  insert failed {alert_id}: {exc}")

    print(f"Enriched KV from index=phishing: {updated} updated, {inserted} inserted "
          f"({len(alerts)} alerts in index).")
    return 0


def seed_audit_log(service):
    """Mirror existing index=phishnet_audit events into the phishnet_audit_log KV.

    Idempotent: uses a deterministic _key so re-runs don't duplicate.
    """
    try:
        coll = service.kvstore["phishnet_audit_log"].data
    except Exception as exc:  # noqa: BLE001
        print(f"  (audit_log KV not ready: {exc})")
        return
    spl = (
        'search index=phishnet_audit sourcetype=phishnet:audit '
        '| eval ts=strftime(_time, "%Y-%m-%dT%H:%M:%SZ") '
        '| table ts, action, alert_id, analyst, detail'
    )
    job = service.jobs.oneshot(spl, output_mode="json", count=0,
                               earliest_time="0", latest_time="now")
    n = 0
    for item in results.JSONResultsReader(job):
        if not isinstance(item, dict) or "action" not in item:
            continue
        rec = {
            "_key": "{}-{}-{}".format(
                item.get("action"), item.get("alert_id"), item.get("ts"),
            ).replace(":", ""),
            "ts": item.get("ts", ""),
            "action": item.get("action", ""),
            "alert_id": item.get("alert_id", ""),
            "analyst": item.get("analyst", ""),
            "detail": item.get("detail", ""),
        }
        try:
            coll.insert(json.dumps(rec))
            n += 1
        except Exception:
            try:
                coll.update(rec["_key"], json.dumps(rec))
            except Exception:
                pass
    print(f"Seeded audit log KV from index: {n} events.")


def main():
    service = connect()
    rc = enrich(service)
    seed_audit_log(service)
    return rc


if __name__ == "__main__":
    raise SystemExit(main())
