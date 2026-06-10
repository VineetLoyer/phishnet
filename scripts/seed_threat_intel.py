#!/usr/bin/env python
"""
PhishNet AI - Compute Splunk-native reputation into the phishnet_threat_intel KV.

Instead of caching third-party (VirusTotal/urlscan) responses, this computes an
in-platform reputation for every sender domain and signal-bearing URL from
PhishNet's OWN Splunk data:

  - alert_count     : how many alerts the indicator appears in (index=phishing)
  - recipient_reach : total recipients those alerts targeted
  - prior_malicious : how many of those alerts the agent judged malicious
                      (cross-referenced from the phishnet_decisions KV)
  - first_seen      : earliest time the indicator appeared in your environment

The agent and the enrich script then read this instantly/offline, and the
investigation reasoning cites real in-house signals — no API keys, no external
calls, and it works even for never-before-seen domains.

Usage (PowerShell):
    $env:PHISHNET_SPLUNK_USER = "VineetLoyer"
    $env:PHISHNET_SPLUNK_PW = "your-password"
    python scripts/seed_threat_intel.py
"""

import json
import os
import sys

import splunklib.client as client
import splunklib.results as results

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib.config import AgentConfig  # noqa: E402
from phishnet_lib.threat_intel import SOURCE  # noqa: E402
from phishnet_lib.threat_intel.cache import IntelCache  # noqa: E402

# Agent verdicts that count an alert as malicious for reputation purposes.
MALICIOUS_VERDICTS = {"targeted_attack", "phishing"}


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


def load_alerts(service):
    job = service.jobs.oneshot(
        "search index=phishing sourcetype=phishnet:alert | fields _raw",
        output_mode="json", count=0, earliest_time="0", latest_time="now",
    )
    out = []
    for item in results.JSONResultsReader(job):
        if isinstance(item, dict) and "_raw" in item:
            try:
                out.append(json.loads(item["_raw"]))
            except (TypeError, ValueError):
                continue
    return out


def load_verdicts(service):
    """alert_id -> agent verdict, from the phishnet_decisions KV collection."""
    try:
        rows = service.kvstore["phishnet_decisions"].data.query()
    except Exception:
        return {}
    return {r.get("alert_id"): r.get("verdict") for r in rows if r.get("alert_id")}


def _domain_of(sender: str) -> str:
    return sender.split("@")[-1].strip().lower() if sender and "@" in sender else ""


def compute_reputation(alerts, verdicts):
    """Aggregate per-domain and per-URL reputation from the alert corpus."""
    domains = {}
    urls = {}
    for raw in alerts:
        alert_id = raw.get("alert_id", "")
        verdict = verdicts.get(alert_id, "")
        is_mal = verdict in MALICIOUS_VERDICTS
        received = raw.get("received_at", "")

        domain = (raw.get("sender_domain") or _domain_of(raw.get("sender", ""))).lower()
        if domain:
            d = domains.setdefault(domain, {
                "alert_count": 0, "recipient_reach": 0,
                "prior_malicious": 0, "first_seen": received,
            })
            d["alert_count"] += 1
            d["recipient_reach"] += len(raw.get("recipients", []))
            if is_mal:
                d["prior_malicious"] += 1
            if received and (not d["first_seen"] or received < d["first_seen"]):
                d["first_seen"] = received

        url_verdicts = raw.get("url_verdicts", {})
        for url in raw.get("urls", []):
            u = urls.setdefault(url, {
                "verdict": url_verdicts.get(url, "unknown"),
                "seen_count": 0, "prior_malicious": 0,
            })
            u["seen_count"] += 1
            if is_mal:
                u["prior_malicious"] += 1
    return domains, urls


def seed(service):
    """Recompute Splunk-native reputation and write it to phishnet_threat_intel."""
    if "phishnet_threat_intel" not in service.kvstore:
        print("phishnet_threat_intel collection not found — deploy the app first.")
        return 1

    alerts = load_alerts(service)
    if not alerts:
        print("No alerts in index=phishing. Run ingest first.")
        return 1
    verdicts = load_verdicts(service)
    domains, urls = compute_reputation(alerts, verdicts)

    # Start clean so stale records (e.g. old external-API rows) don't linger.
    try:
        service.kvstore["phishnet_threat_intel"].data.delete()
    except Exception:
        pass

    cache = IntelCache(AgentConfig())
    for domain, d in domains.items():
        risk = "high" if d["prior_malicious"] else ("medium" if d["alert_count"] > 1 else "low")
        cache.set(domain, "domain", SOURCE, {
            "source": SOURCE, "indicator": domain, "indicator_type": "domain",
            "first_seen": d["first_seen"],
            "alert_count": d["alert_count"],
            "recipient_reach": d["recipient_reach"],
            "prior_malicious": d["prior_malicious"],
            "risk": risk, "derived": False,
        })

    # URLs: only cache signal-bearing ones (the rest derive cleanly at lookup).
    n_urls = 0
    for url, u in urls.items():
        if u["verdict"] in ("malicious", "suspicious") or u["prior_malicious"]:
            cache.set(url, "url", SOURCE, {
                "source": SOURCE, "indicator": url, "indicator_type": "url",
                "verdict": u["verdict"], "seen_count": u["seen_count"],
                "prior_malicious": u["prior_malicious"], "derived": False,
            })
            n_urls += 1

    print(f"Computed Splunk-native reputation: {len(domains)} domain(s), "
          f"{n_urls} signal-bearing URL(s) into phishnet_threat_intel.")
    return 0


def main():
    return seed(connect())


if __name__ == "__main__":
    raise SystemExit(main())
