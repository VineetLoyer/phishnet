#!/usr/bin/env python
"""
PhishNet AI - Pre-cache threat-intel responses for the demo.

Reads the live alert indicators from index=phishing and writes a cached
VirusTotal / urlscan.io response into the phishnet_threat_intel KV collection
for every indicator that carries a signal (malicious/suspicious URL, or a
newly-registered sender domain). With the cache warm, the agent and the
enrich script resolve intel instantly and offline — no API keys, no rate
limits, no live calls during the demo.

Indicators are pulled from the real generated data, so the cached responses
always match whatever demo dataset is currently loaded.

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
from phishnet_lib.threat_intel import _synth_domain, _synth_url  # noqa: E402
from phishnet_lib.threat_intel.cache import IntelCache  # noqa: E402


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


def seed(service):
    """Warm the threat-intel KV cache from current index=phishing indicators."""
    if "phishnet_threat_intel" not in service.kvstore:
        print("phishnet_threat_intel collection not found — deploy the app first.")
        return 1

    cache = IntelCache(AgentConfig())
    alerts = load_alerts(service)
    if not alerts:
        print("No alerts in index=phishing. Run ingest first.")
        return 1

    domains, urls = 0, 0
    seen_domains = set()
    for raw in alerts:
        domain = raw.get("sender_domain", "")
        age = raw.get("sender_domain_age_days", 365)
        # Only cache intel for domains with a signal (young) — mirrors real
        # behavior of only querying intel when a check warrants it.
        if domain and domain not in seen_domains and age < 90:
            cache.set(domain, "domain", "virustotal", _synth_domain(domain, age))
            seen_domains.add(domain)
            domains += 1
        for url, verdict in raw.get("url_verdicts", {}).items():
            if verdict in ("malicious", "suspicious"):
                cache.set(url, "url", "urlscan", _synth_url(url, verdict))
                urls += 1

    print(f"Cached threat intel: {domains} domain(s), {urls} URL(s) "
          f"into phishnet_threat_intel.")
    return 0


def main():
    return seed(connect())


if __name__ == "__main__":
    raise SystemExit(main())
