"""Splunk-native reputation enrichment for the investigation playbook.

Instead of phoning a third-party API (VirusTotal/urlscan), PhishNet derives an
indicator's reputation from Splunk's *own* telemetry — how new the domain is to
your environment, how many alerts it spans, how many recipients it reached, and
how often the agent has previously judged it malicious. That works even for
never-before-seen domains (where an external feed returns "no data") and keeps
the whole pipeline in-platform.

Lookup strategy (demo-safe, offline-safe):

    1. KV cache (phishnet_threat_intel) -> the batch-computed reputation, the
       authoritative record used in the demo. Seeded by scripts/seed_threat_intel.py
       from one Splunk search across index=phishing + phishnet_decisions.
    2. local derivation -> if the cache misses (offline / file backend / an
       indicator the batch never saw), derive a believable record from the
       alert's own fields so a finding is never blank.

`attach_intel(alert, config)` mutates `alert.raw["threat_intel"]` and returns it.
"""

from typing import Any, Dict, Optional

from .cache import IntelCache

# Single logical source now that reputation is computed in-platform.
SOURCE = "splunk_local"

_cache_singleton: Optional[IntelCache] = None


def _get_cache(config) -> IntelCache:
    """One cache per process; lazily connects to KV when creds are present."""
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = IntelCache(config)
    return _cache_singleton


def _risk(age_days: int, prior_malicious: int) -> str:
    if age_days < 3 or prior_malicious > 0:
        return "high"
    if age_days < 90:
        return "medium"
    return "low"


def _local_domain(domain: str, age_days: int) -> Dict[str, Any]:
    """Reputation derived from the alert's own fields when the cache misses.

    No cross-alert Splunk stats are available here, so first_seen/reach are left
    unknown and the record is flagged `derived` so the finding phrases honestly.
    """
    return {
        "source": SOURCE,
        "indicator": domain,
        "indicator_type": "domain",
        "first_seen": "",
        "days_observed": age_days,
        "alert_count": 1,
        "recipient_reach": 0,
        "prior_malicious": 0,
        "risk": _risk(age_days, 0),
        "derived": True,
    }


def _local_url(url: str, verdict: str) -> Dict[str, Any]:
    """URL reputation derived from the alert's baked proxy verdict on cache miss."""
    v = verdict if verdict in ("malicious", "suspicious", "benign") else "unknown"
    return {
        "source": SOURCE,
        "indicator": url,
        "indicator_type": "url",
        "verdict": v,
        "seen_count": 1,
        "prior_malicious": 0,
        "derived": True,
    }


def _lookup_domain(domain: str, age_days: int, cache: IntelCache) -> Dict[str, Any]:
    cached = cache.get(domain, "domain", SOURCE)
    if cached is not None:
        return cached
    return _local_domain(domain, age_days)


def _lookup_url(url: str, verdict: str, cache: IntelCache) -> Dict[str, Any]:
    cached = cache.get(url, "url", SOURCE)
    if cached is not None:
        return cached
    return _local_url(url, verdict)


def attach_intel(alert, config=None) -> Dict[str, Any]:
    """Enrich an alert with reputation and stash it on alert.raw['threat_intel'].

    Safe to call repeatedly; returns the intel dict
    {"domain": {...}, "urls": {url: {...}}}.
    """
    cache = _get_cache(config)
    age_days = alert.raw.get("sender_domain_age_days", 365)
    verdicts = alert.raw.get("url_verdicts", {})

    intel: Dict[str, Any] = {"domain": None, "urls": {}}
    if alert.sender_domain:
        intel["domain"] = _lookup_domain(alert.sender_domain, age_days, cache)
    for url in alert.urls:
        intel["urls"][url] = _lookup_url(url, verdicts.get(url, "unknown"), cache)

    alert.raw["threat_intel"] = intel
    return intel
