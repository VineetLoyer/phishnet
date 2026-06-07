"""Threat-intel enrichment for the investigation playbook.

Adds external reputation context (VirusTotal, urlscan.io) to an alert's sender
domain and URLs. The lookup is deliberately demo-safe:

    1. KV cache  (phishnet_threat_intel)  -> instant, offline, the demo path
    2. live API  (only if an API key is configured AND the cache missed)
    3. synthesis (deterministic, derived from the alert's own reputation data)

Step 3 means every alert gets believable intel even with zero API keys and an
empty cache, so the dashboards are never blank on stage. Each provider is a
single, isolated swap point — drop in a real key and the same code path calls
the live API and caches the response.

`attach_intel(alert, config)` mutates `alert.raw["threat_intel"]` and returns it.
"""

import hashlib
from typing import Any, Dict, Optional

from .cache import IntelCache
from . import vt, urlscan

_cache_singleton: Optional[IntelCache] = None


def _get_cache(config) -> IntelCache:
    """One cache per process; lazily connects to KV when creds are present."""
    global _cache_singleton
    if _cache_singleton is None:
        _cache_singleton = IntelCache(config)
    return _cache_singleton


def _seed(indicator: str) -> int:
    """Stable pseudo-random seed derived from the indicator string."""
    return int(hashlib.sha256(indicator.encode("utf-8")).hexdigest(), 16)


def _synth_domain(domain: str, age_days: int) -> Dict[str, Any]:
    """Believable VirusTotal-style domain reputation from local signals."""
    if age_days < 7:
        rng = _seed(domain)
        malicious = 6 + rng % 9          # 6-14 engines
        suspicious = 2 + (rng >> 4) % 4
    elif age_days < 90:
        rng = _seed(domain)
        malicious = rng % 3              # 0-2 engines
        suspicious = 1 + (rng >> 4) % 3
    else:
        malicious = 0
        suspicious = 0
    total = 89
    harmless = total - malicious - suspicious
    return {
        "source": "virustotal",
        "indicator": domain,
        "indicator_type": "domain",
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "total_engines": total,
        "synthesized": True,
    }


def _synth_url(url: str, verdict: str) -> Dict[str, Any]:
    """Believable urlscan.io-style verdict from the alert's baked URL verdict."""
    rng = _seed(url)
    if verdict == "malicious":
        score = -(60 + rng % 40)         # urlscan score: negative = malicious
        categories = ["phishing", "credential-harvesting"]
        v = "malicious"
    elif verdict == "suspicious":
        score = -(10 + rng % 30)
        categories = ["suspicious-redirect"]
        v = "suspicious"
    else:
        score = rng % 10
        categories = []
        v = "benign"
    return {
        "source": "urlscan",
        "indicator": url,
        "indicator_type": "url",
        "verdict": v,
        "score": score,
        "categories": categories,
        "synthesized": True,
    }


def _lookup_domain(domain: str, age_days: int, config, cache: IntelCache) -> Dict[str, Any]:
    cached = cache.get(domain, "domain", "virustotal")
    if cached is not None:
        return cached
    if config and getattr(config, "vt_api_key", None):
        live = vt.lookup_domain(domain, config.vt_api_key, getattr(config, "llm_timeout", 30))
        if live is not None:
            cache.set(domain, "domain", "virustotal", live)
            return live
    return _synth_domain(domain, age_days)


def _lookup_url(url: str, verdict: str, config, cache: IntelCache) -> Dict[str, Any]:
    cached = cache.get(url, "url", "urlscan")
    if cached is not None:
        return cached
    if config and getattr(config, "urlscan_api_key", None):
        live = urlscan.lookup_url(url, config.urlscan_api_key, getattr(config, "llm_timeout", 30))
        if live is not None:
            cache.set(url, "url", "urlscan", live)
            return live
    return _synth_url(url, verdict)


def attach_intel(alert, config=None) -> Dict[str, Any]:
    """Enrich an alert with threat intel and stash it on alert.raw['threat_intel'].

    Safe to call repeatedly; returns the intel dict
    {"domain": {...}, "urls": {url: {...}}}.
    """
    cache = _get_cache(config)
    age_days = alert.raw.get("sender_domain_age_days", 365)
    verdicts = alert.raw.get("url_verdicts", {})

    intel: Dict[str, Any] = {"domain": None, "urls": {}}
    if alert.sender_domain:
        intel["domain"] = _lookup_domain(alert.sender_domain, age_days, config, cache)
    for url in alert.urls:
        intel["urls"][url] = _lookup_url(url, verdicts.get(url, "unknown"), config, cache)

    alert.raw["threat_intel"] = intel
    return intel
