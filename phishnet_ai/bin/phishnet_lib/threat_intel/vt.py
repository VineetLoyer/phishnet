"""VirusTotal v3 provider.

Only called when a key is configured and the cache missed. Returns a normalized
dict (matching the synthesized shape in __init__) or None on any failure, so the
caller falls back to synthesis and the demo never breaks.
"""

from typing import Any, Dict, Optional

_BASE = "https://www.virustotal.com/api/v3"


def _normalize(stats: Dict[str, int], indicator: str, indicator_type: str) -> Dict[str, Any]:
    malicious = int(stats.get("malicious", 0))
    suspicious = int(stats.get("suspicious", 0))
    harmless = int(stats.get("harmless", 0))
    undetected = int(stats.get("undetected", 0))
    return {
        "source": "virustotal",
        "indicator": indicator,
        "indicator_type": indicator_type,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless + undetected,
        "total_engines": malicious + suspicious + harmless + undetected,
        "synthesized": False,
    }


def lookup_domain(domain: str, api_key: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    try:
        import requests

        resp = requests.get(
            f"{_BASE}/domains/{domain}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return _normalize(stats, domain, "domain")
    except Exception:
        return None


def lookup_url(url: str, api_key: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    try:
        import base64
        import requests

        url_id = base64.urlsafe_b64encode(url.encode()).decode().strip("=")
        resp = requests.get(
            f"{_BASE}/urls/{url_id}",
            headers={"x-apikey": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return _normalize(stats, url, "url")
    except Exception:
        return None
