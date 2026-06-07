"""urlscan.io provider.

Uses the search API (no submission) to fetch an existing verdict for a URL.
Only called when a key is configured and the cache missed; returns None on any
failure so the caller falls back to synthesis.
"""

from typing import Any, Dict, Optional

_SEARCH = "https://urlscan.io/api/v1/search/"


def lookup_url(url: str, api_key: str, timeout: int = 30) -> Optional[Dict[str, Any]]:
    try:
        import requests

        resp = requests.get(
            _SEARCH,
            params={"q": f'page.url:"{url}"', "size": 1},
            headers={"API-Key": api_key},
            timeout=timeout,
        )
        if resp.status_code != 200:
            return None
        results = resp.json().get("results", [])
        if not results:
            return None
        verdicts = results[0].get("verdicts", {}).get("overall", {})
        score = int(verdicts.get("score", 0))
        malicious = bool(verdicts.get("malicious", False))
        return {
            "source": "urlscan",
            "indicator": url,
            "indicator_type": "url",
            "verdict": "malicious" if malicious else ("suspicious" if score < 0 else "benign"),
            "score": score,
            "categories": verdicts.get("categories", []),
            "synthesized": False,
        }
    except Exception:
        return None
