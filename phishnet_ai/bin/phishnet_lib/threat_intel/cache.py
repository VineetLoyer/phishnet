"""KV-Store-backed cache for threat-intel responses.

Keyed by source + indicator so a domain can be looked up independently per
provider. Falls back to a no-op (returns None / skips writes) when no Splunk
credentials are available — that path is exercised by the offline file backend
and unit tests, and simply means every lookup synthesizes instead of caching.
"""

import json
import time
from typing import Any, Dict, Optional

COLLECTION = "phishnet_threat_intel"


def _key(source: str, indicator_type: str, indicator: str) -> str:
    return f"{source}:{indicator_type}:{indicator}"


class IntelCache:
    def __init__(self, config=None):
        self.config = config
        self._coll = None
        self._connected = False
        self._mem: Optional[Dict[str, Dict[str, Any]]] = None

    def _collection(self):
        """Lazily resolve the KV collection; returns None if unavailable.

        On first connect, preload every row into memory so subsequent get()
        calls are dict lookups — a batch of alerts then costs one query instead
        of an HTTP round-trip (and a 404 on every cache miss) per indicator.
        """
        if self._connected:
            return self._coll
        self._connected = True
        cfg = self.config
        if cfg is None:
            return None
        has_creds = getattr(cfg, "splunk_token", None) or (
            getattr(cfg, "splunk_username", None) and getattr(cfg, "splunk_password", None)
        )
        if not has_creds:
            return None
        try:
            import splunklib.client as client

            kwargs = {
                "host": cfg.splunk_host,
                "port": cfg.splunk_port,
                "scheme": "https",
                "owner": "nobody",
                "app": "phishnet_ai",
            }
            if cfg.splunk_token:
                kwargs["splunkToken"] = cfg.splunk_token
            else:
                kwargs["username"] = cfg.splunk_username
                kwargs["password"] = cfg.splunk_password
            service = client.connect(**kwargs)
            self._coll = service.kvstore[COLLECTION].data
            self._mem = {r.get("_key"): r for r in self._coll.query()}
        except Exception:
            self._coll = None
            self._mem = {}
        return self._coll

    def get(self, indicator: str, indicator_type: str, source: str) -> Optional[Dict[str, Any]]:
        if self._collection() is None:
            return None
        rec = (self._mem or {}).get(_key(source, indicator_type, indicator))
        raw = rec.get("response") if rec else None
        if not raw:
            return None
        try:
            return json.loads(raw)
        except (TypeError, ValueError):
            return None

    def set(self, indicator: str, indicator_type: str, source: str,
            response: Dict[str, Any]) -> None:
        coll = self._collection()
        if coll is None:
            return
        record = {
            "_key": _key(source, indicator_type, indicator),
            "indicator": indicator,
            "indicator_type": indicator_type,
            "source": source,
            "response": json.dumps(response),
            "cached_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        }
        try:
            coll.insert(json.dumps(record))
        except Exception:
            try:
                coll.update(record["_key"], json.dumps(record))
            except Exception:
                pass
        if self._mem is not None:
            self._mem[record["_key"]] = record
