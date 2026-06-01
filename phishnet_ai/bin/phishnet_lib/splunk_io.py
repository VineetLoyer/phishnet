"""Splunk I/O: read alerts from / write results to Splunk.

Two backends:
  - file:  reads alerts from a local JSON file (synthetic data) and writes
           reports to stdout/files. Used in Week 1 standalone dev.
  - mcp:   reads via the Splunk MCP Server and writes to Splunk indexes +
           KV Store. Wired Week 1 Day 3.

The interface is intentionally small: get_alerts() and write_result().
"""

import json
import os
from typing import List, Iterable
from .models import Alert, Investigation
from .config import AgentConfig

# Default synthetic data location (produced by scripts/generate_demo_data.py)
_DEFAULT_DATA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "data", "generated", "alerts.json",
)


class FileBackend:
    """Reads synthetic alerts from JSON; writes reports to the data dir."""

    def __init__(self, config: AgentConfig, path: str = None):
        self.config = config
        self.path = path or os.path.normpath(_DEFAULT_DATA)

    def get_alerts(self) -> List[Alert]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        alerts = []
        for r in records:
            alerts.append(Alert(
                alert_id=r["alert_id"],
                received_at=r.get("received_at", ""),
                sender=r.get("sender", ""),
                sender_domain=r.get("sender_domain", ""),
                subject=r.get("subject", ""),
                recipients=r.get("recipients", []),
                urls=r.get("urls", []),
                attachments=r.get("attachments", []),
                raw=r,
            ))
        if self.config.limit:
            alerts = alerts[: self.config.limit]
        return alerts

    def write_result(self, investigation: Investigation) -> None:
        # In dev we just print; persisting to KV Store happens in the MCP backend.
        # (pipeline handles printing the rendered report)
        pass


class McpBackend:
    """Reads/writes via the Splunk MCP Server. Wired Week 1 Day 3."""

    def __init__(self, config: AgentConfig):
        self.config = config

    def get_alerts(self) -> List[Alert]:
        # TODO(week1-day3): use the MCP client to run an SPL search against
        # index=phishing and map results to Alert objects.
        raise NotImplementedError("MCP backend wired on Week 1 Day 3.")

    def write_result(self, investigation: Investigation) -> None:
        # TODO(week1-day3): write report to index=phishnet_actions and upsert
        # the verdict into the phishnet_decisions KV Store collection via MCP.
        raise NotImplementedError("MCP backend wired on Week 1 Day 3.")


def get_backend(config: AgentConfig):
    """Return the I/O backend. File-based for dev; MCP when token is present."""
    if config.splunk_token:
        return McpBackend(config)
    return FileBackend(config)
