"""Splunk I/O: read alerts from / write results to Splunk.

Backends:
  - file:   reads alerts from a local JSON file (synthetic data) and prints
            reports. Used for fast offline dev.
  - sdk:    reads alerts via the Splunk Python SDK (splunklib) by searching
            index=phishing, and writes investigation results back to
            index=phishnet_actions plus the phishnet_decisions KV Store.
  - mcp:    (Day 3) reads/writes via the Splunk MCP Server for the agentic
            "tool interface" story. Falls back to sdk if unavailable.

The interface is intentionally small: get_alerts() and write_result().
Backend selection:
  - file  : default, no credentials
  - sdk   : when splunk_token OR splunk_username/password provided
  - mcp   : when use_mcp is set on the config (Day 3)
"""

import json
import os
from typing import List
from .models import Alert, Investigation
from .config import AgentConfig

# Default synthetic data location (produced by scripts/generate_demo_data.py)
_DEFAULT_DATA = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "..", "..", "data", "generated", "alerts.json",
)


# --------------------------------------------------------------------------- #
# File backend (offline dev)
# --------------------------------------------------------------------------- #
class FileBackend:
    """Reads synthetic alerts from JSON; prints reports (no persistence)."""

    name = "file"

    def __init__(self, config: AgentConfig, path: str = None):
        self.config = config
        self.path = path or os.path.normpath(_DEFAULT_DATA)

    def get_alerts(self) -> List[Alert]:
        if not os.path.exists(self.path):
            return []
        with open(self.path, "r", encoding="utf-8") as fh:
            records = json.load(fh)
        alerts = [_record_to_alert(r) for r in records]
        if self.config.limit:
            alerts = alerts[: self.config.limit]
        return alerts

    def write_result(self, investigation: Investigation) -> None:
        # Dev mode: pipeline prints the rendered report; nothing to persist.
        pass


# --------------------------------------------------------------------------- #
# Splunk SDK backend (native REST via splunklib)
# --------------------------------------------------------------------------- #
class SplunkSdkBackend:
    """Reads alerts from Splunk and writes results back, via splunklib.

    Reads:  search `index=<source_index> sourcetype=phishnet:alert`
    Writes: investigation reports -> index=<actions_index> (HEC or REST submit)
            verdict records        -> KV Store collection 'phishnet_decisions'
    """

    name = "sdk"

    def __init__(self, config: AgentConfig):
        self.config = config
        self._service = None
        self._kv = None

    # -- connection ------------------------------------------------------- #
    def _connect(self):
        if self._service is not None:
            return self._service
        import splunklib.client as client

        connect_kwargs = {
            "host": self.config.splunk_host,
            "port": self.config.splunk_port,
            "scheme": "https",
            "owner": "nobody",
            "app": "phishnet_ai",
        }
        if self.config.splunk_token:
            connect_kwargs["splunkToken"] = self.config.splunk_token
        else:
            connect_kwargs["username"] = self.config.splunk_username
            connect_kwargs["password"] = self.config.splunk_password

        self._service = client.connect(**connect_kwargs)
        return self._service

    # -- read ------------------------------------------------------------- #
    def get_alerts(self) -> List[Alert]:
        import splunklib.results as results

        service = self._connect()
        limit_clause = f"| head {self.config.limit}" if self.config.limit else ""
        # _raw holds the original JSON event we ingested via HEC.
        spl = (
            f'search index={self.config.source_index} '
            f'sourcetype=phishnet:alert {limit_clause} '
            f'| fields _raw'
        )
        job = service.jobs.oneshot(spl, output_mode="json", count=0)
        reader = results.JSONResultsReader(job)

        alerts: List[Alert] = []
        for item in reader:
            if isinstance(item, dict) and "_raw" in item:
                try:
                    record = json.loads(item["_raw"])
                    alerts.append(_record_to_alert(record))
                except (ValueError, KeyError):
                    continue
        return alerts

    # -- write ------------------------------------------------------------ #
    def write_result(self, investigation: Investigation) -> None:
        service = self._connect()
        self._write_report_event(service, investigation)
        self._upsert_decision(service, investigation)

    def _write_report_event(self, service, investigation: Investigation) -> None:
        """Submit the investigation result as an event into the actions index."""
        try:
            index = service.indexes[self.config.actions_index]
        except KeyError:
            # Index missing — skip gracefully (created by app indexes.conf)
            return
        index.submit(
            json.dumps(investigation.as_dict()),
            sourcetype="phishnet:investigation",
            source="phishnet:agent",
        )

    def _upsert_decision(self, service, investigation: Investigation) -> None:
        """Upsert the verdict into the phishnet_decisions KV Store collection."""
        try:
            coll = service.kvstore["phishnet_decisions"].data
        except Exception:
            return  # KV Store not ready; non-fatal in dev

        d = investigation.as_dict()
        br = investigation.blast_radius
        raw = investigation.alert.raw
        timeline = br.timeline if br else []
        timeline_text = ""
        if timeline:
            timeline_text = " || ".join(
                "{}\t{}".format(
                    t.get("time", ""),
                    str(t.get("event", "")).replace("\t", " "),
                )
                for t in timeline
            )
        steps_text = " || ".join(
            "{}\t{}\t{}\t{}".format(
                s.signal,
                s.name,
                s.tool,
                str(s.finding).replace("\t", " ").replace("||", "/"),
            )
            for s in investigation.steps
        )
        metrics = raw.get("endpoint_metrics", [])
        endpoint_metrics_text = " || ".join(
            "{}\t{}\t{}".format(
                m.get("time", ""),
                m.get("cpu_pct", ""),
                m.get("net_out_kb", ""),
            )
            for m in metrics
        )
        record = {
            "_key": d["alert_id"],
            "alert_id": d["alert_id"],
            "verdict": d.get("verdict"),
            "confidence": d.get("confidence"),
            "reasoning": d.get("reasoning"),
            "status": d.get("status"),
            "recommended_action": d.get("recommended_action"),
            "analyst_override": False,
            "payload_executed": bool(br.payload_executed) if br else False,
            "affected_host": br.affected_hosts[0] if br and br.affected_hosts else "",
            "recipient_count": len(investigation.alert.recipients),
            "sender": investigation.alert.sender,
            "subject": investigation.alert.subject,
            "users_clicked": len(raw.get("clicked_users", [])),
            "creds_submitted": len(raw.get("cred_submitted_users", [])),
            "blast_timeline_json": json.dumps(timeline) if timeline else "",
            "blast_timeline_text": timeline_text,
            "steps_text": steps_text,
            "endpoint_metrics_text": endpoint_metrics_text,
        }
        try:
            coll.insert(json.dumps(record))
        except Exception:
            try:
                coll.update(d["alert_id"], json.dumps(record))
            except Exception as exc:
                import sys
                print(
                    f"KV upsert failed for {d['alert_id']}: {exc}",
                    file=sys.stderr,
                )


# --------------------------------------------------------------------------- #
# MCP backend (Day 3 — agentic tool interface)
# --------------------------------------------------------------------------- #
class McpBackend:
    """Reads/writes via the Splunk MCP Server. Wired Week 1 Day 3.

    Falls back to SplunkSdkBackend for any operation not yet implemented so the
    pipeline never breaks while MCP is being wired.
    """

    name = "mcp"

    def __init__(self, config: AgentConfig):
        self.config = config
        self._fallback = SplunkSdkBackend(config)

    def get_alerts(self) -> List[Alert]:
        # TODO(day3): call the MCP 'run_splunk_search' tool; map results to Alerts.
        return self._fallback.get_alerts()

    def write_result(self, investigation: Investigation) -> None:
        # TODO(day3): write via MCP tools where available.
        self._fallback.write_result(investigation)


# --------------------------------------------------------------------------- #
# Helpers / factory
# --------------------------------------------------------------------------- #
def _record_to_alert(record: dict) -> Alert:
    return Alert(
        alert_id=record["alert_id"],
        received_at=record.get("received_at", ""),
        sender=record.get("sender", ""),
        sender_domain=record.get("sender_domain", ""),
        subject=record.get("subject", ""),
        recipients=record.get("recipients", []),
        urls=record.get("urls", []),
        attachments=record.get("attachments", []),
        raw=record,
    )


def get_backend(config: AgentConfig):
    """Return the configured I/O backend.

    Priority:
      - explicit config.backend if set ("file" | "sdk" | "mcp")
      - mcp  if config.use_mcp
      - sdk  if credentials present (token or username/password)
      - file otherwise
    """
    backend = getattr(config, "backend", None)
    if backend == "file":
        return FileBackend(config)
    if backend == "sdk":
        return SplunkSdkBackend(config)
    if backend == "mcp":
        return McpBackend(config)

    if getattr(config, "use_mcp", False):
        return McpBackend(config)
    if config.splunk_token or (config.splunk_username and config.splunk_password):
        return SplunkSdkBackend(config)
    return FileBackend(config)
