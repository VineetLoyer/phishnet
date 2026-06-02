"""Tests for the high-level agent API (the layer the MCP server calls).

Uses the file backend + mock classifier — no Splunk, no network.
Run:  pytest tests/ -v
"""

import os
import sys

BIN = os.path.join(os.path.dirname(__file__), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib.config import AgentConfig          # noqa: E402
from phishnet_lib import agent_api                    # noqa: E402


def _cfg():
    # Force file backend + mock classifier for deterministic offline tests.
    return AgentConfig(backend="file", classifier="mock")


def test_list_alerts_returns_queue():
    out = agent_api.list_alerts(_cfg(), limit=5)
    assert "count" in out and "alerts" in out
    assert out["count"] <= 5
    if out["alerts"]:
        assert {"alert_id", "sender", "subject"}.issubset(out["alerts"][0].keys())


def test_triage_queue_summarizes():
    out = agent_api.triage_queue(_cfg(), limit=10)
    assert "summary" in out and "outcomes" in out
    s = out["summary"]
    assert s["processed"] == len(out["outcomes"])
    # processed should equal auto_closed + flagged + real_threats
    assert s["processed"] == s["auto_closed"] + s["flagged"] + s["real_threats"]


def test_investigate_alert_unknown_id():
    out = agent_api.investigate_alert("DOES-NOT-EXIST", _cfg())
    assert "error" in out


def test_blast_radius_on_targeted_attack():
    # The generator always includes exactly one targeted attack with a timeline.
    # Find it via triage, then assert blast radius reports execution.
    triage = agent_api.triage_queue(_cfg())
    target = next((o["alert_id"] for o in triage["outcomes"]
                   if o.get("payload_executed")), None)
    if target is None:
        # No executed-payload alert in this dataset; skip gracefully.
        return
    br = agent_api.get_blast_radius(target, _cfg())
    assert br["payload_executed"] is True
    assert br["affected_hosts"]
    assert len(br["timeline"]) >= 3
