#!/usr/bin/env python
"""
PhishNet AI - MCP Server

Exposes PhishNet AI's autonomous phishing-investigation capability as Model
Context Protocol (MCP) tools. Any MCP client (Claude Desktop, an IDE agent, a
custom orchestrator) can connect and ask PhishNet AI to triage the queue,
investigate a specific alert, or pull the blast radius for an alert — driving
the same investigation pipeline that runs inside Splunk.

This is the "agentic" interface: instead of a human clicking through five tools,
an AI client calls one tool and PhishNet AI runs the whole investigation.

Tools exposed:
  - list_alerts        : list alerts currently in the queue
  - triage_queue       : investigate the whole queue, return summary + outcomes
  - investigate_alert  : full investigation + report for one alert
  - get_blast_radius   : security + observability fusion for one alert

Backend selection mirrors the agent:
  - With Splunk creds in env (PHISHNET_SPLUNK_USER / PHISHNET_SPLUNK_PW) it reads
    live from Splunk via the SDK backend.
  - Otherwise it falls back to the local synthetic-data file backend, so the
    server is fully demoable offline.

Run (stdio transport, for Claude Desktop / IDE clients):
    python phishnet_ai/bin/phishnet_mcp_server.py

Configure in an MCP client (example mcp.json):
    {
      "mcpServers": {
        "phishnet-ai": {
          "command": "python",
          "args": ["C:/Users/vinee/SplunkHacks/phishnet_ai/bin/phishnet_mcp_server.py"],
          "env": {
            "PHISHNET_SPLUNK_USER": "VineetLoyer",
            "PHISHNET_SPLUNK_PW": "..."
          }
        }
      }
    }
"""

import os
import sys

# Make phishnet_lib importable whether run from repo root or bin/.
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from mcp.server.fastmcp import FastMCP            # noqa: E402
from phishnet_lib.config import AgentConfig        # noqa: E402
from phishnet_lib import agent_api                 # noqa: E402


mcp = FastMCP("phishnet-ai")


def _config() -> AgentConfig:
    """Build the agent config from environment (live Splunk if creds present)."""
    user = os.environ.get("PHISHNET_SPLUNK_USER")
    pw = os.environ.get("PHISHNET_SPLUNK_PW")
    token = os.environ.get("PHISHNET_SPLUNK_TOKEN")
    classifier = os.environ.get("PHISHNET_CLASSIFIER", "mock")

    kwargs = {"classifier": classifier}
    if token:
        kwargs.update(backend="sdk", splunk_token=token)
    elif user and pw:
        kwargs.update(backend="sdk", splunk_username=user, splunk_password=pw)
    # else: leave backend=None -> auto -> file backend (offline demo)
    return AgentConfig(**kwargs)


@mcp.tool()
def list_alerts(limit: int = 20) -> dict:
    """List phishing alerts currently in the queue.

    Args:
        limit: Max number of alerts to return (0 = all).
    Returns:
        Count and a list of {alert_id, sender, subject, recipients}.
    """
    return agent_api.list_alerts(_config(), limit=limit)


@mcp.tool()
def triage_queue(limit: int = 0) -> dict:
    """Autonomously investigate the entire phishing alert queue.

    Runs the full PhishNet AI investigation pipeline on every alert: sender
    reputation, URL analysis, recipient scope, click-through, and endpoint
    blast-radius correlation, then classifies each with the security model.

    Args:
        limit: Max alerts to investigate this run (0 = all).
    Returns:
        A summary (processed / auto_closed / flagged / real_threats) plus a
        compact per-alert outcome list.
    """
    return agent_api.triage_queue(_config(), limit=limit)


@mcp.tool()
def investigate_alert(alert_id: str) -> dict:
    """Run a complete investigation on a single phishing alert.

    Args:
        alert_id: The alert identifier, e.g. 'PH-0050'.
    Returns:
        The structured investigation (verdict, confidence, reasoning, steps,
        recommended action) plus a human-readable report and blast radius.
    """
    return agent_api.investigate_alert(alert_id, _config())


@mcp.tool()
def get_blast_radius(alert_id: str) -> dict:
    """Return the blast radius (security + observability fusion) for an alert.

    Shows whether the phishing payload actually executed in the environment,
    which hosts were affected, and the fused timeline of
    email arrival -> user click -> endpoint impact (CPU spike, outbound C2).

    Args:
        alert_id: The alert identifier, e.g. 'PH-0050'.
    """
    return agent_api.get_blast_radius(alert_id, _config())


if __name__ == "__main__":
    # Default transport is stdio (works with Claude Desktop and IDE MCP clients).
    mcp.run()
