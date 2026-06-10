#!/usr/bin/env python
"""
Verify the official Splunk MCP Server (Splunkbase app 7931) integration.

Confirms PhishNet can drive Splunk *through* its own MCP server end-to-end:
mints an encrypted MCP token, pings the server, lists its tools, and runs a
sample SPL query via `splunk_run_query`.

Prereqs:
  - Splunk_MCP_Server app installed on the search head.
  - Splunk token authentication enabled.
  - Your role has the `mcp_tool_execute` (and `mcp_tool_admin` to mint tokens)
    capabilities. The built-in `admin` role has both.

Usage (PowerShell):
    $env:PHISHNET_SPLUNK_USER = "VineetLoyer"
    $env:PHISHNET_SPLUNK_PW   = "..."
    python scripts/verify_splunk_mcp.py
"""

import os
import sys

sys.path.insert(0, os.path.join(os.path.dirname(os.path.abspath(__file__)),
                                "..", "phishnet_ai", "bin"))

from phishnet_lib.config import AgentConfig          # noqa: E402
from phishnet_lib.splunk_mcp_client import SplunkMcpClient, SplunkMcpError  # noqa: E402


def main() -> int:
    cfg = AgentConfig(use_splunk_mcp=True)
    if not (cfg.splunk_username and cfg.splunk_password) and not cfg.splunk_token:
        print("FAIL: set PHISHNET_SPLUNK_USER / PHISHNET_SPLUNK_PW (or _TOKEN).")
        return 1

    print(f"MCP endpoint : {cfg.splunk_mcp_url}")
    print(f"search tool  : {cfg.splunk_mcp_tool}")

    try:
        client = SplunkMcpClient.from_config(cfg)
    except SplunkMcpError as exc:
        print(f"FAIL minting token: {exc}")
        return 1
    print("token minted : ok")

    if not client.ping():
        print("FAIL: ping did not return pong")
        return 1
    print("ping         : pong")

    tools = client._rpc("tools/list").get("tools", [])
    names = [t.get("name") for t in tools]
    print(f"tools/list   : {len(names)} tools -> {', '.join(names)}")
    if cfg.splunk_mcp_tool not in names:
        print(f"FAIL: '{cfg.splunk_mcp_tool}' not exposed by the server")
        return 1

    rows = client.run_query(
        "search index=phishing sourcetype=phishnet:alert | stats count")
    count = rows[0].get("count") if rows else "0"
    print(f"sample query : index=phishing -> {count} event(s)")
    print("PASS: PhishNet can run Splunk searches via the official MCP server.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
