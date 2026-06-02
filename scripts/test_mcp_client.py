#!/usr/bin/env python
"""
PhishNet AI - MCP client smoke test

Spawns the PhishNet AI MCP server over stdio, lists its tools, and calls each
one — proving the MCP integration works end-to-end without needing Claude
Desktop or any external client.

Usage (offline / file backend):
    python scripts/test_mcp_client.py

Usage (live Splunk backend):
    set PHISHNET_SPLUNK_USER=VineetLoyer
    set PHISHNET_SPLUNK_PW=...
    python scripts/test_mcp_client.py
"""

import asyncio
import os
import sys

from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client

SERVER = os.path.join(
    os.path.dirname(os.path.abspath(__file__)),
    "..", "phishnet_ai", "bin", "phishnet_mcp_server.py",
)


async def main():
    params = StdioServerParameters(
        command=sys.executable,
        args=[os.path.normpath(SERVER)],
        env=os.environ.copy(),
    )

    async with stdio_client(params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # 1. List tools
            tools = await session.list_tools()
            print("=== TOOLS EXPOSED ===")
            for t in tools.tools:
                print(f"  - {t.name}: {t.description.splitlines()[0]}")

            # 2. list_alerts
            print("\n=== list_alerts(limit=5) ===")
            res = await session.call_tool("list_alerts", {"limit": 5})
            print(_text(res))

            # 3. triage_queue (all alerts)
            print("\n=== triage_queue(limit=0 = all) ===")
            res = await session.call_tool("triage_queue", {"limit": 0})
            triage = _json(res) or {}
            print(_text(res)[:600])

            # 4. investigate the hero attack — find the targeted attack from triage
            outcomes = triage.get("outcomes", [])
            target_id = next(
                (o["alert_id"] for o in outcomes if o.get("payload_executed")),
                None,
            )
            # Fall back to any escalated alert if no executed payload in this batch
            if not target_id:
                target_id = next(
                    (o["alert_id"] for o in outcomes
                     if o.get("recommended_action") in ("escalate", "remediate")),
                    outcomes[0]["alert_id"] if outcomes else "PH-0001",
                )

            print(f"\n=== investigate_alert('{target_id}') ===")
            res = await session.call_tool("investigate_alert", {"alert_id": target_id})
            print(_text(res)[:800])

            # 5. blast radius for the hero attack
            print(f"\n=== get_blast_radius('{target_id}') ===")
            res = await session.call_tool("get_blast_radius", {"alert_id": target_id})
            print(_text(res))


def _text(result):
    """Extract text content from an MCP tool result."""
    parts = []
    for c in result.content:
        if getattr(c, "type", None) == "text":
            parts.append(c.text)
    return "\n".join(parts) if parts else str(result)


def _json(result):
    """Parse the tool result text as JSON, or return None."""
    import json
    txt = _text(result)
    try:
        return json.loads(txt)
    except (ValueError, TypeError):
        return None


if __name__ == "__main__":
    asyncio.run(main())
