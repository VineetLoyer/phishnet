#!/usr/bin/env python
"""REST endpoint: structured end-of-shift handoff report."""

import json
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from splunk.persistconn.application import PersistentServerConnectionApplication  # noqa: E402


class ShiftReportHandler(PersistentServerConnectionApplication):
    def __init__(self, _command_line, _command_arg):
        PersistentServerConnectionApplication.__init__(self)

    def handle(self, in_string):
        try:
            request = json.loads(in_string) if in_string else {}
        except json.JSONDecodeError:
            request = {}

        session = request.get("session") or {}
        token = session.get("authtoken")
        if not token:
            return {"status": 401, "payload": {"error": "not authenticated"}}

        query = request.get("query") or {}
        analyst = query.get("analyst") or session.get("user")
        base_url = query.get("base_url") or ""

        try:
            from phishnet_lib.config import AgentConfig
            from phishnet_lib import agent_api

            config = AgentConfig(backend="sdk", splunk_token=token)
            payload = agent_api.get_shift_handoff(
                config,
                analyst=analyst,
                base_url=base_url or None,
            )
            return {
                "status": 200,
                "payload": payload,
                "headers": [{"key": "Content-Type", "value": "application/json"}],
            }
        except Exception as exc:  # noqa: BLE001
            return {"status": 500, "payload": {"error": str(exc)}}
