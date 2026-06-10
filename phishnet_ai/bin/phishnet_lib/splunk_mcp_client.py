"""Client for the official Splunk MCP Server (Splunkbase app 7931).

Lets PhishNet run its Splunk searches *through* Splunk's own MCP server instead
of calling splunklib directly — so PhishNet is a genuine MCP client of the
Splunkverse. The server runs as persistent REST handlers inside splunkd and
speaks JSON-RPC over HTTPS on the management port:

    POST https://<host>:<port>/services/mcp      (Authorization: Bearer <token>)

Tokens are minted from the server's own `/services/mcp_token` endpoint (the
returned token is RSA-encrypted with the server's public key, which the server
decrypts on each call). We mint via an authenticated splunklib session so the
caller only needs the Splunk credentials it already has.

The search tool is `splunk_run_query`, which applies a default -24h time window;
we pass explicit earliest/latest so historical data is found.
"""

import json
import ssl
import urllib.request
from typing import Any, Dict, List, Optional


class SplunkMcpError(RuntimeError):
    """Raised when the Splunk MCP server returns an error or is unreachable."""


class SplunkMcpClient:
    def __init__(self, url: str, token: str, tool: str = "splunk_run_query",
                 verify_ssl: bool = False, timeout: int = 90):
        self.url = url
        self.token = token
        self.tool = tool
        self.timeout = timeout
        self._ctx = ssl.create_default_context()
        if not verify_ssl:
            self._ctx.check_hostname = False
            self._ctx.verify_mode = ssl.CERT_NONE
        self._rid = 0

    # -- construction ----------------------------------------------------- #
    @classmethod
    def from_config(cls, config, service=None) -> "SplunkMcpClient":
        """Mint a token via splunklib and build a client. Raises on failure."""
        import splunklib.client as client

        if service is None:
            service = client.connect(
                host=config.splunk_host, port=config.splunk_port, scheme="https",
                username=config.splunk_username, password=config.splunk_password,
                splunkToken=config.splunk_token,
            )
        username = config.splunk_username or "admin"
        resp = service.get("mcp_token", username=username, expires_on="+1d",
                           output_mode="json")
        token = json.loads(resp.body.read()).get("token")
        if not token:
            raise SplunkMcpError("mcp_token endpoint returned no token")
        return cls(config.splunk_mcp_url, token, tool=config.splunk_mcp_tool)

    # -- JSON-RPC --------------------------------------------------------- #
    def _rpc(self, method: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        self._rid += 1
        body = {"jsonrpc": "2.0", "id": self._rid, "method": method}
        if params is not None:
            body["params"] = params
        req = urllib.request.Request(
            self.url, data=json.dumps(body).encode("utf-8"),
            headers={"Authorization": f"Bearer {self.token}",
                     "Content-Type": "application/json"},
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=self.timeout, context=self._ctx) as r:
                payload = json.loads(r.read().decode("utf-8"))
        except Exception as exc:  # noqa: BLE001 - normalize transport errors
            raise SplunkMcpError(f"{method} transport error: {exc}") from exc
        if "error" in payload:
            raise SplunkMcpError(f"{method} error: {payload['error']}")
        return payload.get("result", {})

    # -- public API ------------------------------------------------------- #
    def run_query(self, spl: str, earliest: str = "0", latest: str = "now") -> List[dict]:
        """Run an SPL query via `splunk_run_query`; return the result rows."""
        result = self._rpc("tools/call", {
            "name": self.tool,
            "arguments": {"query": spl, "earliest_time": earliest, "latest_time": latest},
        })
        structured = result.get("structuredContent")
        if isinstance(structured, dict) and "results" in structured:
            return structured["results"]
        # Fall back to parsing the text content block.
        for block in result.get("content", []):
            if block.get("type") == "text":
                try:
                    return json.loads(block["text"]).get("results", [])
                except Exception:  # noqa: BLE001
                    continue
        return []

    def ping(self) -> bool:
        return self._rpc("ping").get("message") == "pong"
