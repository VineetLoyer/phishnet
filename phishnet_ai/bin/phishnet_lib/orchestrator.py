"""Parallel tool orchestration for a single-alert SOC investigation.

This is the surface behind the MCP `investigate_alert` tool: a single call fans
out several *independent* Splunk searches concurrently — each one a distinct
"tool" across Splunk data sources (mail-gateway index, reputation KV, decisions
decisions KV) — and consolidates them into one timed SOC report.

Because the tools are independent, running them in a thread pool turns a series
of sequential round-trips into one wall-clock window: the report records both
the parallel wall time and the summed tool time so the speedup is visible.

This path is deliberately read-only and side-effect free: it does NOT write KV
steps_text (the batch pipeline owns that), so dashboards are unaffected. It just
produces the richer, sourced report an AI client gets back from one MCP call.
"""

import json
import time
from concurrent.futures import ThreadPoolExecutor
from typing import Any, Callable, Dict, List


def sdk_search_fn(service) -> Callable[[str], List[dict]]:
    """Build a run(spl)->rows callable backed by the splunklib SDK (all-time)."""
    import splunklib.results as results

    def run(spl: str) -> List[dict]:
        job = service.jobs.oneshot(
            spl, output_mode="json", count=0, earliest_time="0", latest_time="now",
        )
        return [r for r in results.JSONResultsReader(job) if isinstance(r, dict)]

    return run


# --------------------------------------------------------------------------- #
# Tools: each returns (finding, signal, data). Each issues ONE real search via
# the injected run(spl) callable (SDK or the official Splunk MCP server).
# --------------------------------------------------------------------------- #
def _tool_reputation(run, alert) -> Dict[str, Any]:
    domain = alert.sender_domain
    rows = run(
        f'| inputlookup phishnet_threat_intel '
        f'| search indicator="{domain}" indicator_type="domain"',
    )
    if not rows:
        return {"finding": f"No prior reputation on file for {domain}.",
                "signal": "neutral", "data": {}}
    rep = json.loads(rows[0].get("response", "{}"))
    prior = rep.get("prior_malicious", 0)
    finding = (f"Domain {domain}: seen in {rep.get('alert_count', 0)} alert(s) "
               f"reaching {rep.get('recipient_reach', 0)} recipient(s); "
               f"{prior} judged malicious by the agent.")
    signal = "malicious" if prior else ("suspicious" if rep.get("risk") == "medium" else "benign")
    return {"finding": finding, "signal": signal, "data": rep}


def _tool_message_trace(run, alert) -> Dict[str, Any]:
    rows = run(
        f'search index=phishing sourcetype=phishnet:alert alert_id="{alert.alert_id}" '
        f'| stats count',
    )
    n = int(rows[0].get("count", 0)) if rows else 0
    return {
        "finding": (f"Message confirmed in mail-gateway feed (index=phishing)."
                    if n else "Message not found in mail-gateway feed."),
        "signal": "neutral" if n else "suspicious",
        "data": {"events": n},
    }


def _tool_exposure(run, alert) -> Dict[str, Any]:
    rows = run(
        f'| inputlookup phishnet_decisions | search alert_id="{alert.alert_id}" '
        f'| fields recipient_count',
    )
    n = int(rows[0].get("recipient_count", 0)) if rows else len(alert.recipients)
    return {"finding": f"Delivered to {n} recipient(s).",
            "signal": "suspicious" if n >= 10 else "neutral",
            "data": {"recipient_count": n}}


def _tool_user_interaction(run, alert) -> Dict[str, Any]:
    rows = run(
        f'| inputlookup phishnet_decisions | search alert_id="{alert.alert_id}" '
        f'| fields users_clicked, creds_submitted',
    )
    clicked = int(rows[0].get("users_clicked", 0)) if rows else 0
    creds = int(rows[0].get("creds_submitted", 0)) if rows else 0
    if creds:
        return {"finding": f"{creds} user(s) submitted credentials after clicking — "
                           "account compromise likely.",
                "signal": "malicious", "data": {"clicked": clicked, "creds": creds}}
    if clicked:
        return {"finding": f"{clicked} user(s) clicked; no credential submission detected.",
                "signal": "suspicious", "data": {"clicked": clicked, "creds": 0}}
    return {"finding": "No user interaction detected.", "signal": "benign",
            "data": {"clicked": 0, "creds": 0}}


def _tool_endpoint_blast(run, alert) -> Dict[str, Any]:
    rows = run(
        f'| inputlookup phishnet_decisions | search alert_id="{alert.alert_id}" '
        f'| fields payload_executed, affected_host',
    )
    executed = str(rows[0].get("payload_executed", "")).lower() in ("true", "1") if rows else False
    host = rows[0].get("affected_host", "") if rows else ""
    if executed:
        return {"finding": f"Payload executed on endpoint {host or 'unknown'} — confirmed breach.",
                "signal": "malicious", "data": {"payload_executed": True, "host": host}}
    return {"finding": "No endpoint payload execution detected.",
            "signal": "benign", "data": {"payload_executed": False}}


# name, source, function
TOOLS: List[tuple] = [
    ("sender_reputation", "kvstore:phishnet_threat_intel", _tool_reputation),
    ("message_trace", "index=phishing", _tool_message_trace),
    ("recipient_exposure", "kvstore:phishnet_decisions", _tool_exposure),
    ("user_interaction", "kvstore:phishnet_decisions", _tool_user_interaction),
    ("endpoint_blast_radius", "kvstore:phishnet_decisions", _tool_endpoint_blast),
]


def _run_one(name: str, source: str, fn: Callable, run, alert) -> Dict[str, Any]:
    t0 = time.time()
    try:
        out = fn(run, alert)
        err = None
    except Exception as exc:  # noqa: BLE001 - one tool failing must not sink the report
        out = {"finding": f"tool error: {exc}", "signal": "neutral", "data": {}}
        err = str(exc)
    elapsed = round((time.time() - t0) * 1000)
    return {"tool": name, "source": source, "elapsed_ms": elapsed,
            "signal": out["signal"], "finding": out["finding"], "error": err}


def parallel_soc_report(alert, run, transport: str = "sdk") -> Dict[str, Any]:
    """Fan out the investigation tools concurrently against Splunk; consolidate.

    Args:
        alert: the Alert under investigation.
        run: a run(spl)->rows callable (SDK- or Splunk-MCP-backed).
        transport: label for how searches were issued ("sdk" | "splunk_mcp").

    Returns a SOC report dict with per-tool results plus parallel-vs-sequential
    timing so the orchestration speedup is explicit.
    """
    t0 = time.time()
    with ThreadPoolExecutor(max_workers=len(TOOLS)) as pool:
        futures = [pool.submit(_run_one, name, source, fn, run, alert)
                   for name, source, fn in TOOLS]
        results = [f.result() for f in futures]
    wall_ms = round((time.time() - t0) * 1000)

    # Preserve canonical tool order in the report.
    order = {name: i for i, (name, _, _) in enumerate(TOOLS)}
    results.sort(key=lambda r: order.get(r["tool"], 99))

    sequential_ms = sum(r["elapsed_ms"] for r in results)
    worst = max((r["signal"] for r in results),
                key=lambda s: {"malicious": 3, "suspicious": 2, "benign": 1, "neutral": 0}.get(s, 0),
                default="neutral")
    return {
        "alert_id": alert.alert_id,
        "parallel": True,
        "transport": transport,
        "tools_run": len(results),
        "wall_ms": wall_ms,
        "sequential_ms": sequential_ms,
        "speedup": round(sequential_ms / wall_ms, 1) if wall_ms else 1.0,
        "aggregate_signal": worst,
        "tools": results,
    }
