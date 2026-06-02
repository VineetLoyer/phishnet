"""High-level agent API.

A thin, stable interface over the pipeline that both the MCP server and any
future UI can call. Keeps tool/transport code (MCP) decoupled from the core
investigation logic.

Functions return plain dicts (JSON-serializable) so they map cleanly onto MCP
tool responses.
"""

from typing import Optional, List, Dict, Any

from .config import AgentConfig
from .splunk_io import get_backend
from .classifier import get_classifier
from .pipeline import process_alert
from . import report as report_mod


def _make_config(**overrides) -> AgentConfig:
    """Build an AgentConfig from overrides, falling back to safe defaults."""
    return AgentConfig(**overrides)


def triage_queue(config: Optional[AgentConfig] = None,
                 limit: int = 0) -> Dict[str, Any]:
    """Investigate the current alert queue and return a summary.

    Returns counts plus a compact list of per-alert outcomes — exactly what a
    SOC analyst (or an AI client) needs to see "what did the agent do tonight."
    """
    config = config or _make_config(limit=limit)
    if limit:
        config.limit = limit

    backend = get_backend(config)
    classifier = get_classifier(config)

    alerts = backend.get_alerts()
    outcomes: List[Dict[str, Any]] = []
    counts = {"processed": 0, "auto_closed": 0, "flagged": 0, "real_threats": 0}

    for alert in alerts:
        inv = process_alert(alert, config, classifier)
        backend.write_result(inv)
        counts["processed"] += 1

        if inv.status == "confirmed" and inv.recommended_action == "close":
            counts["auto_closed"] += 1
        elif inv.recommended_action in ("escalate", "remediate"):
            if inv.blast_radius and inv.blast_radius.payload_executed:
                counts["real_threats"] += 1
            else:
                counts["flagged"] += 1
        else:
            counts["flagged"] += 1

        outcomes.append({
            "alert_id": alert.alert_id,
            "sender": alert.sender,
            "subject": alert.subject,
            "verdict": inv.verdict.label if inv.verdict else None,
            "confidence": inv.verdict.confidence if inv.verdict else None,
            "recommended_action": inv.recommended_action,
            "payload_executed": bool(inv.blast_radius and inv.blast_radius.payload_executed),
        })

    return {"summary": counts, "outcomes": outcomes}


def investigate_alert(alert_id: str,
                      config: Optional[AgentConfig] = None) -> Dict[str, Any]:
    """Run a full investigation on one alert and return the complete record.

    Looks the alert up in the configured backend, runs the playbook, classifies,
    builds the blast radius, and returns the structured investigation plus a
    rendered text report.
    """
    config = config or _make_config()
    backend = get_backend(config)
    classifier = get_classifier(config)

    target = None
    for alert in backend.get_alerts():
        if alert.alert_id == alert_id:
            target = alert
            break

    if target is None:
        return {"error": f"alert '{alert_id}' not found"}

    inv = process_alert(target, config, classifier)
    backend.write_result(inv)

    result = inv.as_dict()
    result["report_text"] = report_mod.render_text(inv)
    if inv.blast_radius:
        result["blast_radius"] = {
            "payload_executed": inv.blast_radius.payload_executed,
            "affected_hosts": inv.blast_radius.affected_hosts,
            "timeline": inv.blast_radius.timeline,
            "evidence": inv.blast_radius.evidence,
        }
    return result


def get_blast_radius(alert_id: str,
                     config: Optional[AgentConfig] = None) -> Dict[str, Any]:
    """Return just the blast-radius (security + observability fusion) for an alert.

    This is the differentiator surface: did the payload execute, which hosts,
    and the fused timeline of email -> click -> endpoint impact.
    """
    config = config or _make_config()
    backend = get_backend(config)
    classifier = get_classifier(config)

    target = None
    for alert in backend.get_alerts():
        if alert.alert_id == alert_id:
            target = alert
            break

    if target is None:
        return {"error": f"alert '{alert_id}' not found"}

    inv = process_alert(target, config, classifier)
    br = inv.blast_radius
    if br is None:
        return {"alert_id": alert_id, "payload_executed": False, "timeline": []}

    return {
        "alert_id": alert_id,
        "payload_executed": br.payload_executed,
        "affected_hosts": br.affected_hosts,
        "timeline": br.timeline,
        "evidence": br.evidence,
    }


def list_alerts(config: Optional[AgentConfig] = None,
                limit: int = 0) -> Dict[str, Any]:
    """List alerts currently in the queue (id, sender, subject) without investigating."""
    config = config or _make_config(limit=limit)
    if limit:
        config.limit = limit
    backend = get_backend(config)
    alerts = backend.get_alerts()
    return {
        "count": len(alerts),
        "alerts": [
            {"alert_id": a.alert_id, "sender": a.sender, "subject": a.subject,
             "recipients": len(a.recipients)}
            for a in alerts
        ],
    }
