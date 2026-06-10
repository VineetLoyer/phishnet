"""End-of-shift handoff report from phishnet_decisions KV records."""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict, List, Optional


def _as_bool(val: Any) -> bool:
    if val is True or val == 1:
        return True
    if isinstance(val, str):
        return val.lower() in ("true", "1", "yes")
    return False


def _float(val: Any, default: float = 0.0) -> float:
    try:
        return float(val)
    except (TypeError, ValueError):
        return default


def compute_stats(decisions: List[dict]) -> Dict[str, Any]:
    """Aggregate shift KPIs (matches Command Center handoff panel SPL)."""
    processed = len(decisions)
    auto_closed = sum(
        1
        for d in decisions
        if d.get("status") == "confirmed" and d.get("recommended_action") == "close"
    )
    real_threats = sum(1 for d in decisions if d.get("verdict") == "targeted_attack")
    handed_off = sum(
        1
        for d in decisions
        if d.get("recommended_action") != "close"
        and not _as_bool(d.get("analyst_override"))
        and d.get("status") != "confirmed"
    )
    payload_executed = sum(1 for d in decisions if _as_bool(d.get("payload_executed")))
    hours_saved = round(auto_closed * 25 / 60, 1)
    return {
        "processed": processed,
        "auto_closed": auto_closed,
        "real_threats": real_threats,
        "handed_off": handed_off,
        "payload_executed": payload_executed,
        "hours_saved": hours_saved,
    }


def _priority_key(d: dict) -> tuple:
    pe = _as_bool(d.get("payload_executed"))
    verdict = d.get("verdict") or ""
    verdict_rank = {"targeted_attack": 0, "phishing": 1}.get(verdict, 2)
    return (0 if pe else 1, verdict_rank, -_float(d.get("confidence")))


def _priority_alerts(decisions: List[dict], limit: int = 8) -> List[dict]:
    flagged = [
        d
        for d in decisions
        if d.get("verdict") in ("targeted_attack", "phishing")
        or _as_bool(d.get("payload_executed"))
        or d.get("recommended_action") in ("escalate", "remediate")
    ]
    flagged.sort(key=_priority_key)
    return flagged[:limit]


def _handoff_queue(decisions: List[dict], limit: int = 10) -> List[dict]:
    pending = [
        d
        for d in decisions
        if d.get("recommended_action") != "close"
        and not _as_bool(d.get("analyst_override"))
        and d.get("status") != "confirmed"
    ]
    pending.sort(key=_priority_key)
    return pending[:limit]


def _line_alert(d: dict) -> str:
    aid = d.get("alert_id", "?")
    verdict = d.get("verdict") or "unknown"
    conf = _float(d.get("confidence"))
    subject = (d.get("subject") or "").strip()
    host = (d.get("affected_host") or "").strip()
    action = d.get("recommended_action") or ""
    parts = [f"{aid}  {verdict} ({conf:.0%})"]
    if subject:
        parts.append(f"— {subject[:72]}")
    if _as_bool(d.get("payload_executed")) and host:
        parts.append(f"[payload on {host}]")
    elif action and action != "close":
        parts.append(f"[{action}]")
    return " ".join(parts)


def build_report_text(
    decisions: List[dict],
    *,
    analyst: Optional[str] = None,
    base_url: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> str:
    """Render a plain-text end-of-shift handoff for email or clipboard."""
    stats = compute_stats(decisions)
    when = generated_at or datetime.now(timezone.utc)
    stamp = when.strftime("%Y-%m-%d %H:%M UTC")
    lines = [
        "PHISHNET AI — SHIFT HANDOFF REPORT",
        f"Report generated: {stamp}",
    ]
    if analyst:
        lines.append(f"Prepared by: {analyst}")
    lines.extend(
        [
            "",
            "EXECUTIVE SUMMARY",
            "-" * 40,
            f"Alerts processed:                 {stats['processed']}",
            f"Auto-closed (false positive):     {stats['auto_closed']}",
            f"Targeted attacks identified:      {stats['real_threats']}",
            f"Confirmed payload execution:      {stats['payload_executed']}",
            f"Estimated analyst hours saved:    {stats['hours_saved']}",
            f"Open cases — next shift:          {stats['handed_off']}",
        ]
    )

    priority = _priority_alerts(decisions)
    if priority:
        lines.extend(["", "PRIORITY REVIEW QUEUE", "-" * 40])
        for d in priority:
            lines.append(f"  • {_line_alert(d)}")

    executed = [d for d in decisions if _as_bool(d.get("payload_executed"))]
    if executed:
        lines.extend(["", "CONFIRMED ENDPOINT IMPACT", "-" * 40])
        for d in executed:
            host = d.get("affected_host") or "unknown host"
            lines.append(
                f"  • {d.get('alert_id', '?')} — {host} — action: {d.get('recommended_action', 'review')}"
            )

    queue = _handoff_queue(decisions)
    if queue:
        lines.extend(["", "OPEN QUEUE FOR NEXT ANALYST", "-" * 40])
        for d in queue:
            lines.append(f"  • {_line_alert(d)}")

    lines.extend(
        [
            "",
            "HANDOFF NOTES",
            "-" * 40,
            "• All queue alerts were investigated; reasoning is stored in phishnet_decisions.",
            "• Review priority items and confirm or override agent recommendations before shift end.",
            "• Escalate any Payload Executed = Yes finding per incident response playbook.",
        ]
    )
    if base_url:
        lines.append(f"• Management ROI view (managers only): {base_url.rstrip('/')}/app/phishnet_ai/manager_roi")

    return "\n".join(lines)


def build_handoff(
    decisions: List[dict],
    *,
    analyst: Optional[str] = None,
    base_url: Optional[str] = None,
    generated_at: Optional[datetime] = None,
) -> Dict[str, Any]:
    """Structured handoff payload for API, MCP, and dashboard consumers."""
    stats = compute_stats(decisions)
    return {
        "stats": stats,
        "priority_alerts": [
            {
                "alert_id": d.get("alert_id"),
                "verdict": d.get("verdict"),
                "confidence": _float(d.get("confidence")),
                "subject": d.get("subject"),
                "recommended_action": d.get("recommended_action"),
                "payload_executed": _as_bool(d.get("payload_executed")),
                "affected_host": d.get("affected_host"),
            }
            for d in _priority_alerts(decisions)
        ],
        "report_text": build_report_text(
            decisions,
            analyst=analyst,
            base_url=base_url,
            generated_at=generated_at,
        ),
    }
