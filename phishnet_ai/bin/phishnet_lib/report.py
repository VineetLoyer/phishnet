"""Investigation report generation.

Produces a human-readable report from an Investigation. Week 1 ships a plain-text
renderer; Week 2 adds a Jinja2 HTML template for the dashboard report viewer.
"""

from .models import Investigation


def render_text(inv: Investigation) -> str:
    """Render a plain-text investigation report."""
    a = inv.alert
    lines = []
    lines.append("=" * 64)
    lines.append(f"PHISHNET AI — INVESTIGATION REPORT")
    lines.append(f"Alert ID : {a.alert_id}")
    lines.append(f"Received : {a.received_at}")
    lines.append("=" * 64)
    lines.append(f"Sender   : {a.sender}")
    lines.append(f"Subject  : {a.subject}")
    lines.append(f"Recipients: {len(a.recipients)}")
    lines.append("")
    lines.append("INVESTIGATION STEPS")
    lines.append("-" * 64)
    for i, step in enumerate(inv.steps, 1):
        marker = {
            "malicious": "[!]",
            "suspicious": "[?]",
            "benign": "[ok]",
            "neutral": "[-]",
        }.get(step.signal, "[-]")
        lines.append(f"{i}. {marker} {step.name} ({step.tool})")
        lines.append(f"     {step.finding}")
    lines.append("")

    if inv.verdict:
        lines.append("VERDICT")
        lines.append("-" * 64)
        lines.append(f"  Label      : {inv.verdict.label}")
        lines.append(f"  Confidence : {inv.verdict.confidence:.0%}")
        lines.append(f"  Reasoning  : {inv.verdict.reasoning}")
        lines.append("")

    if inv.blast_radius:
        br = inv.blast_radius
        lines.append("BLAST RADIUS")
        lines.append("-" * 64)
        lines.append(f"  Payload executed : {br.payload_executed}")
        if br.affected_hosts:
            lines.append(f"  Affected hosts   : {', '.join(br.affected_hosts)}")
        if br.timeline:
            lines.append("  Timeline:")
            for ev in br.timeline:
                lines.append(f"    {ev.get('time','?')}  {ev.get('event','')}")
        if br.evidence:
            lines.append(f"  Evidence         : {br.evidence}")
        lines.append("")

    lines.append("RECOMMENDATION")
    lines.append("-" * 64)
    lines.append(f"  Recommended action : {inv.recommended_action}")
    lines.append(f"  Status             : {inv.status}")
    lines.append("=" * 64)
    return "\n".join(lines)
