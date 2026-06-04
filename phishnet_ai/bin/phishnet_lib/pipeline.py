"""End-to-end orchestration: ingest -> investigate -> classify -> report.

This is the heart of the agent. `run_once` processes the current alert batch and
returns a RunSummary. It is deliberately backend-agnostic: it works with the
file backend (synthetic data) today and the MCP backend once that is wired.
"""

from .config import AgentConfig
from .models import Investigation, RunSummary
from .splunk_io import get_backend
from .classifier import get_classifier
from . import investigation as playbook
from . import report as report_mod


def _decide_action(inv: Investigation, config: AgentConfig) -> None:
    """Set recommended_action and status based on verdict + mode."""
    verdict = inv.verdict
    executed = bool(inv.blast_radius and inv.blast_radius.payload_executed)

    if verdict is None:
        inv.recommended_action = "review"
        inv.status = "pending"
        return

    if executed or verdict.label == "targeted_attack":
        inv.recommended_action = "remediate"
        inv.status = "recommended"
    elif verdict.label == "phishing":
        if verdict.confidence >= 0.85:
            inv.recommended_action = "escalate"
            inv.status = "recommended"
        else:
            inv.recommended_action = "review"      # ambiguous -> human review
            inv.status = "pending"
    else:  # legitimate / spam
        if config.mode == "auto" and verdict.confidence >= config.auto_close_confidence:
            inv.recommended_action = "close"
            inv.status = "confirmed"                # auto-closed
        else:
            inv.recommended_action = "close"
            inv.status = "recommended"              # recommend close, analyst confirms


def process_alert(alert, config: AgentConfig, classifier) -> Investigation:
    inv = Investigation(alert=alert)
    inv.steps = playbook.investigate(alert)
    inv.blast_radius = playbook.build_blast_radius(alert)
    inv.verdict = classifier.classify(alert, inv)
    _decide_action(inv, config)
    return inv


def run_once(config: AgentConfig, verbose: bool = True) -> RunSummary:
    backend = get_backend(config)
    classifier = get_classifier(config)
    summary = RunSummary()

    if verbose:
        print(f"Backend: {backend.name} | Classifier: {config.classifier}")

    alerts = backend.get_alerts()
    if verbose and not alerts:
        print("No alerts found. Run scripts/generate_demo_data.py first.")

    for alert in alerts:
        try:
            inv = process_alert(alert, config, classifier)
            backend.write_result(inv)
            summary.processed += 1

            if inv.status == "confirmed" and inv.recommended_action == "close":
                summary.auto_closed += 1
            elif inv.recommended_action in ("escalate", "remediate"):
                if inv.blast_radius and inv.blast_radius.payload_executed:
                    summary.real_threats += 1
                else:
                    summary.flagged_for_review += 1
            else:
                summary.flagged_for_review += 1

            if verbose:
                # Print full report for flagged/real items; one-liner for FPs.
                if inv.recommended_action in ("escalate", "remediate"):
                    print(report_mod.render_text(inv))
                else:
                    v = inv.verdict
                    print(f"[{alert.alert_id}] {v.label} "
                          f"({v.confidence:.0%}) -> {inv.recommended_action}")
        except Exception as exc:  # noqa: BLE001 - keep the batch running
            summary.errors += 1
            if verbose:
                print(f"[{getattr(alert, 'alert_id', '?')}] ERROR: {exc}")

    return summary
