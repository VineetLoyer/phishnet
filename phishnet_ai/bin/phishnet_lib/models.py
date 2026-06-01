"""Typed data structures used throughout the agent pipeline."""

from dataclasses import dataclass, field
from typing import List, Optional, Dict, Any


@dataclass
class Alert:
    """A single inbound phishing alert."""
    alert_id: str
    received_at: str
    sender: str
    sender_domain: str
    subject: str
    recipients: List[str] = field(default_factory=list)
    urls: List[str] = field(default_factory=list)
    attachments: List[str] = field(default_factory=list)
    raw: Dict[str, Any] = field(default_factory=dict)


@dataclass
class InvestigationStep:
    """Output of one step in the investigation playbook."""
    name: str                       # e.g. "sender_reputation"
    tool: str                       # e.g. "virustotal", "splunk_mcp"
    finding: str                    # human-readable result
    data: Dict[str, Any] = field(default_factory=dict)
    signal: str = "neutral"         # benign | suspicious | malicious | neutral


@dataclass
class Verdict:
    """Classification result from Foundation-Sec-8B (or mock)."""
    label: str                      # phishing | spam | legitimate | targeted_attack
    confidence: float               # 0.0 - 1.0
    reasoning: str                  # chain-of-thought style explanation


@dataclass
class BlastRadius:
    """Security + observability fusion: did the payload execute?"""
    payload_executed: bool = False
    affected_hosts: List[str] = field(default_factory=list)
    timeline: List[Dict[str, Any]] = field(default_factory=list)  # ordered events
    evidence: str = ""


@dataclass
class Investigation:
    """The complete investigation record for one alert."""
    alert: Alert
    steps: List[InvestigationStep] = field(default_factory=list)
    verdict: Optional[Verdict] = None
    blast_radius: Optional[BlastRadius] = None
    recommended_action: str = "review"   # close | escalate | remediate | review
    status: str = "pending"              # pending | recommended | confirmed | overridden

    def as_dict(self) -> Dict[str, Any]:
        return {
            "alert_id": self.alert.alert_id,
            "sender": self.alert.sender,
            "subject": self.alert.subject,
            "verdict": self.verdict.label if self.verdict else None,
            "confidence": self.verdict.confidence if self.verdict else None,
            "reasoning": self.verdict.reasoning if self.verdict else None,
            "payload_executed": self.blast_radius.payload_executed if self.blast_radius else None,
            "recommended_action": self.recommended_action,
            "status": self.status,
            "steps": [
                {"name": s.name, "tool": s.tool, "finding": s.finding, "signal": s.signal}
                for s in self.steps
            ],
        }


@dataclass
class RunSummary:
    """Summary of one agent run, printed at the end of --once."""
    processed: int = 0
    auto_closed: int = 0
    flagged_for_review: int = 0
    real_threats: int = 0
    errors: int = 0

    def as_text(self) -> str:
        return (
            "\n=== PhishNet AI run summary ===\n"
            f"  Alerts processed   : {self.processed}\n"
            f"  Auto-closed (FP)   : {self.auto_closed}\n"
            f"  Flagged for review : {self.flagged_for_review}\n"
            f"  Real threats found : {self.real_threats}\n"
            f"  Errors             : {self.errors}\n"
            "================================\n"
        )
