"""The multi-step investigation playbook.

Each step takes an Alert and returns an InvestigationStep with a signal
(benign | suspicious | malicious | neutral). In Week 1 these steps run against
synthetic data baked into the alert's `raw` payload, so the whole pipeline runs
offline. In Weeks 2-3 the steps are upgraded to call real sources:
  - sender/url reputation  -> VirusTotal, urlscan.io (threat_intel module)
  - recipients / clicks     -> Splunk via MCP (splunk_io module)
  - endpoint correlation    -> metrics index (Blast Radius)
"""

from typing import List
from .models import Alert, InvestigationStep, BlastRadius


def step_sender_reputation(alert: Alert) -> InvestigationStep:
    domain_age_days = alert.raw.get("sender_domain_age_days", 365)
    if domain_age_days < 7:
        return InvestigationStep(
            name="sender_reputation",
            tool="whois/threat_intel",
            finding=f"Sender domain '{alert.sender_domain}' registered "
                    f"{domain_age_days} day(s) ago — newly created domains are high-risk.",
            data={"domain_age_days": domain_age_days},
            signal="malicious" if domain_age_days < 3 else "suspicious",
        )
    return InvestigationStep(
        name="sender_reputation",
        tool="whois/threat_intel",
        finding=f"Sender domain '{alert.sender_domain}' is established "
                f"({domain_age_days} days old).",
        data={"domain_age_days": domain_age_days},
        signal="benign",
    )


def step_url_analysis(alert: Alert) -> InvestigationStep:
    verdicts = alert.raw.get("url_verdicts", {})
    malicious_urls = [u for u, v in verdicts.items() if v == "malicious"]
    suspicious_urls = [u for u, v in verdicts.items() if v == "suspicious"]
    if malicious_urls:
        return InvestigationStep(
            name="url_analysis",
            tool="urlscan.io/virustotal",
            finding=f"{len(malicious_urls)} URL(s) flagged malicious, including a "
                    "credential-harvesting redirect.",
            data={"malicious_urls": malicious_urls},
            signal="malicious",
        )
    if suspicious_urls:
        return InvestigationStep(
            name="url_analysis",
            tool="urlscan.io/virustotal",
            finding=f"{len(suspicious_urls)} URL(s) have suspicious reputation or "
                    "unusual redirect behavior; not confirmed malicious.",
            data={"suspicious_urls": suspicious_urls},
            signal="suspicious",
        )
    if alert.urls:
        return InvestigationStep(
            name="url_analysis",
            tool="urlscan.io/virustotal",
            finding=f"{len(alert.urls)} URL(s) analyzed; no known-malicious reputation.",
            data={"urls": alert.urls},
            signal="benign",
        )
    return InvestigationStep(
        name="url_analysis", tool="urlscan.io/virustotal",
        finding="No URLs present in message.", signal="neutral",
    )


def step_recipient_scope(alert: Alert) -> InvestigationStep:
    n = len(alert.recipients)
    return InvestigationStep(
        name="recipient_scope",
        tool="splunk_mcp",
        finding=f"Message delivered to {n} recipient(s).",
        data={"recipient_count": n, "recipients": alert.recipients},
        signal="suspicious" if n >= 10 else "neutral",
    )


def step_click_through(alert: Alert) -> InvestigationStep:
    clicked = alert.raw.get("clicked_users", [])
    entered_creds = alert.raw.get("cred_submitted_users", [])
    if entered_creds:
        return InvestigationStep(
            name="click_through",
            tool="splunk_mcp/proxy_logs",
            finding=f"{len(entered_creds)} user(s) entered credentials after clicking. "
                    "Account compromise likely.",
            data={"clicked": clicked, "entered_creds": entered_creds},
            signal="malicious",
        )
    if clicked:
        return InvestigationStep(
            name="click_through",
            tool="splunk_mcp/proxy_logs",
            finding=f"{len(clicked)} user(s) clicked the link; no credential submission detected.",
            data={"clicked": clicked},
            signal="suspicious",
        )
    return InvestigationStep(
        name="click_through", tool="splunk_mcp/proxy_logs",
        finding="No user interaction detected.", signal="benign",
    )


def build_blast_radius(alert: Alert) -> BlastRadius:
    """Fuse the click event with endpoint metrics to determine payload execution.

    Week 1: reads a pre-correlated timeline baked into alert.raw for the demo
    'real attack'. Week 2: queries index=metrics for live correlation.
    """
    timeline = alert.raw.get("blast_timeline", [])
    executed = alert.raw.get("payload_executed", False)
    hosts = alert.raw.get("affected_hosts", [])
    evidence = ""
    if executed:
        evidence = (
            "Endpoint telemetry confirms payload execution: a CPU spike and "
            "outbound connection to a new external IP followed the click within minutes."
        )
    return BlastRadius(
        payload_executed=executed,
        affected_hosts=hosts,
        timeline=timeline,
        evidence=evidence,
    )


PLAYBOOK = [
    step_sender_reputation,
    step_url_analysis,
    step_recipient_scope,
    step_click_through,
]


def investigate(alert: Alert) -> List[InvestigationStep]:
    """Run every step in the playbook and return the ordered findings."""
    return [step(alert) for step in PLAYBOOK]
