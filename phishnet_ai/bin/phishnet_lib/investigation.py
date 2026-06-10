"""The multi-step investigation playbook.

Each step takes an Alert and returns an InvestigationStep with a signal
(benign | suspicious | malicious | neutral). Sources are all in-platform:
  - sender/url reputation  -> Splunk own-data reputation (threat_intel module:
                              first-seen, volume, recipient reach, prior verdicts)
  - recipients / clicks     -> Splunk searches (proxy/email logs)
  - endpoint correlation    -> metrics index (Blast Radius)
"""

from typing import List
from .models import Alert, InvestigationStep, BlastRadius


def _rep_phrase(rep: dict) -> str:
    """One-line Splunk-native domain reputation summary for a finding."""
    if not rep:
        return ""
    prior = rep.get("prior_malicious", 0)
    alerts = rep.get("alert_count", 0)
    reach = rep.get("recipient_reach", 0)
    if rep.get("derived") or not alerts:
        # Cache miss: only the alert's own fields are known.
        return (f" Splunk reputation: {prior} prior confirmed-malicious sighting(s)."
                if prior else " Splunk reputation: no prior internal sightings.")
    base = f" Splunk reputation: seen in {alerts} alert(s) reaching {reach} recipient(s)"
    base += (f"; {prior} judged malicious by the agent." if prior
             else "; none previously judged malicious.")
    return base


def _url_rep_phrase(rep: dict) -> str:
    """One-line Splunk-native URL reputation summary for a finding."""
    if not rep:
        return ""
    prior = rep.get("prior_malicious", 0)
    seen = rep.get("seen_count", 0)
    return (f" Splunk URL intel: verdict {rep.get('verdict', 'unknown')}, "
            f"seen {seen} time(s) in your telemetry, "
            f"{prior} prior malicious sighting(s).")


def step_sender_reputation(alert: Alert) -> InvestigationStep:
    domain_age_days = alert.raw.get("sender_domain_age_days", 365)
    rep = (alert.raw.get("threat_intel") or {}).get("domain") or {}
    rep_phrase = _rep_phrase(rep)
    rep_data = {
        "rep_prior_malicious": rep.get("prior_malicious"),
        "rep_alert_count": rep.get("alert_count"),
    } if rep else {}
    if domain_age_days < 7:
        return InvestigationStep(
            name="sender_reputation",
            tool="splunk:reputation",
            finding=f"Sender domain '{alert.sender_domain}' registered "
                    f"{domain_age_days} day(s) ago — newly created domains are high-risk."
                    + rep_phrase,
            data={"domain_age_days": domain_age_days, **rep_data},
            signal="malicious" if domain_age_days < 3 else "suspicious",
        )
    return InvestigationStep(
        name="sender_reputation",
        tool="splunk:reputation",
        finding=f"Sender domain '{alert.sender_domain}' is established "
                f"({domain_age_days} days old)." + rep_phrase,
        data={"domain_age_days": domain_age_days, **rep_data},
        signal="benign",
    )


def step_url_analysis(alert: Alert) -> InvestigationStep:
    verdicts = alert.raw.get("url_verdicts", {})
    url_intel = (alert.raw.get("threat_intel") or {}).get("urls") or {}
    malicious_urls = [u for u, v in verdicts.items() if v == "malicious"]
    suspicious_urls = [u for u, v in verdicts.items() if v == "suspicious"]
    if malicious_urls:
        return InvestigationStep(
            name="url_analysis",
            tool="splunk:reputation",
            finding=f"{len(malicious_urls)} URL(s) flagged malicious, including a "
                    "credential-harvesting redirect."
                    + _url_rep_phrase(url_intel.get(malicious_urls[0])),
            data={"malicious_urls": malicious_urls},
            signal="malicious",
        )
    if suspicious_urls:
        return InvestigationStep(
            name="url_analysis",
            tool="splunk:reputation",
            finding=f"{len(suspicious_urls)} URL(s) have suspicious reputation or "
                    "unusual redirect behavior; not confirmed malicious."
                    + _url_rep_phrase(url_intel.get(suspicious_urls[0])),
            data={"suspicious_urls": suspicious_urls},
            signal="suspicious",
        )
    if alert.urls:
        return InvestigationStep(
            name="url_analysis",
            tool="splunk:reputation",
            finding=f"{len(alert.urls)} URL(s) analyzed; no known-malicious reputation.",
            data={"urls": alert.urls},
            signal="benign",
        )
    return InvestigationStep(
        name="url_analysis", tool="splunk:reputation",
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
