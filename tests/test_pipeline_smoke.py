"""Smoke tests for the PhishNet AI pipeline.

These run without Splunk, using the file backend and mock classifier. They
verify the core invariant: the agent processes alerts end-to-end and reaches
sensible verdicts on each synthetic alert class.

Run:  pytest tests/ -v
"""

import os
import sys

# Make the app's bin/ importable
BIN = os.path.join(os.path.dirname(__file__), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib.config import AgentConfig            # noqa: E402
from phishnet_lib.models import Alert                  # noqa: E402
from phishnet_lib.pipeline import process_alert        # noqa: E402
from phishnet_lib.classifier import get_classifier      # noqa: E402


def _alert(**raw):
    return Alert(
        alert_id=raw.get("alert_id", "PH-TEST"),
        received_at="2026-05-18T00:00:00Z",
        sender=raw.get("sender", "x@example.com"),
        sender_domain=raw.get("sender_domain", "example.com"),
        subject=raw.get("subject", "test"),
        recipients=raw.get("recipients", ["a@acmecorp.com"]),
        urls=raw.get("urls", []),
        raw=raw,
    )


def test_legitimate_is_recommended_close():
    cfg = AgentConfig(classifier="mock", mode="recommend")
    clf = get_classifier(cfg)
    alert = _alert(sender_domain_age_days=2000, url_verdicts={}, clicked_users=[])
    inv = process_alert(alert, cfg, clf)
    assert inv.verdict.label == "legitimate"
    assert inv.recommended_action == "close"
    assert inv.status == "recommended"   # not auto-closed in recommend mode


def test_auto_mode_auto_closes_high_confidence_fp():
    cfg = AgentConfig(classifier="mock", mode="auto")
    clf = get_classifier(cfg)
    alert = _alert(sender_domain_age_days=2000, url_verdicts={}, clicked_users=[])
    inv = process_alert(alert, cfg, clf)
    assert inv.verdict.label == "legitimate"
    assert inv.status == "confirmed"     # auto-closed


def test_real_attack_with_blast_is_remediate():
    cfg = AgentConfig(classifier="mock", mode="recommend")
    clf = get_classifier(cfg)
    alert = _alert(
        sender_domain_age_days=1,
        urls=["http://bad.tld/login"],
        url_verdicts={"http://bad.tld/login": "malicious"},
        clicked_users=["u@acmecorp.com"],
        cred_submitted_users=["u@acmecorp.com"],
        payload_executed=True,
        affected_hosts=["WKSTN-123"],
        blast_timeline=[{"time": "t", "event": "click"}],
    )
    inv = process_alert(alert, cfg, clf)
    assert inv.verdict.label == "targeted_attack"
    assert inv.blast_radius.payload_executed is True
    assert inv.recommended_action == "remediate"


def test_ambiguous_goes_to_review():
    cfg = AgentConfig(classifier="mock", mode="recommend")
    clf = get_classifier(cfg)
    alert = _alert(
        sender_domain_age_days=30,
        urls=["http://verify.tld/x"],
        url_verdicts={"http://verify.tld/x": "suspicious"},
        clicked_users=[],
    )
    inv = process_alert(alert, cfg, clf)
    # suspicious-only signal -> phishing at lower confidence -> review
    assert inv.verdict.label == "phishing"
    assert inv.recommended_action in ("review", "escalate")
