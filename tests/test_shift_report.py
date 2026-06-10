"""Tests for end-of-shift handoff report."""

import os
import sys

BIN = os.path.join(os.path.dirname(__file__), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib import shift_report  # noqa: E402


SAMPLE = [
    {
        "alert_id": "PH-0286",
        "verdict": "targeted_attack",
        "confidence": 0.94,
        "status": "pending",
        "recommended_action": "remediate",
        "payload_executed": True,
        "affected_host": "WKSTN-904",
        "subject": "Invoice overdue — action required",
        "sender": "billing@evil-corp.test",
    },
    {
        "alert_id": "PH-0001",
        "verdict": "legitimate",
        "confidence": 0.91,
        "status": "confirmed",
        "recommended_action": "close",
        "payload_executed": False,
        "subject": "Team standup notes",
        "sender": "alice@acmecorp.com",
    },
    {
        "alert_id": "PH-0042",
        "verdict": "phishing",
        "confidence": 0.78,
        "status": "pending",
        "recommended_action": "escalate",
        "payload_executed": False,
        "subject": "Password reset required",
        "sender": "it-support@fake.test",
    },
]


def test_shift_report_stats():
    stats = shift_report.compute_stats(SAMPLE)
    assert stats["processed"] == 3
    assert stats["auto_closed"] == 1
    assert stats["real_threats"] == 1
    assert stats["payload_executed"] == 1
    assert stats["handed_off"] == 2
    assert stats["hours_saved"] == round(1 * 25 / 60, 1)


def test_shift_report_text_includes_priority_and_payload():
    out = shift_report.build_handoff(SAMPLE, analyst="maya")
    text = out["report_text"]
    assert "PH-0286" in text
    assert "WKSTN-904" in text
    assert "CONFIRMED ENDPOINT IMPACT" in text
    assert "Prepared by: maya" in text
    assert len(out["priority_alerts"]) >= 2
