#!/usr/bin/env python
"""
PhishNet AI - Foundation-Sec classifier smoke test

Sends three representative alerts (legitimate, phishing, targeted attack) through
the configured classifier and prints the verdicts. Use this to confirm the
Foundation-Sec model (via Ollama or DSDL) is reachable and returning sane output
before running the full pipeline.

Usage:
    # mock (no model needed)
    python scripts/test_classifier.py

    # Ollama running the official Foundation-Sec GGUF
    python scripts/test_classifier.py --classifier dsdl \
        --llm-url http://localhost:11434 \
        --llm-model hf.co/fdtn-ai/Foundation-Sec-8B-Q8_0-GGUF
"""

import argparse
import os
import sys
import time

BIN = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "phishnet_ai", "bin")
sys.path.insert(0, os.path.normpath(BIN))

from phishnet_lib.config import AgentConfig            # noqa: E402
from phishnet_lib.models import Alert                  # noqa: E402
from phishnet_lib.classifier import get_classifier      # noqa: E402
from phishnet_lib import investigation as playbook      # noqa: E402
from phishnet_lib.pipeline import process_alert         # noqa: E402


SAMPLES = [
    {
        "name": "legitimate (GitHub notice)",
        "raw": {
            "alert_id": "T-LEGIT", "received_at": "2026-05-21T00:00:00Z",
            "sender": "noreply@github.com", "sender_domain": "github.com",
            "subject": "A new sign-in to your account",
            "recipients": ["a@acmecorp.com"], "urls": ["https://github.com/x"],
            "sender_domain_age_days": 4000, "url_verdicts": {}, "clicked_users": [],
            "cred_submitted_users": [], "payload_executed": False,
        },
    },
    {
        "name": "phishing (new domain, malicious URL)",
        "raw": {
            "alert_id": "T-PHISH", "received_at": "2026-05-21T00:00:00Z",
            "sender": "account-security@micros0ft-verify.com",
            "sender_domain": "micros0ft-verify.com",
            "subject": "Unusual sign-in attempt detected",
            "recipients": [f"u{i}@acmecorp.com" for i in range(6)],
            "urls": ["http://micros0ft-verify.com/login"],
            "sender_domain_age_days": 2,
            "url_verdicts": {"http://micros0ft-verify.com/login": "malicious"},
            "clicked_users": ["u1@acmecorp.com"], "cred_submitted_users": [],
            "payload_executed": False,
        },
    },
    {
        "name": "targeted attack (payload executed)",
        "raw": {
            "alert_id": "T-ATTACK", "received_at": "2026-05-21T00:00:00Z",
            "sender": "ceo@acmecorp-exec.com", "sender_domain": "acmecorp-exec.com",
            "subject": "URGENT: Wire transfer approval needed",
            "recipients": [f"u{i}@acmecorp.com" for i in range(12)],
            "urls": ["http://acmecorp-exec.com/login/sso"],
            "sender_domain_age_days": 1,
            "url_verdicts": {"http://acmecorp-exec.com/login/sso": "malicious"},
            "clicked_users": ["u3@acmecorp.com"],
            "cred_submitted_users": ["u3@acmecorp.com"],
            "payload_executed": True, "affected_hosts": ["WKSTN-501"],
            "blast_timeline": [{"time": "t", "event": "click"}],
        },
    },
]


def main():
    p = argparse.ArgumentParser()
    p.add_argument("--classifier", default="mock", choices=["mock", "dsdl", "huggingface"])
    p.add_argument("--llm-provider", default=None, choices=["ollama", "dsdl"])
    p.add_argument("--llm-url", default=None)
    p.add_argument("--llm-model", default=None)
    args = p.parse_args()

    kwargs = {"classifier": args.classifier, "backend": "file"}
    if args.llm_provider:
        kwargs["llm_provider"] = args.llm_provider
    if args.llm_url:
        kwargs["dsdl_url"] = args.llm_url
    if args.llm_model:
        kwargs["llm_model"] = args.llm_model
    config = AgentConfig(**kwargs)
    clf = get_classifier(config)

    print(f"Classifier backend: {args.classifier}")
    if args.classifier != "mock":
        print(f"  endpoint: {config.dsdl_url}")
        print(f"  model   : {config.llm_model}")
    print("-" * 60)

    for s in SAMPLES:
        alert = Alert(
            alert_id=s["raw"]["alert_id"], received_at=s["raw"]["received_at"],
            sender=s["raw"]["sender"], sender_domain=s["raw"]["sender_domain"],
            subject=s["raw"]["subject"], recipients=s["raw"]["recipients"],
            urls=s["raw"].get("urls", []), raw=s["raw"],
        )
        inv = process_alert(alert, config, clf)
        t0 = time.time()
        # process_alert already classified; time a second call for latency feel
        elapsed = time.time() - t0
        v = inv.verdict
        print(f"{s['name']}")
        print(f"  -> label={v.label}  confidence={v.confidence:.0%}  action={inv.recommended_action}")
        print(f"     reasoning: {v.reasoning[:140]}")
        print()


if __name__ == "__main__":
    main()
