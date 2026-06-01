#!/usr/bin/env python
"""
PhishNet AI - Modular Alert Action: Remediation

Triggered when an analyst approves a recommended action from the Command Center
(e.g. block sender domain, quarantine emails, force credential reset). Splunk
invokes this script with the alert payload on stdin.

This is analyst-approved (human-in-the-loop) by design — see the discovery
interviews: every participant rejected silent auto-remediation.

Wired fully in Week 2 (Day 13). Skeleton only for now.
"""

import sys
import json


def main():
    # Splunk passes the alert action payload as JSON on stdin.
    try:
        payload = json.load(sys.stdin)
    except Exception:
        payload = {}

    # TODO(week2-day13):
    #   - read configuration (which remediation, which alert)
    #   - perform the approved action (block IP/domain, quarantine, reset)
    #   - write an audit record to index=phishnet_audit
    #   - update the phishnet_decisions KV Store status -> 'confirmed'
    action = payload.get("configuration", {}).get("action", "unknown")
    sys.stderr.write(f"phishnet_remediate: received action='{action}' (stub)\n")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
