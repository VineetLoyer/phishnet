#!/usr/bin/env python
"""
PhishNet AI - Synthetic Demo Data Generator

Generates realistic phishing alerts for development and the demo. Output is a
JSON file the file-backend reads, AND (later) can be sent to Splunk's HTTP Event
Collector for the in-product experience.

Mix (default):
  - ~80% obvious false positives (legitimate marketing, internal notices)
  - ~15% ambiguous (suspicious but not confirmed)
  -  ~5% real attacks (1 of which has a full blast-radius timeline)

Usage:
    python scripts/generate_demo_data.py --count 50
    python scripts/generate_demo_data.py --count 300 --out data/generated/alerts.json
"""

import argparse
import json
import os
import random
from datetime import datetime, timedelta

LEGIT_SENDERS = [
    ("newsletter", "marketing.acmecorp.com"),
    ("noreply", "github.com"),
    ("hr-updates", "workday.com"),
    ("billing", "salesforce.com"),
    ("notifications", "slack.com"),
]

SUSPICIOUS_SENDERS = [
    ("it-support", "acmecorp-helpdesk.net"),
    ("account-security", "micros0ft-verify.com"),
    ("payroll", "acmecorp-hr.co"),
]

MALICIOUS_SENDERS = [
    ("ceo", "acmecorp-exec.com"),
    ("docusign", "secure-docusign-portal.net"),
]

LEGIT_SUBJECTS = [
    "Your weekly newsletter is here",
    "[GitHub] A new sign-in to your account",
    "Your pay statement is now available",
    "Reminder: Q2 all-hands on Friday",
    "Your Slack workspace digest",
]
SUSPICIOUS_SUBJECTS = [
    "Action required: verify your mailbox",
    "Your password will expire in 24 hours",
    "Unusual sign-in attempt detected",
]
MALICIOUS_SUBJECTS = [
    "URGENT: Wire transfer approval needed",
    "You have a pending DocuSign document",
]

RECIPIENT_POOL = [f"user{n:02d}@acmecorp.com" for n in range(1, 60)]


def _ts(minutes_ago):
    return (datetime.utcnow() - timedelta(minutes=minutes_ago)).strftime("%Y-%m-%dT%H:%M:%SZ")


def make_false_positive(i):
    user, domain = random.choice(LEGIT_SENDERS)
    return {
        "alert_id": f"PH-{i:04d}",
        "received_at": _ts(random.randint(1, 700)),
        "sender": f"{user}@{domain}",
        "sender_domain": domain,
        "subject": random.choice(LEGIT_SUBJECTS),
        "recipients": random.sample(RECIPIENT_POOL, random.randint(1, 4)),
        "urls": [f"https://{domain}/track/{random.randint(1000,9999)}"],
        "attachments": [],
        "sender_domain_age_days": random.randint(400, 4000),
        "url_verdicts": {},
        "clicked_users": [],
        "cred_submitted_users": [],
        "payload_executed": False,
        "label_truth": "legitimate",
    }


def make_ambiguous(i):
    user, domain = random.choice(SUSPICIOUS_SENDERS)
    recips = random.sample(RECIPIENT_POOL, random.randint(3, 12))
    clicked = random.sample(recips, random.randint(0, 1))
    url = f"http://{domain}/verify?id={random.randint(1000,9999)}"
    return {
        "alert_id": f"PH-{i:04d}",
        "received_at": _ts(random.randint(1, 700)),
        "sender": f"{user}@{domain}",
        "sender_domain": domain,
        "subject": random.choice(SUSPICIOUS_SUBJECTS),
        "recipients": recips,
        "urls": [url],
        "attachments": [],
        "sender_domain_age_days": random.randint(10, 90),
        "url_verdicts": {url: random.choice(["unknown", "suspicious"])},
        "clicked_users": clicked,
        "cred_submitted_users": [],
        "payload_executed": False,
        "label_truth": "phishing",
    }


def make_real_attack(i, with_blast=False):
    user, domain = random.choice(MALICIOUS_SENDERS)
    recips = random.sample(RECIPIENT_POOL, random.randint(8, 20))
    clicked = random.sample(recips, random.randint(1, 3))
    creds = random.sample(clicked, 1) if clicked else []
    url = f"http://{domain}/login/sso?redirect={random.randint(1000,9999)}"
    rec = {
        "alert_id": f"PH-{i:04d}",
        "received_at": _ts(random.randint(1, 300)),
        "sender": f"{user}@{domain}",
        "sender_domain": domain,
        "subject": random.choice(MALICIOUS_SUBJECTS),
        "recipients": recips,
        "urls": [url],
        "attachments": [],
        "sender_domain_age_days": random.randint(0, 3),
        "url_verdicts": {url: "malicious"},
        "clicked_users": clicked,
        "cred_submitted_users": creds,
        "payload_executed": with_blast,
        "label_truth": "targeted_attack" if with_blast else "phishing",
    }
    if with_blast:
        host = "WKSTN-" + str(random.randint(100, 999))
        click_t = _ts(46)
        rec["affected_hosts"] = [host]
        rec["blast_timeline"] = [
            {"time": _ts(48), "event": f"Phishing email delivered to {creds[0] if creds else recips[0]}"},
            {"time": _ts(46), "event": f"User clicked credential-harvesting URL ({url})"},
            {"time": _ts(45), "event": f"Credentials submitted on spoofed SSO page"},
            {"time": _ts(45), "event": f"{host} CPU spiked to 94% (baseline 12%)"},
            {"time": _ts(44), "event": f"{host} outbound TLS to new external IP 185.220.101.47"},
        ]
    return rec


def generate(count):
    records = []
    n_real = max(1, int(count * 0.05))
    n_ambiguous = int(count * 0.15)
    n_fp = count - n_real - n_ambiguous

    idx = 1
    for _ in range(n_fp):
        records.append(make_false_positive(idx)); idx += 1
    for _ in range(n_ambiguous):
        records.append(make_ambiguous(idx)); idx += 1
    # Exactly one "hero" attack with a full blast-radius timeline.
    records.append(make_real_attack(idx, with_blast=True)); idx += 1
    for _ in range(n_real - 1):
        records.append(make_real_attack(idx, with_blast=False)); idx += 1

    random.shuffle(records)
    return records


def main():
    parser = argparse.ArgumentParser(description="Generate synthetic phishing alerts")
    parser.add_argument("--count", type=int, default=50)
    parser.add_argument("--out", default=os.path.join("data", "generated", "alerts.json"))
    parser.add_argument("--seed", type=int, default=42)
    args = parser.parse_args()

    random.seed(args.seed)
    records = generate(args.count)

    out_dir = os.path.dirname(args.out)
    if out_dir:
        os.makedirs(out_dir, exist_ok=True)
    with open(args.out, "w", encoding="utf-8") as fh:
        json.dump(records, fh, indent=2)

    n_real = sum(1 for r in records if r["label_truth"] == "targeted_attack")
    n_phish = sum(1 for r in records if r["label_truth"] == "phishing")
    n_legit = sum(1 for r in records if r["label_truth"] == "legitimate")
    print(f"Wrote {len(records)} alerts to {args.out}")
    print(f"  legitimate (FP) : {n_legit}")
    print(f"  phishing        : {n_phish}")
    print(f"  targeted_attack : {n_real}  (with blast-radius timeline)")


if __name__ == "__main__":
    main()
