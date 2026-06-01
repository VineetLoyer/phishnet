# PhishNet AI

> **Autonomous phishing investigation, native to Splunk.**
> Submitted to the Splunk Agentic Ops Hackathon (May 18 – June 15, 2026), Security Track.

PhishNet AI is a Splunk app that acts as an autonomous Tier-1 SOC analyst for phishing
alerts. It investigates every alert end-to-end, classifies threats using the
Foundation-Sec-8B security model, fuses security signals with observability data to
show the real **blast radius** of an attack, and hands analysts a complete
investigation report with transparent reasoning — so they can focus on the threats
that matter instead of drowning in false positives.

---

## The Problem

A Tier-1 SOC analyst's queue holds 200+ phishing alerts per 12-hour shift. Each proper
investigation takes 20-30 minutes. The math doesn't work — so analysts speed-triage,
bulk-close, and gamble that the one real attack isn't in the pile they skipped.

PhishNet AI investigates all of them. Autonomously. In seconds each.

## What It Does

- **Ingests** phishing alerts from Splunk
- **Investigates** each one: sender, URLs, recipients, click-through, endpoint impact
- **Classifies** with Foundation-Sec-8B (zero-shot, no training needed) with full reasoning
- **Correlates** security + observability data into a **Blast Radius** view that shows
  whether a payload actually executed (CPU spike, outbound C2 traffic, process spawn)
- **Recommends** actions (analyst confirms by default — no silent auto-close)
- **Reports** a complete, auditable investigation back into Splunk
- **Measures** ROI for SOC managers (alerts processed, threats caught, hours saved)

## Architecture

```
Splunk Enterprise
 ├─ index=phishing          (incoming alerts)
 ├─ index=metrics           (endpoint/host telemetry for Blast Radius)
 ├─ index=phishnet_actions  (agent investigation reports)
 └─ index=phishnet_audit    (every agent decision, for audit)

PhishNet AI App (this repo)
 ├─ Modular Input  → continuous agent: ingest → investigate → classify → report
 ├─ Alert Action   → analyst-approved remediation
 ├─ MCP Client     → talks to Splunk via the official Splunk MCP Server
 ├─ DSDL bridge    → Foundation-Sec-8B classification
 └─ Dashboards     → Command Center · Blast Radius · Manager ROI
```

## Splunk AI Capabilities Used

| Capability | Use |
|------------|-----|
| **Splunk MCP Server** | Data plane between the agent and Splunk |
| **Splunk Hosted Models (Foundation-Sec-8B)** | Zero-shot phishing classification via DSDL |
| **Python SDK (Developer Tools)** | Modular input + alert action |

## Repository Layout

```
SplunkHacks/
├── README.md                  # This file
├── docs/                      # Full research & planning (00-19)
├── phishnet_ai/               # The Splunk app (deployable)
│   ├── default/               # app.conf, inputs.conf, dashboards, etc.
│   ├── bin/                   # Python agent + remediation code
│   ├── metadata/              # default.meta
│   └── README/                # Splunk app README + conf specs
├── scripts/                   # Dev tooling: data gen, demo reset, deploy
├── docker/                    # docker-compose for DSDL (Foundation-Sec-8B)
└── tests/                     # Smoke tests
```

## Status

🚧 **In active development** — Hackathon build period May 18 – June 15, 2026.

## License

Apache 2.0 — see [LICENSE](LICENSE).
