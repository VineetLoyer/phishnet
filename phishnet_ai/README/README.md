# PhishNet AI (Splunk App)

Autonomous phishing investigation agent for Splunk.

## What's in this app

```
phishnet_ai/
├── default/
│   ├── app.conf            # App metadata
│   ├── inputs.conf         # phishnet_agent modular input
│   ├── indexes.conf        # phishing / phishnet_actions / phishnet_audit
│   ├── collections.conf    # KV Store: decisions, threat_intel, metrics
│   └── data/ui/views/      # Dashboards (Week 2)
├── bin/
│   ├── phishnet_agent.py       # Modular input entry point
│   ├── phishnet_remediate.py   # Alert action: analyst-approved remediation
│   └── phishnet_lib/           # Agent library (pipeline, classifier, etc.)
├── metadata/
│   └── default.meta
└── README/
    ├── README.md           # This file
    └── inputs.conf.spec     # Modular input schema
```

## Install (dev)

From an elevated PowerShell prompt at the repo root:

```powershell
.\scripts\deploy_to_splunk.ps1
```

Then open http://localhost:8000 → the **PhishNet AI** app appears in the launcher.

## Run the agent standalone (no Splunk needed)

```bash
python scripts/generate_demo_data.py --count 50
python phishnet_ai/bin/phishnet_agent.py --once --classifier mock
```

## Configuration

The `phishnet_agent` modular input accepts:
- `source_index` (default `phishing`)
- `mode` — `recommend` (default) or `auto`
- `classifier` — `mock` (default) | `dsdl` | `huggingface`

See `README/inputs.conf.spec` for the full schema.
