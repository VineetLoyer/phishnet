"""Pre-push smoke test against live Splunk. Exit 0 = all checks pass."""
import json
import os
import sys

sys.path.insert(0, os.path.join("phishnet_ai", "bin"))

from phishnet_lib.config import AgentConfig
from phishnet_lib import agent_api

USER = os.environ.get("PHISHNET_SPLUNK_USER")
PW = os.environ.get("PHISHNET_SPLUNK_PW")
if not USER or not PW:
    print("FAIL: set PHISHNET_SPLUNK_USER and PHISHNET_SPLUNK_PW")
    sys.exit(1)

HERO = "PH-0286"
failures = []


def check(name, ok, detail=""):
    status = "PASS" if ok else "FAIL"
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))
    if not ok:
        failures.append(name)


def orchestration(cfg, label):
    r = agent_api.investigate_alert(HERO, cfg)
    if "error" in r:
        check(f"investigate_alert ({label})", False, r["error"])
        return
    o = r.get("orchestration") or {}
    if "error" in o:
        check(f"orchestration ({label})", False, o["error"])
        return
    tools = o.get("tools") or []
    ok = (
        o.get("parallel") is True
        and o.get("tools_run") == 5
        and o.get("aggregate_signal") == "malicious"
        and o.get("transport") == label
        and all(not t.get("error") for t in tools)
        and any("secure-docusign-portal.net" in t.get("finding", "") for t in tools)
    )
    check(
        f"orchestration ({label})",
        ok,
        f"transport={o.get('transport')} tools={o.get('tools_run')} "
        f"signal={o.get('aggregate_signal')} speedup={o.get('speedup')}x",
    )


print("=== PhishNet pre-push smoke test ===\n")

# 1) KV hero alert — Splunk-native reputation in steps_text
import splunklib.client as client

s = client.connect(host="localhost", port=8089, scheme="https", username=USER, password=PW)
rows = s.kvstore["phishnet_decisions"].data.query(
    query=json.dumps({"alert_id": HERO})
)
d = rows[0] if rows else {}
steps = d.get("steps_text", "")
check("hero verdict preserved", d.get("verdict") == "targeted_attack", d.get("verdict"))
check("Splunk-native reputation phrasing", "Splunk reputation:" in steps, "steps_text")
check("no external VT/urlscan labels", "urlscan" not in steps.lower() and "virustotal" not in steps.lower())

# 2) Index + KV counts
job = s.jobs.oneshot(
    "search index=phishing sourcetype=phishnet:alert | stats count",
    output_mode="json",
    earliest_time="0",
    latest_time="now",
)
import splunklib.results as results

idx_rows = [r for r in results.JSONResultsReader(job) if isinstance(r, dict)]
idx_count = int(idx_rows[0].get("count", 0)) if idx_rows else 0
kv_count = len(s.kvstore["phishnet_decisions"].data.query())
check("index=phishing has 300 alerts", idx_count == 300, str(idx_count))
check("phishnet_decisions KV has 300 rows", kv_count == 300, str(kv_count))

# 3) Orchestration — SDK transport (default)
print()
cfg_sdk = AgentConfig(
    backend="sdk", classifier="mock",
    splunk_username=USER, splunk_password=PW,
    use_splunk_mcp=False,
)
orchestration(cfg_sdk, "sdk")

# 4) Orchestration — official Splunk MCP transport
cfg_mcp = AgentConfig(
    backend="sdk", classifier="mock",
    splunk_username=USER, splunk_password=PW,
    use_splunk_mcp=True,
)
orchestration(cfg_mcp, "splunk_mcp")

print()
if failures:
    print(f"FAILED: {len(failures)} check(s): {', '.join(failures)}")
    sys.exit(1)
print("ALL CHECKS PASSED — safe to push.")
