#!/usr/bin/env python
"""
PhishNet AI - Modular Input Entry Point

Registered with Splunk as the `phishnet_agent` modular input. On each interval,
the agent:
  1. Reads new phishing alerts from the source index (via MCP / Splunk SDK).
  2. Runs the multi-step investigation playbook on each alert.
  3. Classifies each alert with Foundation-Sec-8B (DSDL / HF / mock).
  4. Generates an investigation report.
  5. Writes results to the actions index and the phishnet_decisions KV Store.

During Week 1 this runs in --once mode from the CLI for fast iteration.
Splunk modular-input wiring (Scheme/validation/stream) is completed once the
core pipeline works end-to-end.

Usage (dev, standalone):
    python phishnet_agent.py --once
    python phishnet_agent.py --once --classifier mock --limit 5
"""

import argparse
import sys

# NOTE: when running inside Splunk, phishnet_lib is importable because Splunk
# adds the app's bin/ directory to sys.path. For standalone dev runs we ensure
# the local package is importable too.
try:
    from phishnet_lib.pipeline import run_once
    from phishnet_lib.config import AgentConfig
except ImportError:
    import os
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from phishnet_lib.pipeline import run_once
    from phishnet_lib.config import AgentConfig


def parse_args(argv):
    parser = argparse.ArgumentParser(description="PhishNet AI agent")
    parser.add_argument("--once", action="store_true",
                        help="Process the current alert batch once and exit (dev mode).")
    parser.add_argument("--classifier", default="mock",
                        choices=["mock", "dsdl", "huggingface"],
                        help="Classification backend to use.")
    parser.add_argument("--mode", default="recommend",
                        choices=["recommend", "auto"],
                        help="recommend = analyst confirms; auto = auto-close high-confidence FPs.")
    parser.add_argument("--limit", type=int, default=0,
                        help="Max alerts to process this run (0 = no limit).")
    return parser.parse_args(argv)


def main(argv=None):
    args = parse_args(argv if argv is not None else sys.argv[1:])
    config = AgentConfig(
        classifier=args.classifier,
        mode=args.mode,
        limit=args.limit,
    )

    if args.once:
        summary = run_once(config)
        print(summary.as_text())
        return 0

    # TODO(week1-day7): wire Splunk ModularInput Scheme/validation/stream loop here.
    print("Continuous modular-input mode not yet wired. Use --once for dev runs.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
