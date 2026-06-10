#!/usr/bin/env python
"""Print the end-of-shift handoff report from phishnet_decisions KV."""

import argparse
import json
import os
import sys

REPO = os.path.normpath(os.path.join(os.path.dirname(__file__), ".."))
sys.path.insert(0, os.path.join(REPO, "phishnet_ai", "bin"))

from phishnet_lib.config import AgentConfig  # noqa: E402
from phishnet_lib import agent_api  # noqa: E402


def main() -> int:
    parser = argparse.ArgumentParser(description="PhishNet AI end-of-shift handoff report")
    parser.add_argument("--json", action="store_true", help="Emit structured JSON")
    parser.add_argument("-o", "--output", help="Write to file instead of stdout")
    parser.add_argument("--base-url", default="", help="Base URL for Manager ROI link")
    args = parser.parse_args()

    config = AgentConfig(backend="sdk")
    handoff = agent_api.get_shift_handoff(
        config,
        base_url=args.base_url or None,
    )

    if args.json:
        text = json.dumps(handoff, indent=2)
    else:
        text = handoff["report_text"]

    if args.output:
        with open(args.output, "w", encoding="utf-8") as fh:
            fh.write(text)
        print(f"Wrote {args.output}")
    else:
        print(text)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
