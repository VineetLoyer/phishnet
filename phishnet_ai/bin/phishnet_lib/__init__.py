"""PhishNet AI agent library.

Modules:
    config        - AgentConfig dataclass and defaults.
    models        - Typed data structures (Alert, Investigation, Verdict, Report).
    splunk_io     - Reads alerts from / writes results to Splunk (MCP + SDK).
    investigation - The multi-step investigation playbook.
    classifier    - Foundation-Sec-8B classification backends (mock/dsdl/hf).
    report        - Investigation report generation.
    pipeline      - Orchestrates the end-to-end run.
"""

__version__ = "0.1.0"
