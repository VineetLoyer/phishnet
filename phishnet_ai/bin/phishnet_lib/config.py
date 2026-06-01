"""Agent configuration."""

from dataclasses import dataclass, field
from typing import Optional


@dataclass
class AgentConfig:
    """Runtime configuration for a PhishNet agent run.

    Values mirror the modular-input stanza in inputs.conf so that the same
    config object works in both standalone (--once) and Splunk-managed modes.
    """

    # Indexes
    source_index: str = "phishing"
    actions_index: str = "phishnet_actions"
    metrics_index: str = "metrics"
    audit_index: str = "phishnet_audit"

    # Behavior
    mode: str = "recommend"          # recommend | auto
    classifier: str = "mock"         # mock | dsdl | huggingface
    limit: int = 0                   # 0 = no limit

    # Confidence threshold above which a false-positive may auto-close (auto mode only)
    auto_close_confidence: float = 0.90

    # Connection (populated from Splunk session token when running in-product)
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_token: Optional[str] = None

    # DSDL endpoint for Foundation-Sec-8B (classifier == "dsdl")
    dsdl_url: str = "http://localhost:5000"

    # Threat-intel API keys (loaded from env / Splunk secret store, never hardcoded)
    vt_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None

    def __post_init__(self):
        if self.mode not in ("recommend", "auto"):
            raise ValueError(f"invalid mode: {self.mode}")
        if self.classifier not in ("mock", "dsdl", "huggingface"):
            raise ValueError(f"invalid classifier: {self.classifier}")
