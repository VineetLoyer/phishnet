"""Agent configuration."""

import os
from dataclasses import dataclass
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

    # I/O backend: None (auto) | "file" | "sdk" | "mcp"
    backend: Optional[str] = None
    use_mcp: bool = False

    # Confidence threshold above which a false-positive may auto-close (auto mode only)
    auto_close_confidence: float = 0.90

    # Connection (populated from Splunk session token when running in-product)
    splunk_host: str = "localhost"
    splunk_port: int = 8089
    splunk_token: Optional[str] = None
    splunk_username: Optional[str] = None
    splunk_password: Optional[str] = None

    # DSDL / local LLM endpoint for Foundation-Sec-8B
    # provider: None (auto-detect from url) | "ollama" | "dsdl"
    llm_provider: Optional[str] = None
    dsdl_url: str = "http://localhost:11434"      # Ollama default; DSDL uses :5000
    # Foundation-Sec-8B (Cisco Foundation AI). Instruct GGUF fits a 6GB GPU and
    # follows the JSON classification prompt. Override via --llm-model.
    llm_model: str = "hf.co/mradermacher/Foundation-Sec-8B-Instruct-GGUF:Q4_K_M"
    llm_timeout: int = 300        # seconds; first call loads model into VRAM/RAM

    # Threat-intel API keys (loaded from env / Splunk secret store, never hardcoded)
    vt_api_key: Optional[str] = None
    urlscan_api_key: Optional[str] = None

    def __post_init__(self):
        if not self.splunk_username:
            self.splunk_username = os.environ.get("PHISHNET_SPLUNK_USER")
        if not self.splunk_password:
            self.splunk_password = os.environ.get("PHISHNET_SPLUNK_PW")
        if not self.splunk_token:
            self.splunk_token = os.environ.get("PHISHNET_SPLUNK_TOKEN")

        if self.mode not in ("recommend", "auto"):
            raise ValueError(f"invalid mode: {self.mode}")
        if self.classifier not in ("mock", "dsdl", "huggingface"):
            raise ValueError(f"invalid classifier: {self.classifier}")
