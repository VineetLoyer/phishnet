"""Classification backends for phishing verdicts.

Three backends:
  - mock:        deterministic stub for dev/demo (no model needed)
  - dsdl:        calls the Foundation-Sec-8B DSDL container endpoint
  - huggingface: loads Foundation-Sec-8B locally (fallback)

Week 1 ships `mock`. `dsdl` is wired on Day 4. `huggingface` is the fallback.
"""

import sys
from typing import Protocol
from .models import Alert, Investigation, Verdict
from .config import AgentConfig


class Classifier(Protocol):
    def classify(self, alert: Alert, investigation: Investigation) -> Verdict:
        ...


class MockClassifier:
    """Deterministic classifier driven by signals in the investigation.

    Heuristics (transparent, demo-friendly):
      - any malicious-signal step  -> phishing / high confidence
      - any suspicious-signal step -> phishing / medium confidence
      - otherwise                  -> legitimate / high confidence
    A 'targeted_attack' label is produced when the payload executed.
    """

    def classify(self, alert: Alert, investigation: Investigation) -> Verdict:
        signals = [s.signal for s in investigation.steps]
        executed = bool(investigation.blast_radius and investigation.blast_radius.payload_executed)

        if executed or "malicious" in signals:
            label = "targeted_attack" if executed else "phishing"
            confidence = 0.96 if executed else 0.91
            reasons = [s.finding for s in investigation.steps
                       if s.signal in ("malicious", "suspicious")]
            reasoning = (
                "Classified as {} (confidence {:.0%}). Key evidence: {}".format(
                    label, confidence,
                    "; ".join(reasons) or "multiple high-risk indicators",
                )
            )
            return Verdict(label=label, confidence=confidence, reasoning=reasoning)

        if "suspicious" in signals:
            reasons = [s.finding for s in investigation.steps if s.signal == "suspicious"]
            return Verdict(
                label="phishing",
                confidence=0.78,
                reasoning="Ambiguous indicators present; flagged for analyst review. "
                          + ("; ".join(reasons) if reasons else ""),
            )

        return Verdict(
            label="legitimate",
            confidence=0.93,
            reasoning="No malicious or suspicious indicators found across "
                      f"{len(investigation.steps)} investigation steps. "
                      "Matches known false-positive patterns.",
        )


class DsdlClassifier:
    """Foundation-Sec-8B via an HTTP inference endpoint.

    Works against either:
      - Ollama  (default, http://localhost:11434) running a Foundation-Sec GGUF
      - Splunk DSDL container (http://localhost:5000) hosting Foundation-Sec-8B

    The endpoint type is auto-detected from config.dsdl_url, or set explicitly
    via config.llm_provider ("ollama" | "dsdl"). Both speak HTTP+JSON; only the
    request/response shape differs, handled below.

    The classifier sends the alert + investigation context and asks the security
    model for a zero-shot verdict with reasoning. Output is parsed into a Verdict.
    """

    LABELS = ["phishing", "legitimate", "spam", "targeted_attack"]

    def __init__(self, config: AgentConfig):
        self.config = config
        self.provider = getattr(config, "llm_provider", None) or self._detect_provider()

    def _detect_provider(self) -> str:
        url = (self.config.dsdl_url or "").lower()
        if "11434" in url or "ollama" in url:
            return "ollama"
        return "dsdl"

    def _build_prompt(self, alert: Alert, investigation: Investigation) -> str:
        findings = "\n".join(
            f"- [{s.signal}] {s.name}: {s.finding}" for s in investigation.steps
        )
        executed = bool(investigation.blast_radius and investigation.blast_radius.payload_executed)
        return (
            "You are a SOC security analyst model. Classify the following email "
            "security alert into exactly one label: phishing, legitimate, spam, "
            "or targeted_attack. Use targeted_attack only if a payload executed "
            "or credentials were compromised.\n\n"
            f"Sender: {alert.sender}\n"
            f"Sender domain: {alert.sender_domain}\n"
            f"Subject: {alert.subject}\n"
            f"Recipients: {len(alert.recipients)}\n"
            f"Payload executed on endpoint: {executed}\n\n"
            f"Investigation findings:\n{findings}\n\n"
            "Respond in JSON only: "
            '{"label": "<one label>", "confidence": <0.0-1.0>, "reasoning": "<one sentence>"}'
        )

    def classify(self, alert: Alert, investigation: Investigation) -> Verdict:
        # The model endpoint can be momentarily unavailable (cold load, GPU
        # contention, transient socket drop). A single alert must never be left
        # unclassified mid-batch, so any endpoint failure degrades gracefully to
        # the deterministic heuristics instead of raising.
        try:
            text = self._call_model(alert, investigation)
        except Exception as exc:  # noqa: BLE001 - intentional catch-all fallback
            sys.stderr.write(
                f"[classifier] Foundation-Sec endpoint unavailable "
                f"({type(exc).__name__}: {exc}); falling back to heuristics.\n"
            )
            return MockClassifier().classify(alert, investigation)
        return self._parse(text, investigation)

    def _call_model(self, alert: Alert, investigation: Investigation) -> str:
        import json
        import requests

        prompt = self._build_prompt(alert, investigation)
        # First call may be slow while the model loads into VRAM/RAM. Use a
        # generous timeout; keep_alive holds the model in memory between calls.
        timeout = getattr(self.config, "llm_timeout", 300)

        if self.provider == "ollama":
            base = self.config.dsdl_url or "http://localhost:11434"
            resp = requests.post(
                f"{base}/api/generate",
                json={
                    "model": self.config.llm_model,
                    "prompt": prompt,
                    "stream": False,
                    "format": "json",
                    "keep_alive": "10m",
                    "options": {"temperature": 0.0, "num_predict": 200},
                },
                timeout=timeout,
            )
            resp.raise_for_status()
            return resp.json().get("response", "")

        # dsdl
        base = self.config.dsdl_url or "http://localhost:5000"
        resp = requests.post(
            f"{base}/predict",
            json={"prompt": prompt},
            timeout=timeout,
        )
        resp.raise_for_status()
        payload = resp.json()
        return payload.get("response") or payload.get("text") or json.dumps(payload)

    def _parse(self, text: str, investigation: Investigation) -> Verdict:
        import json
        import re

        label, confidence, reasoning = "phishing", 0.5, text.strip()[:300]
        try:
            # Extract the first JSON object in the response.
            match = re.search(r"\{.*\}", text, re.DOTALL)
            data = json.loads(match.group(0)) if match else json.loads(text)
            label = str(data.get("label", label)).strip().lower()
            if label not in self.LABELS:
                label = "phishing"
            confidence = float(data.get("confidence", confidence))
            confidence = max(0.0, min(1.0, confidence))  # clamp to [0,1]
            reasoning = str(data.get("reasoning", reasoning))
        except (ValueError, AttributeError, TypeError):
            # Model didn't return clean JSON — fall back to keyword heuristics.
            low = text.lower()
            for cand in self.LABELS:
                if cand in low:
                    label = cand
                    break
        return Verdict(label=label, confidence=confidence, reasoning=reasoning)


class HuggingFaceClassifier:
    """Foundation-Sec-8B loaded locally via transformers. Fallback backend."""

    def __init__(self, config: AgentConfig):
        self.config = config

    def classify(self, alert: Alert, investigation: Investigation) -> Verdict:
        # TODO(fallback): load fdtn-ai/Foundation-Sec-8B-Instruct and run inference.
        raise NotImplementedError("HuggingFace classifier is the fallback backend.")


def get_classifier(config: AgentConfig) -> Classifier:
    if config.classifier == "mock":
        return MockClassifier()
    if config.classifier == "dsdl":
        return DsdlClassifier(config)
    if config.classifier == "huggingface":
        return HuggingFaceClassifier(config)
    raise ValueError(f"unknown classifier: {config.classifier}")
