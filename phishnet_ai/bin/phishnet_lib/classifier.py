"""Classification backends for phishing verdicts.

Three backends:
  - mock:        deterministic stub for dev/demo (no model needed)
  - dsdl:        calls the Foundation-Sec-8B DSDL container endpoint
  - huggingface: loads Foundation-Sec-8B locally (fallback)

Week 1 ships `mock`. `dsdl` is wired on Day 4. `huggingface` is the fallback.
"""

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
    """Foundation-Sec-8B via the DSDL container. Wired on Week 1 Day 4."""

    def __init__(self, config: AgentConfig):
        self.config = config

    def classify(self, alert: Alert, investigation: Investigation) -> Verdict:
        # TODO(week1-day4): POST alert + investigation context to DSDL endpoint
        # at self.config.dsdl_url, parse the zero-shot classification response.
        raise NotImplementedError("DSDL classifier wired on Week 1 Day 4.")


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
