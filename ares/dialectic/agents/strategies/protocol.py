"""Strategy protocols for pluggable agent reasoning.

Three separate protocols because each agent has a different input signature:
- ThreatAnalyzer: (packet) -> anomalies (Architect)
- ExplanationFinder: (architect_msg, packet) -> explanations (Skeptic)
- NarrativeGenerator: (verdict, packet, ...) -> narrative text (OracleNarrator)

Each protocol allows independent substitution — the Architect can use an LLM
while the Skeptic stays rule-based, or vice versa.
"""

from __future__ import annotations

from typing import List, Optional, Protocol, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.agents.patterns import AnomalyPattern, BenignExplanation, Verdict
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


class ThreatAnalyzer(Protocol):
    """Strategy for detecting anomaly patterns in evidence.

    Implementations:
    - RuleBasedThreatAnalyzer: Extracted deterministic logic (default)
    - LLMThreatAnalyzer: Anthropic API with closed-world validation
    """

    def analyze_threats(self, packet: EvidencePacket) -> List[AnomalyPattern]: ...


class ExplanationFinder(Protocol):
    """Strategy for finding benign explanations for the Architect's claims.

    Takes the full Architect message (not individual assertions) because
    the rule-based implementation analyzes the packet holistically, and
    the LLM strategy benefits from seeing all assertions for context.

    Implementations:
    - RuleBasedExplanationFinder: Extracted deterministic logic (default)
    - LLMExplanationFinder: Anthropic API with closed-world validation
    """

    def find_explanations(
        self,
        architect_msg: DialecticalMessage,
        packet: EvidencePacket,
    ) -> List[BenignExplanation]: ...


class NarrativeGenerator(Protocol):
    """Strategy for generating verdict explanations.

    The narrative explains a locked verdict — it CANNOT change the outcome.
    architect_msg and skeptic_msg are Optional because the OracleNarrator
    may not have them in scope (the orchestrator only passes verdict + packet).

    Implementations:
    - RuleBasedNarrativeGenerator: Template-based explanation (default)
    - LLMNarrativeGenerator: Anthropic API for natural language
    """

    def generate_narrative(
        self,
        verdict: Verdict,
        packet: EvidencePacket,
        architect_msg: Optional[DialecticalMessage] = None,
        skeptic_msg: Optional[DialecticalMessage] = None,
    ) -> str: ...
