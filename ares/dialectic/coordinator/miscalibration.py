"""Miscalibration Detector — overconfidence detection for dialectical verdicts.

Session 023: Deterministic rule-based pre-screen that flags suspicious
confidence patterns where the verdict is confident but evidence doesn't
support that confidence level.

The EscalationGate (Session 022) catches uncertainty. This detector
catches the complementary problem: overconfidence (miscalibration).

Design insight: Session 022 showed all 7 benchmark errors are
MISCALIBRATED (confidently wrong), not uncertain. The gate at
[0.35, 0.70] only captures 14% of errors because miscalibrated
verdicts sit above the band with high confidence.

Public API:
    MiscalibrationPattern  — enum of detection patterns
    MiscalibrationResult   — frozen dataclass with detection outcome
    MiscalibrationDetector — the detector; call .detect() -> MiscalibrationResult
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Tuple

from ares.dialectic.agents.patterns import Verdict
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage


class MiscalibrationPattern(Enum):
    """Patterns that indicate a verdict may be miscalibrated.

    EVIDENCE_STARVATION: High confidence with very few cited facts.
    EVIDENCE_CONFLICT: High confidence despite conflicting evidence.
    CONFIDENCE_COMPLEXITY_MISMATCH: High confidence on complex scenarios.
    NARROW_SPREAD: Architect and Skeptic agree at high confidence
                   (groupthink — no real challenge occurred).
    """

    EVIDENCE_STARVATION = "evidence_starvation"
    EVIDENCE_CONFLICT = "evidence_conflict"
    CONFIDENCE_COMPLEXITY_MISMATCH = "confidence_complexity_mismatch"
    NARROW_SPREAD = "narrow_spread"


class MiscalibrationRecommendation(Enum):
    """Recommendation from the miscalibration detector.

    PASS: No miscalibration detected; verdict can be trusted.
    INSPECT: Potential miscalibration; verdict should be audited.
    """

    PASS = "pass"
    INSPECT = "inspect"


@dataclass(frozen=True)
class MiscalibrationResult:
    """Immutable result from miscalibration detection.

    Attributes:
        flagged: True if any miscalibration pattern was triggered.
        patterns_triggered: Which patterns fired.
        risk_score: Proportion of patterns triggered (0.0–1.0).
        recommendation: PASS or INSPECT.
        details: Human-readable explanation for each triggered pattern.
    """

    flagged: bool
    patterns_triggered: Tuple[MiscalibrationPattern, ...]
    risk_score: float
    recommendation: MiscalibrationRecommendation
    details: Tuple[str, ...]


# Default conflict pairs: field values that contradict each other
# when found on the same entity_id.
DEFAULT_CONFLICT_PAIRS: Tuple[Tuple[str, str], ...] = (
    ("authentication_success", "authentication_failure"),
    ("login_success", "login_failure"),
    ("allow", "deny"),
    ("permit", "block"),
    ("connection_established", "connection_refused"),
)


class MiscalibrationDetector:
    """Deterministic rule-based miscalibration detector.

    Examines verdict confidence against evidence quality signals.
    Flags verdicts that are confident but poorly supported.

    Args:
        min_facts_for_confidence: Minimum cited facts for high confidence.
        confidence_threshold: Confidence level above which patterns are checked.
        conflict_indicators: Pairs of field values that conflict.
        complexity_entity_threshold: Entity type count triggering complexity.
        complexity_source_threshold: Source type count triggering complexity.
        spread_threshold: Maximum architect-skeptic spread for NARROW_SPREAD.
        spread_minimum: Minimum individual confidence for NARROW_SPREAD.
    """

    _PATTERN_COUNT = 4  # Total number of patterns for risk_score

    def __init__(
        self,
        min_facts_for_confidence: int = 3,
        confidence_threshold: float = 0.70,
        conflict_indicators: Tuple[Tuple[str, str], ...] = DEFAULT_CONFLICT_PAIRS,
        complexity_entity_threshold: int = 4,
        complexity_source_threshold: int = 3,
        spread_threshold: float = 0.15,
        spread_minimum: float = 0.60,
    ) -> None:
        if not 0.0 <= confidence_threshold <= 1.0:
            raise ValueError(
                f"confidence_threshold must be in [0.0, 1.0], got {confidence_threshold}"
            )
        if not 0.0 <= spread_threshold <= 1.0:
            raise ValueError(
                f"spread_threshold must be in [0.0, 1.0], got {spread_threshold}"
            )
        if not 0.0 <= spread_minimum <= 1.0:
            raise ValueError(
                f"spread_minimum must be in [0.0, 1.0], got {spread_minimum}"
            )
        if min_facts_for_confidence < 0:
            raise ValueError(
                f"min_facts_for_confidence must be >= 0, got {min_facts_for_confidence}"
            )
        if complexity_entity_threshold < 1:
            raise ValueError(
                f"complexity_entity_threshold must be >= 1, got {complexity_entity_threshold}"
            )
        if complexity_source_threshold < 1:
            raise ValueError(
                f"complexity_source_threshold must be >= 1, got {complexity_source_threshold}"
            )

        self._min_facts_for_confidence = min_facts_for_confidence
        self._confidence_threshold = confidence_threshold
        self._conflict_indicators = conflict_indicators
        self._complexity_entity_threshold = complexity_entity_threshold
        self._complexity_source_threshold = complexity_source_threshold
        self._spread_threshold = spread_threshold
        self._spread_minimum = spread_minimum

    @property
    def min_facts_for_confidence(self) -> int:
        """Minimum cited facts needed for high confidence."""
        return self._min_facts_for_confidence

    @property
    def confidence_threshold(self) -> float:
        """Confidence level above which patterns are checked."""
        return self._confidence_threshold

    @property
    def conflict_indicators(self) -> Tuple[Tuple[str, str], ...]:
        """Pairs of field values that constitute conflicts."""
        return self._conflict_indicators

    @property
    def complexity_entity_threshold(self) -> int:
        """Entity type count that triggers complexity pattern."""
        return self._complexity_entity_threshold

    @property
    def complexity_source_threshold(self) -> int:
        """Source type count that triggers complexity pattern."""
        return self._complexity_source_threshold

    @property
    def spread_threshold(self) -> float:
        """Maximum architect-skeptic spread for narrow spread detection."""
        return self._spread_threshold

    @property
    def spread_minimum(self) -> float:
        """Minimum individual confidence for narrow spread detection."""
        return self._spread_minimum

    def detect(
        self,
        verdict: Verdict,
        architect_message: DialecticalMessage,
        skeptic_message: DialecticalMessage,
        packet: EvidencePacket,
    ) -> MiscalibrationResult:
        """Run all miscalibration detection patterns.

        Args:
            verdict: The Oracle's verdict to evaluate.
            architect_message: The Architect's dialectical message.
            skeptic_message: The Skeptic's dialectical message.
            packet: The EvidencePacket grounding the debate.

        Returns:
            MiscalibrationResult with detection outcome.
        """
        patterns: list[MiscalibrationPattern] = []
        details: list[str] = []

        # Pattern 1: Evidence Starvation
        if self._check_evidence_starvation(verdict, architect_message):
            patterns.append(MiscalibrationPattern.EVIDENCE_STARVATION)
            cited = self._count_cited_facts(architect_message)
            details.append(
                f"EVIDENCE_STARVATION: Verdict confidence {verdict.confidence:.3f} "
                f">= {self._confidence_threshold:.2f} but only {cited} fact(s) cited "
                f"(minimum {self._min_facts_for_confidence} required)."
            )

        # Pattern 2: Evidence Conflict
        if self._check_evidence_conflict(verdict, packet):
            patterns.append(MiscalibrationPattern.EVIDENCE_CONFLICT)
            details.append(
                f"EVIDENCE_CONFLICT: Verdict confidence {verdict.confidence:.3f} "
                f">= {self._confidence_threshold:.2f} but packet contains "
                f"conflicting evidence fields on overlapping entities."
            )

        # Pattern 3: Confidence-Complexity Mismatch
        if self._check_complexity_mismatch(verdict, packet):
            patterns.append(MiscalibrationPattern.CONFIDENCE_COMPLEXITY_MISMATCH)
            entity_types = self._count_distinct_entity_types(packet)
            source_types = self._count_distinct_source_types(packet)
            details.append(
                f"CONFIDENCE_COMPLEXITY_MISMATCH: Verdict confidence "
                f"{verdict.confidence:.3f} >= {self._confidence_threshold:.2f} "
                f"but scenario has {entity_types} entity type(s) "
                f"(threshold {self._complexity_entity_threshold}) and "
                f"{source_types} source type(s) "
                f"(threshold {self._complexity_source_threshold})."
            )

        # Pattern 4: Narrow Spread
        if self._check_narrow_spread(architect_message, skeptic_message):
            patterns.append(MiscalibrationPattern.NARROW_SPREAD)
            spread = abs(architect_message.confidence - skeptic_message.confidence)
            details.append(
                f"NARROW_SPREAD: Architect ({architect_message.confidence:.3f}) "
                f"and Skeptic ({skeptic_message.confidence:.3f}) spread "
                f"{spread:.3f} <= {self._spread_threshold:.2f}, both "
                f">= {self._spread_minimum:.2f}. No real challenge occurred."
            )

        flagged = len(patterns) > 0
        risk_score = len(patterns) / self._PATTERN_COUNT
        recommendation = (
            MiscalibrationRecommendation.INSPECT
            if flagged
            else MiscalibrationRecommendation.PASS
        )

        return MiscalibrationResult(
            flagged=flagged,
            patterns_triggered=tuple(patterns),
            risk_score=risk_score,
            recommendation=recommendation,
            details=tuple(details),
        )

    def _check_evidence_starvation(
        self, verdict: Verdict, architect_message: DialecticalMessage
    ) -> bool:
        """Check if verdict is confident with too few cited facts."""
        if verdict.confidence < self._confidence_threshold:
            return False
        if len(architect_message.assertions) == 0:
            return False
        cited = self._count_cited_facts(architect_message)
        return cited < self._min_facts_for_confidence

    def _count_cited_facts(self, message: DialecticalMessage) -> int:
        """Count total unique fact IDs cited across all assertions."""
        all_facts: set[str] = set()
        for assertion in message.assertions:
            all_facts.update(assertion.fact_ids)
        return len(all_facts)

    def _check_evidence_conflict(
        self, verdict: Verdict, packet: EvidencePacket
    ) -> bool:
        """Check if packet has conflicting evidence fields on same entity."""
        if verdict.confidence < self._confidence_threshold:
            return False

        # Build entity_id -> set of field values
        entity_fields: dict[str, set[str]] = {}
        for fact in packet.get_all_facts():
            if fact.entity_id not in entity_fields:
                entity_fields[fact.entity_id] = set()
            entity_fields[fact.entity_id].add(fact.field)

        # Check each entity for conflict pairs
        for _entity_id, fields in entity_fields.items():
            for field_a, field_b in self._conflict_indicators:
                if field_a in fields and field_b in fields:
                    return True
        return False

    def _check_complexity_mismatch(
        self, verdict: Verdict, packet: EvidencePacket
    ) -> bool:
        """Check if verdict is confident on a complex scenario."""
        if verdict.confidence < self._confidence_threshold:
            return False

        entity_types = self._count_distinct_entity_types(packet)
        source_types = self._count_distinct_source_types(packet)

        return (
            entity_types >= self._complexity_entity_threshold
            or source_types >= self._complexity_source_threshold
        )

    def _count_distinct_entity_types(self, packet: EvidencePacket) -> int:
        """Count distinct entity_type values in the packet."""
        return len({fact.entity_type for fact in packet.get_all_facts()})

    def _count_distinct_source_types(self, packet: EvidencePacket) -> int:
        """Count distinct source_type values in the packet's provenance."""
        return len({fact.provenance.source_type for fact in packet.get_all_facts()})

    def _check_narrow_spread(
        self,
        architect_message: DialecticalMessage,
        skeptic_message: DialecticalMessage,
    ) -> bool:
        """Check if architect and skeptic agree at high confidence."""
        arch_conf = architect_message.confidence
        skep_conf = skeptic_message.confidence
        spread = abs(arch_conf - skep_conf)
        return (
            spread <= self._spread_threshold
            and arch_conf >= self._spread_minimum
            and skep_conf >= self._spread_minimum
        )

    def __repr__(self) -> str:
        return (
            f"MiscalibrationDetector("
            f"confidence_threshold={self._confidence_threshold}, "
            f"min_facts={self._min_facts_for_confidence})"
        )
