"""Tests for MiscalibrationDetector — Session 023.

Comprehensive tests covering construction, each detection pattern,
pattern combinations, boundary conditions, risk score, recommendation
logic, immutability, and integration with existing types.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from ares.dialectic.coordinator.miscalibration import (
    DEFAULT_CONFLICT_PAIRS,
    MiscalibrationDetector,
    MiscalibrationPattern,
    MiscalibrationRecommendation,
    MiscalibrationResult,
)
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def _make_provenance(source_type: SourceType = SourceType.SYSLOG) -> Provenance:
    return Provenance(
        source_type=source_type,
        source_id="test-src",
        parser_version="1.0.0",
        extracted_at=_ts(),
    )


def _make_fact(
    fact_id: str,
    entity_id: str = "host-1",
    entity_type: EntityType = EntityType.NODE,
    field: str = "event",
    value: str = "test",
    source_type: SourceType = SourceType.SYSLOG,
) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=entity_type,
        field=field,
        value=value,
        timestamp=_ts(),
        provenance=_make_provenance(source_type),
    )


def _make_packet(facts: list[Fact] | None = None) -> EvidencePacket:
    tw = TimeWindow(start=_ts() - timedelta(hours=1), end=_ts())
    pkt = EvidencePacket(packet_id="pkt-001", time_window=tw)
    for f in (facts or []):
        pkt.add_fact(f)
    pkt.freeze()
    return pkt


def _make_assertion(
    assertion_id: str = "a1",
    fact_ids: tuple[str, ...] = ("f1",),
    interpretation: str = "test claim",
) -> Assertion:
    return Assertion(
        assertion_id=assertion_id,
        assertion_type=AssertionType.ASSERT,
        fact_ids=fact_ids,
        interpretation=interpretation,
    )


def _make_message(
    confidence: float = 0.5,
    assertions: list[Assertion] | None = None,
    source_agent: str = "architect",
) -> DialecticalMessage:
    return DialecticalMessage(
        message_id="msg-001",
        timestamp=_ts(),
        source_agent=source_agent,
        target_agent="oracle",
        confidence=confidence,
        assertions=assertions or [],
        phase=Phase.THESIS,
        message_type=MessageType.HYPOTHESIS,
    )


def _make_verdict(
    confidence: float = 0.80,
    architect_confidence: float = 0.80,
    skeptic_confidence: float = 0.30,
    outcome: VerdictOutcome = VerdictOutcome.THREAT_CONFIRMED,
) -> Verdict:
    return Verdict(
        outcome=outcome,
        confidence=confidence,
        supporting_fact_ids=frozenset({"f1"}),
        architect_confidence=architect_confidence,
        skeptic_confidence=skeptic_confidence,
        reasoning="Test verdict",
    )


# ===========================================================================
# Construction and defaults
# ===========================================================================

class TestMiscalibrationDetectorConstruction:
    """Test MiscalibrationDetector construction and defaults."""

    def test_default_construction(self) -> None:
        d = MiscalibrationDetector()
        assert d.min_facts_for_confidence == 3
        assert d.confidence_threshold == 0.70
        assert d.complexity_entity_threshold == 4
        assert d.complexity_source_threshold == 3
        assert d.spread_threshold == 0.15
        assert d.spread_minimum == 0.60
        assert d.conflict_indicators == DEFAULT_CONFLICT_PAIRS

    def test_custom_thresholds(self) -> None:
        d = MiscalibrationDetector(
            min_facts_for_confidence=5,
            confidence_threshold=0.80,
            complexity_entity_threshold=6,
            complexity_source_threshold=4,
            spread_threshold=0.10,
            spread_minimum=0.70,
        )
        assert d.min_facts_for_confidence == 5
        assert d.confidence_threshold == 0.80
        assert d.complexity_entity_threshold == 6
        assert d.complexity_source_threshold == 4
        assert d.spread_threshold == 0.10
        assert d.spread_minimum == 0.70

    def test_invalid_confidence_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_threshold"):
            MiscalibrationDetector(confidence_threshold=1.5)

    def test_invalid_confidence_threshold_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="confidence_threshold"):
            MiscalibrationDetector(confidence_threshold=-0.1)

    def test_invalid_spread_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="spread_threshold"):
            MiscalibrationDetector(spread_threshold=2.0)

    def test_invalid_spread_minimum_raises(self) -> None:
        with pytest.raises(ValueError, match="spread_minimum"):
            MiscalibrationDetector(spread_minimum=-0.5)

    def test_invalid_min_facts_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="min_facts_for_confidence"):
            MiscalibrationDetector(min_facts_for_confidence=-1)

    def test_invalid_complexity_entity_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="complexity_entity_threshold"):
            MiscalibrationDetector(complexity_entity_threshold=0)

    def test_invalid_complexity_source_threshold_raises(self) -> None:
        with pytest.raises(ValueError, match="complexity_source_threshold"):
            MiscalibrationDetector(complexity_source_threshold=0)

    def test_repr(self) -> None:
        d = MiscalibrationDetector()
        r = repr(d)
        assert "MiscalibrationDetector" in r
        assert "0.7" in r

    def test_custom_conflict_indicators(self) -> None:
        custom = (("open", "closed"),)
        d = MiscalibrationDetector(conflict_indicators=custom)
        assert d.conflict_indicators == custom


# ===========================================================================
# Evidence Starvation pattern
# ===========================================================================

class TestEvidenceStarvation:
    """Tests for the EVIDENCE_STARVATION detection pattern."""

    def test_starvation_triggers_when_few_facts_cited(self) -> None:
        """High confidence + assertions citing only 1 fact -> flagged."""
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION in result.patterns_triggered

    def test_starvation_no_trigger_enough_facts(self) -> None:
        """High confidence with 3+ cited facts -> not flagged."""
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        facts = [_make_fact(f"f{i}") for i in range(3)]
        pkt = _make_packet(facts)
        arch = _make_message(
            confidence=0.85,
            assertions=[_make_assertion("a1", ("f0", "f1", "f2"))],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION not in result.patterns_triggered

    def test_starvation_no_trigger_low_confidence(self) -> None:
        """Low confidence with few facts -> not flagged."""
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.50, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.40, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.50)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION not in result.patterns_triggered

    def test_starvation_no_trigger_no_assertions(self) -> None:
        """High confidence but no assertions -> not flagged (nothing to evaluate)."""
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION not in result.patterns_triggered

    def test_starvation_boundary_exactly_at_threshold(self) -> None:
        """Confidence exactly at threshold with few facts -> flagged."""
        d = MiscalibrationDetector(confidence_threshold=0.70, min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1"), _make_fact("f2")])
        arch = _make_message(
            confidence=0.70,
            assertions=[_make_assertion("a1", ("f1", "f2"))],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.70)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION in result.patterns_triggered

    def test_starvation_boundary_exactly_at_fact_count(self) -> None:
        """Cited facts exactly at min_facts_for_confidence -> not flagged."""
        d = MiscalibrationDetector(min_facts_for_confidence=2)
        pkt = _make_packet([_make_fact("f1"), _make_fact("f2")])
        arch = _make_message(
            confidence=0.85,
            assertions=[_make_assertion("a1", ("f1", "f2"))],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION not in result.patterns_triggered

    def test_starvation_deduplicates_fact_ids(self) -> None:
        """Same fact cited by multiple assertions counts once."""
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(
            confidence=0.85,
            assertions=[
                _make_assertion("a1", ("f1",)),
                _make_assertion("a2", ("f1",)),
            ],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_STARVATION in result.patterns_triggered


# ===========================================================================
# Evidence Conflict pattern
# ===========================================================================

class TestEvidenceConflict:
    """Tests for the EVIDENCE_CONFLICT detection pattern."""

    def test_conflict_triggers_on_default_pair(self) -> None:
        """Conflicting fields on same entity -> flagged."""
        d = MiscalibrationDetector()
        facts = [
            _make_fact("f1", entity_id="user-1", field="authentication_success"),
            _make_fact("f2", entity_id="user-1", field="authentication_failure"),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_CONFLICT in result.patterns_triggered

    def test_conflict_no_trigger_different_entities(self) -> None:
        """Conflicting fields on different entities -> not flagged."""
        d = MiscalibrationDetector()
        facts = [
            _make_fact("f1", entity_id="user-1", field="authentication_success"),
            _make_fact("f2", entity_id="user-2", field="authentication_failure"),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_CONFLICT not in result.patterns_triggered

    def test_conflict_no_trigger_low_confidence(self) -> None:
        """Conflicting fields but low confidence -> not flagged."""
        d = MiscalibrationDetector()
        facts = [
            _make_fact("f1", entity_id="user-1", field="authentication_success"),
            _make_fact("f2", entity_id="user-1", field="authentication_failure"),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.50, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.40, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.50)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_CONFLICT not in result.patterns_triggered

    def test_conflict_custom_indicators(self) -> None:
        """Custom conflict pair triggers correctly."""
        d = MiscalibrationDetector(conflict_indicators=(("open", "closed"),))
        facts = [
            _make_fact("f1", entity_id="port-80", field="open"),
            _make_fact("f2", entity_id="port-80", field="closed"),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_CONFLICT in result.patterns_triggered

    def test_conflict_no_trigger_no_conflict_fields(self) -> None:
        """No matching conflict pairs -> not flagged."""
        d = MiscalibrationDetector()
        facts = [
            _make_fact("f1", entity_id="host-1", field="cpu_usage"),
            _make_fact("f2", entity_id="host-1", field="memory_usage"),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.EVIDENCE_CONFLICT not in result.patterns_triggered


# ===========================================================================
# Confidence-Complexity Mismatch pattern
# ===========================================================================

class TestComplexityMismatch:
    """Tests for the CONFIDENCE_COMPLEXITY_MISMATCH pattern."""

    def test_complexity_triggers_many_entity_types(self) -> None:
        """4+ entity types with high confidence -> flagged."""
        d = MiscalibrationDetector(complexity_entity_threshold=2)
        facts = [
            _make_fact("f1", entity_type=EntityType.NODE, source_type=SourceType.SYSLOG),
            _make_fact("f2", entity_type=EntityType.EDGE, source_type=SourceType.SYSLOG),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.CONFIDENCE_COMPLEXITY_MISMATCH in result.patterns_triggered

    def test_complexity_triggers_many_source_types(self) -> None:
        """3+ source types with high confidence -> flagged."""
        d = MiscalibrationDetector(complexity_source_threshold=3)
        facts = [
            _make_fact("f1", source_type=SourceType.SYSLOG),
            _make_fact("f2", entity_id="h2", source_type=SourceType.NETFLOW),
            _make_fact("f3", entity_id="h3", source_type=SourceType.AUTH_LOG),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.CONFIDENCE_COMPLEXITY_MISMATCH in result.patterns_triggered

    def test_complexity_no_trigger_simple_scenario(self) -> None:
        """Single entity type + single source -> not flagged."""
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.CONFIDENCE_COMPLEXITY_MISMATCH not in result.patterns_triggered

    def test_complexity_no_trigger_low_confidence(self) -> None:
        """Complex scenario but low confidence -> not flagged."""
        d = MiscalibrationDetector(complexity_entity_threshold=2)
        facts = [
            _make_fact("f1", entity_type=EntityType.NODE),
            _make_fact("f2", entity_type=EntityType.EDGE),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(confidence=0.50, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.40, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.50)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.CONFIDENCE_COMPLEXITY_MISMATCH not in result.patterns_triggered


# ===========================================================================
# Narrow Spread pattern
# ===========================================================================

class TestNarrowSpread:
    """Tests for the NARROW_SPREAD detection pattern."""

    def test_narrow_spread_triggers(self) -> None:
        """Both agents high confidence, small spread -> flagged."""
        d = MiscalibrationDetector(spread_threshold=0.15, spread_minimum=0.60)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.80)
        skep = _make_message(confidence=0.75, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.80)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.NARROW_SPREAD in result.patterns_triggered

    def test_narrow_spread_no_trigger_wide_spread(self) -> None:
        """Large spread between agents -> not flagged."""
        d = MiscalibrationDetector(spread_threshold=0.15, spread_minimum=0.60)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.90)
        skep = _make_message(confidence=0.30, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.80)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.NARROW_SPREAD not in result.patterns_triggered

    def test_narrow_spread_no_trigger_low_confidence(self) -> None:
        """Small spread but both below minimum -> not flagged."""
        d = MiscalibrationDetector(spread_threshold=0.15, spread_minimum=0.60)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.40)
        skep = _make_message(confidence=0.35, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.40)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.NARROW_SPREAD not in result.patterns_triggered

    def test_narrow_spread_boundary_exactly_at_threshold(self) -> None:
        """Spread exactly at threshold -> flagged (inclusive)."""
        d = MiscalibrationDetector(spread_threshold=0.10, spread_minimum=0.60)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.70)
        skep = _make_message(confidence=0.60, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.70)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.NARROW_SPREAD in result.patterns_triggered

    def test_narrow_spread_one_below_minimum(self) -> None:
        """One agent below minimum -> not flagged."""
        d = MiscalibrationDetector(spread_threshold=0.15, spread_minimum=0.60)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.65)
        skep = _make_message(confidence=0.55, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.65)

        result = d.detect(verdict, arch, skep, pkt)
        assert MiscalibrationPattern.NARROW_SPREAD not in result.patterns_triggered


# ===========================================================================
# Pattern combinations
# ===========================================================================

class TestPatternCombinations:
    """Tests for multiple patterns triggering simultaneously."""

    def test_no_patterns_triggered_clean(self) -> None:
        """Scenario with no issues -> clean pass."""
        d = MiscalibrationDetector(min_facts_for_confidence=2)
        facts = [_make_fact("f1"), _make_fact("f2", entity_id="h2")]
        pkt = _make_packet(facts)
        arch = _make_message(
            confidence=0.85,
            assertions=[_make_assertion("a1", ("f1", "f2"))],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert not result.flagged
        assert result.patterns_triggered == ()
        assert result.risk_score == 0.0
        assert result.recommendation == MiscalibrationRecommendation.PASS

    def test_multiple_patterns_triggered(self) -> None:
        """Scenario triggering starvation + narrow spread."""
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(
            confidence=0.80,
            assertions=[_make_assertion("a1", ("f1",))],
        )
        skep = _make_message(confidence=0.75, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.80)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.flagged
        assert MiscalibrationPattern.EVIDENCE_STARVATION in result.patterns_triggered
        assert MiscalibrationPattern.NARROW_SPREAD in result.patterns_triggered
        assert result.risk_score == 2.0 / 4.0

    def test_all_four_patterns_triggered(self) -> None:
        """Worst-case scenario triggers all four patterns."""
        d = MiscalibrationDetector(
            min_facts_for_confidence=3,
            complexity_entity_threshold=2,
            conflict_indicators=(("auth_ok", "auth_fail"),),
        )
        facts = [
            _make_fact("f1", entity_id="e1", entity_type=EntityType.NODE,
                        field="auth_ok", source_type=SourceType.SYSLOG),
            _make_fact("f2", entity_id="e1", entity_type=EntityType.EDGE,
                        field="auth_fail", source_type=SourceType.NETFLOW),
            _make_fact("f3", entity_id="e2", entity_type=EntityType.NODE,
                        field="data", source_type=SourceType.AUTH_LOG),
        ]
        pkt = _make_packet(facts)
        arch = _make_message(
            confidence=0.80,
            assertions=[_make_assertion("a1", ("f1",))],
        )
        skep = _make_message(confidence=0.75, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.flagged
        assert result.risk_score == 1.0
        assert len(result.patterns_triggered) == 4


# ===========================================================================
# Risk score and recommendation
# ===========================================================================

class TestRiskScoreAndRecommendation:
    """Tests for risk_score calculation and recommendation logic."""

    def test_risk_score_zero_no_patterns(self) -> None:
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact(f"f{i}", entity_id=f"h{i}") for i in range(5)])
        arch = _make_message(
            confidence=0.85,
            assertions=[_make_assertion("a1", ("f0", "f1", "f2", "f3", "f4"))],
        )
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.risk_score == 0.0

    def test_risk_score_quarter_one_pattern(self) -> None:
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.risk_score == 0.25

    def test_recommendation_pass_when_clean(self) -> None:
        d = MiscalibrationDetector(min_facts_for_confidence=1)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.recommendation == MiscalibrationRecommendation.PASS

    def test_recommendation_inspect_when_flagged(self) -> None:
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert result.recommendation == MiscalibrationRecommendation.INSPECT


# ===========================================================================
# Immutability
# ===========================================================================

class TestImmutability:
    """Tests that all output types are frozen."""

    def test_miscalibration_result_frozen(self) -> None:
        result = MiscalibrationResult(
            flagged=True,
            patterns_triggered=(MiscalibrationPattern.EVIDENCE_STARVATION,),
            risk_score=0.25,
            recommendation=MiscalibrationRecommendation.INSPECT,
            details=("test",),
        )
        with pytest.raises(AttributeError):
            result.flagged = False  # type: ignore[misc]

    def test_miscalibration_result_details_is_tuple(self) -> None:
        result = MiscalibrationResult(
            flagged=False,
            patterns_triggered=(),
            risk_score=0.0,
            recommendation=MiscalibrationRecommendation.PASS,
            details=(),
        )
        assert isinstance(result.details, tuple)
        assert isinstance(result.patterns_triggered, tuple)


# ===========================================================================
# Empty / minimal inputs
# ===========================================================================

class TestEdgeCases:
    """Tests for edge cases and minimal inputs."""

    def test_empty_packet_no_crash(self) -> None:
        d = MiscalibrationDetector()
        pkt = _make_packet([])
        arch = _make_message(confidence=0.85, assertions=[])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert isinstance(result, MiscalibrationResult)

    def test_low_confidence_verdict_passes(self) -> None:
        """Low confidence verdict should trigger no confidence-gated patterns."""
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.30, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.25, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.30)

        result = d.detect(verdict, arch, skep, pkt)
        assert not result.flagged

    def test_details_contain_pattern_names(self) -> None:
        """Details strings should name the triggered pattern."""
        d = MiscalibrationDetector(min_facts_for_confidence=3)
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.85, assertions=[_make_assertion("a1", ("f1",))])
        skep = _make_message(confidence=0.20, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.85)

        result = d.detect(verdict, arch, skep, pkt)
        assert any("EVIDENCE_STARVATION" in d for d in result.details)

    def test_detect_returns_correct_type(self) -> None:
        d = MiscalibrationDetector()
        pkt = _make_packet([_make_fact("f1")])
        arch = _make_message(confidence=0.50)
        skep = _make_message(confidence=0.50, source_agent="skeptic")
        verdict = _make_verdict(confidence=0.50)

        result = d.detect(verdict, arch, skep, pkt)
        assert isinstance(result, MiscalibrationResult)
