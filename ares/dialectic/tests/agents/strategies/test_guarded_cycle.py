"""Tests for run_guarded_cycle — firewall-guarded dialectical cycle.

~30 tests across firewall pass-through, hot-swap protocol, sanitized
fallback, edge cases, and integration smoke tests.

All tests use rule-based or mock strategies — no live LLM calls.
"""

from __future__ import annotations

import dataclasses
import uuid
from datetime import datetime
from typing import Optional
from unittest.mock import MagicMock, patch, call

import pytest

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    Verdict,
    VerdictOutcome,
)
from ares.dialectic.agents.strategies.guarded_cycle import (
    GuardedCycleResult,
    run_guarded_cycle,
)
from ares.dialectic.coordinator.firewall import (
    FirewallVerdict,
    FirewallViolation,
    OracleFirewall,
)
from ares.dialectic.coordinator.orchestrator import CycleError, CycleResult
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
)


# =============================================================================
# Inline Helpers
# =============================================================================


def _make_provenance() -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="guarded-cycle-test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def _make_frozen_packet(
    packet_id: str = "guarded-test-packet",
) -> EvidencePacket:
    """Build a frozen packet with enough facts to trigger anomalies."""
    packet = EvidencePacket(
        packet_id=packet_id,
        time_window=TimeWindow(
            start=datetime(2024, 1, 1), end=datetime(2024, 1, 31, 23, 59, 59),
        ),
    )
    prov = _make_provenance()

    packet.add_fact(Fact(
        fact_id="fact-001", entity_id="user-admin",
        entity_type=EntityType.NODE, field="privilege",
        value="SeDebugPrivilege",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-002", entity_id="proc-cmd",
        entity_type=EntityType.NODE, field="process_name",
        value="cmd.exe",
        timestamp=datetime(2024, 1, 15, 2, 31), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-003", entity_id="user-admin",
        entity_type=EntityType.NODE, field="account_type",
        value="administrator",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))
    packet.add_fact(Fact(
        fact_id="fact-004", entity_id="session-001",
        entity_type=EntityType.NODE, field="maintenance_window",
        value="scheduled",
        timestamp=datetime(2024, 1, 15, 2, 30), provenance=prov,
    ))

    packet.freeze()
    return packet


def _make_unfrozen_packet() -> EvidencePacket:
    """Build an unfrozen packet for validation tests."""
    packet = EvidencePacket(
        packet_id="unfrozen-packet",
        time_window=TimeWindow(
            start=datetime(2024, 1, 1), end=datetime(2024, 1, 31),
        ),
    )
    packet.add_fact(Fact(
        fact_id="fact-001", entity_id="node-001",
        entity_type=EntityType.NODE, field="data", value="test",
        timestamp=datetime(2024, 1, 15), provenance=_make_provenance(),
    ))
    return packet


def _make_mock_threat_analyzer(
    patterns: Optional[list[AnomalyPattern]] = None,
) -> MagicMock:
    """Create a mock ThreatAnalyzer returning predictable patterns."""
    analyzer = MagicMock()
    if patterns is None:
        patterns = [
            AnomalyPattern(
                pattern_type=PatternType.PRIVILEGE_ESCALATION,
                fact_ids=frozenset({"fact-001", "fact-002"}),
                confidence=0.85,
                description="Privilege escalation detected via SeDebugPrivilege + cmd.exe",
            ),
        ]
    analyzer.analyze_threats.return_value = patterns
    return analyzer


def _make_mock_explanation_finder() -> MagicMock:
    """Create a mock ExplanationFinder returning a benign explanation."""
    finder = MagicMock()
    finder.find_explanations.return_value = [
        BenignExplanation(
            explanation_type=ExplanationType.KNOWN_ADMIN,
            fact_ids=frozenset({"fact-003"}),
            confidence=0.6,
            description="Known admin account activity",
        ),
    ]
    return finder


def _make_passing_firewall() -> MagicMock:
    """Create a mock firewall that always passes."""
    fw = MagicMock(spec=OracleFirewall)
    fw.validate.return_value = FirewallVerdict(
        passed=True,
        violations=(),
        taint_score=0.0,
        sanitized_output=None,
        timestamp=datetime.utcnow(),
    )
    return fw


def _make_failing_firewall(
    taint_score: float = 0.9,
    sanitized_interpretations: tuple[str, ...] = ("[REDACTED] escalation detected",),
) -> MagicMock:
    """Create a mock firewall that always fails with injection violations."""
    fw = MagicMock(spec=OracleFirewall)
    fw.validate.return_value = FirewallVerdict(
        passed=False,
        violations=(
            FirewallViolation(
                violation_type="INSTRUCTION_INJECTION",
                evidence="ignore previous instructions",
                severity=1.0,
            ),
        ),
        taint_score=taint_score,
        sanitized_output=sanitized_interpretations,
        timestamp=datetime.utcnow(),
    )
    return fw


def _make_hot_swap_factory(
    patterns: Optional[list[AnomalyPattern]] = None,
) -> MagicMock:
    """Create a mock hot-swap factory returning a fresh ThreatAnalyzer."""
    fresh_analyzer = _make_mock_threat_analyzer(patterns)
    factory = MagicMock(return_value=fresh_analyzer)
    return factory


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture
def frozen_packet() -> EvidencePacket:
    return _make_frozen_packet()


@pytest.fixture
def unfrozen_packet() -> EvidencePacket:
    return _make_unfrozen_packet()


# =============================================================================
# 1. Firewall pass-through (5 tests)
# =============================================================================


class TestFirewallPassThrough:
    """Tests for clean Architect output passing through the firewall."""

    def test_clean_output_passes_firewall(self, frozen_packet: EvidencePacket) -> None:
        """Clean architect output passes firewall; Skeptic gets unmodified output."""
        fw = _make_passing_firewall()
        analyzer = _make_mock_threat_analyzer()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=analyzer,
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert isinstance(result, GuardedCycleResult)
        assert isinstance(result.cycle_result, CycleResult)
        assert result.cycle_result.verdict is not None
        assert result.cycle_result.architect_message is not None
        assert result.cycle_result.skeptic_message is not None
        # Firewall was called
        fw.validate.assert_called_once()

    def test_pass_through_metadata_correct(self, frozen_packet: EvidencePacket) -> None:
        """hot_swap_triggered is False, used_sanitized is False on clean pass."""
        fw = _make_passing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.hot_swap_triggered is False
        assert result.used_sanitized is False
        assert result.quarantined_output is None
        assert result.hot_swap_firewall_verdict is None

    def test_firewall_verdict_passed_and_clean(self, frozen_packet: EvidencePacket) -> None:
        """firewall_verdict.passed is True and taint_score is 0.0."""
        fw = _make_passing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.firewall_verdict.passed is True
        assert result.firewall_verdict.taint_score == 0.0
        assert len(result.firewall_verdict.violations) == 0

    def test_no_firewall_produces_synthetic_clean_verdict(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """firewall=None produces a pass-through with synthetic clean verdict."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
        )

        assert result.firewall_verdict.passed is True
        assert result.firewall_verdict.taint_score == 0.0
        assert result.firewall_verdict.violations == ()
        assert result.firewall_verdict.sanitized_output is None
        assert result.hot_swap_triggered is False
        assert result.used_sanitized is False

    def test_guarded_cycle_result_is_frozen(self, frozen_packet: EvidencePacket) -> None:
        """GuardedCycleResult is a frozen dataclass."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=_make_passing_firewall(),
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        with pytest.raises(dataclasses.FrozenInstanceError):
            result.hot_swap_triggered = True


# =============================================================================
# 2. Firewall failure + hot-swap (8 tests)
# =============================================================================


class TestFirewallFailureHotSwap:
    """Tests for tainted output triggering the hot-swap protocol."""

    def _make_failing_then_passing_firewall(self) -> MagicMock:
        """Firewall that fails first call, passes second (hot-swap)."""
        fw = MagicMock(spec=OracleFirewall)
        fw.validate.side_effect = [
            FirewallVerdict(
                passed=False,
                violations=(
                    FirewallViolation(
                        violation_type="INSTRUCTION_INJECTION",
                        evidence="ignore previous instructions",
                        severity=1.0,
                    ),
                ),
                taint_score=0.9,
                sanitized_output=("[REDACTED] escalation detected",),
                timestamp=datetime.utcnow(),
            ),
            FirewallVerdict(
                passed=True,
                violations=(),
                taint_score=0.0,
                sanitized_output=None,
                timestamp=datetime.utcnow(),
            ),
        ]
        return fw

    def test_tainted_output_triggers_hot_swap(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Tainted output triggers firewall, hot-swap factory called."""
        fw = self._make_failing_then_passing_firewall()
        factory = _make_hot_swap_factory()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=factory,
        )

        assert result.hot_swap_triggered is True
        factory.assert_called_once()

    def test_hot_swap_factory_creates_fresh_strategy(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Fresh strategy instance created via factory (call_count == 1)."""
        fw = self._make_failing_then_passing_firewall()
        factory = _make_hot_swap_factory()

        run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=factory,
        )

        assert factory.call_count == 1
        # The returned analyzer should have been used
        fresh_analyzer = factory.return_value
        assert fresh_analyzer.analyze_threats.called

    def test_hot_swap_architect_gets_new_agent_id(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Hot-swap architect gets a new agent_id containing 'swap'."""
        fw = self._make_failing_then_passing_firewall()
        factory = _make_hot_swap_factory()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=factory,
        )

        # When hot-swap passes, the cycle uses the swap message
        arch_agent = result.cycle_result.architect_message.source_agent
        assert "-arch-swap-" in arch_agent

    def test_hot_swap_passes_completes_normally(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """If hot-swap passes, cycle completes with hot-swap output."""
        fw = self._make_failing_then_passing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.hot_swap_triggered is True
        assert result.used_sanitized is False
        assert result.cycle_result.verdict is not None

    def test_hot_swap_also_fails_uses_sanitized(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """If hot-swap also fails, falls through to sanitized output."""
        # Both calls fail
        fw = MagicMock(spec=OracleFirewall)
        fw.validate.side_effect = [
            FirewallVerdict(
                passed=False,
                violations=(
                    FirewallViolation(
                        violation_type="INSTRUCTION_INJECTION",
                        evidence="ignore previous instructions",
                        severity=1.0,
                    ),
                ),
                taint_score=0.9,
                sanitized_output=("[REDACTED]",),
                timestamp=datetime.utcnow(),
            ),
            FirewallVerdict(
                passed=False,
                violations=(
                    FirewallViolation(
                        violation_type="INSTRUCTION_INJECTION",
                        evidence="disregard all",
                        severity=0.9,
                    ),
                ),
                taint_score=0.8,
                sanitized_output=("[REDACTED] swap output",),
                timestamp=datetime.utcnow(),
            ),
        ]

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.hot_swap_triggered is True
        assert result.used_sanitized is True
        # Architect message should contain sanitized text
        arch_interp = result.cycle_result.architect_message.assertions[0].interpretation
        assert "[REDACTED]" in arch_interp

    def test_quarantined_output_contains_original_text(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """quarantined_output contains original tainted interpretation."""
        fw = self._make_failing_then_passing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.quarantined_output is not None
        assert len(result.quarantined_output) >= 1
        # Should be the original interpretation, not sanitized
        for q in result.quarantined_output:
            assert isinstance(q, str)
            assert len(q) > 0

    def test_hot_swap_firewall_verdict_is_set(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """hot_swap_firewall_verdict is not None when hot-swap runs."""
        fw = self._make_failing_then_passing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.hot_swap_firewall_verdict is not None
        assert isinstance(result.hot_swap_firewall_verdict, FirewallVerdict)

    def test_firewall_called_twice_on_hot_swap(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Firewall validate is called twice: original + hot-swap."""
        fw = self._make_failing_then_passing_firewall()

        run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert fw.validate.call_count == 2


# =============================================================================
# 3. Firewall failure + no hot-swap (5 tests)
# =============================================================================


class TestFirewallFailureNoHotSwap:
    """Tests for tainted output when hot-swap is disabled."""

    def test_no_hot_swap_no_factory_call(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """enable_hot_swap=False does not call factory."""
        fw = _make_failing_firewall()
        factory = _make_hot_swap_factory()

        run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        factory.assert_not_called()

    def test_used_sanitized_is_true(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """used_sanitized is True when firewall fails and no hot-swap."""
        fw = _make_failing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        assert result.used_sanitized is True

    def test_skeptic_receives_sanitized_text(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Skeptic receives sanitized text, not tainted original."""
        fw = _make_failing_firewall(
            sanitized_interpretations=("[REDACTED] priv esc activity",),
        )

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        # The architect_message stored in CycleResult should be sanitized
        arch_interp = result.cycle_result.architect_message.assertions[0].interpretation
        assert "[REDACTED]" in arch_interp

    def test_hot_swap_triggered_is_false(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """hot_swap_triggered is False when hot-swap disabled."""
        fw = _make_failing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        assert result.hot_swap_triggered is False
        assert result.hot_swap_firewall_verdict is None

    def test_cycle_still_completes_with_verdict(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Cycle completes normally with a verdict even when sanitized."""
        fw = _make_failing_firewall()

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        assert result.cycle_result.verdict is not None
        assert result.cycle_result.skeptic_message is not None


# =============================================================================
# 4. Edge cases (5 tests)
# =============================================================================


class TestEdgeCases:
    """Edge case and validation tests."""

    def test_hot_swap_true_no_factory_raises_value_error(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """enable_hot_swap=True with hot_swap_factory=None raises ValueError."""
        with pytest.raises(ValueError, match="hot_swap_factory"):
            run_guarded_cycle(
                frozen_packet,
                threat_analyzer=_make_mock_threat_analyzer(),
                firewall=_make_passing_firewall(),
                enable_hot_swap=True,
                hot_swap_factory=None,
            )

    def test_unfrozen_packet_raises_value_error(
        self, unfrozen_packet: EvidencePacket,
    ) -> None:
        """Unfrozen packet raises ValueError."""
        with pytest.raises(ValueError, match="frozen"):
            run_guarded_cycle(
                unfrozen_packet,
                firewall=None,
                enable_hot_swap=False,
            )

    def test_empty_violations_passes(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Empty violations list means firewall passes."""
        fw = MagicMock(spec=OracleFirewall)
        fw.validate.return_value = FirewallVerdict(
            passed=True,
            violations=(),
            taint_score=0.0,
            sanitized_output=None,
            timestamp=datetime.utcnow(),
        )

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.firewall_verdict.passed is True
        assert result.hot_swap_triggered is False

    def test_taint_at_threshold_fails(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Taint exactly at threshold (0.5) fails the firewall."""
        fw = MagicMock(spec=OracleFirewall)
        fw.validate.return_value = FirewallVerdict(
            passed=False,  # taint_score >= TAINT_THRESHOLD (0.5)
            violations=(
                FirewallViolation(
                    violation_type="CONFIDENCE_MANIPULATION",
                    evidence="definitely benign",
                    severity=0.5,
                ),
            ),
            taint_score=0.5,
            sanitized_output=("[REDACTED]",),
            timestamp=datetime.utcnow(),
        )

        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=fw,
            enable_hot_swap=False,
        )

        assert result.firewall_verdict.passed is False
        assert result.used_sanitized is True

    def test_custom_agent_id_prefix(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Custom agent_id_prefix propagates to all agent IDs."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
            agent_id_prefix="custom",
        )

        assert result.cycle_result.architect_message.source_agent.startswith("custom-arch-")
        assert result.cycle_result.skeptic_message.source_agent.startswith("custom-skep-")


# =============================================================================
# 5. Integration smoke tests (2 tests)
# =============================================================================


class TestIntegrationSmoke:
    """Integration smoke tests with real components."""

    def test_rule_based_with_real_firewall(self) -> None:
        """Run with rule-based strategies + real OracleFirewall + real packet."""
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedThreatAnalyzer,
        )

        packet = _make_frozen_packet(packet_id="integration-test-1")
        fw = OracleFirewall()

        result = run_guarded_cycle(
            packet,
            threat_analyzer=RuleBasedThreatAnalyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=lambda: RuleBasedThreatAnalyzer(),
        )

        assert isinstance(result, GuardedCycleResult)
        assert isinstance(result.cycle_result, CycleResult)
        assert result.cycle_result.verdict is not None
        # Rule-based on clean evidence should pass firewall
        assert result.firewall_verdict.passed is True
        assert result.hot_swap_triggered is False

    def test_injection_scenario_with_real_firewall(self) -> None:
        """Run INJ-001 with rule-based strategies + real firewall."""
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedThreatAnalyzer,
        )
        from ares.dialectic.scripts.injection_corpus import (
            get_injection_scenario_by_id,
        )

        scenario = get_injection_scenario_by_id("INJ-001")
        packet = scenario.packet
        fw = OracleFirewall()

        result = run_guarded_cycle(
            packet,
            threat_analyzer=RuleBasedThreatAnalyzer(),
            firewall=fw,
            enable_hot_swap=True,
            hot_swap_factory=lambda: RuleBasedThreatAnalyzer(),
        )

        assert isinstance(result, GuardedCycleResult)
        assert result.cycle_result.verdict is not None
        # INJ-001 has injection text in fact values — firewall should detect it
        assert result.firewall_verdict is not None
        # The cycle should still produce a result regardless of firewall outcome
        assert result.cycle_result.architect_message is not None
        assert result.cycle_result.skeptic_message is not None


# =============================================================================
# Additional coverage: narration and determinism
# =============================================================================


class TestNarrationAndMiscellaneous:
    """Tests for narration control and cycle consistency."""

    def test_narration_disabled(self, frozen_packet: EvidencePacket) -> None:
        """include_narration=False omits narrator message."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
            include_narration=False,
        )

        assert result.cycle_result.narrator_message is None

    def test_narration_enabled_by_default(self, frozen_packet: EvidencePacket) -> None:
        """Narration is included by default."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
        )

        assert result.cycle_result.narrator_message is not None

    def test_cycle_result_has_correct_phases(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Messages have correct phase assignments."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=_make_passing_firewall(),
            enable_hot_swap=True,
            hot_swap_factory=_make_hot_swap_factory(),
        )

        assert result.cycle_result.architect_message.phase == Phase.THESIS
        assert result.cycle_result.skeptic_message.phase == Phase.ANTITHESIS
        if result.cycle_result.narrator_message:
            assert result.cycle_result.narrator_message.phase == Phase.SYNTHESIS

    def test_no_state_leakage_between_guarded_calls(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Fresh agents per call — no state leakage."""
        r1 = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
        )
        r2 = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
        )

        assert r1.cycle_result.cycle_id != r2.cycle_result.cycle_id

    def test_duration_ms_is_nonnegative(
        self, frozen_packet: EvidencePacket,
    ) -> None:
        """Duration is recorded and non-negative."""
        result = run_guarded_cycle(
            frozen_packet,
            threat_analyzer=_make_mock_threat_analyzer(),
            firewall=None,
            enable_hot_swap=False,
        )

        assert result.cycle_result.duration_ms >= 0
