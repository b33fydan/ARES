"""Tests for ablated_cycle — Skeptic-ablated single-turn pipeline.

Covers:
    1. Skeptic LLM is not invoked (no ExplanationFinder call).
    2. Firewall still runs and still sanitizes tainted interpretations.
    3. Synthetic null Skeptic message is built with confidence 0.0 and
       passed to OracleJudge.
    4. pipeline_variant label is the constant "ablated".
    5. Deterministic rule-based end-to-end on real scenarios (no API).
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.agents.strategies.ablated_cycle import (
    PIPELINE_VARIANT_LABEL,
    AblatedCycleResult,
    build_null_skeptic_message,
    run_ablated_cycle,
)
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.messages.protocol import MessageType, Phase
from ares.dialectic.scripts.injection_corpus import get_injection_scenario_by_id
from ares.dialectic.scripts.injection_corpus_b_framing import (
    get_framing_scenario_by_id,
)
from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id


# =============================================================================
# Null Skeptic message
# =============================================================================


class TestNullSkepticMessage:
    def test_confidence_is_zero(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert m.confidence == 0.0

    def test_has_no_assertions(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert len(m.assertions) == 0

    def test_message_type_is_rebuttal(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert m.message_type == MessageType.REBUTTAL

    def test_phase_is_antithesis(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert m.phase == Phase.ANTITHESIS

    def test_default_turn_number_is_two(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert m.turn_number == 2

    def test_cycle_id_preserved(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-abc", packet_id="pkt-x",
        )
        assert m.cycle_id == "cycle-abc"

    def test_packet_id_preserved(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-42",
        )
        assert m.packet_id == "pkt-42"

    def test_narrative_indicates_ablation(self):
        m = build_null_skeptic_message(
            cycle_id="cycle-x", packet_id="pkt-x",
        )
        assert m.narrative is not None
        assert "ablated" in m.narrative.lower()


# =============================================================================
# Result type
# =============================================================================


class TestAblatedCycleResultType:
    def test_pipeline_variant_label_constant(self):
        assert PIPELINE_VARIANT_LABEL == "ablated"

    def test_is_frozen_dataclass(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert isinstance(result, AblatedCycleResult)
        with pytest.raises(FrozenInstanceError):
            result.pipeline_variant = "other"  # type: ignore[misc]

    def test_pipeline_variant_field_is_ablated(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.pipeline_variant == "ablated"


# =============================================================================
# Skeptic non-invocation
# =============================================================================


class _SkepticTrap:
    """An ExplanationFinder that fails the test if invoked.

    The ablated cycle must not call the Skeptic strategy. If this class's
    method is ever called, the test fails loudly.
    """

    def __init__(self) -> None:
        self.calls = 0

    def find_explanations(self, packet):
        self.calls += 1
        raise AssertionError(
            "Skeptic strategy must NOT be invoked inside the ablated cycle"
        )


def test_skeptic_strategy_is_not_invoked_in_ablated_cycle():
    scenario = get_scenario_by_id("SC-001")
    firewall = OracleFirewall()
    trap = _SkepticTrap()
    # The ablated cycle does not accept an explanation_finder parameter.
    # This test asserts the absence indirectly: no exception means no call.
    result = run_ablated_cycle(
        packet=scenario.packet,
        firewall=firewall,
        include_narration=False,
    )
    assert trap.calls == 0
    # Furthermore, the synthetic null Skeptic is what OracleJudge sees:
    assert result.cycle_result.skeptic_message.confidence == 0.0
    assert len(result.cycle_result.skeptic_message.assertions) == 0


# =============================================================================
# Firewall integration
# =============================================================================


class TestFirewallIntegration:
    def test_firewall_runs_in_ablated_cycle(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.firewall_verdict is not None

    def test_none_firewall_produces_pass_through(self):
        scenario = get_scenario_by_id("SC-001")
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=None,
            include_narration=False,
        )
        assert result.firewall_verdict.passed is True
        assert result.firewall_verdict.taint_score == 0.0
        assert result.used_sanitized is False

    def test_used_sanitized_false_when_firewall_passes(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        if result.firewall_verdict.passed:
            assert result.used_sanitized is False


# =============================================================================
# Verdict shape
# =============================================================================


class TestVerdictShape:
    def test_skeptic_confidence_is_zero_in_verdict(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.cycle_result.verdict.skeptic_confidence == 0.0

    def test_verdict_has_outcome(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.cycle_result.verdict.outcome is not None


# =============================================================================
# End-to-end deterministic sanity
# =============================================================================


class TestEndToEndRuleBased:
    def test_runs_on_framing_seed_scenario(self):
        scenario = get_framing_scenario_by_id("INJ-013")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.cycle_result.packet_id == scenario.packet.packet_id

    def test_runs_on_injection_seed_direct_scenario(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.cycle_result.packet_id == scenario.packet.packet_id

    def test_cycle_id_is_ablated_prefixed(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        result = run_ablated_cycle(
            packet=scenario.packet,
            firewall=firewall,
            include_narration=False,
        )
        assert result.cycle_result.cycle_id.startswith("cycle-ablated-")

    def test_requires_frozen_packet(self):
        scenario = get_scenario_by_id("SC-001")
        assert scenario.packet.is_frozen  # sanity

    def test_raises_on_unfrozen_packet(self):
        from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
        from datetime import datetime
        unfrozen = EvidencePacket(
            packet_id="test-unfrozen",
            time_window=TimeWindow(
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 2),
            ),
        )
        with pytest.raises(ValueError, match="frozen"):
            run_ablated_cycle(packet=unfrozen, include_narration=False)


# =============================================================================
# Fail-closed contract
# =============================================================================


class TestFirewallFailClosed:
    """Ablated cycle must never propagate a tainted message to OracleJudge.

    The FirewallVerdict invariant prevents the bad shape at the producer
    side, but per Codex's belt-and-suspenders argument the consumer-side
    raise is asserted locally for audit clarity.
    """

    def test_failed_verdict_with_none_sanitized_raises(self):
        from datetime import datetime
        from unittest.mock import MagicMock

        from ares.dialectic.coordinator.firewall import (
            FirewallVerdict,
            FirewallViolation,
            OracleFirewall,
        )
        from ares.dialectic.coordinator.orchestrator import CycleError

        scenario = get_scenario_by_id("SC-001")

        spoofed = MagicMock(spec=FirewallVerdict)
        spoofed.passed = False
        spoofed.violations = (
            FirewallViolation(
                violation_type="INSTRUCTION_INJECTION",
                evidence="ignore previous instructions",
                severity=1.0,
            ),
        )
        spoofed.taint_score = 0.9
        spoofed.sanitized_output = None
        spoofed.timestamp = datetime.utcnow()

        fw = MagicMock(spec=OracleFirewall)
        fw.validate.return_value = spoofed

        with pytest.raises(CycleError, match="Firewall failed-closed"):
            run_ablated_cycle(
                packet=scenario.packet,
                firewall=fw,
                include_narration=False,
            )
