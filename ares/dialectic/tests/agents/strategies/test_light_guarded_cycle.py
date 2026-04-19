"""Tests for light_guarded_cycle — deterministic Light Skeptic cycle.

Covers:
    * Firewall still runs and produces a verdict.
    * Skeptic LLM strategy (ExplanationFinder) is NOT invoked.
    * Light Skeptic judgment is attached to the result.
    * Skeptic message carries the judgment's confidence.
    * pipeline_variant = "light".
    * End-to-end runs on the 3 acceptance-gate scenarios.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from ares.dialectic.agents.strategies.light_guarded_cycle import (
    PIPELINE_VARIANT_LABEL,
    LightGuardedCycleResult,
    build_skeptic_message_from_judgment,
    run_light_guarded_cycle,
)
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.messages.protocol import MessageType, Phase
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment
from ares.dialectic.scripts.injection_corpus import get_injection_scenario_by_id
from ares.dialectic.scripts.injection_corpus_b_framing import (
    get_framing_scenario_by_id,
)
from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id


class _SkepticTrap:
    """ExplanationFinder trap — fails the test if invoked."""

    def __init__(self):
        self.calls = 0

    def find_explanations(self, architect_msg, packet):
        self.calls += 1
        raise AssertionError(
            "Skeptic ExplanationFinder must NOT be invoked in light cycle"
        )


class TestPipelineVariantLabel:
    def test_constant_is_light(self):
        assert PIPELINE_VARIANT_LABEL == "light"

    def test_result_carries_label(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert r.pipeline_variant == "light"


class TestResultShape:
    def test_is_frozen(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert isinstance(r, LightGuardedCycleResult)
        with pytest.raises(FrozenInstanceError):
            r.pipeline_variant = "other"  # type: ignore[misc]

    def test_exposes_light_judgment(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert isinstance(r.light_judgment, LightSkepticJudgment)

    def test_exposes_firewall_verdict(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert r.firewall_verdict is not None

    def test_cycle_id_prefixed_with_light(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert r.cycle_result.cycle_id.startswith("cycle-light-")


class TestFirewallRuns:
    def test_firewall_produces_verdict(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        # INJ-001 is a direct-injection scenario; firewall typically flags it.
        assert r.firewall_verdict is not None
        assert 0.0 <= r.firewall_verdict.taint_score <= 1.0

    def test_none_firewall_produces_pass_through(self):
        scenario = get_scenario_by_id("SC-001")
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=None, include_narration=False,
        )
        assert r.firewall_verdict.passed is True
        assert r.used_sanitized is False


class TestSkepticNotInvoked:
    def test_explanation_finder_not_called(self):
        # We construct a trap-style explanation_finder and smuggle it
        # through... but light_guarded_cycle's signature does not accept
        # an explanation_finder. The absence of that parameter is itself
        # the contract. We verify the judgment is the Light Skeptic's.
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        # Skeptic message source is the light-skeptic constant, not any LLM.
        assert r.cycle_result.skeptic_message.source_agent == "ares-skep-light"


class TestJudgmentFlowsToOracle:
    def test_skeptic_confidence_matches_judgment(self):
        scenario = get_injection_scenario_by_id("INJ-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        verdict = r.cycle_result.verdict
        assert verdict.skeptic_confidence == pytest.approx(r.light_judgment.confidence)

    def test_skeptic_message_narrative_references_rules(self):
        scenario = get_scenario_by_id("SC-001")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        narrative = r.cycle_result.skeptic_message.narrative or ""
        for rule in r.light_judgment.triggered_rules:
            assert rule in narrative


class TestAcceptanceGatesEndToEnd:
    def test_inj_014_threat_dismissed(self):
        scenario = get_framing_scenario_by_id("INJ-014")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        # With rule-based Architect + light Skeptic, INJ-014 should dismiss.
        assert r.cycle_result.verdict.outcome.value.upper() == "THREAT_DISMISSED"

    def test_inj_020_threat_dismissed(self):
        scenario = get_framing_scenario_by_id("INJ-020")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        assert r.cycle_result.verdict.outcome.value.upper() == "THREAT_DISMISSED"

    def test_inj_006_inconclusive(self):
        scenario = get_injection_scenario_by_id("INJ-006")
        firewall = OracleFirewall()
        r = run_light_guarded_cycle(
            packet=scenario.packet, firewall=firewall, include_narration=False,
        )
        # Not THREAT_DISMISSED — light Skeptic must not over-dismiss this.
        assert (
            r.cycle_result.verdict.outcome.value.upper() != "THREAT_DISMISSED"
        )


class TestBuildSkepticMessageFromJudgment:
    def test_confidence_copied(self):
        judgment = LightSkepticJudgment(
            confidence=0.82,
            rationale=("rule_one: ok",),
            triggered_rules=("rule_one",),
            benign_score=0.3,
            malign_score=0.0,
        )
        msg = build_skeptic_message_from_judgment(
            judgment, cycle_id="c-1", packet_id="p-1",
        )
        assert msg.confidence == 0.82

    def test_no_assertions(self):
        judgment = LightSkepticJudgment(
            confidence=0.5, rationale=("x",),
            triggered_rules=("x",), benign_score=0.0, malign_score=0.0,
        )
        msg = build_skeptic_message_from_judgment(
            judgment, cycle_id="c-1", packet_id="p-1",
        )
        assert len(msg.assertions) == 0

    def test_type_is_rebuttal(self):
        judgment = LightSkepticJudgment(
            confidence=0.5, rationale=("x",),
            triggered_rules=("x",), benign_score=0.0, malign_score=0.0,
        )
        msg = build_skeptic_message_from_judgment(
            judgment, cycle_id="c-1", packet_id="p-1",
        )
        assert msg.message_type == MessageType.REBUTTAL

    def test_phase_is_antithesis(self):
        judgment = LightSkepticJudgment(
            confidence=0.5, rationale=("x",),
            triggered_rules=("x",), benign_score=0.0, malign_score=0.0,
        )
        msg = build_skeptic_message_from_judgment(
            judgment, cycle_id="c-1", packet_id="p-1",
        )
        assert msg.phase == Phase.ANTITHESIS

    def test_narrative_includes_rules(self):
        judgment = LightSkepticJudgment(
            confidence=0.7,
            rationale=("r1: y",),
            triggered_rules=("rule_a", "rule_b"),
            benign_score=0.2,
            malign_score=0.0,
        )
        msg = build_skeptic_message_from_judgment(
            judgment, cycle_id="c-1", packet_id="p-1",
        )
        assert "rule_a" in (msg.narrative or "")
        assert "rule_b" in (msg.narrative or "")


class TestRequiresFrozenPacket:
    def test_unfrozen_raises(self):
        unfrozen = EvidencePacket(
            packet_id="unfrozen",
            time_window=TimeWindow(
                start=datetime(2026, 1, 1),
                end=datetime(2026, 1, 2),
            ),
        )
        with pytest.raises(ValueError, match="frozen"):
            run_light_guarded_cycle(packet=unfrozen, include_narration=False)
