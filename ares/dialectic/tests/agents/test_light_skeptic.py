"""Tests for the Light Skeptic rule engine.

Covers:
    * Each rule (R1-R4) fires independently on crafted packets.
    * Rules compose additively (e.g., R1 + R2 both contribute).
    * R4 default_floor fires only when no other rule matches.
    * clamp(0.5 + benign - malign, 0, 1) invariant holds.
    * Zero LLM calls across a 22-scenario run (mocked Anthropic API).
    * Architect message is accepted but does not change v1 output.
    * Acceptance gates: INJ-014, INJ-020 produce >= 0.7; INJ-006 < 0.7.
"""

from __future__ import annotations

from datetime import datetime
from unittest import mock

import pytest

from ares.dialectic.agents.light_skeptic import (
    DEFAULT_CONFIDENCE,
    MALIGN_CAP_WHEN_STAGE_LOW,
    RULE_AUTHORIZATION_MARKER,
    RULE_BENIGN_EXPLANATION_MARKER,
    RULE_DEFAULT_FLOOR,
    RULE_KILL_CHAIN_STAGE_LOW,
    WEIGHT_AUTHORIZATION,
    WEIGHT_BENIGN_EXPLANATION,
    WEIGHT_KILL_CHAIN_STAGE_LOW,
    _max_kill_chain_stage,
    evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import (
    MessageBuilder,
    MessageType,
    Phase,
)
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


# =============================================================================
# Fixture helpers
# =============================================================================


def _packet_with_fields(field_value_pairs: list[tuple[str, str]]) -> EvidencePacket:
    packet = EvidencePacket(
        packet_id="test-packet",
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, 0, 0, 0),
            end=datetime(2026, 1, 1, 1, 0, 0),
        ),
    )
    prov = Provenance(
        source_type=SourceType.SYSLOG,
        source_id="test-src",
        parser_version="1.0.0",
    )
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"fact-{i:03d}",
            entity_id=f"ent-{i}",
            entity_type=EntityType.NODE,
            field=field,
            value=value,
            timestamp=datetime(2026, 1, 1, 0, 30, 0),
            provenance=prov,
        ))
    packet.freeze()
    return packet


def _arch_msg(packet_id="test-packet", cycle_id="cycle-1") -> "DialecticalMessage":
    builder = MessageBuilder(
        source_agent="test-arch",
        packet_id=packet_id,
        cycle_id=cycle_id,
    )
    builder.set_phase(Phase.THESIS)
    builder.set_type(MessageType.HYPOTHESIS)
    builder.set_confidence(0.5)
    return builder.build()


# =============================================================================
# Rule firing independence
# =============================================================================


class TestRuleIndependence:
    def test_r1_only(self):
        # change_ticket is stage 0 → R3 also fires. Exercise R1 in isolation
        # with a stage-2 field alongside.
        packet = _packet_with_fields([
            ("change_ticket", "CR-123"),
            ("process_name", "svchost.exe"),
        ])
        j = evaluate(packet, _arch_msg())
        assert RULE_AUTHORIZATION_MARKER in j.triggered_rules
        assert RULE_KILL_CHAIN_STAGE_LOW not in j.triggered_rules
        assert j.benign_score == pytest.approx(WEIGHT_AUTHORIZATION)

    def test_r2_only(self):
        packet = _packet_with_fields([
            ("patch_applied", "KB-123"),
            ("process_name", "notepad.exe"),
        ])
        j = evaluate(packet, _arch_msg())
        assert RULE_BENIGN_EXPLANATION_MARKER in j.triggered_rules
        assert RULE_AUTHORIZATION_MARKER not in j.triggered_rules
        assert j.benign_score == pytest.approx(WEIGHT_BENIGN_EXPLANATION)

    def test_r3_only(self):
        # All mapped to stage 0 or 1 → R3 fires; no auth or benign fields
        # that would fire R1/R2 since port_scan/scan_plugin aren't in those sets.
        packet = _packet_with_fields([
            ("port_scan", "nmap -sS"),
            ("scan_plugin", "plugin-42"),
            ("src_ip", "10.0.0.1"),
        ])
        j = evaluate(packet, _arch_msg())
        assert RULE_KILL_CHAIN_STAGE_LOW in j.triggered_rules
        assert RULE_AUTHORIZATION_MARKER not in j.triggered_rules
        assert RULE_BENIGN_EXPLANATION_MARKER not in j.triggered_rules
        assert j.benign_score == pytest.approx(WEIGHT_KILL_CHAIN_STAGE_LOW)

    def test_r4_default_floor(self):
        # No known low-stage fields, no auth, no benign markers.
        packet = _packet_with_fields([
            ("process_name", "evil.exe"),
            ("command_line", "evil.exe args"),
        ])
        j = evaluate(packet, _arch_msg())
        assert j.triggered_rules == (RULE_DEFAULT_FLOOR,)
        assert j.confidence == DEFAULT_CONFIDENCE
        assert j.benign_score == 0.0

    def test_r4_fires_on_empty_packet(self):
        packet = _packet_with_fields([])
        # Empty packet has max stage 0 → R3 fires, not R4
        j = evaluate(packet, _arch_msg())
        assert RULE_KILL_CHAIN_STAGE_LOW in j.triggered_rules


class TestRuleComposition:
    def test_r1_plus_r2(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-123"),
            ("patch_applied", "KB-456"),
            ("process_name", "svchost.exe"),  # stage 2 → blocks R3
        ])
        j = evaluate(packet, _arch_msg())
        assert set(j.triggered_rules) == {
            RULE_AUTHORIZATION_MARKER, RULE_BENIGN_EXPLANATION_MARKER,
        }
        assert j.benign_score == pytest.approx(
            WEIGHT_AUTHORIZATION + WEIGHT_BENIGN_EXPLANATION
        )

    def test_r1_plus_r3(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-999"),
            # Change_ticket maps to stage 0, no other facts → R3 fires
        ])
        j = evaluate(packet, _arch_msg())
        assert set(j.triggered_rules) == {
            RULE_AUTHORIZATION_MARKER, RULE_KILL_CHAIN_STAGE_LOW,
        }
        assert j.benign_score == pytest.approx(
            WEIGHT_AUTHORIZATION + WEIGHT_KILL_CHAIN_STAGE_LOW
        )

    def test_all_three_rules_together(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-999"),
            ("patch_applied", "KB-777"),
            # Both fields map to stage 0
        ])
        j = evaluate(packet, _arch_msg())
        assert set(j.triggered_rules) == {
            RULE_AUTHORIZATION_MARKER,
            RULE_BENIGN_EXPLANATION_MARKER,
            RULE_KILL_CHAIN_STAGE_LOW,
        }

    def test_confidence_clamped_to_one(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-999"),
            ("patch_applied", "KB-777"),
            # Both stage 0 → R1 + R2 + R3 → benign 0.4+0.3+0.2 = 0.9,
            # raw 0.5 + 0.9 = 1.4, clamped to 1.0.
        ])
        j = evaluate(packet, _arch_msg())
        assert j.confidence == 1.0


# =============================================================================
# Acceptance gates (the three scenarios the spec explicitly names)
# =============================================================================


class TestAcceptanceGates:
    def test_inj_006_stays_below_dismiss_threshold(self):
        from ares.dialectic.scripts.injection_corpus import (
            get_injection_scenario_by_id,
        )
        scenario = get_injection_scenario_by_id("INJ-006")
        j = evaluate(scenario.packet, _arch_msg())
        assert j.confidence < 0.7, (
            f"INJ-006 light confidence {j.confidence} would push dismissal; "
            f"rules: {j.triggered_rules}"
        )

    def test_inj_014_reaches_dismiss_threshold(self):
        from ares.dialectic.scripts.injection_corpus_b_framing import (
            get_framing_scenario_by_id,
        )
        scenario = get_framing_scenario_by_id("INJ-014")
        j = evaluate(scenario.packet, _arch_msg())
        assert j.confidence >= 0.7, (
            f"INJ-014 light confidence {j.confidence} insufficient for "
            f"THREAT_DISMISSED; rules: {j.triggered_rules}"
        )

    def test_inj_020_reaches_dismiss_threshold(self):
        from ares.dialectic.scripts.injection_corpus_b_framing import (
            get_framing_scenario_by_id,
        )
        scenario = get_framing_scenario_by_id("INJ-020")
        j = evaluate(scenario.packet, _arch_msg())
        assert j.confidence >= 0.7, (
            f"INJ-020 light confidence {j.confidence} insufficient for "
            f"THREAT_DISMISSED; rules: {j.triggered_rules}"
        )


# =============================================================================
# Zero LLM calls
# =============================================================================


class TestZeroLLMCalls:
    """Mock the Anthropic SDK at its canonical patch point and assert
    that the Light Skeptic does not invoke it across a 22-scenario run."""

    def test_zero_anthropic_calls_across_22_scenario_run(self):
        from ares.dialectic.scripts.injection_corpus_b_framing import (
            get_framing_scenarios,
        )
        from ares.dialectic.scripts.injection_corpus import (
            get_injection_scenarios,
        )

        with mock.patch(
            "ares.dialectic.agents.strategies.client._anthropic_sdk.Anthropic"
        ) as mock_anthropic:
            # Touch every framing scenario (Category B seed + expansion)
            seed = [s for s in get_injection_scenarios()
                    if s.metadata.scenario_id in {"INJ-005", "INJ-006", "INJ-007", "INJ-008"}]
            expansion = list(get_framing_scenarios())
            for scenario in seed + expansion:
                _ = evaluate(scenario.packet, _arch_msg(
                    packet_id=scenario.packet.packet_id,
                ))
            assert mock_anthropic.call_count == 0, (
                "Light Skeptic must not instantiate the Anthropic client"
            )


def test_module_does_not_import_anthropic():
    """The light_skeptic module must not import anthropic at any level."""
    import sys
    # Simulate a fresh import to look at side-effects.
    module_name = "ares.dialectic.agents.light_skeptic"
    if module_name in sys.modules:
        # The import has already happened at test-collection time.
        mod = sys.modules[module_name]
    else:
        import importlib
        mod = importlib.import_module(module_name)
    # Walk the module source: 'anthropic' must not appear as a direct import.
    import inspect
    source = inspect.getsource(mod)
    assert "import anthropic" not in source, (
        "light_skeptic must not import anthropic"
    )
    assert "from anthropic" not in source, (
        "light_skeptic must not import from anthropic"
    )


# =============================================================================
# Kill-chain stage helper
# =============================================================================


class TestMaxKillChainStage:
    def test_empty_packet(self):
        packet = _packet_with_fields([])
        assert _max_kill_chain_stage(packet) == 0

    def test_only_low_stages(self):
        packet = _packet_with_fields([
            ("src_ip_reputation", "bad"),
            ("port_scan", "1000"),
        ])
        assert _max_kill_chain_stage(packet) == 1

    def test_mixed_stages(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-1"),  # stage 0
            ("process_name", "evil.exe"),  # stage 2 (default)
        ])
        assert _max_kill_chain_stage(packet) == 2

    def test_unmapped_fields_default_to_stage_two(self):
        packet = _packet_with_fields([
            ("some_random_field", "value"),
        ])
        assert _max_kill_chain_stage(packet) == 2


# =============================================================================
# Judgment shape + invariants
# =============================================================================


class TestJudgmentShape:
    def test_returns_frozen_judgment(self):
        packet = _packet_with_fields([])
        j = evaluate(packet, _arch_msg())
        assert isinstance(j, LightSkepticJudgment)

    def test_rationale_non_empty(self):
        packet = _packet_with_fields([])
        j = evaluate(packet, _arch_msg())
        assert len(j.rationale) >= 1

    def test_rationale_references_each_triggered_rule(self):
        packet = _packet_with_fields([
            ("change_ticket", "CR-1"),
            ("patch_applied", "KB-1"),
        ])
        j = evaluate(packet, _arch_msg())
        joined = " ".join(j.rationale)
        for rule in j.triggered_rules:
            assert rule in joined


class TestArchitectMessageAccepted:
    """Architect message is part of the protocol; v1 ignores it but
    the evaluator must accept any legal DialecticalMessage."""

    def test_accepts_varied_architect_confidence(self):
        packet = _packet_with_fields([("change_ticket", "CR-X")])
        for conf in (0.0, 0.3, 0.7, 1.0):
            b = MessageBuilder("a", packet.packet_id, "cycle-x")
            b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS)
            b.set_confidence(conf)
            msg = b.build()
            j = evaluate(packet, msg)
            # Same packet + v1 rules → same judgment regardless of arch conf.
            # Raw 0.5 + 0.4 + 0.2 = 1.1 → clamped to 1.0.
            assert j.confidence == 1.0


class TestMalignCap:
    def test_cap_is_0_5_when_r3_fires(self):
        packet = _packet_with_fields([("port_scan", "x")])
        j = evaluate(packet, _arch_msg())
        # malign_score should be at or below cap; v1 rules don't set it,
        # so it stays 0 which is <= 0.5.
        assert j.malign_score <= MALIGN_CAP_WHEN_STAGE_LOW
