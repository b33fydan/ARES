# tests/dialectic/measurement/test_read_depth_evasion_operators.py
"""Tests for the lexical-evasion operators."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_canonical import (
    evaluate as canonical_evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.measurement.read_depth_evasion_operators import (
    EVASION_OPERATORS,
    exe_to_binary_transform,
    temp_to_temporary_transform,
)
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
import pytest
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator,
    SkeletonInvariantError,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


def _scenario(field_value_pairs, sid="T-001"):
    packet = EvidencePacket(
        packet_id=sid, time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.PROCESS_LIST, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"{sid}-fact-{i:03d}", entity_id=f"e-{i}",
            entity_type=EntityType.NODE, field=field, value=value,
            timestamp=datetime(2026, 1, 1, 0, 30), provenance=prov))
    packet.freeze()
    meta = ScenarioMetadata(
        scenario_id=sid, name="t", description="t", mitre_attack_ids=("T1003",),
        mitre_tactic="x", difficulty_tier=3, expected_verdict="THREAT_CONFIRMED",
        expected_winner="ARCHITECT", fact_count=len(field_value_pairs), notes="t")
    return BenchmarkScenario(metadata=meta, packet=packet)


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _value_of(scenario, fact_id):
    return scenario.packet.get_fact(fact_id).value


def test_exe_to_binary_rewrites_extension():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    out = exe_to_binary_transform(s, 0)
    assert ".exe" not in _value_of(out, "T-001-fact-000")
    assert "binary" in _value_of(out, "T-001-fact-000")


def test_temp_to_temporary_rewrites_word():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    out = temp_to_temporary_transform(s, 0)
    assert "Temporary" in _value_of(out, "T-001-fact-000") or \
        "temporary" in _value_of(out, "T-001-fact-000").lower()


def test_evasion_flips_lexical_but_canonical_recovers():
    # An exe-path-only malign scenario (no credential-tool token).
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    # Baseline: both tiers fire.
    assert lexical_evaluate(s.packet, _arch()).malign_score > 0
    assert canonical_evaluate(s.packet, _arch()).malign_score > 0
    # After exe->binary: tier 2 (literal) misses, tier 3 (canonical) recovers.
    evaded = exe_to_binary_transform(s, 0)
    assert lexical_evaluate(evaded.packet, _arch()).malign_score == 0
    assert canonical_evaluate(evaded.packet, _arch()).malign_score > 0


def test_operators_are_skeleton_invariant_via_mutator():
    s = _scenario([("process_name", "C:\\Temp\\update.exe")])
    mut = PairedScenarioMutator(operators=EVASION_OPERATORS, seed=0)
    pair = mut.mutate(s, "exe_to_binary_v1")  # must not raise
    assert pair.mutation_record  # at least one fact value changed (skeleton held)


def test_noop_when_token_absent_raises_via_mutator():
    s = _scenario([("normal_login", "user signed in at 09:00")])
    mut = PairedScenarioMutator(operators=EVASION_OPERATORS, seed=0)
    with pytest.raises(SkeletonInvariantError):
        mut.mutate(s, "exe_to_binary_v1")  # no ".exe" => no-op => rejected


def test_registry_names_unique_and_synonym_family():
    names = [op.operator_name for op in EVASION_OPERATORS]
    assert len(set(names)) == len(names)
    assert all(op.family == "synonym" for op in EVASION_OPERATORS)
