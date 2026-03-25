"""Tests for expanded benchmark scenarios (SC-019 through SC-033).

Session 021: Validates all 15 new scenarios + combined 33-scenario corpus.
Mirrors the structure of test_scenario_corpus.py and test_mixed_source_scenarios.py.
"""

from __future__ import annotations

import pytest

from ares.dialectic.coordinator.orchestrator import DialecticalOrchestrator
from ares.dialectic.evidence.provenance import SourceType
from ares.dialectic.scripts.expanded_scenarios import (
    get_expanded_scenario_by_id,
    get_expanded_scenarios,
    get_full_corpus,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# ------------------------------------------------------------------
# Corpus Integrity
# ------------------------------------------------------------------


class TestCorpusIntegrity:
    """Expanded corpus has correct structure and size."""

    def test_expanded_corpus_has_fifteen_scenarios(self):
        scenarios = get_expanded_scenarios()
        assert len(scenarios) == 15

    def test_full_corpus_has_thirty_three_scenarios(self):
        corpus = get_full_corpus()
        assert len(corpus) == 33

    def test_all_expanded_scenarios_are_benchmark_type(self):
        for s in get_expanded_scenarios():
            assert isinstance(s, BenchmarkScenario)

    def test_all_expanded_scenario_ids_unique(self):
        ids = [s.metadata.scenario_id for s in get_expanded_scenarios()]
        assert len(ids) == len(set(ids))

    def test_expanded_scenario_ids_follow_format(self):
        for s in get_expanded_scenarios():
            sid = s.metadata.scenario_id
            assert sid.startswith("SC-"), f"{sid} doesn't start with SC-"
            num = int(sid.split("-")[1])
            assert 19 <= num <= 33, f"{sid} number {num} outside 19-33 range"

    def test_no_cross_corpus_fact_id_collisions(self):
        """Fact IDs must not collide between expanded and original corpora."""
        all_fact_ids = set()
        for s in get_full_corpus():
            scenario_facts = s.packet.fact_ids
            overlap = all_fact_ids & scenario_facts
            assert not overlap, (
                f"Fact ID collision in {s.metadata.scenario_id}: {overlap}"
            )
            all_fact_ids.update(scenario_facts)

    def test_full_corpus_ids_are_sequential(self):
        corpus = get_full_corpus()
        ids = [s.metadata.scenario_id for s in corpus]
        for i, sid in enumerate(ids):
            expected = f"SC-{i + 1:03d}"
            assert sid == expected, f"Position {i}: expected {expected}, got {sid}"


# ------------------------------------------------------------------
# Packet Validity
# ------------------------------------------------------------------


class TestPacketValidity:
    """All expanded packets are valid frozen EvidencePackets."""

    def test_all_packets_are_frozen(self):
        for s in get_expanded_scenarios():
            assert s.packet.is_frozen, f"{s.metadata.scenario_id} packet not frozen"

    def test_all_packets_have_facts(self):
        for s in get_expanded_scenarios():
            assert s.packet.fact_count > 0, (
                f"{s.metadata.scenario_id} has no facts"
            )

    def test_fact_counts_match_metadata(self):
        for s in get_expanded_scenarios():
            assert s.packet.fact_count == s.metadata.fact_count, (
                f"{s.metadata.scenario_id}: packet has {s.packet.fact_count} "
                f"facts but metadata says {s.metadata.fact_count}"
            )

    def test_all_facts_have_provenance(self):
        for s in get_expanded_scenarios():
            for fact in s.packet.get_all_facts():
                assert fact.provenance is not None, (
                    f"{s.metadata.scenario_id}/{fact.fact_id} has no provenance"
                )

    def test_all_fact_ids_non_empty(self):
        for s in get_expanded_scenarios():
            for fact in s.packet.get_all_facts():
                assert fact.fact_id, (
                    f"{s.metadata.scenario_id} has empty fact_id"
                )

    def test_no_duplicate_fact_ids_within_scenarios(self):
        for s in get_expanded_scenarios():
            facts = s.packet.get_all_facts()
            ids = [f.fact_id for f in facts]
            assert len(ids) == len(set(ids)), (
                f"{s.metadata.scenario_id} has duplicate fact_ids"
            )

    def test_all_facts_have_valid_source_types(self):
        for s in get_expanded_scenarios():
            for fact in s.packet.get_all_facts():
                assert isinstance(fact.provenance.source_type, SourceType)


# ------------------------------------------------------------------
# Metadata Validity
# ------------------------------------------------------------------


class TestMetadataValidity:
    """All expanded scenario metadata is valid."""

    def test_mitre_ids_format(self):
        for s in get_expanded_scenarios():
            for mid in s.metadata.mitre_attack_ids:
                assert mid.startswith("T"), (
                    f"{s.metadata.scenario_id}: MITRE ID '{mid}' doesn't start with T"
                )

    def test_expected_verdicts_valid(self):
        valid = {"THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"}
        for s in get_expanded_scenarios():
            assert s.metadata.expected_verdict in valid, (
                f"{s.metadata.scenario_id}: invalid verdict "
                f"'{s.metadata.expected_verdict}'"
            )

    def test_expected_winners_valid(self):
        valid = {"ARCHITECT", "SKEPTIC", "BALANCED"}
        for s in get_expanded_scenarios():
            assert s.metadata.expected_winner in valid

    def test_difficulty_tiers_valid(self):
        valid = {1, 2, 3, 4}
        for s in get_expanded_scenarios():
            assert s.metadata.difficulty_tier in valid

    def test_all_metadata_have_non_empty_names(self):
        for s in get_expanded_scenarios():
            assert s.metadata.name

    def test_all_metadata_have_non_empty_descriptions(self):
        for s in get_expanded_scenarios():
            assert s.metadata.description

    def test_all_metadata_have_non_empty_notes(self):
        for s in get_expanded_scenarios():
            assert s.metadata.notes


# ------------------------------------------------------------------
# Tier Distribution
# ------------------------------------------------------------------


class TestTierDistribution:
    """Expanded scenarios have the correct tier distribution."""

    def test_clear_threat_count(self):
        threats = [s for s in get_expanded_scenarios()
                   if s.metadata.difficulty_tier == 1]
        assert len(threats) == 2

    def test_ambiguous_count(self):
        ambiguous = [s for s in get_expanded_scenarios()
                     if s.metadata.difficulty_tier == 2]
        assert len(ambiguous) == 6

    def test_clear_benign_count(self):
        benign = [s for s in get_expanded_scenarios()
                  if s.metadata.difficulty_tier == 3]
        assert len(benign) == 3

    def test_mixed_signals_count(self):
        mixed = [s for s in get_expanded_scenarios()
                 if s.metadata.difficulty_tier == 4]
        assert len(mixed) == 4

    def test_verdict_coverage(self):
        """All three verdict types must be represented."""
        verdicts = {s.metadata.expected_verdict for s in get_expanded_scenarios()}
        assert "THREAT_CONFIRMED" in verdicts
        assert "THREAT_DISMISSED" in verdicts
        assert "INCONCLUSIVE" in verdicts


# ------------------------------------------------------------------
# API Tests
# ------------------------------------------------------------------


class TestExpandedAPI:
    """Public API functions work correctly."""

    def test_get_expanded_scenario_by_id_returns_correct(self):
        s = get_expanded_scenario_by_id("SC-019")
        assert s.metadata.scenario_id == "SC-019"

    def test_get_expanded_scenario_by_id_all_fifteen(self):
        for i in range(19, 34):
            sid = f"SC-{i:03d}"
            s = get_expanded_scenario_by_id(sid)
            assert s.metadata.scenario_id == sid

    def test_get_expanded_scenario_by_id_raises_on_invalid(self):
        with pytest.raises(ValueError):
            get_expanded_scenario_by_id("SC-999")

    def test_get_expanded_scenario_by_id_raises_for_original(self):
        with pytest.raises(ValueError):
            get_expanded_scenario_by_id("SC-001")

    def test_full_corpus_includes_original_ids(self):
        ids = {s.metadata.scenario_id for s in get_full_corpus()}
        for i in range(1, 19):
            assert f"SC-{i:03d}" in ids

    def test_full_corpus_includes_expanded_ids(self):
        ids = {s.metadata.scenario_id for s in get_full_corpus()}
        for i in range(19, 34):
            assert f"SC-{i:03d}" in ids

    def test_full_corpus_all_ids_unique(self):
        ids = [s.metadata.scenario_id for s in get_full_corpus()]
        assert len(ids) == len(set(ids))


# ------------------------------------------------------------------
# Immutability
# ------------------------------------------------------------------


class TestImmutability:
    """All new types are frozen."""

    def test_expanded_benchmark_scenario_is_frozen(self):
        s = get_expanded_scenario_by_id("SC-019")
        with pytest.raises(AttributeError):
            s.metadata = None

    def test_expanded_scenario_metadata_is_frozen(self):
        s = get_expanded_scenario_by_id("SC-019")
        with pytest.raises(AttributeError):
            s.metadata.name = "tampered"


# ------------------------------------------------------------------
# Rule-based smoke test
# ------------------------------------------------------------------


@pytest.mark.parametrize(
    "scenario_id",
    [f"SC-{i:03d}" for i in range(19, 34)],
)
def test_expanded_scenario_runs_rule_based_without_error(scenario_id):
    """Each expanded scenario runs through rule-based orchestrator without error."""
    s = get_expanded_scenario_by_id(scenario_id)
    orchestrator = DialecticalOrchestrator()
    result = orchestrator.run_cycle(s.packet)
    assert result.verdict is not None
    assert result.verdict.outcome is not None
