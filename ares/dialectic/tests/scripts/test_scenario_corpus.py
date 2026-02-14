"""Tests for the scenario corpus — structure, metadata, and packet validity."""

from __future__ import annotations

import pytest
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
    get_all_scenarios,
    get_scenario_by_id,
    get_scenarios_by_tier,
)
from ares.dialectic.agents.patterns import VerdictOutcome

ALL_SCENARIOS = get_all_scenarios()


# =============================================================================
# Corpus Integrity
# =============================================================================

def test_corpus_has_twelve_scenarios():
    assert len(ALL_SCENARIOS) == 12


def test_all_scenarios_are_benchmark_scenario_type():
    for s in ALL_SCENARIOS:
        assert isinstance(s, BenchmarkScenario)


def test_all_scenario_ids_unique():
    ids = [s.metadata.scenario_id for s in ALL_SCENARIOS]
    assert len(ids) == len(set(ids))


def test_scenario_ids_follow_format():
    """SC-001 through SC-012."""
    for s in ALL_SCENARIOS:
        assert s.metadata.scenario_id.startswith("SC-")
        num = int(s.metadata.scenario_id.split("-")[1])
        assert 1 <= num <= 12


# =============================================================================
# Packet Validity
# =============================================================================

def test_all_packets_are_frozen():
    for s in ALL_SCENARIOS:
        assert s.packet.is_frozen


def test_all_packets_have_facts():
    for s in ALL_SCENARIOS:
        assert s.packet.fact_count > 0


def test_fact_counts_match_metadata():
    for s in ALL_SCENARIOS:
        assert s.packet.fact_count == s.metadata.fact_count, (
            f"{s.metadata.scenario_id}: metadata says {s.metadata.fact_count}, "
            f"packet has {s.packet.fact_count}"
        )


def test_all_facts_have_provenance():
    for s in ALL_SCENARIOS:
        for fact in s.packet.get_all_facts():
            assert fact.provenance is not None


def test_all_fact_ids_non_empty_strings():
    for s in ALL_SCENARIOS:
        for fact in s.packet.get_all_facts():
            assert isinstance(fact.fact_id, str)
            assert len(fact.fact_id) > 0


def test_no_duplicate_fact_ids_within_scenarios():
    for s in ALL_SCENARIOS:
        fact_ids = [f.fact_id for f in s.packet.get_all_facts()]
        assert len(fact_ids) == len(set(fact_ids)), (
            f"{s.metadata.scenario_id}: duplicate fact_ids found"
        )


def test_no_cross_scenario_fact_id_collisions():
    all_fact_ids = []
    for s in ALL_SCENARIOS:
        for fact in s.packet.get_all_facts():
            all_fact_ids.append(fact.fact_id)
    assert len(all_fact_ids) == len(set(all_fact_ids)), (
        "Cross-scenario fact_id collision detected"
    )


# =============================================================================
# Metadata Validity
# =============================================================================

def test_mitre_ids_format():
    for s in ALL_SCENARIOS:
        for mid in s.metadata.mitre_attack_ids:
            assert mid.startswith("T"), (
                f"{s.metadata.scenario_id}: invalid MITRE ID {mid}"
            )


def test_expected_verdicts_valid():
    valid = {"THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"}
    for s in ALL_SCENARIOS:
        assert s.metadata.expected_verdict in valid, (
            f"{s.metadata.scenario_id}: invalid expected_verdict "
            f"{s.metadata.expected_verdict}"
        )


def test_expected_winners_valid():
    valid = {"ARCHITECT", "SKEPTIC", "BALANCED"}
    for s in ALL_SCENARIOS:
        assert s.metadata.expected_winner in valid


def test_difficulty_tiers_valid():
    for s in ALL_SCENARIOS:
        assert 1 <= s.metadata.difficulty_tier <= 4


def test_each_tier_has_scenarios():
    for tier in range(1, 5):
        tier_scenarios = get_scenarios_by_tier(tier)
        assert len(tier_scenarios) >= 2, (
            f"Tier {tier} has fewer than 2 scenarios"
        )


def test_verdict_coverage():
    """At least one scenario expects each VerdictOutcome."""
    expected = {s.metadata.expected_verdict for s in ALL_SCENARIOS}
    assert "THREAT_CONFIRMED" in expected
    assert "THREAT_DISMISSED" in expected
    assert "INCONCLUSIVE" in expected


def test_get_scenario_by_id_returns_correct():
    sc = get_scenario_by_id("SC-001")
    assert sc.metadata.scenario_id == "SC-001"


def test_get_scenario_by_id_raises_on_invalid():
    with pytest.raises(KeyError):
        get_scenario_by_id("SC-999")


def test_get_scenarios_by_tier_returns_correct_tier():
    for tier in range(1, 5):
        for s in get_scenarios_by_tier(tier):
            assert s.metadata.difficulty_tier == tier


def test_get_scenarios_by_tier_invalid_raises():
    with pytest.raises(ValueError):
        get_scenarios_by_tier(0)
    with pytest.raises(ValueError):
        get_scenarios_by_tier(5)


def test_all_metadata_have_non_empty_names():
    for s in ALL_SCENARIOS:
        assert len(s.metadata.name) > 0


def test_all_metadata_have_non_empty_descriptions():
    for s in ALL_SCENARIOS:
        assert len(s.metadata.description) > 0


def test_all_metadata_have_non_empty_notes():
    for s in ALL_SCENARIOS:
        assert len(s.metadata.notes) > 0


def test_scenario_metadata_is_frozen():
    for s in ALL_SCENARIOS:
        with pytest.raises(AttributeError):
            s.metadata.scenario_id = "tampered"


def test_benchmark_scenario_is_frozen():
    for s in ALL_SCENARIOS:
        with pytest.raises(AttributeError):
            s.metadata = None


# =============================================================================
# Rule-Based Execution
# =============================================================================

@pytest.mark.parametrize(
    "scenario", ALL_SCENARIOS, ids=lambda s: s.metadata.scenario_id
)
def test_scenario_runs_rule_based_without_error(scenario):
    """Every scenario must complete a rule-based cycle without exceptions."""
    from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedNarrativeGenerator,
        RuleBasedThreatAnalyzer,
    )

    result = run_cycle_with_strategies(
        packet=scenario.packet,
        threat_analyzer=RuleBasedThreatAnalyzer(),
        explanation_finder=RuleBasedExplanationFinder(),
        narrative_generator=RuleBasedNarrativeGenerator(),
    )
    assert result.verdict is not None
    assert result.verdict.outcome in VerdictOutcome
