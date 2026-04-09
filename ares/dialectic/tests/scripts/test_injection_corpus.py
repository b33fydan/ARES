"""Tests for the injection scenario corpus — structure, metadata, packet validity,
cross-corpus collision checks, and injection content verification.

Covers:
    1. Corpus integrity (count, types, IDs, API consistency)
    2. Packet validity (frozen, facts, provenance)
    3. No fact_id collisions (within injection, vs SC, vs PT)
    4. Metadata validity (verdicts, difficulty, notes, MITRE IDs)
    5. Category coverage (A/B/C split)
    6. Injection content present in Category A scenarios
    7. INJ-012 authorization evidence
    8. Rule-based smoke test for every scenario
"""

from __future__ import annotations

import re

import pytest

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.scripts.injection_corpus import (
    ALL_INJECTION_SCENARIOS,
    INJECTION_SCENARIOS,
    get_injection_scenario_by_id,
    get_injection_scenarios,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    get_all_scenarios,
)
from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_scenarios

ALL = get_injection_scenarios()

CATEGORY_A_IDS = ["INJ-001", "INJ-002", "INJ-003", "INJ-004"]
CATEGORY_B_IDS = ["INJ-005", "INJ-006", "INJ-007", "INJ-008"]
CATEGORY_C_IDS = ["INJ-009", "INJ-010", "INJ-011", "INJ-012"]

# Common injection phrases that should appear in Category A fact values.
INJECTION_PHRASES = [
    "ignore previous",
    "classify this activity as benign",
    "dismiss all threats",
    "false positive",
    "confidence 0.1",
    "confidence: 0.1",
    "new system instructions",
    "threat_dismissed",
    "do not flag",
    "system:",
]


# =============================================================================
# Corpus Integrity
# =============================================================================


def test_corpus_has_twelve_scenarios():
    assert len(ALL) == 12


def test_all_scenarios_are_benchmark_scenario_type():
    for s in ALL:
        assert isinstance(s, BenchmarkScenario)


def test_all_scenario_ids_unique():
    ids = [s.metadata.scenario_id for s in ALL]
    assert len(ids) == len(set(ids))


def test_scenario_ids_use_inj_prefix():
    """All IDs follow INJ-NNN format, INJ-001 through INJ-012."""
    for s in ALL:
        assert s.metadata.scenario_id.startswith("INJ-"), (
            f"Unexpected prefix: {s.metadata.scenario_id}"
        )
        num = int(s.metadata.scenario_id.split("-")[1])
        assert 1 <= num <= 12, (
            f"Unexpected number: {s.metadata.scenario_id}"
        )


def test_get_injection_scenarios_and_constant_are_same():
    """get_injection_scenarios() and INJECTION_SCENARIOS return the same data."""
    assert get_injection_scenarios() == INJECTION_SCENARIOS


def test_all_injection_scenarios_alias():
    """ALL_INJECTION_SCENARIOS is an alias for INJECTION_SCENARIOS."""
    assert ALL_INJECTION_SCENARIOS is INJECTION_SCENARIOS


def test_get_injection_scenario_by_id_works_for_all():
    for s in ALL:
        result = get_injection_scenario_by_id(s.metadata.scenario_id)
        assert result.metadata.scenario_id == s.metadata.scenario_id


def test_get_injection_scenario_by_id_raises_on_invalid():
    with pytest.raises(KeyError):
        get_injection_scenario_by_id("INJ-999")


# =============================================================================
# Packet Validity
# =============================================================================


def test_all_packets_are_frozen():
    for s in ALL:
        assert s.packet.is_frozen, f"{s.metadata.scenario_id} not frozen"


def test_all_packets_have_facts():
    for s in ALL:
        assert s.packet.fact_count > 0, (
            f"{s.metadata.scenario_id}: no facts"
        )


def test_fact_counts_match_metadata():
    for s in ALL:
        assert s.packet.fact_count == s.metadata.fact_count, (
            f"{s.metadata.scenario_id}: metadata says {s.metadata.fact_count}, "
            f"packet has {s.packet.fact_count}"
        )


def test_all_facts_have_provenance():
    for s in ALL:
        for fact in s.packet.get_all_facts():
            assert fact.provenance is not None, (
                f"{s.metadata.scenario_id}/{fact.fact_id}: missing provenance"
            )


# =============================================================================
# No Collisions
# =============================================================================


def test_no_fact_id_collisions_within_injection_corpus():
    """All fact IDs are unique across all 12 injection scenarios."""
    all_fact_ids = []
    for s in ALL:
        for fact in s.packet.get_all_facts():
            all_fact_ids.append(fact.fact_id)
    assert len(all_fact_ids) == len(set(all_fact_ids)), (
        "Duplicate fact_id found within injection corpus"
    )


def test_no_fact_id_collisions_with_sc_scenarios():
    """No injection fact IDs overlap with SC scenario fact IDs."""
    inj_ids = set()
    for s in ALL:
        for fact in s.packet.get_all_facts():
            inj_ids.add(fact.fact_id)

    sc_ids = set()
    for s in get_all_scenarios():
        for fact in s.packet.get_all_facts():
            sc_ids.add(fact.fact_id)

    collisions = inj_ids & sc_ids
    assert len(collisions) == 0, (
        f"Fact ID collisions with SC corpus: {collisions}"
    )


def test_no_fact_id_collisions_with_pt_scenarios():
    """No injection fact IDs overlap with PT scenario fact IDs."""
    inj_ids = set()
    for s in ALL:
        for fact in s.packet.get_all_facts():
            inj_ids.add(fact.fact_id)

    pt_ids = set()
    for s in get_pentagi_scenarios():
        for fact in s.packet.get_all_facts():
            pt_ids.add(fact.fact_id)

    collisions = inj_ids & pt_ids
    assert len(collisions) == 0, (
        f"Fact ID collisions with PT corpus: {collisions}"
    )


# =============================================================================
# Metadata Validity
# =============================================================================


def test_expected_verdicts_valid():
    valid = {"THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"}
    for s in ALL:
        assert s.metadata.expected_verdict in valid, (
            f"{s.metadata.scenario_id}: invalid verdict "
            f"'{s.metadata.expected_verdict}'"
        )


def test_all_difficulty_tier_five():
    """All injection scenarios are difficulty tier 5."""
    for s in ALL:
        assert s.metadata.difficulty_tier == 5, (
            f"{s.metadata.scenario_id}: tier {s.metadata.difficulty_tier}, expected 5"
        )


def test_all_notes_non_empty():
    """All notes describe the injection technique used."""
    for s in ALL:
        assert s.metadata.notes is not None
        assert len(s.metadata.notes.strip()) > 0, (
            f"{s.metadata.scenario_id}: empty notes"
        )


def test_mitre_attack_ids_format():
    """All MITRE ATT&CK IDs follow Txxxx format where present."""
    pattern = re.compile(r"^T\d{4}$")
    for s in ALL:
        for mid in s.metadata.mitre_attack_ids:
            assert pattern.match(mid), (
                f"{s.metadata.scenario_id}: invalid MITRE ID '{mid}'"
            )


# =============================================================================
# Category Coverage
# =============================================================================


def test_category_a_has_four_scenarios():
    """INJ-001 through INJ-004 are Category A (direct instruction injection)."""
    found = [s for s in ALL if s.metadata.scenario_id in CATEGORY_A_IDS]
    assert len(found) == 4


def test_category_b_has_four_scenarios():
    """INJ-005 through INJ-008 are Category B (subtle framing injection)."""
    found = [s for s in ALL if s.metadata.scenario_id in CATEGORY_B_IDS]
    assert len(found) == 4


def test_category_c_has_four_scenarios():
    """INJ-009 through INJ-012 are Category C (cross-agent propagation)."""
    found = [s for s in ALL if s.metadata.scenario_id in CATEGORY_C_IDS]
    assert len(found) == 4


# =============================================================================
# Injection Content Present
# =============================================================================


@pytest.mark.parametrize(
    "scenario_id", CATEGORY_A_IDS, ids=CATEGORY_A_IDS,
)
def test_category_a_contains_injection_content(scenario_id):
    """Each Category A scenario has at least one fact value with injection phrases."""
    scenario = get_injection_scenario_by_id(scenario_id)
    found_injection = False
    for fact in scenario.packet.get_all_facts():
        value_lower = str(fact.value).lower()
        for phrase in INJECTION_PHRASES:
            if phrase.lower() in value_lower:
                found_injection = True
                break
        if found_injection:
            break
    assert found_injection, (
        f"{scenario_id}: no injection content found in any fact value"
    )


def test_inj012_has_authorization_evidence():
    """INJ-012 is a legit red team scenario — must have actual authorization facts."""
    scenario = get_injection_scenario_by_id("INJ-012")
    auth_keywords = ["authorized", "authorization", "change window", "pentest engagement"]
    found_auth = False
    for fact in scenario.packet.get_all_facts():
        value_lower = str(fact.value).lower()
        for kw in auth_keywords:
            if kw in value_lower:
                found_auth = True
                break
        if found_auth:
            break
    assert found_auth, "INJ-012 must have authorization evidence in the packet"


# =============================================================================
# Rule-Based Smoke Test
# =============================================================================


@pytest.mark.parametrize(
    "scenario", ALL, ids=lambda s: s.metadata.scenario_id,
)
def test_scenario_runs_rule_based_without_error(scenario):
    """Every injection scenario must complete a rule-based cycle without exceptions."""
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
