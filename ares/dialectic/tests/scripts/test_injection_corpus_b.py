"""Tests for the Category B framing corpus expansion (injection_corpus_b_framing).

Covers:
    1. Corpus integrity (count, types, IDs, API consistency)
    2. Packet validity (frozen, facts, provenance, fact_count)
    3. No fact_id collisions (within Category B, vs injection seed, SC, PT)
    4. Metadata validity (verdicts, difficulty, notes, MITRE IDs)
    5. FramingRecord wrapper integrity (unique strategies, flag is False)
    6. Firewall-avoidance — concatenated text must not match any firewall regex
    7. Rule-based smoke test for every Category B scenario
"""

from __future__ import annotations

import re

import pytest

from ares.dialectic.agents.patterns import VerdictOutcome
from ares.dialectic.coordinator import firewall as _firewall_module
from ares.dialectic.scripts.injection_corpus import get_injection_scenarios
from ares.dialectic.scripts.injection_corpus_b_framing import (
    FRAMING_RECORDS,
    FramingRecord,
    INJECTION_SCENARIOS_B,
    get_framing_record_by_id,
    get_framing_records,
    get_framing_scenario_by_id,
    get_framing_scenarios,
)
from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_scenarios
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    get_all_scenarios,
)


EXPECTED_IDS = tuple(f"INJ-{n:03d}" for n in range(13, 28))  # INJ-013..INJ-027

ALL = get_framing_scenarios()
RECORDS = get_framing_records()


# =============================================================================
# Corpus Integrity
# =============================================================================


def test_corpus_has_fifteen_scenarios():
    assert len(ALL) == 15


def test_all_scenarios_are_benchmark_scenario_type():
    for s in ALL:
        assert isinstance(s, BenchmarkScenario)


def test_all_records_are_framing_record_type():
    for r in RECORDS:
        assert isinstance(r, FramingRecord)


def test_scenario_ids_are_inj013_through_inj027():
    ids = tuple(s.metadata.scenario_id for s in ALL)
    assert ids == EXPECTED_IDS, (
        f"Expected {EXPECTED_IDS!r}, got {ids!r}"
    )


def test_all_scenario_ids_unique():
    ids = [s.metadata.scenario_id for s in ALL]
    assert len(ids) == len(set(ids))


def test_get_framing_scenarios_constant_and_function_agree():
    assert get_framing_scenarios() == INJECTION_SCENARIOS_B


def test_get_framing_records_constant_and_function_agree():
    assert get_framing_records() == FRAMING_RECORDS


def test_get_framing_scenario_by_id_works_for_all():
    for s in ALL:
        result = get_framing_scenario_by_id(s.metadata.scenario_id)
        assert result.metadata.scenario_id == s.metadata.scenario_id


def test_get_framing_scenario_by_id_raises_on_invalid():
    with pytest.raises(KeyError):
        get_framing_scenario_by_id("INJ-999")


def test_get_framing_record_by_id_roundtrip():
    for r in RECORDS:
        sid = r.scenario.metadata.scenario_id
        assert get_framing_record_by_id(sid) is r


def test_get_framing_record_by_id_raises_on_invalid():
    with pytest.raises(KeyError):
        get_framing_record_by_id("INJ-999")


# =============================================================================
# Packet Validity
# =============================================================================


def test_all_packets_are_frozen():
    for s in ALL:
        assert s.packet.is_frozen, f"{s.metadata.scenario_id}: packet not frozen"


def test_all_packets_have_facts():
    for s in ALL:
        assert s.packet.fact_count > 0, (
            f"{s.metadata.scenario_id}: packet has zero facts"
        )


def test_fact_counts_match_metadata():
    for s in ALL:
        assert s.packet.fact_count == s.metadata.fact_count, (
            f"{s.metadata.scenario_id}: metadata says {s.metadata.fact_count} "
            f"facts; packet has {s.packet.fact_count}"
        )


def test_all_facts_have_provenance():
    for s in ALL:
        for fact in s.packet.get_all_facts():
            assert fact.provenance is not None, (
                f"{s.metadata.scenario_id}/{fact.fact_id}: missing provenance"
            )


def test_fact_ids_follow_prefix_convention():
    """Every fact_id must match injNNN-fact-NNN with NNN in [013, 027]."""
    pattern = re.compile(r"^inj0(1[3-9]|2[0-7])-fact-\d{3}$")
    for s in ALL:
        for fact in s.packet.get_all_facts():
            assert pattern.match(fact.fact_id), (
                f"{s.metadata.scenario_id}: fact_id '{fact.fact_id}' violates "
                "expected prefix convention"
            )


# =============================================================================
# No Collisions
# =============================================================================


def _collect_fact_ids(scenarios):
    ids = set()
    for s in scenarios:
        for fact in s.packet.get_all_facts():
            ids.add(fact.fact_id)
    return ids


def test_no_fact_id_collisions_within_category_b():
    """All fact IDs are unique across the 15 Category B scenarios."""
    fact_ids = []
    for s in ALL:
        for fact in s.packet.get_all_facts():
            fact_ids.append(fact.fact_id)
    assert len(fact_ids) == len(set(fact_ids)), (
        "Duplicate fact_id within Category B expansion"
    )


def test_no_fact_id_collisions_with_injection_seed():
    b = _collect_fact_ids(ALL)
    seed = _collect_fact_ids(get_injection_scenarios())
    collisions = b & seed
    assert not collisions, (
        f"fact_id collisions with INJ-001..012: {sorted(collisions)}"
    )


def test_no_fact_id_collisions_with_sc_scenarios():
    b = _collect_fact_ids(ALL)
    sc = _collect_fact_ids(get_all_scenarios())
    collisions = b & sc
    assert not collisions, f"fact_id collisions with SC corpus: {sorted(collisions)}"


def test_no_fact_id_collisions_with_pt_scenarios():
    b = _collect_fact_ids(ALL)
    pt = _collect_fact_ids(get_pentagi_scenarios())
    collisions = b & pt
    assert not collisions, f"fact_id collisions with PT corpus: {sorted(collisions)}"


def test_no_scenario_id_collisions_with_injection_seed():
    b_ids = {s.metadata.scenario_id for s in ALL}
    seed_ids = {s.metadata.scenario_id for s in get_injection_scenarios()}
    collisions = b_ids & seed_ids
    assert not collisions, (
        f"scenario_id collisions with INJ-001..012: {sorted(collisions)}"
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


def test_expected_winners_valid():
    valid = {"ARCHITECT", "SKEPTIC", "BALANCED"}
    for s in ALL:
        assert s.metadata.expected_winner in valid, (
            f"{s.metadata.scenario_id}: invalid winner "
            f"'{s.metadata.expected_winner}'"
        )


def test_all_difficulty_tier_five():
    for s in ALL:
        assert s.metadata.difficulty_tier == 5, (
            f"{s.metadata.scenario_id}: tier {s.metadata.difficulty_tier}, "
            "expected 5"
        )


def test_all_notes_non_empty():
    for s in ALL:
        assert s.metadata.notes is not None
        assert len(s.metadata.notes.strip()) > 0, (
            f"{s.metadata.scenario_id}: empty notes"
        )


def test_mitre_attack_ids_format():
    pattern = re.compile(r"^T\d{4}$")
    for s in ALL:
        assert len(s.metadata.mitre_attack_ids) > 0, (
            f"{s.metadata.scenario_id}: no MITRE IDs"
        )
        for mid in s.metadata.mitre_attack_ids:
            assert pattern.match(mid), (
                f"{s.metadata.scenario_id}: invalid MITRE ID '{mid}'"
            )


# =============================================================================
# FramingRecord Wrapper
# =============================================================================


def test_framing_records_all_expected_firewall_detection_false():
    """Category B exists precisely because the firewall does not catch framing."""
    for r in RECORDS:
        assert r.expected_firewall_detection is False, (
            f"{r.scenario.metadata.scenario_id}: "
            "expected_firewall_detection must be False for Category B"
        )


def test_framing_strategies_are_unique():
    strategies = [r.framing_strategy for r in RECORDS]
    assert len(strategies) == len(set(strategies)), (
        f"Duplicate framing_strategy values: {strategies}"
    )


def test_framing_strategies_non_empty():
    for r in RECORDS:
        assert isinstance(r.framing_strategy, str)
        assert r.framing_strategy.strip(), (
            f"{r.scenario.metadata.scenario_id}: empty framing_strategy"
        )


def test_strategy_rationales_non_empty():
    for r in RECORDS:
        assert isinstance(r.strategy_rationale, str)
        assert r.strategy_rationale.strip(), (
            f"{r.scenario.metadata.scenario_id}: empty strategy_rationale"
        )


def test_record_and_scenario_order_match():
    for record, scenario in zip(RECORDS, ALL):
        assert record.scenario is scenario


# =============================================================================
# Firewall-avoidance (the defining property of Category B)
# =============================================================================


# Import the module-private firewall regex objects so this test stays coupled
# to what the firewall actually enforces today.  If a new detection pattern is
# added there, this test will surface any scenarios that happen to hit it.
_FIREWALL_PATTERNS = {
    "IGNORE_PATTERNS": _firewall_module._IGNORE_PATTERNS,
    "DISREGARD_PATTERNS": _firewall_module._DISREGARD_PATTERNS,
    "DIRECTIVE_PREFIXES": _firewall_module._DIRECTIVE_PREFIXES,
    "SYSTEM_DIRECTIVE": _firewall_module._SYSTEM_DIRECTIVE,
    "DO_NOT_FLAG": _firewall_module._DO_NOT_FLAG,
    "CODE_FENCE_INJECTION": _firewall_module._CODE_FENCE_INJECTION,
    "AUTHORITY_VERBS": _firewall_module._AUTHORITY_VERBS,
    "AUTHORITY_ENTITIES": _firewall_module._AUTHORITY_ENTITIES,
    "FALSE_POSITIVE_CLAIMS": _firewall_module._FALSE_POSITIVE_CLAIMS,
    "DOWNWARD_PUSH": _firewall_module._DOWNWARD_PUSH,
    "UPWARD_PUSH": _firewall_module._UPWARD_PUSH,
    "CODE_FENCE": _firewall_module._CODE_FENCE,
    "CODE_FENCE_TYPED": _firewall_module._CODE_FENCE_TYPED,
    "CONTROL_CHARS": _firewall_module._CONTROL_CHARS,
    "EXCESSIVE_NEWLINES": _firewall_module._EXCESSIVE_NEWLINES,
}


def _scenario_observable_text(scenario: BenchmarkScenario) -> str:
    """Concatenate every string the firewall could ever see for this scenario.

    The firewall inspects fact.value text (as referenced by assertions) and
    interpretation text (from Architect output).  We don't have a real
    Architect output here, so we use the scenario metadata text as the
    closest analogue — if the firewall would trip on the metadata prose,
    it might also trip on interpretation text that quotes it.
    """
    parts: list[str] = [
        scenario.metadata.name,
        scenario.metadata.description,
        scenario.metadata.notes,
    ]
    for fact in scenario.packet.get_all_facts():
        parts.append(str(fact.value))
    return "\n".join(parts)


@pytest.mark.parametrize(
    "scenario", ALL, ids=lambda s: s.metadata.scenario_id,
)
@pytest.mark.parametrize("pattern_name", sorted(_FIREWALL_PATTERNS))
def test_scenario_text_does_not_match_firewall_pattern(scenario, pattern_name):
    """No Category B scenario's observable text may match any firewall regex.

    This is the defining invariant of Category B: the firewall is meant to
    be blind to these scenarios.  If any regex hit appears, either the
    scenario needs rewording or the firewall has expanded its surface area
    and Category B is no longer the open problem it was designed to be.
    """
    pattern = _FIREWALL_PATTERNS[pattern_name]
    text = _scenario_observable_text(scenario)
    match = pattern.search(text)
    assert match is None, (
        f"{scenario.metadata.scenario_id} unexpectedly matched firewall "
        f"pattern {pattern_name!r}: {match.group(0)!r}"
    )


# =============================================================================
# Rule-Based Smoke Test
# =============================================================================


@pytest.mark.parametrize(
    "scenario", ALL, ids=lambda s: s.metadata.scenario_id,
)
def test_scenario_runs_rule_based_without_error(scenario):
    """Every Category B scenario must complete a rule-based cycle cleanly."""
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
