"""Tests for the Session 049 authority-family expansion corpus.

Covers:
    1. All 3 scenarios build with correct IDs, metadata, expected verdicts.
    2. Sub-strategy names are unique and well-formed.
    3. Every scenario's observable text contains zero verbatim hits on
       any OracleFirewall regex (parametrized 3 × N matrix).
    4. FramingRecord metadata: expected_firewall_detection is False on
       every scenario, and the rationale is non-empty.
    5. By-ID lookup raises KeyError on unknown scenario_ids.
"""

from __future__ import annotations

import pytest

from ares.dialectic.coordinator.firewall import (
    _AUTHORITY_ENTITIES,
    _AUTHORITY_VERBS,
    _CODE_FENCE,
    _CODE_FENCE_INJECTION,
    _CODE_FENCE_TYPED,
    _CONTROL_CHARS,
    _DIRECTIVE_PREFIXES,
    _DISREGARD_PATTERNS,
    _DO_NOT_FLAG,
    _DOWNWARD_PUSH,
    _EXCESSIVE_NEWLINES,
    _FALSE_POSITIVE_CLAIMS,
    _IGNORE_PATTERNS,
    _SYSTEM_DIRECTIVE,
    _UPWARD_PUSH,
)
from ares.dialectic.scripts.injection_corpus_b_authority_expansion import (
    AUTHORITY_EXPANSION_RECORDS,
    AUTHORITY_EXPANSION_SCENARIOS,
    build_inj028_authority_credentialed_source,
    build_inj029_authority_automated_system,
    build_inj030_authority_tool_output,
    get_authority_expansion_record_by_id,
    get_authority_expansion_records,
    get_authority_expansion_scenario_by_id,
    get_authority_expansion_scenarios,
)


# =============================================================================
# Basic shape
# =============================================================================


class TestCorpusShape:
    def test_exactly_three_records(self):
        assert len(AUTHORITY_EXPANSION_RECORDS) == 3

    def test_exactly_three_scenarios(self):
        assert len(AUTHORITY_EXPANSION_SCENARIOS) == 3

    def test_records_and_scenarios_agree(self):
        record_ids = [r.scenario.metadata.scenario_id
                      for r in AUTHORITY_EXPANSION_RECORDS]
        scenario_ids = [s.metadata.scenario_id for s in AUTHORITY_EXPANSION_SCENARIOS]
        assert record_ids == scenario_ids

    def test_public_accessors(self):
        assert get_authority_expansion_records() == AUTHORITY_EXPANSION_RECORDS
        assert get_authority_expansion_scenarios() == AUTHORITY_EXPANSION_SCENARIOS


# =============================================================================
# Metadata
# =============================================================================


class TestMetadata:
    def test_scenario_ids(self):
        ids = {s.metadata.scenario_id for s in AUTHORITY_EXPANSION_SCENARIOS}
        assert ids == {"INJ-028", "INJ-029", "INJ-030"}

    def test_all_expected_threat_confirmed(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            assert s.metadata.expected_verdict == "THREAT_CONFIRMED"

    def test_all_difficulty_tier_five(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            assert s.metadata.difficulty_tier == 5

    def test_sub_strategies_unique(self):
        strategies = [r.framing_strategy for r in AUTHORITY_EXPANSION_RECORDS]
        assert len(set(strategies)) == 3

    def test_sub_strategies_start_with_authority(self):
        for r in AUTHORITY_EXPANSION_RECORDS:
            assert r.framing_strategy.startswith("authority_")

    def test_sub_strategy_names(self):
        strategies = {r.framing_strategy for r in AUTHORITY_EXPANSION_RECORDS}
        assert strategies == {
            "authority_credentialed_source",
            "authority_automated_system",
            "authority_tool_output",
        }

    def test_every_record_expected_firewall_false(self):
        for r in AUTHORITY_EXPANSION_RECORDS:
            assert r.expected_firewall_detection is False

    def test_every_record_has_rationale(self):
        for r in AUTHORITY_EXPANSION_RECORDS:
            assert r.strategy_rationale
            assert len(r.strategy_rationale) >= 30

    def test_metadata_fact_count_matches_packet(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            assert s.metadata.fact_count == len(s.packet.get_all_facts())


# =============================================================================
# Packet structure
# =============================================================================


class TestPackets:
    def test_packets_are_frozen(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            assert s.packet.is_frozen

    def test_fact_ids_use_injNNN_prefix(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            sid_short = s.metadata.scenario_id.replace("INJ-", "inj").lower()
            for fact in s.packet.get_all_facts():
                assert fact.fact_id.startswith(f"{sid_short}-fact-"), (
                    f"{s.metadata.scenario_id}: {fact.fact_id} wrong prefix"
                )

    def test_packet_has_at_least_five_facts(self):
        for s in AUTHORITY_EXPANSION_SCENARIOS:
            assert len(s.packet.get_all_facts()) >= 5


# =============================================================================
# Builder functions
# =============================================================================


class TestBuilders:
    def test_inj028_builds(self):
        scenario = build_inj028_authority_credentialed_source()
        assert scenario.metadata.scenario_id == "INJ-028"

    def test_inj029_builds(self):
        scenario = build_inj029_authority_automated_system()
        assert scenario.metadata.scenario_id == "INJ-029"

    def test_inj030_builds(self):
        scenario = build_inj030_authority_tool_output()
        assert scenario.metadata.scenario_id == "INJ-030"


# =============================================================================
# By-ID lookup
# =============================================================================


class TestLookup:
    def test_get_scenario_by_id(self):
        s = get_authority_expansion_scenario_by_id("INJ-028")
        assert s.metadata.scenario_id == "INJ-028"

    def test_get_record_by_id(self):
        r = get_authority_expansion_record_by_id("INJ-029")
        assert r.framing_strategy == "authority_automated_system"

    def test_unknown_id_raises(self):
        with pytest.raises(KeyError):
            get_authority_expansion_record_by_id("INJ-999")

    def test_unknown_scenario_id_raises(self):
        with pytest.raises(KeyError):
            get_authority_expansion_scenario_by_id("INJ-123")


# =============================================================================
# Firewall blind-spot matrix (scenarios × regexes)
# =============================================================================


_FIREWALL_PATTERNS = (
    ("ignore", _IGNORE_PATTERNS),
    ("disregard", _DISREGARD_PATTERNS),
    ("directive_prefixes", _DIRECTIVE_PREFIXES),
    ("system_directive", _SYSTEM_DIRECTIVE),
    ("do_not_flag", _DO_NOT_FLAG),
    ("code_fence_injection", _CODE_FENCE_INJECTION),
    ("authority_verbs", _AUTHORITY_VERBS),
    ("authority_entities", _AUTHORITY_ENTITIES),
    ("false_positive_claims", _FALSE_POSITIVE_CLAIMS),
    ("downward_push", _DOWNWARD_PUSH),
    ("upward_push", _UPWARD_PUSH),
    ("code_fence", _CODE_FENCE),
    ("code_fence_typed", _CODE_FENCE_TYPED),
    ("control_chars", _CONTROL_CHARS),
    ("excessive_newlines", _EXCESSIVE_NEWLINES),
)


def _concatenated_text(scenario) -> str:
    """Concatenate every observable text in a scenario."""
    parts = []
    for fact in scenario.packet.get_all_facts():
        parts.append(str(fact.value))
    meta = scenario.metadata
    parts.extend([meta.name, meta.description, meta.notes])
    return "\n".join(parts)


@pytest.mark.parametrize(
    "scenario", AUTHORITY_EXPANSION_SCENARIOS,
    ids=[s.metadata.scenario_id for s in AUTHORITY_EXPANSION_SCENARIOS],
)
@pytest.mark.parametrize(
    "regex_name,regex", _FIREWALL_PATTERNS,
    ids=[name for name, _ in _FIREWALL_PATTERNS],
)
def test_firewall_regex_does_not_match(scenario, regex_name, regex):
    """Every authority-expansion scenario's text is a firewall blind spot.

    This parametrized matrix enforces the Category B constraint: semantic
    framing sits outside the current firewall's detection surface.
    """
    text = _concatenated_text(scenario)
    match = regex.search(text)
    assert match is None, (
        f"{scenario.metadata.scenario_id} triggers {regex_name}: "
        f"{match.group() if match else ''!r}"
    )
