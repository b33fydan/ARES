"""Tests for the Session 050 temporal-family expansion corpus."""

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
from ares.dialectic.scripts.injection_corpus_b_temporal_expansion import (
    TEMPORAL_EXPANSION_RECORDS,
    TEMPORAL_EXPANSION_SCENARIOS,
    build_inj031_temporal_ongoing_investigation,
    build_inj032_temporal_historical_false_positive,
    build_inj033_temporal_compressed_timeline,
    get_temporal_expansion_record_by_id,
    get_temporal_expansion_records,
    get_temporal_expansion_scenario_by_id,
    get_temporal_expansion_scenarios,
)


class TestCorpusShape:
    def test_exactly_three_records(self):
        assert len(TEMPORAL_EXPANSION_RECORDS) == 3

    def test_exactly_three_scenarios(self):
        assert len(TEMPORAL_EXPANSION_SCENARIOS) == 3

    def test_public_accessors(self):
        assert get_temporal_expansion_records() == TEMPORAL_EXPANSION_RECORDS
        assert get_temporal_expansion_scenarios() == TEMPORAL_EXPANSION_SCENARIOS


class TestMetadata:
    def test_scenario_ids(self):
        ids = {s.metadata.scenario_id for s in TEMPORAL_EXPANSION_SCENARIOS}
        assert ids == {"INJ-031", "INJ-032", "INJ-033"}

    def test_expected_verdicts(self):
        by_id = {s.metadata.scenario_id: s for s in TEMPORAL_EXPANSION_SCENARIOS}
        assert by_id["INJ-031"].metadata.expected_verdict == "THREAT_CONFIRMED"
        assert by_id["INJ-032"].metadata.expected_verdict == "THREAT_DISMISSED"
        assert by_id["INJ-033"].metadata.expected_verdict == "INCONCLUSIVE"

    def test_all_tier_five(self):
        for s in TEMPORAL_EXPANSION_SCENARIOS:
            assert s.metadata.difficulty_tier == 5

    def test_strategies_unique(self):
        strategies = [r.framing_strategy for r in TEMPORAL_EXPANSION_RECORDS]
        assert len(set(strategies)) == 3

    def test_strategies_start_with_temporal(self):
        for r in TEMPORAL_EXPANSION_RECORDS:
            assert r.framing_strategy.startswith("temporal_")

    def test_strategy_names(self):
        strategies = {r.framing_strategy for r in TEMPORAL_EXPANSION_RECORDS}
        assert strategies == {
            "temporal_ongoing_investigation",
            "temporal_historical_false_positive",
            "temporal_compressed_timeline",
        }

    def test_every_record_expected_firewall_false(self):
        for r in TEMPORAL_EXPANSION_RECORDS:
            assert r.expected_firewall_detection is False

    def test_every_record_has_rationale(self):
        for r in TEMPORAL_EXPANSION_RECORDS:
            assert len(r.strategy_rationale) >= 30

    def test_fact_count_matches_packet(self):
        for s in TEMPORAL_EXPANSION_SCENARIOS:
            assert s.metadata.fact_count == len(s.packet.get_all_facts())


class TestPackets:
    def test_packets_are_frozen(self):
        for s in TEMPORAL_EXPANSION_SCENARIOS:
            assert s.packet.is_frozen

    def test_fact_ids_use_injNNN_prefix(self):
        for s in TEMPORAL_EXPANSION_SCENARIOS:
            sid_short = s.metadata.scenario_id.replace("INJ-", "inj").lower()
            for fact in s.packet.get_all_facts():
                assert fact.fact_id.startswith(f"{sid_short}-fact-")


class TestBuilders:
    def test_inj031_builds(self):
        s = build_inj031_temporal_ongoing_investigation()
        assert s.metadata.scenario_id == "INJ-031"

    def test_inj032_builds(self):
        s = build_inj032_temporal_historical_false_positive()
        assert s.metadata.scenario_id == "INJ-032"

    def test_inj033_builds(self):
        s = build_inj033_temporal_compressed_timeline()
        assert s.metadata.scenario_id == "INJ-033"


class TestLookup:
    def test_get_scenario_by_id(self):
        s = get_temporal_expansion_scenario_by_id("INJ-031")
        assert s.metadata.scenario_id == "INJ-031"

    def test_get_record_by_id(self):
        r = get_temporal_expansion_record_by_id("INJ-033")
        assert r.framing_strategy == "temporal_compressed_timeline"

    def test_unknown_raises(self):
        with pytest.raises(KeyError):
            get_temporal_expansion_record_by_id("INJ-999")

    def test_unknown_scenario_id_raises(self):
        with pytest.raises(KeyError):
            get_temporal_expansion_scenario_by_id("INJ-999")


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
    parts = [str(f.value) for f in scenario.packet.get_all_facts()]
    m = scenario.metadata
    parts.extend([m.name, m.description, m.notes])
    return "\n".join(parts)


@pytest.mark.parametrize(
    "scenario", TEMPORAL_EXPANSION_SCENARIOS,
    ids=[s.metadata.scenario_id for s in TEMPORAL_EXPANSION_SCENARIOS],
)
@pytest.mark.parametrize(
    "regex_name,regex", _FIREWALL_PATTERNS,
    ids=[name for name, _ in _FIREWALL_PATTERNS],
)
def test_firewall_regex_does_not_match(scenario, regex_name, regex):
    text = _concatenated_text(scenario)
    match = regex.search(text)
    assert match is None, (
        f"{scenario.metadata.scenario_id} triggers {regex_name}: "
        f"{match.group() if match else ''!r}"
    )
