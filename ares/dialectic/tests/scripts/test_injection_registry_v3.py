"""Tests for the Session 050 v3 injection-corpus registry."""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.scripts.injection_corpus_b_temporal_expansion import (
    TEMPORAL_EXPANSION_SCENARIOS,
)
from ares.dialectic.scripts.injection_registry_v3 import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistryV3,
    build_registry_v3,
)


REGISTRY = build_registry_v3()


class TestComposition:
    def test_is_frozen(self):
        with pytest.raises(FrozenInstanceError):
            REGISTRY.scenarios = ()  # type: ignore[misc]

    def test_v2_reference_preserved(self):
        assert REGISTRY.v2 is not None
        assert REGISTRY.v2.scenario_count() == 30

    def test_extension_is_three_scenarios(self):
        assert len(REGISTRY.extension_scenarios) == 3
        assert len(REGISTRY.extension_records) == 3

    def test_scenario_count(self):
        assert REGISTRY.scenario_count() == 33

    def test_scenarios_combine_v2_and_extension(self):
        assert len(REGISTRY.scenarios) == 30 + 3

    def test_records_combine_v2_and_extension(self):
        # v2 had 15 + 3 = 18 records. v3 adds 3 → 21.
        assert len(REGISTRY.records) == 21


class TestCoverage:
    def test_every_temporal_scenario_present(self):
        ext_ids = {s.metadata.scenario_id for s in TEMPORAL_EXPANSION_SCENARIOS}
        reg_ids = {s.metadata.scenario_id for s in REGISTRY.all_scenarios()}
        assert ext_ids <= reg_ids

    def test_no_duplicate_ids(self):
        ids = [s.metadata.scenario_id for s in REGISTRY.all_scenarios()]
        assert len(ids) == len(set(ids))


class TestCategories:
    def test_category_counts(self):
        assert REGISTRY.category_counts() == {
            DIRECT: 4,
            FRAMING: 25,
            PROPAGATION: 4,
        }

    def test_framing_includes_temporal_expansion(self):
        framing_ids = {s.metadata.scenario_id for s in REGISTRY.by_category(FRAMING)}
        assert {"INJ-031", "INJ-032", "INJ-033"} <= framing_ids

    def test_direct_count(self):
        assert len(REGISTRY.by_category(DIRECT)) == 4

    def test_propagation_count(self):
        assert len(REGISTRY.by_category(PROPAGATION)) == 4

    def test_framing_count(self):
        assert len(REGISTRY.by_category(FRAMING)) == 25

    def test_unknown_category_raises(self):
        with pytest.raises(KeyError):
            REGISTRY.by_category("UNKNOWN")


class TestTemporalFamily:
    def test_temporal_family_count_is_five(self):
        assert len(REGISTRY.temporal_records()) == 5

    def test_temporal_family_members(self):
        temporal = REGISTRY.temporal_records()
        strategies = {r.framing_strategy for r in temporal}
        assert strategies == {
            "temporal_patched_since",
            "temporal_active_exploitation_claim",
            "temporal_ongoing_investigation",
            "temporal_historical_false_positive",
            "temporal_compressed_timeline",
        }

    def test_temporal_members_all_map_to_framing(self):
        for r in REGISTRY.temporal_records():
            sid = r.scenario.metadata.scenario_id
            assert REGISTRY.categories[sid] == FRAMING


class TestFramingStrategies:
    def test_framing_strategies_count(self):
        # 18 from v2 + 3 temporal = 21.
        assert len(REGISTRY.framing_strategies()) == 21

    def test_all_strategies_unique(self):
        strategies = [r.framing_strategy for r in REGISTRY.records]
        assert len(strategies) == len(set(strategies))

    def test_by_strategy_ongoing_investigation(self):
        hits = REGISTRY.by_framing_strategy("temporal_ongoing_investigation")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-031"

    def test_by_strategy_historical_fp(self):
        hits = REGISTRY.by_framing_strategy("temporal_historical_false_positive")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-032"

    def test_by_strategy_compressed_timeline(self):
        hits = REGISTRY.by_framing_strategy("temporal_compressed_timeline")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-033"


class TestByScenarioId:
    def test_finds_v1_scenario(self):
        assert REGISTRY.by_scenario_id("INJ-001").metadata.scenario_id == "INJ-001"

    def test_finds_v2_scenario(self):
        assert REGISTRY.by_scenario_id("INJ-028").metadata.scenario_id == "INJ-028"

    def test_finds_v3_scenario(self):
        assert REGISTRY.by_scenario_id("INJ-031").metadata.scenario_id == "INJ-031"

    def test_unknown_raises_keyerror(self):
        with pytest.raises(KeyError):
            REGISTRY.by_scenario_id("INJ-999")


class TestAuthorityFamilyUnchanged:
    def test_authority_family_size_is_six(self):
        assert len(REGISTRY.authority_records()) == 6


class TestDifficulty:
    def test_every_scenario_tier_5_or_lower(self):
        for s in REGISTRY.all_scenarios():
            assert 1 <= s.metadata.difficulty_tier <= 5
