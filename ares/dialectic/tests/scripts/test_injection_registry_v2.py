"""Tests for the Session 049 v2 injection-corpus registry.

Covers:
    1. v2 composes v1 correctly — v1 scenarios and records pass through.
    2. Authority family count = 6 (3 Session 047 + 3 Session 049).
    3. Total scenario count = 30.
    4. Category mapping includes the 3 Session 049 additions as FRAMING.
    5. by_category / by_difficulty / by_framing_strategy / by_scenario_id
       all work across the combined population.
    6. Frozen dataclass immutability.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.scripts.injection_corpus import get_injection_scenarios
from ares.dialectic.scripts.injection_corpus_b_authority_expansion import (
    AUTHORITY_EXPANSION_SCENARIOS,
)
from ares.dialectic.scripts.injection_corpus_b_framing import (
    get_framing_scenarios,
)
from ares.dialectic.scripts.injection_registry_v2 import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistryV2,
    build_registry_v2,
)


REGISTRY = build_registry_v2()


# =============================================================================
# Composition
# =============================================================================


class TestComposition:
    def test_is_frozen_dataclass(self):
        assert isinstance(REGISTRY, InjectionCorpusRegistryV2)
        with pytest.raises(FrozenInstanceError):
            REGISTRY.scenarios = ()  # type: ignore[misc]

    def test_v1_reference_preserved(self):
        assert REGISTRY.v1 is not None
        assert REGISTRY.v1.scenario_count() == 27

    def test_extension_is_three_scenarios(self):
        assert len(REGISTRY.extension_scenarios) == 3
        assert len(REGISTRY.extension_records) == 3

    def test_scenarios_combine_v1_and_extension(self):
        assert len(REGISTRY.scenarios) == 27 + 3

    def test_scenario_count_matches_expected(self):
        assert REGISTRY.scenario_count() == 30

    def test_records_combine_v1_and_extension(self):
        # v1 has 15 framing records; v2 adds 3.
        assert len(REGISTRY.records) == 15 + 3


# =============================================================================
# Coverage invariants
# =============================================================================


class TestCoverage:
    def test_every_seed_injection_scenario_present(self):
        seed_ids = {s.metadata.scenario_id for s in get_injection_scenarios()}
        reg_ids = {s.metadata.scenario_id for s in REGISTRY.all_scenarios()}
        assert seed_ids <= reg_ids

    def test_every_framing_scenario_present(self):
        framing_ids = {s.metadata.scenario_id for s in get_framing_scenarios()}
        reg_ids = {s.metadata.scenario_id for s in REGISTRY.all_scenarios()}
        assert framing_ids <= reg_ids

    def test_every_authority_expansion_scenario_present(self):
        auth_ids = {
            s.metadata.scenario_id for s in AUTHORITY_EXPANSION_SCENARIOS
        }
        reg_ids = {s.metadata.scenario_id for s in REGISTRY.all_scenarios()}
        assert auth_ids <= reg_ids

    def test_no_duplicate_scenario_ids(self):
        ids = [s.metadata.scenario_id for s in REGISTRY.all_scenarios()]
        assert len(ids) == len(set(ids))


# =============================================================================
# Categories
# =============================================================================


class TestCategories:
    def test_category_counts(self):
        assert REGISTRY.category_counts() == {
            DIRECT: 4,
            FRAMING: 22,
            PROPAGATION: 4,
        }

    def test_by_category_direct(self):
        direct = REGISTRY.by_category(DIRECT)
        assert len(direct) == 4
        ids = {s.metadata.scenario_id for s in direct}
        assert ids == {"INJ-001", "INJ-002", "INJ-003", "INJ-004"}

    def test_by_category_framing_count(self):
        framing = REGISTRY.by_category(FRAMING)
        assert len(framing) == 22

    def test_by_category_framing_includes_authority_expansion(self):
        framing_ids = {s.metadata.scenario_id for s in REGISTRY.by_category(FRAMING)}
        assert {"INJ-028", "INJ-029", "INJ-030"} <= framing_ids

    def test_by_category_propagation(self):
        prop = REGISTRY.by_category(PROPAGATION)
        assert len(prop) == 4

    def test_unknown_category_raises(self):
        with pytest.raises(KeyError):
            REGISTRY.by_category("UNKNOWN")

    def test_authority_expansion_ids_mapped_to_framing(self):
        for sid in ("INJ-028", "INJ-029", "INJ-030"):
            assert REGISTRY.categories[sid] == FRAMING


# =============================================================================
# Framing strategies / authority family
# =============================================================================


class TestFramingStrategies:
    def test_authority_family_count_is_six(self):
        auth = REGISTRY.authority_records()
        assert len(auth) == 6

    def test_authority_family_strategies(self):
        auth = REGISTRY.authority_records()
        strategies = {r.framing_strategy for r in auth}
        assert strategies == {
            "authority_vendor_implication",
            "authority_industry_consensus",
            "authority_passive_voice_attribution",
            "authority_credentialed_source",
            "authority_automated_system",
            "authority_tool_output",
        }

    def test_framing_strategies_unique(self):
        strategies = [r.framing_strategy for r in REGISTRY.records]
        assert len(strategies) == len(set(strategies))

    def test_framing_strategies_count_is_eighteen(self):
        # 15 (Session 047 expansion) + 3 (Session 049 authority) = 18.
        assert len(REGISTRY.framing_strategies()) == 18

    def test_by_framing_strategy_authority_credentialed_source(self):
        hits = REGISTRY.by_framing_strategy("authority_credentialed_source")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-028"

    def test_by_framing_strategy_authority_automated_system(self):
        hits = REGISTRY.by_framing_strategy("authority_automated_system")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-029"

    def test_by_framing_strategy_authority_tool_output(self):
        hits = REGISTRY.by_framing_strategy("authority_tool_output")
        assert len(hits) == 1
        assert hits[0].metadata.scenario_id == "INJ-030"

    def test_by_framing_strategy_unknown_returns_empty(self):
        hits = REGISTRY.by_framing_strategy("nonexistent_strategy")
        assert hits == ()


# =============================================================================
# by_scenario_id
# =============================================================================


class TestByScenarioId:
    def test_finds_v1_scenario(self):
        s = REGISTRY.by_scenario_id("INJ-001")
        assert s.metadata.scenario_id == "INJ-001"

    def test_finds_session_047_expansion(self):
        s = REGISTRY.by_scenario_id("INJ-013")
        assert s.metadata.scenario_id == "INJ-013"

    def test_finds_session_049_addition(self):
        s = REGISTRY.by_scenario_id("INJ-028")
        assert s.metadata.scenario_id == "INJ-028"

    def test_unknown_raises_keyerror(self):
        with pytest.raises(KeyError):
            REGISTRY.by_scenario_id("INJ-999")


# =============================================================================
# Difficulty tier
# =============================================================================


class TestDifficultyTier:
    def test_every_scenario_has_positive_tier(self):
        for s in REGISTRY.all_scenarios():
            assert s.metadata.difficulty_tier >= 1

    def test_tier_five_includes_framing_expansion_and_authority_ext(self):
        tier_five = REGISTRY.by_difficulty(5)
        ids = {s.metadata.scenario_id for s in tier_five}
        assert {"INJ-013", "INJ-028", "INJ-029", "INJ-030"} <= ids
