"""Tests for the central injection-corpus registry.

Covers:
    1. Scenario aggregation across modules (count, membership)
    2. Category mapping correctness (DIRECT/FRAMING/PROPAGATION)
    3. by_category / by_difficulty / by_framing_strategy queries
    4. scenario_count / category_counts arithmetic
    5. Frozen-dataclass immutability
    6. No duplicate scenario IDs / fact IDs after aggregation
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.scripts.injection_corpus import get_injection_scenarios
from ares.dialectic.scripts.injection_corpus_b_framing import (
    get_framing_records,
    get_framing_scenarios,
)
from ares.dialectic.scripts.injection_registry import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistry,
    build_registry,
)


REGISTRY = build_registry()


# =============================================================================
# Aggregation
# =============================================================================


def test_registry_is_frozen_dataclass():
    assert isinstance(REGISTRY, InjectionCorpusRegistry)
    with pytest.raises(FrozenInstanceError):
        REGISTRY.scenarios = ()  # type: ignore[misc]


def test_scenario_count_matches_sum_of_modules():
    assert REGISTRY.scenario_count() == (
        len(get_injection_scenarios()) + len(get_framing_scenarios())
    )


def test_scenario_count_is_twenty_seven():
    assert REGISTRY.scenario_count() == 27


def test_all_scenarios_contains_every_source_scenario():
    seed_ids = {s.metadata.scenario_id for s in get_injection_scenarios()}
    framing_ids = {s.metadata.scenario_id for s in get_framing_scenarios()}
    reg_ids = {s.metadata.scenario_id for s in REGISTRY.all_scenarios()}
    assert seed_ids <= reg_ids
    assert framing_ids <= reg_ids


def test_records_match_framing_module():
    assert REGISTRY.records == get_framing_records()


# =============================================================================
# Category mapping
# =============================================================================


def test_category_counts_match_plan():
    assert REGISTRY.category_counts() == {
        DIRECT: 4,
        FRAMING: 19,
        PROPAGATION: 4,
    }


def test_by_category_direct_returns_four_seed_scenarios():
    direct = REGISTRY.by_category(DIRECT)
    assert len(direct) == 4
    ids = {s.metadata.scenario_id for s in direct}
    assert ids == {"INJ-001", "INJ-002", "INJ-003", "INJ-004"}


def test_by_category_framing_returns_nineteen_scenarios():
    framing = REGISTRY.by_category(FRAMING)
    assert len(framing) == 19
    ids = {s.metadata.scenario_id for s in framing}
    expected = {f"INJ-{n:03d}" for n in (5, 6, 7, 8)}
    expected |= {f"INJ-{n:03d}" for n in range(13, 28)}
    assert ids == expected


def test_by_category_propagation_returns_four_scenarios():
    prop = REGISTRY.by_category(PROPAGATION)
    assert len(prop) == 4
    ids = {s.metadata.scenario_id for s in prop}
    assert ids == {"INJ-009", "INJ-010", "INJ-011", "INJ-012"}


def test_by_category_unknown_label_raises():
    with pytest.raises(KeyError):
        REGISTRY.by_category("UNKNOWN_CATEGORY")


# =============================================================================
# Difficulty
# =============================================================================


def test_by_difficulty_five_returns_all_injection_scenarios():
    """Every scenario in every injection corpus module is tier 5."""
    tier5 = REGISTRY.by_difficulty(5)
    assert len(tier5) == REGISTRY.scenario_count()


def test_by_difficulty_unknown_tier_returns_empty():
    assert REGISTRY.by_difficulty(99) == ()


# =============================================================================
# Framing strategies
# =============================================================================


def test_framing_strategies_are_fifteen_unique():
    strategies = REGISTRY.framing_strategies()
    assert len(strategies) == 15
    assert len(set(strategies)) == 15


def test_by_framing_strategy_returns_exactly_one_scenario():
    for strategy in REGISTRY.framing_strategies():
        matched = REGISTRY.by_framing_strategy(strategy)
        assert len(matched) == 1, (
            f"Strategy {strategy!r} matched {len(matched)} scenarios; "
            "expected exactly one"
        )


def test_by_framing_strategy_unknown_returns_empty():
    assert REGISTRY.by_framing_strategy("not_a_real_strategy") == ()


# =============================================================================
# Uniqueness after aggregation
# =============================================================================


def test_no_duplicate_scenario_ids_after_aggregation():
    ids = [s.metadata.scenario_id for s in REGISTRY.all_scenarios()]
    assert len(ids) == len(set(ids))


def test_no_duplicate_fact_ids_after_aggregation():
    fact_ids: list[str] = []
    for s in REGISTRY.all_scenarios():
        for fact in s.packet.get_all_facts():
            fact_ids.append(fact.fact_id)
    assert len(fact_ids) == len(set(fact_ids))


# =============================================================================
# Category-map immutability
# =============================================================================


def test_category_mapping_is_read_only():
    with pytest.raises(TypeError):
        REGISTRY.categories["INJ-001"] = "PROPAGATION"  # type: ignore[index]
