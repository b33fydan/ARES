"""JSON contract guard for the Prism renderer.

prism-timeline.json is consumed by the standalone HTML renderer at
skyframe-main/assets/ares/prism.html. These tests lock the JSON shape
so that a future regen with renamed fields fails fast on the ARES side,
not silently in the browser.
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
TIMELINE_PATH = REPO_ROOT / "docs" / "marketing" / "prism-timeline.json"

REQUIRED_TOP_LEVEL_KEYS = frozenset({"operators", "pairs", "run_id", "schema_version"})
REQUIRED_PAIR_KEYS = frozenset({
    "pair_index",
    "operator",
    "scenario_id",
    "broad_leakage",
    "narrow_leakage",
    "first_diverging_layer",
})
EXPECTED_OPERATORS = (
    "framing_prefix_v1",
    "framing_suffix_v1",
    "synonym_substitution_conservative_v2",
)
VALID_DIVERGING_LAYERS = frozenset({"Architect", "Skeptic", "Oracle", "Final"})


@pytest.fixture(scope="module")
def timeline() -> dict:
    assert TIMELINE_PATH.exists(), f"prism-timeline.json missing at {TIMELINE_PATH}"
    with TIMELINE_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_top_level_keys(timeline: dict) -> None:
    assert REQUIRED_TOP_LEVEL_KEYS.issubset(timeline.keys()), (
        f"Missing top-level keys: {REQUIRED_TOP_LEVEL_KEYS - timeline.keys()}"
    )


def test_pair_count_is_98(timeline: dict) -> None:
    assert len(timeline["pairs"]) == 98


def test_exactly_one_broad_leakage_pair(timeline: dict) -> None:
    count = sum(1 for p in timeline["pairs"] if p["broad_leakage"])
    assert count == 1, f"Expected exactly 1 broad_leakage pair, found {count}"


def test_drift_pair_first_diverging_layer_is_valid(timeline: dict) -> None:
    drift_pairs = [p for p in timeline["pairs"] if p["broad_leakage"]]
    assert len(drift_pairs) == 1
    layer = drift_pairs[0]["first_diverging_layer"]
    assert layer in VALID_DIVERGING_LAYERS, (
        f"first_diverging_layer={layer!r} not in {VALID_DIVERGING_LAYERS}"
    )


def test_every_pair_has_required_keys(timeline: dict) -> None:
    for pair in timeline["pairs"]:
        missing = REQUIRED_PAIR_KEYS - pair.keys()
        assert not missing, f"Pair {pair.get('pair_index')} missing keys: {missing}"


def test_operators_equal_expected(timeline: dict) -> None:
    assert tuple(timeline["operators"]) == EXPECTED_OPERATORS


def test_each_pair_operator_is_in_operators_list(timeline: dict) -> None:
    operators = set(timeline["operators"])
    for pair in timeline["pairs"]:
        assert pair["operator"] in operators, (
            f"Pair {pair['pair_index']} operator={pair['operator']!r} not in {operators}"
        )


def test_pair_indices_are_unique_sorted_and_nonneg(timeline: dict) -> None:
    # The pipeline emits pair_index from the global 33 × 3 enumeration (max 99).
    # Some pairs are dropped when an operator is a no-op on a given scenario
    # (Session 058.5: synonym_substitution_conservative_v2 has 1 no-op),
    # so the index sequence has documented gaps. The renderer requires only
    # uniqueness, monotonic order, and non-negative values for its activation
    # timeline to make sense.
    indices = [p["pair_index"] for p in timeline["pairs"]]
    assert len(set(indices)) == len(indices), "pair_index values must be unique"
    assert indices == sorted(indices), "pair_index must be monotonically increasing"
    assert min(indices) >= 0, "pair_index must be non-negative"
    assert max(indices) < 200, f"max pair_index {max(indices)} unexpectedly large (sanity bound)"
