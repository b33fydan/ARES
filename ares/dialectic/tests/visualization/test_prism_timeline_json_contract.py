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
    "baseline_llm",
    "mutated_llm",
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


# ────────────────────────────────────────────────────────────────────
# Panel 2 (Confidence Trajectories) contract additions
# ────────────────────────────────────────────────────────────────────
#
# Panel 2 renders one primitive per pair: an arrow from baseline_llm to
# mutated_llm in (architect_confidence, skeptic_confidence,
# oracle_confidence) space when confidence moves, or a sphere at the
# baseline coord when the cycle's confidence held steady. These tests
# lock the data shape Panel 2 depends on:
#   (1) baseline_llm has the three confidence fields, all in [0, 1]
#   (2) mutated_llm has them too (Phase A pipeline drops no-op pairs
#       entirely; no null branch to handle)
#   (3) the dropped-pair count is exactly 2 (locks Session 059 pipeline
#       output shape so a regen with a different no-op count surfaces
#       immediately — see "open items" #5 in the spec for the CLAUDE.md
#       vs. data discrepancy)
#   (4) the single broad-leakage pair has near-zero confidence delta
#       AND a non-trivial citation-surface change — locks Session 059's
#       architectural finding that the broad-leakage signal was in
#       Oracle citation passthrough, not confidence drift. If a future
#       dataset shows confidence drift on broad-leakage, this test
#       fails loud and forces the Panel 2 narrative to update.

CONFIDENCE_FIELDS = ("architect_confidence", "skeptic_confidence", "oracle_confidence")
ZERO_DELTA_THRESHOLD = 0.01

# Session 058.5 audit documented 1 no-op for synonym_substitution_conservative_v2,
# but the live Session 059 pipeline output drops 2 pair_indices.
# Whether the audit text is wrong, the live run had a different no-op count,
# or there's a downstream pipeline artifact is a separate ARES question.
# The visualization reflects what shipped: 2 dropped pairs.
EXPECTED_DROPPED_PAIR_COUNT = 2


def test_every_pair_has_baseline_llm_confidences(timeline: dict) -> None:
    for pair in timeline["pairs"]:
        baseline = pair.get("baseline_llm")
        assert isinstance(baseline, dict), (
            f"Pair {pair['pair_index']} baseline_llm must be a dict, got {type(baseline).__name__}"
        )
        for field in CONFIDENCE_FIELDS:
            value = baseline.get(field)
            assert isinstance(value, (int, float)), (
                f"Pair {pair['pair_index']} baseline_llm.{field} must be numeric, got {type(value).__name__}"
            )
            assert 0.0 <= float(value) <= 1.0, (
                f"Pair {pair['pair_index']} baseline_llm.{field}={value} outside [0.0, 1.0]"
            )


def test_every_pair_has_mutated_llm_confidences(timeline: dict) -> None:
    # Phase A pipeline drops no-op pairs entirely from the JSON.
    # Every delivered pair therefore has a populated mutated_llm dict.
    for pair in timeline["pairs"]:
        mutated = pair.get("mutated_llm")
        assert isinstance(mutated, dict), (
            f"Pair {pair['pair_index']} mutated_llm must be a dict (pipeline drops no-ops), "
            f"got {type(mutated).__name__}"
        )
        for field in CONFIDENCE_FIELDS:
            value = mutated.get(field)
            assert isinstance(value, (int, float)), (
                f"Pair {pair['pair_index']} mutated_llm.{field} must be numeric, got {type(value).__name__}"
            )
            assert 0.0 <= float(value) <= 1.0, (
                f"Pair {pair['pair_index']} mutated_llm.{field}={value} outside [0.0, 1.0]"
            )


def test_dropped_pair_count_locks_pipeline_state(timeline: dict) -> None:
    # Locks the count of pair_indices missing from the global enumeration.
    # Session 059 produces 2 dropped indices (3 and 4). Any change to this
    # count means the pipeline ran differently — Panel 2's "N visible
    # primitives per operator" expectations would silently drift.
    pairs = timeline["pairs"]
    indices = [p["pair_index"] for p in pairs]
    enumeration_size = max(indices) + 1
    delivered = len(indices)
    dropped = enumeration_size - delivered
    assert dropped == EXPECTED_DROPPED_PAIR_COUNT, (
        f"Expected {EXPECTED_DROPPED_PAIR_COUNT} dropped pairs from the global enumeration "
        f"(max_index={max(indices)}, delivered={delivered}, dropped={dropped}). "
        f"If the pipeline now drops more or fewer no-ops, the visualization may need to update."
    )


def test_broad_leakage_pair_has_zero_confidence_delta_per_session_059(timeline: dict) -> None:
    # Session 059's documented architectural finding: the broad-leakage
    # signal was Oracle citation-surface passthrough (the Oracle inherits
    # the Architect's cite-set drift), NOT confidence drift. The Oracle's
    # decision (outcome + confidence) is preserved deterministically.
    # Lock this with a paired assertion:
    #   (a) confidence delta is near-zero on all three axes
    #   (b) the citation surface IS different (architect_cited_facts
    #       differs OR oracle_supporting_facts differs between baseline
    #       and mutated)
    # If a future dataset shows confidence drift on broad-leakage, (a)
    # fails and Panel 2's renderer (which puts the broad-leakage pair as
    # a glowing red sphere AT the baseline coord) needs to update to
    # render an arrow instead.
    drift_pairs = [p for p in timeline["pairs"] if p["broad_leakage"]]
    assert len(drift_pairs) == 1, f"Expected exactly 1 broad_leakage pair, found {len(drift_pairs)}"
    pair = drift_pairs[0]
    baseline = pair["baseline_llm"]
    mutated = pair["mutated_llm"]

    # (a) Near-zero confidence delta
    deltas = [abs(float(mutated[f]) - float(baseline[f])) for f in CONFIDENCE_FIELDS]
    assert max(deltas) < ZERO_DELTA_THRESHOLD, (
        f"broad_leakage pair {pair['pair_index']}: confidence deltas {deltas} include one "
        f">= {ZERO_DELTA_THRESHOLD}. Session 059 finding was citation-surface drift only — "
        f"this would invert it. Update Panel 2 renderer + spec narrative."
    )

    # (b) Citation surface IS different
    arch_baseline_cites = baseline.get("architect_cited_facts", [])
    arch_mutated_cites = mutated.get("architect_cited_facts", [])
    oracle_baseline_sup = baseline.get("oracle_supporting_facts", [])
    oracle_mutated_sup = mutated.get("oracle_supporting_facts", [])
    citation_surface_changed = (
        arch_baseline_cites != arch_mutated_cites
        or oracle_baseline_sup != oracle_mutated_sup
    )
    assert citation_surface_changed, (
        f"broad_leakage pair {pair['pair_index']}: neither architect_cited_facts nor "
        f"oracle_supporting_facts changed between baseline and mutated. The leakage signal "
        f"should be IN the citation surface per Session 059 — if it isn't, the pipeline output "
        f"is inconsistent with the documented finding."
    )
