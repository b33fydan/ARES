# tests/dialectic/measurement/test_read_depth_frontier_runner.py
"""Runner determinism + the frontier-sanity scientific contract."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    FrontierSummary,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier


def _coord(summary, tier_id, view):
    for c in summary.coordinates:
        if c.tier_id == tier_id and c.view == view:
            return c
    raise AssertionError(f"no coordinate {tier_id}/{view}")


def test_run_is_deterministic():
    a = run_frontier()
    b = run_frontier()
    assert a.to_json() == b.to_json()


def test_emits_four_tiers_two_views_no_anchor():
    s = run_frontier()
    tier_ids = {c.tier_id for c in s.coordinates}
    assert tier_ids == {"v1_field", "v2_structured", "v2_lexical", "v2_canonical"}
    assert "llm_semantic" not in tier_ids
    views = {c.view for c in s.coordinates}
    assert views == {VIEW_STANDALONE, VIEW_CUMULATIVE}
    assert isinstance(s, FrontierSummary)


def test_blind_baseline_tier0_has_zero_detection():
    s = run_frontier()
    c = _coord(s, "v1_field", VIEW_STANDALONE)
    assert c.tpr == 0.0 and c.fpr == 0.0 and c.youden_j == 0.0


def test_standalone_youden_strictly_rises_with_depth():
    s = run_frontier()
    j = {t: _coord(s, t, VIEW_STANDALONE).youden_j
         for t in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical")}
    assert j["v1_field"] < j["v2_structured"] < j["v2_lexical"] < j["v2_canonical"]


def test_cumulative_caps_below_standalone_at_depth3():
    # The trilemma's teeth: keeping the structural rule (cumulative) caps Y
    # below what value-reading alone (standalone tier 3) achieves.
    s = run_frontier()
    standalone3 = _coord(s, "v2_canonical", VIEW_STANDALONE).youden_j
    cumulative3 = _coord(s, "v2_canonical", VIEW_CUMULATIVE).youden_j
    assert cumulative3 < standalone3


def test_semantic_framing_does_not_move_deterministic_tiers():
    s = run_frontier()
    for t in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical"):
        assert _coord(s, t, VIEW_STANDALONE).x_semantic == 0.0


def test_lexical_evasion_moves_tier2_but_tier1_and_tier3_robust():
    s = run_frontier()
    assert _coord(s, "v2_lexical", VIEW_STANDALONE).x_lexical > 0.0
    assert _coord(s, "v1_field", VIEW_STANDALONE).x_lexical == 0.0
    assert _coord(s, "v2_canonical", VIEW_STANDALONE).x_lexical == 0.0


def test_positive_control_flips_tier1_only():
    s = run_frontier()
    by_tier = {}
    for pc in s.positive_control_records:
        if pc.scenario_id.startswith("RDF-M-LEX-001") and pc.view == VIEW_STANDALONE:
            by_tier[pc.tier_id] = pc
    assert by_tier["v1_field"].moved is True
    assert by_tier["v1_field"].controlled_malign_verdict is False
    assert by_tier["v2_lexical"].moved is False
    assert by_tier["v2_lexical"].controlled_malign_verdict is True


def test_m_syn_caught_only_from_tier3():
    # Detection gain tier2->tier3: M-SYN missed by tier 2, caught by tier 3.
    s = run_frontier()
    recs = {(r.tier_id): r for r in s.records
            if r.scenario_id == "RDF-M-SYN-001" and r.view == VIEW_STANDALONE}
    assert recs["v2_lexical"].baseline_malign_verdict is False
    assert recs["v2_canonical"].baseline_malign_verdict is True
