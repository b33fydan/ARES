# tests/dialectic/measurement/test_read_depth_frontier_schema.py
"""Tests for the read-depth frontier result schema."""
from __future__ import annotations

import dataclasses

import pytest
from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEW_CUMULATIVE,
    VIEW_STANDALONE,
    FrontierConfig,
    FrontierSummary,
    PositiveControlRecord,
    ScenarioVerdictRecord,
    TierCoordinate,
)


def _coord(tier="v2_lexical", view=VIEW_STANDALONE):
    return TierCoordinate(
        tier_id=tier, view=view, x_semantic=0.0, x_lexical=0.4,
        tpr=0.75, fpr=0.25, youden_j=0.5, n_malign=4, n_benign=4,
    )


def test_views_constants():
    assert VIEW_STANDALONE == "standalone"
    assert VIEW_CUMULATIVE == "cumulative"


def test_tier_coordinate_roundtrip():
    c = _coord()
    d = c.to_dict()
    assert d["tier_id"] == "v2_lexical"
    assert d["youden_j"] == 0.5
    assert TierCoordinate.from_dict(d) == c


def test_summary_roundtrip_via_json():
    rec = ScenarioVerdictRecord(
        scenario_id="RDF-M-LEX-001", tier_id="v2_lexical",
        view=VIEW_STANDALONE, is_malign=True, stratum="M-lex",
        baseline_malign_verdict=True, malign_score=0.8,
        n_mut_semantic=2, flips_semantic=0, n_mut_lexical=2, flips_lexical=1,
    )
    pc = PositiveControlRecord(
        scenario_id="RDF-M-LEX-001", tier_id="v1_field", view=VIEW_STANDALONE,
        baseline_malign_verdict=True, controlled_malign_verdict=False, moved=True,
    )
    cfg = FrontierConfig(
        operating_point=0.0,
        semantic_operator_names=("framing_prefix_v1",),
        lexical_operator_names=("exe_to_binary_v1",),
        seed=0,
    )
    summary = FrontierSummary(
        coordinates=(_coord(),),
        records=(rec,),
        positive_control_records=(pc,),
        corpus_digest="abc123",
        config=cfg,
    )
    restored = FrontierSummary.from_dict(summary.to_dict())
    assert restored == summary
    # to_json must be deterministic (sorted keys).
    assert summary.to_json() == summary.to_json()


def test_frozen():
    c = _coord()
    with pytest.raises(dataclasses.FrozenInstanceError):
        c.tpr = 0.1  # type: ignore[misc]
