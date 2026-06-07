# tests/dialectic/measurement/test_read_depth_frontier_report.py
"""Tests for the frontier markdown + JSON emitters."""
from __future__ import annotations

import json

from ares.dialectic.measurement.read_depth_frontier_report import (
    coordinates_json,
    render_report,
)
from ares.dialectic.measurement.read_depth_frontier_runner import run_frontier


def test_render_report_has_both_views_and_all_tiers():
    md = render_report(run_frontier())
    assert "standalone" in md
    assert "cumulative" in md
    for tier in ("v1_field", "v2_structured", "v2_lexical", "v2_canonical"):
        assert tier in md
    # Carry-forward #2 precision note must be present.
    assert "high_stage_without_authorization" in md or "M2" in md


def test_coordinates_json_is_valid_and_has_eight_points():
    payload = coordinates_json(run_frontier())
    data = json.loads(payload)
    assert len(data["coordinates"]) == 8  # 4 tiers x 2 views
    assert data["corpus_digest"]
