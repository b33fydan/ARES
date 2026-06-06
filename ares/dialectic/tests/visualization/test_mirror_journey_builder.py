from __future__ import annotations

import json
from pathlib import Path

import pytest

from ares.dialectic.visualization.mirror_journey_builder import (
    build_mirror_journey,
    jaccard_distance,
)

F = [f"inj020-fact-00{i}" for i in range(1, 6)]  # f1..f5


def _row(condition, arch, skep, outcome="threat_dismissed", ri=0):
    return {
        "scenario_id": "INJ-020", "condition": condition, "resample_index": ri,
        "architect_cited_facts": arch, "skeptic_cited_facts": skep,
        "final_outcome": outcome,
    }


def _write_traces(tmp_path: Path) -> Path:
    rows = []
    # baseline: arch all 5, skep {f1,f2,f4} (modal 4 of 5) + one minority set
    for ri in range(4):
        rows.append(_row("baseline", F, [F[0], F[1], F[3]], ri=ri))
    rows.append(_row("baseline", F, [F[0], F[1], F[3], F[4]], ri=4))  # minority
    # framing: arch {f3}, skep all 5
    for ri in range(5):
        rows.append(_row("framing:framing_prefix_v1", [F[2]], F, ri=ri))
    # a non-hero scenario row that must be ignored
    rows.append({"scenario_id": "INJ-001", "condition": "baseline", "resample_index": 0,
                 "architect_cited_facts": [F[0]], "skeptic_cited_facts": [F[0]],
                 "final_outcome": "threat_confirmed"})
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p


def test_jaccard_distance_basic():
    assert jaccard_distance({"a", "b", "c", "d", "e"}, {"c"}) == pytest.approx(0.8)
    assert jaccard_distance({"a", "b", "d"}, {"a", "b", "c", "d", "e"}) == pytest.approx(0.4)
    assert jaccard_distance(set(), set()) == 0.0


def test_builder_extracts_hero(tmp_path):
    journey = build_mirror_journey(_write_traces(tmp_path), run_id="TESTRUN")
    h = journey.hero
    assert h.scenario_id == "INJ-020"
    assert h.threat_fact == "inj020-fact-003"
    assert h.architect.baseline_facts == tuple(F)        # all 5
    assert h.architect.framed_facts == ("inj020-fact-003",)
    assert h.architect.jaccard == pytest.approx(0.8)
    assert h.architect.direction == "collapse"
    assert h.skeptic.baseline_facts == ("inj020-fact-001", "inj020-fact-002", "inj020-fact-004")
    assert h.skeptic.framed_facts == tuple(F)
    assert h.skeptic.jaccard == pytest.approx(0.4)
    assert h.skeptic.direction == "expand"
    assert h.verdict == "threat_dismissed"
    assert h.verdict_held_fraction == 1.0


def test_builder_landscape_constants(tmp_path):
    j = build_mirror_journey(_write_traces(tmp_path), run_id="TESTRUN")
    assert (j.landscape.opposed, j.landscape.aligned, j.landscape.single, j.landscape.none_) == (4, 5, 20, 21)
    assert (j.landscape.architect_real, j.landscape.skeptic_real, j.landscape.n_scenarios) == (11, 9, 17)


def test_builder_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_mirror_journey(tmp_path / "nope.jsonl", run_id="X")
