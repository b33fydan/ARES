import json
from pathlib import Path

import pytest

from ares.dialectic.visualization.cycle_trace_builder import build_cycle_timeline
from ares.dialectic.visualization.cycle_trace import CycleTimelineV2


def _row(
    *,
    scenario_id: str,
    operator: str | None,
    pipeline: str,
    pair_index: int,
    is_baseline: bool,
    architect_facts=("f1", "f2"),
    architect_conf=0.95,
    skeptic_facts=("f1",),
    skeptic_conf=0.3,
    oracle_facts=("f1", "f2"),
    oracle_outcome="threat_confirmed",
    final_outcome="threat_confirmed",
) -> dict:
    cycle_kind = "baseline" if is_baseline else "mutated"
    op_part = "" if operator is None else f"-{operator}"
    return {
        "cycle_id": f"{cycle_kind}-{scenario_id}{op_part}-{pipeline}",
        "scenario_id": scenario_id,
        "operator_name": operator,
        "pair_index": pair_index,
        "is_baseline": is_baseline,
        "pipeline": pipeline,
        "architect_message_type": "hypothesis",
        "architect_confidence": architect_conf,
        "architect_cited_facts": list(architect_facts),
        "skeptic_message_type": "rebuttal",
        "skeptic_confidence": skeptic_conf,
        "skeptic_cited_facts": list(skeptic_facts),
        "skeptic_triggered_rules": [],
        "oracle_outcome": oracle_outcome,
        "oracle_confidence": 0.95,
        "oracle_supporting_facts": list(oracle_facts),
        "final_outcome": final_outcome,
        "final_confidence": 0.95,
        "cost_usd": 0.01,
        "tokens_in": 100,
        "tokens_out": 50,
        "elapsed_ms": 1000.0,
    }


def _write_jsonl(tmp_path: Path, rows: list[dict]) -> Path:
    p = tmp_path / "traces.jsonl"
    p.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    return p


def test_build_cycle_timeline_returns_v2(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    assert isinstance(timeline, CycleTimelineV2)
    assert timeline.schema_version == "v2"
    assert timeline.run_id == "r1"


def test_build_cycle_timeline_emits_one_pair_per_operator(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator="op-b", pipeline="llm", pair_index=1, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator="op-b", pipeline="light", pair_index=1, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    operators = {p.operator for p in timeline.pairs}
    assert operators == {"op-a", "op-b"}
    assert len(timeline.pairs) == 2


def test_build_cycle_timeline_skips_baseline_only_groups(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
    ]
    with pytest.raises(ValueError, match="No pairs"):
        build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")


def test_build_cycle_timeline_detects_citation_drift(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True,
             architect_facts=("f1", "f2", "f3")),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False,
             architect_facts=("f1", "f2")),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    # bit index 2 = cited_facts_changed (per InfluenceLeakage bit order)
    assert pair.llm_architect_bits[2] is True


def test_build_cycle_timeline_no_drift_means_all_bits_false(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    assert pair.llm_architect_bits == (False, False, False, False)
    assert pair.llm_skeptic_bits == (False, False, False, False)
    assert pair.llm_oracle_bits == (False, False, False, False)
    assert pair.llm_final_bits == (False, False, False, False)


def test_build_cycle_timeline_orders_operators_deterministically(tmp_path):
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="zeta", pipeline="llm", pair_index=2, is_baseline=False),
        _row(scenario_id="INJ-001", operator="alpha", pipeline="llm", pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light", pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="zeta", pipeline="light", pair_index=2, is_baseline=False),
        _row(scenario_id="INJ-001", operator="alpha", pipeline="light", pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    assert timeline.operators == ("alpha", "zeta")


def test_build_cycle_timeline_raises_on_missing_file(tmp_path):
    with pytest.raises(FileNotFoundError):
        build_cycle_timeline(tmp_path / "does_not_exist.jsonl", run_id="r1")


def test_build_cycle_timeline_detects_confidence_drift(tmp_path):
    # Architect confidence drops from 0.95 to 0.80 — delta 0.15 > 0.10 threshold,
    # so bit index 3 (confidence_drift_exceeded) must fire on architect layer.
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm",
             pair_index=0, is_baseline=True, architect_conf=0.95),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm",
             pair_index=0, is_baseline=False, architect_conf=0.80),
        _row(scenario_id="INJ-001", operator=None, pipeline="light",
             pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light",
             pair_index=0, is_baseline=False),
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    assert pair.llm_architect_bits[3] is True  # confidence_drift_exceeded


def test_build_cycle_timeline_flags_broad_leakage_on_oracle_facts_change(tmp_path):
    # broad_leakage fires when the light-pipeline broad reading
    # (Light Skeptic + Oracle + Final) leaks at any of those layers.
    # Oracle's cited_facts changing is the Session-059 INJ-001 pattern.
    rows = [
        _row(scenario_id="INJ-001", operator=None, pipeline="llm",
             pair_index=0, is_baseline=True),
        _row(scenario_id="INJ-001", operator="op-a", pipeline="llm",
             pair_index=0, is_baseline=False),
        _row(scenario_id="INJ-001", operator=None, pipeline="light",
             pair_index=0, is_baseline=True,
             oracle_facts=("f1", "f2", "f3")),  # baseline cites 3 facts
        _row(scenario_id="INJ-001", operator="op-a", pipeline="light",
             pair_index=0, is_baseline=False,
             oracle_facts=("f1", "f2")),  # mutated drops f3
    ]
    timeline = build_cycle_timeline(_write_jsonl(tmp_path, rows), run_id="r1")
    pair = timeline.pairs[0]
    assert pair.broad_leakage is True
