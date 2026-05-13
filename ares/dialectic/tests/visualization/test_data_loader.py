"""Tests for DataLoader.load_run — Task 3."""

from pathlib import Path

import pytest

from ares.dialectic.visualization.data_loader import PairRecord, load_run

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_load_run_returns_one_record_per_pair():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    assert len(records) == 1
    assert isinstance(records[0], PairRecord)


def test_load_run_extracts_scenario_and_operator():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.scenario_id == "FIX-001"
    assert record.operator == "framing_prefix_v1"


def test_load_run_detects_broad_leakage_from_oracle_citation_drift():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.broad_leakage is True
    assert record.narrow_leakage is False


def test_load_run_extracts_confidence_values():
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    record = records[0]
    assert record.confidence_baseline == 0.9
    assert record.confidence_mutated == 0.9


def test_load_run_raises_on_missing_file():
    with pytest.raises(FileNotFoundError):
        load_run(FIXTURE_DIR / "does_not_exist.jsonl")


def test_pair_record_rejects_invalid_diverging_layer():
    with pytest.raises(ValueError, match="first_diverging_layer"):
        PairRecord(
            scenario_id="INJ-001",
            operator="framing_prefix_v1",
            narrow_leakage=False,
            broad_leakage=False,
            confidence_baseline=0.95,
            confidence_mutated=0.95,
            first_diverging_layer="BadLayer",
        )


def test_load_run_first_diverging_layer_prefers_light_pipeline():
    """Light pipeline's Oracle citation drift must win over LLM pipeline's
    'no divergence' — and if light diverges first, it must be attributed to
    that layer, not the LLM pipeline's result.

    The fixture encodes exactly one divergence: the light-pipeline mutated
    row has oracle_supporting_facts ["a","b","c"] vs baseline ["a","b"].
    The LLM pipeline pair has identical oracle_supporting_facts.
    After the loop-order fix (light before llm), first_diverging_layer must
    be "Oracle" (from the light pipeline), not "None" or any LLM-side layer.
    """
    records = load_run(FIXTURE_DIR / "mini_traces.jsonl")
    fires = [r for r in records if r.broad_leakage]
    assert len(fires) >= 1, "Expected at least one broad-leakage record in fixture"
    assert fires[0].first_diverging_layer == "Oracle"
