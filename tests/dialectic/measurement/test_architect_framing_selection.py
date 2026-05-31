import json
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios


def _write(tmp_path, rows):
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p


def test_selects_only_llm_scenarios_that_diverged(tmp_path):
    rows = [
        # INJ-001 diverges on llm path
        {"pipeline": "llm", "scenario_id": "INJ-001", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["f1", "f2"]},
        {"pipeline": "llm", "scenario_id": "INJ-001", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["f1"]},
        # INJ-002 stable on llm path
        {"pipeline": "llm", "scenario_id": "INJ-002", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["a"]},
        {"pipeline": "llm", "scenario_id": "INJ-002", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["a"]},
        # light-path divergence must be IGNORED
        {"pipeline": "light", "scenario_id": "INJ-003", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["x"]},
        {"pipeline": "light", "scenario_id": "INJ-003", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["y"]},
    ]
    p = _write(tmp_path, rows)
    assert select_diverging_scenarios(p) == ["INJ-001"]


def test_missing_file_returns_empty(tmp_path):
    assert select_diverging_scenarios(tmp_path / "nope.jsonl") == []
