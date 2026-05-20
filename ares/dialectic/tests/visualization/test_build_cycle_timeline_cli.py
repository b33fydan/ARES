import json
import subprocess
import sys
from pathlib import Path


def _row(**overrides) -> dict:
    base = dict(
        cycle_id="cid",
        scenario_id="INJ-001",
        operator_name=None,
        pair_index=0,
        is_baseline=True,
        pipeline="llm",
        architect_message_type="hypothesis",
        architect_confidence=0.95,
        architect_cited_facts=["f1"],
        skeptic_message_type="rebuttal",
        skeptic_confidence=0.3,
        skeptic_cited_facts=["f1"],
        skeptic_triggered_rules=[],
        oracle_outcome="threat_confirmed",
        oracle_confidence=0.95,
        oracle_supporting_facts=["f1"],
        final_outcome="threat_confirmed",
        final_confidence=0.95,
        cost_usd=0.01,
        tokens_in=100,
        tokens_out=50,
        elapsed_ms=1000.0,
    )
    base.update(overrides)
    return base


def _write_min_jsonl(tmp_path: Path) -> Path:
    rows = [
        _row(),
        _row(operator_name="op-a", is_baseline=False, cycle_id="m-a-llm"),
        _row(pipeline="light", cycle_id="b-light"),
        _row(operator_name="op-a", is_baseline=False, pipeline="light",
             cycle_id="m-a-light"),
    ]
    p = tmp_path / "traces.jsonl"
    p.write_text(
        "\n".join(json.dumps(r, sort_keys=True) for r in rows) + "\n",
        encoding="utf-8",
    )
    return p


def test_cli_writes_json(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
    payload = json.loads(out.read_text(encoding="utf-8"))
    assert payload["schema_version"] == "v2"
    assert payload["run_id"] == "test-run"


def test_cli_reports_pair_count(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert "1 pair" in result.stdout


def test_cli_exits_nonzero_on_missing_file(tmp_path):
    out = tmp_path / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(tmp_path / "missing.jsonl"),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 1
    assert "not found" in result.stderr.lower() or "no such" in result.stderr.lower()


def test_cli_creates_output_parent_dir(tmp_path):
    traces = _write_min_jsonl(tmp_path)
    out = tmp_path / "nested" / "subdir" / "prism-timeline.json"
    result = subprocess.run(
        [
            sys.executable, "-m",
            "ares.dialectic.visualization.build_cycle_timeline",
            "--traces", str(traces),
            "--output", str(out),
            "--run-id", "test-run",
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    assert result.returncode == 0, result.stderr
    assert out.exists()
