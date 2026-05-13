import json
import sys
from pathlib import Path
from unittest.mock import patch
from ares.dialectic.visualization.build_timeline import main

FIXTURE_DIR = Path(__file__).parent / "fixtures"


def test_cli_writes_json_file(tmp_path):
    output = tmp_path / "out.json"
    args = ["--traces", str(FIXTURE_DIR / "mini_traces.jsonl"),
            "--output", str(output)]
    with patch.object(sys, "argv", ["build_timeline", *args]):
        exit_code = main()
    assert exit_code == 0
    assert output.exists()
    parsed = json.loads(output.read_text())
    assert parsed["version"] == "1"
    assert "pins" in parsed
    assert len(parsed["pins"]) == 1  # mini fixture has one pair


def test_cli_returns_nonzero_when_traces_missing(tmp_path):
    args = ["--traces", str(tmp_path / "missing.jsonl"),
            "--output", str(tmp_path / "out.json")]
    with patch.object(sys, "argv", ["build_timeline", *args]):
        exit_code = main()
    assert exit_code != 0
