# tests/dialectic/measurement/test_run_session_087.py
"""Smoke test for the session-087 CLI (offline)."""
from __future__ import annotations

import json


def test_main_writes_artifacts(tmp_path):
    from scripts.run_session_087 import main

    code = main(["--out-dir", str(tmp_path)])
    assert code == 0
    report = tmp_path / "frontier_report.md"
    coords = tmp_path / "frontier_coordinates.json"
    assert report.exists()
    assert coords.exists()
    data = json.loads(coords.read_text(encoding="utf-8"))
    assert len(data["coordinates"]) == 8
