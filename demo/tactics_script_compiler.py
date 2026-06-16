"""ARES Tactics script compiler (Half A).

Reads the recorded S084 dual-agent traces and emits one provenanced
tactics-script JSON per scenario for the forked Tactics renderer. Pure
transform; no LLM calls. Mirrors demo/battle_script_compiler.py.

Spec: docs/superpowers/specs/2026-06-16-ares-tactics-behavior-viz-design.md
"""
from __future__ import annotations

import json
from pathlib import Path

DEFAULT_TRACES_PATH = (
    "data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl"
)
SOURCE_RUN = "20260605-194137-713674"
COMPILER_VERSION = "1.0"
DEFAULT_OUT_DIR = "demo/out"


def _load_all(traces_path: str) -> list[dict]:
    out: list[dict] = []
    with Path(traces_path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                out.append(json.loads(line))
    return out


def scenarios_in_run(traces_path: str = DEFAULT_TRACES_PATH) -> list[str]:
    """Sorted unique scenario IDs present in the run."""
    return sorted({r["scenario_id"] for r in _load_all(traces_path)})


def load_scenario_traces(scenario_id: str,
                         traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    """All records for one scenario."""
    return [r for r in _load_all(traces_path) if r["scenario_id"] == scenario_id]
