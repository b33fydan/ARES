"""ARES Tactics script compiler (Half A).

Reads the recorded S084 dual-agent traces and emits one provenanced
tactics-script JSON per scenario for the forked Tactics renderer. Pure
transform; no LLM calls. Mirrors demo/battle_script_compiler.py.

Spec: docs/superpowers/specs/2026-06-16-ares-tactics-behavior-viz-design.md
"""
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

# Reuse the regression-locked helpers from the Glass Box compiler.
from demo.battle_script_compiler import modal_fact_set, median_confidence

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


def conditions_in(records: list[dict]) -> list[str]:
    """Condition labels present, baseline first then sorted framings."""
    conds = {r["condition"] for r in records}
    ordered = ["baseline"] if "baseline" in conds else []
    ordered += sorted(c for c in conds if c != "baseline")
    return ordered


def _modal_outcome(records: list[dict]) -> str:
    counter = Counter(r["final_outcome"] for r in records)
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def condition_summary(records: list[dict], condition: str) -> dict:
    """Modal cited-fact sets + median confidences + modal outcome for one condition."""
    recs = [r for r in records if r["condition"] == condition]
    return {
        "architect": {
            "cited_fact_ids": list(modal_fact_set(recs, "architect_cited_facts")),
            "confidence": round(median_confidence(recs, "architect_confidence"), 3),
        },
        "skeptic": {
            "cited_fact_ids": list(modal_fact_set(recs, "skeptic_cited_facts")),
            "confidence": round(median_confidence(recs, "skeptic_confidence"), 3),
        },
        "oracle": {
            "verdict": _modal_outcome(recs),
            "supporting_fact_ids": list(modal_fact_set(recs, "oracle_supporting_facts")),
        },
    }
