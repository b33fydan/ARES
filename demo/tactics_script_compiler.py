"""ARES Tactics script compiler (Half A).

Reads the recorded S084 dual-agent traces and emits one provenanced
tactics-script JSON per scenario for the forked Tactics renderer. Pure
transform; no LLM calls. Mirrors demo/battle_script_compiler.py.

Spec: docs/superpowers/specs/2026-06-16-ares-tactics-behavior-viz-design.md
"""
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
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


LABEL_MAX = 80


def _load_scenario_packet(scenario_id: str):
    from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
    for sc in build_registry_v3().all_scenarios():
        if sc.metadata.scenario_id == scenario_id:
            return sc.packet
    raise LookupError(f"{scenario_id} not in injection_registry_v3")


def _source_str(source_type) -> str:
    return str(getattr(source_type, "value", source_type))


def _threat_dominant_ids(scenario_id: str,
                         traces_path: str = DEFAULT_TRACES_PATH) -> set:
    """Facts the Architect cites under the prefix-framing condition = threat-dominant."""
    recs = load_scenario_traces(scenario_id, traces_path)
    framed = [r for r in recs if r["condition"] == "framing:framing_prefix_v1"]
    pool = framed or [r for r in recs if r["condition"] == "baseline"]
    return set(modal_fact_set(pool, "architect_cited_facts"))


def resolve_facts(scenario_id: str,
                  traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    packet = _load_scenario_packet(scenario_id)
    threat = _threat_dominant_ids(scenario_id, traces_path)
    out = []
    for fact in packet.get_all_facts():
        out.append({
            "fact_id": fact.fact_id,
            "field": fact.field,
            "display_label": str(fact.value)[:LABEL_MAX],
            "source_type": _source_str(fact.provenance.source_type),
            "is_threat_dominant": fact.fact_id in threat,
        })
    return out


_NAME = {"architect": "Architect", "skeptic": "Skeptic"}
_STANCE = {"architect": "threat", "skeptic": "benign"}


def synthesize_claim(actor: str, cited: list, total: int) -> str:
    """Deterministic, provenanced claim string (NOT a model quote)."""
    return f"{_NAME[actor]} cites {len(cited)} of {total} facts — {_STANCE[actor]}."


def _git_sha() -> str:
    try:
        out = subprocess.run(["git", "rev-parse", "--short", "HEAD"],
                             capture_output=True, text=True, check=True)
        return out.stdout.strip()
    except Exception:
        return "unknown"


def _trace_sha256(traces_path: str) -> str:
    return hashlib.sha256(Path(traces_path).read_bytes()).hexdigest()


def compile_tactics_script(scenario_id: str,
                           traces_path: str = DEFAULT_TRACES_PATH,
                           compiled_at: str | None = None) -> dict:
    if compiled_at is None:
        from datetime import datetime, timezone
        compiled_at = datetime.now(timezone.utc).isoformat()
    recs = load_scenario_traces(scenario_id, traces_path)
    if not recs:
        raise LookupError(f"no traces for {scenario_id}")
    facts = resolve_facts(scenario_id, traces_path)
    total = len(facts)
    conditions = []
    for cond in conditions_in(recs):
        summ = condition_summary(recs, cond)
        summ["name"] = cond
        summ["architect"]["claim"] = synthesize_claim(
            "architect", summ["architect"]["cited_fact_ids"], total)
        summ["skeptic"]["claim"] = synthesize_claim(
            "skeptic", summ["skeptic"]["cited_fact_ids"], total)
        conditions.append(summ)
    return {
        "scenario_id": scenario_id,
        "title_label": scenario_id,  # human title optional; scenario_id is the stable label
        "facts": facts,
        "conditions": conditions,
        "provenance": {
            "source_run": SOURCE_RUN,
            "trace_sha256": _trace_sha256(traces_path),
            "git_sha": _git_sha(),
            "compiler_version": COMPILER_VERSION,
            "compiled_at": compiled_at,
        },
    }


def validate_provenance(script: dict) -> None:
    prov = script.get("provenance") or {}
    if not prov.get("source_run") or not prov.get("trace_sha256"):
        raise ValueError("tactics-script missing provenance (source_run + trace_sha256)")


def emit_tactics_script(scenario_id: str, out_dir: str = DEFAULT_OUT_DIR,
                        traces_path: str = DEFAULT_TRACES_PATH,
                        compiled_at: str | None = None) -> str:
    script = compile_tactics_script(scenario_id, traces_path, compiled_at)
    validate_provenance(script)
    out = Path(out_dir) / f"{scenario_id.lower()}.tactics.json"
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(script, indent=2) + "\n", encoding="utf-8")
    return str(out)


def emit_all(out_dir: str = DEFAULT_OUT_DIR,
             traces_path: str = DEFAULT_TRACES_PATH) -> list[str]:
    return [emit_tactics_script(sid, out_dir, traces_path)
            for sid in scenarios_in_run(traces_path)]


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Compile ARES tactics-scripts from S084 traces.")
    p.add_argument("--scenario", default=None, help="one scenario id, or all if omitted")
    p.add_argument("--out-dir", default=DEFAULT_OUT_DIR)
    p.add_argument("--traces", default=DEFAULT_TRACES_PATH)
    args = p.parse_args(argv)
    if args.scenario:
        path = emit_tactics_script(args.scenario, args.out_dir, args.traces)
        print(f"wrote {path}")
    else:
        for path in emit_all(args.out_dir, args.traces):
            print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
