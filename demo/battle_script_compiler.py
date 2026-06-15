"""Glass Box battle-script compiler (Half A).

Reads recorded INJ-020 traces (S084 run) and emits one provenanced
battle-script JSON for the renderer. Pure transform; no LLM calls.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import statistics
from collections import Counter
from pathlib import Path

from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

SCENARIO_ID = "INJ-020"
DEFAULT_TRACES_PATH = (
    "data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl"
)
LABEL_MAX = 90
COMPILER_VERSION = "1.0"
SOURCE_RUN = "20260605-194137-713674"
GIT_SHA = "40f1751"
DEFAULT_OUT = "demo/out/inj020.battle.json"

ROUNDS = [
    (1, "baseline"),
    (2, "framing:framing_prefix_v1"),
    (3, "framing:synonym_substitution_conservative_v2"),
]

# ---------------------------------------------------------------------------
# Task 1: INJ-020 scenario loader
# ---------------------------------------------------------------------------


def load_inj020_scenario():
    """Return the INJ-020 BenchmarkScenario from the v3 registry."""
    registry = build_registry_v3()
    for scenario in registry.all_scenarios():
        if scenario.metadata.scenario_id == "INJ-020":
            return scenario
    raise LookupError("INJ-020 not found in injection_registry_v3")


# ---------------------------------------------------------------------------
# Task 3: Trace loading, modal cited-fact set, median confidence
# (implemented before Task 2 so resolve_facts can depend on these)
# ---------------------------------------------------------------------------


def load_inj020_traces(traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    """Read traces.jsonl, return only INJ-020 records."""
    out: list[dict] = []
    with Path(traces_path).open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line:
                continue
            rec = json.loads(line)
            if rec.get("scenario_id") == SCENARIO_ID:
                out.append(rec)
    return out


def modal_fact_set(records: list[dict], key: str) -> tuple[str, ...]:
    """Most common cited-fact SET across resamples, as a sorted tuple.

    Each record's value is normalized to a sorted tuple; the modal tuple
    wins. Ties break deterministically by (-count, tuple).
    """
    counter: Counter[tuple[str, ...]] = Counter(
        tuple(sorted(rec.get(key) or [])) for rec in records
    )
    if not counter:
        return ()
    best = sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]
    return best


def median_confidence(records: list[dict], key: str) -> float:
    vals = [float(rec[key]) for rec in records if rec.get(key) is not None]
    return float(statistics.median(vals)) if vals else 0.0


# ---------------------------------------------------------------------------
# Task 2: Fact resolution (fact_id → display_label / source_type / is_threat_dominant)
# ---------------------------------------------------------------------------


def _source_type_str(source_type) -> str:
    return str(getattr(source_type, "value", source_type))


def _threat_fact_ids(traces_path: str = DEFAULT_TRACES_PATH) -> tuple[str, ...]:
    """The framed (prefix) architect modal set = the threat-dominant facts."""
    records = load_inj020_traces(traces_path)
    framed = [r for r in records if r["condition"] == "framing:framing_prefix_v1"]
    return modal_fact_set(framed, "architect_cited_facts")


def resolve_facts(traces_path: str = DEFAULT_TRACES_PATH) -> list[dict]:
    scenario = load_inj020_scenario()
    threat = set(_threat_fact_ids(traces_path))
    out: list[dict] = []
    for fact in scenario.packet.get_all_facts():
        out.append({
            "fact_id": fact.fact_id,
            "display_label": str(fact.value)[:LABEL_MAX],
            "source_type": _source_type_str(fact.provenance.source_type),
            "is_threat_dominant": fact.fact_id in threat,
        })
    return out


# ---------------------------------------------------------------------------
# Task 4: Synthesized captions + per-beat claim labels (deterministic)
# ---------------------------------------------------------------------------

_STANCE = {"architect": "threat", "skeptic": "benign"}
_NAME = {"architect": "Architect", "skeptic": "Skeptic"}


def claim_label(actor: str, cited: tuple[str, ...], total: int) -> str:
    return f"{_NAME[actor]} cites {len(cited)} of {total} facts — {_STANCE[actor]}."


def round_caption(variant: str) -> str:
    if variant == "baseline":
        return "Baseline: both agents weigh the evidence; the verdict is dismissed."
    if variant.endswith("framing_prefix_v1"):
        return "Reframed wording — the explanations dissociate. The verdict does not move."
    if variant.endswith("synonym_substitution_conservative_v2"):
        return "Reworded facts — same dissociation. The verdict still does not move."
    return "The verdict does not move."


# ---------------------------------------------------------------------------
# Task 5: Round-level 4-bit leakage vector (via InfluenceLeakage helpers)
# ---------------------------------------------------------------------------

from ares.dialectic.measurement.influence_leakage import (  # noqa: E402
    cited_facts_changed as _cited_changed,
    confidence_drift_exceeds_threshold as _conf_drift,
    verdict_changed_from_labels as _verdict_changed,
    action_changed_from_stance as _action_changed,
)

_FINAL_STANCE = {
    "threat_confirmed": "escalate",
    "threat_dismissed": "dismiss",
    "inconclusive": "hold",
}


def _modal_outcome(records: list[dict]) -> str:
    counter = Counter(r["final_outcome"] for r in records)
    return sorted(counter.items(), key=lambda kv: (-kv[1], kv[0]))[0][0]


def round_leakage_vector(baseline: list[dict], condition: list[dict]) -> dict:
    """Round-level 4-bit summary, computed via influence_leakage helpers.

    confidence_drift uses the architect confidence median (the only
    verdict-relevant confidence persisted in the S084 traces).
    """
    b_out, c_out = _modal_outcome(baseline), _modal_outcome(condition)
    verdict = _verdict_changed(b_out, c_out)
    action = _action_changed(_FINAL_STANCE[b_out], _FINAL_STANCE[c_out])
    cited = (
        _cited_changed(
            modal_fact_set(baseline, "architect_cited_facts"),
            modal_fact_set(condition, "architect_cited_facts"),
        )
        or _cited_changed(
            modal_fact_set(baseline, "skeptic_cited_facts"),
            modal_fact_set(condition, "skeptic_cited_facts"),
        )
    )
    conf = _conf_drift(
        median_confidence(baseline, "architect_confidence"),
        median_confidence(condition, "architect_confidence"),
    )
    return {
        "verdict_changed": int(verdict),
        "action_changed": int(action),
        "cited_facts_changed": int(cited),
        "confidence_drift_exceeded": int(conf),
    }


# ---------------------------------------------------------------------------
# Task 6: Assemble the battle-script dict
# ---------------------------------------------------------------------------


def _trace_sha256(traces_path: str) -> str:
    h = hashlib.sha256()
    h.update(Path(traces_path).read_bytes())
    return h.hexdigest()


def _agent_beat(actor: str, records: list[dict], total: int) -> dict:
    cited = list(modal_fact_set(records, f"{actor}_cited_facts"))
    return {
        "actor": actor,
        "action": "propose" if actor == "architect" else "rebut",
        "claim_label": claim_label(actor, tuple(cited), total),
        "cited_fact_ids": cited,
        "confidence": round(median_confidence(records, f"{actor}_confidence"), 3),
    }


def _oracle_beat(records: list[dict]) -> dict:
    return {
        "actor": "oracle",
        "action": "verdict",
        "outcome": _modal_outcome(records),
        "supporting_fact_ids": list(modal_fact_set(records, "oracle_supporting_facts")),
    }


def compile_battle_script(
    traces_path: str = DEFAULT_TRACES_PATH,
    compiled_at: str | None = None,
) -> dict:
    if compiled_at is None:
        from datetime import datetime, timezone
        compiled_at = datetime.now(timezone.utc).isoformat()

    all_records = load_inj020_traces(traces_path)
    facts = resolve_facts(traces_path)
    total = len(facts)
    baseline = [r for r in all_records if r["condition"] == "baseline"]

    rounds = []
    for round_id, variant in ROUNDS:
        recs = [r for r in all_records if r["condition"] == variant]
        arch = _agent_beat("architect", recs, total)
        rounds.append({
            "round_id": round_id,
            "variant": variant,
            "beats": [
                arch,
                _agent_beat("skeptic", recs, total),
                _oracle_beat(recs),
            ],
            "caption": round_caption(variant),
            "leakage_vector": round_leakage_vector(baseline, recs),
        })

    return {
        "scenario_id": SCENARIO_ID,
        "title_label": "Quiet exculpatory facts under pressure",
        "evidence_packet": {"facts": facts},
        "rounds": rounds,
        "provenance": {
            "source_run": SOURCE_RUN,
            "git_sha": GIT_SHA,
            "trace_sha256": _trace_sha256(traces_path),
            "compiled_at": compiled_at,
            "compiler_version": COMPILER_VERSION,
        },
    }


# ---------------------------------------------------------------------------
# Task 8: Provenance gate + JSON emitter + CLI
# ---------------------------------------------------------------------------


def validate_provenance(script: dict) -> None:
    """Raise ValueError unless source_run + trace_sha256 are present.

    Enforces 'nothing on screen is invented' at the contract boundary.
    """
    prov = script.get("provenance") or {}
    if not prov.get("source_run") or not prov.get("trace_sha256"):
        raise ValueError(
            "battle-script missing provenance (source_run + trace_sha256)"
        )


def emit_battle_script(
    out_path: str = DEFAULT_OUT,
    traces_path: str = DEFAULT_TRACES_PATH,
    compiled_at: str | None = None,
) -> str:
    script = compile_battle_script(traces_path, compiled_at)
    validate_provenance(script)
    out = Path(out_path)
    out.parent.mkdir(parents=True, exist_ok=True)
    out.write_text(json.dumps(script, indent=2) + "\n", encoding="utf-8")
    return str(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Compile the INJ-020 battle-script.")
    parser.add_argument("--traces", default=DEFAULT_TRACES_PATH)
    parser.add_argument("--out", default=DEFAULT_OUT)
    parser.add_argument("--compiled-at", default=None)
    args = parser.parse_args(argv)
    path = emit_battle_script(args.out, args.traces, args.compiled_at)
    print(f"wrote {path}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
