"""Build CycleTimelineV2 documents from Session 059-style traces.jsonl.

Reuses ``compute_pair_leakage`` from
``ares.dialectic.measurement.leakage_runner`` so per-layer leakage bits agree
with the canonical Phase 7 measurement primitives. JSONL loading is replicated
here (small) rather than imported from v1 ``data_loader.py``, per the ARES
"new files only" rule.
"""

from __future__ import annotations

import json
from pathlib import Path

from ares.dialectic.visualization.cycle_trace import (
    CycleSnapshot,
    CycleTimelineV2,
    PairTrace,
)


_LLM_LAYER_TO_FIELD: dict[str, str] = {
    "architect": "llm_architect_bits",
    "skeptic_llm": "llm_skeptic_bits",
    "oracle": "llm_oracle_bits",
    "final_verdict": "llm_final_bits",
}

_LAYER_NAME_MAP: dict[str, str] = {
    "architect": "Architect",
    "skeptic_llm": "Skeptic",
    "light_skeptic": "Skeptic",
    "oracle": "Oracle",
    "final_verdict": "Final",
}


def _snapshot_from_row(row: dict) -> CycleSnapshot:
    return CycleSnapshot(
        architect_confidence=float(row["architect_confidence"]),
        architect_cited_facts=tuple(row["architect_cited_facts"]),
        architect_message_type=str(row["architect_message_type"]),
        skeptic_confidence=float(row["skeptic_confidence"]),
        skeptic_cited_facts=tuple(row["skeptic_cited_facts"]),
        skeptic_message_type=str(row["skeptic_message_type"]),
        skeptic_triggered_rules=tuple(row["skeptic_triggered_rules"]),
        oracle_outcome=str(row["oracle_outcome"]),
        oracle_confidence=float(row["oracle_confidence"]),
        oracle_supporting_facts=tuple(row["oracle_supporting_facts"]),
        final_outcome=str(row["final_outcome"]),
        final_confidence=float(row["final_confidence"]),
        pipeline=str(row["pipeline"]),
    )


def _trace_from_row(row: dict):
    """Reconstruct leakage_runner.CycleTrace from a JSONL row.

    Imported lazily here to mirror data_loader.py's pattern and avoid heavy
    transitive imports at module load.
    """
    from ares.dialectic.measurement.leakage_runner import CycleTrace  # noqa: PLC0415

    return CycleTrace(
        cycle_id=row["cycle_id"],
        scenario_id=row["scenario_id"],
        operator_name=row.get("operator_name"),
        pair_index=int(row["pair_index"]),
        is_baseline=bool(row["is_baseline"]),
        pipeline=row["pipeline"],
        architect_message_type=row["architect_message_type"],
        architect_confidence=float(row["architect_confidence"]),
        architect_cited_facts=tuple(row["architect_cited_facts"]),
        skeptic_message_type=row["skeptic_message_type"],
        skeptic_confidence=float(row["skeptic_confidence"]),
        skeptic_cited_facts=tuple(row["skeptic_cited_facts"]),
        skeptic_triggered_rules=tuple(row["skeptic_triggered_rules"]),
        oracle_outcome=row["oracle_outcome"],
        oracle_confidence=float(row["oracle_confidence"]),
        oracle_supporting_facts=tuple(row["oracle_supporting_facts"]),
        final_outcome=row["final_outcome"],
        final_confidence=float(row["final_confidence"]),
        cost_usd=float(row["cost_usd"]),
        tokens_in=int(row["tokens_in"]),
        tokens_out=int(row["tokens_out"]),
        elapsed_ms=float(row["elapsed_ms"]),
    )


def build_cycle_timeline(traces_path: Path, run_id: str) -> CycleTimelineV2:
    """Read traces.jsonl, assemble CycleTimelineV2.

    Raises:
        FileNotFoundError: traces_path missing.
        ValueError: no (scenario, operator) pairs found.
    """
    from ares.dialectic.measurement.leakage_runner import compute_pair_leakage  # noqa: PLC0415

    if not traces_path.exists():
        raise FileNotFoundError(f"Traces file not found: {traces_path}")

    with traces_path.open("r", encoding="utf-8") as fh:
        rows = [json.loads(line) for line in fh if line.strip()]

    # Index by (scenario_id, operator_name|None) -> {pipeline: row}
    index: dict[tuple[str, str | None], dict[str, dict]] = {}
    for row in rows:
        key = (row["scenario_id"], row.get("operator_name"))
        index.setdefault(key, {})[row["pipeline"]] = row

    pair_traces: list[PairTrace] = []
    seen_operators: set[str] = set()

    for (scenario_id, operator_name), pipelines in index.items():
        if operator_name is None:
            continue
        baseline_key = (scenario_id, None)
        if baseline_key not in index:
            continue
        baseline_pipelines = index[baseline_key]
        seen_operators.add(operator_name)

        baseline_llm_row = baseline_pipelines.get("llm")
        mutated_llm_row = pipelines.get("llm")
        baseline_light_row = baseline_pipelines.get("light")
        mutated_light_row = pipelines.get("light")

        baseline_llm = (
            _snapshot_from_row(baseline_llm_row) if baseline_llm_row else None
        )
        mutated_llm = (
            _snapshot_from_row(mutated_llm_row) if mutated_llm_row else None
        )
        baseline_light = (
            _snapshot_from_row(baseline_light_row)
            if baseline_light_row
            else None
        )
        mutated_light = (
            _snapshot_from_row(mutated_light_row)
            if mutated_light_row
            else None
        )

        llm_bits_by_field: dict[str, tuple[bool, bool, bool, bool]] = {
            name: (False, False, False, False)
            for name in _LLM_LAYER_TO_FIELD.values()
        }
        llm_first_diverging: str | None = None
        if baseline_llm_row and mutated_llm_row:
            llm_record = compute_pair_leakage(
                baseline=_trace_from_row(baseline_llm_row),
                mutated=_trace_from_row(mutated_llm_row),
                pair_index=int(mutated_llm_row["pair_index"]),
            )
            for leakage in llm_record.leakages:
                field = _LLM_LAYER_TO_FIELD.get(leakage.layer)
                if field:
                    llm_bits_by_field[field] = leakage.bits
            llm_first_diverging = llm_record.first_diverging_layer

        narrow = False
        broad = False
        light_first_diverging: str | None = None
        if baseline_light_row and mutated_light_row:
            light_record = compute_pair_leakage(
                baseline=_trace_from_row(baseline_light_row),
                mutated=_trace_from_row(mutated_light_row),
                pair_index=int(mutated_light_row["pair_index"]),
            )
            narrow = light_record.kill_fires_narrow
            broad = light_record.kill_fires_brief_broad
            light_first_diverging = light_record.first_diverging_layer

        # Prefer the light-pipeline divergence layer (matches v1 data_loader.py
        # and the Session 059 narrative). Light Skeptic uses pure-Python rules
        # that don't drift under prose mutation, so when the broad-reading kill
        # fires it surfaces at the architectural seam — typically Oracle, via
        # the documented citation-passthrough from Architect's facts. That's
        # the story the Labyrinth's red crumb tells. The LLM pipeline always
        # shows Architect first (LLM Architect re-cites under mutation), which
        # is a less interesting story for the viewer — the rule-based defense's
        # bypass is the point of interest.
        diverging_raw = light_first_diverging or llm_first_diverging
        first_diverging = (
            _LAYER_NAME_MAP.get(diverging_raw, "None")
            if diverging_raw
            else "None"
        )

        pair_traces.append(
            PairTrace(
                pair_index=(
                    int(mutated_llm_row["pair_index"])
                    if mutated_llm_row
                    else int(mutated_light_row["pair_index"])
                ),
                scenario_id=scenario_id,
                operator=operator_name,
                baseline_llm=baseline_llm,
                mutated_llm=mutated_llm,
                baseline_light=baseline_light,
                mutated_light=mutated_light,
                narrow_leakage=narrow,
                broad_leakage=broad,
                first_diverging_layer=first_diverging,
                llm_architect_bits=llm_bits_by_field["llm_architect_bits"],
                llm_skeptic_bits=llm_bits_by_field["llm_skeptic_bits"],
                llm_oracle_bits=llm_bits_by_field["llm_oracle_bits"],
                llm_final_bits=llm_bits_by_field["llm_final_bits"],
            )
        )

    if not pair_traces:
        raise ValueError(
            f"No pairs assembled from {traces_path} — file contains only "
            "baseline rows or no mutated rows reference any baseline."
        )

    pair_traces.sort(key=lambda p: (p.pair_index, p.scenario_id, p.operator))

    return CycleTimelineV2(
        schema_version="v2",
        run_id=run_id,
        operators=tuple(sorted(seen_operators)),
        pairs=tuple(pair_traces),
    )
