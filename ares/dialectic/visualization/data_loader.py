"""Loads Session 059 leakage traces into PairRecord objects."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING, List, Literal

if TYPE_CHECKING:
    from ares.dialectic.measurement.leakage_runner import CycleTrace

DivergingLayer = Literal["Architect", "Skeptic", "Oracle", "Final", "None"]

VALID_DIVERGING_LAYERS: frozenset[str] = frozenset(
    {"Architect", "Skeptic", "Oracle", "Final", "None"}
)

# Map from leakage_runner layer names (lowercase) to PairRecord layer names
# (title-case). Both "skeptic_llm" and "light_skeptic" map to "Skeptic".
_LAYER_NAME_MAP: dict[str, str] = {
    "architect": "Architect",
    "skeptic_llm": "Skeptic",
    "light_skeptic": "Skeptic",
    "oracle": "Oracle",
    "final_verdict": "Final",
}


@dataclass(frozen=True)
class PairRecord:
    """One paired-cycle outcome from a Session 059 leakage run."""

    scenario_id: str
    operator: str
    narrow_leakage: bool
    broad_leakage: bool
    confidence_baseline: float
    confidence_mutated: float
    first_diverging_layer: DivergingLayer

    def __post_init__(self) -> None:
        if self.first_diverging_layer not in VALID_DIVERGING_LAYERS:
            raise ValueError(
                f"first_diverging_layer must be one of "
                f"{sorted(VALID_DIVERGING_LAYERS)}; "
                f"got {self.first_diverging_layer!r}"
            )


def _trace_from_dict(row: dict) -> CycleTrace:
    """Reconstruct a CycleTrace from a JSONL row dict.

    Imported here to avoid a circular import; leakage_runner imports from
    measurement, not from visualization.
    """
    # Import inside function to avoid heavy transitive imports at module load.
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


def load_run(traces_path: Path) -> List[PairRecord]:
    """Load Session 059 traces.jsonl and produce one PairRecord per pair.

    Pairs are identified by (scenario_id, operator_name) across pipelines.
    Each pair contributes one PairRecord with narrow + broad leakage flags
    computed via the existing InfluenceLeakage helpers in leakage_runner.

    Raises:
        FileNotFoundError: if traces_path does not exist.
    """
    from ares.dialectic.measurement.leakage_runner import compute_pair_leakage as _compute_pair_leakage  # noqa: PLC0415

    if not traces_path.exists():
        raise FileNotFoundError(f"Traces file not found: {traces_path}")

    with traces_path.open("r", encoding="utf-8") as fh:
        all_rows = [json.loads(line) for line in fh if line.strip()]

    # Index rows by (scenario_id, operator_name [None for baseline], pipeline)
    # Structure: {(scenario_id, operator_name): {pipeline: row_dict}}
    index: dict[tuple[str, str | None], dict[str, dict]] = {}
    for row in all_rows:
        key = (row["scenario_id"], row.get("operator_name"))
        index.setdefault(key, {})[row["pipeline"]] = row

    records: List[PairRecord] = []
    for (scenario_id, operator_name), pipelines in index.items():
        if operator_name is None:
            # This is a baseline group — processed when we encounter operators.
            continue
        baseline_key = (scenario_id, None)
        if baseline_key not in index:
            continue

        baseline_pipelines = index[baseline_key]

        # Collect per-pipeline pair leakage records; we need the light one
        # for narrow / broad readings.
        light_pair_record = None
        first_diverging_runner: str | None = None  # from whichever pipeline fires first

        for pipeline in ("light", "llm"):
            baseline_row = baseline_pipelines.get(pipeline)
            mutated_row = pipelines.get(pipeline)
            if baseline_row is None or mutated_row is None:
                continue

            baseline_trace = _trace_from_dict(baseline_row)
            mutated_trace = _trace_from_dict(mutated_row)

            pair_record = _compute_pair_leakage(
                baseline=baseline_trace,
                mutated=mutated_trace,
                pair_index=int(mutated_row["pair_index"]),
            )

            if pipeline == "light":
                light_pair_record = pair_record

            # Track the first diverging layer (prefer light pipeline, then llm)
            if first_diverging_runner is None and pair_record.first_diverging_layer is not None:
                first_diverging_runner = pair_record.first_diverging_layer

        # Determine narrow + broad leakage from the light pipeline record.
        narrow_leakage: bool = False
        broad_leakage: bool = False
        if light_pair_record is not None:
            narrow_leakage = light_pair_record.kill_fires_narrow
            broad_leakage = light_pair_record.kill_fires_brief_broad

        # Map runner layer name (lowercase) to PairRecord layer name.
        if first_diverging_runner is None:
            first_diverging_layer: DivergingLayer = "None"
        else:
            first_diverging_layer = _LAYER_NAME_MAP.get(
                first_diverging_runner, "None"
            )

        # Confidence values from the LLM baseline / mutated architect.
        llm_baseline_row = baseline_pipelines.get("llm")
        llm_mutated_row = pipelines.get("llm")
        confidence_baseline = (
            float(llm_baseline_row["architect_confidence"])
            if llm_baseline_row is not None
            else 0.0
        )
        confidence_mutated = (
            float(llm_mutated_row["architect_confidence"])
            if llm_mutated_row is not None
            else 0.0
        )

        records.append(
            PairRecord(
                scenario_id=scenario_id,
                operator=operator_name,
                narrow_leakage=narrow_leakage,
                broad_leakage=broad_leakage,
                confidence_baseline=confidence_baseline,
                confidence_mutated=confidence_mutated,
                first_diverging_layer=first_diverging_layer,
            )
        )

    return records
