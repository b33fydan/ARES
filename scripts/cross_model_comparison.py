"""Cross-model InfluenceLeakage comparison — Session 075.

Loads traces from multiple measurement runs (different providers),
recomputes pair leakage records, and renders a side-by-side comparison
table for Paper 3 Step 5 (multi-model validation).

Usage:
    python scripts/cross_model_comparison.py

The script auto-discovers runs under data/paper_3/leakage_runs/ and
produces a markdown comparison report at the repo root.
"""

from __future__ import annotations

import json
import sys
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from ares.dialectic.measurement.leakage_runner import (
    CycleTrace,
    PairLeakageRecord,
    _compute_pair_leakage,
)


# ---------------------------------------------------------------------------
# Known runs (hardcoded for reproducibility)
# ---------------------------------------------------------------------------

KNOWN_RUNS: dict[str, dict[str, str]] = {
    "20260510-184611-8e6e6d": {
        "label": "Sonnet 4.6 (S059 run 1)",
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "exclude": "true",
    },
    "20260510-193950-f401a8": {
        "label": "Sonnet 4.6 (S059 run 2)",
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
    },
    "20260510-224622-154556": {
        "label": "Sonnet 4.6 (S060 narrow)",
        "provider": "anthropic",
        "model": "claude-sonnet-4-20250514",
        "narrow_only": "true",
    },
    "20260527-121916-c543fa": {
        "label": "GPT-4o (S075)",
        "provider": "openai",
        "model": "gpt-4o",
    },
    "20260527-123857-c2d10f": {
        "label": "Gemini 2.5 Pro (S075)",
        "provider": "gemini",
        "model": "gemini-2.5-pro",
    },
    "20260528-000438-5614fa": {
        "label": "GPT-4o (S076 narrow)",
        "provider": "openai",
        "model": "gpt-4o",
        "narrow_only": "true",
    },
    "20260528-000629-a3bf23": {
        "label": "Gemini 2.5 Pro (S076 narrow)",
        "provider": "gemini",
        "model": "gemini-2.5-pro",
        "narrow_only": "true",
    },
}

MIN_TRACES_FOR_COMPLETE_RUN: int = 50

RUNS_ROOT = _REPO_ROOT / "data" / "paper_3" / "leakage_runs"


# ---------------------------------------------------------------------------
# Trace loading
# ---------------------------------------------------------------------------


def _load_trace(row: dict) -> CycleTrace:
    return CycleTrace(
        cycle_id=row["cycle_id"],
        scenario_id=row["scenario_id"],
        operator_name=row.get("operator_name"),
        pair_index=row["pair_index"],
        is_baseline=row["is_baseline"],
        pipeline=row["pipeline"],
        architect_message_type=row["architect_message_type"],
        architect_confidence=row["architect_confidence"],
        architect_cited_facts=tuple(row["architect_cited_facts"]),
        skeptic_message_type=row["skeptic_message_type"],
        skeptic_confidence=row["skeptic_confidence"],
        skeptic_cited_facts=tuple(row["skeptic_cited_facts"]),
        skeptic_triggered_rules=tuple(row["skeptic_triggered_rules"]),
        oracle_outcome=row["oracle_outcome"],
        oracle_confidence=row["oracle_confidence"],
        oracle_supporting_facts=tuple(row["oracle_supporting_facts"]),
        final_outcome=row["final_outcome"],
        final_confidence=row["final_confidence"],
        cost_usd=row["cost_usd"],
        tokens_in=row["tokens_in"],
        tokens_out=row["tokens_out"],
        elapsed_ms=row["elapsed_ms"],
    )


def _load_traces(run_dir: Path) -> list[CycleTrace]:
    traces_path = run_dir / "traces.jsonl"
    if not traces_path.exists():
        return []
    traces = []
    with traces_path.open("r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                traces.append(_load_trace(json.loads(line)))
    return traces


# ---------------------------------------------------------------------------
# Pair reconstruction from traces
# ---------------------------------------------------------------------------


def _reconstruct_pairs(traces: list[CycleTrace]) -> list[PairLeakageRecord]:
    """Match baseline + mutated traces by (scenario_id, pipeline),
    compute pair leakage records."""
    baselines: dict[tuple[str, str], CycleTrace] = {}
    mutated_list: list[CycleTrace] = []
    for t in traces:
        if t.is_baseline:
            baselines[(t.scenario_id, t.pipeline)] = t
        else:
            mutated_list.append(t)

    records = []
    for m in mutated_list:
        key = (m.scenario_id, m.pipeline)
        b = baselines.get(key)
        if b is None:
            continue
        record = _compute_pair_leakage(
            baseline=b,
            mutated=m,
            pair_index=m.pair_index,
        )
        records.append(record)
    return records


# ---------------------------------------------------------------------------
# Metrics extraction
# ---------------------------------------------------------------------------


@dataclass
class RunMetrics:
    run_id: str
    label: str
    provider: str
    model: str
    total_cost_usd: float
    total_cycles: int

    # LLM path
    llm_pairs: int
    llm_diverged: int
    llm_divergence_rate: float
    llm_architect_diverged: int
    llm_no_divergence: int

    # Light path
    light_pairs: int
    narrow_fires: int
    narrow_stability_rate: float
    broad_fires: int
    broad_dead: bool

    # First-diverging layer counts (LLM path)
    llm_first_architect: int
    llm_first_skeptic: int


def _extract_metrics(
    run_id: str,
    label: str,
    provider: str,
    model: str,
    traces: list[CycleTrace],
    pairs: list[PairLeakageRecord],
) -> RunMetrics:
    total_cost = sum(t.cost_usd for t in traces)

    llm_pairs = [r for r in pairs if r.pipeline == "llm"]
    light_pairs = [r for r in pairs if r.pipeline == "light"]

    # LLM-path divergence: any layer has non-zero leakage
    llm_diverged = sum(
        1 for r in llm_pairs if r.first_diverging_layer is not None
    )
    llm_n = len(llm_pairs)

    llm_first_arch = sum(
        1 for r in llm_pairs if r.first_diverging_layer == "architect"
    )
    llm_first_skep = sum(
        1 for r in llm_pairs
        if r.first_diverging_layer in ("skeptic_llm", "light_skeptic")
    )
    llm_no_div = sum(
        1 for r in llm_pairs if r.first_diverging_layer is None
    )

    # Narrow and broad
    narrow_fires = sum(1 for r in light_pairs if r.kill_fires_narrow)
    broad_fires = sum(1 for r in light_pairs if r.kill_fires_brief_broad)

    light_n = len(light_pairs)

    return RunMetrics(
        run_id=run_id,
        label=label,
        provider=provider,
        model=model,
        total_cost_usd=total_cost,
        total_cycles=len(traces),
        llm_pairs=llm_n,
        llm_diverged=llm_diverged,
        llm_divergence_rate=(llm_diverged / llm_n * 100.0) if llm_n else 0.0,
        llm_architect_diverged=llm_first_arch,
        llm_no_divergence=llm_no_div,
        light_pairs=light_n,
        narrow_fires=narrow_fires,
        narrow_stability_rate=(
            (light_n - narrow_fires) / light_n * 100.0 if light_n else 0.0
        ),
        broad_fires=broad_fires,
        broad_dead=broad_fires > 0,
        llm_first_architect=llm_first_arch,
        llm_first_skeptic=llm_first_skep,
    )


# ---------------------------------------------------------------------------
# Report rendering
# ---------------------------------------------------------------------------


def _render_comparison(runs: list[RunMetrics]) -> str:
    lines = [
        "# Cross-Model InfluenceLeakage Comparison — Step 5",
        "",
        "Side-by-side comparison of InfluenceLeakage measurement across "
        "model families. Paper 3 claim: the deterministic path (Light "
        "Skeptic) absorbs LLM-layer framing sensitivity without leaking "
        "to downstream verdicts.",
        "",
        "## Summary table",
        "",
    ]

    # Header
    cols = ["Metric"] + [r.label for r in runs]
    sep = "|".join(["---"] * (len(cols)))
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + sep + "|")

    def _row(label: str, values: list[str]) -> str:
        return "| " + " | ".join([label] + values) + " |"

    lines.append(_row("Provider", [r.provider for r in runs]))
    lines.append(_row("Model", [f"`{r.model}`" for r in runs]))
    lines.append(_row("Run ID", [f"`{r.run_id}`" for r in runs]))
    lines.append(_row("Total cost", [f"${r.total_cost_usd:.2f}" for r in runs]))
    lines.append(_row("Total cycles", [str(r.total_cycles) for r in runs]))
    lines.append("")

    # Narrow reading
    lines.append("## Narrow reading (Light Skeptic only)")
    lines.append("")
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + sep + "|")
    lines.append(_row("Light pairs evaluated", [str(r.light_pairs) for r in runs]))
    lines.append(_row("Narrow fires", [str(r.narrow_fires) for r in runs]))
    lines.append(_row(
        "Narrow stability",
        [
            f"{r.narrow_stability_rate:.2f}% ({r.light_pairs - r.narrow_fires}/{r.light_pairs})"
            if r.light_pairs > 0 else "N/A"
            for r in runs
        ],
    ))
    lines.append(_row(
        "**Narrow verdict**",
        [
            f"**{'ALIVE' if r.narrow_fires == 0 else 'DEAD'}**"
            for r in runs
        ],
    ))
    lines.append("")

    # Broad reading
    lines.append("## Broad reading (Light Skeptic + Oracle + Final Verdict)")
    lines.append("")
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + sep + "|")
    lines.append(_row("Broad fires", [str(r.broad_fires) for r in runs]))
    lines.append(_row(
        "**Broad verdict**",
        [f"**{'DEAD' if r.broad_dead else 'ALIVE'}**" for r in runs],
    ))
    lines.append("")

    # LLM path divergence
    lines.append("## LLM-path divergence (Architect layer sensitivity)")
    lines.append("")
    lines.append("| " + " | ".join(cols) + " |")
    lines.append("|" + sep + "|")
    lines.append(_row("LLM pairs", [str(r.llm_pairs) for r in runs]))
    lines.append(_row(
        "Diverged",
        [
            f"{r.llm_diverged}/{r.llm_pairs} ({r.llm_divergence_rate:.1f}%)"
            if r.llm_pairs > 0 else "N/A"
            for r in runs
        ],
    ))
    lines.append(_row("No divergence", [str(r.llm_no_divergence) for r in runs]))
    lines.append(_row(
        "First diverge: Architect",
        [str(r.llm_first_architect) for r in runs],
    ))
    lines.append(_row(
        "First diverge: Skeptic",
        [str(r.llm_first_skeptic) for r in runs],
    ))
    lines.append("")

    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Discovery + main
# ---------------------------------------------------------------------------


def _discover_runs() -> list[tuple[str, Path, dict[str, str]]]:
    """Find all run directories under the leakage_runs root."""
    discovered = []
    if not RUNS_ROOT.exists():
        return discovered
    for d in sorted(RUNS_ROOT.iterdir()):
        if not d.is_dir():
            continue
        traces = d / "traces.jsonl"
        if not traces.exists():
            continue
        run_id = d.name
        meta = KNOWN_RUNS.get(run_id, {})

        # Try to read summary.json for provider/model
        summary_path = d / "summary.json"
        if summary_path.exists():
            with summary_path.open("r", encoding="utf-8") as f:
                sj = json.load(f)
            if "provider" not in meta:
                meta["provider"] = sj.get("provider", "unknown")
            if "model" not in meta:
                meta["model"] = sj.get("model", "unknown")
            if "label" not in meta:
                meta["label"] = f"{meta['provider']} / {meta['model']} ({run_id})"

        if "label" not in meta:
            meta["label"] = f"Unknown ({run_id})"
        if "provider" not in meta:
            meta["provider"] = "unknown"
        if "model" not in meta:
            meta["model"] = "unknown"

        discovered.append((run_id, d, meta))
    return discovered


def main() -> int:
    print("Discovering runs ...")
    all_runs = _discover_runs()

    # Skip narrow-only runs, excluded runs, and in-progress runs.
    runs = [
        (rid, d, m) for rid, d, m in all_runs
        if m.get("narrow_only") != "true"
        and m.get("exclude") != "true"
    ]

    print(f"Found {len(runs)} full measurement runs:")
    for run_id, d, meta in runs:
        print(f"  {run_id}: {meta['label']}")

    metrics_list: list[RunMetrics] = []
    for run_id, d, meta in runs:
        print(f"\nLoading traces for {run_id} ...")
        traces = _load_traces(d)
        print(f"  {len(traces)} traces loaded")
        if len(traces) < MIN_TRACES_FOR_COMPLETE_RUN:
            print(f"  SKIPPED (< {MIN_TRACES_FOR_COMPLETE_RUN} traces; likely in-progress)")
            continue
        pairs = _reconstruct_pairs(traces)
        print(f"  {len(pairs)} pairs reconstructed")
        m = _extract_metrics(
            run_id=run_id,
            label=meta["label"],
            provider=meta["provider"],
            model=meta["model"],
            traces=traces,
            pairs=pairs,
        )
        metrics_list.append(m)

    report = _render_comparison(metrics_list)
    out_path = _REPO_ROOT / "CROSS_MODEL_COMPARISON.md"
    out_path.write_text(report, encoding="utf-8")
    print(f"\nComparison report written: {out_path}")
    print("\n" + report)
    return 0


if __name__ == "__main__":
    sys.exit(main())
