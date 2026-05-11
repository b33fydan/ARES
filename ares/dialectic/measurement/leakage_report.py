"""LEAKAGE_REPORT_<run_id>.md renderer — Session 059.

Five sections in this exact order, no hedging language:

    1. Run metadata
    2. Per-bit results table (per operator × path)
    3. Per-layer leakage attribution
    4. Kill-criterion verdict (Boolean)
    5. Paper 3 claim status (`ALIVE` / `DEAD`)

Discipline: forbidden phrases ("appears to," "may indicate,"
"potentially," "suggests," "could indicate") are not used in the
verdict section. The renderer constructs that section from a fixed
template.
"""

from __future__ import annotations

from collections import defaultdict
from pathlib import Path
from typing import Iterable

from ares.dialectic.measurement.influence_leakage import (
    CONFIDENCE_DRIFT_THRESHOLD,
    InfluenceLeakage,
    KILL_THRESHOLD,
)
from ares.dialectic.measurement.leakage_runner import (
    HALT_ANCHOR_TEST_FAILURE,
    HALT_COMPLETED,
    HALT_COST_CEILING,
    HALT_DETERMINISTIC_KILL,
    PairLeakageRecord,
    RunSummary,
)


_FORBIDDEN_PHRASES_IN_VERDICT: tuple[str, ...] = (
    "appears to",
    "may indicate",
    "potentially",
    "suggests",
    "could indicate",
)


def _section_metadata(summary: RunSummary) -> str:
    halt_label = {
        HALT_COMPLETED: "completed",
        HALT_COST_CEILING: "cost_ceiling",
        HALT_DETERMINISTIC_KILL: "deterministic_kill",
        HALT_ANCHOR_TEST_FAILURE: "anchor_test_failure",
    }.get(summary.halt_reason, summary.halt_reason)
    lines = [
        "## 1. Run metadata",
        "",
        f"- **run_id**: `{summary.run_id}`",
        f"- **timestamp**: `{summary.timestamp_iso}`",
        f"- **git_sha**: `{summary.git_sha}`",
        f"- **total_cost_usd**: `${summary.total_cost_usd:.4f}`",
        f"- **cycles_completed**: `{summary.cycles_completed}`",
        f"- **halt_reason**: `{halt_label}`",
        f"- **anchor_test_at_start**: "
        f"`{'pass' if summary.anchor_test_passed_at_start else 'FAIL'}`",
        f"- **anchor_test_at_end**: "
        f"`{'pass' if summary.anchor_test_passed_at_end else 'FAIL'}`",
        f"- **operator_set**: `{list(summary.operator_set)}`",
        f"- **pre_registered_weights**: "
        f"`{summary.pre_registered_weights}`",
        f"- **confidence_drift_threshold**: `{summary.confidence_drift_threshold}`",
        f"- **traces_path**: `{summary.traces_path}`",
        f"- **sha256_path**: `{summary.sha256_path}`",
    ]
    return "\n".join(lines)


def _per_bit_cell(records: list[PairLeakageRecord]) -> dict[str, float]:
    """Aggregate per-bit fire rate across one (operator, path) cell.

    Returns dict with verdict_changed_rate, action_changed_rate,
    cited_facts_changed_rate, confidence_drift_rate, mean_scalar.
    Each rate is the fraction of pairs where ANY layer fired that bit.
    """
    if not records:
        return {
            "verdict_changed_rate": 0.0,
            "action_changed_rate": 0.0,
            "cited_facts_changed_rate": 0.0,
            "confidence_drift_rate": 0.0,
            "mean_scalar": 0.0,
            "n_pairs": 0,
        }
    n = len(records)
    v = sum(any(l.verdict_changed for l in r.leakages) for r in records)
    a = sum(any(l.action_changed for l in r.leakages) for r in records)
    c = sum(any(l.cited_facts_changed for l in r.leakages) for r in records)
    d = sum(any(l.confidence_drift_exceeded for l in r.leakages) for r in records)
    s = sum(r.aggregate_max_scalar for r in records) / n
    return {
        "verdict_changed_rate": v / n,
        "action_changed_rate": a / n,
        "cited_facts_changed_rate": c / n,
        "confidence_drift_rate": d / n,
        "mean_scalar": s,
        "n_pairs": n,
    }


def _section_per_bit_table(summary: RunSummary) -> str:
    by_cell: dict[tuple[str, str], list[PairLeakageRecord]] = defaultdict(list)
    for r in summary.pair_records:
        by_cell[(r.operator_name, r.pipeline)].append(r)

    lines = [
        "## 2. Per-bit results table",
        "",
        "Each row is one `(operator, pipeline)` cell. Rates are the "
        "fraction of pairs where ANY layer fired the bit. "
        "`mean_scalar` is the mean of per-pair `aggregate_max_scalar`.",
        "",
        "| operator | pipeline | n_pairs | verdict | action | cited_facts | conf_drift | mean_scalar |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for op in summary.operator_set:
        for pipeline in ("light", "llm"):
            cell = _per_bit_cell(by_cell.get((op, pipeline), []))
            lines.append(
                f"| `{op}` | `{pipeline}` | "
                f"{cell['n_pairs']} | "
                f"{cell['verdict_changed_rate']:.3f} | "
                f"{cell['action_changed_rate']:.3f} | "
                f"{cell['cited_facts_changed_rate']:.3f} | "
                f"{cell['confidence_drift_rate']:.3f} | "
                f"{cell['mean_scalar']:.3f} |"
            )
    return "\n".join(lines)


def _section_per_layer_attribution(summary: RunSummary) -> str:
    """Aggregate first-diverging-layer counts per pipeline."""
    counts: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
    for r in summary.pair_records:
        layer = r.first_diverging_layer or "no_divergence"
        counts[r.pipeline][layer] += 1

    lines = [
        "## 3. Per-layer leakage attribution",
        "",
        "Counts the layer at which divergence first appeared per pair.",
        "",
        "| pipeline | architect | skeptic_llm | light_skeptic | oracle | final_verdict | no_divergence |",
        "|---|---|---|---|---|---|---|",
    ]
    for pipeline in ("light", "llm"):
        c = counts[pipeline]
        lines.append(
            f"| `{pipeline}` | "
            f"{c['architect']} | "
            f"{c['skeptic_llm']} | "
            f"{c['light_skeptic']} | "
            f"{c['oracle']} | "
            f"{c['final_verdict']} | "
            f"{c['no_divergence']} |"
        )
    return "\n".join(lines)


def _section_kill_verdict(summary: RunSummary) -> str:
    """Dual-criterion Boolean verdict, no hedging.

    Two readings are reported transparently per the post-cycle-6
    drafting-error resolution (see SESSION_059 supersede notes):

        narrow      : Light Skeptic's judgment-level output only
                      (matches the original Phase 7 / Paper 3 framing).
        brief_broad : Light Skeptic + Oracle + Final Verdict
                      (matches the SESSION_059 prompt's literal
                      `deterministic path (OracleJudge + Light Skeptic)`,
                      excluding Architect — Architect is the LLM input
                      the deterministic path is supposed to absorb).
    """
    light_records = [r for r in summary.pair_records if r.pipeline == "light"]
    n_light = len(light_records)
    narrow_kill_count = sum(1 for r in light_records if r.kill_fires_narrow)
    broad_kill_count = sum(1 for r in light_records if r.kill_fires_brief_broad)
    narrow_kill = narrow_kill_count > 0
    broad_kill = broad_kill_count > 0

    lines = [
        "## 4. Kill-criterion verdict (dual reading)",
        "",
        f"- **deterministic_path_pairs_evaluated**: {n_light}",
        f"- **kill_threshold**: `weighted_scalar > {KILL_THRESHOLD}`",
        "",
        "### 4a. Narrow reading (Light Skeptic only)",
        "",
        f"- **pairs_with_leak**: {narrow_kill_count}",
        f"- **kill_fires (narrow)**: `{narrow_kill}`",
        f"- **Verdict**: {'TRUE' if narrow_kill else 'FALSE'}",
        "",
        "### 4b. Brief-broad reading (Light Skeptic + Oracle + Final Verdict)",
        "",
        f"- **pairs_with_leak**: {broad_kill_count}",
        f"- **kill_fires (brief_broad)**: `{broad_kill}`",
        f"- **Verdict**: {'TRUE' if broad_kill else 'FALSE'}",
    ]
    rendered = "\n".join(lines)

    # Discipline assertion: forbidden phrases must not appear.
    lowered = rendered.lower()
    for phrase in _FORBIDDEN_PHRASES_IN_VERDICT:
        if phrase in lowered:
            raise RuntimeError(
                f"discipline violation: forbidden phrase {phrase!r} "
                f"appeared in kill-verdict section"
            )
    return rendered


def _section_claim_status(summary: RunSummary) -> str:
    light_records = [r for r in summary.pair_records if r.pipeline == "light"]
    narrow_kill = any(r.kill_fires_narrow for r in light_records)
    broad_kill = any(r.kill_fires_brief_broad for r in light_records)
    narrow_status = "DEAD" if narrow_kill else "ALIVE"
    broad_status = "DEAD" if broad_kill else "ALIVE"
    return (
        "## 5. Paper 3 claim status (dual reading)\n\n"
        f"`Paper 3 claim status (narrow / Light Skeptic only): {narrow_status}`\n\n"
        f"`Paper 3 claim status (brief_broad / Light + Oracle + Final): {broad_status}`"
    )


def render_report(summary: RunSummary) -> str:
    """Render the full LEAKAGE_REPORT markdown."""
    title = f"# LEAKAGE_REPORT — {summary.run_id}"
    sections = [
        title,
        "",
        _section_metadata(summary),
        "",
        _section_per_bit_table(summary),
        "",
        _section_per_layer_attribution(summary),
        "",
        _section_kill_verdict(summary),
        "",
        _section_claim_status(summary),
        "",
    ]
    return "\n".join(sections)


def write_report(summary: RunSummary, output_dir: Path | None = None) -> Path:
    """Write the rendered report to `LEAKAGE_REPORT_<run_id>.md`.

    Args:
        summary: A frozen RunSummary from the runner.
        output_dir: Where to write. Defaults to repo root.

    Returns:
        The path written.
    """
    if output_dir is None:
        output_dir = Path(__file__).resolve().parents[3]
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"LEAKAGE_REPORT_{summary.run_id}.md"
    path.write_text(render_report(summary), encoding="utf-8")
    return path


__all__ = [
    "render_report",
    "write_report",
]
