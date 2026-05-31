"""Markdown renderer for the Architect-path framing measurement."""
from __future__ import annotations

from pathlib import Path

from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingSummary


def render_report(summary: ArchitectFramingSummary) -> str:
    lines: list[str] = []
    lines.append(f"# Architect-Path Framing Measurement — {summary.run_id}")
    lines.append("")
    lines.append(f"- provider/model: {summary.provider} / {summary.model}")
    lines.append(f"- K resamples: {summary.k_resamples}")
    lines.append(f"- git: {summary.git_sha}  |  cost: ${summary.total_cost_usd:.2f}"
                 f"  |  halt: {summary.halt_reason}")
    n_valid = sum(1 for s in summary.scenario_results if s.control_exceeds_noise)
    n_total = len(summary.scenario_results)
    if n_total and n_valid == 0:
        lines.append("")
        lines.append("> **RUN VOID** — no scenario has a valid positive control; the "
                     "harness cannot be trusted to register a real change. All verdicts "
                     "below are unreliable.")
    elif n_valid < n_total:
        lines.append("")
        lines.append(f"> **PARTIAL** — {n_valid}/{n_total} scenarios have a valid positive "
                     "control. Scenarios flagged ⚠ below have an INVALID control; their "
                     "verdicts are unreliable. The rest are control-backed.")
    if summary.deferred_scenario_ids:
        lines.append("")
        lines.append(f"> Deferred (budget): {', '.join(summary.deferred_scenario_ids)} "
                     "— selected but not measured this run (not silently dropped).")
    lines.append("")
    for sr in summary.scenario_results:
        flag = "" if sr.control_exceeds_noise else "  ⚠ CONTROL INVALID — verdicts unreliable"
        lines.append(f"## {sr.scenario_id}{flag}")
        lines.append(f"Positive control exceeds noise: **{sr.control_exceeds_noise}**")
        if sr.skipped_operators:
            lines.append(f"No-op operators (skipped): {', '.join(sr.skipped_operators)}")
        lines.append("")
        lines.append("| operator | effect | p | 95% CI | verdict |")
        lines.append("|---|---|---|---|---|")
        for op in sr.operator_results:
            lines.append(
                f"| {op.operator_name} | {op.effect_size:+.3f} | {op.p_value:.3f} "
                f"| [{op.ci_low:+.3f}, {op.ci_high:+.3f}] | {op.verdict} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_report(summary: ArchitectFramingSummary) -> Path:
    path = Path(summary.traces_path).parent / f"ARCHITECT_FRAMING_{summary.run_id}.md"
    path.write_text(render_report(summary), encoding="utf-8")
    return path
