"""Markdown report renderer for the dual-agent framing measurement (Session 084)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ares.dialectic.measurement.dual_agent_framing_schema import DualAgentFramingSummary


def _agent_table(summary: DualAgentFramingSummary, attr: str, title: str) -> str:
    lines = [f"### {title} — per-operator verdicts\n",
             "| scenario | operator | within med | cross med | effect | p | verdict |",
             "|---|---|---|---|---|---|---|"]
    for s in summary.scenario_results:
        ar = getattr(s, attr)
        for op in ar.operator_results:
            lines.append(
                f"| {s.scenario_id} | {op.operator_name} | {op.within_median:.3f} | "
                f"{op.cross_median:.3f} | {op.effect_size:+.3f} | {op.p_value:.3f} | {op.verdict} |"
            )
    return "\n".join(lines)


def _mirror_table(summary: DualAgentFramingSummary) -> str:
    lines = ["### Dual-agent mirror — paired direction by condition\n",
             "| scenario | operator | arch jac | arch dir | skep jac | skep dir | mirror |",
             "|---|---|---|---|---|---|---|"]
    for s in summary.scenario_results:
        for m in s.mirror:
            lines.append(
                f"| {m.scenario_id} | {m.operator_name} | {m.architect_jaccard:.2f} | "
                f"{m.architect_direction} | {m.skeptic_jaccard:.2f} | {m.skeptic_direction} | "
                f"{m.mirror_class} |"
            )
    return "\n".join(lines)


def _control_section(summary: DualAgentFramingSummary) -> str:
    lines = ["### Positive-control validity\n",
             f"- control_valid_architect: **{summary.control_valid_architect}**",
             f"- control_valid_skeptic: **{summary.control_valid_skeptic}**"]
    flagged = []
    for s in summary.scenario_results:
        if not s.architect.control_exceeds_noise:
            flagged.append(f"{s.scenario_id} (architect)")
        if not s.skeptic.control_exceeds_noise:
            flagged.append(f"{s.scenario_id} (skeptic)")
    if flagged:
        lines.append("- control-unvalidated (result flagged): " + ", ".join(flagged))
    else:
        lines.append("- all scenarios control-valid for both agents")
    return "\n".join(lines)


def _mirror_summary(summary: DualAgentFramingSummary) -> str:
    c: Counter = Counter()
    for s in summary.scenario_results:
        for m in s.mirror:
            c[m.mirror_class] += 1
    parts = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    return f"### Mirror summary\n\nmirror-class counts across all conditions: {parts or '(none)'}"


def render_report(summary: DualAgentFramingSummary) -> str:
    header = (
        f"# Dual-Agent Framing Measurement — {summary.run_id}\n\n"
        f"- git_sha: {summary.git_sha}\n"
        f"- provider/model: {summary.provider} / {summary.model}\n"
        f"- K resamples: {summary.k_resamples}\n"
        f"- operators: {', '.join(summary.operator_names)}\n"
        f"- scenarios: {len(summary.scenario_results)} "
        f"(deferred: {len(summary.deferred_scenario_ids)})\n"
        f"- total cost: ${summary.total_cost_usd:.2f}\n"
        f"- halt: {summary.halt_reason}\n"
    )
    return "\n\n".join([
        header,
        _agent_table(summary, "architect", "Architect path"),
        _agent_table(summary, "skeptic", "Skeptic path"),
        _mirror_table(summary),
        _control_section(summary),
        _mirror_summary(summary),
    ]) + "\n"


def write_report(summary: DualAgentFramingSummary) -> str:
    text = render_report(summary)
    out = Path(summary.traces_path).parent / f"DUAL_AGENT_FRAMING_{summary.run_id}.md"
    out.write_text(text, encoding="utf-8")
    return str(out)
