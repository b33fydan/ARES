"""Session 060 narrow-extended report renderer.

Emits ``LEAKAGE_REPORT_<run_id>_narrow_extended.md`` at the repo root.
Six sections in this exact order, rate-based (no Boolean verdict):

    1. Run metadata
    2. Narrow stability rate
    3. Per-operator narrow stability rate
    4. Per-pair record table (narrow fires only)
    5. Cross-reference to Session 059
    6. Paper 3 narrow-claim status (rate-based)

Discipline preserved: forbidden hedging phrases are guarded at
render-time and raise ``RuntimeError`` if they leak into the report.
"""

from __future__ import annotations

from pathlib import Path

from ares.dialectic.measurement.influence_leakage import CONFIDENCE_DRIFT_THRESHOLD
from ares.dialectic.measurement.leakage_runner import (
    HALT_ANCHOR_TEST_FAILURE,
    HALT_COMPLETED,
    HALT_COST_CEILING,
)
from ares.dialectic.measurement.narrow_characterization_runner import (
    NarrowExtendedSummary,
)


_FORBIDDEN_PHRASES_IN_VERDICT: tuple[str, ...] = (
    "appears to",
    "may indicate",
    "potentially",
    "suggests",
    "could indicate",
)


def _section_metadata(summary: NarrowExtendedSummary) -> str:
    halt_label = {
        HALT_COMPLETED: "completed",
        HALT_COST_CEILING: "cost_ceiling",
        HALT_ANCHOR_TEST_FAILURE: "anchor_test_failure",
    }.get(summary.halt_reason, summary.halt_reason)
    lines = [
        "## 1. Run metadata",
        "",
        f"- **run_id**: `{summary.run_id}`",
        f"- **timestamp**: `{summary.timestamp_iso}`",
        f"- **git_sha**: `{summary.git_sha}`",
        f"- **provider**: `{summary.provider}`",
        f"- **model**: `{summary.model}`",
        f"- **total_cost_usd**: `${summary.total_cost_usd:.4f}`",
        f"- **cycles_completed**: `{summary.cycles_completed}`",
        f"- **halt_reason**: `{halt_label}`",
        f"- **anchor_test_at_start**: "
        f"`{'pass' if summary.anchor_test_passed_at_start else 'FAIL'}`",
        f"- **anchor_test_at_end**: "
        f"`{'pass' if summary.anchor_test_passed_at_end else 'FAIL'}`",
        f"- **operator_set**: `{list(summary.operator_set)}`",
        f"- **confidence_drift_threshold**: "
        f"`{summary.confidence_drift_threshold}`",
        f"- **traces_path**: `{summary.traces_path}`",
        f"- **sha256_path**: `{summary.sha256_path}`",
        f"- **measurement_mode**: `characterization` (no halt on narrow "
        "fire; light path only)",
    ]
    return "\n".join(lines)


def _section_narrow_stability_rate(summary: NarrowExtendedSummary) -> str:
    rate = summary.narrow_stability_rate
    pct = summary.narrow_stability_percent
    lines = [
        "## 2. Narrow stability rate",
        "",
        "**Light Skeptic byte-stability on the deterministic path** "
        "across all skeleton-preserving paired mutations.",
        "",
        f"- **pairs_evaluated**: {summary.n_pairs_evaluated}",
        f"- **pairs_stable_narrow**: {summary.n_pairs_stable_narrow}",
        f"- **pairs_narrow_fired**: {summary.n_pairs_narrow_fired}",
        "",
        f"- **narrow_stability_rate**: "
        f"`{summary.n_pairs_stable_narrow} / {summary.n_pairs_evaluated} "
        f"= {rate:.4f}`",
        f"- **narrow_stability_percent**: `{pct:.2f}%`",
    ]
    return "\n".join(lines)


def _section_per_operator_stability(summary: NarrowExtendedSummary) -> str:
    per_op = summary.per_operator_stability()
    lines = [
        "## 3. Per-operator narrow stability rate",
        "",
        "| operator | n_evaluated | n_stable | n_fired | stability_rate | stability_percent |",
        "|---|---|---|---|---|---|",
    ]
    for op in summary.operator_set:
        stats = per_op.get(op, {})
        lines.append(
            f"| `{op}` | "
            f"{stats.get('n_evaluated', 0)} | "
            f"{stats.get('n_stable', 0)} | "
            f"{stats.get('n_narrow_fired', 0)} | "
            f"{stats.get('stability_rate', 0.0):.4f} | "
            f"{stats.get('stability_percent', 0.0):.2f}% |"
        )
    return "\n".join(lines)


def _section_per_pair_drift_table(summary: NarrowExtendedSummary) -> str:
    if not summary.drift_records:
        return (
            "## 4. Per-pair record table (narrow fires only)\n\n"
            "**No narrow fires observed.** Light Skeptic was byte-stable "
            "on every evaluated pair."
        )

    lines = [
        "## 4. Per-pair record table (narrow fires only)",
        "",
        "Each row is one pair where `kill_fires_narrow == True`. The "
        "drifted field is identified by the corresponding bit.",
        "",
        "| scenario_id | operator | verdict_changed | action_changed (rules) | conf_drift | baseline_rules | mutated_rules | baseline_conf | mutated_conf |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for d in summary.drift_records:
        b_rules = ",".join(d.baseline_triggered_rules) or "(none)"
        m_rules = ",".join(d.mutated_triggered_rules) or "(none)"
        lines.append(
            f"| `{d.scenario_id}` | "
            f"`{d.operator_name}` | "
            f"{d.verdict_changed} | "
            f"{d.action_changed} | "
            f"{d.confidence_drift_exceeded} | "
            f"`{b_rules}` | "
            f"`{m_rules}` | "
            f"{d.baseline_confidence:.4f} | "
            f"{d.mutated_confidence:.4f} |"
        )
    return "\n".join(lines)


def _section_session_059_crossref() -> str:
    return (
        "## 5. Cross-reference to Session 059\n\n"
        "This run **extends only the narrow-reading characterization** of "
        "Paper 3's claim. The Session 059 run-2 report "
        "(`LEAKAGE_REPORT_20260510-193950-f401a8.md`) remains the "
        "canonical locked verdict for both readings:\n\n"
        "- Session 059 narrow verdict (N=2 light pairs): `Paper 3 claim "
        "status (narrow / Light Skeptic only): ALIVE`\n"
        "- Session 059 brief-broad verdict (N=2 light pairs): "
        "`Paper 3 claim status (brief_broad / Light + Oracle + Final): "
        "DEAD`\n\n"
        "Session 060 expands the narrow N from 2 to the achievable bound "
        "under the cost ceiling. **The broad-reading verdict is unchanged "
        "by this run** and remains DEAD per the Oracle citation-surface "
        "passthrough finding documented in Session 059's debrief."
    )


def _section_paper_3_narrow_status(summary: NarrowExtendedSummary) -> str:
    """Rate-based Paper 3 narrow-claim status line. No Boolean verdict.

    Discipline assertion guards against forbidden phrases.
    """
    line = (
        f"`Paper 3 narrow claim: HOLDS at "
        f"{summary.n_pairs_stable_narrow}/{summary.n_pairs_evaluated} "
        f"pairs ({summary.narrow_stability_percent:.2f}%)`"
    )
    rendered = "## 6. Paper 3 narrow-claim status\n\n" + line

    lowered = rendered.lower()
    for phrase in _FORBIDDEN_PHRASES_IN_VERDICT:
        if phrase in lowered:
            raise RuntimeError(
                f"discipline violation: forbidden phrase {phrase!r} "
                f"appeared in Paper 3 status section"
            )
    return rendered


def render_report(summary: NarrowExtendedSummary) -> str:
    """Render the full Session 060 narrow-extended report markdown."""
    title = f"# LEAKAGE_REPORT — {summary.run_id} (narrow-extended)"
    sections = [
        title,
        "",
        _section_metadata(summary),
        "",
        _section_narrow_stability_rate(summary),
        "",
        _section_per_operator_stability(summary),
        "",
        _section_per_pair_drift_table(summary),
        "",
        _section_session_059_crossref(),
        "",
        _section_paper_3_narrow_status(summary),
        "",
    ]
    return "\n".join(sections)


def write_report(
    summary: NarrowExtendedSummary, output_dir: Path | None = None
) -> Path:
    """Write the rendered report to
    ``LEAKAGE_REPORT_<run_id>_narrow_extended.md`` at the repo root.

    Args:
        summary: A frozen :class:`NarrowExtendedSummary`.
        output_dir: Where to write. Defaults to repo root.

    Returns:
        The path written.
    """
    if output_dir is None:
        output_dir = Path(__file__).resolve().parents[3]
    output_dir.mkdir(parents=True, exist_ok=True)
    path = output_dir / f"LEAKAGE_REPORT_{summary.run_id}_narrow_extended.md"
    path.write_text(render_report(summary), encoding="utf-8")
    return path


__all__ = ["render_report", "write_report"]
