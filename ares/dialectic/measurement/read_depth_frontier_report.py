# ares/dialectic/measurement/read_depth_frontier_report.py
"""Markdown + JSON emitters for the read-depth frontier (Phase B).

The JSON ``coordinates`` payload feeds the Phase-C visual-companion frontier
plot. The markdown is the human-readable summary. Neither asserts a frontier
*verdict* (that needs the Phase-C LLM anchor + pre-registration).
"""
from __future__ import annotations

import json

from ares.dialectic.measurement.read_depth_frontier_schema import (
    VIEWS,
    FrontierSummary,
)

# Carry-forward #2: keep the blindness claim precise.
_PRECISION_NOTE = (
    "> Note: \"tier 1 is blind to value-borne attacks\" is precise only for the "
    "`high_threat_field` (M1) rule; `high_stage_without_authorization` (M2) "
    "still fires via the field-name-derived kill-chain stage."
)


def render_report(summary: FrontierSummary) -> str:
    """Render the frontier as a markdown report (no verdict)."""
    lines = [
        "# Read-Depth Robustness Frontier — Phase B (deterministic tiers)",
        "",
        f"Corpus digest: `{summary.corpus_digest}`  |  "
        f"operating point: malign_score > {summary.config.operating_point}",
        "",
        f"Semantic operators: {', '.join(summary.config.semantic_operator_names)}",
        f"Lexical operators: {', '.join(summary.config.lexical_operator_names)}",
        "",
        "No frontier verdict here — that requires the Phase-C LLM anchor (tier 4) "
        "and the pre-registration commit.",
        "",
    ]
    for view in VIEWS:
        lines += [
            f"## View: {view}",
            "",
            "| tier | X_semantic | X_lexical | TPR | FPR | Youden J |",
            "|------|-----------:|----------:|----:|----:|---------:|",
        ]
        for c in summary.coordinates:
            if c.view != view:
                continue
            lines.append(
                f"| {c.tier_id} | {c.x_semantic:.3f} | {c.x_lexical:.3f} "
                f"| {c.tpr:.3f} | {c.fpr:.3f} | {c.youden_j:.3f} |"
            )
        lines.append("")
    # Positive-control summary.
    lines += ["## Positive control (inject genuine authorization)", ""]
    moved = [pc for pc in summary.positive_control_records
             if pc.view == "standalone" and pc.moved]
    lines.append(
        f"Standalone verdict MOVED in {len(moved)} (tier, scenario) cells "
        "— expected: the structural tier swings benign, value tiers hold."
    )
    lines += ["", _PRECISION_NOTE, ""]
    return "\n".join(lines)


def coordinates_json(summary: FrontierSummary) -> str:
    """Emit the (X, Y) coordinates + provenance as JSON (for the plot)."""
    return json.dumps(
        {
            "coordinates": [c.to_dict() for c in summary.coordinates],
            "corpus_digest": summary.corpus_digest,
            "config": summary.config.to_dict(),
        },
        sort_keys=True,
        indent=2,
    )
