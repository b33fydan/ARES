"""Paper 3 figure renderer — Session 073.

Renders fig_1 through fig_6 from backed source artifacts to vector PDF
at ACM sigconf column widths.  Every plotted value traces to a locked
prose substring or a verified source file.

Usage::

    python -m docs.paper_3.build_figures
    python -m docs.paper_3.build_figures --figure 3   # render one

Output: docs/paper_3/figures/fig_{1..6}.pdf
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import matplotlib
matplotlib.use("pdf")
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch, FancyArrowPatch

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "paper_3" / "figures"

SINGLE_COL = 3.333
DOUBLE_COL = 7.0

C_STABLE = "#2E7D32"
C_DIVERGE = "#C62828"
C_ARCHITECT = "#E65100"
C_SKEPTIC = "#4A148C"
C_ORACLE = "#006064"
C_EVIDENCE = "#37474F"
C_DECISION = "#1565C0"
C_EXPLAIN = "#C62828"
C_HIGHLIGHT = "#FFF9C4"
C_CODEBG = "#F5F5F5"
C_LINENUM = "#9E9E9E"
C_KEYWORD = "#1565C0"
C_COMMENT = "#6A8759"
C_STRING = "#6A8759"
C_BG_CARD = "#FAFAFA"
C_BORDER = "#BDBDBD"


def _save(fig: plt.Figure, name: str) -> None:
    path = OUT / f"{name}.pdf"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"  {name}.pdf  ({path.stat().st_size:,} bytes)")


# =========================================================================
# fig_1 — ARES pipeline architecture (DESIGN-REQUIRED, double-col, ≤2.6in)
# =========================================================================

def render_fig_1() -> None:
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 2.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 3.2)
    ax.axis("off")

    box_h = 1.4
    box_y = 1.2
    boxes = [
        (0.3, 1.5, "Evidence\nPacket", C_EVIDENCE, "white"),
        (2.2, 1.5, "Architect\n(LLM)", C_ARCHITECT, "white"),
        (4.1, 1.5, "Oracle\nFirewall", C_ORACLE, "white"),
        (6.0, 1.5, "Skeptic\n(LLM | Light)", C_SKEPTIC, "white"),
        (7.9, 1.8, "OracleJudge\n(Deterministic)", C_ORACLE, "white"),
    ]

    for x, w, label, color, tc in boxes:
        rect = FancyBboxPatch(
            (x, box_y), w, box_h,
            boxstyle="round,pad=0.08",
            facecolor=color, edgecolor="black", linewidth=0.8,
            alpha=0.85,
        )
        ax.add_patch(rect)
        ax.text(
            x + w / 2, box_y + box_h / 2, label,
            ha="center", va="center", fontsize=7.5,
            fontweight="bold", color=tc, family="sans-serif",
        )

    arrows = [
        (0.3 + 1.5, 2.2 + 1.5 / 2),
        (2.2 + 1.5, 4.1 + 1.5 / 2),
        (4.1 + 1.5, 6.0 + 1.5 / 2),
        (6.0 + 1.5, 7.9 + 1.8 / 2),
    ]
    for (x1, x2) in arrows:
        mid_y = box_y + box_h / 2
        ax.annotate(
            "", xy=(x2 - 0.55, mid_y), xytext=(x1 + 0.05, mid_y),
            arrowprops=dict(arrowstyle="->", color="black", lw=1.2),
        )

    ax.text(
        6.0 + 1.5 / 2, box_y - 0.35,
        "Light Skeptic: 4 evidence-graph rules\n"
        "(authorization | benign_indicator | kill_chain_stage | default_floor)",
        ha="center", va="top", fontsize=6, color="#555555",
        family="monospace", style="italic",
    )

    ax.text(
        7.9 + 1.8 / 2, box_y + box_h + 0.15,
        "Verdict",
        ha="center", va="bottom", fontsize=7, fontweight="bold",
        color=C_ORACLE, family="sans-serif",
    )

    _save(fig, "fig_1")


# =========================================================================
# fig_2 — InfluenceLeakage 4-bit decomposition (DESIGN-REQUIRED, ≤2.4in)
# =========================================================================

def render_fig_2() -> None:
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.2))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")

    ax.text(5, 6.6, "InfluenceLeakage  (per-pair, per-layer)",
            ha="center", va="top", fontsize=8, fontweight="bold",
            family="sans-serif")

    bits = [
        ("verdict_changed", "0.40", C_DIVERGE),
        ("action_changed", "0.20", C_ARCHITECT),
        ("cited_facts_changed", "0.20", C_DECISION),
        ("confidence_drift_exceeded", "0.20", C_SKEPTIC),
    ]

    start_y = 5.6
    for i, (name, weight, color) in enumerate(bits):
        y = start_y - i * 1.2
        rect = FancyBboxPatch(
            (0.5, y - 0.35), 6.5, 0.7,
            boxstyle="round,pad=0.06",
            facecolor="white", edgecolor=color, linewidth=1.2,
        )
        ax.add_patch(rect)
        ax.text(0.8, y, name, ha="left", va="center",
                fontsize=7, family="monospace", color="#333333")
        ax.text(7.4, y, f"w = {weight}", ha="left", va="center",
                fontsize=7, family="monospace", fontweight="bold",
                color=color)

    ax.text(5, 0.8, "weighted_scalar = Σ (bit × weight)",
            ha="center", va="center", fontsize=7, family="monospace",
            color="#555555")
    ax.text(5, 0.3, "kill fires when weighted_scalar > 0.0",
            ha="center", va="center", fontsize=6.5, family="monospace",
            color=C_DIVERGE, style="italic")

    ax.annotate(
        "", xy=(5, 1.2), xytext=(5, start_y - 3 * 1.2 - 0.5),
        arrowprops=dict(arrowstyle="->", color="#999999", lw=1),
    )

    _save(fig, "fig_2")


# =========================================================================
# fig_3 — Byte-stability vs LLM comparison (DATA, ≤2.4in)
#
# Backed quantities (locked prose substrings):
#   - 98/98 byte-stable (narrow-extended report §2)
#   - 73/98 divergent, 25/98 stable (run 2 report §3)
#   - Per-layer: architect 39, skeptic_llm 34 (run 2 report §3)
# =========================================================================

def render_fig_3() -> None:
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.1))

    labels = [
        "Deterministic\nLight Skeptic",
        "Full LLM\nSkeptic",
    ]
    stable = [98, 25]
    diverge = [0, 73]

    x = [0, 1]
    bar_w = 0.55

    bars_s = ax.bar(x, stable, bar_w, color=C_STABLE, label="Stable pairs",
                    edgecolor="white", linewidth=0.5)
    bars_d = ax.bar(x, diverge, bar_w, bottom=stable, color=C_DIVERGE,
                    label="Divergent pairs", edgecolor="white", linewidth=0.5)

    ax.text(0, 98 / 2, "98/98\nstable", ha="center", va="center",
            fontsize=8, fontweight="bold", color="white")
    ax.text(1, 25 / 2, "25", ha="center", va="center",
            fontsize=7, color="white")
    ax.text(1, 25 + 73 / 2, "73/98\ndiverge", ha="center", va="center",
            fontsize=8, fontweight="bold", color="white")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, fontsize=7.5)
    ax.set_ylabel("Paired trials (N = 98)", fontsize=7.5)
    ax.set_ylim(0, 108)
    ax.set_yticks([0, 25, 50, 75, 98])
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)

    ax.legend(fontsize=6.5, loc="upper right", framealpha=0.9)

    fig.tight_layout()
    _save(fig, "fig_3")


# =========================================================================
# fig_4 — Verdict two-surface structure (DESIGN-REQUIRED, ≤2.5in)
# =========================================================================

def render_fig_4() -> None:
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, 7)
    ax.axis("off")

    ax.text(5, 6.7, "Verdict Object", ha="center", va="top",
            fontsize=9, fontweight="bold", family="sans-serif")

    dec_rect = FancyBboxPatch(
        (0.3, 3.6), 4.2, 2.6,
        boxstyle="round,pad=0.1",
        facecolor="#E3F2FD", edgecolor=C_DECISION, linewidth=1.3,
    )
    ax.add_patch(dec_rect)
    ax.text(2.4, 6.0, "Decision Surface", ha="center", va="center",
            fontsize=7.5, fontweight="bold", color=C_DECISION)
    for i, field in enumerate(["outcome", "confidence", "reasoning"]):
        ax.text(2.4, 5.3 - i * 0.55, field, ha="center", va="center",
                fontsize=7, family="monospace", color="#333333")

    exp_rect = FancyBboxPatch(
        (5.5, 3.6), 4.2, 2.6,
        boxstyle="round,pad=0.1",
        facecolor="#FFEBEE", edgecolor=C_EXPLAIN, linewidth=1.3,
    )
    ax.add_patch(exp_rect)
    ax.text(7.6, 6.0, "Explanation Surface", ha="center", va="center",
            fontsize=7.5, fontweight="bold", color=C_EXPLAIN)
    ax.text(7.6, 5.0, "supporting_fact_ids", ha="center", va="center",
            fontsize=7, family="monospace", color="#333333")

    ax.annotate(
        "", xy=(2.4, 3.4), xytext=(2.4, 2.6),
        arrowprops=dict(arrowstyle="<-", color=C_DECISION, lw=1.3),
    )
    ax.text(2.4, 2.3, "Decision Table\n(deterministic)", ha="center",
            va="top", fontsize=6.5, color=C_DECISION, family="sans-serif")

    ax.annotate(
        "", xy=(7.6, 3.4), xytext=(7.6, 2.6),
        arrowprops=dict(arrowstyle="<-", color=C_EXPLAIN, lw=1.3),
    )
    ax.text(7.6, 2.3, "arch_facts passthrough\noracle.py:102",
            ha="center", va="top", fontsize=6.5, color=C_EXPLAIN,
            family="monospace", fontweight="bold")

    ax.text(2.4, 1.2, "Byte-stable\nunder perturbation",
            ha="center", va="center", fontsize=6, color=C_STABLE,
            fontweight="bold")
    ax.text(7.6, 1.2, "Drifts with\nArchitect output",
            ha="center", va="center", fontsize=6, color=C_DIVERGE,
            fontweight="bold")

    ax.annotate(
        "", xy=(4.7, 4.9), xytext=(5.3, 4.9),
        arrowprops=dict(
            arrowstyle="-",
            color="#999999", lw=0.8,
            linestyle="dashed",
        ),
    )

    _save(fig, "fig_4")


# =========================================================================
# fig_5 — light_skeptic.py:185 code snippet (DATA, ≤1.4in)
# =========================================================================

def render_fig_5() -> None:
    light_skeptic = REPO / "ares" / "dialectic" / "agents" / "light_skeptic.py"
    lines = light_skeptic.read_text(encoding="utf-8").splitlines()

    start = 183
    end = 190
    snippet = lines[start:end]

    fig, ax = plt.subplots(figsize=(SINGLE_COL, 1.3))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(snippet) + 1.5)
    ax.axis("off")

    highlight_line = 185

    for i, line_text in enumerate(snippet):
        line_num = start + 1 + i
        y = len(snippet) - i + 0.2

        if line_num == highlight_line:
            rect = mpatches.Rectangle(
                (0, y - 0.42), 10, 0.85,
                facecolor=C_HIGHLIGHT, edgecolor="none",
            )
            ax.add_patch(rect)

        ax.text(0.3, y, str(line_num), ha="right", va="center",
                fontsize=5.5, family="monospace", color=C_LINENUM)

        ax.text(0.6, y, line_text, ha="left", va="center",
                fontsize=5.5, family="monospace", color="#333333")

    target_y = len(snippet) - (highlight_line - start - 1) + 0.2
    ax.annotate(
        "discard: Architect output\ndeliberately unused",
        xy=(5.5, target_y),
        xytext=(7.5, target_y + 2.2),
        fontsize=5.5, color=C_DIVERGE, fontweight="bold",
        ha="center",
        arrowprops=dict(arrowstyle="->", color=C_DIVERGE, lw=0.8),
    )

    _save(fig, "fig_5")


# =========================================================================
# fig_6 — oracle.py:101-111 code snippet (DATA, ≤2.6in)
# =========================================================================

def render_fig_6() -> None:
    oracle = REPO / "ares" / "dialectic" / "agents" / "oracle.py"
    lines = oracle.read_text(encoding="utf-8").splitlines()

    start = 99
    end = 112
    snippet = lines[start:end]

    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    ax.set_xlim(0, 10)
    ax.set_ylim(0, len(snippet) + 2)
    ax.axis("off")

    highlight_line = 102

    for i, line_text in enumerate(snippet):
        line_num = start + 1 + i
        y = len(snippet) - i + 0.5

        if line_num == highlight_line:
            rect = mpatches.Rectangle(
                (0, y - 0.42), 10, 0.85,
                facecolor=C_HIGHLIGHT, edgecolor=C_DIVERGE,
                linewidth=0.6,
            )
            ax.add_patch(rect)

        ax.text(0.5, y, str(line_num), ha="right", va="center",
                fontsize=5, family="monospace", color=C_LINENUM)

        ax.text(0.8, y, line_text, ha="left", va="center",
                fontsize=5, family="monospace", color="#333333")

    ax.annotate(
        "passthrough:\narch_facts → Verdict",
        xy=(9.0, len(snippet) - (highlight_line - start - 1) + 0.5),
        xytext=(8.0, 1.0),
        fontsize=5.5, color=C_DIVERGE, fontweight="bold",
        ha="center",
        arrowprops=dict(arrowstyle="->", color=C_DIVERGE, lw=0.8),
    )

    _save(fig, "fig_6")


# =========================================================================
# CLI
# =========================================================================

ALL_FIGURES = {
    1: render_fig_1,
    2: render_fig_2,
    3: render_fig_3,
    4: render_fig_4,
    5: render_fig_5,
    6: render_fig_6,
}


def main() -> int:
    parser = argparse.ArgumentParser(description="Paper 3 figure renderer")
    parser.add_argument(
        "--figure", type=int, default=None,
        help="Render a single figure (1-6). Default: all.",
    )
    args = parser.parse_args()

    OUT.mkdir(parents=True, exist_ok=True)

    targets = {args.figure: ALL_FIGURES[args.figure]} if args.figure else ALL_FIGURES

    print(f"Rendering {len(targets)} figure(s) to {OUT}/")
    for num, fn in sorted(targets.items()):
        print(f"  fig_{num}...", end="", flush=True)
        fn()

    print(f"\nDone. {len(targets)} PDF(s) written.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
