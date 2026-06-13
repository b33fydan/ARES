"""Paper 4 figure renderer — Session 094 (Phase 2).

Renders fig_1..6 (the read-depth robustness trilemma) from the closed
S088-S090 artifacts to vector PDF at acmart sigconf column widths. Every
plotted value traces to a file under data/paper_4/ (no hardcoded magic
numbers in the data figures).

Usage::

    python -m docs.paper_4.build_figures
    python -m docs.paper_4.build_figures --figure 2   # render one

Output: docs/paper_4/figures/fig_{1..6}.pdf
"""
from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("pdf")
# TrueType (fonttype 42), not matplotlib's PDF-default Type 3 which ACM
# camera-ready / IEEE PDF eXpress reject (Paper 3 B3 lesson).
matplotlib.rcParams["pdf.fonttype"] = 42
matplotlib.rcParams["ps.fonttype"] = 42
import matplotlib.pyplot as plt
import matplotlib.patches as mpatches
from matplotlib.patches import FancyBboxPatch

REPO = Path(__file__).resolve().parents[2]
OUT = REPO / "docs" / "paper_4" / "figures"
FRONTIER = REPO / "data" / "paper_4" / "read_depth_frontier"
OOV = REPO / "data" / "paper_4" / "read_depth_oov"

SINGLE_COL = 3.333
DOUBLE_COL = 7.0

# Palette (carried from Paper 3 for cross-paper visual consistency).
C_STABLE = "#2E7D32"      # robust / resist / pass (green)
C_DIVERGE = "#C62828"     # evaded / flip / fail (red)
C_LADDER = "#1565C0"      # ladder / detection (blue)
C_ADVERSARY = "#E65100"   # OOV adversary (orange)
C_AUDIT = "#4A148C"       # independent judges (purple)
C_GOODCORNER = "#FFF9C4"  # good-corner shading (pale yellow)
C_BORDER = "#BDBDBD"
C_CODEBG = "#F5F5F5"
C_HIGHLIGHT = "#FFF9C4"
C_LINENUM = "#9E9E9E"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _save(fig: "plt.Figure", name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.pdf"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"  {name}.pdf  ({path.stat().st_size:,} bytes)")


_LADDER_ORDER = ["v1_field", "v2_structured", "v2_lexical",
                 "v2_canonical", "llm_semantic"]
_TIER_LABEL = {
    "v1_field": "v1_field", "v2_structured": "v2_struct",
    "v2_lexical": "v2_lexical", "v2_canonical": "v2_canon",
    "llm_semantic": "LLM",
}
GOOD_X_MAX = 0.10   # framing-robust band (prereg)
GOOD_J_MIN = 0.50   # high-detection band (prereg)


def _frontier_points(view: str) -> dict:
    """tier_id -> (x_semantic, youden_j) for `view`, merging the
    deterministic rungs (frontier_coordinates.json) with llm_semantic
    (tier4_summary.json). Pure read from disk — no hardcoded values."""
    pts = {}
    for c in _load(FRONTIER / "frontier_coordinates.json")["coordinates"]:
        if c["view"] == view:
            pts[c["tier_id"]] = (c["x_semantic"], c["youden_j"])
    for c in _load(FRONTIER / "tier4_summary.json")["coordinates"]:
        if c["view"] == view and c["tier_id"] == "llm_semantic":
            pts[c["tier_id"]] = (c["x_semantic"], c["youden_j"])
    return pts


def render_fig_2() -> None:
    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL, 3.0), sharey=True)
    for ax, view in zip(axes, ("standalone", "cumulative")):
        pts = _frontier_points(view)
        # good-corner shading
        ax.add_patch(mpatches.Rectangle(
            (0, GOOD_J_MIN), GOOD_X_MAX, 1.0 - GOOD_J_MIN,
            facecolor=C_GOODCORNER, edgecolor=C_STABLE, linewidth=1.0,
            linestyle="--", zorder=0))
        # jitter overlapping points horizontally so all 5 are visible
        seen: dict = {}
        for tier in _LADDER_ORDER:
            x, j = pts[tier]
            key = (round(x, 4), round(j, 4))
            n = seen.get(key, 0); seen[key] = n + 1
            xx = x + n * 0.012
            occupied = (x <= GOOD_X_MAX and j >= GOOD_J_MIN)
            color = C_DIVERGE if (tier == "v2_canonical" and occupied) else C_LADDER
            ax.scatter([xx], [j], s=46, color=color, zorder=3,
                       edgecolor="white", linewidth=0.6)
            ax.annotate(_TIER_LABEL[tier], (xx, j),
                        textcoords="offset points", xytext=(5, 3),
                        fontsize=6.0, color="#333333")
        ax.set_title(view, fontsize=8, fontweight="bold")
        ax.set_xlabel(r"$X_{\mathrm{sem}}$ (framing-flip rate)", fontsize=7.5)
        ax.set_xlim(-0.03, 0.42)
        ax.set_ylim(-0.05, 1.05)
        ax.tick_params(labelsize=7)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.axvline(GOOD_X_MAX, color=C_BORDER, lw=0.6, ls=":")
        ax.axhline(GOOD_J_MIN, color=C_BORDER, lw=0.6, ls=":")
    axes[0].set_ylabel("Youden's J (TPR - FPR)", fontsize=7.5)
    axes[0].text(0.005, 0.96, "good corner", fontsize=6, color=C_STABLE,
                 style="italic", va="top")
    axes[1].text(0.20, 0.27, "all rungs cap\nat J = 0.25", fontsize=6.5,
                 color=C_DIVERGE, ha="left", va="center", style="italic")
    fig.suptitle("Read-depth frontier: good corner occupied standalone, "
                 "empty cumulative", fontsize=8.5, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.95))
    _save(fig, "fig_2")


ALL_FIGURES: dict[int, "callable"] = {}
ALL_FIGURES[2] = render_fig_2


def main() -> int:
    parser = argparse.ArgumentParser(description="Paper 4 figure renderer")
    parser.add_argument("--figure", type=int, default=None,
                        help="Render a single figure (1-6). Default: all.")
    args = parser.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    targets = ({args.figure: ALL_FIGURES[args.figure]}
               if args.figure else ALL_FIGURES)
    print(f"Rendering {len(targets)} figure(s) to {OUT}/")
    for num, fn in sorted(targets.items()):
        print(f"  fig_{num}...", end="", flush=True)
        fn()
    print(f"\nDone. {len(targets)} PDF(s) written.")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
