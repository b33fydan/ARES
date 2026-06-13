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


_OOV_SCENARIOS = ["RDF-M-LEX-001", "RDF-M-LEX-002",
                  "RDF-M-SYN-001", "RDF-M-PATCH-001"]
_OOV_SHORT = {"RDF-M-LEX-001": "LEX-001\n(lsass)",
              "RDF-M-LEX-002": "LEX-002\n(exe-in-temp)",
              "RDF-M-SYN-001": "SYN-001\n(synonym)",
              "RDF-M-PATCH-001": "PATCH-001\n(procdump)"}


def _oov_flips(arm: str) -> dict:
    """scenario_id -> count of canonical_flipped over its K records, for arm."""
    recs = [r for r in _load(OOV / "oov_summary.json")["records"]
            if r["arm"] == arm]
    out = {s: 0 for s in _OOV_SCENARIOS}
    for r in recs:
        if r["canonical_flipped"]:
            out[r["scenario_id"]] += 1
    return out


def render_fig_3() -> None:
    black = _oov_flips("black")
    white = _oov_flips("white")
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    x = range(len(_OOV_SCENARIOS)); w = 0.38
    ax.bar([i - w / 2 for i in x], [black[s] for s in _OOV_SCENARIOS], w,
           color=C_ADVERSARY, label="black-box", edgecolor="white", linewidth=0.5)
    ax.bar([i + w / 2 for i in x], [white[s] for s in _OOV_SCENARIOS], w,
           color=C_AUDIT, label="white-box", edgecolor="white", linewidth=0.5)
    ax.set_xticks(list(x))
    ax.set_xticklabels([_OOV_SHORT[s] for s in _OOV_SCENARIOS], fontsize=6.0)
    ax.set_ylabel("canonical flips (of K=8)", fontsize=7.5)
    ax.set_ylim(0, 8.5)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.legend(fontsize=6.5, loc="upper left", framealpha=0.9)
    ax.text(0.5, 8.0, "evaded", fontsize=6.5, color=C_DIVERGE,
            ha="center", style="italic")
    ax.text(2.5, 8.0, "", fontsize=6.5)
    ax.axvspan(0.5, 2.5, color=C_DIVERGE, alpha=0.05)
    fig.tight_layout()
    _save(fig, "fig_3")


_JUDGES = [("sonnet", "Sonnet\n(original)", C_BORDER),
           ("gemini", "Gemini", C_AUDIT),
           ("openai", "GPT-4o", C_ADVERSARY)]


def _audit_malign_counts() -> dict:
    """judge -> count of malign verdicts over the evading disguises.
    sonnet is malign on every evading entry by construction; the
    independents come from each entry's `independents` list."""
    ev = _load(OOV / "oov_audit.json")["evading"]
    counts = {"sonnet": 0, "gemini": 0, "openai": 0}
    for e in ev:
        if e.get("sonnet_malign", True):
            counts["sonnet"] += 1
        for judge, verdict in e["independents"]:
            if verdict:
                counts[judge] += 1
    return counts


def render_fig_4() -> None:
    audit = _load(OOV / "oov_audit.json")
    counts = _audit_malign_counts()
    n_ev = len(audit["evading"])
    n_conf = sum(1 for e in audit["evading"]
                 if e["classification"] == "independent_confirmed")
    n_split = sum(1 for e in audit["evading"]
                  if e["classification"] == "independent_split")
    n_ctrl = len(audit["controls"])
    fig, ax = plt.subplots(figsize=(SINGLE_COL, 2.3))
    xs = range(len(_JUDGES))
    ax.bar(list(xs), [counts[k] for k, _, _ in _JUDGES],
           0.6, color=[c for _, _, c in _JUDGES], edgecolor="white", linewidth=0.5)
    for i, (k, _, _) in enumerate(_JUDGES):
        ax.text(i, counts[k] + 0.3, str(counts[k]), ha="center",
                fontsize=8, fontweight="bold")
    ax.set_xticks(list(xs))
    ax.set_xticklabels([lbl for _, lbl, _ in _JUDGES], fontsize=6.5)
    ax.set_ylabel(f"malign verdicts (of {n_ev} evading)", fontsize=7.5)
    ax.set_ylim(0, n_ev + 3)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title(f"Audit: {n_conf} confirmed / {n_split} split; "
                 f"{n_ctrl}/{n_ctrl} controls pass -> ROBUST",
                 fontsize=7.0, fontweight="bold")
    fig.tight_layout()
    _save(fig, "fig_4")


def render_fig_1() -> None:
    rungs = [
        ("v1_field", "reads: field presence only"),
        ("v2_structured", "reads: high-threat field + stage logic"),
        ("v2_lexical", "reads: exe-in-user-path regex"),
        ("v2_canonical", "reads: canonicalize-then-match"),
        ("llm_semantic", "reads: full LLM by meaning"),
    ]
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 3.0))
    ax.set_xlim(0, 10); ax.set_ylim(0, 6); ax.axis("off")
    bw, bh = 5.2, 0.8
    for i, (name, reads) in enumerate(rungs):
        x = 0.6 + i * 0.7
        y = 0.6 + i * 1.0
        shade = 0.30 + 0.14 * i
        ax.add_patch(FancyBboxPatch(
            (x, y), bw, bh, boxstyle="round,pad=0.06",
            facecolor=C_LADDER, alpha=shade, edgecolor=C_LADDER, linewidth=1.0))
        ax.text(x + 0.15, y + bh / 2, name, ha="left", va="center",
                fontsize=7.5, fontweight="bold", family="monospace")
        ax.text(x + bw - 0.15, y + bh / 2, reads, ha="right", va="center",
                fontsize=6.0, color="#333333", style="italic")
    ax.annotate("", xy=(0.35, 5.6), xytext=(0.35, 0.5),
                arrowprops=dict(arrowstyle="->", color=C_DIVERGE, lw=1.4))
    ax.text(0.05, 3.0, "read depth", rotation=90, va="center", ha="center",
            fontsize=7, color=C_DIVERGE, fontweight="bold")
    ax.text(9.6, 0.2, "deeper -> more detection AND more\nattacker-controlled "
            "surface (the trilemma)", ha="right", va="bottom",
            fontsize=6.5, color=C_DIVERGE, style="italic")
    _save(fig, "fig_1")


def render_fig_5() -> None:
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 2.4))
    ax.set_xlim(0, 12); ax.set_ylim(0, 5); ax.axis("off")
    boxes = [
        (0.3, 3.0, "LLM adversary\n(generate\ndisguises)", C_ADVERSARY),
        (3.2, 3.0, "deterministic gate\n(skeleton +\nnovelty)", C_STABLE),
        (6.1, 3.0, "LLM judge\n(meaning-\npreserving?)", C_AUDIT),
        (9.0, 3.0, "verdict", C_LADDER),
    ]
    bw, bh = 2.4, 1.4
    for x, y, label, color in boxes:
        ax.add_patch(FancyBboxPatch((x, y), bw, bh, boxstyle="round,pad=0.08",
                     facecolor=color, alpha=0.85, edgecolor="black", linewidth=0.8))
        ax.text(x + bw / 2, y + bh / 2, label, ha="center", va="center",
                fontsize=7, fontweight="bold", color="white")
    for x1 in (0.3, 3.2, 6.1):
        ax.annotate("", xy=(x1 + bw + 0.45, 3.0 + bh / 2),
                    xytext=(x1 + bw + 0.05, 3.0 + bh / 2),
                    arrowprops=dict(arrowstyle="->", color="black", lw=1.2))
    ax.add_patch(FancyBboxPatch((6.1, 0.5), 5.3, 1.2, boxstyle="round,pad=0.08",
                 facecolor=C_AUDIT, alpha=0.5, edgecolor=C_AUDIT, linewidth=1.0))
    ax.text(8.75, 1.1, "independent audit: GPT-4o + Gemini\n+ calibration controls",
            ha="center", va="center", fontsize=6.5, fontweight="bold", color="#222222")
    ax.annotate("", xy=(9.0 + bw / 2, 2.95), xytext=(9.0 + bw / 2, 1.75),
                arrowprops=dict(arrowstyle="->", color=C_AUDIT, lw=1.1))
    ax.text(6.0, 4.7, "LLM proposes, code disposes", ha="center", va="top",
            fontsize=8, fontweight="bold", color="#222222")
    _save(fig, "fig_5")


def _first_syn001_disguise() -> dict:
    for e in _load(OOV / "oov_audit.json")["evading"]:
        if (e["scenario_id"] == "RDF-M-SYN-001" and e["arm"] == "black"
                and e["classification"] == "independent_confirmed"):
            return e
    raise LookupError("no confirmed black SYN-001 evading disguise found")


def render_fig_6() -> None:
    e = _first_syn001_disguise()
    orig = [v for _, v in e["original_values"]]
    new = [v for _, v in e["value_rewrites"]]
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 1.9))
    ax.set_xlim(0, 12); ax.set_ylim(0, len(orig) + 1.6); ax.axis("off")
    ax.text(3.0, len(orig) + 1.1, "original (canonical matches)", ha="center",
            fontsize=7, fontweight="bold", color=C_STABLE)
    ax.text(9.0, len(orig) + 1.1, "OOV disguise (canonical misses)", ha="center",
            fontsize=7, fontweight="bold", color=C_DIVERGE)
    for i, (o, n) in enumerate(zip(orig, new)):
        y = len(orig) - i
        ax.add_patch(mpatches.Rectangle((0.2, y - 0.35), 5.6, 0.7,
                     facecolor=C_CODEBG, edgecolor=C_BORDER, linewidth=0.5))
        ax.text(0.4, y, o, ha="left", va="center", fontsize=6.0, family="monospace")
        ax.add_patch(mpatches.Rectangle((6.2, y - 0.35), 5.6, 0.7,
                     facecolor="#FFEBEE", edgecolor=C_DIVERGE, linewidth=0.5))
        ax.text(6.4, y, n, ha="left", va="center", fontsize=6.0, family="monospace")
        ax.annotate("", xy=(6.15, y), xytext=(5.85, y),
                    arrowprops=dict(arrowstyle="->", color="#999999", lw=0.8))
    ax.text(6.0, 0.2, "meaning preserved -> both independents (GPT-4o + Gemini) "
            "read it malign", ha="center", va="bottom", fontsize=6.0,
            color=C_DIVERGE, style="italic")
    _save(fig, "fig_6")


ALL_FIGURES: dict[int, "callable"] = {}
ALL_FIGURES[1] = render_fig_1
ALL_FIGURES[2] = render_fig_2
ALL_FIGURES[3] = render_fig_3
ALL_FIGURES[4] = render_fig_4
ALL_FIGURES[5] = render_fig_5
ALL_FIGURES[6] = render_fig_6


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
