"""Paper 5 figure renderer — Session 101 (Phase 2).

Renders fig_1..6 (the ARES-Harness injection defense / deterministic-guarantee
result) from the closed S099 artifact to vector PDF at acmart sigconf column
widths. Every plotted value in data figures traces to
data/paper_5/s099_phase3_run_20260627-070037.json (no hardcoded magic numbers).
Conceptual figures (1, 2-right, 5, 6) are hand-drawn.

Usage::

    python -m docs.paper_5.build_figures
    python -m docs.paper_5.build_figures --figure 2   # render one

Output: docs/paper_5/figures/fig_{1..6}.pdf
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
OUT = REPO / "docs" / "paper_5" / "figures"
RUN = REPO / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"

SINGLE_COL = 3.333
DOUBLE_COL = 7.0

# Palette — identical to Paper 4 for cross-paper visual consistency.
# Semantic mapping for Paper 5:
#   C_STABLE   = allow / clean / utility-kept / guarantee-holds  (green)
#   C_DIVERGE  = deny / tainted / blocked / the-cost             (red)
#   C_LADDER   = neutral / structural stages                     (blue)
#   C_ADVERSARY= injected / attacker path                        (orange)
#   C_AUDIT    = conclusion-integrity                             (purple)
C_STABLE = "#2E7D32"
C_DIVERGE = "#C62828"
C_LADDER = "#1565C0"
C_ADVERSARY = "#E65100"
C_AUDIT = "#4A148C"
C_GOODCORNER = "#FFF9C4"
C_BORDER = "#BDBDBD"
C_CODEBG = "#F5F5F5"
C_HIGHLIGHT = "#FFF9C4"
C_LINENUM = "#9E9E9E"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))


def _run() -> dict:
    """Load the canonical S099 run artifact (read-only)."""
    return _load(RUN)


def _save(fig: "plt.Figure", name: str) -> None:
    OUT.mkdir(parents=True, exist_ok=True)
    path = OUT / f"{name}.pdf"
    fig.savefig(path, bbox_inches="tight", pad_inches=0.04)
    plt.close(fig)
    print(f"  {name}.pdf  ({path.stat().st_size:,} bytes)")


# ---------------------------------------------------------------------------
# fig_1 — ARES-Harness architecture (conceptual; host §3; DOUBLE_COL)
# ---------------------------------------------------------------------------

def render_fig_1() -> None:
    """Left-to-right pipeline: 5 input-path stages → action gate → allow/deny."""
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 2.6))
    ax.set_xlim(0, 10); ax.set_ylim(0, 4); ax.axis("off")

    # Five input-path modules (blue), evenly spaced along x
    input_stages = [
        "capture",
        "normalize",
        "ingress-scan",
        "IOC-anchor",
        "quarantine /\ninert-render",
    ]
    stage_x = [0.15, 1.85, 3.55, 5.25, 6.95]
    bw, bh = 1.55, 0.85

    for i, (label, x) in enumerate(zip(input_stages, stage_x)):
        ax.add_patch(FancyBboxPatch(
            (x, 2.1), bw, bh, boxstyle="round,pad=0.06",
            facecolor=C_LADDER, alpha=0.80, edgecolor=C_LADDER, linewidth=1.0))
        ax.text(x + bw / 2, 2.1 + bh / 2, label,
                ha="center", va="center", fontsize=6.5, fontweight="bold",
                color="white", family="monospace")
        # Arrow to next stage
        if i < len(input_stages) - 1:
            ax.annotate("", xy=(stage_x[i + 1] - 0.05, 2.1 + bh / 2),
                        xytext=(x + bw + 0.05, 2.1 + bh / 2),
                        arrowprops=dict(arrowstyle="->", color="#444444", lw=0.9))

    # Action gate (green)
    gate_x = 8.65
    gate_bw, gate_bh = 1.20, 0.85
    ax.add_patch(FancyBboxPatch(
        (gate_x, 2.1), gate_bw, gate_bh, boxstyle="round,pad=0.06",
        facecolor=C_STABLE, alpha=0.90, edgecolor=C_STABLE, linewidth=1.2))
    ax.text(gate_x + gate_bw / 2, 2.1 + gate_bh / 2, "action\ngate",
            ha="center", va="center", fontsize=6.5, fontweight="bold", color="white")

    # Arrow from last input stage to gate
    ax.annotate("", xy=(gate_x - 0.05, 2.1 + gate_bh / 2),
                xytext=(stage_x[-1] + bw + 0.05, 2.1 + bh / 2),
                arrowprops=dict(arrowstyle="->", color="#444444", lw=0.9))

    # ALLOW / DENY outputs
    ax.annotate("", xy=(9.30 + 0.35, 3.35),
                xytext=(gate_x + gate_bw / 2, 2.1 + gate_bh),
                arrowprops=dict(arrowstyle="->", color=C_STABLE, lw=1.0))
    ax.text(9.70, 3.50, "ALLOW", ha="center", va="bottom",
            fontsize=7, fontweight="bold", color=C_STABLE)

    ax.annotate("", xy=(9.30 + 0.35, 0.85),
                xytext=(gate_x + gate_bw / 2, 2.1),
                arrowprops=dict(arrowstyle="->", color=C_DIVERGE, lw=1.0))
    ax.text(9.70, 0.70, "DENY", ha="center", va="top",
            fontsize=7, fontweight="bold", color=C_DIVERGE)

    # Band under the 5 input-path stages
    band_left = stage_x[0]
    band_right = stage_x[-1] + bw
    band_y = 1.75
    ax.add_patch(mpatches.FancyBboxPatch(
        (band_left, band_y), band_right - band_left, 0.28,
        boxstyle="round,pad=0.04",
        facecolor=C_LADDER, alpha=0.12, edgecolor=C_LADDER, linewidth=0.5))
    ax.text((band_left + band_right) / 2, band_y + 0.14,
            "untrusted content rendered inert (data, never instructions)",
            ha="center", va="center", fontsize=6.0, color=C_LADDER, style="italic")

    # Caption strip at bottom
    ax.text(5.0, 0.25,
            "fail-closed at every stage; provenance derived harness-side from raw bytes",
            ha="center", va="center", fontsize=6.0, color="#444444", style="italic")

    ax.set_title("ARES-Harness: input-path defense → action gate",
                 fontsize=8, fontweight="bold")
    fig.tight_layout()
    _save(fig, "fig_1")


# ---------------------------------------------------------------------------
# fig_2 — Money figure: regime + guarantee (two-panel; DOUBLE_COL)
# ---------------------------------------------------------------------------

def render_fig_2() -> None:
    run = _run()
    sweep = run["sweep"]
    tau_asr = run["tau_asr"]
    gate_denials_live = run["stage1_arms"]["full_defense"]["gate_denials"]

    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL, 3.2))

    # ── LEFT PANEL: no-headroom regime ────────────────────────────────────
    ax = axes[0]
    cell_labels = [
        f"{c['model'].split('-')[0]}·{'ii' if 'important' in c['attack'] else 'tk'}"
        for c in sweep
    ]
    asr_vals = [c["undefended_asr"] for c in sweep]
    x_pos = list(range(len(sweep)))

    bars = ax.bar(x_pos, asr_vals, color=C_BORDER, edgecolor="white",
                  linewidth=0.5, width=0.55)
    # Label the 0.00 atop each bar (zero bars need explicit label)
    for i, v in enumerate(asr_vals):
        ax.text(i, 0.015, f"{v:.2f}", ha="center", va="bottom",
                fontsize=7, color="#555555", fontweight="bold")

    ax.axhline(tau_asr, color=C_DIVERGE, lw=1.1, ls="--", zorder=3)
    ax.text(len(sweep) - 0.5, tau_asr + 0.015,
            f"τ_asr = {tau_asr} (selection threshold)",
            ha="right", va="bottom", fontsize=6.5, color=C_DIVERGE)

    ax.set_xticks(x_pos)
    ax.set_xticklabels(cell_labels, fontsize=6.5)
    ax.set_ylabel("Undefended ASR", fontsize=7.5)
    ax.set_ylim(0, 0.40)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title("Undefended ASR = 0 across the grid", fontsize=8, fontweight="bold")
    ax.text(0.5, 0.22, "no cell clears τ →\nno-cell contingency",
            ha="center", va="center", transform=ax.transAxes,
            fontsize=6.5, color=C_DIVERGE, style="italic",
            bbox=dict(boxstyle="round,pad=0.3", facecolor="white",
                      edgecolor=C_DIVERGE, linewidth=0.7, alpha=0.9))

    # ── RIGHT PANEL: by-construction gate rule ─────────────────────────────
    ax = axes[1]
    ax.set_xlim(0, 4); ax.set_ylim(0, 5); ax.axis("off")

    cap_classes = ["READ_ONLY", "WRITE_LOCAL", "IRREVERSIBLE", "EXFIL_SHAPED"]
    col_labels = ["clean arg", "tainted arg"]

    # Column headers
    ax.text(1.5, 4.60, "provenance →", ha="center", va="bottom",
            fontsize=7, fontweight="bold", color="#333333")
    for j, cl in enumerate(col_labels):
        ax.text(1.0 + j * 1.5, 4.40, cl, ha="center", va="bottom",
                fontsize=6.5, color="#333333")

    # Row labels + cells
    # PRIVILEGED_CLASSES = {WRITE_LOCAL, IRREVERSIBLE, EXFIL_SHAPED}
    # (per action_gate.py) — READ_ONLY always ALLOW; privileged ∩ tainted → DENY
    _PRIVILEGED = {"WRITE_LOCAL", "IRREVERSIBLE", "EXFIL_SHAPED"}
    deny_cells_drawn = 0
    deny_tainted_cx = None  # track x of the tainted column for annotation
    deny_row_y_top = None   # topmost DENY cell y
    deny_row_y_bot = None   # bottommost DENY cell y

    for i, cap in enumerate(cap_classes):
        row_y = 3.5 - i * 0.85
        ax.text(0.0, row_y + 0.30, cap, ha="left", va="center",
                fontsize=6.0, family="monospace", color="#333333")
        for j in range(2):
            tainted = (j == 1)
            privileged = cap in _PRIVILEGED
            allow = not (tainted and privileged)
            cell_color = C_STABLE if allow else C_DIVERGE
            cell_text = "ALLOW" if allow else "DENY"
            cx = 0.75 + j * 1.5
            cy = row_y
            ax.add_patch(FancyBboxPatch(
                (cx, cy), 1.10, 0.60, boxstyle="round,pad=0.04",
                facecolor=cell_color, alpha=0.80,
                edgecolor=cell_color, linewidth=0.8))
            ax.text(cx + 0.55, cy + 0.30, cell_text,
                    ha="center", va="center", fontsize=6.5,
                    fontweight="bold", color="white")
            if not allow:
                deny_cells_drawn += 1
                deny_tainted_cx = cx
                if deny_row_y_top is None:
                    deny_row_y_top = cy + 0.60  # top edge of first deny cell
                deny_row_y_bot = cy             # bottom edge of last deny cell

    # Single annotation OUTSIDE the matrix, pointing at the tainted-arg DENY region
    if deny_cells_drawn > 0 and deny_tainted_cx is not None:
        annot_x = deny_tainted_cx + 1.10 + 0.08  # just to the right of tainted column
        annot_y = (deny_row_y_top + deny_row_y_bot) / 2  # vertically centered on deny region
        ax.annotate(
            f"← {gate_denials_live} live gate denials\n"
            "  (injected privileged\n   tainted calls)",
            xy=(deny_tainted_cx + 1.10, annot_y),
            xytext=(annot_x + 0.05, annot_y),
            fontsize=5.5, color=C_DIVERGE, style="italic",
            va="center", ha="left",
            arrowprops=dict(arrowstyle="-|>", color=C_DIVERGE, lw=0.9),
        )

    ax.text(2.0, 0.15,
            "value-blind, no LLM — holds env-state ASR = 0 by construction",
            ha="center", va="bottom", fontsize=6.0, color="#444444", style="italic")
    ax.set_title("The gate: (class × arg-taint) → allow / deny",
                 fontsize=8, fontweight="bold")

    fig.suptitle(
        "A deterministic gate holds injected actions at zero"
        " — in a regime with no ASR headroom left",
        fontsize=8.5, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.93))
    _save(fig, "fig_2")


# ---------------------------------------------------------------------------
# fig_3 — Arms on the fallback cell (DATA; host §6; slightly wider SINGLE_COL)
# ---------------------------------------------------------------------------

def render_fig_3() -> None:
    run = _run()
    arms_data = run["stage1_arms"]

    arm_names = ["undefended", "full_defense", "gate_off"]
    arm_labels = ["undefended", "full_defense", "gate_off"]
    arm_colors = [C_BORDER, C_STABLE, C_LADDER]

    measures = ["asr", "utility", "gate_denials", "conclusion_integrity_rate"]
    measure_labels = ["ASR", "Utility", "Gate\nDenials", "Conclusion\nIntegrity"]

    # Collect values
    vals = {arm: [arms_data[arm][m] for m in measures] for arm in arm_names}

    fig, axes = plt.subplots(1, 4, figsize=(DOUBLE_COL, 2.5))

    for mi, (m_key, m_lbl) in enumerate(zip(measures, measure_labels)):
        ax = axes[mi]
        x = range(len(arm_names))
        bar_vals = [vals[arm][mi] for arm in arm_names]

        # Highlight gate_denials subplot
        if m_key == "gate_denials":
            edge_colors = ["none", C_STABLE, "none"]
            lws = [0.5, 2.0, 0.5]
        else:
            edge_colors = ["none"] * 3
            lws = [0.5] * 3

        for xi, (bv, bc, ec, lw) in enumerate(zip(bar_vals, arm_colors, edge_colors, lws)):
            ax.bar(xi, bv, color=bc, alpha=0.85, edgecolor=ec,
                   linewidth=lw, width=0.6)
            label_str = str(int(bv)) if m_key == "gate_denials" else f"{bv:.2f}"
            ax.text(xi, bv + 0.02 * (ax.get_ylim()[1] if ax.get_ylim()[1] > 0 else 1),
                    label_str, ha="center", va="bottom",
                    fontsize=7, fontweight="bold", color="#333333")

        ax.set_xticks(list(x))
        ax.set_xticklabels(["U", "FD", "GO"], fontsize=6.5)
        ax.set_title(m_lbl, fontsize=7, fontweight="bold")
        ax.tick_params(axis="y", labelsize=6.5)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)

        # Set y limits sensibly
        max_val = max(bar_vals) if max(bar_vals) > 0 else 1.0
        ax.set_ylim(0, max_val * 1.40)

        # Re-label bars after ylim is set
        for xi, bv in enumerate(bar_vals):
            label_str = str(int(bv)) if m_key == "gate_denials" else f"{bv:.2f}"
            ax.texts[xi].set_y(bv + max_val * 0.05)

    # Legend
    legend_patches = [
        mpatches.Patch(color=C_BORDER, label="undefended (U)"),
        mpatches.Patch(color=C_STABLE, label="full_defense (FD)"),
        mpatches.Patch(color=C_LADDER, label="gate_off (GO)"),
    ]
    fig.legend(handles=legend_patches, loc="lower center", ncol=3,
               fontsize=6.0, framealpha=0.9,
               bbox_to_anchor=(0.5, -0.02))
    fig.suptitle("Arms @ fallback cell (haiku / important_instructions, N=20)",
                 fontsize=8, fontweight="bold")
    fig.tight_layout(rect=(0, 0.08, 1, 0.93))
    _save(fig, "fig_3")


# ---------------------------------------------------------------------------
# fig_4 — The honest cost (DATA; host §6; SINGLE_COL)
# ---------------------------------------------------------------------------

def render_fig_4() -> None:
    run = _run()
    arms = run["stage1_arms"]
    benign = run["benign_false_block"]["full_defense"]

    false_block_rate = benign["false_block_rate_per_task"]  # 0.2
    benign_denials = benign["benign_denials"]               # 4
    benign_n = benign["n"]                                  # 20
    util_undef = arms["undefended"]["utility"]              # 0.5
    util_full = arms["full_defense"]["utility"]             # 0.3

    fig, axes = plt.subplots(1, 2, figsize=(DOUBLE_COL * 0.70, 2.6))

    # ── LEFT: benign false-block rate ────────────────────────────────────
    ax = axes[0]
    # Pre-registered band shading
    ax.axhspan(0, 0.50, facecolor=C_GOODCORNER, alpha=0.70, zorder=0)
    ax.axhline(0.50, color="#888888", lw=1.0, ls="--", zorder=2)
    ax.text(0.55, 0.50 + 0.015, "pre-registered band ≤ 0.50",
            ha="left", va="bottom", fontsize=6.0, color="#555555",
            transform=ax.get_yaxis_transform())

    ax.bar([0], [false_block_rate], color=C_DIVERGE, alpha=0.85,
           width=0.50, edgecolor="none")
    ax.text(0, false_block_rate + 0.015, f"{false_block_rate:.2f}",
            ha="center", va="bottom", fontsize=8, fontweight="bold",
            color=C_DIVERGE)
    ax.text(0, false_block_rate / 2,
            f"{benign_denials}/{benign_n}\nbenign tasks\nover-blocked",
            ha="center", va="center", fontsize=6.5, color="white",
            fontweight="bold")
    ax.set_xticks([0])
    ax.set_xticklabels(["full_defense"], fontsize=7)
    ax.set_ylabel("False-block rate", fontsize=7.5)
    ax.set_ylim(0, 0.70)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title("Benign false-block", fontsize=7.5, fontweight="bold")

    # ── RIGHT: utility cost ───────────────────────────────────────────────
    ax = axes[1]
    x_pos = [0, 1]
    util_vals = [util_undef, util_full]
    util_colors = [C_BORDER, C_STABLE]
    util_labels = ["undefended", "full_defense"]

    ax.bar(x_pos, util_vals, color=util_colors, alpha=0.85,
           width=0.50, edgecolor="none")
    for xi, val in zip(x_pos, util_vals):
        ax.text(xi, val + 0.015, f"{val:.2f}",
                ha="center", va="bottom", fontsize=8,
                fontweight="bold", color="#333333")

    # Delta annotation arrow
    delta = util_full - util_undef
    ax.annotate("",
                xy=(1, util_full + 0.03),
                xytext=(0, util_undef + 0.03),
                arrowprops=dict(arrowstyle="<->", color="#555555", lw=1.0))
    ax.text(0.5, max(util_vals) + 0.08, f"Δ = {delta:+.2f}",
            ha="center", va="bottom", fontsize=7, color="#555555",
            fontweight="bold")

    ax.set_xticks(x_pos)
    ax.set_xticklabels(util_labels, fontsize=6.5)
    ax.set_ylabel("Utility", fontsize=7.5)
    ax.set_ylim(0, 0.85)
    ax.tick_params(axis="y", labelsize=7)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.set_title("Utility cost", fontsize=7.5, fontweight="bold")

    fig.suptitle("The guarantee's honest cost (within the pre-registered band)",
                 fontsize=8, fontweight="bold")
    fig.tight_layout(rect=(0, 0, 1, 0.90))
    _save(fig, "fig_4")


# ---------------------------------------------------------------------------
# fig_5 — SOTA positioning matrix (conceptual; host §7; DOUBLE_COL)
# ---------------------------------------------------------------------------

_SOTA_ROWS = [
    ("Dual-LLM\n(Willison '23)",      "input\n(ctrl/data sep)",  "quarantined LLM",       False),
    ("Spotlighting\n(Hines '24)",      "input",                   "prompt marking (model)", False),
    ("Instr. Hierarchy\n(Wallace '24)","input priority",          "learned (training)",     False),
    ("StruQ\n(Chen '24)",             "input",                   "struct queries + learned",False),
    ("SecAlign\n(Chen '24)",          "input",                   "preference-opt (learned)",False),
    ("CaMeL\n(Debenedetti '25)",      "action",                  "cap interp-IFC (det.)",  False),
    ("ARES-Harness\n(this work)",     "input + action",          "det. provenance-taint\n(no LLM in decision)", True),
]
_SOTA_COLS = ["Surface\nguarded", "Mechanism", "Conclusion-\nintegrity?"]


def render_fig_5() -> None:
    """SOTA positioning matrix rebuilt with explicit fixed y-positions.

    Design:
    - Figure uses data coordinates (0..1) via ax.transData for precise placement.
    - 4 columns at fixed x: System | Surface guarded | Mechanism | Conclusion-integrity
    - 1 header row + 7 data rows evenly spaced.
    - Column-4 vertical band + callout placed ABOVE the header row (no overlap).
    - ARES row highlighted with a green band.
    """
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 4.2))
    ax.set_xlim(0, 1); ax.set_ylim(0, 1); ax.axis("off")

    # ── Layout constants (all in axes-fraction coords 0..1) ─────────────────
    # Column x-centres for text; col_x_left for the CI band/cells
    # System | Surface | Mechanism | CI
    sys_x_left   = 0.00   # system name left-align start
    surf_x_ctr   = 0.22   # Surface guarded centre
    mech_x_ctr   = 0.50   # Mechanism centre
    ci_x_left    = 0.70   # CI column left edge
    ci_x_right   = 0.84   # CI column right edge
    ci_x_ctr     = (ci_x_left + ci_x_right) / 2

    n_rows = len(_SOTA_ROWS)          # 7
    header_y  = 0.935                 # y for header text (va=bottom)
    rule_y    = 0.900                 # horizontal rule under header
    rows_top  = 0.880                 # top of first data row band
    rows_bot  = 0.050                 # bottom of last data row band
    row_h     = (rows_top - rows_bot) / n_rows  # even spacing

    # ── CI column highlight band (spans all rows + header area) ─────────────
    band_bottom = rows_bot
    band_top    = rule_y + 0.005
    ax.add_patch(mpatches.Rectangle(
        (ci_x_left - 0.01, band_bottom),
        (ci_x_right - ci_x_left) + 0.02,
        band_top - band_bottom,
        facecolor=C_AUDIT, alpha=0.07, edgecolor=C_AUDIT, linewidth=0.8,
        transform=ax.transAxes, zorder=0))

    # CI callout in the RIGHT MARGIN (clear of the header + every cell), with
    # an arrow pointing left at the CI column. xlim/ylim are 0..1 so plain
    # data coords equal axes fractions.
    ax.annotate(
        "the decision-\nintegrity axis —\northogonal to all\nsurface defenses;\nonly ARES scores it",
        xy=(ci_x_right + 0.01, 0.52), xytext=(0.995, 0.55),
        ha="right", va="center", fontsize=5.5, color=C_AUDIT,
        fontweight="bold", style="italic",
        arrowprops=dict(arrowstyle="->", color=C_AUDIT, lw=0.9))

    # ── Column headers ───────────────────────────────────────────────────────
    col_headers = [
        (sys_x_left, "left",   "System"),
        (surf_x_ctr, "center", "Surface\nguarded"),
        (mech_x_ctr, "center", "Mechanism"),
        (ci_x_ctr,   "center", "Conclusion-\nintegrity?"),
    ]
    for (cx, ha_val, lbl) in col_headers:
        ax.text(cx, header_y, lbl,
                ha=ha_val, va="bottom", fontsize=7,
                fontweight="bold", color="#222222",
                transform=ax.transAxes)

    # Header rule (axhline uses data coords since xlim=0..1, ylim=0..1)
    ax.axhline(rule_y, xmin=0.0, xmax=1.0, color=C_BORDER, lw=0.8)

    # ── Data rows ────────────────────────────────────────────────────────────
    for i, (system, surface, mechanism, ci) in enumerate(_SOTA_ROWS):
        # row_y_top = top of this row band; row_y_ctr = text centre
        row_y_top = rows_top - i * row_h
        row_y_bot = row_y_top - row_h
        row_y_ctr = (row_y_top + row_y_bot) / 2
        is_ares = ci

        # Row highlight for ARES
        if is_ares:
            ax.add_patch(mpatches.Rectangle(
                (0.0, row_y_bot + 0.005),
                1.0, row_h - 0.010,
                facecolor=C_STABLE, alpha=0.09,
                edgecolor=C_STABLE, linewidth=1.0,
                transform=ax.transAxes, zorder=1))

        fw = "bold" if is_ares else "normal"

        # System name
        ax.text(sys_x_left, row_y_ctr, system,
                ha="left", va="center", fontsize=5.8, fontweight=fw,
                color="#111111", transform=ax.transAxes)

        # Surface column
        ax.text(surf_x_ctr, row_y_ctr, surface,
                ha="center", va="center", fontsize=5.6, fontweight=fw,
                color="#333333", transform=ax.transAxes)

        # Mechanism column
        ax.text(mech_x_ctr, row_y_ctr, mechanism,
                ha="center", va="center", fontsize=5.4, fontweight=fw,
                color="#333333", transform=ax.transAxes)

        # CI cell — FancyBboxPatch using axes fraction coords via transform
        cell_color = C_STABLE if ci else C_BORDER
        check = "✓" if ci else "✗"
        cell_pad_h = 0.008
        cell_pad_v = 0.012
        ax.add_patch(FancyBboxPatch(
            (ci_x_left, row_y_bot + cell_pad_v),
            ci_x_right - ci_x_left,
            row_h - 2 * cell_pad_v,
            boxstyle="round,pad=0.01",
            facecolor=cell_color, alpha=0.80,
            edgecolor=cell_color, linewidth=0.8,
            transform=ax.transAxes, zorder=2))
        ax.text(ci_x_ctr, row_y_ctr, check,
                ha="center", va="center", fontsize=9,
                fontweight="bold", color="white",
                transform=ax.transAxes, zorder=3)

    ax.set_title("Positioning: ARES-Harness vs. SOTA injection defenses",
                 fontsize=8, fontweight="bold", pad=4)
    fig.tight_layout()
    _save(fig, "fig_5")


# ---------------------------------------------------------------------------
# fig_6 — Worked example pipeline (conceptual; host §4; DOUBLE_COL)
# ---------------------------------------------------------------------------

def render_fig_6() -> None:
    run = _run()
    gate_denials = run["stage1_arms"]["full_defense"]["gate_denials"]

    # Pipeline stages: (label, color, note)
    stages = [
        ("injected\nbill text\n(untrusted)", C_ADVERSARY, ""),
        ("capture +\nnormalize", C_LADDER, ""),
        ("ingress-scan /\ninert-render", C_LADDER, ""),
        ("agent proposes\nsend_money(\n  recipient=<IBAN>)", C_BORDER, "from bill"),
        ("harness-side\nprovenance:\nrecipient → TAINTED", C_ADVERSARY, "untrusted bytes"),
        ("gate: IRREVERSIBLE\n∩ tainted → DENY", C_DIVERGE, ""),
    ]

    IBAN = "US133000000121212121212"

    n = len(stages)
    fig, ax = plt.subplots(figsize=(DOUBLE_COL, 2.8))
    ax.set_xlim(0, n * 1.65); ax.set_ylim(0, 3.5); ax.axis("off")

    bw, bh = 1.45, 1.20
    x_positions = [0.10 + i * 1.60 for i in range(n)]

    for i, ((label, color, note), x) in enumerate(zip(stages, x_positions)):
        alpha = 0.90 if color != C_BORDER else 0.55
        ec = color if color != C_BORDER else "#999999"
        ax.add_patch(FancyBboxPatch(
            (x, 1.4), bw, bh, boxstyle="round,pad=0.06",
            facecolor=color, alpha=alpha,
            edgecolor=ec, linewidth=1.0))
        txt_color = "white" if color not in (C_BORDER,) else "#333333"
        ax.text(x + bw / 2, 1.4 + bh / 2, label,
                ha="center", va="center", fontsize=5.8,
                fontweight="bold", color=txt_color)
        if note:
            ax.text(x + bw / 2, 1.35, f"({note})",
                    ha="center", va="top", fontsize=5.2,
                    color="#555555", style="italic")
        if i < n - 1:
            ax.annotate("", xy=(x_positions[i + 1] - 0.05, 1.4 + bh / 2),
                        xytext=(x + bw + 0.05, 1.4 + bh / 2),
                        arrowprops=dict(arrowstyle="->", color="#444444", lw=0.9))

    # IBAN annotation below the "send_money" box (stage index 3)
    iban_x = x_positions[3]
    ax.text(iban_x + bw / 2, 1.30,
            f"recipient=\n{IBAN}",
            ha="center", va="top", fontsize=5.2,
            family="monospace", color=C_ADVERSARY)

    # Caption at bottom
    ax.text(n * 1.65 / 2, 0.35,
            "the gate decides on WHERE the arg came from (raw-byte provenance),"
            " never on WHAT the text says",
            ha="center", va="center", fontsize=6.0, color="#444444",
            style="italic")

    # Gate-denial annotation
    ax.text(x_positions[-1] + bw / 2, 2.75,
            f"({gate_denials} injected calls\ndenied in live run)",
            ha="center", va="bottom", fontsize=5.5,
            color=C_DIVERGE, style="italic")

    ax.set_title(
        "Worked example: injected banking task → deterministic gate denial",
        fontsize=8, fontweight="bold")
    fig.tight_layout()
    _save(fig, "fig_6")


# ---------------------------------------------------------------------------
# Registry + main
# ---------------------------------------------------------------------------

ALL_FIGURES: dict[int, "callable"] = {}
ALL_FIGURES[1] = render_fig_1
ALL_FIGURES[2] = render_fig_2
ALL_FIGURES[3] = render_fig_3
ALL_FIGURES[4] = render_fig_4
ALL_FIGURES[5] = render_fig_5
ALL_FIGURES[6] = render_fig_6


def main() -> int:
    parser = argparse.ArgumentParser(description="Paper 5 figure renderer")
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
