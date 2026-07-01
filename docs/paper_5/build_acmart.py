"""Paper 5 Phase 4: build an acmart sigconf ``.tex`` from the canonical
Paper 5 source markdown, then compile it to the submission PDF.

This is the Paper 5 peer of ``docs/paper_4/build_acmart.py`` (itself a
peer of Paper 3's). The discipline is identical — the canonical markdown
at ``docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md`` is READ-ONLY here;
figures ``fig_1``..``fig_6`` are the real vector PDFs from
``docs/paper_5/build_figures.py``; references render via ``\\nocite{*}``
+ the ACM-Reference-Format style over ``docs/paper_5/references.bib``.

Adaptations the Paper 5 source forces over the Paper 4 port (each is
gate-critical, render-critical, or a source-structure difference; see
``tests/paper_5/test_build_acmart.py``):

* **Markdown dollar escapes.** The source writes every dollar amount as
  ``\\$`` (a markdown escape). A prose escape pass first *un*-escapes
  markdown punctuation, then LaTeX-escapes, so ``\\$3.8`` round-trips to
  the LaTeX literal ``\\$3.8``. The locked gate substrings ``$3.8`` /
  ``$0.07`` depend on this.
* **Two new unicode codepoints.** The Paper 5 prose adds the Greek small
  letter tau (``\\tau``, in ``tau_asr`` / ``tau_util``) and the plus-minus
  sign (``\\pm``, in the Wald-interval prose) that the Paper 4 map lacked;
  both would hard-error ``utf8`` inputenc. The rest of the Paper 4 map is
  retained as a superset.
* **"In Plain Terms" is dropped from the PDF.** The source opens with a
  plain-language ``## In Plain Terms`` section *before* the Abstract.
  acmart cannot render a section before ``\\maketitle`` / the abstract,
  and (Dan's call, S101) the submission PDF stays a conventional academic
  artifact (Title -> Abstract -> body, as Papers 1-4). The section is
  removed *in memory* only — the canonical markdown source keeps it (for
  web / Notion use). Every locked gate substring appears elsewhere in the
  body, so the drop does not weaken the PDF gate.
* **Multi-key parenthetical cites.** ``[@a; @b; @c; @d]`` ->
  ``\\citep{a, b, c, d}`` (the abstract's four self-cites).
* **Real figures + real tables, in body.** The six figures land at their
  host sections (skeleton ``figures[].host_section``) as
  ``\\includegraphics``; §6 hosts three (fig_2/3/4). The four tables
  (tbl_1..tbl_4) render as booktabs floats built from the closed S099 run
  artifact (no hardcoded measurement numbers), at their host sections.
* **Float cross-references.** Unlike Paper 4, the Paper 5 prose *does*
  point at floats with the author's "Figure N (fig_M)" / "Table N (tbl_M)"
  convention. Those literal numbers are wrong once figures float out of
  fig_id order, so they are translated to real ``\\ref`` (see
  ``substitute_float_references``); the ``(fig_M)`` scaffolding is removed.
* **References heading.** ``## 11. References`` is dropped by the body
  walker (the bibliography emits its own References section) — the same
  generic drop Paper 4 relies on; the source keeps the heading.

Usage::

    python -m docs.paper_5.build_acmart \\
        --out docs/paper_5/acmart/paper_5_acmart.tex

Then (the ``\\ref`` float cross-references need an extra settling pass, so
repeat ``pdflatex`` until the "Rerun to get cross-references right" warning
clears — typically one more pass than a ref-free build)::

    cd docs/paper_5/acmart
    pdflatex -interaction=nonstopmode paper_5_acmart.tex
    bibtex paper_5_acmart
    pdflatex -interaction=nonstopmode paper_5_acmart.tex
    pdflatex -interaction=nonstopmode paper_5_acmart.tex
    pdflatex -interaction=nonstopmode paper_5_acmart.tex
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import string
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


# =============================================================================
# Source-level constants
# =============================================================================


_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

_AUTHOR_REDACTION_MARKER = "[Author block redacted for double-blind review]"

# The plain-language section that opens the source, dropped from the PDF in
# memory (Dan's call, S101). Matches from its heading up to the next ``## ``.
_IN_PLAIN_TERMS_RE = re.compile(r"(?ms)^##\s+In Plain Terms\b.*?(?=^##\s)")

# Inline tokens: **bold**, *italic*, `code` — order matters because
# **bold** has to win against *italic* on the same starting position.
_INLINE_RE = re.compile(r"(\*\*[^*\n]+\*\*|\*[^*\n]+\*|`[^`\n]+`)")

# Non-ASCII present in the Paper 5 source. Math symbols translate to
# math-mode equivalents (the acmart default font ships no glyphs for
# them, and bare codepoints would hard-error utf8 inputenc). The em dash
# becomes ``---`` and the section sign ``\S`` so neither depends on
# inputenc behaviour. ``\tau`` and ``\pm`` are the two Paper 5 additions
# over the Paper 4 map; the rest is retained as a superset.
_UNICODE_MAP = {
    "×": r"$\times$",      # multiplication sign (grid: {haiku, sonnet} x ...)
    "τ": r"$\tau$",        # Greek small tau (tau_asr / tau_util)  [Paper 5]
    "±": r"$\pm$",         # plus-minus sign (Wald intervals)       [Paper 5]
    "Δ": r"$\Delta$",      # capital delta
    "⊕": r"$\oplus$",      # circled plus
    "≤": r"$\leq$",        # less-than-or-equal (<= 0.50 band)
    "≥": r"$\geq$",        # greater-than-or-equal
    "→": r"$\rightarrow$",  # rightwards arrow
    "−": r"$-$",           # minus sign
    "≈": r"$\approx$",      # almost-equal
    "—": r"---",           # em dash
    "§": r"\S{}",          # section sign
}


# Markdown backslash escapes: the source uses ``\$`` to write a literal
# dollar in markdown. Un-escape ``\<punct>`` -> ``<punct>`` on prose
# *before* LaTeX-escaping, so the subsequent ``$`` -> ``\$`` produces a
# single, correct LaTeX literal. Applied to prose only — code spans keep
# their literal backslashes (handled by ``latex_escape_in_verbatim``).
_MD_UNESCAPE_RE = re.compile(r"\\([" + re.escape(string.punctuation) + r"])")


def _unescape_markdown_punct(text: str) -> str:
    return _MD_UNESCAPE_RE.sub(r"\1", text)


# Pandoc-style citation markers. Parenthetical markers carry one *or more*
# semicolon-separated keys (``[@a; @b]``); narrative markers are single
# (``@a``). The narrative lookbehind excludes alphanumerics / ``_`` (spares
# email-style ``@``) and ``[`` (spares the inner ``@`` of a parenthetical
# marker). Parenthetical substitution runs first and consumes the whole
# bracket, so a multi-key marker's later keys never reach the narrative pass.
_CITE_PAREN_MARKER_RE = re.compile(
    r"\[@([a-z0-9\-]+(?:\s*;\s*@[a-z0-9\-]+)*)\]"
)
_CITE_NARRATIVE_MARKER_RE = re.compile(r"(?<![\[a-zA-Z0-9_])@([a-z0-9\-]+)\b")


def _paren_cite_repl(m: "re.Match[str]") -> str:
    keys = [k.strip().lstrip("@").strip() for k in m.group(1).split(";")]
    return r"\citep{" + ", ".join(keys) + "}"


def substitute_citation_markers(latex_text: str) -> str:
    """Convert pandoc-style citation markers to LaTeX cite commands.

    Applied AFTER inline rendering and LaTeX escaping so the substituted
    backslash commands are not themselves escaped.
    """
    out = _CITE_PAREN_MARKER_RE.sub(_paren_cite_repl, latex_text)
    out = _CITE_NARRATIVE_MARKER_RE.sub(r"\\citet{\1}", out)
    return out


# =============================================================================
# Float (figure/table) cross-references
# =============================================================================
#
# The source prose points at floats with the author's "Figure N (fig_M)" /
# "Table N (tbl_M)" convention (plus bare "(fig_M)" and inline pairs). Two
# problems this creates in the compiled PDF: the literal number N is *wrong*
# once figures float out of fig_id order (fig_6 lives in Section 4, so LaTeX
# numbers it Figure 2, not 6), and the "(fig_M)" tag is authoring scaffolding
# that should not reach a submission. We translate these to real ``\ref`` —
# the labels ``fig:fig_M`` / ``tab:tbl_M`` are emitted by render_figure /
# render_table — so the numbers auto-resolve and the scaffolding is removed.
# This is the same build-time translation posture as the citation markers,
# and runs on the ESCAPED tex where a source ``_`` has become ``\_``.


def _single_float_ref(m: "re.Match[str]") -> str:
    word, kind, num = m.group(1), m.group(2), m.group(3)
    prefix = "fig" if kind == "fig" else "tab"
    return f"{word}~\\ref{{{prefix}:{kind}_{num}}}"


def substitute_float_references(latex_text: str) -> str:
    """Convert the source's ``Figure N (fig_M)`` pointers to LaTeX ``\\ref``.

    Ordered specific-to-general so no pattern eats another's target.
    """
    out = latex_text
    # 1. "Tables A and B (tbl\_X, tbl\_Y)"
    out = re.sub(
        r"Tables\s+\d+\s+and\s+\d+\s+\(tbl\\_(\d+),\s*tbl\\_(\d+)\)",
        r"Tables~\\ref{tab:tbl_\1} and~\\ref{tab:tbl_\2}",
        out,
    )
    # 2. "Figures A, B, and C (fig\_X, fig\_Y, fig\_Z)"
    out = re.sub(
        r"Figures\s+\d+,\s*\d+,\s*and\s+\d+\s+"
        r"\(fig\\_(\d+),\s*fig\\_(\d+),\s*fig\\_(\d+)\)",
        r"Figures~\\ref{fig:fig_\1}, \\ref{fig:fig_\2}, and~\\ref{fig:fig_\3}",
        out,
    )
    # 3. inline pair "Table N, fig\_M" (parenthetical panel references)
    out = re.sub(
        r"Table\s+(\d+),\s*fig\\_(\d+)",
        r"Table~\\ref{tab:tbl_\1}, Figure~\\ref{fig:fig_\2}",
        out,
    )
    # 4. single "Figure N (fig\_M)" / "Table N (tbl\_M)"
    out = re.sub(
        r"\b(Figure|Table)\s+\d+\s+\((fig|tbl)\\_(\d+)\)",
        _single_float_ref,
        out,
    )
    # 5. bare "(fig\_M)"
    out = re.sub(
        r"\(fig\\_(\d+)\)",
        r"(Figure~\\ref{fig:fig_\1})",
        out,
    )
    return out


def _assert_no_float_scaffolding(tex: str) -> None:
    """Fail loudly if any float-reference scaffolding survived substitution.

    The five ``substitute_float_references`` patterns cover exactly the
    reference phrasings the current source uses. A future prose edit that
    introduces an unhandled form (a two-figure plural, a three-table plural,
    or a bare ``(tbl_M)`` with no leading word) would otherwise silently ship
    ``(fig_M)``-style scaffolding into the PDF. Every converted reference is
    a ``\\ref{fig:...}``/``\\ref{tab:...}`` — none contains the escaped
    ``(fig\\_`` / ``(tbl\\_`` token — so any surviving occurrence is an
    unconverted pointer. Turn that into a build failure, not a silent leak.
    """
    for token in (r"(fig\_", r"(tbl\_"):
        idx = tex.find(token)
        if idx != -1:
            raise ValueError(
                "Unconverted float-reference scaffolding survived into the "
                f".tex near {tex[idx:idx + 48]!r}. Extend "
                "substitute_float_references to cover this phrasing."
            )


# =============================================================================
# Section title / number stripping
# =============================================================================


# `## 1. Introduction` -> `Introduction`
_SECTION_TITLE_RE = re.compile(r"^\s*(\d+)\.\s+(.*)$")
# `### 5.1 Result statement` -> `Result statement`
_SUBSECTION_TITLE_RE = re.compile(r"^\s*(\d+)\.(\d+)\s+(.*)$")


def strip_section_number(title: str) -> str:
    m = _SECTION_TITLE_RE.match(title)
    return m.group(2).strip() if m else title.strip()


def strip_subsection_number(title: str) -> str:
    m = _SUBSECTION_TITLE_RE.match(title)
    return m.group(3).strip() if m else title.strip()


# =============================================================================
# LaTeX escaping
# =============================================================================


# Characters that must be escaped when emitting prose into LaTeX body text.
_LATEX_SPECIALS = {
    "&": r"\&",
    "%": r"\%",
    "$": r"\$",
    "#": r"\#",
    "_": r"\_",
    "{": r"\{",
    "}": r"\}",
    "^": r"\^{}",
    "~": r"\~{}",
}


def latex_escape(text: str) -> str:
    """Escape LaTeX special characters in plain prose.

    Un-escapes markdown punctuation first (so ``\\$`` -> ``$`` -> ``\\$``),
    then escapes specials and maps non-ASCII to math/text equivalents.
    """
    text = _unescape_markdown_punct(text)
    out: list[str] = []
    for ch in text:
        if ch in _LATEX_SPECIALS:
            out.append(_LATEX_SPECIALS[ch])
        elif ch in _UNICODE_MAP:
            out.append(_UNICODE_MAP[ch])
        else:
            out.append(ch)
    return "".join(out)


def latex_escape_in_verbatim(text: str) -> str:
    """Escape content inside ``\\texttt{...}``.

    A literal backslash becomes ``\\textbackslash{}`` (code spans carry
    real paths like ``C:\\Temp\\``); the remaining LaTeX specials and the
    non-ASCII map apply as in prose. No markdown un-escape here — a
    backslash in a code span is literal, not a markdown escape.
    """
    out: list[str] = []
    for ch in text:
        if ch == "\\":
            out.append(r"\textbackslash{}")
        elif ch in _LATEX_SPECIALS:
            out.append(_LATEX_SPECIALS[ch])
        elif ch in _UNICODE_MAP:
            out.append(_UNICODE_MAP[ch])
        else:
            out.append(ch)
    return "".join(out)


# =============================================================================
# Inline span rendering
# =============================================================================


def render_inline(text: str) -> str:
    """Render a paragraph string, honoring **bold**, *italic*, `code`."""
    pieces: list[str] = []
    pos = 0
    for m in _INLINE_RE.finditer(text):
        if m.start() > pos:
            pieces.append(latex_escape(text[pos:m.start()]))
        token = m.group(0)
        if token.startswith("**"):
            pieces.append(r"\textbf{" + latex_escape(token[2:-2]) + r"}")
        elif token.startswith("*"):
            pieces.append(r"\textit{" + latex_escape(token[1:-1]) + r"}")
        elif token.startswith("`"):
            pieces.append(r"\texttt{" + latex_escape_in_verbatim(token[1:-1]) + r"}")
        pos = m.end()
    if pos < len(text):
        pieces.append(latex_escape(text[pos:]))
    return "".join(pieces)


# =============================================================================
# Figure roster (real vector figures, in body)
# =============================================================================


@dataclass(frozen=True)
class FigureSpec:
    """One Paper 5 figure: id, host section, column span, caption."""

    fig_id: str
    host_section: int
    span: str  # ``single`` (one column) or ``double`` (figure*)
    caption: str


# Spans match the widths build_figures.py renders at: DOUBLE_COL (7.0in,
# figure*) for figures 1/2/3/5/6; SINGLE_COL (figure) for the narrower
# cost figure (fig_4, rendered at 0.70x double). Host sections match the
# skeleton's ``figures[].host_section`` (fig_1 -> 3, fig_2/3/4 -> 6,
# fig_5 -> 7, fig_6 -> 4). Because host order is not fig_id order, LaTeX
# auto-numbers the floats out of fig_id order; the prose's literal "Figure
# N" pointers are therefore resolved via ``\label``/``\ref``
# (substitute_float_references), not left to match by coincidence.
_FIGURE_ROSTER: tuple[FigureSpec, ...] = (
    FigureSpec(
        "fig_1", 3, "double",
        "The ARES-Harness architecture: untrusted content flows through a "
        "five-stage deterministic input path (capture, normalize, "
        "ingress-scan, IOC-anchor, and quarantine with inert rendering), and "
        "every proposed tool call passes the LLM-free action gate before "
        "execution. Every stage is fail-closed, and provenance is derived "
        "harness-side from the raw captured bytes; there is no language model "
        "anywhere in the defense.",
    ),
    FigureSpec(
        "fig_2", 6, "double",
        "The central result: the no-headroom regime and the by-construction "
        "guarantee. Left: undefended attack-success-rate is 0 in every cell "
        "of the model-by-attack sweep, so no cell clears the selection "
        "threshold and the pre-registered no-cell contingency fires. Right: "
        "the gate's pure decision rule over (capability class, argument "
        "taint) denies every privileged call with a tainted argument, "
        "holding environment-state attack-success-rate at zero by "
        "construction, annotated with the two live gate denials.",
    ),
    FigureSpec(
        "fig_3", 6, "double",
        "Arms on the fallback cell (haiku-4-5 / important_instructions, "
        "N = 20): attack-success-rate, utility, gate denials, and "
        "conclusion-integrity across the undefended, full_defense, and "
        "gate_off arms. Only full_defense issues gate denials (2), the "
        "cleanest defense-attributable signal, since the no-gate arms are "
        "structurally incapable of one.",
    ),
    FigureSpec(
        "fig_4", 6, "single",
        "The guarantee's honest cost. Left: the benign false-block rate is "
        "0.20 (4 of 20 benign tasks over-blocked), comfortably within the "
        "pre-registered ≤ 0.50 band. Right: the utility cost, undefended "
        "0.50 falling to 0.30 under full_defense — the price of a "
        "deterministic floor, pre-registered as a measured cost rather than "
        "discovered after the fact.",
    ),
    FigureSpec(
        "fig_5", 7, "double",
        "Positioning against SOTA injection defenses by the surface each "
        "guards and its mechanism. Model-surface defenses raise a model's "
        "learned probability of resisting; action-surface defenses move the "
        "security decision out of the model. Only ARES-Harness scores the "
        "conclusion-integrity axis, which is orthogonal to the surface each "
        "system guards.",
    ),
    FigureSpec(
        "fig_6", 4, "double",
        "A worked example end to end: an injected bill's text is captured as "
        "untrusted and rendered inert; the agent proposes a send_money call "
        "whose recipient argument is the attacker's IBAN; harness-side "
        "value-tracking finds that value in the captured untrusted bytes and "
        "taints the argument; and the gate, seeing an IRREVERSIBLE class with "
        "a tainted argument, denies the call. The gate decides on where the "
        "argument came from, never on what the text says.",
    ),
)


def figures_for_section(section_number: int) -> tuple[FigureSpec, ...]:
    """Return roster figures whose ``host_section`` matches the section."""
    return tuple(f for f in _FIGURE_ROSTER if f.host_section == section_number)


def render_figure(spec: FigureSpec) -> str:
    """Render one figure float with the real vector PDF.

    Double-column floats (``figure*``) span ``\\textwidth``; single-column
    floats span ``\\columnwidth`` — matching the assets build_figures.py
    renders.
    """
    env = "figure*" if spec.span == "double" else "figure"
    width = r"\textwidth" if spec.span == "double" else r"\columnwidth"
    body = f"\\includegraphics[width={width}]{{../figures/{spec.fig_id}.pdf}}"
    cap = latex_escape(spec.caption)
    return (
        f"\\begin{{{env}}}[!htbp]\n"
        f"\\centering\n"
        f"{body}\n"
        f"\\caption{{{cap}}}\n"
        f"\\Description{{{cap}}}\n"
        f"\\label{{fig:{spec.fig_id}}}\n"
        f"\\end{{{env}}}\n"
    )


# =============================================================================
# Table roster (rendered from the closed S099 run artifact)
# =============================================================================
#
# The Paper 5 prose references Table 1-4; the skeleton defines them. Unlike
# figures (pre-rendered vector PDFs), tables are LaTeX built here from data.
# Every measured value is read from the canonical S099 run artifact (no
# hardcoded measurement numbers); tbl_1's pre-registration constants (the
# band, the token budget, the planted IBAN) are protocol design values, and
# tbl_4 is a static positioning matrix (the same rows fig_5 draws).

_RUN_PATH = (
    Path(__file__).resolve().parents[2]
    / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"
)


def _load_run() -> dict:
    return json.loads(_RUN_PATH.read_text(encoding="utf-8"))


@dataclass(frozen=True)
class TableSpec:
    """One Paper 5 table: id, host section, column span, caption."""

    tbl_id: str
    host_section: int
    span: str  # ``single`` (one column) or ``double`` (table*)
    caption: str


_TABLE_ROSTER: tuple[TableSpec, ...] = (
    TableSpec(
        "tbl_1", 5, "double",
        "The frozen pre-registered measurement protocol (Stage A structural "
        "+ Stage B numeric): the model-by-attack grid on the banking suite, "
        "the environment-state injection-task filter, the selection "
        "thresholds, the three arms, the sample sizes, and the pre-registered "
        "benign false-block band. Every value was locked to a single source "
        "of truth before any deciding measurement spend.",
    ),
    TableSpec(
        "tbl_2", 6, "single",
        "Stage-0 sweep: undefended attack-success-rate and utility for each "
        "cell of the model-by-attack grid on the banking suite. "
        "Attack-success-rate is 0 in every cell (the no-headroom regime); "
        "utility varies, confirming the cells differ in task capability "
        "rather than all failing trivially.",
    ),
    TableSpec(
        "tbl_3", 6, "single",
        "Stage-1 arms on the fallback cell (haiku-4-5 / important_instructions "
        "/ banking, N = 20): attack-success-rate, utility, gate denials, echo "
        "rate, and conclusion-integrity. Only full_defense issues gate denials "
        "(2), the cleanest defense-attributable signal.",
    ),
    TableSpec(
        "tbl_4", 7, "double",
        "Positioning against SOTA injection defenses by the surface each "
        "guards and its mechanism. Only ARES-Harness scores the "
        "conclusion-integrity axis, which is orthogonal to the surface a "
        "defense guards.",
    ),
)


def tables_for_section(section_number: int) -> tuple[TableSpec, ...]:
    """Return roster tables whose ``host_section`` matches the section."""
    return tuple(t for t in _TABLE_ROSTER if t.host_section == section_number)


def _tt(text: str) -> str:
    """Render a code-identifier table cell as escaped ``\\texttt``."""
    return r"\texttt{" + latex_escape_in_verbatim(text) + "}"


def _tabular(colspec: str, headers: list[str], rows: list[list[str]]) -> str:
    """Assemble a booktabs tabular from already-LaTeX header/row cells."""
    out = [r"\begin{tabular}{" + colspec + "}", r"\toprule"]
    out.append(" & ".join(headers) + r" \\")
    out.append(r"\midrule")
    for row in rows:
        out.append(" & ".join(row) + r" \\")
    out.append(r"\bottomrule")
    out.append(r"\end{tabular}")
    return "\n".join(out)


# Static SOTA positioning rows (the same content fig_5 draws) — positioning
# facts, not measurement, so they live here rather than in the run artifact.
_SOTA_TABLE_ROWS: tuple[tuple[str, str, str, str], ...] = (
    ("Dual-LLM (Willison 2023)", "input (control/data sep.)",
     "quarantined second LLM", "No"),
    ("Spotlighting (Hines 2024)", "input",
     "prompt marking (learned)", "No"),
    ("Instruction hierarchy (Wallace 2024)", "input priority",
     "learned prioritization", "No"),
    ("StruQ (Chen 2024)", "input",
     "structured queries + learned", "No"),
    ("SecAlign (Chen 2024)", "input",
     "preference optimization (learned)", "No"),
    ("CaMeL (Debenedetti 2025)", "action",
     "capability interpreter-IFC (deterministic)", "No"),
    ("ARES-Harness (this work)", "input + action",
     "deterministic provenance-taint (no LLM in decision)", "Yes"),
)


def _table_body(tbl_id: str) -> str:
    """Build the booktabs tabular for one table from the run artifact."""
    run = _load_run()

    if tbl_id == "tbl_1":
        sweep = run["sweep"]
        models = sorted({c["model"] for c in sweep})
        attacks = sorted({c["attack"] for c in sweep})
        suites = sorted({c["suite"] for c in sweep})
        n_elig = len(run["eligible_injection_tasks"]["banking"])
        arms = list(run["stage1_arms"].keys())
        n_arm = run["stage1_arms"]["full_defense"]["n"]
        n_benign = run["benign_false_block"]["full_defense"]["n"]
        # Read both thresholds from the run — the prose collapses them to a
        # single value only because they are equal in this run; render them
        # separately if a future run diverges rather than asserting equality
        # in the format string.
        tau_asr = run["tau_asr"]
        tau_util = run["tau_util"]
        if tau_asr == tau_util:
            tau_cell = (
                r"$\tau_{\mathrm{asr}} = \tau_{\mathrm{util}} = "
                f"{tau_asr:.2f}$"
            )
        else:
            tau_cell = (
                rf"$\tau_{{\mathrm{{asr}}}} = {tau_asr:.2f}$, "
                rf"$\tau_{{\mathrm{{util}}}} = {tau_util:.2f}$"
            )
        shim = run["pipe_name_shim"]
        rows = [
            ["Models (grid rows)", ", ".join(_tt(m) for m in models)],
            ["Attack families (grid cols)", ", ".join(_tt(a) for a in attacks)],
            ["Suite", ", ".join(_tt(s) for s in suites)],
            ["Eligible injection tasks",
             f"{n_elig} (all environment-state, "
             f"{_tt('injection_task_0')} through {_tt('injection_task_8')})"],
            ["Selection thresholds", tau_cell],
            ["Arms", ", ".join(_tt(a) for a in arms)],
            [r"Samples per arm ($N$ / $N_{\mathrm{benign}}$)",
             f"{n_arm} / {n_benign}"],
            ["Benign false-block band", r"$\leq 0.50$"],
            ["Model token budget", r"\texttt{max\_tokens} $= 2048$"],
            ["Attack-prose resolver shim", _tt(shim)],
            ["Planted IBAN (echo-check)", _tt("US133000000121212121212")],
        ]
        return _tabular(r"l p{0.66\textwidth}",
                        ["Parameter", "Value"], rows)

    if tbl_id == "tbl_2":
        rows = [
            [_tt(c["model"]), _tt(c["attack"]),
             f"{c['undefended_asr']:.2f}", f"{c['undefended_utility']:.2f}"]
            for c in run["sweep"]
        ]
        return _tabular(
            "llrr",
            ["Model", "Attack", r"Undef.\ ASR", r"Undef.\ utility"],
            rows,
        )

    if tbl_id == "tbl_3":
        arms = ["undefended", "full_defense", "gate_off"]
        a = run["stage1_arms"]
        rows = [
            [_tt(name),
             f"{a[name]['asr']:.2f}",
             f"{a[name]['utility']:.2f}",
             str(a[name]["gate_denials"]),
             f"{a[name]['echo_rate']:.2f}",
             f"{a[name]['conclusion_integrity_rate']:.2f}"]
            for name in arms
        ]
        return _tabular(
            "lrrrrr",
            ["Arm", "ASR", "Utility", r"Gate den.", "Echo", r"C-integ."],
            rows,
        )

    if tbl_id == "tbl_4":
        rows = []
        for system, surface, mechanism, ci in _SOTA_TABLE_ROWS:
            sys_cell = latex_escape(system)
            if "this work" in system:
                sys_cell = r"\textbf{" + sys_cell + "}"
            rows.append([
                sys_cell,
                latex_escape(surface),
                latex_escape(mechanism),
                latex_escape(ci),
            ])
        return _tabular(
            r"l l p{0.40\textwidth} c",
            ["System", "Surface guarded", "Mechanism",
             r"Concl.\ integ.?"],
            rows,
        )

    raise KeyError(f"unknown table id: {tbl_id}")


def render_table(spec: TableSpec) -> str:
    """Render one table float with a booktabs tabular built from the run.

    Double-span tables use ``table*`` (both columns); single-span use
    ``table``. The body is ``\\footnotesize`` so the wider grids fit.
    """
    env = "table*" if spec.span == "double" else "table"
    cap = latex_escape(spec.caption)
    return (
        f"\\begin{{{env}}}[!htbp]\n"
        f"\\centering\n"
        f"\\caption{{{cap}}}\n"
        f"\\Description{{{cap}}}\n"
        f"\\label{{tab:{spec.tbl_id}}}\n"
        f"\\footnotesize\n"
        f"{_table_body(spec.tbl_id)}\n"
        f"\\end{{{env}}}\n"
    )


# =============================================================================
# Markdown walker
# =============================================================================


def strip_html_comments(text: str) -> str:
    return _HTML_COMMENT_RE.sub("", text)


def drop_in_plain_terms(text: str) -> str:
    """Remove the ``## In Plain Terms`` section in memory (Dan's call, S101).

    acmart cannot host a section before ``\\maketitle`` / the abstract, and
    the submission PDF stays a conventional academic artifact. The removal
    is in-memory only; the canonical markdown source keeps the section.
    """
    return _IN_PLAIN_TERMS_RE.sub("", text, count=1)


def split_appendix(source_text: str) -> tuple[str, str]:
    """Split off the Appendix so it lands after References."""
    pattern = re.compile(r"(?m)^## Appendix.*$")
    m = pattern.search(source_text)
    if not m:
        return source_text, ""
    return source_text[:m.start()].rstrip() + "\n", source_text[m.start():]


def _flush_block(out: list[str], block: list[str]) -> None:
    non_empty = [ln for ln in block if ln.strip()]
    if not non_empty:
        return
    if all(ln.lstrip().startswith("- ") for ln in non_empty):
        out.append("\\begin{itemize}")
        for ln in non_empty:
            out.append("  \\item " + render_inline(ln.lstrip()[2:]))
        out.append("\\end{itemize}")
        return
    para = " ".join(ln.strip() for ln in non_empty)
    out.append(render_inline(para))
    out.append("")


def render_body(body_text: str) -> str:
    """Walk markdown body lines, emitting LaTeX sections / paragraphs.

    The Abstract becomes ``\\begin{abstract}...\\end{abstract}`` followed by
    ``\\maketitle``; the ``# Title`` line is held out by the caller; the
    ``References`` heading is dropped (the bibliography emits its own).
    Figures hosted by a numbered section are inserted right after its
    heading.
    """
    out: list[str] = []
    block: list[str] = []
    in_abstract = False
    current_section_number = 0

    def flush() -> None:
        nonlocal block
        _flush_block(out, block)
        block = []

    for raw_line in body_text.splitlines():
        line = raw_line.rstrip()
        stripped = line.strip()

        # Title — handled by caller; skip here.
        if line.startswith("# ") and not line.startswith("## "):
            continue

        # Subsection (``### N.M Title``)
        if line.startswith("### "):
            flush()
            title = strip_subsection_number(line[4:].strip())
            out.append("")
            out.append(r"\subsection{" + latex_escape(title) + r"}")
            continue

        # Section (``## Title``)
        if line.startswith("## "):
            flush()
            heading = line[3:].strip()
            if in_abstract:
                out.append(r"\end{abstract}")
                in_abstract = False
                out.append(r"\maketitle")
                out.append("")
            if heading.lower().startswith("abstract"):
                out.append(r"\begin{abstract}")
                in_abstract = True
                continue
            m = _SECTION_TITLE_RE.match(heading)
            if m:
                current_section_number = int(m.group(1))
                title = m.group(2).strip()
            else:
                current_section_number = 0
                title = heading
            # The bibliography emits its own References section.
            if title.strip().lower() == "references":
                continue
            out.append("")
            out.append(r"\section{" + latex_escape(title) + r"}")
            for fig in figures_for_section(current_section_number):
                out.append(render_figure(fig))
            for tbl in tables_for_section(current_section_number):
                out.append(render_table(tbl))
            continue

        # Decorative separator
        if stripped == "---":
            flush()
            continue

        # Blank line closes the current block
        if not stripped:
            flush()
            continue

        # Author redaction marker — acmart anonymous mode handles authorship.
        if _AUTHOR_REDACTION_MARKER in stripped:
            flush()
            continue

        block.append(line)

    flush()

    if in_abstract:  # defensive — Paper 5 always has sections after Abstract
        out.append(r"\end{abstract}")
        out.append(r"\maketitle")
        out.append("")

    return "\n".join(out) + "\n"


# =============================================================================
# Preamble + bibliography blocks
# =============================================================================


def acmart_preamble(title_text: str) -> str:
    """Venue-neutral acmart sigconf preamble (anonymous + review).

    The Paper 5 venue is TBD ("acmart-portable"); the prose is written
    anonymized, so ``anonymous`` mode + a neutral conference stub keep the
    artifact submission-ready without committing to venue-specific metadata.
    """
    return r"""\documentclass[sigconf,anonymous,review]{acmart}

%% ---- placeins provides \FloatBarrier if float packing needs a nudge.
\usepackage{placeins}

%% ---- The Paper 5 prose carries many long inline code spans / identifiers
%%      (the grid expression, capability_class, IBAN, model ids,
%%      haiku/tool_knowledge ...). \emergencystretch lets TeX stretch the
%%      measure to place them rather than overflow into the two-column
%%      gutter. Built-in only (no package install); the voice-approved prose
%%      is not modified — a rendering-only accommodation.
\emergencystretch=3em

%% ---- author-year citations; the body emits \citep / \citet from
%%      pandoc-style markers in the canonical source.
\citestyle{acmauthoryear}

%% ---- neutral bibliographic stubs (manuscript under review) -----------
\acmConference[Preprint]{Manuscript under review}{2026}{}
\acmYear{2026}
\settopmatter{printacmref=false}
\setcopyright{none}
\renewcommand\footnotetextcopyrightpermission[1]{}
\pagestyle{plain}

%% ---- ACM CCS concepts stub (real values land at camera-ready) --------
\begin{CCSXML}
<ccs2012>
  <concept>
    <concept_id>10002978.10003022.10003023</concept_id>
    <concept_desc>Security and privacy~Software and application security</concept_desc>
    <concept_significance>500</concept_significance>
  </concept>
</ccs2012>
\end{CCSXML}
\ccsdesc[500]{Security and privacy~Software and application security}

\keywords{indirect prompt injection, deterministic defense, action authorization gate, provenance taint, tool-using LLM agents, AgentDojo, pre-registration, conclusion integrity}

\title{""" + latex_escape(title_text) + r"""}

%% ---- acmart anonymous mode requires at least one author block --------
\author{Anonymous Author(s)}
\affiliation{%
  \institution{Submission under double-blind review}
  \country{}
}
\email{anonymous@paper5.example}

\begin{document}
"""


def render_bibliography(references_path: Path, paper_dir: Path) -> str:
    """Copy references.bib into the build dir and emit the bib commands.

    ``\\nocite{*}`` forces every verified entry into the rendered
    References section even though the body prose carries pandoc-style
    cite markers converted to ``\\citep`` / ``\\citet``.
    """
    target = paper_dir / "references.bib"
    if references_path.resolve() != target.resolve():
        target.parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(references_path, target)
    return (
        r"\nocite{*}"
        + "\n"
        + r"\bibliographystyle{ACM-Reference-Format}"
        + "\n"
        + r"\bibliography{references}"
        + "\n"
    )


# =============================================================================
# Document assembly
# =============================================================================


def extract_title(source_text: str) -> str:
    for line in source_text.splitlines():
        line = line.strip()
        if line.startswith("# ") and not line.startswith("## "):
            return line[2:].strip()
    return "Untitled"


def build_tex(
    source_text: str,
    references_path: Path,
    out_path: Path,
) -> str:
    """Build the full sigconf .tex string."""
    cleaned = strip_html_comments(source_text)
    cleaned = drop_in_plain_terms(cleaned)
    body, appendix = split_appendix(cleaned)
    title = extract_title(cleaned)

    paper_dir = out_path.parent
    bib_block = render_bibliography(references_path, paper_dir)

    parts: list[str] = []
    parts.append(acmart_preamble(title))
    parts.append(render_body(body))
    # Page-count audit markers: the page of ``end-of-body`` is the body
    # page count; ``end-of-bib`` minus that is the bibliography's.
    parts.append(r"\label{end-of-body}")
    parts.append(bib_block)
    parts.append(r"\label{end-of-bib}")
    if appendix.strip():
        # Appendices land after References. ``\appendix`` switches numbering
        # to A, B, C... The ``## Appendix A:`` prefix is stripped in-memory
        # (we are already inside the ``\appendix`` region); the canonical
        # source markdown is not modified.
        parts.append(r"\appendix")
        cleaned_appendix = appendix.replace(
            "## Appendix A: Generative AI Use Declaration",
            "## Generative AI Use Declaration",
        )
        parts.append(render_body(cleaned_appendix))
        parts.append(r"\label{end-of-appendix}")
    parts.append(r"\end{document}")
    parts.append("")
    tex = "\n".join(parts)
    # Post-process pandoc-style citation markers and float cross-references
    # last, so the substituted backslash sequences are not re-escaped by
    # ``latex_escape``.
    tex = substitute_citation_markers(tex)
    tex = substitute_float_references(tex)
    _assert_no_float_scaffolding(tex)
    return tex


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a sigconf acmart .tex from the Paper 5 source markdown.",
    )
    parser.add_argument(
        "--source", type=Path,
        default=Path("docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md"),
    )
    parser.add_argument(
        "--out", type=Path,
        default=Path("docs/paper_5/acmart/paper_5_acmart.tex"),
    )
    parser.add_argument(
        "--references", type=Path,
        default=Path("docs/paper_5/references.bib"),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    source_text = args.source.resolve().read_text(encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tex = build_tex(source_text, args.references.resolve(), args.out.resolve())
    args.out.write_text(tex, encoding="utf-8")
    print(f"[ACMART] wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
