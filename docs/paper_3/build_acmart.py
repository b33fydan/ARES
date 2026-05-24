"""Session 072 measurement spike: build a sigconf-2-column acmart .tex
from the canonical Paper 3 source markdown.

This is a SPIKE artifact, not the canonical pipeline. The single
question it answers is whether Paper 3's prose + figures fit the
AISec 2026 budget (10-page body, 12-page overall under
``\\documentclass[sigconf,anonymous,review]{acmart}``).

Discipline:

* The canonical markdown at ``docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md``
  is READ-ONLY here — the spike never edits it. The existing docx
  pipeline at ``docs/paper_3/build_v1_0.py`` is untouched.
* Literal in-text citation strings (``(Gmys-Casiano, 2026)`` etc.) are
  preserved verbatim per the Session 072 brief; citation-marker
  migration is a Part B task and out of scope here.
* Figures fig_1 through fig_6 are rendered as size-accurate framed
  boxes — no figure source assets exist yet, and a measurement
  without them is worthless. Sizes come from the figure roster in
  ``docs/paper_3/skeleton_v1_0.json``.
* References render via ``\\nocite{*}`` + the ACM-Reference-Format
  bibliography style consuming ``docs/paper_3/references.bib``.
  bibtex emits all six verified entries despite literal in-text cites.

Usage::

    python -m docs.paper_3.build_acmart \\
        --out docs/paper_3/acmart_spike/paper_3_acmart.tex

Then::

    cd docs/paper_3/acmart_spike
    pdflatex -interaction=nonstopmode paper_3_acmart.tex
    bibtex paper_3_acmart
    pdflatex -interaction=nonstopmode paper_3_acmart.tex
    pdflatex -interaction=nonstopmode paper_3_acmart.tex
"""

from __future__ import annotations

import argparse
import re
import shutil
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Optional


# =============================================================================
# Source-level constants
# =============================================================================


_HTML_COMMENT_RE = re.compile(r"<!--.*?-->", re.DOTALL)

_APPENDIX_HEADER_PREFIX = "## Appendix"

_AUTHOR_REDACTION_MARKER = "[Author block redacted for double-blind review]"

# Inline tokens: **bold**, *italic*, `code` — order matters because
# **bold** has to win against *italic* on the same starting position.
_INLINE_RE = re.compile(
    r"(\*\*[^*\n]+\*\*|\*[^*\n]+\*|`[^`\n]+`)"
)

# Non-ASCII characters present in the source. Math symbols translate
# to math-mode equivalents because the default acmart font does not
# ship glyphs for them. The em dash and section sign render via the
# acmart default ``inputenc{utf8}``.
_UNICODE_MAP = {
    "×": r"$\times$",   # × multiplication sign
    "Δ": r"$\Delta$",   # Δ capital delta
    "≤": r"$\leq$",     # ≤ less-than-or-equal
    "⊕": r"$\oplus$",   # ⊕ circled plus
}


# Pandoc-style citation markers. Part B citation migration adopts these
# as the canonical-source representation; LaTeX rendering converts to
# natbib's ``\citep`` (parenthetical) and ``\citet`` (narrative).
#
# The narrative lookbehind excludes:
#   * alphanumeric / underscore — prevents matching email-style ``@``
#     addresses (e.g., ``anonymous@aisec26.example``)
#   * ``[`` — prevents matching the inner ``@`` of a parenthetical
#     marker ``[@key]`` when ordering of substitutions is permuted.
# Order-independent: parenthetical and narrative substitutions can run
# in either order without corrupting the other.
_CITE_PAREN_MARKER_RE = re.compile(r"\[@([a-z0-9\-]+)\]")
_CITE_NARRATIVE_MARKER_RE = re.compile(r"(?<![\[a-zA-Z0-9_])@([a-z0-9\-]+)\b")


def substitute_citation_markers(latex_text: str) -> str:
    """Convert pandoc-style citation markers to LaTeX cite commands.

    Applied AFTER inline rendering and LaTeX escaping so the substituted
    backslash commands are not themselves escaped. The regexes do not
    touch text inside ``\\texttt{...}`` spans by convention — current
    Paper 3 prose has no citation markers inside code spans, so the
    constraint holds without a special case.
    """
    out = _CITE_PAREN_MARKER_RE.sub(r"\\citep{\1}", latex_text)
    out = _CITE_NARRATIVE_MARKER_RE.sub(r"\\citet{\1}", out)
    return out


# =============================================================================
# Section title / number stripping
# =============================================================================


# `## 1. Introduction` -> `Introduction`
_SECTION_TITLE_RE = re.compile(r"^\s*(\d+)\.\s+(.*)$")
# `### 4.1 Paired-trial leakage protocol` -> `Paired-trial leakage protocol`
_SUBSECTION_TITLE_RE = re.compile(r"^\s*(\d+)\.(\d+)\s+(.*)$")


def strip_section_number(title: str) -> str:
    """Drop the leading ``N.`` numeric prefix from a level-1 title."""
    m = _SECTION_TITLE_RE.match(title)
    return m.group(2).strip() if m else title.strip()


def strip_subsection_number(title: str) -> str:
    """Drop the leading ``N.M`` prefix from a level-2 title."""
    m = _SUBSECTION_TITLE_RE.match(title)
    return m.group(3).strip() if m else title.strip()


# =============================================================================
# Figure roster (size-accurate placeholders)
# =============================================================================


@dataclass(frozen=True)
class FigureSpec:
    """One figure placeholder spec from the Paper 3 skeleton."""

    fig_id: str
    host_section: int
    span: str  # ``single`` (one column) or ``double`` (figure*)
    height_in: float
    caption: str


# Placeholder sizes use conservative academic-paper conventions:
# - architecture diagrams span both columns (figure*)
# - conceptual diagrams + bar charts + code snippets sit single-column
# - heights match the typical real-asset dimensions for each category
_FIGURE_ROSTER: tuple[FigureSpec, ...] = (
    FigureSpec(
        fig_id="fig_1",
        host_section=3,
        span="double",
        height_in=2.6,
        caption=(
            "ARES three-agent pipeline (Architect / Skeptic / OracleJudge), "
            "compressed from Paper 2. Placeholder for spike measurement."
        ),
    ),
    FigureSpec(
        fig_id="fig_2",
        host_section=4,
        span="single",
        height_in=2.4,
        caption=(
            "Leakage decomposition into citation-surface drift and "
            "confidence-axis drift. Placeholder for spike measurement."
        ),
    ),
    FigureSpec(
        fig_id="fig_3",
        host_section=5,
        span="single",
        height_in=2.4,
        caption=(
            "Byte-stability result (98/98 paired trials) and LLM Skeptic "
            "comparison. Placeholder for spike measurement."
        ),
    ),
    FigureSpec(
        fig_id="fig_4",
        host_section=6,
        span="single",
        height_in=2.5,
        caption=(
            "Decoupling: Verdict structure showing decision and explanation "
            "surfaces sourced from different paths. Placeholder for spike "
            "measurement."
        ),
    ),
    FigureSpec(
        fig_id="fig_5",
        host_section=5,
        span="single",
        height_in=1.4,
        caption=(
            "light_skeptic.py:185 with annotation showing the discard. "
            "Placeholder for spike measurement."
        ),
    ),
    FigureSpec(
        fig_id="fig_6",
        host_section=6,
        span="single",
        height_in=2.6,
        caption=(
            "Oracle decision logic, THREAT_CONFIRMED branch "
            "(oracle.py:101-111). Placeholder for spike measurement."
        ),
    ),
)


# Body vs. appendix figure routing (Session 072 triage iteration).
# Strategy decision: relocate Fig 2 (decomposition diagram) and Fig 5 (code
# snippet) to a well-marked "Supplementary Figures" appendix, freeing ~0.5
# page of body space. The four remaining figures are evidence-bearing for
# headline findings or the architecture overview and must stay in-body
# (committee members are not required to read appendices).
_BODY_FIGURE_IDS: frozenset[str] = frozenset({"fig_1", "fig_3", "fig_4", "fig_6"})
_APPENDIX_FIGURE_IDS: frozenset[str] = frozenset({"fig_2", "fig_5"})


def figures_for_section(section_number: int) -> tuple[FigureSpec, ...]:
    """Return body figures whose ``host_section`` matches the given numbered section.

    Appendix-routed figures (``_APPENDIX_FIGURE_IDS``) are excluded; they
    are rendered separately by ``render_supplementary_figures_appendix``.
    """
    return tuple(
        f for f in _FIGURE_ROSTER
        if f.host_section == section_number and f.fig_id in _BODY_FIGURE_IDS
    )


def render_supplementary_figures_appendix() -> str:
    """Render the well-marked Supplementary Figures appendix.

    Lands as the first ``\\section`` after ``\\appendix``, so it is
    numbered "A". The figures are referenced from their original body
    locations as "Figure N" — acmart's auto-numbering preserves the
    paper-wide ordering regardless of float position.
    """
    parts: list[str] = []
    parts.append(r"\section{Supplementary Figures}")
    parts.append(
        "The figures in this appendix are deferred from their original "
        "section locations to keep the body of the paper within the "
        "AISec 2026 page budget. They are referenced from the body "
        "(Sections~4 and~5) as ``Figure 2'' and ``Figure 5'' respectively; "
        "acmart's float numbering is paper-wide, so the numerical "
        "ordering is preserved across the appendix split."
    )
    parts.append("")
    for spec in _FIGURE_ROSTER:
        if spec.fig_id in _APPENDIX_FIGURE_IDS:
            parts.append(render_figure_placeholder(spec))
    # \FloatBarrier forces all pending floats (Fig 2 + Fig 5) to be
    # placed before LaTeX continues into Appendix B. Without this,
    # Fig 5 was drifting into the Appendix B (Generative AI) region.
    parts.append(r"\FloatBarrier")
    return "\n".join(parts) + "\n"


def _canonical_figure_number(fig_id: str) -> int:
    """Extract the canonical figure number from ``fig_N`` ids.

    Canonical numbering is the roster ordering (1..6). With Session 072
    figure relocation, source order no longer matches canonical order
    (Fig 2 and Fig 5 land in the appendix after body figures), so the
    figure counter must be set explicitly before each ``\\begin{figure}``
    to preserve the prose's inline "Figure N" references.
    """
    return int(fig_id.split("_")[1])


def render_figure_placeholder(spec: FigureSpec) -> str:
    """Render one figure environment with a size-accurate framed box.

    Emits ``\\setcounter{figure}{N-1}`` immediately before the float so
    LaTeX assigns the canonical figure number on the next
    ``\\stepcounter`` call inside ``\\caption``. This is the mechanism
    that lets us relocate Fig 2 and Fig 5 to a Supplementary Figures
    appendix while keeping the prose's "Figure 5" / "Figure 6"
    references intact (the prose is frozen per Session 072 brief).
    """
    env = "figure*" if spec.span == "double" else "figure"
    safe_fig_id = latex_escape(spec.fig_id)
    canonical_n = _canonical_figure_number(spec.fig_id)
    # Width = full column width (``\linewidth``); height fixed in inches.
    # ``\framebox[\linewidth]{...}`` puts a visible border around the area.
    body = (
        f"\\framebox[\\linewidth]{{"
        f"\\rule{{0pt}}{{{spec.height_in}in}}"
        f"\\textit{{[Placeholder: {safe_fig_id} ({spec.span} column, "
        f"{spec.height_in}\\,in)]}}"
        f"}}"
    )
    return (
        f"\\setcounter{{figure}}{{{canonical_n - 1}}}\n"
        f"\\begin{{{env}}}[!htbp]\n"
        f"\\centering\n"
        f"{body}\n"
        f"\\caption{{{latex_escape(spec.caption)}}}\n"
        f"\\Description{{{latex_escape(spec.caption)}}}\n"
        f"\\label{{fig:{spec.fig_id}}}\n"
        f"\\end{{{env}}}\n"
    )


# =============================================================================
# LaTeX escaping
# =============================================================================


# Characters that must be escaped when emitting prose into LaTeX body
# text. Backslash is intentionally NOT escaped here because the prose
# does not contain literal backslashes outside code spans (which are
# rendered through ``\texttt``).
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
    """Escape LaTeX special characters in plain prose."""
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
    """Escape content inside ``\\texttt{...}`` — fewer specials are reserved.

    Inside ``\\texttt`` the printable characters render literally, but
    ``{``, ``}``, ``\\``, ``&``, ``%``, ``$``, ``#``, ``_``, ``^``, ``~``
    are still LaTeX-special. ``|Δ|`` math-style escapes do not apply
    here because the math symbols never appear inside code spans.
    """
    return latex_escape(text)


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
# Markdown walker
# =============================================================================


def strip_html_comments(text: str) -> str:
    return _HTML_COMMENT_RE.sub("", text)


def split_appendix(source_text: str) -> tuple[str, str]:
    """Split off the Appendix section so it lands after References."""
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
    """Walk markdown body lines and emit LaTeX section/subsection/paragraph blocks.

    The Abstract is wrapped in ``\\begin{abstract}...\\end{abstract}``
    rather than emitted as a section. The title (``# ...``) is held
    out by the caller and rendered into ``\\title{...}``; this
    function ignores it.
    """
    out: list[str] = []
    block: list[str] = []
    in_abstract = False
    current_section_number: int = 0

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
                # Emit the abstract end + the maketitle so figures/sections
                # below land in the body.
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
            out.append("")
            out.append(r"\section{" + latex_escape(title) + r"}")
            # Insert figures hosted by this section right after the heading.
            for fig in figures_for_section(current_section_number):
                out.append(render_figure_placeholder(fig))
            continue

        # Decorative separator
        if stripped == "---":
            flush()
            continue

        # Blank line: closes the current block
        if not stripped:
            flush()
            continue

        # Author redaction marker — acmart anonymous mode handles this
        # automatically; we just emit an italic line of acknowledgement
        # text inside the abstract environment if it appears.
        if _AUTHOR_REDACTION_MARKER in stripped:
            flush()
            continue

        block.append(line)

    flush()

    # Defensive close in case abstract was last block emitted (Paper 3
    # source always has sections after Abstract, but be safe).
    if in_abstract:
        out.append(r"\end{abstract}")
        out.append(r"\maketitle")
        out.append("")

    return "\n".join(out) + "\n"


# =============================================================================
# Preamble + bibliography blocks
# =============================================================================


def acmart_preamble(title_text: str) -> str:
    """Render the acmart sigconf preamble with anonymous + review modes on.

    CCS metadata and ACM Reference Format stubs satisfy the acmart
    template requirements without committing to final values; review
    submission is what the spike compiles against.
    """
    return r"""\documentclass[sigconf,anonymous,review,nonacm=false]{acmart}

%% ---- placeins provides \FloatBarrier to keep Appendix A's figures
%%      from drifting into the Appendix B region (Session 072 fix).
\usepackage{placeins}

%% ---- Switch acmart from the sigconf-default numbered citation style
%%      to author-year style. Part B citation migration emits \citep /
%%      \citet from pandoc-style markers in the canonical source.
\citestyle{acmauthoryear}

%% ---- ACM bibliographic metadata stubs (review submission) ----------
\acmConference[AISec '26]{The 19th ACM Workshop on Artificial Intelligence and Security}{October 2026}{Taipei, Taiwan}
\acmYear{2026}
\acmISBN{}
\acmDOI{}
\acmPrice{}

%% ---- During review, suppress the ACM-ref-box and the rights footer
\settopmatter{printacmref=false}
\setcopyright{none}
\renewcommand\footnotetextcopyrightpermission[1]{}
\pagestyle{plain}

%% ---- ACM CCS concepts stub (per CFP; real values land at camera-ready)
\begin{CCSXML}
<ccs2012>
  <concept>
    <concept_id>10002978.10003014.10003017</concept_id>
    <concept_desc>Security and privacy~Intrusion/anomaly detection and malware mitigation</concept_desc>
    <concept_significance>500</concept_significance>
  </concept>
</ccs2012>
\end{CCSXML}
\ccsdesc[500]{Security and privacy~Intrusion/anomaly detection and malware mitigation}

\keywords{multi-agent LLM, adversarial robustness, deterministic verification, explanation faithfulness, prompt injection}

\title{""" + latex_escape(title_text) + r"""}

%% ---- acmart anonymous mode requires at least one author block ------
\author{Anonymous Author(s)}
\affiliation{%
  \institution{Submission under double-blind review}
  \country{}
}
\email{anonymous@aisec26.example}

\begin{document}
"""


def render_bibliography(references_path: Path, paper_dir: Path) -> str:
    """Copy references.bib into the spike dir and emit the bib commands.

    ``\\nocite{*}`` forces every entry in the bib to land in the
    rendered References section even though the body prose carries
    literal cite text instead of ``\\cite{...}`` markers. That makes
    the spike's 12-page overall measurement honest about how much
    space the bibliography occupies.
    """
    target = paper_dir / "references.bib"
    if references_path.resolve() != target.resolve():
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
    body, appendix = split_appendix(cleaned)
    title = extract_title(cleaned)

    paper_dir = out_path.parent
    bib_block = render_bibliography(references_path, paper_dir)

    parts: list[str] = []
    parts.append(acmart_preamble(title))
    parts.append(render_body(body))
    # Marker labels used by the post-compile page-count audit: the page
    # number of ``label:end-of-body`` is the body page count, and the
    # page number of ``label:end-of-bib`` minus the body's is the
    # bibliography contribution.
    parts.append(r"\label{end-of-body}")
    parts.append(bib_block)
    parts.append(r"\label{end-of-bib}")
    if appendix.strip():
        # Appendices land after References. ``\appendix`` switches
        # numbering to A, B, C... All appendix pages are exempt from the
        # body page-limit per the AISec 2026 CFP.
        # Appendix A: Supplementary Figures (Session 072 triage routes
        # Fig 2 + Fig 5 here to recover ~0.5 page of body space).
        # Appendix B: Generative AI Use Declaration (from canonical
        # markdown; the ``## Appendix:`` prefix is stripped here in-memory
        # since we are already inside the ``\appendix`` region — canonical
        # source markdown is not modified).
        parts.append(r"\appendix")
        parts.append(render_supplementary_figures_appendix())
        cleaned_appendix = appendix.replace(
            "## Appendix: Generative AI Use Declaration",
            "## Generative AI Use Declaration",
        )
        parts.append(render_body(cleaned_appendix))
        parts.append(r"\label{end-of-appendix}")
    parts.append(r"\end{document}")
    parts.append("")
    tex = "\n".join(parts)
    # Post-process: convert pandoc-style citation markers to LaTeX cite
    # commands. Done last so the substituted backslash sequences are not
    # re-escaped by ``latex_escape``.
    tex = substitute_citation_markers(tex)
    return tex


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a sigconf acmart .tex from the Paper 3 source markdown.",
    )
    parser.add_argument(
        "--source", type=Path,
        default=Path("docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md"),
    )
    parser.add_argument(
        "--out", type=Path,
        default=Path("docs/paper_3/acmart_spike/paper_3_acmart.tex"),
    )
    parser.add_argument(
        "--references", type=Path,
        default=Path("docs/paper_3/references.bib"),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    source_text = args.source.resolve().read_text(encoding="utf-8")
    args.out.parent.mkdir(parents=True, exist_ok=True)
    tex = build_tex(source_text, args.references.resolve(), args.out.resolve())
    args.out.write_text(tex, encoding="utf-8")
    print(f"[ACMART SPIKE] wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
