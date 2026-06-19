"""Paper 4 Phase 4: build an acmart sigconf ``.tex`` from the canonical
Paper 4 source markdown, then compile it to the submission PDF.

This is the Paper 4 peer of ``docs/paper_3/build_acmart.py``. The
discipline is identical — the canonical markdown at
``docs/paper_4/source/PAPER4_DRAFT_v1_0_source.md`` is READ-ONLY here;
figures ``fig_1``..``fig_6`` are the real vector PDFs from
``docs/paper_4/build_figures.py``; references render via ``\\nocite{*}``
+ the ACM-Reference-Format style over ``docs/paper_4/references.bib``.

Adaptations the Paper 4 source forces over the Paper 3 port (each is
gate-critical or render-critical, see ``tests/paper_4/test_build_acmart.py``):

* **Markdown dollar escapes.** The source writes every dollar amount as
  ``\\$`` (a markdown escape). A prose escape pass first *un*-escapes
  markdown punctuation, then LaTeX-escapes, so ``\\$0.106`` round-trips
  to the LaTeX literal ``\\$0.106``. The locked gate substrings
  ``$0.106`` / ``$0.0093`` depend on this.
* **Wider unicode map.** Adds ``>=`` (``\\geq``), ``~~`` (``\\approx``),
  the em dash (``---``), the section sign (``\\S``), the minus sign, and
  the rightwards arrow — codepoints the Paper 3 map lacked that would
  otherwise hard-error ``utf8`` inputenc.
* **Multi-key parenthetical cites.** ``[@a; @b]`` -> ``\\citep{a, b}``.
* **Backslashes in code spans.** ``C:\\Temp\\`` inside ``\\texttt`` ->
  ``\\textbackslash``.
* **Real figures, in body.** No Paper 3 appendix-relocation; the six
  figures land at their host sections as ``\\includegraphics``.
* **References heading.** ``## 12. References`` is dropped (the
  bibliography emits its own References section).

Usage::

    python -m docs.paper_4.build_acmart \\
        --out docs/paper_4/acmart/paper_4_acmart.tex

Then::

    cd docs/paper_4/acmart
    pdflatex -interaction=nonstopmode paper_4_acmart.tex
    bibtex paper_4_acmart
    pdflatex -interaction=nonstopmode paper_4_acmart.tex
    pdflatex -interaction=nonstopmode paper_4_acmart.tex
"""

from __future__ import annotations

import argparse
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

# Inline tokens: **bold**, *italic*, `code` — order matters because
# **bold** has to win against *italic* on the same starting position.
_INLINE_RE = re.compile(r"(\*\*[^*\n]+\*\*|\*[^*\n]+\*|`[^`\n]+`)")

# Non-ASCII present in the Paper 4 source. Math symbols translate to
# math-mode equivalents (the acmart default font ships no glyphs for
# them, and bare codepoints would hard-error utf8 inputenc). The em dash
# becomes ``---`` and the section sign ``\S`` so neither depends on
# inputenc behaviour.
_UNICODE_MAP = {
    "×": r"$\times$",      # multiplication sign
    "Δ": r"$\Delta$",      # capital delta
    "⊕": r"$\oplus$",      # circled plus
    "≤": r"$\leq$",        # less-than-or-equal
    "≥": r"$\geq$",        # greater-than-or-equal
    "→": r"$\rightarrow$",  # rightwards arrow (code spans: 0.00 -> 0.25 ...)
    "−": r"$-$",           # minus sign (TPR - FPR)
    "≈": r"$\approx$",      # almost-equal (White-box ~~ black-box heading)
    "—": r"---",           # em dash
    "§": r"\S{}",          # section sign (cross-references)
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
# Section title / number stripping
# =============================================================================


# `## 1. Introduction` -> `Introduction`
_SECTION_TITLE_RE = re.compile(r"^\s*(\d+)\.\s+(.*)$")
# `### 4.1 Adaptive Corpus C` -> `Adaptive Corpus C`
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
    """One Paper 4 figure: id, host section, column span, caption."""

    fig_id: str
    host_section: int
    span: str  # ``single`` (one column) or ``double`` (figure*)
    caption: str


# Spans match the widths build_figures.py renders at: DOUBLE_COL (7.0in,
# figure*) for the ladder, frontier, method, and worked-disguise figures;
# SINGLE_COL (3.333in, figure) for the two bar charts. Host sections match
# the skeleton's ``figures[].host_section``. The prose carries no "Figure N"
# cross-references, so float auto-numbering is sufficient.
_FIGURE_ROSTER: tuple[FigureSpec, ...] = (
    FigureSpec(
        "fig_1", 3, "double",
        "The read-depth ladder: five rungs from v1_field through "
        "v2_structured, v2_lexical, and v2_canonical up to llm_semantic. "
        "Each rung reads more of the evidence value than the one below it, "
        "raising detection potential but enlarging the attacker-controlled "
        "surface.",
    ),
    FigureSpec(
        "fig_2", 5, "double",
        "The read-depth frontier (the central result): framing-flip rate "
        "X_sem versus Youden's J, standalone (left) versus cumulative "
        "(right). The good corner is occupied standalone by deterministic "
        "canonicalization but empty on the deployment-realistic cumulative "
        "view, where every rung caps at J = 0.25.",
    ),
    FigureSpec(
        "fig_3", 6, "single",
        "Out-of-vocabulary adversarial evasion per scenario: canonical flip "
        "counts (of K = 8) for each malign scenario, black-box versus "
        "white-box arms. RDF-M-LEX-002 and RDF-M-SYN-001 are evaded in both "
        "arms; the named-indicator scenarios RDF-M-LEX-001 (lsass) and "
        "RDF-M-PATCH-001 (procdump) resist.",
    ),
    FigureSpec(
        "fig_4", 7, "single",
        "Independent-judge audit: malign verdicts over the 18 evading "
        "disguises by judge family (Sonnet, Gemini, GPT-4o), with GPT-4o the "
        "stricter judge. Fifteen disguises are confirmed by both independents "
        "and three split; all four calibration controls pass, yielding the "
        "ROBUST verdict.",
    ),
    FigureSpec(
        "fig_5", 8, "double",
        "The method as a transferable contribution: the LLM-proposes / "
        "code-disposes pipeline (generate, then a deterministic "
        "skeleton-and-novelty gate, then an LLM judge, then verdict), plus "
        "the independent-judge audit panel that separates adversarial "
        "creativity from adversarial validity.",
    ),
    FigureSpec(
        "fig_6", 6, "double",
        "A worked out-of-vocabulary disguise (RDF-M-SYN-001, black-box arm, "
        "confirmed by both independents): the original values the "
        "canonicalizer matches versus the disguise it misses, with threat "
        "meaning preserved.",
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
# Markdown walker
# =============================================================================


def strip_html_comments(text: str) -> str:
    return _HTML_COMMENT_RE.sub("", text)


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

    if in_abstract:  # defensive — Paper 4 always has sections after Abstract
        out.append(r"\end{abstract}")
        out.append(r"\maketitle")
        out.append("")

    return "\n".join(out) + "\n"


# =============================================================================
# Preamble + bibliography blocks
# =============================================================================


def acmart_preamble(title_text: str) -> str:
    """Venue-neutral acmart sigconf preamble (anonymous + review).

    The Paper 4 venue is TBD ("acmart-portable"); the prose is written
    anonymized, so ``anonymous`` mode + a neutral conference stub keep the
    artifact submission-ready without committing to AISec-style metadata.
    """
    return r"""\documentclass[sigconf,anonymous,review]{acmart}

%% ---- placeins provides \FloatBarrier if float packing needs a nudge.
\usepackage{placeins}

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
    <concept_id>10002978.10003014.10003017</concept_id>
    <concept_desc>Security and privacy~Intrusion/anomaly detection and malware mitigation</concept_desc>
    <concept_significance>500</concept_significance>
  </concept>
</ccs2012>
\end{CCSXML}
\ccsdesc[500]{Security and privacy~Intrusion/anomaly detection and malware mitigation}

\keywords{deterministic verification, read-depth robustness, adversarial evasion, pre-registration, multi-agent LLM security, LLM-judge audit}

\title{""" + latex_escape(title_text) + r"""}

%% ---- acmart anonymous mode requires at least one author block --------
\author{Anonymous Author(s)}
\affiliation{%
  \institution{Submission under double-blind review}
  \country{}
}
\email{anonymous@paper4.example}

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
    # Post-process pandoc-style citation markers last, so the substituted
    # backslash sequences are not re-escaped by ``latex_escape``.
    tex = substitute_citation_markers(tex)
    return tex


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Build a sigconf acmart .tex from the Paper 4 source markdown.",
    )
    parser.add_argument(
        "--source", type=Path,
        default=Path("docs/paper_4/source/PAPER4_DRAFT_v1_0_source.md"),
    )
    parser.add_argument(
        "--out", type=Path,
        default=Path("docs/paper_4/acmart/paper_4_acmart.tex"),
    )
    parser.add_argument(
        "--references", type=Path,
        default=Path("docs/paper_4/references.bib"),
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
