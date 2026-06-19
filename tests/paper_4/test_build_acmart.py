"""Paper 4 acmart build (Phase 4) — behavior tests.

Covers the adaptations the Paper 4 source forces over the Paper 3
``build_acmart`` port, all gate-critical or rendering-critical:

* markdown ``\\$`` dollar-escapes round-trip to a LaTeX literal ``\\$``
  (the locked gate substrings ``$0.106`` / ``$0.0093`` depend on it);
* non-ASCII the Paper 3 map lacked (``>=``, ``~~``, ``--``, ``S``, ``-``);
* multi-key parenthetical cites ``[@a; @b]`` -> ``\\citep{a, b}``;
* literal backslashes inside code spans (``C:\\Temp\\``) -> ``\\textbackslash``;
* the six real Paper 4 figures render as ``\\includegraphics`` (no
  placeholder boxes), in-body at their host sections;
* the ``## 12. References`` heading is not double-emitted (the
  bibliography creates the References section).

Source markdown is read-only; ``build_tex`` takes the source *text*.
"""
from __future__ import annotations

from pathlib import Path

from docs.paper_4 import build_acmart as ba

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "docs" / "paper_4" / "source" / "PAPER4_DRAFT_v1_0_source.md"
REFERENCES = REPO / "docs" / "paper_4" / "references.bib"


class TestLatexEscape:
    def test_markdown_dollar_escape_round_trips_to_literal(self):
        # \$0.106 in the markdown must render the LaTeX literal \$0.106
        assert ba.latex_escape(r"\$0.106") == r"\$0.106"

    def test_bare_dollar_is_escaped(self):
        assert ba.latex_escape("$") == r"\$"

    def test_geq_maps_to_math(self):
        assert ba.latex_escape("J ≥ 0.50") == r"J $\geq$ 0.50"

    def test_approx_maps_to_math(self):
        assert ba.latex_escape("≈") == r"$\approx$"

    def test_em_dash_maps_to_triple_hyphen(self):
        assert ba.latex_escape("a—b") == "a---b"

    def test_section_sign_maps_to_command(self):
        assert ba.latex_escape("§4.4") == r"\S{}4.4"

    def test_minus_sign_maps_to_math(self):
        assert ba.latex_escape("TPR − FPR") == r"TPR $-$ FPR"

    def test_ordinary_specials_escaped(self):
        assert ba.latex_escape("100% & x_y") == r"100\% \& x\_y"


class TestVerbatimEscape:
    def test_backslash_becomes_textbackslash(self):
        # input is the literal path  C:\Temp\
        assert ba.latex_escape_in_verbatim("C:\\Temp\\") == (
            r"C:\textbackslash{}Temp\textbackslash{}"
        )

    def test_underscore_escaped_in_verbatim(self):
        assert ba.latex_escape_in_verbatim("v2_canonical") == r"v2\_canonical"

    def test_percent_escaped_in_verbatim(self):
        assert ba.latex_escape_in_verbatim("%TEMP%") == r"\%TEMP\%"

    def test_arrow_maps_in_verbatim(self):
        assert ba.latex_escape_in_verbatim("a→b") == r"a$\rightarrow$b"


class TestCitations:
    def test_single_paren_marker(self):
        assert ba.substitute_citation_markers("[@greshake-2023]") == r"\citep{greshake-2023}"

    def test_multi_key_paren_marker(self):
        assert ba.substitute_citation_markers(
            "[@gmys-casiano-2026b; @gmys-casiano-2026c]"
        ) == r"\citep{gmys-casiano-2026b, gmys-casiano-2026c}"

    def test_narrative_marker(self):
        assert ba.substitute_citation_markers("@guo-2024 survey") == r"\citet{guo-2024} survey"

    def test_email_like_at_is_untouched(self):
        # narrative lookbehind excludes a preceding alnum, sparing emails
        assert ba.substitute_citation_markers("anonymous@paper4.example") == (
            "anonymous@paper4.example"
        )


class TestInline:
    def test_bold(self):
        assert ba.render_inline("**SUPPORTED_STRONG**") == r"\textbf{SUPPORTED\_STRONG}"

    def test_italic(self):
        assert ba.render_inline("*J*") == r"\textit{J}"

    def test_code_span(self):
        assert ba.render_inline("`v2_canonical`") == r"\texttt{v2\_canonical}"


class TestFigureRoster:
    def test_all_six_figures_present(self):
        assert {f.fig_id for f in ba._FIGURE_ROSTER} == {
            "fig_1", "fig_2", "fig_3", "fig_4", "fig_5", "fig_6"
        }

    def test_host_sections(self):
        host = {f.fig_id: f.host_section for f in ba._FIGURE_ROSTER}
        assert host == {
            "fig_1": 3, "fig_2": 5, "fig_3": 6, "fig_4": 7, "fig_5": 8, "fig_6": 6
        }

    def test_spans(self):
        span = {f.fig_id: f.span for f in ba._FIGURE_ROSTER}
        assert span == {
            "fig_1": "double", "fig_2": "double", "fig_3": "single",
            "fig_4": "single", "fig_5": "double", "fig_6": "double",
        }

    def test_section_six_hosts_two_figures(self):
        ids = {f.fig_id for f in ba.figures_for_section(6)}
        assert ids == {"fig_3", "fig_6"}

    def test_section_five_hosts_money_figure(self):
        assert [f.fig_id for f in ba.figures_for_section(5)] == ["fig_2"]

    def test_double_figure_uses_textwidth_includegraphics(self):
        spec = next(f for f in ba._FIGURE_ROSTER if f.fig_id == "fig_2")
        out = ba.render_figure(spec)
        assert r"\begin{figure*}" in out
        assert r"\includegraphics[width=\textwidth]{../figures/fig_2.pdf}" in out
        assert r"\label{fig:fig_2}" in out
        assert r"\framebox" not in out

    def test_single_figure_uses_columnwidth_includegraphics(self):
        spec = next(f for f in ba._FIGURE_ROSTER if f.fig_id == "fig_3")
        out = ba.render_figure(spec)
        assert r"\begin{figure}" in out
        assert r"\includegraphics[width=\columnwidth]{../figures/fig_3.pdf}" in out


class TestRenderBody:
    def test_references_section_not_double_emitted(self):
        out = ba.render_body("## 12. References\n\n")
        assert r"\section{References}" not in out

    def test_abstract_then_maketitle_then_section(self):
        out = ba.render_body(
            "## Abstract\n\nWe study the trilemma.\n\n## 1. Introduction\n\nBody text.\n"
        )
        assert r"\begin{abstract}" in out
        assert r"\end{abstract}" in out
        assert r"\maketitle" in out
        assert r"\section{Introduction}" in out
        # maketitle lands after the abstract ends
        assert out.index(r"\end{abstract}") < out.index(r"\maketitle")


class TestBuildTex:
    def _tex(self, tmp_path) -> str:
        out = tmp_path / "paper_4_acmart.tex"
        return ba.build_tex(SOURCE.read_text(encoding="utf-8"), REFERENCES, out)

    def test_preamble_and_document_frame(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\documentclass" in tex and "acmart" in tex
        assert r"\begin{document}" in tex
        assert r"\end{document}" in tex
        assert r"\maketitle" in tex

    def test_dollar_amounts_preserved(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\$0.106" in tex
        assert r"\$0.0093" in tex
        assert r"\$3.23" in tex

    def test_citations_converted(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\citep{greshake-2023}" in tex
        assert r"\citep{gmys-casiano-2026b, gmys-casiano-2026c}" in tex
        assert r"\citet{guo-2024}" in tex
        # no raw pandoc markers survive
        assert "[@" not in tex

    def test_real_figures_included(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\includegraphics" in tex
        assert "../figures/fig_2.pdf" in tex
        assert r"\framebox" not in tex

    def test_bibliography_and_appendix(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\bibliography{references}" in tex
        assert r"\appendix" in tex
        assert "Generative AI Use Declaration" in tex

    def test_author_block_redaction_not_rendered(self, tmp_path):
        tex = self._tex(tmp_path)
        assert "Author block redacted" not in tex

    def test_writes_references_copy_next_to_out(self, tmp_path):
        out = tmp_path / "paper_4_acmart.tex"
        ba.build_tex(SOURCE.read_text(encoding="utf-8"), REFERENCES, out)
        assert (tmp_path / "references.bib").exists()
