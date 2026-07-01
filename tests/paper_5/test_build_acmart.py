"""Paper 5 acmart build (Phase 4) — behavior tests.

Covers the adaptations the Paper 5 source forces over the Paper 4
``build_acmart`` port, all gate-critical, rendering-critical, or a
source-structure difference:

* markdown ``\\$`` dollar-escapes round-trip to a LaTeX literal ``\\$``
  (the locked gate substrings ``$3.8`` / ``$0.07`` depend on it);
* the two new non-ASCII codepoints the Paper 4 map lacked — ``\\tau``
  (``tau_asr``) and ``\\pm`` (Wald intervals) — plus the retained
  ``<=`` / em-dash;
* multi-key parenthetical cites ``[@a; @b; @c; @d]`` ->
  ``\\citep{a, b, c, d}`` (the abstract's four self-cites);
* the ``## In Plain Terms`` section is dropped from the PDF (in memory);
* the six real Paper 5 figures render as ``\\includegraphics`` (no
  placeholder boxes), in-body at their host sections (§6 hosts three);
* the ``## 11. References`` heading is not double-emitted (the
  bibliography creates the References section).

Source markdown is read-only; ``build_tex`` takes the source *text*.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from docs.paper_5 import build_acmart as ba

REPO = Path(__file__).resolve().parents[2]
SOURCE = REPO / "docs" / "paper_5" / "source" / "PAPER5_DRAFT_v1_0_source.md"
REFERENCES = REPO / "docs" / "paper_5" / "references.bib"


class TestLatexEscape:
    def test_markdown_dollar_escape_round_trips_to_literal(self):
        # \$3.8 in the markdown must render the LaTeX literal \$3.8
        assert ba.latex_escape(r"\$3.8") == r"\$3.8"

    def test_calibration_dollar_round_trips(self):
        assert ba.latex_escape(r"\$0.07") == r"\$0.07"

    def test_bare_dollar_is_escaped(self):
        assert ba.latex_escape("$") == r"\$"

    def test_tau_maps_to_math(self):
        # tau_asr renders \tau then the escaped underscore
        assert ba.latex_escape("τ_asr") == r"$\tau$\_asr"

    def test_pm_maps_to_math(self):
        assert ba.latex_escape("±22 pp") == r"$\pm$22 pp"

    def test_leq_maps_to_math(self):
        assert ba.latex_escape("≤ 0.50") == r"$\leq$ 0.50"

    def test_em_dash_maps_to_triple_hyphen(self):
        assert ba.latex_escape("a—b") == "a---b"

    def test_ordinary_specials_escaped(self):
        assert ba.latex_escape("100% & x_y") == r"100\% \& x\_y"


class TestVerbatimEscape:
    def test_backslash_becomes_textbackslash(self):
        # input is the literal path  C:\Temp\
        assert ba.latex_escape_in_verbatim("C:\\Temp\\") == (
            r"C:\textbackslash{}Temp\textbackslash{}"
        )

    def test_underscore_escaped_in_verbatim(self):
        assert ba.latex_escape_in_verbatim("full_defense") == r"full\_defense"

    def test_tau_maps_in_verbatim(self):
        # `τ_asr = τ_util = 0.20` appears inside a code span
        assert ba.latex_escape_in_verbatim("τ_asr") == r"$\tau$\_asr"

    def test_leq_maps_in_verbatim(self):
        # `≤ 0.50` appears inside a code span
        assert ba.latex_escape_in_verbatim("≤ 0.50") == r"$\leq$ 0.50"


class TestCitations:
    def test_single_paren_marker(self):
        assert ba.substitute_citation_markers("[@greshake-2023]") == r"\citep{greshake-2023}"

    def test_multi_key_paren_marker(self):
        # the abstract's four self-cites
        assert ba.substitute_citation_markers(
            "[@gmys-casiano-2026a; @gmys-casiano-2026b; "
            "@gmys-casiano-2026c; @gmys-casiano-2026d]"
        ) == (
            r"\citep{gmys-casiano-2026a, gmys-casiano-2026b, "
            r"gmys-casiano-2026c, gmys-casiano-2026d}"
        )

    def test_narrative_marker(self):
        assert ba.substitute_citation_markers("@greshake-2023 showed") == r"\citet{greshake-2023} showed"

    def test_email_like_at_is_untouched(self):
        # narrative lookbehind excludes a preceding alnum, sparing emails
        assert ba.substitute_citation_markers("anonymous@paper5.example") == (
            "anonymous@paper5.example"
        )


class TestFloatReferences:
    def test_single_figure_ref(self):
        assert ba.substitute_float_references(r"Figure 1 (fig\_1)") == (
            r"Figure~\ref{fig:fig_1}"
        )

    def test_single_table_ref(self):
        assert ba.substitute_float_references(r"Table 1 (tbl\_1)") == (
            r"Table~\ref{tab:tbl_1}"
        )

    def test_scrambled_figure_number_is_dropped(self):
        # fig_6 renders as a different number (it floats out of fig_id order);
        # the literal "6 (" scaffolding must be gone, replaced by \ref.
        out = ba.substitute_float_references(r"Figure 6 (fig\_6)")
        assert out == r"Figure~\ref{fig:fig_6}"
        assert "6 (" not in out

    def test_plural_tables(self):
        assert ba.substitute_float_references(r"Tables 2 and 3 (tbl\_2, tbl\_3)") == (
            r"Tables~\ref{tab:tbl_2} and~\ref{tab:tbl_3}"
        )

    def test_plural_figures(self):
        assert ba.substitute_float_references(
            r"Figures 2, 3, and 4 (fig\_2, fig\_3, fig\_4)"
        ) == r"Figures~\ref{fig:fig_2}, \ref{fig:fig_3}, and~\ref{fig:fig_4}"

    def test_inline_table_figure_pair(self):
        assert ba.substitute_float_references(
            r"(Table 2, fig\_2 left panel)"
        ) == r"(Table~\ref{tab:tbl_2}, Figure~\ref{fig:fig_2} left panel)"

    def test_bare_figure_ref(self):
        assert ba.substitute_float_references(r"band (fig\_4)") == (
            r"band (Figure~\ref{fig:fig_4})"
        )


class TestFloatScaffoldingGuard:
    def test_clean_tex_passes(self):
        # real refs + includegraphics paths must NOT trip the guard
        ba._assert_no_float_scaffolding(
            r"See Figure~\ref{fig:fig_2}; asset ../figures/fig_2.pdf; "
            r"\label{tab:tbl_3}"
        )

    def test_bare_table_scaffolding_raises(self):
        # a phrasing the 5 patterns do not cover leaves "(tbl\_M)" behind
        with pytest.raises(ValueError):
            ba._assert_no_float_scaffolding(r"as shown in (tbl\_2) above")

    def test_bare_figure_scaffolding_raises(self):
        with pytest.raises(ValueError):
            ba._assert_no_float_scaffolding(r"see (fig\_9) here")

    def test_build_tex_guards_against_scaffolding(self, tmp_path):
        # end-to-end: the real build passes the guard (no scaffolding ships)
        out = tmp_path / "paper_5_acmart.tex"
        tex = ba.build_tex(SOURCE.read_text(encoding="utf-8"), REFERENCES, out)
        assert r"(fig\_" not in tex and r"(tbl\_" not in tex


class TestInline:
    def test_bold(self):
        assert ba.render_inline("**no-headroom**") == r"\textbf{no-headroom}"

    def test_italic(self):
        assert ba.render_inline("*indirect*") == r"\textit{indirect}"

    def test_code_span(self):
        assert ba.render_inline("`full_defense`") == r"\texttt{full\_defense}"


class TestFigureRoster:
    def test_all_six_figures_present(self):
        assert {f.fig_id for f in ba._FIGURE_ROSTER} == {
            "fig_1", "fig_2", "fig_3", "fig_4", "fig_5", "fig_6"
        }

    def test_host_sections(self):
        host = {f.fig_id: f.host_section for f in ba._FIGURE_ROSTER}
        assert host == {
            "fig_1": 3, "fig_2": 6, "fig_3": 6, "fig_4": 6, "fig_5": 7, "fig_6": 4
        }

    def test_spans(self):
        span = {f.fig_id: f.span for f in ba._FIGURE_ROSTER}
        assert span == {
            "fig_1": "double", "fig_2": "double", "fig_3": "double",
            "fig_4": "single", "fig_5": "double", "fig_6": "double",
        }

    def test_section_six_hosts_three_figures(self):
        ids = {f.fig_id for f in ba.figures_for_section(6)}
        assert ids == {"fig_2", "fig_3", "fig_4"}

    def test_section_four_hosts_worked_example(self):
        assert [f.fig_id for f in ba.figures_for_section(4)] == ["fig_6"]

    def test_double_figure_uses_textwidth_includegraphics(self):
        spec = next(f for f in ba._FIGURE_ROSTER if f.fig_id == "fig_2")
        out = ba.render_figure(spec)
        assert r"\begin{figure*}" in out
        assert r"\includegraphics[width=\textwidth]{../figures/fig_2.pdf}" in out
        assert r"\label{fig:fig_2}" in out
        assert r"\framebox" not in out

    def test_single_figure_uses_columnwidth_includegraphics(self):
        spec = next(f for f in ba._FIGURE_ROSTER if f.fig_id == "fig_4")
        out = ba.render_figure(spec)
        assert r"\begin{figure}" in out
        assert r"\includegraphics[width=\columnwidth]{../figures/fig_4.pdf}" in out


class TestTableRoster:
    def test_all_four_tables_present(self):
        assert {t.tbl_id for t in ba._TABLE_ROSTER} == {
            "tbl_1", "tbl_2", "tbl_3", "tbl_4"
        }

    def test_host_sections(self):
        host = {t.tbl_id: t.host_section for t in ba._TABLE_ROSTER}
        assert host == {"tbl_1": 5, "tbl_2": 6, "tbl_3": 6, "tbl_4": 7}

    def test_section_six_hosts_two_tables(self):
        assert {t.tbl_id for t in ba.tables_for_section(6)} == {"tbl_2", "tbl_3"}

    def test_section_five_hosts_protocol(self):
        assert [t.tbl_id for t in ba.tables_for_section(5)] == ["tbl_1"]


class TestTables:
    def test_sweep_table_has_booktabs_and_run_data(self):
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_2")
        out = ba.render_table(spec)
        assert r"\begin{table}" in out and r"\end{table}" in out
        assert r"\toprule" in out and r"\bottomrule" in out
        assert r"\label{tab:tbl_2}" in out
        # sonnet cell undefended utility is 0.75 in the run
        assert "0.75" in out
        assert r"\texttt{haiku-4-5}" in out

    def test_arms_table_reflects_run(self):
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_3")
        out = ba.render_table(spec)
        assert r"\texttt{full\_defense}" in out
        # full_defense: utility 0.30 and gate denials 2
        assert "0.30" in out

    def test_arms_full_defense_row_exact(self):
        # Row-equality lock (not just presence): pins each value to its column
        # so a row/column swap can't slip through. full_defense is the
        # headline arm (2 gate denials).
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_3")
        out = ba.render_table(spec)
        assert (
            r"\texttt{full\_defense} & 0.00 & 0.30 & 2 & 0.05 & 0.95 \\" in out
        )

    def test_sweep_sonnet_row_exact(self):
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_2")
        out = ba.render_table(spec)
        assert (
            r"\texttt{sonnet-4-6} & \texttt{important\_instructions} & "
            r"0.00 & 0.75 \\" in out
        )

    def test_protocol_table_double_span_and_iban(self):
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_1")
        out = ba.render_table(spec)
        assert r"\begin{table*}" in out
        assert "US133000000121212121212" in out
        assert r"\texttt{banking}" in out

    def test_sota_table_positions_ares(self):
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_4")
        out = ba.render_table(spec)
        assert r"\begin{table*}" in out
        assert "CaMeL" in out
        assert "ARES-Harness" in out

    def test_data_fidelity_reads_the_loader(self, monkeypatch):
        # Non-tautological guard: if the loader yields no arms, the arms
        # table must fail — proving render_table reads _load_run(), not a
        # hardcoded literal.
        monkeypatch.setattr(ba, "_load_run", lambda: {})
        spec = next(t for t in ba._TABLE_ROSTER if t.tbl_id == "tbl_3")
        with pytest.raises(KeyError):
            ba.render_table(spec)


class TestRenderBody:
    def test_references_section_not_double_emitted(self):
        out = ba.render_body("## 11. References\n\n")
        assert r"\section{References}" not in out

    def test_abstract_then_maketitle_then_section(self):
        out = ba.render_body(
            "## Abstract\n\nWe study the regime.\n\n## 1. Introduction\n\nBody text.\n"
        )
        assert r"\begin{abstract}" in out
        assert r"\end{abstract}" in out
        assert r"\maketitle" in out
        assert r"\section{Introduction}" in out
        # maketitle lands after the abstract ends
        assert out.index(r"\end{abstract}") < out.index(r"\maketitle")


class TestDropInPlainTerms:
    def test_in_plain_terms_removed_in_memory(self):
        src = (
            "# Title\n\n## In Plain Terms\n\nA soft underbelly paragraph.\n\n"
            "---\n\n## Abstract\n\nThe formal summary.\n"
        )
        out = ba.drop_in_plain_terms(src)
        assert "In Plain Terms" not in out
        assert "soft underbelly" not in out
        # the Abstract that follows survives
        assert "## Abstract" in out
        assert "The formal summary." in out


class TestBuildTex:
    def _tex(self, tmp_path) -> str:
        out = tmp_path / "paper_5_acmart.tex"
        return ba.build_tex(SOURCE.read_text(encoding="utf-8"), REFERENCES, out)

    def test_preamble_and_document_frame(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\documentclass" in tex and "acmart" in tex
        assert r"\begin{document}" in tex
        assert r"\end{document}" in tex
        assert r"\maketitle" in tex

    def test_dollar_amounts_preserved(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\$3.8" in tex
        assert r"\$0.07" in tex

    def test_new_unicode_codepoints_rendered(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"$\tau$" in tex
        assert r"$\pm$" in tex
        # no raw non-ASCII survives that would break utf8 inputenc
        assert "τ" not in tex
        assert "±" not in tex

    def test_citations_converted(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\citep{greshake-2023}" in tex
        assert (
            r"\citep{gmys-casiano-2026a, gmys-casiano-2026b, "
            r"gmys-casiano-2026c, gmys-casiano-2026d}"
        ) in tex
        # no raw pandoc markers survive
        assert "[@" not in tex

    def test_real_figures_included(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\includegraphics" in tex
        assert "../figures/fig_2.pdf" in tex
        assert r"\framebox" not in tex

    def test_all_four_tables_rendered(self, tmp_path):
        tex = self._tex(tmp_path)
        # 2 single (table) + 2 double (table*) -> 4 "\begin{table" prefixes
        assert tex.count(r"\begin{table") == 4
        assert r"\label{tab:tbl_1}" in tex
        assert r"\label{tab:tbl_2}" in tex
        assert r"\label{tab:tbl_3}" in tex
        assert r"\label{tab:tbl_4}" in tex

    def test_float_references_resolved_to_ref(self, tmp_path):
        tex = self._tex(tmp_path)
        # no authoring scaffolding survives into the submission
        assert r"(fig\_" not in tex
        assert r"(tbl\_" not in tex
        # the scrambled literal figure number is gone
        assert r"Figure 6 (fig" not in tex
        # real refs present (labels exist on the floats)
        assert r"\ref{fig:fig_1}" in tex
        assert r"\ref{fig:fig_6}" in tex
        assert r"\ref{tab:tbl_1}" in tex
        assert r"\ref{tab:tbl_4}" in tex

    def test_in_plain_terms_dropped_from_pdf(self, tmp_path):
        tex = self._tex(tmp_path)
        assert "In Plain Terms" not in tex
        assert "soft underbelly" not in tex

    def test_bibliography_and_appendix(self, tmp_path):
        tex = self._tex(tmp_path)
        assert r"\bibliography{references}" in tex
        assert r"\appendix" in tex
        assert "Generative AI Use Declaration" in tex

    def test_author_block_redaction_not_rendered(self, tmp_path):
        tex = self._tex(tmp_path)
        assert "Author block redacted" not in tex

    def test_writes_references_copy_next_to_out(self, tmp_path):
        out = tmp_path / "paper_5_acmart.tex"
        ba.build_tex(SOURCE.read_text(encoding="utf-8"), REFERENCES, out)
        assert (tmp_path / "references.bib").exists()
