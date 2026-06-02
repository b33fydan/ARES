"""B1+B2 guards for acmart figure rendering in build_acmart.py.

B2: figures render as \\includegraphics of the S073 vector PDFs (so the
documented build reproduces the committed .tex), not \\framebox boxes.
B1 (added in Task 3): captions carry no placeholder spike text."""
from __future__ import annotations

from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parents[2]
SOURCE = REPO_ROOT / "docs" / "paper_3" / "source" / "PAPER3_DRAFT_v1_0_source.md"
REFS = REPO_ROOT / "docs" / "paper_3" / "references.bib"


def _build_tex(tmp_path) -> str:
    from docs.paper_3.build_acmart import build_tex
    src = SOURCE.read_text(encoding="utf-8")
    # build_tex returns the .tex string; it copies references.bib into the
    # out dir as a side effect, so point it at tmp_path.
    return build_tex(src, REFS, tmp_path / "paper.tex")


def test_figures_use_includegraphics_not_framebox(tmp_path):
    tex = _build_tex(tmp_path)
    assert tex.count("\\includegraphics") == 6
    assert "\\framebox" not in tex
    assert "[Placeholder:" not in tex


def test_figure_width_matches_span(tmp_path):
    tex = _build_tex(tmp_path)
    # fig_1 is the only double-column figure -> \textwidth
    assert "\\includegraphics[width=\\textwidth]{../figures/fig_1.pdf}" in tex
    for fid in ("fig_2", "fig_3", "fig_4", "fig_5", "fig_6"):
        assert f"\\includegraphics[width=\\columnwidth]{{../figures/{fid}.pdf}}" in tex
