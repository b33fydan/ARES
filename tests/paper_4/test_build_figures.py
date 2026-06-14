"""Paper 4 figure renderer guards: TrueType embedding (ACM-safe) + all
six figures render to non-trivial vector PDFs traced to closed artifacts."""
from __future__ import annotations

import matplotlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_4.build_figures  # noqa: F401  (import sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42


def test_all_six_figures_render_nontrivial_pdfs(tmp_path, monkeypatch):
    import docs.paper_4.build_figures as bf
    monkeypatch.setattr(bf, "OUT", tmp_path)
    assert sorted(bf.ALL_FIGURES) == [1, 2, 3, 4, 5, 6]
    for num, fn in bf.ALL_FIGURES.items():
        fn()
        pdf = tmp_path / f"fig_{num}.pdf"
        assert pdf.exists(), num
        assert pdf.stat().st_size > 2000, (num, pdf.stat().st_size)
        assert pdf.read_bytes()[:4] == b"%PDF", num
