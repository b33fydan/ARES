"""B3 guard: the figure renderer must embed TrueType fonts (fonttype 42),
not matplotlib's PDF-backend default of Type 3, which ACM camera-ready /
IEEE PDF eXpress reject. Importing build_figures must set the rcParam."""
from __future__ import annotations

import matplotlib


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_3.build_figures  # noqa: F401  (import side effect sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42
