"""Paper 4 figure renderer guards: TrueType embedding (ACM-safe) + all
six figures render to non-trivial vector PDFs traced to closed artifacts."""
from __future__ import annotations

import matplotlib


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_4.build_figures  # noqa: F401  (import sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42
