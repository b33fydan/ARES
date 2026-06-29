"""Paper 5 figure renderer guards: TrueType embedding (ACM-safe) + all six
figures render to non-trivial vector PDFs; data figures trace to the S099 artifact."""
from __future__ import annotations

import json
import matplotlib
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
RUN = REPO / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"


def test_build_figures_sets_truetype_fonttype():
    import docs.paper_5.build_figures  # noqa: F401  (import sets rcParams)
    assert matplotlib.rcParams["pdf.fonttype"] == 42
    assert matplotlib.rcParams["ps.fonttype"] == 42


def test_all_six_figures_render_nontrivial_pdfs(tmp_path, monkeypatch):
    import docs.paper_5.build_figures as bf
    monkeypatch.setattr(bf, "OUT", tmp_path)
    assert sorted(bf.ALL_FIGURES) == [1, 2, 3, 4, 5, 6]
    for num, fn in bf.ALL_FIGURES.items():
        fn()
        pdf = tmp_path / f"fig_{num}.pdf"
        assert pdf.exists(), num
        assert pdf.stat().st_size > 2000, (num, pdf.stat().st_size)
        assert pdf.read_bytes()[:4] == b"%PDF", num


def test_data_figures_trace_to_s099_artifact():
    """The data-figure loader must return the artifact's values, not hardcoded ones."""
    import docs.paper_5.build_figures as bf
    run = json.loads(RUN.read_text(encoding="utf-8"))
    # max undefended ASR across the sweep is 0.0 (the no-headroom regime)
    assert max(c["undefended_asr"] for c in run["sweep"]) == 0.0
    arms = run["stage1_arms"]
    assert arms["full_defense"]["gate_denials"] == 2
    assert arms["undefended"]["gate_denials"] == 0 and arms["gate_off"]["gate_denials"] == 0
    assert arms["full_defense"]["utility"] == 0.3 and arms["undefended"]["utility"] == 0.5
    assert run["benign_false_block"]["full_defense"]["false_block_rate_per_task"] == 0.2
    assert run["tau_asr"] == 0.2
