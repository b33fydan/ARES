"""Tests for Paper 2 figure generation.

Run make_figures.build_all against the real results directory and
assert every PNG is produced, non-empty, and at least 100KB. Also
verify each builder function is callable in isolation and that
FIGURE_BUILDERS covers the full filename set.
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = REPO_ROOT / "results"


@pytest.fixture(scope="module")
def figures_dir(tmp_path_factory) -> Path:
    """Build figures into a tmp dir once per module."""
    out_dir = tmp_path_factory.mktemp("paper2_figures")
    from docs.paper_2.figures.make_figures import build_all
    build_all(out_dir, RESULTS_ROOT)
    return out_dir


class TestBuildAll:
    def test_all_five_written(self, figures_dir):
        pngs = sorted(p.name for p in figures_dir.glob("*.png"))
        assert len(pngs) == 5

    def test_expected_filenames(self, figures_dir):
        pngs = {p.name for p in figures_dir.glob("*.png")}
        assert pngs == {
            "fig1_architecture.png",
            "fig2_firewall_detection.png",
            "fig3_family_heatmap.png",
            "fig4_scenario_verdicts.png",
            "fig5_rubric_bands.png",
        }


class TestSizeFloor:
    @pytest.mark.parametrize("fname", [
        "fig1_architecture.png",
        "fig2_firewall_detection.png",
        "fig3_family_heatmap.png",
        "fig4_scenario_verdicts.png",
        "fig5_rubric_bands.png",
    ])
    def test_figure_at_least_100kb(self, figures_dir, fname):
        path = figures_dir / fname
        assert path.exists(), f"{fname} not produced"
        size = path.stat().st_size
        assert size >= 100 * 1024, (
            f"{fname} is only {size} bytes; need >= 100KB"
        )


class TestBuilderCoverage:
    def test_figure_builders_tuple_has_five_entries(self):
        from docs.paper_2.figures.make_figures import FIGURE_BUILDERS
        assert len(FIGURE_BUILDERS) == 5

    def test_every_builder_is_callable(self):
        from docs.paper_2.figures.make_figures import FIGURE_BUILDERS
        for _fname, _label, builder, _needs in FIGURE_BUILDERS:
            assert callable(builder)

    def test_builder_filenames_match_expected_set(self):
        from docs.paper_2.figures.make_figures import FIGURE_BUILDERS
        fnames = {row[0] for row in FIGURE_BUILDERS}
        assert fnames == {
            "fig1_architecture.png",
            "fig2_firewall_detection.png",
            "fig3_family_heatmap.png",
            "fig4_scenario_verdicts.png",
            "fig5_rubric_bands.png",
        }


class TestBuilderDocstrings:
    def test_each_builder_has_non_empty_docstring(self):
        from docs.paper_2.figures.make_figures import (
            make_fig1_architecture,
            make_fig2_firewall_detection,
            make_fig3_family_heatmap,
            make_fig4_scenario_verdicts,
            make_fig5_rubric_bands,
        )
        for fn in (
            make_fig1_architecture,
            make_fig2_firewall_detection,
            make_fig3_family_heatmap,
            make_fig4_scenario_verdicts,
            make_fig5_rubric_bands,
        ):
            assert fn.__doc__, f"{fn.__name__} missing docstring/caption"
            assert "Caption" in fn.__doc__ or "Figure" in fn.__doc__


class TestCLIEntrypoint:
    def test_main_returns_zero(self, tmp_path):
        from docs.paper_2.figures.make_figures import main
        code = main([
            "--out-dir", str(tmp_path),
            "--results-root", str(RESULTS_ROOT),
        ])
        assert code == 0
        assert len(list(tmp_path.glob("*.png"))) == 5

    def test_main_prints_each_file(self, tmp_path, capsys):
        from docs.paper_2.figures.make_figures import main
        main([
            "--out-dir", str(tmp_path),
            "--results-root", str(RESULTS_ROOT),
        ])
        captured = capsys.readouterr()
        for fname in (
            "fig1_architecture.png",
            "fig2_firewall_detection.png",
            "fig3_family_heatmap.png",
            "fig4_scenario_verdicts.png",
            "fig5_rubric_bands.png",
        ):
            assert fname in captured.out


class TestDocxSkeleton:
    def test_skeleton_builds(self, tmp_path):
        from docs.paper_2.build_skeleton import build_document
        doc = build_document(figures_dir=(REPO_ROOT / "docs/paper_2/figures").resolve())
        out_path = tmp_path / "skeleton.docx"
        doc.save(str(out_path))
        assert out_path.exists()
        # DocX files are zipped — a populated skeleton with inlined
        # PNGs must be far larger than a minimal docx (~15KB).
        assert out_path.stat().st_size > 200 * 1024

    def test_skeleton_has_expected_headers(self, tmp_path):
        from docs.paper_2.build_skeleton import (
            EXPECTED_SUBSECTION_HEADERS,
            EXPECTED_TOP_LEVEL_HEADERS,
            build_document,
        )
        from docx import Document as _load
        doc = build_document(figures_dir=(REPO_ROOT / "docs/paper_2/figures").resolve())
        out_path = tmp_path / "skel.docx"
        doc.save(str(out_path))
        loaded = _load(str(out_path))
        headings = [
            p.text for p in loaded.paragraphs
            if p.style.name.startswith("Heading")
        ]
        for expected in EXPECTED_TOP_LEVEL_HEADERS:
            assert expected in headings, f"Missing top-level: {expected}"
        for expected in EXPECTED_SUBSECTION_HEADERS:
            assert expected in headings, f"Missing subsection: {expected}"

    def test_skeleton_has_13_top_level_headers(self, tmp_path):
        from docs.paper_2.build_skeleton import (
            EXPECTED_TOP_LEVEL_HEADERS,
        )
        # The skeleton is required to have all top-level entries.
        assert len(EXPECTED_TOP_LEVEL_HEADERS) == 13
