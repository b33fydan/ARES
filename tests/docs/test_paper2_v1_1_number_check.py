"""Tests for the v1.1 extension to docs/paper_2/number_check.py.

Covers:
    * Prose substring claim list is non-empty and includes required IDs.
    * extract_docx_text returns concatenated paragraph text.
    * check_prose_substrings flags missing substrings as failures.
    * The actual v1.1 docx (built fresh) passes every prose substring.
    * The new per-family three-way claim cells are present and resolve.
    * main() with --docx exits 0 on the built v1.1 docx.
"""

from __future__ import annotations

from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
RESULTS_ROOT = REPO_ROOT / "results"
SOURCE_MD = REPO_ROOT / "docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md"
FIGURES_DIR = REPO_ROOT / "docs/paper_2/figures"


# ----------------------------------------------------------------------------
# Build a v1.1 docx ONCE for this module
# ----------------------------------------------------------------------------


@pytest.fixture(scope="module")
def v1_1_docx(tmp_path_factory) -> Path:
    """Build a fresh v1.1 docx (no References) for prose substring checks."""
    from docs.paper_2.build_v1_1 import build_document, parse_source
    parsed = parse_source(SOURCE_MD)
    doc = build_document(parsed, FIGURES_DIR)
    out_dir = tmp_path_factory.mktemp("v1_1_docx_for_numcheck")
    out_path = out_dir / "PAPER2_DRAFT_v1_1.docx"
    doc.save(str(out_path))
    return out_path


# ----------------------------------------------------------------------------
# Substring claim list
# ----------------------------------------------------------------------------


class TestProseSubstringClaims:
    def test_non_empty(self):
        from docs.paper_2.number_check import prose_substring_claims
        assert len(prose_substring_claims()) > 0

    def test_includes_corpus_split(self):
        from docs.paper_2.number_check import prose_substring_claims
        claims = prose_substring_claims()
        assert "27" in claims
        assert "19" in claims
        assert "25" in claims

    def test_includes_required_inj_ids(self):
        from docs.paper_2.number_check import prose_substring_claims
        claims = prose_substring_claims()
        for inj in ("INJ-006", "INJ-008", "INJ-014",
                    "INJ-020", "INJ-024", "INJ-025", "INJ-027"):
            assert inj in claims, f"Substring claim missing: {inj}"

    def test_includes_headline_accuracies(self):
        from docs.paper_2.number_check import prose_substring_claims
        claims = prose_substring_claims()
        for value in ("0.7895", "0.8400", "0.7200"):
            assert value in claims, f"Missing accuracy substring: {value}"


# ----------------------------------------------------------------------------
# extract_docx_text
# ----------------------------------------------------------------------------


class TestExtractDocxText:
    def test_returns_non_empty(self, v1_1_docx):
        from docs.paper_2.number_check import extract_docx_text
        text = extract_docx_text(v1_1_docx)
        assert len(text) > 1000

    def test_concatenates_paragraphs(self, v1_1_docx):
        """Every section header must show up in the extracted text."""
        from docs.paper_2.number_check import extract_docx_text
        text = extract_docx_text(v1_1_docx)
        for header in ("Abstract", "1. Introduction",
                       "5. Syntactic Firewall", "11. Conclusion",
                       "References"):
            assert header in text, f"Missing header in extracted text: {header}"


# ----------------------------------------------------------------------------
# check_prose_substrings
# ----------------------------------------------------------------------------


class TestCheckProseSubstrings:
    def test_present_substrings_pass(self):
        from docs.paper_2.number_check import check_prose_substrings
        text = "alpha beta gamma 27 INJ-006"
        results = check_prose_substrings(text, ("alpha", "27", "INJ-006"))
        assert all(r.passed for r in results)

    def test_missing_substring_fails(self):
        from docs.paper_2.number_check import check_prose_substrings
        text = "only this exists"
        results = check_prose_substrings(text, ("only", "missing-thing"))
        assert results[0].passed is True
        assert results[1].passed is False
        assert "missing-thing" in results[1].label

    def test_built_v1_1_passes_every_prose_claim(self, v1_1_docx):
        from docs.paper_2.number_check import (
            check_prose_substrings,
            extract_docx_text,
            prose_substring_claims,
        )
        text = extract_docx_text(v1_1_docx)
        results = check_prose_substrings(text, prose_substring_claims())
        failed = [r for r in results if not r.passed]
        assert not failed, (
            "Built v1.1 docx is missing prose substrings: "
            + ", ".join(r.label for r in failed)
        )


# ----------------------------------------------------------------------------
# Extended default_claims (per-family three-way cells)
# ----------------------------------------------------------------------------


class TestExtendedClaims:
    def test_severity_full_claim_present(self):
        from docs.paper_2.number_check import default_claims
        labels = {c.label for c in default_claims()}
        assert "Session 050 severity full accuracy" in labels

    def test_all_five_families_have_three_variants(self):
        from docs.paper_2.number_check import default_claims
        labels = {c.label for c in default_claims()}
        for family in ("severity", "authority", "temporal", "causal",
                       "narrative"):
            for variant in ("full", "light", "ablated"):
                label = f"Session 050 {family} {variant} accuracy"
                assert label in labels, f"Missing claim: {label}"

    def test_all_extended_claims_pass_on_real_data(self):
        from docs.paper_2.number_check import default_claims, run_checks
        results = run_checks(default_claims(), RESULTS_ROOT)
        failed = [r for r in results if not r.passed]
        assert not failed, (
            "Default claims not passing: "
            + ", ".join(r.label for r in failed)
        )


# ----------------------------------------------------------------------------
# CLI integration with --docx
# ----------------------------------------------------------------------------


class TestCLIWithDocx:
    def test_main_with_docx_exits_zero(self, v1_1_docx, tmp_path):
        from docs.paper_2.number_check import main
        report = tmp_path / "report.md"
        code = main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(report),
            "--docx", str(v1_1_docx),
        ])
        assert code == 0
        assert report.exists()

    def test_main_with_docx_includes_prose_lines(self, v1_1_docx, tmp_path):
        from docs.paper_2.number_check import main
        report = tmp_path / "report.md"
        main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(report),
            "--docx", str(v1_1_docx),
        ])
        text = report.read_text(encoding="utf-8")
        # Substring-check rows render with "prose contains '...'" labels.
        assert "prose contains" in text

    def test_main_with_broken_docx_fails(self, tmp_path):
        """A docx that lacks the expected substrings must fail the run."""
        from docx import Document
        from docs.paper_2.number_check import main
        broken_docx = tmp_path / "broken.docx"
        d = Document()
        d.add_paragraph("This document contains none of the expected values.")
        d.save(str(broken_docx))
        report = tmp_path / "report.md"
        code = main([
            "--results-root", str(RESULTS_ROOT),
            "--out-report", str(report),
            "--docx", str(broken_docx),
        ])
        assert code == 1
        text = report.read_text(encoding="utf-8")
        assert "FAIL" in text
