"""Paper 5 acmart PDF substring gate — behavior + integration.

The compiled submission PDF must contain every value in
``docs.paper_5.number_check.prose_substring_claims()`` (the locked,
load-bearing numbers — ``$3.8``, ``$0.07``, ``US133000000121212121212``,
``0.95`` ...). The gate runs pdftotext and checks. The pure substring
logic is unit-tested; the real-PDF check is integration and skips when the
compiled artifact or pdftotext is unavailable.
"""
from __future__ import annotations

from pathlib import Path

import pytest

from docs.paper_5 import number_check as nc
from docs.paper_5.acmart import verify_pdf_substrings as gate

REPO = Path(__file__).resolve().parents[2]
PDF = REPO / "docs" / "paper_5" / "acmart" / "paper_5_acmart.pdf"


class TestSubstringLogic:
    def test_missing_substrings_flags_absent(self):
        assert gate.missing_substrings("hello world", ["hello", "xyz"]) == ["xyz"]

    def test_missing_substrings_empty_when_all_present(self):
        assert gate.missing_substrings("a b c", ["a", "c"]) == []

    def test_locked_list_is_number_check_prose_claims(self):
        assert tuple(gate.locked_substrings()) == tuple(nc.prose_substring_claims())


class TestRealPdf:
    def test_compiled_pdf_contains_all_locked_substrings(self):
        if not PDF.exists():
            pytest.skip("paper_5_acmart.pdf not built")
        try:
            text = gate.extract_pdf_text(PDF)
        except FileNotFoundError:
            pytest.skip("pdftotext unavailable")
        missing = gate.missing_substrings(text, gate.locked_substrings())
        assert not missing, missing
