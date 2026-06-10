# tests/paper_4/test_prereg_bands_match_code.py
from pathlib import Path

from ares.dialectic.measurement.read_depth_verdict import (
    FRAMING_ROBUST_MAX_X, HIGH_DETECTION_MIN_J,
)

_DOC = (Path(__file__).resolve().parents[2]
        / "docs" / "paper_4"
        / "PREREGISTRATION_read_depth_frontier_phase_c.md")


def test_prereg_doc_exists():
    assert _DOC.is_file()


def test_prereg_cites_the_code_bands():
    text = _DOC.read_text(encoding="utf-8")
    # The doc must cite the exact band constants the verdict code uses.
    assert f"X_semantic <= {FRAMING_ROBUST_MAX_X:.2f}" in text
    assert f"cumulative Youden J >= {HIGH_DETECTION_MIN_J:.2f}" in text


def test_prereg_names_the_observed_vs_predicted_ledger():
    text = _DOC.read_text(encoding="utf-8").lower()
    assert "observed" in text and "predicted" in text
    assert "9401b7188ba790a5" in text  # frozen corpus digest


def test_prereg_records_the_falsifier():
    text = _DOC.read_text(encoding="utf-8").lower()
    assert "falsif" in text
