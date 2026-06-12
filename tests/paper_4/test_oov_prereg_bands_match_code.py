# tests/paper_4/test_oov_prereg_bands_match_code.py
from pathlib import Path

from ares.dialectic.measurement.read_depth_oov_schema import (
    FALSIFIED_REQUIRES_ZERO_EVASIONS, READ_DEPTH_OOV_HARD_CEILING_USD,
    VERDICT_FALSIFIED, VERDICT_SUPPORTED_MODERATE, VERDICT_SUPPORTED_STRONG,
)

_DOC = (Path(__file__).resolve().parents[2]
        / "docs" / "paper_4" / "PREREGISTRATION_oov_evasion_phase_d.md")


def test_prereg_doc_exists():
    assert _DOC.is_file()


def test_prereg_states_the_any_hole_rule_matching_code():
    text = _DOC.read_text(encoding="utf-8")
    assert FALSIFIED_REQUIRES_ZERO_EVASIONS is True
    assert "zero evaded scenarios" in text
    assert f"${READ_DEPTH_OOV_HARD_CEILING_USD:.0f}" in text  # $10


def test_prereg_names_all_three_verdict_labels():
    text = _DOC.read_text(encoding="utf-8")
    for label in (VERDICT_SUPPORTED_STRONG, VERDICT_SUPPORTED_MODERATE,
                  VERDICT_FALSIFIED):
        assert label in text


def test_prereg_names_corpus_arms_and_falsifier():
    text = _DOC.read_text(encoding="utf-8").lower()
    assert "9401b7188ba790a5" in text
    assert "black-box" in text and "white-box" in text
    assert "falsif" in text
