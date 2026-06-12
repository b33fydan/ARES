# tests/paper_4/test_oov_audit_prereg_bands_match_code.py
from pathlib import Path

from ares.dialectic.measurement.read_depth_oov_audit import (
    AUDIT_ROBUST, AUDIT_PARTIAL, AUDIT_REFUTED, AUDIT_INCONCLUSIVE,
    CONFIRM_REQUIRES_BOTH_INDEPENDENTS,
)
from ares.dialectic.measurement.read_depth_oov_schema import (
    READ_DEPTH_OOV_HARD_CEILING_USD,
)

_DOC = (Path(__file__).resolve().parents[2]
        / "docs" / "paper_4" / "PREREGISTRATION_oov_audit_phase_e.md")


def test_prereg_doc_exists():
    assert _DOC.is_file()


def test_prereg_names_all_audit_verdicts():
    text = _DOC.read_text(encoding="utf-8")
    for label in (AUDIT_ROBUST, AUDIT_PARTIAL, AUDIT_REFUTED, AUDIT_INCONCLUSIVE):
        assert label in text


def test_prereg_states_both_independents_rule_and_controls():
    text = _DOC.read_text(encoding="utf-8").lower()
    assert CONFIRM_REQUIRES_BOTH_INDEPENDENTS is True
    assert "both" in text and "independent" in text
    assert "positive control" in text and "negative control" in text
    assert "committed before any live run" in text


def test_prereg_states_cap_and_panel():
    text = _DOC.read_text(encoding="utf-8")
    assert f"${READ_DEPTH_OOV_HARD_CEILING_USD:.0f}" in text  # $10
    assert "gpt-4o" in text.lower() and "gemini" in text.lower()
