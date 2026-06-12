# tests/dialectic/measurement/test_read_depth_oov_report.py
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, OOVArmSummary, OOVEvasionRecord, OOVFrontierSummary,
    VERDICT_SUPPORTED_STRONG,
)
from ares.dialectic.measurement.read_depth_oov_report import render_oov_report


def _summary():
    black = OOVArmSummary(ARM_BLACK, 8, 6, 1, 1, 0, ("RDF-M-LEX-001",),
                          0.25, 0.1667, 4)
    white = OOVArmSummary(ARM_WHITE, 8, 7, 0, 1, 0, ("RDF-M-LEX-001",),
                          0.25, 0.1429, 4)
    rec = OOVEvasionRecord("RDF-M-LEX-001", ARM_BLACK, True, True)
    return OOVFrontierSummary((black, white), (rec,), VERDICT_SUPPORTED_STRONG,
                              "9401b7188ba790a5", "abcdef0123456789", 1.5,
                              "claude-sonnet-4-20250514", "anthropic", 8)


def test_report_has_verdict_table_and_caveats():
    md = render_oov_report(_summary())
    assert "SUPPORTED_STRONG" in md
    assert "black" in md and "white" in md
    assert "adversarial" in md.lower()
    assert "RDF-M-LEX-001" in md
    # the honest caveats are stated
    assert "small" in md.lower() and "caveat" in md.lower()
    # the non-falsifier framing is named
    assert "v2_canonical" in md
