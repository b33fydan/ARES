# tests/dialectic/measurement/test_read_depth_oov_audit_report.py
from ares.dialectic.measurement.read_depth_oov_audit import (
    AUDIT_REFUTED, INDEP_REFUTED, INDEP_CONFIRMED,
    EvadingJudgement, ControlJudgement, OOVAuditSummary, render_audit_report,
)


def _summary(verdict, evading, controls, psc):
    return OOVAuditSummary(
        evading=evading, controls=controls, per_scenario_confirmed=psc,
        judge_labels=("openai", "gemini"), controls_passed=True,
        audit_verdict=verdict, total_cost_usd=1.5,
        base_oov_corpus_digest="deadbeefdeadbeef")


def test_report_names_verdict_scenarios_controls_and_adjudication():
    ev = (EvadingJudgement(
        "RDF-M-LEX-002", "black",
        (("rdf-m-lex-002-fact-001", "C:/Temp/refresh"),),
        (("rdf-m-lex-002-fact-001", "C:\\Temp\\update.exe"),),
        True, (("openai", False), ("gemini", False)), INDEP_REFUTED),)
    ctrl = (ControlJudgement("RDF-M-LEX-002", "positive", True,
                             (("openai", True), ("gemini", True)), True),
            ControlJudgement("RDF-B-CLEAN-001", "negative", False,
                             (("openai", False), ("gemini", False)), True))
    md = render_audit_report(_summary(AUDIT_REFUTED, ev, ctrl,
                                      (("RDF-M-LEX-002", False),)))
    assert "AUDIT" in md and AUDIT_REFUTED in md
    assert "RDF-M-LEX-002" in md
    assert "update.exe" in md and "refresh" in md     # original->disguised shown
    assert "openai" in md and "gemini" in md
    assert "Human adjudication" in md                 # split/refuted surfaced
    assert "RDF-B-CLEAN-001" in md                    # controls table
    # table structure (not just prose) renders for all three tables
    assert "| evaded scenario | independently confirmed |" in md
    assert "| scenario | arm | original -> disguised | sonnet |" in md
    assert "| control | kind | expected |" in md
