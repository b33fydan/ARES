"""Misclassification diagnosis engine — failure mode classification.

Session 031: Analyzes saved benchmark results to classify WHY each
misclassified scenario got the wrong verdict. Maps failure modes to
concrete prompt engineering recommendations for Session 032.

Public API:
    diagnose_benchmark()       — Load results and produce DiagnosisReport
    classify_failure_mode()    — Classify a single misclassification
    format_diagnosis_report()  — ASCII report
    FailureMode               — Enum of failure categories
    ScenarioDiagnosis          — Per-scenario diagnosis
    DiagnosisReport            — Aggregate report
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Any, Dict, Tuple


# ---------------------------------------------------------------------------
# Failure mode taxonomy
# ---------------------------------------------------------------------------

class FailureMode(Enum):
    """Categories of misclassification root causes."""

    SKEPTIC_OVERWEIGHT = auto()       # Skeptic confidence too high on weak evidence
    ARCHITECT_UNDERWEIGHT = auto()    # Architect missed or underweighted threat indicators
    EVIDENCE_GAP = auto()             # Insufficient facts to make correct determination
    CONFIDENCE_CALIBRATION = auto()   # Right direction, wrong magnitude flipped verdict
    AMBIGUITY_MISMATCH = auto()       # System reasonable, expected verdict arguably wrong
    VERDICT_INVERSION = auto()        # Complete reversal (THREAT expected, DISMISSED produced)
    ERROR_DURING_ANALYSIS = auto()    # Scenario threw an exception during benchmark


# ---------------------------------------------------------------------------
# Diagnosis dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ScenarioDiagnosis:
    """Diagnosis of a single misclassified scenario.

    Attributes:
        scenario_id: Scenario identifier.
        scenario_name: Human-readable name.
        expected_verdict: What the corpus says the answer should be.
        actual_verdict: What the LLM produced.
        failure_mode: Classified root cause.
        architect_confidence: Architect's confidence (0-1).
        skeptic_confidence: Skeptic's confidence (0-1).
        verdict_confidence: Overall verdict confidence (0-1).
        fact_coverage: Fraction of available facts cited (0-1).
        total_facts: Number of facts in the evidence packet.
        evidence_summary: Human-readable summary of available evidence.
        failure_explanation: Why this failure mode was classified.
        recommendation: Concrete suggestion for fixing this miss.
    """

    scenario_id: str
    scenario_name: str
    expected_verdict: str
    actual_verdict: str
    failure_mode: FailureMode
    architect_confidence: float
    skeptic_confidence: float
    verdict_confidence: float
    fact_coverage: float
    total_facts: int
    evidence_summary: str
    failure_explanation: str
    recommendation: str


@dataclass(frozen=True)
class DiagnosisReport:
    """Complete diagnosis of all misclassifications in a benchmark run.

    Attributes:
        benchmark_timestamp: Timestamp of the original benchmark run.
        total_scenarios: Total number of scenarios in the run.
        correct: Number of correctly classified scenarios.
        misclassified: Number of misclassified scenarios.
        error_count: Number of scenarios that errored.
        diagnoses: Per-scenario diagnosis tuples.
        failure_mode_distribution: Count per FailureMode.
    """

    benchmark_timestamp: str
    total_scenarios: int
    correct: int
    misclassified: int
    error_count: int
    diagnoses: Tuple[ScenarioDiagnosis, ...]
    failure_mode_distribution: Dict[str, int]

    @property
    def accuracy(self) -> float:
        """Accuracy as fraction (0-1)."""
        return self.correct / self.total_scenarios if self.total_scenarios > 0 else 0.0


# ---------------------------------------------------------------------------
# Classification logic
# ---------------------------------------------------------------------------

def classify_failure_mode(
    result: Dict[str, Any],
    expected_verdict: str,
) -> FailureMode:
    """Classify why a scenario was misclassified.

    Args:
        result: ScenarioResult dict from saved benchmark JSON.
        expected_verdict: The corpus's expected verdict (lowercase).

    Returns:
        FailureMode classification.
    """
    actual = result["verdict_outcome"]

    # Error during analysis
    if actual == "error":
        return FailureMode.ERROR_DURING_ANALYSIS

    arch_conf = result["architect_confidence"]
    skep_conf = result["skeptic_confidence"]
    coverage = result["fact_coverage_ratio"]

    # Complete reversal
    threat_expected = expected_verdict == "threat_confirmed"
    dismissed_expected = expected_verdict == "threat_dismissed"
    threat_actual = actual == "threat_confirmed"
    dismissed_actual = actual == "threat_dismissed"

    if (threat_expected and dismissed_actual) or (dismissed_expected and threat_actual):
        return FailureMode.VERDICT_INVERSION

    # Expected INCONCLUSIVE — check if system behavior is defensible
    if expected_verdict == "inconclusive":
        # If the system gave a conclusive answer but the truth is ambiguous,
        # the system's call might be reasonable
        if abs(arch_conf - skep_conf) > 0.2:
            return FailureMode.AMBIGUITY_MISMATCH
        return FailureMode.CONFIDENCE_CALIBRATION

    # Skeptic overweight: high skeptic confidence drove dismissal when threat expected
    if threat_expected and skep_conf > 0.7 and dismissed_actual:
        return FailureMode.SKEPTIC_OVERWEIGHT

    if threat_expected and skep_conf > 0.6 and actual == "inconclusive":
        return FailureMode.SKEPTIC_OVERWEIGHT

    # Architect underweight: low architect confidence on real threats
    if threat_expected and arch_conf < 0.5:
        return FailureMode.ARCHITECT_UNDERWEIGHT

    # Evidence gap: coverage too low to make correct call
    if coverage < 0.6:
        return FailureMode.EVIDENCE_GAP

    # Confidence calibration: close call went wrong way
    if abs(arch_conf - skep_conf) < 0.15:
        return FailureMode.CONFIDENCE_CALIBRATION

    # Skeptic overweight for benign expected but got threat
    if dismissed_expected and arch_conf > 0.7:
        return FailureMode.ARCHITECT_UNDERWEIGHT  # Actually architect over-aggressive

    return FailureMode.CONFIDENCE_CALIBRATION


def build_evidence_summary(scenario) -> str:
    """Build a human-readable summary of the evidence in a scenario.

    Args:
        scenario: BenchmarkScenario with .metadata and .packet.

    Returns:
        Concise 2-4 sentence summary.
    """
    meta = scenario.metadata
    packet = scenario.packet
    facts = list(packet.get_all_facts())

    source_types = sorted({f.provenance.source_type.value for f in facts})
    entity_ids = sorted({f.entity_id for f in facts})
    fields = sorted({f.field for f in facts})

    parts = [
        f"{meta.fact_count} facts from {', '.join(source_types)}.",
        f"Entities: {', '.join(entity_ids[:5])}{'...' if len(entity_ids) > 5 else ''}.",
        f"Fields observed: {', '.join(fields[:6])}{'...' if len(fields) > 6 else ''}.",
        f"Tier {meta.difficulty_tier} ({meta.mitre_tactic}).",
    ]
    return " ".join(parts)


def build_recommendation(
    failure_mode: FailureMode,
    result: Dict[str, Any],
    scenario,
) -> str:
    """Generate a concrete recommendation for fixing a misclassification.

    Args:
        failure_mode: The classified failure mode.
        result: ScenarioResult dict.
        scenario: BenchmarkScenario.

    Returns:
        Actionable prompt engineering suggestion.
    """
    sid = result["scenario_id"]
    arch = result["architect_confidence"]
    skep = result["skeptic_confidence"]
    delta = abs(arch - skep)

    if failure_mode == FailureMode.SKEPTIC_OVERWEIGHT:
        return (
            f"Tighten Skeptic plausibility gating — {sid} had skeptic={skep:.2f} "
            f"on weak benign evidence. Require explicit authorization artifacts "
            f"(change tickets, maintenance windows) before confidence > 0.6."
        )
    elif failure_mode == FailureMode.ARCHITECT_UNDERWEIGHT:
        tactic = scenario.metadata.mitre_tactic
        return (
            f"Strengthen Architect detection for {tactic} patterns — {sid} had "
            f"architect={arch:.2f} despite clear threat indicators. Add emphasis "
            f"on this attack type in Architect prompt."
        )
    elif failure_mode == FailureMode.EVIDENCE_GAP:
        coverage = result["fact_coverage_ratio"]
        return (
            f"No prompt fix — {sid} has fact_coverage={coverage:.2f}. "
            f"Consider adding facts to the scenario or reviewing expected verdict."
        )
    elif failure_mode == FailureMode.CONFIDENCE_CALIBRATION:
        return (
            f"Adjust Oracle scoring weights — {sid} had confidence delta "
            f"of only {delta:.2f} (arch={arch:.2f}, skep={skep:.2f}). "
            f"The margin was too thin and flipped the wrong way."
        )
    elif failure_mode == FailureMode.AMBIGUITY_MISMATCH:
        return (
            f"Review expected verdict for {sid} — system behavior is defensible. "
            f"Consider whether INCONCLUSIVE is truly the right label."
        )
    elif failure_mode == FailureMode.VERDICT_INVERSION:
        tactic = scenario.metadata.mitre_tactic
        return (
            f"Critical miss on {sid} ({tactic}) — complete verdict inversion. "
            f"Investigate whether agent prompts fundamentally mishandle this "
            f"attack type. Priority fix for Session 032."
        )
    elif failure_mode == FailureMode.ERROR_DURING_ANALYSIS:
        return (
            f"Fix runtime error in {sid} before addressing accuracy. "
            f"Check API response parsing and fallback handling."
        )
    return f"Investigate {sid} manually — no automatic recommendation available."


def build_failure_explanation(
    failure_mode: FailureMode,
    result: Dict[str, Any],
    expected: str,
) -> str:
    """Explain why the failure mode was classified.

    Args:
        failure_mode: Classified mode.
        result: ScenarioResult dict.
        expected: Expected verdict (lowercase).

    Returns:
        Human-readable explanation.
    """
    actual = result["verdict_outcome"]
    arch = result["architect_confidence"]
    skep = result["skeptic_confidence"]
    coverage = result["fact_coverage_ratio"]

    explanations = {
        FailureMode.SKEPTIC_OVERWEIGHT: (
            f"Expected {expected}, got {actual}. Skeptic confidence ({skep:.2f}) "
            f"dominated despite expected threat. Benign explanations given "
            f"disproportionate weight."
        ),
        FailureMode.ARCHITECT_UNDERWEIGHT: (
            f"Expected {expected}, got {actual}. Architect confidence ({arch:.2f}) "
            f"was too low to drive correct verdict. Threat indicators present "
            f"but insufficiently weighted."
        ),
        FailureMode.EVIDENCE_GAP: (
            f"Expected {expected}, got {actual}. Fact coverage ({coverage:.2f}) "
            f"too low — not enough evidence was cited to reach correct conclusion."
        ),
        FailureMode.CONFIDENCE_CALIBRATION: (
            f"Expected {expected}, got {actual}. Close confidence values "
            f"(arch={arch:.2f}, skep={skep:.2f}, delta={abs(arch - skep):.2f}) "
            f"— the margin flipped the wrong direction."
        ),
        FailureMode.AMBIGUITY_MISMATCH: (
            f"Expected {expected}, got {actual}. The system's verdict is "
            f"arguably defensible given the evidence (arch={arch:.2f}, "
            f"skep={skep:.2f}). Expected verdict may be debatable."
        ),
        FailureMode.VERDICT_INVERSION: (
            f"Expected {expected}, got {actual}. Complete reversal — "
            f"the system produced the opposite conclusion. "
            f"(arch={arch:.2f}, skep={skep:.2f})"
        ),
        FailureMode.ERROR_DURING_ANALYSIS: (
            f"Scenario errored during analysis. Expected {expected}, "
            f"got error state."
        ),
    }
    return explanations.get(failure_mode, f"Expected {expected}, got {actual}.")


# ---------------------------------------------------------------------------
# Main diagnosis function
# ---------------------------------------------------------------------------

def diagnose_benchmark(results_json_path: str) -> DiagnosisReport:
    """Load saved benchmark results and produce a complete diagnosis.

    Args:
        results_json_path: Path to saved benchmark JSON from run_031_benchmark.

    Returns:
        DiagnosisReport with all diagnoses.
    """
    path = Path(results_json_path)
    data = json.loads(path.read_text(encoding="utf-8"))

    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    corpus = {s.metadata.scenario_id: s for s in get_full_corpus()}

    results = data["results"]
    ts = data.get("timestamp", "unknown")

    diagnoses: list[ScenarioDiagnosis] = []
    error_count = 0
    correct_count = 0

    for r in results:
        sid = r["scenario_id"]
        scenario = corpus.get(sid)
        if scenario is None:
            continue

        expected = scenario.metadata.expected_verdict.lower()
        actual = r["verdict_outcome"]

        if actual == expected:
            correct_count += 1
            continue

        if actual == "error":
            error_count += 1

        failure_mode = classify_failure_mode(r, expected)
        evidence_summary = build_evidence_summary(scenario)
        recommendation = build_recommendation(failure_mode, r, scenario)
        explanation = build_failure_explanation(failure_mode, r, expected)

        diag = ScenarioDiagnosis(
            scenario_id=sid,
            scenario_name=scenario.metadata.name,
            expected_verdict=expected,
            actual_verdict=actual,
            failure_mode=failure_mode,
            architect_confidence=r["architect_confidence"],
            skeptic_confidence=r["skeptic_confidence"],
            verdict_confidence=r["verdict_confidence"],
            fact_coverage=r["fact_coverage_ratio"],
            total_facts=r["total_facts_available"],
            evidence_summary=evidence_summary,
            failure_explanation=explanation,
            recommendation=recommendation,
        )
        diagnoses.append(diag)

    # Failure mode distribution
    dist: Dict[str, int] = {}
    for d in diagnoses:
        key = d.failure_mode.name
        dist[key] = dist.get(key, 0) + 1

    return DiagnosisReport(
        benchmark_timestamp=ts,
        total_scenarios=len(results),
        correct=correct_count,
        misclassified=len(diagnoses),
        error_count=error_count,
        diagnoses=tuple(diagnoses),
        failure_mode_distribution=dist,
    )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_diagnosis_report(report: DiagnosisReport) -> str:
    """Format DiagnosisReport as readable ASCII text.

    Sections:
        1. Header with accuracy summary
        2. Failure mode distribution
        3. Per-scenario diagnosis
        4. Aggregate recommendations grouped by failure mode

    Args:
        report: The diagnosis report to format.

    Returns:
        Multi-line string suitable for printing or saving.
    """
    lines: list[str] = []

    # Header
    lines.append("=" * 78)
    lines.append("ARES Misclassification Diagnosis Report")
    lines.append(f"Benchmark: {report.benchmark_timestamp}")
    lines.append(f"Accuracy: {report.correct}/{report.total_scenarios} "
                 f"({report.accuracy * 100:.1f}%)")
    lines.append(f"Misclassified: {report.misclassified}  |  Errors: {report.error_count}")
    lines.append("=" * 78)
    lines.append("")

    # Failure mode distribution
    lines.append("Failure Mode Distribution")
    lines.append("-" * 40)
    for mode_name, count in sorted(report.failure_mode_distribution.items(),
                                    key=lambda x: -x[1]):
        bar = "#" * count
        lines.append(f"  {mode_name:<28s} {count:>2}  {bar}")
    lines.append("")

    # Per-scenario diagnosis
    lines.append("=" * 78)
    lines.append("Per-Scenario Diagnosis")
    lines.append("=" * 78)

    for d in report.diagnoses:
        lines.append("")
        lines.append(f"--- {d.scenario_id}: {d.scenario_name} ---")
        lines.append(f"  Expected: {d.expected_verdict}")
        lines.append(f"  Actual:   {d.actual_verdict}")
        lines.append(f"  Mode:     {d.failure_mode.name}")
        lines.append(f"  Arch={d.architect_confidence:.2f}  "
                     f"Skep={d.skeptic_confidence:.2f}  "
                     f"Verdict={d.verdict_confidence:.2f}  "
                     f"Coverage={d.fact_coverage:.2f}  "
                     f"Facts={d.total_facts}")
        lines.append(f"  Evidence: {d.evidence_summary}")
        lines.append(f"  Why:      {d.failure_explanation}")
        lines.append(f"  Fix:      {d.recommendation}")

    # Aggregate recommendations by failure mode
    lines.append("")
    lines.append("=" * 78)
    lines.append("Prioritized Recommendations (by failure mode frequency)")
    lines.append("=" * 78)

    by_mode: Dict[str, list[str]] = {}
    for d in report.diagnoses:
        key = d.failure_mode.name
        if key not in by_mode:
            by_mode[key] = []
        by_mode[key].append(f"  - {d.scenario_id}: {d.recommendation}")

    for mode_name, count in sorted(report.failure_mode_distribution.items(),
                                    key=lambda x: -x[1]):
        lines.append(f"\n{mode_name} ({count} scenario{'s' if count > 1 else ''}):")
        for rec in by_mode.get(mode_name, []):
            lines.append(rec)

    lines.append("")
    lines.append("=" * 78)
    return "\n".join(lines)
