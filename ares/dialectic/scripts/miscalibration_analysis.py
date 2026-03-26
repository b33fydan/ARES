"""Combined gate analysis — EscalationGate + MiscalibrationDetector evaluation.

Session 023: Evaluates combined error capture rate across the full corpus
by running both the EscalationGate (Session 022) and MiscalibrationDetector
(Session 023) on benchmark results.

This script provides offline analysis functions — no LLM calls required.
It consumes pre-computed benchmark results and produces diagnostic reports.

Public API:
    CombinedGateResult     — frozen dataclass with per-scenario gate decisions
    CombinedGateAnalysis   — frozen dataclass with aggregate statistics
    run_combined_gate_analysis  — analyze benchmark results with both gates
    format_combined_report      — produce formatted text report
    get_miscalibration_patterns_summary — aggregate pattern frequencies
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Tuple

from ares.dialectic.coordinator.escalation import (
    EscalationDecision,
    EscalationGate,
    EscalationResult,
)
from ares.dialectic.coordinator.miscalibration import (
    MiscalibrationDetector,
    MiscalibrationPattern,
    MiscalibrationRecommendation,
    MiscalibrationResult,
)
from ares.dialectic.agents.patterns import Verdict
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.messages.protocol import DialecticalMessage


@dataclass(frozen=True)
class CombinedGateResult:
    """Per-scenario result from combined gate evaluation.

    Attributes:
        scenario_name: Name of the benchmark scenario.
        is_error: Whether this scenario had an incorrect verdict.
        escalation_result: Result from EscalationGate.
        miscalibration_result: Result from MiscalibrationDetector.
        caught_by_escalation: True if EscalationGate escalated this error.
        caught_by_miscalibration: True if MiscalibrationDetector flagged this error.
    """

    scenario_name: str
    is_error: bool
    escalation_result: EscalationResult
    miscalibration_result: MiscalibrationResult
    caught_by_escalation: bool
    caught_by_miscalibration: bool


@dataclass(frozen=True)
class CombinedGateAnalysis:
    """Aggregate statistics from combined gate evaluation.

    Attributes:
        total_scenarios: Total number of scenarios analyzed.
        total_errors: Number of incorrect verdicts.
        caught_by_escalation_only: Errors caught only by EscalationGate.
        caught_by_miscalibration_only: Errors caught only by MiscalibrationDetector.
        caught_by_both: Errors caught by both gates.
        caught_by_neither: Errors caught by neither gate.
        combined_capture_rate: Proportion of errors caught by at least one gate.
        escalation_capture_rate: Proportion of errors caught by EscalationGate.
        miscalibration_capture_rate: Proportion of errors caught by MiscalibrationDetector.
        per_scenario_results: Per-scenario details.
    """

    total_scenarios: int
    total_errors: int
    caught_by_escalation_only: int
    caught_by_miscalibration_only: int
    caught_by_both: int
    caught_by_neither: int
    combined_capture_rate: float
    escalation_capture_rate: float
    miscalibration_capture_rate: float
    per_scenario_results: Tuple[CombinedGateResult, ...]


@dataclass(frozen=True)
class ScenarioInput:
    """Input data for a single benchmark scenario.

    Attributes:
        scenario_name: Name of the scenario.
        verdict: The Oracle's verdict.
        architect_message: The Architect's message.
        skeptic_message: The Skeptic's message.
        packet: The EvidencePacket.
        is_error: Whether the verdict was incorrect.
    """

    scenario_name: str
    verdict: Verdict
    architect_message: DialecticalMessage
    skeptic_message: DialecticalMessage
    packet: EvidencePacket
    is_error: bool


def run_combined_gate_analysis(
    scenarios: List[ScenarioInput],
    escalation_gate: EscalationGate | None = None,
    miscalibration_detector: MiscalibrationDetector | None = None,
) -> CombinedGateAnalysis:
    """Analyze benchmark results with both EscalationGate and MiscalibrationDetector.

    Args:
        scenarios: List of benchmark scenario inputs.
        escalation_gate: Optional custom gate (defaults to standard thresholds).
        miscalibration_detector: Optional custom detector (defaults to standard).

    Returns:
        CombinedGateAnalysis with aggregate statistics.
    """
    gate = escalation_gate or EscalationGate()
    detector = miscalibration_detector or MiscalibrationDetector()

    per_scenario: list[CombinedGateResult] = []
    esc_only = 0
    misc_only = 0
    both = 0
    neither = 0
    total_errors = 0

    for scenario in scenarios:
        esc_result = gate.evaluate(scenario.verdict)
        misc_result = detector.detect(
            scenario.verdict,
            scenario.architect_message,
            scenario.skeptic_message,
            scenario.packet,
        )

        caught_esc = (
            scenario.is_error
            and esc_result.decision == EscalationDecision.ESCALATED
        )
        caught_misc = (
            scenario.is_error
            and misc_result.recommendation == MiscalibrationRecommendation.INSPECT
        )

        if scenario.is_error:
            total_errors += 1
            if caught_esc and caught_misc:
                both += 1
            elif caught_esc:
                esc_only += 1
            elif caught_misc:
                misc_only += 1
            else:
                neither += 1

        per_scenario.append(
            CombinedGateResult(
                scenario_name=scenario.scenario_name,
                is_error=scenario.is_error,
                escalation_result=esc_result,
                miscalibration_result=misc_result,
                caught_by_escalation=caught_esc,
                caught_by_miscalibration=caught_misc,
            )
        )

    total_caught = esc_only + misc_only + both
    combined_rate = total_caught / total_errors if total_errors > 0 else 0.0
    esc_rate = (esc_only + both) / total_errors if total_errors > 0 else 0.0
    misc_rate = (misc_only + both) / total_errors if total_errors > 0 else 0.0

    return CombinedGateAnalysis(
        total_scenarios=len(scenarios),
        total_errors=total_errors,
        caught_by_escalation_only=esc_only,
        caught_by_miscalibration_only=misc_only,
        caught_by_both=both,
        caught_by_neither=neither,
        combined_capture_rate=combined_rate,
        escalation_capture_rate=esc_rate,
        miscalibration_capture_rate=misc_rate,
        per_scenario_results=tuple(per_scenario),
    )


def format_combined_report(analysis: CombinedGateAnalysis) -> str:
    """Produce a formatted text report from combined gate analysis.

    Args:
        analysis: The CombinedGateAnalysis to format.

    Returns:
        Multi-line string report.
    """
    lines: list[str] = []
    lines.append("=" * 60)
    lines.append("COMBINED GATE ANALYSIS REPORT")
    lines.append("=" * 60)
    lines.append("")
    lines.append(f"Total scenarios:  {analysis.total_scenarios}")
    lines.append(f"Total errors:     {analysis.total_errors}")
    lines.append("")
    lines.append("--- Error Capture Breakdown ---")
    lines.append(f"  Escalation only:      {analysis.caught_by_escalation_only}")
    lines.append(f"  Miscalibration only:  {analysis.caught_by_miscalibration_only}")
    lines.append(f"  Both:                 {analysis.caught_by_both}")
    lines.append(f"  Neither:              {analysis.caught_by_neither}")
    lines.append("")
    lines.append("--- Capture Rates ---")
    lines.append(f"  Escalation gate:      {analysis.escalation_capture_rate:.1%}")
    lines.append(f"  Miscalibration:       {analysis.miscalibration_capture_rate:.1%}")
    lines.append(f"  Combined:             {analysis.combined_capture_rate:.1%}")
    lines.append("")
    lines.append("--- Per-Scenario Details ---")

    for r in analysis.per_scenario_results:
        error_tag = " [ERROR]" if r.is_error else ""
        esc_tag = "ESCALATED" if r.escalation_result.decision == EscalationDecision.ESCALATED else "RESOLVED"
        misc_tag = "INSPECT" if r.miscalibration_result.recommendation == MiscalibrationRecommendation.INSPECT else "PASS"
        lines.append(f"  {r.scenario_name}{error_tag}: esc={esc_tag}, misc={misc_tag}")

    lines.append("")
    lines.append("=" * 60)
    return "\n".join(lines)


def get_miscalibration_patterns_summary(
    scenarios: List[ScenarioInput],
    detector: MiscalibrationDetector | None = None,
) -> Dict[MiscalibrationPattern, int]:
    """Aggregate which miscalibration patterns trigger most frequently.

    Args:
        scenarios: List of benchmark scenario inputs.
        detector: Optional custom detector (defaults to standard).

    Returns:
        Dictionary mapping each pattern to its trigger count.
    """
    det = detector or MiscalibrationDetector()
    counts: Dict[MiscalibrationPattern, int] = {
        p: 0 for p in MiscalibrationPattern
    }

    for scenario in scenarios:
        result = det.detect(
            scenario.verdict,
            scenario.architect_message,
            scenario.skeptic_message,
            scenario.packet,
        )
        for pattern in result.patterns_triggered:
            counts[pattern] += 1

    return counts
