"""Corpus replay — stress-test the visual pipeline against all scenarios.

Session 030: Replays every scenario in the 33-scenario corpus through
ScenarioReplayer, validates each event sequence via diagnostics, and
produces an aggregate pass/fail report with anomaly details.

Public API:
    replay_scenario()    — Replay one scenario and validate
    replay_corpus()      — Replay all 33 and aggregate
    format_report()      — ASCII report for the corpus replay
    ReplayResult         — Per-scenario result
    CorpusReplayReport   — Aggregate report
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Sequence, Tuple

from ares.visual.diagnostics import (
    AnomalySeverity,
    DiagnosticResult,
    validate_sequence,
)
from ares.visual.replayer import ScenarioReplayer


# ---------------------------------------------------------------------------
# Result dataclasses
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class ReplayResult:
    """Result of replaying a single scenario through the visual pipeline.

    Attributes:
        scenario_id: Scenario identifier (e.g. 'SC-001').
        scenario_name: Human-readable scenario name.
        event_count: Total events produced by the replayer.
        fact_events: Number of fact_ingested events.
        assertion_events: Number of assertion_formed events.
        diagnostic: Full DiagnosticResult from validate_sequence().
    """

    scenario_id: str
    scenario_name: str
    event_count: int
    fact_events: int
    assertion_events: int
    diagnostic: DiagnosticResult

    @property
    def passed(self) -> bool:
        """True if the event sequence has zero CRITICAL anomalies."""
        return self.diagnostic.is_valid


@dataclass(frozen=True)
class CorpusReplayReport:
    """Aggregate report from replaying all scenarios.

    Attributes:
        total_scenarios: Number of scenarios replayed.
        passed: Count of scenarios with zero CRITICAL anomalies.
        failed: Count of scenarios with at least one CRITICAL anomaly.
        warning_scenarios: Count that passed but had WARNING anomalies.
        results: Tuple of per-scenario ReplayResult instances.
    """

    total_scenarios: int
    passed: int
    failed: int
    warning_scenarios: int
    results: Tuple[ReplayResult, ...]

    @property
    def all_passed(self) -> bool:
        """True if every scenario passed (zero failures)."""
        return self.failed == 0

    @property
    def failed_scenarios(self) -> Tuple[ReplayResult, ...]:
        """Results for scenarios that failed validation."""
        return tuple(r for r in self.results if not r.passed)

    @property
    def warning_list(self) -> Tuple[ReplayResult, ...]:
        """Results for scenarios that passed but had warnings."""
        return tuple(
            r for r in self.results
            if r.passed and r.diagnostic.warning_count > 0
        )

    @property
    def total_events(self) -> int:
        """Sum of event counts across all scenarios."""
        return sum(r.event_count for r in self.results)


# ---------------------------------------------------------------------------
# Replay functions
# ---------------------------------------------------------------------------

def replay_scenario(scenario, replayer: ScenarioReplayer | None = None) -> ReplayResult:
    """Replay a single BenchmarkScenario and validate the event sequence.

    No network, no WebSocket, no LLM. Pure data transformation + validation.

    Args:
        scenario: A BenchmarkScenario with .metadata and .packet.
        replayer: Optional pre-configured ScenarioReplayer.

    Returns:
        ReplayResult with diagnostic information.
    """
    if replayer is None:
        replayer = ScenarioReplayer()

    events = replayer.replay(scenario)
    diagnostic = validate_sequence(
        events,
        scenario.packet,
        scenario_id=scenario.metadata.scenario_id,
    )

    return ReplayResult(
        scenario_id=scenario.metadata.scenario_id,
        scenario_name=scenario.metadata.name,
        event_count=len(events),
        fact_events=diagnostic.fact_events,
        assertion_events=diagnostic.assertion_events,
        diagnostic=diagnostic,
    )


def replay_corpus(scenarios: Sequence | None = None) -> CorpusReplayReport:
    """Replay ALL scenarios from the corpus and produce an aggregate report.

    Args:
        scenarios: Optional sequence of BenchmarkScenario instances.
                   If None, loads the full corpus via get_full_corpus().

    Returns:
        CorpusReplayReport with per-scenario results and summary counts.
    """
    if scenarios is None:
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        scenarios = list(get_full_corpus())

    replayer = ScenarioReplayer()
    results: list[ReplayResult] = []

    for scenario in scenarios:
        result = replay_scenario(scenario, replayer=replayer)
        results.append(result)

    results_tuple = tuple(results)
    passed = sum(1 for r in results_tuple if r.passed)
    failed = len(results_tuple) - passed
    warning_scenarios = sum(
        1 for r in results_tuple
        if r.passed and r.diagnostic.warning_count > 0
    )

    return CorpusReplayReport(
        total_scenarios=len(results_tuple),
        passed=passed,
        failed=failed,
        warning_scenarios=warning_scenarios,
        results=results_tuple,
    )


# ---------------------------------------------------------------------------
# Report formatting
# ---------------------------------------------------------------------------

def format_report(report: CorpusReplayReport) -> str:
    """Format a CorpusReplayReport as readable ASCII text.

    Sections:
        1. Header with timestamp and summary
        2. Per-scenario table
        3. Failed scenario details (CRITICAL anomalies)
        4. Warning scenario details
        5. Summary metrics

    Args:
        report: The corpus replay report to format.

    Returns:
        Multi-line string suitable for printing or saving.
    """
    lines: list[str] = []

    # --- Header ---
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    lines.append("=" * 78)
    lines.append("ARES Visual Pipeline — Corpus Replay Report")
    lines.append(f"Generated: {now}")
    lines.append(f"Scenarios: {report.total_scenarios}  |  "
                 f"Passed: {report.passed}  |  "
                 f"Failed: {report.failed}  |  "
                 f"Warnings: {report.warning_scenarios}")
    lines.append("=" * 78)
    lines.append("")

    # --- Per-scenario table ---
    lines.append(f"{'ID':<8} {'Name':<32} {'Events':>6} {'Facts':>6} "
                 f"{'Assert':>6} {'Status':<10}")
    lines.append("-" * 78)
    for r in report.results:
        status = "PASS" if r.passed else "FAIL"
        if r.passed and r.diagnostic.warning_count > 0:
            status = f"WARN({r.diagnostic.warning_count})"
        name = r.scenario_name[:31]
        lines.append(
            f"{r.scenario_id:<8} {name:<32} {r.event_count:>6} "
            f"{r.fact_events:>6} {r.assertion_events:>6} {status:<10}"
        )
    lines.append("")

    # --- Failed scenario details ---
    if report.failed > 0:
        lines.append("-" * 78)
        lines.append(f"FAILURES ({report.failed})")
        lines.append("-" * 78)
        for r in report.failed_scenarios:
            lines.append(f"\n  {r.scenario_id}: {r.scenario_name}")
            for a in r.diagnostic.anomalies:
                if a.severity == AnomalySeverity.CRITICAL:
                    idx = f"[idx={a.event_index}]" if a.event_index is not None else ""
                    lines.append(f"    CRITICAL: {a.anomaly_type.name} {idx}")
                    lines.append(f"              {a.description}")
        lines.append("")

    # --- Warning details ---
    if report.warning_scenarios > 0:
        lines.append("-" * 78)
        lines.append(f"WARNINGS ({report.warning_scenarios} scenarios)")
        lines.append("-" * 78)
        for r in report.warning_list:
            lines.append(f"\n  {r.scenario_id}: {r.scenario_name}")
            for a in r.diagnostic.anomalies:
                if a.severity == AnomalySeverity.WARNING:
                    idx = f"[idx={a.event_index}]" if a.event_index is not None else ""
                    lines.append(f"    WARNING:  {a.anomaly_type.name} {idx}")
                    lines.append(f"              {a.description}")
        lines.append("")

    # --- Summary metrics ---
    lines.append("=" * 78)
    lines.append("Summary Metrics")
    lines.append("-" * 78)
    total_events = report.total_events
    avg_events = total_events / report.total_scenarios if report.total_scenarios else 0
    total_facts = sum(r.fact_events for r in report.results)
    total_assertions = sum(r.assertion_events for r in report.results)
    lines.append(f"  Total events across corpus:  {total_events}")
    lines.append(f"  Average events per scenario: {avg_events:.1f}")
    lines.append(f"  Total fact events:           {total_facts}")
    lines.append(f"  Total assertion events:      {total_assertions}")
    lines.append(f"  Verdict: {'ALL PASSED' if report.all_passed else 'FAILURES DETECTED'}")
    lines.append("=" * 78)

    return "\n".join(lines)
