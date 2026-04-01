"""OracleJudgeV2 threshold sweep — single run, multi-rescore.

Session 041: Runs all 39 scenarios once through the LLM pipeline,
captures raw confidence pairs, then rescores locally with multiple
OracleJudgeV2 threshold configurations. Zero additional API calls
for the rescore phase.

The sweep identifies the threshold that maximizes combined accuracy
with zero SC regressions.

Public API:
    rescore_results()   — Rescore a BenchmarkRun with a custom judge
    run_sweep()         — Execute full sweep (Phase A + B + C)
    SweepResult         — Frozen result for one threshold
    SweepReport         — Frozen report across all thresholds

CLI:
    python -m ares.dialectic.scripts.sweep_oracle_v2
    python -m ares.dialectic.scripts.sweep_oracle_v2 --dry-run
    python -m ares.dialectic.scripts.sweep_oracle_v2 --thresholds 0.15,0.20,0.25,0.30
    python -m ares.dialectic.scripts.sweep_oracle_v2 --scenarios PT
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ares.dialectic.agents.oracle_v2 import OracleJudgeV2, ScoringConfig
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.scripts.benchmark_runner import BenchmarkRun, ScenarioResult


# =============================================================================
# Result types
# =============================================================================


@dataclass(frozen=True)
class ScenarioComparison:
    """Comparison of V1 vs V2 verdict for a single scenario.

    Attributes:
        scenario_id: Scenario identifier.
        expected_verdict: Ground-truth expected verdict.
        v1_verdict: Verdict from V1 OracleJudge.
        v2_verdict: Verdict from V2 OracleJudgeV2 at this threshold.
        v1_correct: Whether V1 matched expected.
        v2_correct: Whether V2 matched expected.
        is_regression: V1 correct → V2 incorrect.
        is_improvement: V1 incorrect → V2 correct.
        architect_confidence: Raw architect confidence from LLM run.
        skeptic_confidence: Raw skeptic confidence from LLM run.
    """

    scenario_id: str
    expected_verdict: str
    v1_verdict: str
    v2_verdict: str
    v1_correct: bool
    v2_correct: bool
    is_regression: bool
    is_improvement: bool
    architect_confidence: float
    skeptic_confidence: float


@dataclass(frozen=True)
class SweepResult:
    """Result of rescoring all scenarios at one threshold.

    Attributes:
        threshold: The confirm_delta / dismiss_delta value used.
        config: Full ScoringConfig used.
        comparisons: Per-scenario comparisons.
        sc_total: SC scenarios count.
        sc_correct: SC scenarios correct under V2.
        pt_total: PT scenarios count.
        pt_correct: PT scenarios correct under V2.
        combined_correct: Total correct under V2.
        combined_total: Total scenarios.
        regressions: Count of V1-correct → V2-incorrect.
        improvements: Count of V1-incorrect → V2-correct.
    """

    threshold: float
    config: ScoringConfig
    comparisons: tuple[ScenarioComparison, ...]
    sc_total: int
    sc_correct: int
    pt_total: int
    pt_correct: int
    combined_correct: int
    combined_total: int
    regressions: int
    improvements: int


@dataclass(frozen=True)
class SweepReport:
    """Complete sweep report across all thresholds.

    Attributes:
        run_id: ID of the source BenchmarkRun.
        timestamp: When the sweep was executed.
        v1_sc_correct: SC accuracy under V1.
        v1_pt_correct: PT accuracy under V1.
        v1_combined_correct: Combined accuracy under V1.
        total_scenarios: Total scenarios swept.
        results: Per-threshold results.
        winner_threshold: Threshold with best combined accuracy + 0 regressions.
    """

    run_id: str
    timestamp: datetime
    v1_sc_correct: int
    v1_pt_correct: int
    v1_combined_correct: int
    total_scenarios: int
    results: tuple[SweepResult, ...]
    winner_threshold: Optional[float]


# =============================================================================
# Core logic
# =============================================================================


def rescore_results(
    benchmark_run: BenchmarkRun,
    expected_verdicts: dict[str, str],
    config: ScoringConfig,
) -> SweepResult:
    """Rescore a BenchmarkRun with OracleJudgeV2 at a given config.

    No LLM calls — uses the raw confidence pairs from the benchmark run.

    Args:
        benchmark_run: Completed BenchmarkRun with ScenarioResults.
        expected_verdicts: Map of scenario_id → expected verdict string.
        config: ScoringConfig for OracleJudgeV2.

    Returns:
        SweepResult with per-scenario comparisons and aggregate stats.
    """
    comparisons: list[ScenarioComparison] = []

    for result in benchmark_run.results:
        sid = result.scenario_id
        if result.verdict_outcome == "ERROR":
            continue

        expected = expected_verdicts.get(sid, "UNKNOWN")
        v1_verdict = result.verdict_outcome.upper()

        # Rescore with V2
        v2_outcome, _ = OracleJudgeV2._apply_scoring(
            result.architect_confidence,
            result.skeptic_confidence,
            config,
        )
        v2_verdict = v2_outcome.value.upper()

        v1_correct = _verdicts_match(v1_verdict, expected)
        v2_correct = _verdicts_match(v2_verdict, expected)

        comparisons.append(ScenarioComparison(
            scenario_id=sid,
            expected_verdict=expected,
            v1_verdict=v1_verdict,
            v2_verdict=v2_verdict,
            v1_correct=v1_correct,
            v2_correct=v2_correct,
            is_regression=v1_correct and not v2_correct,
            is_improvement=not v1_correct and v2_correct,
            architect_confidence=result.architect_confidence,
            skeptic_confidence=result.skeptic_confidence,
        ))

    sc_comps = [c for c in comparisons if c.scenario_id.startswith("SC")]
    pt_comps = [c for c in comparisons if c.scenario_id.startswith("PT")]

    return SweepResult(
        threshold=config.confirm_delta,
        config=config,
        comparisons=tuple(comparisons),
        sc_total=len(sc_comps),
        sc_correct=sum(1 for c in sc_comps if c.v2_correct),
        pt_total=len(pt_comps),
        pt_correct=sum(1 for c in pt_comps if c.v2_correct),
        combined_correct=sum(1 for c in comparisons if c.v2_correct),
        combined_total=len(comparisons),
        regressions=sum(1 for c in comparisons if c.is_regression),
        improvements=sum(1 for c in comparisons if c.is_improvement),
    )


def run_sweep(
    benchmark_run: BenchmarkRun,
    expected_verdicts: dict[str, str],
    thresholds: Sequence[float] = (0.15, 0.20, 0.25, 0.30),
) -> SweepReport:
    """Run the full threshold sweep (Phase B + C).

    Args:
        benchmark_run: Completed BenchmarkRun from Phase A.
        expected_verdicts: Map of scenario_id → expected verdict string.
        thresholds: Delta thresholds to sweep.

    Returns:
        SweepReport with results for each threshold and a winner.
    """
    # V1 baseline accuracy
    v1_sc = 0
    v1_pt = 0
    total = 0
    for result in benchmark_run.results:
        if result.verdict_outcome == "ERROR":
            continue
        total += 1
        sid = result.scenario_id
        expected = expected_verdicts.get(sid, "UNKNOWN")
        correct = _verdicts_match(result.verdict_outcome.upper(), expected)
        if sid.startswith("SC") and correct:
            v1_sc += 1
        elif sid.startswith("PT") and correct:
            v1_pt += 1

    # Sweep thresholds
    sweep_results: list[SweepResult] = []
    for delta in thresholds:
        config = ScoringConfig(
            confirm_delta=delta,
            dismiss_delta=delta,
        )
        sweep_results.append(
            rescore_results(benchmark_run, expected_verdicts, config)
        )

    # Find winner: best combined accuracy with 0 SC regressions
    sc_results_v1 = {}
    for result in benchmark_run.results:
        if result.verdict_outcome == "ERROR":
            continue
        sid = result.scenario_id
        if sid.startswith("SC"):
            expected = expected_verdicts.get(sid, "UNKNOWN")
            sc_results_v1[sid] = _verdicts_match(result.verdict_outcome.upper(), expected)

    winner = None
    best_combined = -1
    for sr in sweep_results:
        # Check for SC regressions specifically
        sc_regressions = sum(
            1 for c in sr.comparisons
            if c.scenario_id.startswith("SC") and c.is_regression
        )
        if sc_regressions == 0 and sr.combined_correct > best_combined:
            best_combined = sr.combined_correct
            winner = sr.threshold

    return SweepReport(
        run_id=benchmark_run.run_id,
        timestamp=datetime.now(timezone.utc),
        v1_sc_correct=v1_sc,
        v1_pt_correct=v1_pt,
        v1_combined_correct=v1_sc + v1_pt,
        total_scenarios=total,
        results=tuple(sweep_results),
        winner_threshold=winner,
    )


def _verdicts_match(actual: str, expected: str) -> bool:
    """Case-insensitive verdict comparison."""
    return actual.strip().upper() == expected.strip().upper()


# =============================================================================
# Reporting
# =============================================================================


def print_report(report: SweepReport) -> None:
    """Print the sweep results table to stdout."""
    sc_total = 0
    pt_total = 0
    if report.results:
        sc_total = report.results[0].sc_total
        pt_total = report.results[0].pt_total

    print()
    print("THRESHOLD SWEEP RESULTS")
    print("=" * 75)
    sc_hdr = f"SC ({sc_total})"
    pt_hdr = f"PT ({pt_total})"
    print(f"{'Threshold':<12}{sc_hdr:<12}{pt_hdr:<12}"
          f"{'Combined':<16}{'Regressions':<14}{'Improvements'}")
    print("-" * 75)

    # V1 baseline row
    v1_combined = report.v1_combined_correct
    v1_total = report.total_scenarios
    v1_pct = v1_combined / v1_total * 100 if v1_total else 0
    v1_sc = f"{report.v1_sc_correct}/{sc_total}"
    v1_pt = f"{report.v1_pt_correct}/{pt_total}"
    v1_comb = f"{v1_combined}/{v1_total} ({v1_pct:.1f}%)"
    print(f"{'V1 (base)':<12}{v1_sc:<12}{v1_pt:<12}{v1_comb:<16}{'--':<14}--")

    # V2 rows
    for sr in report.results:
        pct = sr.combined_correct / sr.combined_total * 100 if sr.combined_total else 0
        marker = " <-- WINNER" if sr.threshold == report.winner_threshold else ""
        sc_col = f"{sr.sc_correct}/{sr.sc_total}"
        pt_col = f"{sr.pt_correct}/{sr.pt_total}"
        comb_col = f"{sr.combined_correct}/{sr.combined_total} ({pct:.1f}%)"
        print(f"{sr.threshold:<12.2f}{sc_col:<12}{pt_col:<12}"
              f"{comb_col:<16}{sr.regressions:<14}{sr.improvements}{marker}")

    print("=" * 75)

    if report.winner_threshold is not None:
        winner_sr = next(sr for sr in report.results if sr.threshold == report.winner_threshold)
        pct = winner_sr.combined_correct / winner_sr.combined_total * 100
        print(f"WINNER: {report.winner_threshold:.2f} "
              f"({pct:.1f}% combined, {winner_sr.regressions} regressions, "
              f"+{winner_sr.improvements} improvements)")
    else:
        print("NO WINNER: All thresholds caused SC regressions")

    # Detail: regressions and improvements per threshold
    for sr in report.results:
        regressions = [c for c in sr.comparisons if c.is_regression]
        improvements = [c for c in sr.comparisons if c.is_improvement]
        if regressions or improvements:
            print(f"\n  Threshold {sr.threshold:.2f}:")
            for c in regressions:
                print(f"    REGRESSION {c.scenario_id}: "
                      f"V1={c.v1_verdict} (correct) -> V2={c.v2_verdict} (wrong) "
                      f"[arch={c.architect_confidence:.2f}, skep={c.skeptic_confidence:.2f}]")
            for c in improvements:
                print(f"    IMPROVEMENT {c.scenario_id}: "
                      f"V1={c.v1_verdict} (wrong) -> V2={c.v2_verdict} (correct) "
                      f"[arch={c.architect_confidence:.2f}, skep={c.skeptic_confidence:.2f}]")

    print()


def save_report(report: SweepReport, output_dir: Path) -> Path:
    """Save sweep results to JSON.

    Args:
        report: SweepReport to serialize.
        output_dir: Directory to write to.

    Returns:
        Path to the written JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "sweep_results.json"

    data = {
        "run_id": report.run_id,
        "timestamp": report.timestamp.isoformat(),
        "v1_baseline": {
            "sc_correct": report.v1_sc_correct,
            "pt_correct": report.v1_pt_correct,
            "combined_correct": report.v1_combined_correct,
            "total": report.total_scenarios,
        },
        "thresholds": [],
        "winner_threshold": report.winner_threshold,
    }

    for sr in report.results:
        threshold_data = {
            "threshold": sr.threshold,
            "sc_correct": sr.sc_correct,
            "sc_total": sr.sc_total,
            "pt_correct": sr.pt_correct,
            "pt_total": sr.pt_total,
            "combined_correct": sr.combined_correct,
            "combined_total": sr.combined_total,
            "regressions": sr.regressions,
            "improvements": sr.improvements,
            "regression_details": [
                {
                    "scenario_id": c.scenario_id,
                    "expected": c.expected_verdict,
                    "v1": c.v1_verdict,
                    "v2": c.v2_verdict,
                    "arch": c.architect_confidence,
                    "skep": c.skeptic_confidence,
                }
                for c in sr.comparisons if c.is_regression
            ],
            "improvement_details": [
                {
                    "scenario_id": c.scenario_id,
                    "expected": c.expected_verdict,
                    "v1": c.v1_verdict,
                    "v2": c.v2_verdict,
                    "arch": c.architect_confidence,
                    "skep": c.skeptic_confidence,
                }
                for c in sr.comparisons if c.is_improvement
            ],
        }
        data["thresholds"].append(threshold_data)

    out_path.write_text(json.dumps(data, indent=2))
    return out_path


# =============================================================================
# CLI
# =============================================================================


def main(argv: list[str] | None = None) -> None:
    """CLI entry point for the OracleJudgeV2 threshold sweep."""
    import argparse

    parser = argparse.ArgumentParser(
        description="OracleJudgeV2 threshold sweep — single run, multi-rescore",
    )
    parser.add_argument(
        "--thresholds", type=str, default="0.15,0.20,0.25,0.30",
        help="Comma-separated delta thresholds to sweep (default: 0.15,0.20,0.25,0.30)",
    )
    parser.add_argument(
        "--output", type=str, default="benchmark_results/v2_sweep",
        help="Output directory for results JSON",
    )
    parser.add_argument(
        "--scenarios", type=str, default="all",
        choices=["all", "SC", "PT"],
        help="Which corpus to use: all (39), SC (33), PT (6)",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Use rule-based strategies instead of LLM (no API key needed)",
    )
    parser.add_argument(
        "--include-narration", action="store_true", default=False,
        help="Include OracleNarrator output (slower, costs more)",
    )
    args = parser.parse_args(argv)

    thresholds = [float(t.strip()) for t in args.thresholds.split(",")]

    # --- Load corpus ---
    print("[SWEEP] Loading corpus...")
    if args.scenarios == "SC":
        from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
        corpus = list(get_full_corpus_v2())
    elif args.scenarios == "PT":
        from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_scenarios
        corpus = list(get_pentagi_scenarios())
    else:
        from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_corpus
        corpus = list(get_pentagi_corpus())

    expected_verdicts = {
        s.metadata.scenario_id: s.metadata.expected_verdict
        for s in corpus
    }

    print(f"[SWEEP] Corpus: {len(corpus)} scenarios ({args.scenarios})")
    print(f"[SWEEP] Thresholds: {thresholds}")
    print(f"[SWEEP] Dry-run: {args.dry_run}")

    # --- Phase A: Single run ---
    from ares.dialectic.scripts.benchmark_runner_v2 import run_benchmark_custom

    if args.dry_run:
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedExplanationFinder,
            RuleBasedNarrativeGenerator,
            RuleBasedThreatAnalyzer,
        )
        threat_analyzer = RuleBasedThreatAnalyzer()
        explanation_finder = RuleBasedExplanationFinder()
        narrative_generator = RuleBasedNarrativeGenerator()
        strategy_label = "rule_based"
        print("[SWEEP] Using rule-based strategies (dry-run)")
    else:
        import os
        from pathlib import Path as P

        api_key = os.environ.get("ANTHROPIC_API_KEY")
        if not api_key:
            env_path = P(__file__).resolve().parent.parent.parent.parent / ".env"
            if env_path.exists():
                raw = env_path.read_bytes()
                for enc in ("utf-8", "utf-16"):
                    try:
                        text = raw.decode(enc)
                        for line in text.splitlines():
                            line = line.strip()
                            if line.startswith("ANTHROPIC_API_KEY="):
                                api_key = line.split("=", 1)[1].strip()
                                break
                        if api_key:
                            break
                    except (UnicodeDecodeError, ValueError):
                        continue

        if not api_key:
            print("[SWEEP] ERROR: ANTHROPIC_API_KEY not found. Use --dry-run for testing.")
            return

        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.llm_strategy_v4 import (
            LLMThreatAnalyzerV4,
            LLMExplanationFinderV4,
            LLMNarrativeGeneratorV4,
        )

        client = AnthropicClient(api_key=api_key)
        threat_analyzer = LLMThreatAnalyzerV4(client)
        explanation_finder = LLMExplanationFinderV4(client)
        narrative_generator = LLMNarrativeGeneratorV4(client)
        strategy_label = "llm_v4"
        print("[SWEEP] Using LLM V4 strategies (live)")

    print(f"\n[SWEEP] Phase A: Running {len(corpus)} scenarios...")
    phase_a_start = time.perf_counter()

    benchmark_run = run_benchmark_custom(
        scenarios=corpus,
        threat_analyzer=threat_analyzer,
        explanation_finder=explanation_finder,
        narrative_generator=narrative_generator,
        include_narration=args.include_narration,
        strategy_label=strategy_label,
    )

    phase_a_time = time.perf_counter() - phase_a_start
    print(f"[SWEEP] Phase A complete: {phase_a_time:.1f}s, "
          f"cost=${benchmark_run.total_cost_usd or 0:.2f}")

    # --- Phase B: Local rescore ---
    print(f"\n[SWEEP] Phase B: Rescoring with {len(thresholds)} thresholds (0 API calls)...")
    report = run_sweep(benchmark_run, expected_verdicts, thresholds)

    # --- Phase C: Report ---
    print_report(report)

    # Save results
    output_path = save_report(report, Path(args.output))
    print(f"[SWEEP] Results saved to {output_path}")


if __name__ == "__main__":
    main()
