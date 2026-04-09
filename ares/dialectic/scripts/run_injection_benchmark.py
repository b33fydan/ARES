"""Injection benchmark runner — measures firewall detection effectiveness.

Session 046: Runs the 12-scenario injection corpus through the guarded
pipeline and produces per-scenario and per-category detection metrics.

CLI:
    python -m ares.dialectic.scripts.run_injection_benchmark --dry-run
    python -m ares.dialectic.scripts.run_injection_benchmark
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Sequence

from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.coordinator.firewall import FirewallVerdict, OracleFirewall
from ares.dialectic.scripts.injection_corpus import get_injection_scenarios

logger = logging.getLogger("ares.injection_benchmark")


# =============================================================================
# Category mapping
# =============================================================================

INJECTION_CATEGORIES = {
    "INJ-001": "DIRECT",
    "INJ-002": "DIRECT",
    "INJ-003": "DIRECT",
    "INJ-004": "DIRECT",
    "INJ-005": "FRAMING",
    "INJ-006": "FRAMING",
    "INJ-007": "FRAMING",
    "INJ-008": "FRAMING",
    "INJ-009": "PROPAGATION",
    "INJ-010": "PROPAGATION",
    "INJ-011": "PROPAGATION",
    "INJ-012": "PROPAGATION",
}


# =============================================================================
# Result types
# =============================================================================

@dataclass(frozen=True)
class InjectionResult:
    """Result of running a single injection scenario."""

    scenario_id: str
    injection_category: str  # "DIRECT", "FRAMING", "PROPAGATION"
    injection_detected: bool  # did the firewall detect the injection?
    hot_swap_triggered: bool
    verdict_correct: bool
    taint_score: float
    violations_found: int
    violation_types: tuple[str, ...]
    verdict_outcome: str
    expected_verdict: str
    architect_confidence: float
    skeptic_confidence: float
    duration_ms: int


@dataclass(frozen=True)
class InjectionBenchmarkRun:
    """Complete injection benchmark run."""

    run_id: str
    timestamp: datetime
    strategy_label: str
    results: tuple[InjectionResult, ...]
    detection_rate: float  # % of all scenarios where injection detected
    category_detection: dict  # {category: detection_rate}
    verdict_accuracy: float  # % correct verdicts
    false_positive_count: int  # false positives on clean scenarios
    hot_swap_count: int
    total_duration_ms: int


# =============================================================================
# Internal helpers
# =============================================================================

def _verdicts_match(actual: str, expected: str) -> bool:
    """Case-insensitive verdict comparison."""
    return actual.strip().upper() == expected.strip().upper()


def _compute_category_detection(
    results: Sequence[InjectionResult],
) -> dict[str, float]:
    """Compute detection rate per injection category.

    Args:
        results: Sequence of InjectionResult from injection scenarios only.

    Returns:
        Dict mapping category name to detection rate (0.0-1.0).
    """
    from collections import defaultdict

    category_total: dict[str, int] = defaultdict(int)
    category_detected: dict[str, int] = defaultdict(int)

    for r in results:
        cat = r.injection_category
        category_total[cat] += 1
        if r.injection_detected:
            category_detected[cat] += 1

    return {
        cat: category_detected[cat] / category_total[cat]
        for cat in sorted(category_total)
    }


# =============================================================================
# Public API
# =============================================================================

def run_injection_benchmark(
    threat_analyzer,
    explanation_finder,
    firewall: OracleFirewall,
    *,
    include_clean_check: bool = True,
    strategy_label: str = "custom",
) -> InjectionBenchmarkRun:
    """Run the 12 injection scenarios through the pipeline and firewall.

    For each injection scenario:
        1. Run through run_cycle_with_strategies (unguarded cycle).
        2. Validate the Architect's output through the firewall.
        3. Record detection, taint score, violation types.
        4. Record whether the final verdict was correct.

    If include_clean_check, also runs 3 clean SC scenarios (SC-001, SC-005,
    SC-008) through the firewall to verify zero false positives.

    Args:
        threat_analyzer: ThreatAnalyzer strategy instance.
        explanation_finder: ExplanationFinder strategy instance.
        firewall: OracleFirewall instance for validation.
        include_clean_check: Run clean scenarios to check false positives.
        strategy_label: Label for the run (e.g., "rule_based", "llm_v5").

    Returns:
        InjectionBenchmarkRun with per-scenario results and aggregate metrics.
    """
    run_id = uuid.uuid4().hex[:12]
    run_timestamp = datetime.now(timezone.utc)
    run_start = time.perf_counter()

    injection_scenarios = get_injection_scenarios()
    injection_results: list[InjectionResult] = []

    # --- Run injection scenarios ---
    for scenario in injection_scenarios:
        sid = scenario.metadata.scenario_id
        category = INJECTION_CATEGORIES[sid]
        expected_verdict = scenario.metadata.expected_verdict

        scenario_start = time.perf_counter()
        try:
            cycle_result = run_cycle_with_strategies(
                packet=scenario.packet,
                threat_analyzer=threat_analyzer,
                explanation_finder=explanation_finder,
                include_narration=False,
            )

            # Validate through firewall
            fw_verdict: FirewallVerdict = firewall.validate(
                cycle_result.architect_message, scenario.packet,
            )

            # Determine if injection was detected
            injection_detected = not fw_verdict.passed
            taint_score = fw_verdict.taint_score
            violations_found = len(fw_verdict.violations)
            violation_types = tuple(sorted({
                v.violation_type for v in fw_verdict.violations
            }))

            # Check verdict correctness
            verdict_outcome = cycle_result.verdict.outcome.value.upper()
            verdict_correct = _verdicts_match(verdict_outcome, expected_verdict)

            arch_confidence = cycle_result.verdict.architect_confidence
            skep_confidence = cycle_result.verdict.skeptic_confidence

            # Hot-swap: firewall failed + we would need to replace output
            hot_swap_triggered = not fw_verdict.passed

        except Exception as exc:
            logger.warning("Scenario %s failed: %s", sid, exc)
            injection_detected = False
            taint_score = 0.0
            violations_found = 0
            violation_types = ()
            verdict_outcome = "ERROR"
            verdict_correct = False
            arch_confidence = 0.0
            skep_confidence = 0.0
            hot_swap_triggered = False

        scenario_ms = int((time.perf_counter() - scenario_start) * 1000)

        injection_results.append(InjectionResult(
            scenario_id=sid,
            injection_category=category,
            injection_detected=injection_detected,
            hot_swap_triggered=hot_swap_triggered,
            verdict_correct=verdict_correct,
            taint_score=taint_score,
            violations_found=violations_found,
            violation_types=violation_types,
            verdict_outcome=verdict_outcome,
            expected_verdict=expected_verdict,
            architect_confidence=arch_confidence,
            skeptic_confidence=skep_confidence,
            duration_ms=scenario_ms,
        ))

    # --- Clean scenario check for false positives ---
    false_positive_count = 0
    if include_clean_check:
        from ares.dialectic.scripts.scenario_corpus import get_scenario_by_id

        clean_ids = ["SC-001", "SC-005", "SC-008"]
        for clean_id in clean_ids:
            try:
                clean_scenario = get_scenario_by_id(clean_id)
                clean_cycle = run_cycle_with_strategies(
                    packet=clean_scenario.packet,
                    threat_analyzer=threat_analyzer,
                    explanation_finder=explanation_finder,
                    include_narration=False,
                )
                clean_fw = firewall.validate(
                    clean_cycle.architect_message, clean_scenario.packet,
                )
                if not clean_fw.passed:
                    false_positive_count += 1
                    logger.warning(
                        "False positive on clean scenario %s (taint=%.2f)",
                        clean_id,
                        clean_fw.taint_score,
                    )
            except Exception as exc:
                logger.warning("Clean check %s failed: %s", clean_id, exc)

    # --- Aggregate metrics ---
    total_injection = len(injection_results)
    detected_count = sum(1 for r in injection_results if r.injection_detected)
    correct_count = sum(1 for r in injection_results if r.verdict_correct)
    hot_swap_count = sum(1 for r in injection_results if r.hot_swap_triggered)

    detection_rate = detected_count / total_injection if total_injection > 0 else 0.0
    verdict_accuracy = correct_count / total_injection if total_injection > 0 else 0.0
    category_detection = _compute_category_detection(injection_results)

    total_ms = int((time.perf_counter() - run_start) * 1000)

    return InjectionBenchmarkRun(
        run_id=run_id,
        timestamp=run_timestamp,
        strategy_label=strategy_label,
        results=tuple(injection_results),
        detection_rate=detection_rate,
        category_detection=category_detection,
        verdict_accuracy=verdict_accuracy,
        false_positive_count=false_positive_count,
        hot_swap_count=hot_swap_count,
        total_duration_ms=total_ms,
    )


# =============================================================================
# Reporting
# =============================================================================

def print_injection_report(run: InjectionBenchmarkRun) -> None:
    """Print the injection benchmark report to stdout.

    Args:
        run: Completed InjectionBenchmarkRun.
    """
    total = len(run.results)
    detected = sum(1 for r in run.results if r.injection_detected)
    correct = sum(1 for r in run.results if r.verdict_correct)

    print()
    print("INJECTION RESILIENCE BENCHMARK")
    print("\u2550" * 75)
    print(f"{'Scenario':<13}{'Category':<14}{'Detected':<10}{'Taint':<8}"
          f"{'Violations':<12}{'Verdict':<16}{'Correct'}")
    print("\u2500" * 75)

    for r in run.results:
        det_str = "YES" if r.injection_detected else "NO"
        cor_str = "OK" if r.verdict_correct else "MISS"
        viol_str = str(r.violations_found)
        print(f"{r.scenario_id:<13}{r.injection_category:<14}{det_str:<10}"
              f"{r.taint_score:<8.2f}{viol_str:<12}{r.verdict_outcome:<16}{cor_str}")

    print("\u2550" * 75)

    # Category summary
    print()
    print("CATEGORY SUMMARY:")
    for cat in ("DIRECT", "FRAMING", "PROPAGATION"):
        cat_results = [r for r in run.results if r.injection_category == cat]
        cat_detected = sum(1 for r in cat_results if r.injection_detected)
        cat_total = len(cat_results)
        pct = cat_detected / cat_total * 100 if cat_total > 0 else 0.0
        print(f"  {cat + ':':<16}{cat_detected}/{cat_total} detected ({pct:.0f}%)")

    # Overall
    det_pct = detected / total * 100 if total > 0 else 0.0
    acc_pct = correct / total * 100 if total > 0 else 0.0
    print()
    print("OVERALL:")
    print(f"  Detection rate: {detected}/{total} ({det_pct:.1f}%)")
    print(f"  Verdict accuracy: {correct}/{total} ({acc_pct:.1f}%)")
    print(f"  False positives: {run.false_positive_count}")
    print(f"  Hot-swaps: {run.hot_swap_count}")
    print()


# =============================================================================
# JSON persistence
# =============================================================================

def save_injection_report(
    run: InjectionBenchmarkRun,
    output_dir: Path,
) -> Path:
    """Save injection benchmark results to JSON.

    Args:
        run: Completed InjectionBenchmarkRun.
        output_dir: Directory to write to.

    Returns:
        Path to the written JSON file.
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "results.json"

    data = {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "strategy_label": run.strategy_label,
        "detection_rate": run.detection_rate,
        "verdict_accuracy": run.verdict_accuracy,
        "false_positive_count": run.false_positive_count,
        "hot_swap_count": run.hot_swap_count,
        "total_duration_ms": run.total_duration_ms,
        "category_detection": run.category_detection,
        "results": [
            {
                "scenario_id": r.scenario_id,
                "injection_category": r.injection_category,
                "injection_detected": r.injection_detected,
                "hot_swap_triggered": r.hot_swap_triggered,
                "verdict_correct": r.verdict_correct,
                "taint_score": r.taint_score,
                "violations_found": r.violations_found,
                "violation_types": list(r.violation_types),
                "verdict_outcome": r.verdict_outcome,
                "expected_verdict": r.expected_verdict,
                "architect_confidence": r.architect_confidence,
                "skeptic_confidence": r.skeptic_confidence,
                "duration_ms": r.duration_ms,
            }
            for r in run.results
        ],
    }

    out_path.write_text(json.dumps(data, indent=2))
    return out_path


# =============================================================================
# CLI
# =============================================================================

def main(argv=None):
    """CLI entry point for the injection benchmark."""
    import argparse

    parser = argparse.ArgumentParser(
        description="Injection benchmark — measure firewall detection effectiveness",
    )
    parser.add_argument(
        "--output", type=str, default="benchmark_results/injection",
        help="Output directory for results JSON",
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Use rule-based strategies instead of LLM (no API key needed)",
    )
    parser.add_argument(
        "--no-clean-check", action="store_true",
        help="Skip clean scenario false-positive check",
    )
    args = parser.parse_args(argv)

    # --- Build strategies ---
    if args.dry_run:
        from ares.dialectic.agents.strategies.rule_based import (
            RuleBasedExplanationFinder,
            RuleBasedThreatAnalyzer,
        )
        threat_analyzer = RuleBasedThreatAnalyzer()
        explanation_finder = RuleBasedExplanationFinder()
        strategy_label = "rule_based"
        print("[INJECTION] Using rule-based strategies (dry-run)")
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
            print("[INJECTION] ERROR: ANTHROPIC_API_KEY not found. Use --dry-run for testing.")
            return

        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.llm_strategy_v5 import (
            LLMThreatAnalyzerV5,
            LLMExplanationFinderV5,
        )

        client = AnthropicClient(api_key=api_key)
        threat_analyzer = LLMThreatAnalyzerV5(client)
        explanation_finder = LLMExplanationFinderV5(client)
        strategy_label = "llm_v5"
        print("[INJECTION] Using LLM V5 strategies (live)")

    # --- Create firewall ---
    firewall = OracleFirewall()

    # --- Run benchmark ---
    include_clean = not args.no_clean_check
    print(f"[INJECTION] Running 12 injection scenarios (clean check: {include_clean})...")

    run = run_injection_benchmark(
        threat_analyzer=threat_analyzer,
        explanation_finder=explanation_finder,
        firewall=firewall,
        include_clean_check=include_clean,
        strategy_label=strategy_label,
    )

    # --- Report ---
    print_injection_report(run)

    # --- Save ---
    output_path = save_injection_report(run, Path(args.output))
    print(f"[INJECTION] Results saved to {output_path}")


if __name__ == "__main__":
    main()
