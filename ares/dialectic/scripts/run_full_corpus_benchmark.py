"""Session 048 full-corpus injection benchmark runner.

Executes every scenario in ``InjectionCorpusRegistry`` (27 as of this
session: 4 direct + 19 framing + 4 propagation) through the production
firewall-guarded single-turn cycle. Each run emits one
``FramingBenchmarkResult`` regardless of whether the pipeline succeeded
or raised — the closed-world principle: any anomaly becomes a typed
field, never a silent swallow.

Model for live runs is ``claude-sonnet-4-6``; rule-based strategies
are used for dry-runs and mocked tests.

CLI:
    python -m ares.dialectic.scripts.run_full_corpus_benchmark --dry-run
    python -m ares.dialectic.scripts.run_full_corpus_benchmark --limit 3
    python -m ares.dialectic.scripts.run_full_corpus_benchmark \
        --output-dir results/session_048/

Outputs a single file: ``<output-dir>/raw_results.json``.
"""

from __future__ import annotations

import argparse
import json
import logging
import os
import sys
import time
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable, Iterable, Optional, Sequence

from ares.dialectic.agents.strategies.guarded_cycle import (
    GuardedCycleResult,
    run_guarded_cycle,
)
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.scripts.injection_registry import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistry,
    build_registry,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


logger = logging.getLogger("ares.full_corpus_benchmark")


# The model used for every live cycle in this session.
LIVE_MODEL_ID = "claude-sonnet-4-6"

# Where the runner writes its outputs by default.
DEFAULT_OUTPUT_DIR = Path("results/session_048")

# Maps registry uppercase labels to the lowercase schema labels.
_CATEGORY_NORMALIZATION: dict[str, str] = {
    DIRECT: "direct",
    FRAMING: "framing",
    PROPAGATION: "propagation",
}


# =============================================================================
# Frozen wrapper around a full run
# =============================================================================

@dataclass(frozen=True)
class FullCorpusBenchmarkRun:
    """The complete set of results from a full-corpus run.

    Attributes:
        run_id: Short unique identifier.
        timestamp: Wall-clock start of the run (UTC).
        model: Label identifying the reasoning strategy (e.g., the live
            model ID or ``"rule_based"`` for dry-runs).
        total_scenarios: Number of scenarios executed (post-limit).
        results: Per-scenario FramingBenchmarkResult instances in
            execution order.
        total_elapsed_ms: Wall-clock runtime for the whole benchmark.
    """

    run_id: str
    timestamp: datetime
    model: str
    total_scenarios: int
    results: tuple[FramingBenchmarkResult, ...]
    total_elapsed_ms: int


# =============================================================================
# Helpers
# =============================================================================


def _scenario_framing_strategy(
    registry: InjectionCorpusRegistry,
    scenario_id: str,
) -> Optional[str]:
    """Return the framing_strategy for a Category B expansion scenario.

    Returns None for scenarios that do not carry framing metadata (the
    seed injection corpus and any future non-framing additions).
    """
    for record in registry.records:
        if record.scenario.metadata.scenario_id == scenario_id:
            return record.framing_strategy
    return None


def _scenario_category(
    registry: InjectionCorpusRegistry,
    scenario_id: str,
) -> str:
    """Normalize the registry's uppercase category to the schema label."""
    raw = registry.categories.get(scenario_id)
    if raw is None:
        raise KeyError(
            f"Scenario '{scenario_id}' has no category in the registry"
        )
    try:
        return _CATEGORY_NORMALIZATION[raw]
    except KeyError as exc:
        raise KeyError(
            f"Unknown registry category '{raw}' for scenario '{scenario_id}'"
        ) from exc


def _extract_confidence_trajectory(
    guarded: GuardedCycleResult,
) -> tuple[float, ...]:
    """Return (architect, skeptic, final_verdict) confidences from a cycle."""
    verdict = guarded.cycle_result.verdict
    return (
        float(verdict.architect_confidence),
        float(verdict.skeptic_confidence),
        float(verdict.confidence),
    )


def _verdict_label(guarded: GuardedCycleResult) -> str:
    """Extract the verdict outcome label, normalized uppercase."""
    return guarded.cycle_result.verdict.outcome.value.upper()


# =============================================================================
# Per-scenario execution
# =============================================================================


def _execute_scenario(
    scenario: BenchmarkScenario,
    *,
    category: str,
    framing_strategy: Optional[str],
    runner: Callable[[BenchmarkScenario], GuardedCycleResult],
) -> FramingBenchmarkResult:
    """Run one scenario and convert its outcome to a FramingBenchmarkResult.

    Any exception raised by ``runner`` is captured into the
    ``pipeline_error`` field; the function never propagates.

    Args:
        scenario: The BenchmarkScenario (metadata + frozen packet).
        category: Normalized category label.
        framing_strategy: Category B strategy identifier, or None.
        runner: Callable that executes the guarded cycle for this scenario.
            Injected for test seams.

    Returns:
        A FramingBenchmarkResult with the run outcome.
    """
    scenario_id = scenario.metadata.scenario_id
    expected = scenario.metadata.expected_verdict
    start_perf = time.perf_counter()
    pipeline_error: Optional[str] = None
    actual_verdict = ""
    firewall_detected = False
    taint_score = 0.0
    trajectory: tuple[float, ...] = ()

    try:
        guarded = runner(scenario)
        actual_verdict = _verdict_label(guarded)
        firewall_detected = not guarded.firewall_verdict.passed
        taint_score = float(guarded.firewall_verdict.taint_score)
        trajectory = _extract_confidence_trajectory(guarded)
    except Exception as exc:  # closed-world capture
        pipeline_error = f"{type(exc).__name__}: {exc}"
        logger.warning("Scenario %s failed: %s", scenario_id, pipeline_error)

    elapsed_ms = max(0, int((time.perf_counter() - start_perf) * 1000))

    return FramingBenchmarkResult(
        scenario_id=scenario_id,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=expected,
        actual_verdict=actual_verdict,
        firewall_detected=firewall_detected,
        taint_score=taint_score,
        confidence_trajectory=trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=elapsed_ms,
    )


# =============================================================================
# Public API
# =============================================================================


def execute_benchmark(
    registry: InjectionCorpusRegistry,
    runner: Callable[[BenchmarkScenario], GuardedCycleResult],
    *,
    model_label: str,
    limit: Optional[int] = None,
) -> FullCorpusBenchmarkRun:
    """Execute the full-corpus benchmark and return a frozen run record.

    Args:
        registry: Built InjectionCorpusRegistry (use ``build_registry()``).
        runner: Callable that turns one scenario into a GuardedCycleResult.
            This is the seam where production code injects the real
            firewall-guarded pipeline, and where tests inject mocks.
        model_label: Label stored in the run record and JSON output.
        limit: Optional cap on scenario count (applied in registry order).

    Returns:
        A frozen FullCorpusBenchmarkRun aggregating every per-scenario
        FramingBenchmarkResult produced by the runner.
    """
    scenarios: Sequence[BenchmarkScenario] = registry.all_scenarios()
    if limit is not None:
        if limit < 0:
            raise ValueError(f"--limit must be non-negative, got {limit}")
        scenarios = scenarios[:limit]

    run_id = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    run_start = time.perf_counter()
    results: list[FramingBenchmarkResult] = []

    for scenario in scenarios:
        scenario_id = scenario.metadata.scenario_id
        category = _scenario_category(registry, scenario_id)
        framing_strategy = _scenario_framing_strategy(registry, scenario_id)
        results.append(
            _execute_scenario(
                scenario,
                category=category,
                framing_strategy=framing_strategy,
                runner=runner,
            )
        )

    total_ms = max(0, int((time.perf_counter() - run_start) * 1000))

    return FullCorpusBenchmarkRun(
        run_id=run_id,
        timestamp=started,
        model=model_label,
        total_scenarios=len(results),
        results=tuple(results),
        total_elapsed_ms=total_ms,
    )


def serialize_run(run: FullCorpusBenchmarkRun) -> dict[str, Any]:
    """Return a JSON-serializable dict representation of the run."""
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "model": run.model,
        "total_scenarios": run.total_scenarios,
        "total_elapsed_ms": run.total_elapsed_ms,
        "results": [r.to_dict() for r in run.results],
    }


def write_raw_results(
    run: FullCorpusBenchmarkRun,
    output_dir: Path,
) -> Path:
    """Write ``raw_results.json`` into ``output_dir`` and return its path."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "raw_results.json"
    out_path.write_text(
        json.dumps(serialize_run(run), indent=2),
        encoding="utf-8",
    )
    return out_path


def list_scenarios(registry: InjectionCorpusRegistry) -> list[str]:
    """Return scenario IDs in registry iteration order (for --dry-run)."""
    return [s.metadata.scenario_id for s in registry.all_scenarios()]


# =============================================================================
# Strategy construction
# =============================================================================


def _load_api_key() -> Optional[str]:
    """Try environment, then a .env file one level above the repo root."""
    key = os.environ.get("ANTHROPIC_API_KEY")
    if key:
        return key
    env_path = Path(__file__).resolve().parents[3] / ".env"
    if not env_path.exists():
        return None
    raw = env_path.read_bytes()
    for enc in ("utf-8", "utf-16"):
        try:
            text = raw.decode(enc)
        except UnicodeDecodeError:
            continue
        for line in text.splitlines():
            line = line.strip()
            if line.startswith("ANTHROPIC_API_KEY="):
                return line.split("=", 1)[1].strip()
    return None


def _build_live_runner(
    api_key: str,
    firewall: OracleFirewall,
) -> tuple[Callable[[BenchmarkScenario], GuardedCycleResult], str]:
    """Build the live (LLM-backed) scenario runner and its model label."""
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.llm_strategy_v5 import (
        LLMExplanationFinderV5,
        LLMNarrativeGeneratorV5,
        LLMThreatAnalyzerV5,
    )

    client = AnthropicClient(api_key=api_key, model=LIVE_MODEL_ID)
    threat_analyzer = LLMThreatAnalyzerV5(client)
    explanation_finder = LLMExplanationFinderV5(client)
    narrative_generator = LLMNarrativeGeneratorV5(client)

    def _hot_swap_factory() -> "LLMThreatAnalyzerV5":
        return LLMThreatAnalyzerV5(client)

    def _runner(scenario: BenchmarkScenario) -> GuardedCycleResult:
        return run_guarded_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            explanation_finder=explanation_finder,
            narrative_generator=narrative_generator,
            firewall=firewall,
            enable_hot_swap=True,
            hot_swap_factory=_hot_swap_factory,
            include_narration=False,
        )

    return _runner, LIVE_MODEL_ID


def _build_rule_based_runner(
    firewall: OracleFirewall,
) -> tuple[Callable[[BenchmarkScenario], GuardedCycleResult], str]:
    """Build a deterministic rule-based runner (no API calls)."""
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedThreatAnalyzer,
    )

    threat_analyzer = RuleBasedThreatAnalyzer()
    explanation_finder = RuleBasedExplanationFinder()

    def _hot_swap_factory() -> "RuleBasedThreatAnalyzer":
        return RuleBasedThreatAnalyzer()

    def _runner(scenario: BenchmarkScenario) -> GuardedCycleResult:
        return run_guarded_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            explanation_finder=explanation_finder,
            firewall=firewall,
            enable_hot_swap=True,
            hot_swap_factory=_hot_swap_factory,
            include_narration=False,
        )

    return _runner, "rule_based"


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    """Construct the CLI argument parser (exposed for testing)."""
    parser = argparse.ArgumentParser(
        description=(
            "Session 048 full-corpus injection benchmark — runs every "
            "scenario in InjectionCorpusRegistry through the guarded cycle."
        ),
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="List scenario IDs without executing the pipeline.",
    )
    parser.add_argument(
        "--limit",
        type=int,
        default=None,
        help="Cap the number of scenarios (smoke test).",
    )
    parser.add_argument(
        "--output-dir",
        type=Path,
        default=DEFAULT_OUTPUT_DIR,
        help="Destination directory for raw_results.json.",
    )
    parser.add_argument(
        "--rule-based",
        action="store_true",
        help=(
            "Use rule-based strategies instead of the live model. "
            "Intended for local smoke tests without API access."
        ),
    )
    return parser


def _print_dry_run(registry: InjectionCorpusRegistry) -> list[str]:
    ids = list_scenarios(registry)
    print(f"[FULL-CORPUS] Dry-run: {len(ids)} scenarios registered")
    for sid in ids:
        category = _scenario_category(registry, sid)
        strategy = _scenario_framing_strategy(registry, sid) or "-"
        print(f"  {sid}  category={category}  strategy={strategy}")
    return ids


def main(argv: Optional[Iterable[str]] = None) -> int:
    """CLI entry point. Returns 0 on success, non-zero on fatal misconfig."""
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    registry = build_registry()

    if args.dry_run:
        _print_dry_run(registry)
        return 0

    firewall = OracleFirewall()

    if args.rule_based:
        runner, model_label = _build_rule_based_runner(firewall)
    else:
        api_key = _load_api_key()
        if not api_key:
            print(
                "[FULL-CORPUS] ERROR: ANTHROPIC_API_KEY not found. "
                "Use --dry-run or --rule-based for offline execution.",
                file=sys.stderr,
            )
            return 2
        runner, model_label = _build_live_runner(api_key, firewall)

    limit = args.limit
    print(
        f"[FULL-CORPUS] Executing {registry.scenario_count() if limit is None else limit} "
        f"scenarios with model '{model_label}'..."
    )

    run = execute_benchmark(
        registry,
        runner,
        model_label=model_label,
        limit=limit,
    )

    out_path = write_raw_results(run, args.output_dir)
    print(f"[FULL-CORPUS] Wrote {out_path} ({run.total_scenarios} results)")

    error_count = sum(1 for r in run.results if r.pipeline_error is not None)
    if error_count:
        print(f"[FULL-CORPUS] {error_count} scenario(s) raised — see pipeline_error fields")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
