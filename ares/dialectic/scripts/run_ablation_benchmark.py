"""Session 049 ablation + authority-expansion benchmark runner.

Two distinct runs against the v2 registry:

    1. PRIMARY — all 22 framing scenarios through the Skeptic-ablated
       pipeline (:func:`run_ablated_cycle`). Each result carries
       ``pipeline_variant="ablated"``.
    2. SECONDARY — the 3 new authority-family scenarios (INJ-028..030)
       through the full firewall-guarded pipeline (:func:`run_guarded_cycle`).
       Each result carries ``pipeline_variant="full"``.

Results are emitted as :class:`FramingBenchmarkResultV2` records into
``results/session_049/ablated_raw_results.json``.

Model: ``claude-sonnet-4-6`` for live runs; ``--rule-based`` uses the
deterministic strategies for offline smoke tests.

CLI:
    python -m ares.dialectic.scripts.run_ablation_benchmark --dry-run
    python -m ares.dialectic.scripts.run_ablation_benchmark --limit 3
    python -m ares.dialectic.scripts.run_ablation_benchmark \
        --output-dir results/session_049/
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

from ares.dialectic.agents.strategies.ablated_cycle import (
    AblatedCycleResult,
    run_ablated_cycle,
)
from ares.dialectic.agents.strategies.guarded_cycle import (
    GuardedCycleResult,
    run_guarded_cycle,
)
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v2 import (
    FramingBenchmarkResultV2,
)
from ares.dialectic.scripts.injection_registry_v2 import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistryV2,
    build_registry_v2,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


logger = logging.getLogger("ares.ablation_benchmark")


LIVE_MODEL_ID = "claude-sonnet-4-6"
DEFAULT_OUTPUT_DIR = Path("results/session_049")

_CATEGORY_NORMALIZATION: dict[str, str] = {
    DIRECT: "direct",
    FRAMING: "framing",
    PROPAGATION: "propagation",
}


# =============================================================================
# Frozen run record
# =============================================================================


@dataclass(frozen=True)
class AblationBenchmarkRun:
    """A single end-to-end ablation run record.

    Attributes:
        run_id: 12-hex-digit unique identifier.
        timestamp: UTC wall-clock start.
        model: Strategy label (``claude-sonnet-4-6`` for live runs,
            ``rule_based`` for --rule-based).
        ablated_results: Ablated-pipeline results for the 22 framing
            scenarios, in registry order.
        full_results: Full-pipeline results for the 3 authority
            expansion scenarios (INJ-028..030).
        total_elapsed_ms: Wall-clock runtime over the whole benchmark.
    """

    run_id: str
    timestamp: datetime
    model: str
    ablated_results: tuple[FramingBenchmarkResultV2, ...]
    full_results: tuple[FramingBenchmarkResultV2, ...]
    total_elapsed_ms: int

    @property
    def total_scenarios(self) -> int:
        return len(self.ablated_results) + len(self.full_results)


# =============================================================================
# Helpers
# =============================================================================


def _scenario_framing_strategy(
    registry: InjectionCorpusRegistryV2,
    scenario_id: str,
) -> Optional[str]:
    for record in registry.records:
        if record.scenario.metadata.scenario_id == scenario_id:
            return record.framing_strategy
    return None


def _scenario_category(
    registry: InjectionCorpusRegistryV2,
    scenario_id: str,
) -> str:
    raw = registry.categories.get(scenario_id)
    if raw is None:
        raise KeyError(f"Scenario '{scenario_id}' has no category in registry_v2")
    try:
        return _CATEGORY_NORMALIZATION[raw]
    except KeyError as exc:
        raise KeyError(
            f"Unknown registry category '{raw}' for scenario '{scenario_id}'"
        ) from exc


def _extract_ablated_trajectory(
    result: AblatedCycleResult,
) -> tuple[float, ...]:
    verdict = result.cycle_result.verdict
    return (
        float(verdict.architect_confidence),
        float(verdict.skeptic_confidence),
        float(verdict.confidence),
    )


def _extract_full_trajectory(
    result: GuardedCycleResult,
) -> tuple[float, ...]:
    verdict = result.cycle_result.verdict
    return (
        float(verdict.architect_confidence),
        float(verdict.skeptic_confidence),
        float(verdict.confidence),
    )


def _execute_one(
    scenario: BenchmarkScenario,
    *,
    category: str,
    framing_strategy: Optional[str],
    runner: Callable[[BenchmarkScenario], Any],
    variant: str,
    extract_trajectory: Callable[[Any], tuple[float, ...]],
    extract_verdict_label: Callable[[Any], str],
    extract_firewall: Callable[[Any], tuple[bool, float]],
) -> FramingBenchmarkResultV2:
    """Execute one scenario and convert to a v2 result.

    The runner's return type is variant-specific; trajectory/verdict/firewall
    extraction are injected so one body handles both ``AblatedCycleResult``
    and ``GuardedCycleResult``.
    """
    scenario_id = scenario.metadata.scenario_id
    expected = scenario.metadata.expected_verdict
    started = time.perf_counter()

    pipeline_error: Optional[str] = None
    actual_verdict = ""
    firewall_detected = False
    taint_score = 0.0
    trajectory: tuple[float, ...] = ()

    try:
        outcome = runner(scenario)
        actual_verdict = extract_verdict_label(outcome)
        firewall_detected, taint_score = extract_firewall(outcome)
        trajectory = extract_trajectory(outcome)
    except Exception as exc:  # closed-world capture
        pipeline_error = f"{type(exc).__name__}: {exc}"
        logger.warning(
            "Scenario %s failed under variant %s: %s",
            scenario_id, variant, pipeline_error,
        )

    elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))

    inner = FramingBenchmarkResult(
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
    return FramingBenchmarkResultV2(inner=inner, pipeline_variant=variant)


def _ablated_firewall_fields(result: AblatedCycleResult) -> tuple[bool, float]:
    fw = result.firewall_verdict
    return (not fw.passed, float(fw.taint_score))


def _full_firewall_fields(result: GuardedCycleResult) -> tuple[bool, float]:
    fw = result.firewall_verdict
    return (not fw.passed, float(fw.taint_score))


def _ablated_verdict_label(result: AblatedCycleResult) -> str:
    return result.cycle_result.verdict.outcome.value.upper()


def _full_verdict_label(result: GuardedCycleResult) -> str:
    return result.cycle_result.verdict.outcome.value.upper()


# =============================================================================
# Public API
# =============================================================================


def execute_ablation_benchmark(
    registry: InjectionCorpusRegistryV2,
    ablated_runner: Callable[[BenchmarkScenario], AblatedCycleResult],
    full_runner: Callable[[BenchmarkScenario], GuardedCycleResult],
    *,
    model_label: str,
    limit: Optional[int] = None,
) -> AblationBenchmarkRun:
    """Run the two sub-benchmarks and return a frozen record.

    Args:
        registry: v2 registry (must supply all 22 framing + 3 authority
            expansion scenarios).
        ablated_runner: Callable that executes the Skeptic-ablated cycle.
        full_runner: Callable that executes the full guarded cycle.
        model_label: Label stored with every result.
        limit: Optional cap; when set, each sub-benchmark is capped at
            ``limit`` scenarios (applied independently, so ``--limit 2``
            runs the first 2 framing ablated + first 2 authority full).

    Returns:
        AblationBenchmarkRun with both result tuples populated.
    """
    if limit is not None and limit < 0:
        raise ValueError(f"--limit must be non-negative, got {limit}")

    framing_scenarios: Sequence[BenchmarkScenario] = registry.by_category(FRAMING)
    authority_ext_scenarios: Sequence[BenchmarkScenario] = tuple(
        s for s in registry.extension_scenarios
    )

    if limit is not None:
        framing_scenarios = framing_scenarios[:limit]
        authority_ext_scenarios = authority_ext_scenarios[:limit]

    run_id = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    run_start = time.perf_counter()

    ablated_results: list[FramingBenchmarkResultV2] = []
    for scenario in framing_scenarios:
        sid = scenario.metadata.scenario_id
        ablated_results.append(
            _execute_one(
                scenario,
                category=_scenario_category(registry, sid),
                framing_strategy=_scenario_framing_strategy(registry, sid),
                runner=ablated_runner,
                variant="ablated",
                extract_trajectory=_extract_ablated_trajectory,
                extract_verdict_label=_ablated_verdict_label,
                extract_firewall=_ablated_firewall_fields,
            )
        )

    full_results: list[FramingBenchmarkResultV2] = []
    for scenario in authority_ext_scenarios:
        sid = scenario.metadata.scenario_id
        full_results.append(
            _execute_one(
                scenario,
                category=_scenario_category(registry, sid),
                framing_strategy=_scenario_framing_strategy(registry, sid),
                runner=full_runner,
                variant="full",
                extract_trajectory=_extract_full_trajectory,
                extract_verdict_label=_full_verdict_label,
                extract_firewall=_full_firewall_fields,
            )
        )

    total_ms = max(0, int((time.perf_counter() - run_start) * 1000))

    return AblationBenchmarkRun(
        run_id=run_id,
        timestamp=started,
        model=model_label,
        ablated_results=tuple(ablated_results),
        full_results=tuple(full_results),
        total_elapsed_ms=total_ms,
    )


def serialize_run(run: AblationBenchmarkRun) -> dict[str, Any]:
    """JSON-serializable dict mirror of :class:`AblationBenchmarkRun`."""
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "model": run.model,
        "total_scenarios": run.total_scenarios,
        "ablated_count": len(run.ablated_results),
        "full_count": len(run.full_results),
        "total_elapsed_ms": run.total_elapsed_ms,
        "ablated_results": [r.to_dict() for r in run.ablated_results],
        "full_results": [r.to_dict() for r in run.full_results],
    }


def write_raw_results(
    run: AblationBenchmarkRun,
    output_dir: Path,
) -> Path:
    """Write ``ablated_raw_results.json`` into ``output_dir``."""
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "ablated_raw_results.json"
    out_path.write_text(
        json.dumps(serialize_run(run), indent=2),
        encoding="utf-8",
    )
    return out_path


def list_scenarios_for_dry_run(
    registry: InjectionCorpusRegistryV2,
) -> tuple[tuple[str, str, str], tuple[tuple[str, str, str], ...]]:
    """Return (framing triples, authority-expansion triples) for --dry-run.

    Each triple is (scenario_id, framing_strategy or "-", variant).
    """
    framing_list = tuple(
        (
            s.metadata.scenario_id,
            _scenario_framing_strategy(registry, s.metadata.scenario_id) or "-",
            "ablated",
        )
        for s in registry.by_category(FRAMING)
    )
    auth_list = tuple(
        (
            s.metadata.scenario_id,
            _scenario_framing_strategy(registry, s.metadata.scenario_id) or "-",
            "full",
        )
        for s in registry.extension_scenarios
    )
    return framing_list, auth_list  # type: ignore[return-value]


# =============================================================================
# Strategy construction
# =============================================================================


def _load_api_key() -> Optional[str]:
    """Search env + repo-root .env for ANTHROPIC_API_KEY (matches Session 048)."""
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


def _build_live_runners(
    api_key: str,
    firewall: OracleFirewall,
) -> tuple[
    Callable[[BenchmarkScenario], AblatedCycleResult],
    Callable[[BenchmarkScenario], GuardedCycleResult],
    str,
]:
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

    def ablated(scenario: BenchmarkScenario) -> AblatedCycleResult:
        return run_ablated_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            narrative_generator=narrative_generator,
            firewall=firewall,
            include_narration=False,
        )

    def full(scenario: BenchmarkScenario) -> GuardedCycleResult:
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

    return ablated, full, LIVE_MODEL_ID


def _build_rule_based_runners(
    firewall: OracleFirewall,
) -> tuple[
    Callable[[BenchmarkScenario], AblatedCycleResult],
    Callable[[BenchmarkScenario], GuardedCycleResult],
    str,
]:
    from ares.dialectic.agents.strategies.rule_based import (
        RuleBasedExplanationFinder,
        RuleBasedThreatAnalyzer,
    )

    threat_analyzer = RuleBasedThreatAnalyzer()
    explanation_finder = RuleBasedExplanationFinder()

    def _hot_swap_factory() -> "RuleBasedThreatAnalyzer":
        return RuleBasedThreatAnalyzer()

    def ablated(scenario: BenchmarkScenario) -> AblatedCycleResult:
        return run_ablated_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            firewall=firewall,
            include_narration=False,
        )

    def full(scenario: BenchmarkScenario) -> GuardedCycleResult:
        return run_guarded_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            explanation_finder=explanation_finder,
            firewall=firewall,
            enable_hot_swap=True,
            hot_swap_factory=_hot_swap_factory,
            include_narration=False,
        )

    return ablated, full, "rule_based"


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Session 049 ablation + authority-expansion benchmark. "
            "Runs 22 framing scenarios through the Skeptic-ablated cycle "
            "and 3 new authority scenarios through the full guarded cycle."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print scenario routing without invoking the pipeline.",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap each sub-benchmark at N scenarios.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
        help="Destination directory for ablated_raw_results.json.",
    )
    parser.add_argument(
        "--rule-based", action="store_true",
        help="Use deterministic rule-based strategies (no API calls).",
    )
    return parser


def _print_dry_run(registry: InjectionCorpusRegistryV2) -> None:
    framing, authority = list_scenarios_for_dry_run(registry)
    print(
        f"[ABLATION] Dry-run: {len(framing)} framing (ablated) + "
        f"{len(authority)} authority-expansion (full) scenarios"
    )
    print(f"[ABLATION] Ablated pipeline (framing category, n={len(framing)}):")
    for sid, strategy, variant in framing:
        print(f"  {sid}  strategy={strategy}  variant={variant}")
    print(f"[ABLATION] Full pipeline (authority expansion, n={len(authority)}):")
    for sid, strategy, variant in authority:
        print(f"  {sid}  strategy={strategy}  variant={variant}")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    registry = build_registry_v2()

    if args.dry_run:
        _print_dry_run(registry)
        return 0

    firewall = OracleFirewall()

    if args.rule_based:
        ablated_runner, full_runner, model_label = _build_rule_based_runners(firewall)
    else:
        api_key = _load_api_key()
        if not api_key:
            print(
                "[ABLATION] ERROR: ANTHROPIC_API_KEY not found. "
                "Use --dry-run or --rule-based for offline execution.",
                file=sys.stderr,
            )
            return 2
        ablated_runner, full_runner, model_label = _build_live_runners(
            api_key, firewall,
        )

    print(
        f"[ABLATION] Running with model '{model_label}' "
        f"(limit={args.limit if args.limit is not None else 'none'})"
    )

    run = execute_ablation_benchmark(
        registry,
        ablated_runner,
        full_runner,
        model_label=model_label,
        limit=args.limit,
    )

    out_path = write_raw_results(run, args.output_dir)
    print(
        f"[ABLATION] Wrote {out_path} "
        f"(ablated={len(run.ablated_results)}, full={len(run.full_results)})"
    )

    error_count = sum(
        1 for r in (*run.ablated_results, *run.full_results)
        if r.pipeline_error is not None
    )
    if error_count:
        print(f"[ABLATION] {error_count} scenario(s) raised — see pipeline_error fields")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
