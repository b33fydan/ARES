"""Session 050 three-way benchmark runner.

Runs every scenario in the v3 registry's framing category (25 of them)
through *three* pipeline variants:

    * full    — Session 048 guarded cycle (Architect + firewall +
                Skeptic LLM + Oracle). Reused from Session 048 output
                when a matching scenario_id is found; executed live
                otherwise (e.g. INJ-031..033).
    * ablated — Session 049 ablated cycle (Architect + firewall + null
                Skeptic + Oracle). Reused from Session 049 output when
                present; executed live otherwise.
    * light   — Session 050 light-guarded cycle (Architect + firewall +
                deterministic Light Skeptic + Oracle). Always executed
                live — this is the first time it runs.

Output: ``results/session_050/light_raw_results.json`` — a V2 result
array containing one entry per light-cycle run, plus a parallel
``full_from_reuse``/``ablated_from_reuse`` manifest.

Model: ``claude-sonnet-4-6`` for live runs; ``--rule-based`` uses the
deterministic Architect for offline smoke tests.

CLI:
    python -m ares.dialectic.scripts.run_three_way_benchmark --dry-run
    python -m ares.dialectic.scripts.run_three_way_benchmark --limit 3
    python -m ares.dialectic.scripts.run_three_way_benchmark \
        --no-reuse --output-dir results/session_050/
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
from ares.dialectic.agents.strategies.light_guarded_cycle import (
    LightGuardedCycleResult,
    run_light_guarded_cycle,
)
from ares.dialectic.coordinator.firewall import OracleFirewall
from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v3 import (
    FramingBenchmarkResultV3,
)
from ares.dialectic.scripts.injection_registry_v3 import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistryV3,
    build_registry_v3,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


logger = logging.getLogger("ares.three_way_benchmark")


LIVE_MODEL_ID = "claude-sonnet-4-6"
DEFAULT_OUTPUT_DIR = Path("results/session_050")
SESSION_048_INPUT = Path("results/session_048/raw_results.json")
SESSION_049_INPUT = Path("results/session_049/ablated_raw_results.json")

_CATEGORY_NORMALIZATION: dict[str, str] = {
    DIRECT: "direct",
    FRAMING: "framing",
    PROPAGATION: "propagation",
}


# =============================================================================
# Frozen run record
# =============================================================================


@dataclass(frozen=True)
class ThreeWayBenchmarkRun:
    """A single three-way benchmark execution record.

    Attributes:
        run_id: 12-hex-digit unique identifier.
        timestamp: UTC wall-clock start.
        model: Strategy label (``claude-sonnet-4-6`` or ``rule_based``).
        light_results: FramingBenchmarkResultV3 with ``pipeline_variant="light"``
            for every framing scenario executed in this session.
        full_live_results: Live-executed full-pipeline results for any
            scenario not present in the Session 048 input (e.g. temporal
            expansion additions). Empty when --no-reuse is used and
            everything was re-run.
        ablated_live_results: Same but for the ablated pipeline.
        full_reused_ids: Scenario IDs whose full-pipeline result was
            loaded from ``results/session_048/raw_results.json``.
        ablated_reused_ids: Scenario IDs whose ablated-pipeline result
            was loaded from ``results/session_049/ablated_raw_results.json``.
        total_elapsed_ms: Wall-clock runtime over the whole benchmark.
    """

    run_id: str
    timestamp: datetime
    model: str
    light_results: tuple[FramingBenchmarkResultV3, ...]
    full_live_results: tuple[FramingBenchmarkResultV3, ...]
    ablated_live_results: tuple[FramingBenchmarkResultV3, ...]
    full_reused_ids: tuple[str, ...]
    ablated_reused_ids: tuple[str, ...]
    total_elapsed_ms: int


# =============================================================================
# Helpers
# =============================================================================


def _scenario_framing_strategy(
    registry: InjectionCorpusRegistryV3,
    scenario_id: str,
) -> Optional[str]:
    for record in registry.records:
        if record.scenario.metadata.scenario_id == scenario_id:
            return record.framing_strategy
    return None


def _scenario_category(
    registry: InjectionCorpusRegistryV3,
    scenario_id: str,
) -> str:
    raw = registry.categories.get(scenario_id)
    if raw is None:
        raise KeyError(f"Scenario '{scenario_id}' has no category in registry_v3")
    return _CATEGORY_NORMALIZATION[raw]


def _load_previous_results(path: Path, key: str) -> dict[str, dict[str, Any]]:
    """Load a prior-session results JSON and index by scenario_id."""
    if not path.exists():
        return {}
    payload = json.loads(path.read_text(encoding="utf-8"))
    rows = payload.get(key, []) or []
    return {r["scenario_id"]: r for r in rows}


def _extract_trajectory(verdict) -> tuple[float, ...]:
    return (
        float(verdict.architect_confidence),
        float(verdict.skeptic_confidence),
        float(verdict.confidence),
    )


def _make_result(
    *,
    scenario_id: str,
    category: str,
    framing_strategy: Optional[str],
    expected_verdict: str,
    actual_verdict: str,
    firewall_detected: bool,
    taint_score: float,
    confidence_trajectory: tuple[float, ...],
    pipeline_error: Optional[str],
    elapsed_ms: int,
    pipeline_variant: str,
) -> FramingBenchmarkResultV3:
    inner = FramingBenchmarkResult(
        scenario_id=scenario_id,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=expected_verdict,
        actual_verdict=actual_verdict,
        firewall_detected=firewall_detected,
        taint_score=taint_score,
        confidence_trajectory=confidence_trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=elapsed_ms,
    )
    return FramingBenchmarkResultV3(inner=inner, pipeline_variant=pipeline_variant)


def _execute_light(
    scenario: BenchmarkScenario,
    *,
    category: str,
    framing_strategy: Optional[str],
    runner: Callable[[BenchmarkScenario], LightGuardedCycleResult],
) -> FramingBenchmarkResultV3:
    sid = scenario.metadata.scenario_id
    started = time.perf_counter()
    pipeline_error: Optional[str] = None
    actual_verdict = ""
    firewall_detected = False
    taint_score = 0.0
    trajectory: tuple[float, ...] = ()

    try:
        result = runner(scenario)
        actual_verdict = result.cycle_result.verdict.outcome.value.upper()
        firewall_detected = not result.firewall_verdict.passed
        taint_score = float(result.firewall_verdict.taint_score)
        trajectory = _extract_trajectory(result.cycle_result.verdict)
    except Exception as exc:
        pipeline_error = f"{type(exc).__name__}: {exc}"
        logger.warning("Light scenario %s failed: %s", sid, pipeline_error)

    elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))

    return _make_result(
        scenario_id=sid,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=scenario.metadata.expected_verdict,
        actual_verdict=actual_verdict,
        firewall_detected=firewall_detected,
        taint_score=taint_score,
        confidence_trajectory=trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=elapsed_ms,
        pipeline_variant="light",
    )


def _execute_full(
    scenario: BenchmarkScenario,
    *,
    category: str,
    framing_strategy: Optional[str],
    runner: Callable[[BenchmarkScenario], GuardedCycleResult],
) -> FramingBenchmarkResultV3:
    sid = scenario.metadata.scenario_id
    started = time.perf_counter()
    pipeline_error: Optional[str] = None
    actual_verdict = ""
    firewall_detected = False
    taint_score = 0.0
    trajectory: tuple[float, ...] = ()

    try:
        result = runner(scenario)
        actual_verdict = result.cycle_result.verdict.outcome.value.upper()
        firewall_detected = not result.firewall_verdict.passed
        taint_score = float(result.firewall_verdict.taint_score)
        trajectory = _extract_trajectory(result.cycle_result.verdict)
    except Exception as exc:
        pipeline_error = f"{type(exc).__name__}: {exc}"
        logger.warning("Full scenario %s failed: %s", sid, pipeline_error)

    elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))

    return _make_result(
        scenario_id=sid,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=scenario.metadata.expected_verdict,
        actual_verdict=actual_verdict,
        firewall_detected=firewall_detected,
        taint_score=taint_score,
        confidence_trajectory=trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=elapsed_ms,
        pipeline_variant="full",
    )


def _execute_ablated(
    scenario: BenchmarkScenario,
    *,
    category: str,
    framing_strategy: Optional[str],
    runner: Callable[[BenchmarkScenario], AblatedCycleResult],
) -> FramingBenchmarkResultV3:
    sid = scenario.metadata.scenario_id
    started = time.perf_counter()
    pipeline_error: Optional[str] = None
    actual_verdict = ""
    firewall_detected = False
    taint_score = 0.0
    trajectory: tuple[float, ...] = ()

    try:
        result = runner(scenario)
        actual_verdict = result.cycle_result.verdict.outcome.value.upper()
        firewall_detected = not result.firewall_verdict.passed
        taint_score = float(result.firewall_verdict.taint_score)
        trajectory = _extract_trajectory(result.cycle_result.verdict)
    except Exception as exc:
        pipeline_error = f"{type(exc).__name__}: {exc}"
        logger.warning("Ablated scenario %s failed: %s", sid, pipeline_error)

    elapsed_ms = max(0, int((time.perf_counter() - started) * 1000))

    return _make_result(
        scenario_id=sid,
        category=category,
        framing_strategy=framing_strategy,
        expected_verdict=scenario.metadata.expected_verdict,
        actual_verdict=actual_verdict,
        firewall_detected=firewall_detected,
        taint_score=taint_score,
        confidence_trajectory=trajectory,
        pipeline_error=pipeline_error,
        elapsed_ms=elapsed_ms,
        pipeline_variant="ablated",
    )


# =============================================================================
# Public API
# =============================================================================


def execute_three_way_benchmark(
    registry: InjectionCorpusRegistryV3,
    light_runner: Callable[[BenchmarkScenario], LightGuardedCycleResult],
    full_runner: Callable[[BenchmarkScenario], GuardedCycleResult],
    ablated_runner: Callable[[BenchmarkScenario], AblatedCycleResult],
    *,
    model_label: str,
    limit: Optional[int] = None,
    reuse_full: bool = True,
    reuse_ablated: bool = True,
    session_048_path: Path = SESSION_048_INPUT,
    session_049_path: Path = SESSION_049_INPUT,
) -> ThreeWayBenchmarkRun:
    """Execute the three-way benchmark over every framing scenario.

    Args:
        registry: v3 registry.
        light_runner: Callable that runs the Light-Skeptic cycle.
        full_runner: Callable that runs the full guarded cycle.
        ablated_runner: Callable that runs the ablated cycle.
        model_label: Label stored with every result.
        limit: Optional cap on framing scenarios (first N).
        reuse_full: If True, reuse Session 048 results when they match
            by scenario_id; else run full_runner for every scenario.
        reuse_ablated: Same, for Session 049.
        session_048_path: Path to Session 048 raw_results.json.
        session_049_path: Path to Session 049 ablated_raw_results.json.

    Returns:
        A frozen :class:`ThreeWayBenchmarkRun`.
    """
    if limit is not None and limit < 0:
        raise ValueError(f"--limit must be non-negative, got {limit}")

    framing_scenarios: Sequence[BenchmarkScenario] = registry.by_category(FRAMING)
    if limit is not None:
        framing_scenarios = framing_scenarios[:limit]

    # Index prior-session results by scenario_id for reuse.
    prev_full = (
        _load_previous_results(session_048_path, "results") if reuse_full else {}
    )
    prev_ablated = (
        _load_previous_results(session_049_path, "ablated_results")
        if reuse_ablated else {}
    )

    run_id = uuid.uuid4().hex[:12]
    started = datetime.now(timezone.utc)
    run_start = time.perf_counter()

    light_results: list[FramingBenchmarkResultV3] = []
    full_live: list[FramingBenchmarkResultV3] = []
    ablated_live: list[FramingBenchmarkResultV3] = []
    full_reused: list[str] = []
    ablated_reused: list[str] = []

    for scenario in framing_scenarios:
        sid = scenario.metadata.scenario_id
        category = _scenario_category(registry, sid)
        strategy = _scenario_framing_strategy(registry, sid)

        # Light always runs — this is its premiere.
        light_results.append(
            _execute_light(
                scenario,
                category=category, framing_strategy=strategy,
                runner=light_runner,
            )
        )

        # Full: reuse if possible.
        if reuse_full and sid in prev_full:
            full_reused.append(sid)
        else:
            full_live.append(
                _execute_full(
                    scenario,
                    category=category, framing_strategy=strategy,
                    runner=full_runner,
                )
            )

        # Ablated: reuse if possible.
        if reuse_ablated and sid in prev_ablated:
            ablated_reused.append(sid)
        else:
            ablated_live.append(
                _execute_ablated(
                    scenario,
                    category=category, framing_strategy=strategy,
                    runner=ablated_runner,
                )
            )

    total_ms = max(0, int((time.perf_counter() - run_start) * 1000))

    return ThreeWayBenchmarkRun(
        run_id=run_id,
        timestamp=started,
        model=model_label,
        light_results=tuple(light_results),
        full_live_results=tuple(full_live),
        ablated_live_results=tuple(ablated_live),
        full_reused_ids=tuple(full_reused),
        ablated_reused_ids=tuple(ablated_reused),
        total_elapsed_ms=total_ms,
    )


def serialize_run(run: ThreeWayBenchmarkRun) -> dict[str, Any]:
    return {
        "run_id": run.run_id,
        "timestamp": run.timestamp.isoformat(),
        "model": run.model,
        "total_elapsed_ms": run.total_elapsed_ms,
        "light_count": len(run.light_results),
        "full_live_count": len(run.full_live_results),
        "ablated_live_count": len(run.ablated_live_results),
        "full_reused_ids": list(run.full_reused_ids),
        "ablated_reused_ids": list(run.ablated_reused_ids),
        "light_results": [r.to_dict() for r in run.light_results],
        "full_live_results": [r.to_dict() for r in run.full_live_results],
        "ablated_live_results": [r.to_dict() for r in run.ablated_live_results],
    }


def write_raw_results(
    run: ThreeWayBenchmarkRun,
    output_dir: Path,
) -> Path:
    output_dir.mkdir(parents=True, exist_ok=True)
    out_path = output_dir / "light_raw_results.json"
    out_path.write_text(
        json.dumps(serialize_run(run), indent=2),
        encoding="utf-8",
    )
    return out_path


def list_framing_scenarios(
    registry: InjectionCorpusRegistryV3,
) -> list[tuple[str, str]]:
    return [
        (
            s.metadata.scenario_id,
            _scenario_framing_strategy(registry, s.metadata.scenario_id) or "-",
        )
        for s in registry.by_category(FRAMING)
    ]


# =============================================================================
# Strategy construction
# =============================================================================


def _load_api_key() -> Optional[str]:
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
    Callable[[BenchmarkScenario], LightGuardedCycleResult],
    Callable[[BenchmarkScenario], GuardedCycleResult],
    Callable[[BenchmarkScenario], AblatedCycleResult],
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

    def light(scenario: BenchmarkScenario) -> LightGuardedCycleResult:
        return run_light_guarded_cycle(
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

    def ablated(scenario: BenchmarkScenario) -> AblatedCycleResult:
        return run_ablated_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            narrative_generator=narrative_generator,
            firewall=firewall,
            include_narration=False,
        )

    return light, full, ablated, LIVE_MODEL_ID


def _build_rule_based_runners(
    firewall: OracleFirewall,
) -> tuple[
    Callable[[BenchmarkScenario], LightGuardedCycleResult],
    Callable[[BenchmarkScenario], GuardedCycleResult],
    Callable[[BenchmarkScenario], AblatedCycleResult],
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

    def light(scenario: BenchmarkScenario) -> LightGuardedCycleResult:
        return run_light_guarded_cycle(
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

    def ablated(scenario: BenchmarkScenario) -> AblatedCycleResult:
        return run_ablated_cycle(
            packet=scenario.packet,
            threat_analyzer=threat_analyzer,
            firewall=firewall,
            include_narration=False,
        )

    return light, full, ablated, "rule_based"


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Session 050 three-way benchmark — runs every framing scenario "
            "through full (Session 048), ablated (Session 049), and light "
            "(Session 050) pipelines."
        ),
    )
    parser.add_argument(
        "--dry-run", action="store_true",
        help="Print scenario routing without invoking any pipeline.",
    )
    parser.add_argument(
        "--limit", type=int, default=None,
        help="Cap the number of framing scenarios executed.",
    )
    parser.add_argument(
        "--output-dir", type=Path, default=DEFAULT_OUTPUT_DIR,
        help="Destination directory for light_raw_results.json.",
    )
    parser.add_argument(
        "--rule-based", action="store_true",
        help="Use rule-based strategies (no API calls).",
    )
    parser.add_argument(
        "--no-reuse", action="store_true",
        help=(
            "Do not reuse Session 048/049 results — re-execute "
            "everything live."
        ),
    )
    parser.add_argument(
        "--session-048", type=Path, default=SESSION_048_INPUT,
        help="Path to Session 048 raw_results.json for reuse.",
    )
    parser.add_argument(
        "--session-049", type=Path, default=SESSION_049_INPUT,
        help="Path to Session 049 ablated_raw_results.json for reuse.",
    )
    return parser


def _print_dry_run(
    registry: InjectionCorpusRegistryV3,
    prev_full: dict[str, dict[str, Any]],
    prev_ablated: dict[str, dict[str, Any]],
) -> None:
    rows = list_framing_scenarios(registry)
    print(f"[THREE-WAY] Dry-run: {len(rows)} framing scenarios (v3 registry)")
    for sid, strategy in rows:
        full_tag = "reuse-048" if sid in prev_full else "live-full"
        abl_tag = "reuse-049" if sid in prev_ablated else "live-ablated"
        print(f"  {sid}  strategy={strategy}  full={full_tag}  ablated={abl_tag}  light=live")


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    registry = build_registry_v3()

    reuse_full = not args.no_reuse
    reuse_ablated = not args.no_reuse

    prev_full = (
        _load_previous_results(args.session_048, "results")
        if reuse_full else {}
    )
    prev_ablated = (
        _load_previous_results(args.session_049, "ablated_results")
        if reuse_ablated else {}
    )

    if args.dry_run:
        _print_dry_run(registry, prev_full, prev_ablated)
        return 0

    firewall = OracleFirewall()

    if args.rule_based:
        light_runner, full_runner, ablated_runner, model_label = (
            _build_rule_based_runners(firewall)
        )
    else:
        api_key = _load_api_key()
        if not api_key:
            print(
                "[THREE-WAY] ERROR: ANTHROPIC_API_KEY not found. "
                "Use --dry-run or --rule-based for offline execution.",
                file=sys.stderr,
            )
            return 2
        light_runner, full_runner, ablated_runner, model_label = (
            _build_live_runners(api_key, firewall)
        )

    total_scenarios = registry.by_category(FRAMING)
    live_full_count = sum(1 for s in total_scenarios
                          if s.metadata.scenario_id not in prev_full)
    live_abl_count = sum(1 for s in total_scenarios
                         if s.metadata.scenario_id not in prev_ablated)
    if args.limit is not None:
        live_full_count = min(live_full_count, args.limit)
        live_abl_count = min(live_abl_count, args.limit)

    print(
        f"[THREE-WAY] Running model '{model_label}' "
        f"(limit={args.limit if args.limit is not None else 'none'}, "
        f"live_full={live_full_count}, live_ablated={live_abl_count}, "
        f"reuse={not args.no_reuse})"
    )

    run = execute_three_way_benchmark(
        registry,
        light_runner,
        full_runner,
        ablated_runner,
        model_label=model_label,
        limit=args.limit,
        reuse_full=reuse_full,
        reuse_ablated=reuse_ablated,
        session_048_path=args.session_048,
        session_049_path=args.session_049,
    )

    out_path = write_raw_results(run, args.output_dir)
    print(
        f"[THREE-WAY] Wrote {out_path} "
        f"(light={len(run.light_results)}, "
        f"full_live={len(run.full_live_results)}, "
        f"ablated_live={len(run.ablated_live_results)}, "
        f"full_reused={len(run.full_reused_ids)}, "
        f"ablated_reused={len(run.ablated_reused_ids)})"
    )

    all_results = (
        list(run.light_results)
        + list(run.full_live_results)
        + list(run.ablated_live_results)
    )
    error_count = sum(1 for r in all_results if r.pipeline_error is not None)
    if error_count:
        print(f"[THREE-WAY] {error_count} scenario(s) raised — see pipeline_error fields")

    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
