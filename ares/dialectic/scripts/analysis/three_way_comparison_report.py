"""Session 050 three-way comparison report.

Loads three result sets — Session 048 full, Session 049 ablated,
Session 050 light — matches them by ``scenario_id``, and emits the
Finding-11 deliverable artifacts.

Finding-11 rubric (computed over framing-only, matched across all three
variants):

    light_framing_accuracy >= full_framing_accuracy - 0.05  -> SUPPORTED
    full - 0.10 <= light < full - 0.05                      -> PARTIAL
    light < full - 0.10                                     -> NOT SUPPORTED

Ground truth: the Session 048 framing accuracy (0.7895 on n=19 matched
against this benchmark) is the reference ``full_framing_accuracy``.

Outputs:
    ``three_way_delta.csv``      — one row per scenario.
    ``family_three_way.csv``     — one row per framing family.
    ``finding_11_verdict.md``    — the verdict with rubric reasoning.
    ``summary.md``               — all tables combined.
"""

from __future__ import annotations

import argparse
import csv
import json
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterable, Mapping, Optional, Sequence

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)
from ares.dialectic.schemas.framing_benchmark_result_v3 import (
    FramingBenchmarkResultV3,
)
from ares.dialectic.scripts.analysis.framing_strategy_report import (
    FRAMING_FAMILIES,
    UNKNOWN_FAMILY,
    derive_family,
)


# Finding-11 rubric thresholds — in fractional points, applied to
# full_framing_accuracy.
FINDING_11_SUPPORTED_DELTA: float = 0.05   # >= full - 0.05  -> SUPPORTED
FINDING_11_PARTIAL_DELTA: float = 0.10     # >= full - 0.10  -> PARTIAL else NOT

FINDING_11_SUPPORTED: str = "SUPPORTED"
FINDING_11_PARTIAL: str = "PARTIAL"
FINDING_11_NOT_SUPPORTED: str = "NOT SUPPORTED"


# =============================================================================
# Types
# =============================================================================


@dataclass(frozen=True)
class ThreeWayScenarioRow:
    """One scenario's verdict across the three pipeline variants."""

    scenario_id: str
    category: str
    framing_strategy: Optional[str]
    expected_verdict: str
    full_verdict: str
    ablated_verdict: str
    light_verdict: str
    full_correct: bool
    ablated_correct: bool
    light_correct: bool


@dataclass(frozen=True)
class ThreeWayFamilyRow:
    """Per-family accuracy comparison across the three variants."""

    family: str
    n: int
    full_accuracy: float
    ablated_accuracy: float
    light_accuracy: float


@dataclass(frozen=True)
class FindingElevenVerdict:
    """Finding-11 rubric output + inputs."""

    label: str
    full_framing_accuracy: float
    ablated_framing_accuracy: float
    light_framing_accuracy: float
    delta_light_minus_full: float
    n_framing_scenarios: int


# =============================================================================
# Loading
# =============================================================================


def load_session_048(path: Path) -> tuple[FramingBenchmarkResult, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        FramingBenchmarkResult.from_dict(r) for r in payload.get("results", [])
    )


def load_session_049_ablated(path: Path) -> tuple[FramingBenchmarkResultV3, ...]:
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        FramingBenchmarkResultV3.from_dict(r)
        for r in payload.get("ablated_results", [])
    )


def load_session_049_full(path: Path) -> tuple[FramingBenchmarkResultV3, ...]:
    """Return any ``full_results`` entries from the Session 049 payload."""
    payload = json.loads(path.read_text(encoding="utf-8"))
    return tuple(
        FramingBenchmarkResultV3.from_dict(r)
        for r in payload.get("full_results", [])
    )


def load_session_050(path: Path) -> tuple[FramingBenchmarkResultV3, ...]:
    """Load every result in Session 050's light_raw_results.json.

    The Session 050 runner writes three top-level arrays: ``light_results``
    (always populated), ``full_live_results`` (populated only for
    scenarios that had no Session 048 match), and ``ablated_live_results``
    (same for Session 049). The loader returns all three as a single
    tuple so the caller can partition by ``pipeline_variant``.
    """
    payload = json.loads(path.read_text(encoding="utf-8"))
    out: list[FramingBenchmarkResultV3] = []
    for key in ("light_results", "full_live_results", "ablated_live_results"):
        for raw in payload.get(key, []) or []:
            out.append(FramingBenchmarkResultV3.from_dict(raw))
    return tuple(out)


# =============================================================================
# Helpers
# =============================================================================


def _verdict_matches(actual: str, expected: str) -> bool:
    norm = actual.strip().upper()
    if not norm:
        return False
    return norm == expected.strip().upper()


def _index_by_id_v1(
    rows: Sequence[FramingBenchmarkResult],
) -> dict[str, FramingBenchmarkResult]:
    return {r.scenario_id: r for r in rows}


def _index_by_id_v2(
    rows: Sequence[FramingBenchmarkResultV3],
) -> dict[str, FramingBenchmarkResultV3]:
    return {r.scenario_id: r for r in rows}


# =============================================================================
# Merging + matching
# =============================================================================


@dataclass(frozen=True)
class MergedSources:
    """Indexes of the three variants' results, matched by scenario_id.

    Attributes:
        full_by_id: Full-pipeline results, one per scenario_id.
        ablated_by_id: Ablated-pipeline results.
        light_by_id: Light-pipeline results.
    """

    full_by_id: Mapping[str, FramingBenchmarkResult]
    ablated_by_id: Mapping[str, FramingBenchmarkResultV3]
    light_by_id: Mapping[str, FramingBenchmarkResultV3]


def merge_sources(
    *,
    s048_full: Sequence[FramingBenchmarkResult],
    s049_ablated: Sequence[FramingBenchmarkResultV3],
    s049_full: Sequence[FramingBenchmarkResultV3] = (),
    s050_rows: Sequence[FramingBenchmarkResultV3],
) -> MergedSources:
    """Index every source's results by scenario_id for matching.

    Session 050 rows are split by ``pipeline_variant``:
        * "light"  -> light_by_id (primary)
        * "full"   -> backfills full_by_id when a scenario has no
                      Session 048 entry (e.g., INJ-031..033 temporal
                      additions)
        * "ablated" -> backfills ablated_by_id likewise.

    Session 049 "full_results" backfill (for INJ-028..030 from
    Session 049) is also merged into full_by_id.
    """
    full_v2_from_049 = {r.scenario_id: r.inner for r in s049_full}

    # Start with Session 048 entries; backfill with Session 049 full then
    # with Session 050 live-full runs.
    full_by_id: dict[str, FramingBenchmarkResult] = {
        r.scenario_id: r for r in s048_full
    }
    for sid, r in full_v2_from_049.items():
        full_by_id.setdefault(sid, r)

    ablated_by_id: dict[str, FramingBenchmarkResultV3] = {
        r.scenario_id: r for r in s049_ablated
    }

    light_by_id: dict[str, FramingBenchmarkResultV3] = {}

    for r in s050_rows:
        if r.pipeline_variant == "light":
            light_by_id[r.scenario_id] = r
        elif r.pipeline_variant == "full" and r.scenario_id not in full_by_id:
            full_by_id[r.scenario_id] = r.inner
        elif r.pipeline_variant == "ablated" and r.scenario_id not in ablated_by_id:
            ablated_by_id[r.scenario_id] = r

    return MergedSources(
        full_by_id=full_by_id,
        ablated_by_id=ablated_by_id,
        light_by_id=light_by_id,
    )


def build_scenario_rows(
    sources: MergedSources,
) -> tuple[ThreeWayScenarioRow, ...]:
    """Build per-scenario rows for every scenario present in all three variants."""
    rows: list[ThreeWayScenarioRow] = []
    sids = (
        set(sources.full_by_id)
        & set(sources.ablated_by_id)
        & set(sources.light_by_id)
    )
    for sid in sorted(sids):
        full = sources.full_by_id[sid]
        abl = sources.ablated_by_id[sid]
        lite = sources.light_by_id[sid]
        expected = full.expected_verdict
        rows.append(ThreeWayScenarioRow(
            scenario_id=sid,
            category=lite.category,
            framing_strategy=lite.framing_strategy,
            expected_verdict=expected,
            full_verdict=full.actual_verdict,
            ablated_verdict=abl.actual_verdict,
            light_verdict=lite.actual_verdict,
            full_correct=_verdict_matches(full.actual_verdict, expected),
            ablated_correct=_verdict_matches(abl.actual_verdict, expected),
            light_correct=_verdict_matches(lite.actual_verdict, expected),
        ))
    return tuple(rows)


# =============================================================================
# Aggregation
# =============================================================================


def compute_family_rows(
    scenario_rows: Sequence[ThreeWayScenarioRow],
) -> tuple[ThreeWayFamilyRow, ...]:
    grouped: dict[str, list[ThreeWayScenarioRow]] = {
        f: [] for f in FRAMING_FAMILIES
    }
    unknown: list[ThreeWayScenarioRow] = []
    for r in scenario_rows:
        fam = derive_family(r.framing_strategy)
        if fam is None:
            continue
        if fam in grouped:
            grouped[fam].append(r)
        else:
            unknown.append(r)

    rows: list[ThreeWayFamilyRow] = []
    for family in FRAMING_FAMILIES:
        bucket = grouped[family]
        rows.append(_row_for(family, bucket))
    if unknown:
        rows.append(_row_for(UNKNOWN_FAMILY, unknown))
    return tuple(rows)


def _row_for(
    label: str,
    bucket: Sequence[ThreeWayScenarioRow],
) -> ThreeWayFamilyRow:
    if not bucket:
        return ThreeWayFamilyRow(
            family=label,
            n=0,
            full_accuracy=0.0,
            ablated_accuracy=0.0,
            light_accuracy=0.0,
        )
    n = len(bucket)
    return ThreeWayFamilyRow(
        family=label,
        n=n,
        full_accuracy=sum(1 for r in bucket if r.full_correct) / n,
        ablated_accuracy=sum(1 for r in bucket if r.ablated_correct) / n,
        light_accuracy=sum(1 for r in bucket if r.light_correct) / n,
    )


def compute_finding_11(
    scenario_rows: Sequence[ThreeWayScenarioRow],
) -> FindingElevenVerdict:
    framing = [r for r in scenario_rows if r.category == "framing"]
    n = len(framing)
    if n == 0:
        return FindingElevenVerdict(
            label=FINDING_11_PARTIAL,
            full_framing_accuracy=0.0,
            ablated_framing_accuracy=0.0,
            light_framing_accuracy=0.0,
            delta_light_minus_full=0.0,
            n_framing_scenarios=0,
        )
    full_acc = sum(1 for r in framing if r.full_correct) / n
    abl_acc = sum(1 for r in framing if r.ablated_correct) / n
    light_acc = sum(1 for r in framing if r.light_correct) / n
    delta = light_acc - full_acc

    if light_acc >= full_acc - FINDING_11_SUPPORTED_DELTA:
        label = FINDING_11_SUPPORTED
    elif light_acc >= full_acc - FINDING_11_PARTIAL_DELTA:
        label = FINDING_11_PARTIAL
    else:
        label = FINDING_11_NOT_SUPPORTED

    return FindingElevenVerdict(
        label=label,
        full_framing_accuracy=full_acc,
        ablated_framing_accuracy=abl_acc,
        light_framing_accuracy=light_acc,
        delta_light_minus_full=delta,
        n_framing_scenarios=n,
    )


def find_light_only_wins(
    scenario_rows: Sequence[ThreeWayScenarioRow],
) -> tuple[ThreeWayScenarioRow, ...]:
    """Scenarios where the light pipeline beats both full and ablated.

    "Beats" means ``light_correct`` is True while both ``full_correct``
    and ``ablated_correct`` are False.
    """
    return tuple(
        r for r in scenario_rows
        if r.light_correct and not r.full_correct and not r.ablated_correct
    )


# =============================================================================
# CSV output
# =============================================================================


SCENARIO_CSV_HEADER: tuple[str, ...] = (
    "scenario_id",
    "family",
    "strategy",
    "expected",
    "full",
    "ablated",
    "light",
    "full_correct",
    "ablated_correct",
    "light_correct",
)

FAMILY_CSV_HEADER: tuple[str, ...] = (
    "family",
    "n",
    "full_acc",
    "ablated_acc",
    "light_acc",
)


def write_scenario_csv(
    rows: Sequence[ThreeWayScenarioRow],
    out_path: Path,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(SCENARIO_CSV_HEADER)
        for r in rows:
            writer.writerow([
                r.scenario_id,
                derive_family(r.framing_strategy) or "",
                r.framing_strategy or "",
                r.expected_verdict,
                r.full_verdict,
                r.ablated_verdict,
                r.light_verdict,
                "true" if r.full_correct else "false",
                "true" if r.ablated_correct else "false",
                "true" if r.light_correct else "false",
            ])
    return out_path


def write_family_csv(
    rows: Sequence[ThreeWayFamilyRow],
    out_path: Path,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    with out_path.open("w", encoding="utf-8", newline="") as fh:
        writer = csv.writer(fh)
        writer.writerow(FAMILY_CSV_HEADER)
        for r in rows:
            writer.writerow([
                r.family,
                r.n,
                f"{r.full_accuracy:.4f}",
                f"{r.ablated_accuracy:.4f}",
                f"{r.light_accuracy:.4f}",
            ])
    return out_path


# =============================================================================
# Markdown output
# =============================================================================


def render_finding_11_markdown(verdict: FindingElevenVerdict) -> str:
    lines = [
        "# Finding-11 Verdict",
        "",
        f"**Finding-11: {verdict.label}**",
        "",
        f"- full framing accuracy      = {verdict.full_framing_accuracy:.4f}",
        f"- ablated framing accuracy   = {verdict.ablated_framing_accuracy:.4f}",
        f"- **light framing accuracy   = {verdict.light_framing_accuracy:.4f}**",
        f"- delta (light − full)       = {verdict.delta_light_minus_full:+.4f}",
        f"- n (framing scenarios)      = {verdict.n_framing_scenarios}",
        "",
        "## Rubric",
        "",
        f"- light ≥ full − {FINDING_11_SUPPORTED_DELTA:.2f}  → SUPPORTED",
        f"- full − {FINDING_11_PARTIAL_DELTA:.2f} ≤ light < full − {FINDING_11_SUPPORTED_DELTA:.2f}  → PARTIAL",
        f"- light < full − {FINDING_11_PARTIAL_DELTA:.2f}     → NOT SUPPORTED",
    ]
    return "\n".join(lines)


def render_summary_markdown(
    scenario_rows: Sequence[ThreeWayScenarioRow],
    family_rows: Sequence[ThreeWayFamilyRow],
    verdict: FindingElevenVerdict,
    *,
    s048_path: Optional[Path] = None,
    s049_path: Optional[Path] = None,
    s050_path: Optional[Path] = None,
    light_only_wins: Sequence[ThreeWayScenarioRow] = (),
) -> str:
    lines: list[str] = ["# Session 050 — Three-Way Comparison Report", ""]
    if s048_path is not None:
        lines.append(f"Session 048 input: `{s048_path}`")
    if s049_path is not None:
        lines.append(f"Session 049 input: `{s049_path}`")
    if s050_path is not None:
        lines.append(f"Session 050 input: `{s050_path}`")
    lines.append("")

    lines.append(render_finding_11_markdown(verdict))
    lines.append("")

    # Family table
    lines.append("## Per-Framing-Family Three-Way Accuracy")
    lines.append("")
    lines.append("| family | n | full_acc | ablated_acc | light_acc |")
    lines.append("|---|---:|---:|---:|---:|")
    for r in family_rows:
        lines.append(
            f"| {r.family} | {r.n} | {r.full_accuracy:.4f} | "
            f"{r.ablated_accuracy:.4f} | {r.light_accuracy:.4f} |"
        )
    lines.append("")

    # Per-scenario preview
    lines.append("## Per-Scenario Three-Way Verdicts")
    lines.append("")
    lines.append(
        "| scenario_id | family | expected | full | ablated | light |"
    )
    lines.append("|---|---|---|---|---|---|")
    for r in scenario_rows:
        lines.append(
            f"| {r.scenario_id} | "
            f"{derive_family(r.framing_strategy) or '—'} | "
            f"{r.expected_verdict} | {r.full_verdict} | "
            f"{r.ablated_verdict} | {r.light_verdict} |"
        )
    lines.append("")

    # Light-only wins
    lines.append("## Light-Pipeline Standalone Wins")
    lines.append("")
    if not light_only_wins:
        lines.append("_No scenarios where light beats both full and ablated._")
    else:
        lines.append("These scenarios were verdicted correctly by the light pipeline "
                     "while both full and ablated got them wrong.")
        lines.append("")
        lines.append(
            "| scenario_id | strategy | expected | full | ablated | light |"
        )
        lines.append("|---|---|---|---|---|---|")
        for r in light_only_wins:
            lines.append(
                f"| {r.scenario_id} | {r.framing_strategy or '—'} | "
                f"{r.expected_verdict} | {r.full_verdict} | "
                f"{r.ablated_verdict} | {r.light_verdict} |"
            )
    lines.append("")

    return "\n".join(lines)


def write_finding_11_markdown(
    verdict: FindingElevenVerdict,
    out_path: Path,
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(render_finding_11_markdown(verdict), encoding="utf-8")
    return out_path


def write_summary_markdown(
    scenario_rows: Sequence[ThreeWayScenarioRow],
    family_rows: Sequence[ThreeWayFamilyRow],
    verdict: FindingElevenVerdict,
    out_path: Path,
    *,
    s048_path: Optional[Path] = None,
    s049_path: Optional[Path] = None,
    s050_path: Optional[Path] = None,
    light_only_wins: Sequence[ThreeWayScenarioRow] = (),
) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(
        render_summary_markdown(
            scenario_rows, family_rows, verdict,
            s048_path=s048_path, s049_path=s049_path, s050_path=s050_path,
            light_only_wins=light_only_wins,
        ),
        encoding="utf-8",
    )
    return out_path


def print_finding_11_line(verdict: FindingElevenVerdict) -> str:
    return (
        f"Finding-11: {verdict.label} "
        f"(light_framing_accuracy={verdict.light_framing_accuracy:.4f}, "
        f"full_framing_accuracy={verdict.full_framing_accuracy:.4f}, "
        f"ablated_framing_accuracy={verdict.ablated_framing_accuracy:.4f}, "
        f"delta_light_minus_full={verdict.delta_light_minus_full:+.4f}, "
        f"n={verdict.n_framing_scenarios})"
    )


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description=(
            "Session 050 three-way comparison report. Computes Finding-11 "
            "per predetermined rubric."
        ),
    )
    parser.add_argument(
        "--session-048", type=Path,
        default=Path("results/session_048/raw_results.json"),
    )
    parser.add_argument(
        "--session-049", type=Path,
        default=Path("results/session_049/ablated_raw_results.json"),
    )
    parser.add_argument(
        "--session-050", type=Path,
        default=Path("results/session_050/light_raw_results.json"),
    )
    parser.add_argument(
        "--output-dir", type=Path,
        default=Path("results/session_050"),
    )
    return parser


def run_comparison(
    s048: Path,
    s049: Path,
    s050: Path,
    output_dir: Path,
) -> tuple[Path, Path, Path, Path, FindingElevenVerdict]:
    sources = merge_sources(
        s048_full=load_session_048(s048),
        s049_ablated=load_session_049_ablated(s049),
        s049_full=load_session_049_full(s049),
        s050_rows=load_session_050(s050),
    )
    scenario_rows = build_scenario_rows(sources)
    family_rows = compute_family_rows(scenario_rows)
    verdict = compute_finding_11(scenario_rows)
    light_wins = find_light_only_wins(scenario_rows)

    scenario_csv = write_scenario_csv(
        scenario_rows, output_dir / "three_way_delta.csv",
    )
    family_csv = write_family_csv(
        family_rows, output_dir / "family_three_way.csv",
    )
    verdict_md = write_finding_11_markdown(
        verdict, output_dir / "finding_11_verdict.md",
    )
    summary_md = write_summary_markdown(
        scenario_rows, family_rows, verdict,
        output_dir / "summary.md",
        s048_path=s048, s049_path=s049, s050_path=s050,
        light_only_wins=light_wins,
    )

    print(print_finding_11_line(verdict))
    return scenario_csv, family_csv, verdict_md, summary_md, verdict


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    for path, label in (
        (args.session_048, "Session 048"),
        (args.session_049, "Session 049"),
        (args.session_050, "Session 050"),
    ):
        if not path.exists():
            print(
                f"[THREE-WAY-REPORT] ERROR: {label} input not found at {path}",
                file=sys.stderr,
            )
            return 2

    scenario_csv, family_csv, verdict_md, summary_md, _ = run_comparison(
        args.session_048, args.session_049, args.session_050, args.output_dir,
    )
    print(f"[THREE-WAY-REPORT] Wrote {scenario_csv}")
    print(f"[THREE-WAY-REPORT] Wrote {family_csv}")
    print(f"[THREE-WAY-REPORT] Wrote {verdict_md}")
    print(f"[THREE-WAY-REPORT] Wrote {summary_md}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
