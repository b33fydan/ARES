"""Operator orthogonality audit — Phase 7 / Session 058.

Second line of defense for the Paper 3 experimental claim. Two failure
modes the audit catches:

    1. Operator collision — two operators produce equivalent
       transformations on too many scenarios. The variant space is
       smaller than the operator count suggests.
    2. High applicability gap — an operator is a no-op on too much of
       the corpus. The operator is not earning its inclusion.

Pre-registered decision rule (immutable in
:meth:`OrthogonalityReport.__post_init__`):

    PASS iff every pairwise collision count <= max_acceptable_collision_count
    AND every operator's applicability gap <= max_acceptable_applicability_gap

A FAIL is the audit doing its job. Do NOT modify operators in v1 to
chase a PASS — v1 is reproducibility-locked. Revisions go in v2 in a
later session.
"""

from __future__ import annotations

import argparse
import json
import sys
from dataclasses import asdict, dataclass
from itertools import combinations
from pathlib import Path
from typing import Any, Iterable, Mapping

from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    PairedScenarioMutator,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# Pre-registered thresholds. Locked at v1 for reproducibility.
MAX_ACCEPTABLE_COLLISION_COUNT: int = 2
MAX_ACCEPTABLE_APPLICABILITY_GAP: int = 10


DEFAULT_OUTPUT_PATH: Path = (
    Path(__file__).resolve().parents[4]
    / "docs"
    / "paper_3"
    / "operator_orthogonality_v1.json"
)


# ---------------------------------------------------------------------------
# Report container (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class OrthogonalityReport:
    """Immutable orthogonality-audit result.

    Attributes:
        audit_version: Audit schema version (v1).
        registry_label: Name of the corpus that was audited.
        n_scenarios: Number of scenarios in the corpus.
        operators: Tuple of operator names (registration order).
        applicability_gap: operator_name -> count of scenarios where
            that operator was a no-op.
        pairwise_collision_matrix: ``"opA__opB"`` (lex-sorted) -> count
            of scenarios where opA and opB produced identical mutated
            value-hash sets.
        max_acceptable_collision_count: Pre-registered threshold.
        max_acceptable_applicability_gap: Pre-registered threshold.
        decision: ``"PASS"`` or ``"FAIL"``.
        failed_pairs: Pair-name strings exceeding the collision
            threshold (sorted).
        failed_operators_by_gap: Operator names exceeding the
            applicability-gap threshold (sorted).
    """

    audit_version: str
    registry_label: str
    n_scenarios: int
    operators: tuple[str, ...]
    applicability_gap: Mapping[str, int]
    pairwise_collision_matrix: Mapping[str, int]
    max_acceptable_collision_count: int
    max_acceptable_applicability_gap: int
    decision: str
    failed_pairs: tuple[str, ...]
    failed_operators_by_gap: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.decision not in {"PASS", "FAIL"}:
            raise ValueError(
                f"decision must be 'PASS' or 'FAIL'; got {self.decision!r}"
            )
        if not isinstance(self.operators, tuple):
            raise TypeError("operators must be a tuple")
        if not isinstance(self.failed_pairs, tuple):
            raise TypeError("failed_pairs must be a tuple")
        if not isinstance(self.failed_operators_by_gap, tuple):
            raise TypeError("failed_operators_by_gap must be a tuple")
        if self.n_scenarios < 0:
            raise ValueError(f"n_scenarios must be >= 0; got {self.n_scenarios}")

        expected_failed_pairs = tuple(
            sorted(
                k
                for k, v in self.pairwise_collision_matrix.items()
                if v > self.max_acceptable_collision_count
            )
        )
        if self.failed_pairs != expected_failed_pairs:
            raise ValueError(
                f"failed_pairs {self.failed_pairs!r} disagrees with "
                f"matrix; expected {expected_failed_pairs!r}"
            )

        expected_failed_ops = tuple(
            sorted(
                op
                for op, gap in self.applicability_gap.items()
                if gap > self.max_acceptable_applicability_gap
            )
        )
        if self.failed_operators_by_gap != expected_failed_ops:
            raise ValueError(
                f"failed_operators_by_gap {self.failed_operators_by_gap!r} "
                f"disagrees with gaps; expected {expected_failed_ops!r}"
            )

        expected_decision = (
            "PASS"
            if not expected_failed_pairs and not expected_failed_ops
            else "FAIL"
        )
        if self.decision != expected_decision:
            raise ValueError(
                f"decision {self.decision!r} inconsistent with "
                f"failed_pairs={expected_failed_pairs} and "
                f"failed_operators_by_gap={expected_failed_ops} "
                f"(expected {expected_decision!r})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "audit_version": self.audit_version,
            "registry_label": self.registry_label,
            "n_scenarios": self.n_scenarios,
            "operators": list(self.operators),
            "applicability_gap": dict(self.applicability_gap),
            "pairwise_collision_matrix": dict(self.pairwise_collision_matrix),
            "decision_threshold": {
                "max_acceptable_collision_count": self.max_acceptable_collision_count,
                "max_acceptable_applicability_gap": self.max_acceptable_applicability_gap,
            },
            "decision": self.decision,
            "failed_pairs": list(self.failed_pairs),
            "failed_operators_by_gap": list(self.failed_operators_by_gap),
        }


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------


def _value_hash_set_for_pair(pair) -> frozenset[tuple[str, str]]:
    """Frozenset of (fact_id, mutated_value_hash) for the mutated side."""
    return frozenset(
        (f.fact_id, f.value_hash)
        for f in pair.mutated_scenario.packet.get_all_facts()
    )


def _pair_key(name_a: str, name_b: str) -> str:
    """Canonical lex-sorted ``"opA__opB"`` key."""
    a, b = sorted((name_a, name_b))
    return f"{a}__{b}"


def audit_scenarios(
    scenarios: Iterable[BenchmarkScenario],
    *,
    registry_label: str,
    mutator: PairedScenarioMutator | None = None,
    max_acceptable_collision_count: int = MAX_ACCEPTABLE_COLLISION_COUNT,
    max_acceptable_applicability_gap: int = MAX_ACCEPTABLE_APPLICABILITY_GAP,
    audit_version: str = "v1",
) -> OrthogonalityReport:
    """Run the orthogonality audit.

    Args:
        scenarios: Iterable of BenchmarkScenarios. Materialized once.
        registry_label: Free-form label recorded in the report.
        mutator: PairedScenarioMutator instance. Defaults to a fresh
            mutator with the v1 operators.
        max_acceptable_collision_count: Pre-registered threshold for
            pairwise collisions.
        max_acceptable_applicability_gap: Pre-registered threshold for
            per-operator no-op count.
        audit_version: Recorded in the report. Default ``"v1"``
            preserves bit-identical output for the original audit.

    Returns:
        Frozen :class:`OrthogonalityReport`.
    """
    if mutator is None:
        mutator = PairedScenarioMutator(operators=OPERATORS_V1)

    scenario_list = list(scenarios)
    op_names = mutator.operator_names()
    n_scenarios = len(scenario_list)

    applicability_gap: dict[str, int] = {name: 0 for name in op_names}
    pair_keys: list[str] = sorted(
        _pair_key(a, b) for a, b in combinations(op_names, 2)
    )
    collisions: dict[str, int] = {key: 0 for key in pair_keys}

    for scenario in scenario_list:
        # Per-scenario record: operator_name -> mutated value-hash set
        # for that operator. Operators that are no-ops omit themselves.
        per_op_hashes: dict[str, frozenset[tuple[str, str]]] = {}
        for op_name in op_names:
            try:
                pair = mutator.mutate(scenario, op_name)
            except Exception as exc:  # pragma: no cover - SkeletonInvariantError no-op
                # No-op pairs raise SkeletonInvariantError("...no-op...").
                # Real skeleton breaks indicate a bug and should
                # propagate; we filter on message text rather than
                # silencing all errors.
                if "no Fact value_hash differs" in str(exc):
                    applicability_gap[op_name] += 1
                    continue
                raise
            per_op_hashes[op_name] = _value_hash_set_for_pair(pair)

        for a, b in combinations(op_names, 2):
            if a in per_op_hashes and b in per_op_hashes:
                if per_op_hashes[a] == per_op_hashes[b]:
                    collisions[_pair_key(a, b)] += 1

    failed_pairs = tuple(
        sorted(
            k for k, v in collisions.items() if v > max_acceptable_collision_count
        )
    )
    failed_ops = tuple(
        sorted(
            op
            for op, gap in applicability_gap.items()
            if gap > max_acceptable_applicability_gap
        )
    )
    decision = "PASS" if not failed_pairs and not failed_ops else "FAIL"

    return OrthogonalityReport(
        audit_version=audit_version,
        registry_label=registry_label,
        n_scenarios=n_scenarios,
        operators=op_names,
        applicability_gap=applicability_gap,
        pairwise_collision_matrix=collisions,
        max_acceptable_collision_count=max_acceptable_collision_count,
        max_acceptable_applicability_gap=max_acceptable_applicability_gap,
        decision=decision,
        failed_pairs=failed_pairs,
        failed_operators_by_gap=failed_ops,
    )


def write_report(report: OrthogonalityReport, output_path: Path) -> Path:
    """Serialize the orthogonality report to JSON."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return output_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


def _format_summary(report: OrthogonalityReport) -> str:
    lines = [
        f"Operator orthogonality audit ({report.audit_version}) on "
        f"{report.registry_label}",
        f"  n_scenarios: {report.n_scenarios}",
        f"  operators ({len(report.operators)}):",
    ]
    for op in report.operators:
        gap = report.applicability_gap[op]
        lines.append(f"    {op}  applicability_gap={gap}")
    lines.append("  pairwise collisions:")
    for key in sorted(report.pairwise_collision_matrix.keys()):
        n = report.pairwise_collision_matrix[key]
        if n > 0:
            lines.append(f"    {key}  n={n}")
    lines.append(
        f"  thresholds: collision<={report.max_acceptable_collision_count}, "
        f"gap<={report.max_acceptable_applicability_gap}"
    )
    lines.append(f"  decision: {report.decision}")
    if report.failed_pairs:
        lines.append(f"  failed_pairs: {list(report.failed_pairs)}")
    if report.failed_operators_by_gap:
        lines.append(
            f"  failed_operators_by_gap: {list(report.failed_operators_by_gap)}"
        )
    return "\n".join(lines)


_OPERATOR_SET_CHOICES: tuple[str, ...] = ("v1", "v2")


def _resolve_mutator(operator_set: str) -> PairedScenarioMutator:
    """Build a PairedScenarioMutator for the requested operator set.

    Default is ``"v1"``; that path constructs the same mutator the
    Session 058 audit used and produces bit-identical output.
    """
    if operator_set == "v1":
        return PairedScenarioMutator(operators=OPERATORS_V1)
    if operator_set == "v2":
        # Lazy import keeps v1 audit path independent of v2 module.
        from ares.dialectic.scripts.non_interference.paired_scenario_mutator_v2 import (
            OPERATORS_V2,
        )
        return PairedScenarioMutator(operators=OPERATORS_V2)
    raise ValueError(
        f"unknown operator_set {operator_set!r}; "
        f"choose one of {_OPERATOR_SET_CHOICES}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 7 — operator orthogonality audit on "
            "injection_registry_v3. Default operator set is the "
            "Session 058 v1 PairedScenarioMutator; pass "
            "--operator-set v2 to audit the Session 058.5 v2 roster."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=f"Output JSON path. Defaults to {DEFAULT_OUTPUT_PATH}.",
    )
    parser.add_argument(
        "--collision-threshold",
        type=int,
        default=MAX_ACCEPTABLE_COLLISION_COUNT,
    )
    parser.add_argument(
        "--gap-threshold",
        type=int,
        default=MAX_ACCEPTABLE_APPLICABILITY_GAP,
    )
    parser.add_argument(
        "--operator-set",
        choices=_OPERATOR_SET_CHOICES,
        default="v1",
        help=(
            "Which operator roster to audit. Defaults to v1 for "
            "bit-identical reproduction of the Session 058 audit."
        ),
    )
    args = parser.parse_args(argv)

    registry = build_registry_v3()
    mutator = _resolve_mutator(args.operator_set)
    report = audit_scenarios(
        registry.all_scenarios(),
        registry_label="injection_registry_v3",
        mutator=mutator,
        max_acceptable_collision_count=args.collision_threshold,
        max_acceptable_applicability_gap=args.gap_threshold,
        audit_version=args.operator_set,
    )
    written = write_report(report, args.output)

    print(_format_summary(report))
    print(f"\nWrote: {written}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
