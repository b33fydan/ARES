"""Skeleton audit — Phase 7 / Session 057 / Step 1.

Loads :func:`build_registry_v3` (33-scenario corpus) and groups scenarios
by skeleton hash. Emits a JSON manifest at
``docs/paper_3/skeleton_audit_v1.json``.

The audit answers one question, with a pre-registered branching rule:

    n_groups_size_ge_2 >= 5
        => harness path proceeds. Session 058 builds the trace-capture
           layer + runs a one-shot live capture. Replay-style measurement
           becomes viable.
    n_groups_size_ge_2 < 5
        => mutator path is forced. Session 058 builds
           paired_scenario_mutator.py first.

No LLM calls. No edits to existing files in ``ares/``. Pure replay over
the registry.

Usage:

    python -m ares.dialectic.scripts.non_interference.skeleton_audit

The output JSON shape is documented on :class:`SkeletonAuditReport`.
"""

from __future__ import annotations

import argparse
import json
import sys
from collections import defaultdict
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import TYPE_CHECKING, Any, Iterable, Mapping

from ares.dialectic.schemas.skeleton_equivalence import (
    SkeletonEquivalentGroup,
    make_group_id,
    skeleton_hash,
    skeleton_timestamps,
)
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3

if TYPE_CHECKING:  # pragma: no cover
    from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# Pre-registered decision threshold for downstream sessions.
DECISION_THRESHOLD: int = 5

# Default output location for the audit manifest.
DEFAULT_OUTPUT_PATH: Path = (
    Path(__file__).resolve().parents[4] / "docs" / "paper_3" / "skeleton_audit_v1.json"
)


# ---------------------------------------------------------------------------
# Report container (frozen)
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkeletonAuditReport:
    """Immutable audit result.

    Attributes:
        registry_label: Name of the corpus that was audited.
        n_scenarios: Total scenario count in the registry.
        n_distinct_skeletons: Number of distinct skeleton hashes
            observed.
        n_singleton_skeletons: Number of skeleton hashes seen exactly
            once.
        n_groups_size_ge_2: Number of skeleton hashes shared by >= 2
            scenarios. **This is the headline number.**
        decision_threshold: Pre-registered threshold (currently 5). If
            ``n_groups_size_ge_2 >= decision_threshold`` the harness
            path proceeds; otherwise the mutator path is forced.
        decision: Either ``"harness_path"`` or ``"mutator_path"``,
            derived from ``n_groups_size_ge_2`` vs threshold.
        groups: Materialized SkeletonEquivalentGroup records, one per
            shared skeleton, sorted by ``group_id``.
        singleton_scenario_ids: Sorted tuple of scenario_ids that did
            not share a skeleton with any other scenario.
    """

    registry_label: str
    n_scenarios: int
    n_distinct_skeletons: int
    n_singleton_skeletons: int
    n_groups_size_ge_2: int
    decision_threshold: int
    decision: str
    groups: tuple[SkeletonEquivalentGroup, ...]
    singleton_scenario_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if self.decision not in {"harness_path", "mutator_path"}:
            raise ValueError(
                f"decision must be 'harness_path' or 'mutator_path'; "
                f"got {self.decision!r}"
            )
        if self.n_scenarios < 0:
            raise ValueError(f"n_scenarios must be >= 0; got {self.n_scenarios}")
        if self.n_distinct_skeletons < 0:
            raise ValueError(
                f"n_distinct_skeletons must be >= 0; got {self.n_distinct_skeletons}"
            )
        if self.n_singleton_skeletons < 0:
            raise ValueError(
                f"n_singleton_skeletons must be >= 0; got {self.n_singleton_skeletons}"
            )
        if self.n_groups_size_ge_2 < 0:
            raise ValueError(
                f"n_groups_size_ge_2 must be >= 0; got {self.n_groups_size_ge_2}"
            )
        if not isinstance(self.groups, tuple):
            raise TypeError("groups must be a tuple")
        if not isinstance(self.singleton_scenario_ids, tuple):
            raise TypeError("singleton_scenario_ids must be a tuple")
        if (
            self.n_distinct_skeletons
            != self.n_singleton_skeletons + self.n_groups_size_ge_2
        ):
            raise ValueError(
                "n_distinct_skeletons must equal "
                "n_singleton_skeletons + n_groups_size_ge_2; "
                f"got {self.n_distinct_skeletons} != "
                f"{self.n_singleton_skeletons} + {self.n_groups_size_ge_2}"
            )
        expected_decision = (
            "harness_path"
            if self.n_groups_size_ge_2 >= self.decision_threshold
            else "mutator_path"
        )
        if self.decision != expected_decision:
            raise ValueError(
                f"decision {self.decision!r} inconsistent with "
                f"n_groups_size_ge_2={self.n_groups_size_ge_2}, "
                f"threshold={self.decision_threshold} "
                f"(expected {expected_decision!r})"
            )

    def to_dict(self) -> dict[str, Any]:
        return {
            "registry_label": self.registry_label,
            "n_scenarios": self.n_scenarios,
            "n_distinct_skeletons": self.n_distinct_skeletons,
            "n_singleton_skeletons": self.n_singleton_skeletons,
            "n_groups_size_ge_2": self.n_groups_size_ge_2,
            "decision_threshold": self.decision_threshold,
            "decision": self.decision,
            "groups": [g.to_dict() for g in self.groups],
            "singleton_scenario_ids": list(self.singleton_scenario_ids),
        }


# ---------------------------------------------------------------------------
# Audit logic
# ---------------------------------------------------------------------------


def _index_scenarios(
    scenarios: Iterable["BenchmarkScenario"],
) -> Mapping[str, list[str]]:
    """Bucket scenario_ids by skeleton hash.

    Args:
        scenarios: Iterable of BenchmarkScenarios.

    Returns:
        Mapping from skeleton_hash -> list of scenario_ids in
        first-seen order.
    """
    by_hash: dict[str, list[str]] = defaultdict(list)
    for scenario in scenarios:
        sid = scenario.metadata.scenario_id
        h = skeleton_hash(scenario.packet)
        by_hash[h].append(sid)
    return by_hash


def _build_group(
    skeleton_hash_value: str,
    scenarios_in_group: list["BenchmarkScenario"],
) -> SkeletonEquivalentGroup:
    """Materialize one SkeletonEquivalentGroup from co-located scenarios.

    Computes the timestamp-mismatch flag by comparing per-fact timestamp
    tuples across every member.
    """
    sorted_members = sorted(
        scenarios_in_group, key=lambda s: s.metadata.scenario_id
    )
    scenario_ids = tuple(s.metadata.scenario_id for s in sorted_members)
    n_facts = sorted_members[0].packet.fact_count

    # Collect per-fact timestamp tuples.
    ts_tables = [skeleton_timestamps(s.packet) for s in sorted_members]
    base_table = ts_tables[0]
    mismatched: set[str] = set()
    for other in ts_tables[1:]:
        # Both tuples are sorted by fact_id by construction.
        for (fid_a, ts_a), (fid_b, ts_b) in zip(base_table, other):
            if fid_a != fid_b:
                # Should not happen if skeleton hashes match, but fail
                # loudly rather than silently if the invariant breaks.
                raise RuntimeError(
                    "Skeleton-equivalent group has misaligned fact_ids: "
                    f"{fid_a!r} vs {fid_b!r}"
                )
            if ts_a != ts_b:
                mismatched.add(fid_a)

    timestamp_mismatch = bool(mismatched)
    timestamp_mismatched_fact_ids = tuple(sorted(mismatched))

    return SkeletonEquivalentGroup(
        group_id=make_group_id(skeleton_hash_value),
        skeleton_hash=skeleton_hash_value,
        scenario_ids=scenario_ids,
        n_facts=n_facts,
        timestamp_mismatch=timestamp_mismatch,
        timestamp_mismatched_fact_ids=timestamp_mismatched_fact_ids,
    )


def audit_scenarios(
    scenarios: Iterable["BenchmarkScenario"],
    *,
    registry_label: str,
    decision_threshold: int = DECISION_THRESHOLD,
) -> SkeletonAuditReport:
    """Run the skeleton audit over an iterable of BenchmarkScenarios.

    Args:
        scenarios: Iterable of BenchmarkScenarios. Re-iterated once;
            callers should pass a tuple/list, not a generator.
        registry_label: Free-form label recorded in the report (e.g.,
            ``"injection_registry_v3"``).
        decision_threshold: Pre-registered threshold for the harness vs
            mutator branching rule. Defaults to
            :data:`DECISION_THRESHOLD`.

    Returns:
        A frozen :class:`SkeletonAuditReport`.
    """
    materialized = list(scenarios)
    by_hash = _index_scenarios(materialized)
    by_id = {s.metadata.scenario_id: s for s in materialized}

    groups: list[SkeletonEquivalentGroup] = []
    singletons: list[str] = []
    for h, sids in by_hash.items():
        if len(sids) >= 2:
            members = [by_id[sid] for sid in sids]
            groups.append(_build_group(h, members))
        else:
            singletons.append(sids[0])

    groups_sorted = tuple(sorted(groups, key=lambda g: g.group_id))
    singletons_sorted = tuple(sorted(singletons))

    n_distinct = len(by_hash)
    n_singleton = len(singletons_sorted)
    n_groups = len(groups_sorted)

    decision = (
        "harness_path" if n_groups >= decision_threshold else "mutator_path"
    )

    return SkeletonAuditReport(
        registry_label=registry_label,
        n_scenarios=len(materialized),
        n_distinct_skeletons=n_distinct,
        n_singleton_skeletons=n_singleton,
        n_groups_size_ge_2=n_groups,
        decision_threshold=decision_threshold,
        decision=decision,
        groups=groups_sorted,
        singleton_scenario_ids=singletons_sorted,
    )


def write_report(report: SkeletonAuditReport, output_path: Path) -> Path:
    """Serialize the audit report to JSON at ``output_path``.

    Creates the parent directory if missing. Writes UTF-8 with
    ``ensure_ascii=False`` and ``indent=2`` for human inspection.

    Args:
        report: The SkeletonAuditReport to write.
        output_path: Filesystem path for the output JSON.

    Returns:
        The output_path argument, for caller convenience.
    """
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(report.to_dict(), indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )
    return output_path


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def _format_decision_summary(report: SkeletonAuditReport) -> str:
    lines = [
        f"Skeleton audit on {report.registry_label}",
        f"  n_scenarios:           {report.n_scenarios}",
        f"  n_distinct_skeletons:  {report.n_distinct_skeletons}",
        f"  n_singleton_skeletons: {report.n_singleton_skeletons}",
        f"  n_groups_size_ge_2:    {report.n_groups_size_ge_2}",
        f"  decision_threshold:    {report.decision_threshold}",
        f"  decision:              {report.decision}",
    ]
    if report.groups:
        lines.append("  groups:")
        for g in report.groups:
            ts = " (timestamps differ)" if g.timestamp_mismatch else ""
            lines.append(
                f"    {g.group_id}  size={g.size}  n_facts={g.n_facts}  "
                f"members={list(g.scenario_ids)}{ts}"
            )
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description=(
            "Phase 7 / Session 057 / Step 1 — skeleton-equivalence audit "
            "over injection_registry_v3."
        ),
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=(
            f"Output JSON path. Defaults to {DEFAULT_OUTPUT_PATH} "
            "relative to repo root."
        ),
    )
    parser.add_argument(
        "--threshold",
        type=int,
        default=DECISION_THRESHOLD,
        help=(
            "Pre-registered decision threshold. Defaults to "
            f"{DECISION_THRESHOLD}."
        ),
    )
    args = parser.parse_args(argv)

    registry = build_registry_v3()
    report = audit_scenarios(
        registry.all_scenarios(),
        registry_label="injection_registry_v3",
        decision_threshold=args.threshold,
    )
    written = write_report(report, args.output)

    print(_format_decision_summary(report))
    print(f"\nWrote: {written}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
