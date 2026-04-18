"""Central registry for the injection-resilience benchmark corpus.

Aggregates scenarios across corpus modules so downstream consumers (tests,
runners, analysis notebooks) don't re-hardcode scenario lists as the corpus
grows.  Today two corpus modules contribute:

    * ``injection_corpus``           — INJ-001..012 (Categories A, B, C seed set)
    * ``injection_corpus_b_framing`` — INJ-013..027 (Category B expansion)

The registry is a frozen dataclass built via ``build_registry()``; all query
methods return immutable tuples / dicts to preserve determinism.

Category mapping mirrors the existing hard-coded dict in
``run_injection_benchmark.py``; the runner is intentionally left untouched
this session — the registry exposes the mapping for downstream use without
forcing a change to the live benchmark wiring.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ares.dialectic.scripts.injection_corpus import (
    get_injection_scenarios,
)
from ares.dialectic.scripts.injection_corpus_b_framing import (
    FramingRecord,
    get_framing_records,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


# Canonical category labels
DIRECT = "DIRECT"
FRAMING = "FRAMING"
PROPAGATION = "PROPAGATION"

_BASE_CATEGORIES: dict[str, str] = {
    "INJ-001": DIRECT,
    "INJ-002": DIRECT,
    "INJ-003": DIRECT,
    "INJ-004": DIRECT,
    "INJ-005": FRAMING,
    "INJ-006": FRAMING,
    "INJ-007": FRAMING,
    "INJ-008": FRAMING,
    "INJ-009": PROPAGATION,
    "INJ-010": PROPAGATION,
    "INJ-011": PROPAGATION,
    "INJ-012": PROPAGATION,
}


@dataclass(frozen=True)
class InjectionCorpusRegistry:
    """Immutable view over every injection scenario available to the pipeline.

    Attributes:
        scenarios: All scenarios across every contributing module.
        records: Framing records (Category B expansion only — the seed corpus
            has no per-scenario wrapper metadata).
        categories: Scenario-ID -> category label mapping.
    """

    scenarios: tuple[BenchmarkScenario, ...]
    records: tuple[FramingRecord, ...]
    categories: Mapping[str, str]

    def all_scenarios(self) -> tuple[BenchmarkScenario, ...]:
        return self.scenarios

    def scenario_count(self) -> int:
        return len(self.scenarios)

    def by_category(self, category: str) -> tuple[BenchmarkScenario, ...]:
        """Return scenarios whose category matches ``category``.

        Raises:
            KeyError: If ``category`` is not one of the known labels.
        """
        known = {DIRECT, FRAMING, PROPAGATION}
        if category not in known:
            raise KeyError(
                f"Unknown category '{category}'. Expected one of: "
                f"{sorted(known)}."
            )
        return tuple(
            s for s in self.scenarios
            if self.categories.get(s.metadata.scenario_id) == category
        )

    def by_difficulty(self, tier: int) -> tuple[BenchmarkScenario, ...]:
        return tuple(
            s for s in self.scenarios if s.metadata.difficulty_tier == tier
        )

    def by_framing_strategy(
        self, strategy: str,
    ) -> tuple[BenchmarkScenario, ...]:
        """Return scenarios whose framing_strategy equals ``strategy``.

        Only Category B expansion scenarios carry framing_strategy metadata;
        other scenarios are never matched by this query.
        """
        return tuple(
            r.scenario for r in self.records if r.framing_strategy == strategy
        )

    def category_counts(self) -> dict[str, int]:
        counts: dict[str, int] = {DIRECT: 0, FRAMING: 0, PROPAGATION: 0}
        for s in self.scenarios:
            label = self.categories.get(s.metadata.scenario_id)
            if label is None:
                continue
            counts[label] = counts.get(label, 0) + 1
        return counts

    def framing_strategies(self) -> tuple[str, ...]:
        """Return the set of known framing_strategy identifiers (sorted)."""
        return tuple(sorted({r.framing_strategy for r in self.records}))


def _discover_scenarios() -> tuple[BenchmarkScenario, ...]:
    base = get_injection_scenarios()
    framing = tuple(r.scenario for r in get_framing_records())
    return tuple(list(base) + list(framing))


def _discover_records() -> tuple[FramingRecord, ...]:
    return get_framing_records()


def _build_category_map(
    scenarios: tuple[BenchmarkScenario, ...],
) -> Mapping[str, str]:
    """Build the read-only category map.

    INJ-001..012 use the fixed _BASE_CATEGORIES mapping (matches the
    runner).  INJ-013..027 belong to the Category B expansion and are
    all FRAMING.  Any other scenario ID is left unmapped — callers that
    ask for a category explicitly get a KeyError.
    """
    mapping: dict[str, str] = dict(_BASE_CATEGORIES)
    for s in scenarios:
        sid = s.metadata.scenario_id
        if sid in mapping:
            continue
        if sid.startswith("INJ-"):
            # Every expansion module beyond the seed set contributes Category B
            # framing scenarios for the foreseeable future of Phase 6 Stage 1.
            mapping[sid] = FRAMING
    return MappingProxyType(mapping)


def build_registry() -> InjectionCorpusRegistry:
    """Build a frozen registry over the current injection corpus modules."""
    scenarios = _discover_scenarios()
    records = _discover_records()
    categories = _build_category_map(scenarios)
    return InjectionCorpusRegistry(
        scenarios=scenarios,
        records=records,
        categories=categories,
    )
