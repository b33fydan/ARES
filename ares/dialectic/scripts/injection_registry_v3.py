"""Session 050 v3 injection-corpus registry.

Wraps :class:`InjectionCorpusRegistryV2` (Session 049) with the 3
Session 050 temporal-family scenarios (INJ-031..033) layered on top.
Both v1 and v2 registry modules remain untouched (per the do-not-modify
list).

Total scenario count in v3: **33**
    Direct        : 4  (INJ-001..004)
    Framing       : 25 (INJ-005..008 seed + INJ-013..027 expansion +
                        INJ-028..030 authority expansion +
                        INJ-031..033 temporal expansion)
    Propagation   : 4  (INJ-009..012)

Temporal family in v3 grows from 2 to 5:
    INJ-019, INJ-020 (Session 047) +
    INJ-031, INJ-032, INJ-033 (Session 050).

Public API mirrors v2 with a new ``temporal_records()`` accessor for
tests and analysis.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ares.dialectic.scripts.injection_corpus_b_framing import FramingRecord
from ares.dialectic.scripts.injection_corpus_b_temporal_expansion import (
    TEMPORAL_EXPANSION_RECORDS,
    TEMPORAL_EXPANSION_SCENARIOS,
)
from ares.dialectic.scripts.injection_registry_v2 import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistryV2,
    build_registry_v2,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


@dataclass(frozen=True)
class InjectionCorpusRegistryV3:
    """Immutable view over v2 + the Session 050 temporal expansion.

    Attributes:
        v2: The Session 049 registry (30 scenarios).
        extension_scenarios: The 3 Session 050 temporal-family scenarios.
        extension_records: Matching FramingRecord wrappers.
        scenarios: Combined tuple of every registered scenario.
        records: Combined tuple of every FramingRecord.
        categories: Read-only mapping scenario_id -> category label.
    """

    v2: InjectionCorpusRegistryV2
    extension_scenarios: tuple[BenchmarkScenario, ...]
    extension_records: tuple[FramingRecord, ...]
    scenarios: tuple[BenchmarkScenario, ...]
    records: tuple[FramingRecord, ...]
    categories: Mapping[str, str]

    # ------------------------------------------------------------------
    # v2-parity query surface
    # ------------------------------------------------------------------

    def all_scenarios(self) -> tuple[BenchmarkScenario, ...]:
        return self.scenarios

    def scenario_count(self) -> int:
        return len(self.scenarios)

    def by_category(self, category: str) -> tuple[BenchmarkScenario, ...]:
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
        return tuple(sorted({r.framing_strategy for r in self.records}))

    def authority_records(self) -> tuple[FramingRecord, ...]:
        return tuple(
            r for r in self.records
            if r.framing_strategy.startswith("authority_")
        )

    def by_scenario_id(self, scenario_id: str) -> BenchmarkScenario:
        for s in self.scenarios:
            if s.metadata.scenario_id == scenario_id:
                return s
        raise KeyError(f"No scenario with ID '{scenario_id}'")

    # ------------------------------------------------------------------
    # v3-only accessor
    # ------------------------------------------------------------------

    def temporal_records(self) -> tuple[FramingRecord, ...]:
        """Return every framing record whose family is ``temporal``."""
        return tuple(
            r for r in self.records
            if r.framing_strategy.startswith("temporal_")
        )


def _build_category_map_v3(
    v2_categories: Mapping[str, str],
    extension_scenarios: tuple[BenchmarkScenario, ...],
) -> Mapping[str, str]:
    mapping = dict(v2_categories)
    for s in extension_scenarios:
        sid = s.metadata.scenario_id
        # Temporal expansion is Category B framing.
        mapping.setdefault(sid, FRAMING)
    return MappingProxyType(mapping)


def build_registry_v3() -> InjectionCorpusRegistryV3:
    """Build a v3 registry from the current v2 + the Session 050 delta."""
    v2 = build_registry_v2()

    ext_scenarios = TEMPORAL_EXPANSION_SCENARIOS
    ext_records = TEMPORAL_EXPANSION_RECORDS

    combined_scenarios: tuple[BenchmarkScenario, ...] = tuple(
        list(v2.scenarios) + list(ext_scenarios)
    )
    combined_records: tuple[FramingRecord, ...] = tuple(
        list(v2.records) + list(ext_records)
    )
    categories = _build_category_map_v3(v2.categories, ext_scenarios)

    return InjectionCorpusRegistryV3(
        v2=v2,
        extension_scenarios=ext_scenarios,
        extension_records=ext_records,
        scenarios=combined_scenarios,
        records=combined_records,
        categories=categories,
    )
