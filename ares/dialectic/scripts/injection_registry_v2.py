"""Session 049 v2 injection-corpus registry.

Wraps the Session 047 :class:`InjectionCorpusRegistry` with the 3
Session 049 authority-family scenarios (INJ-028..030) layered on top.
The v1 registry module remains untouched (per the do-not-modify list).

Total scenario count in v2: **30**
    Direct        : 4  (INJ-001..004)
    Framing       : 22 (INJ-005..008 seed + INJ-013..027 expansion +
                        INJ-028..030 authority expansion)
    Propagation   : 4  (INJ-009..012)

Authority family in v2 grows from 3 to 6:
    INJ-016, INJ-017, INJ-018 (Session 047) + INJ-028, INJ-029, INJ-030
    (Session 049).

Public API:
    InjectionCorpusRegistryV2       Frozen dataclass (wraps v1 + delta)
    build_registry_v2()             Build against current modules
    DIRECT, FRAMING, PROPAGATION    Re-exported for ergonomic imports
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Mapping

from ares.dialectic.scripts.injection_corpus_b_authority_expansion import (
    AUTHORITY_EXPANSION_RECORDS,
    AUTHORITY_EXPANSION_SCENARIOS,
)
from ares.dialectic.scripts.injection_corpus_b_framing import FramingRecord
from ares.dialectic.scripts.injection_registry import (
    DIRECT,
    FRAMING,
    PROPAGATION,
    InjectionCorpusRegistry,
    build_registry,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


@dataclass(frozen=True)
class InjectionCorpusRegistryV2:
    """Immutable view over v1 + the Session 049 authority expansion.

    Attributes:
        v1: The Session 047 registry (27 scenarios).
        extension_scenarios: The 3 Session 049 authority-family
            scenarios (INJ-028..030).
        extension_records: Matching FramingRecord wrappers.
        scenarios: Combined tuple of every registered scenario.
        records: Combined tuple of every FramingRecord across the
            v1 framing expansion and the v2 authority expansion.
        categories: Read-only mapping scenario_id -> category label.
    """

    v1: InjectionCorpusRegistry
    extension_scenarios: tuple[BenchmarkScenario, ...]
    extension_records: tuple[FramingRecord, ...]
    scenarios: tuple[BenchmarkScenario, ...]
    records: tuple[FramingRecord, ...]
    categories: Mapping[str, str]

    # ------------------------------------------------------------------
    # v1-parity query surface
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

    # ------------------------------------------------------------------
    # v2-only query surface
    # ------------------------------------------------------------------

    def authority_records(self) -> tuple[FramingRecord, ...]:
        """Return every framing record whose family is ``authority``.

        A record is in the authority family when its ``framing_strategy``
        begins with ``authority_``. Spans both Session 047 seed
        (``authority_vendor_implication``, ``authority_industry_consensus``,
        ``authority_passive_voice_attribution``) and Session 049 expansion
        (``authority_credentialed_source``, ``authority_automated_system``,
        ``authority_tool_output``).
        """
        return tuple(
            r for r in self.records
            if r.framing_strategy.startswith("authority_")
        )

    def by_scenario_id(self, scenario_id: str) -> BenchmarkScenario:
        """Look up a scenario by ID across both v1 and v2 sources."""
        for s in self.scenarios:
            if s.metadata.scenario_id == scenario_id:
                return s
        raise KeyError(f"No scenario with ID '{scenario_id}'")


def _build_category_map_v2(
    v1_categories: Mapping[str, str],
    extension_scenarios: tuple[BenchmarkScenario, ...],
) -> Mapping[str, str]:
    """Merge the v1 category map with the new authority-expansion IDs."""
    mapping = dict(v1_categories)
    for s in extension_scenarios:
        sid = s.metadata.scenario_id
        # Session 049 expansion scenarios are all FRAMING (authority family).
        mapping.setdefault(sid, FRAMING)
    return MappingProxyType(mapping)


def build_registry_v2() -> InjectionCorpusRegistryV2:
    """Build a v2 registry from the current v1 + the Session 049 delta."""
    v1 = build_registry()

    ext_scenarios = AUTHORITY_EXPANSION_SCENARIOS
    ext_records = AUTHORITY_EXPANSION_RECORDS

    combined_scenarios: tuple[BenchmarkScenario, ...] = tuple(
        list(v1.scenarios) + list(ext_scenarios)
    )
    combined_records: tuple[FramingRecord, ...] = tuple(
        list(v1.records) + list(ext_records)
    )

    categories = _build_category_map_v2(v1.categories, ext_scenarios)

    return InjectionCorpusRegistryV2(
        v1=v1,
        extension_scenarios=ext_scenarios,
        extension_records=ext_records,
        scenarios=combined_scenarios,
        records=combined_records,
        categories=categories,
    )
