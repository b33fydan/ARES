"""Tests for paired_scenario_mutator_v2 — Phase 7 / Session 058.5.

Covers:
    * The pre-registered design corrections, made testable:
        - Conservative ↔ aggressive lexicons disjoint by construction
          (both keys and values).
        - Severity-table normalization axis bites on framing scenarios
          where v1's severity operators were no-ops.
    * Per-operator behavior (mutates value_hash, preserves skeleton
      hash, deterministic, valid output).
    * Roster shape (6 operators, 2-2-2 family split, framing ops
      imported by-identity from v1).
    * Sanity coverage on registry_v3 (zero invariant errors).
"""

from __future__ import annotations

from datetime import datetime, timedelta

import pytest

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.schemas.skeleton_equivalence import skeleton_hash
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    PairedScenarioMutator,
)
from ares.dialectic.scripts.non_interference.paired_scenario_mutator_v2 import (
    AGGRESSIVE_LEXICON_V2,
    CONSERVATIVE_LEXICON_V2,
    OPERATORS_V2,
    SEVERITY_DECREASER_TABLE_V2,
    SEVERITY_INTENSIFIER_TABLE_V2,
    get_v2_operator_set,
    severity_decreaser_v2_transform,
    severity_intensifier_v2_transform,
    synonym_substitution_aggressive_v2_transform,
    synonym_substitution_conservative_v2_transform,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


_T0 = datetime(2026, 5, 8, 12, 0, 0)


# ---------------------------------------------------------------------------
# Synthetic builders
# ---------------------------------------------------------------------------


def _meta(scenario_id: str, fact_count: int = 1) -> ScenarioMetadata:
    return ScenarioMetadata(
        scenario_id=scenario_id,
        name=f"synthetic {scenario_id}",
        description="synthetic test fixture for mutator v2",
        mitre_attack_ids=("T1078",),
        mitre_tactic="initial-access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="mutator v2 unit-test fixture",
    )


def _scenario(scenario_id: str, value: object) -> BenchmarkScenario:
    pkt = EvidencePacket(
        packet_id=scenario_id,
        time_window=TimeWindow(start=_T0, end=_T0 + timedelta(hours=1)),
    )
    pkt.add_fact(
        Fact(
            fact_id="f-001",
            entity_id="host-A",
            entity_type=EntityType.NODE,
            field="logon_type",
            value=value,
            timestamp=_T0,
            provenance=Provenance(
                source_type=SourceType.AUTH_LOG,
                source_id="test-src",
                extracted_at=_T0,
            ),
        )
    )
    pkt.freeze()
    return BenchmarkScenario(metadata=_meta(scenario_id), packet=pkt)


def _v2_prose() -> BenchmarkScenario:
    """Prose containing trigger words for all four new v2 operators."""
    return _scenario(
        "INJ-V2-PROSE",
        "The system observed an approved scheduled compromise activity by "
        "the user account; the credential payload may be confirmed.",
    )


def _framing_prose() -> BenchmarkScenario:
    """Framing-style prose: normalization-axis vocabulary, no hedges.

    Mirrors the Phase 6 framing scenarios that v1's severity operators
    were a no-op on. The v2 normalization axis should bite this.
    """
    return _scenario(
        "INJ-FRAMING",
        "Standard scheduled deployment; approved routine activity by "
        "authorized personnel during expected maintenance window.",
    )


# ---------------------------------------------------------------------------
# THE pre-registered design change as a typed property
# ---------------------------------------------------------------------------


class TestLexiconDisjointness:
    """Conservative and aggressive v2 lexicons must be disjoint by
    construction. This is the design correction that fixes v1's
    14/33 collision failure."""

    def test_keys_disjoint(self):
        assert set(CONSERVATIVE_LEXICON_V2.keys()).isdisjoint(
            set(AGGRESSIVE_LEXICON_V2.keys())
        ), (
            "lexicon keys overlap: "
            f"{set(CONSERVATIVE_LEXICON_V2) & set(AGGRESSIVE_LEXICON_V2)}"
        )

    def test_values_disjoint(self):
        assert set(CONSERVATIVE_LEXICON_V2.values()).isdisjoint(
            set(AGGRESSIVE_LEXICON_V2.values())
        ), (
            "lexicon values overlap: "
            f"{set(CONSERVATIVE_LEXICON_V2.values()) & set(AGGRESSIVE_LEXICON_V2.values())}"
        )

    def test_neither_lexicon_empty(self):
        assert len(CONSERVATIVE_LEXICON_V2) > 0
        assert len(AGGRESSIVE_LEXICON_V2) > 0

    def test_no_self_collisions_within_lexicon(self):
        # A key cannot also be its own value (would be a no-op
        # substitution).
        for key, val in CONSERVATIVE_LEXICON_V2.items():
            assert key.lower() != val.lower(), (
                f"conservative self-collision: {key!r} -> {val!r}"
            )
        for key, val in AGGRESSIVE_LEXICON_V2.items():
            assert key.lower() != val.lower(), (
                f"aggressive self-collision: {key!r} -> {val!r}"
            )


# ---------------------------------------------------------------------------
# Per-operator behavior (4 new operators)
# ---------------------------------------------------------------------------


_NEW_TRANSFORMS = [
    ("synonym_substitution_conservative_v2", synonym_substitution_conservative_v2_transform),
    ("synonym_substitution_aggressive_v2", synonym_substitution_aggressive_v2_transform),
    ("severity_intensifier_v2", severity_intensifier_v2_transform),
    ("severity_decreaser_v2", severity_decreaser_v2_transform),
]


class TestNewOperatorMutates:
    @pytest.mark.parametrize("name,transform", _NEW_TRANSFORMS)
    def test_changes_value_hash_on_v2_prose(self, name, transform):
        baseline = _v2_prose()
        mutated = transform(baseline, seed=0)
        b = next(iter(baseline.packet.get_all_facts()))
        m = next(iter(mutated.packet.get_all_facts()))
        assert b.value_hash != m.value_hash, (
            f"{name} did not mutate the v2 prose fixture"
        )


class TestNewOperatorPreservesSkeleton:
    @pytest.mark.parametrize("name,transform", _NEW_TRANSFORMS)
    def test_skeleton_unchanged(self, name, transform):
        baseline = _v2_prose()
        mutated = transform(baseline, seed=0)
        assert skeleton_hash(baseline.packet) == skeleton_hash(mutated.packet)


class TestNewOperatorDeterministic:
    @pytest.mark.parametrize("name,transform", _NEW_TRANSFORMS)
    def test_same_seed_same_output(self, name, transform):
        baseline = _v2_prose()
        a = transform(baseline, seed=42)
        b = transform(baseline, seed=42)
        a_vals = {f.fact_id: f.value for f in a.packet.get_all_facts()}
        b_vals = {f.fact_id: f.value for f in b.packet.get_all_facts()}
        assert a_vals == b_vals


class TestNewOperatorOutputsValid:
    @pytest.mark.parametrize("name,transform", _NEW_TRANSFORMS)
    def test_output_is_benchmark_scenario(self, name, transform):
        baseline = _v2_prose()
        mutated = transform(baseline, seed=0)
        assert isinstance(mutated, BenchmarkScenario)
        assert mutated.metadata is baseline.metadata


# ---------------------------------------------------------------------------
# THE empirical bet: severity v2 bites framing-style prose
# ---------------------------------------------------------------------------


class TestSeverityV2BitesFramingScenarios:
    """The v2 severity table expansion is an empirical bet that the
    normalization-axis entries make the operators applicable to
    framing-class prose where v1 was a no-op. This is the bar the
    session must clear."""

    def test_intensifier_v2_bites_framing_prose(self):
        baseline = _framing_prose()
        # v1 intensifier on this prose: should be a no-op (no hedges
        # like "may", "might", "suspicious").
        from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
            severity_intensifier_transform as v1_intensifier,
        )
        v1_mutated = v1_intensifier(baseline, seed=0)
        v1_b = next(iter(baseline.packet.get_all_facts()))
        v1_m = next(iter(v1_mutated.packet.get_all_facts()))
        assert v1_b.value_hash == v1_m.value_hash, (
            "v1 intensifier bit framing prose; the test fixture is "
            "unrepresentative of Phase 6 framing scenarios"
        )

        # v2 intensifier on the same prose: must NOT be a no-op.
        v2_mutated = severity_intensifier_v2_transform(baseline, seed=0)
        v2_m = next(iter(v2_mutated.packet.get_all_facts()))
        assert v1_b.value_hash != v2_m.value_hash, (
            "v2 intensifier still no-op on framing prose; the v2 "
            "normalization axis failed to bite. v2 design correction "
            "did not work."
        )

    def test_intensifier_v2_bites_at_least_three_corpus_framing_scenarios(self):
        """Concrete corpus check: v2 intensifier must bite at least
        three framing-class scenarios that v1 intensifier did NOT
        bite. Cited in the debrief as evidence the design change
        worked."""
        from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
            severity_intensifier_transform as v1_intensifier,
        )
        registry = build_registry_v3()
        framing_scenarios = registry.by_category("FRAMING")

        v1_no_ops: list[str] = []
        for s in framing_scenarios:
            v1_mut = v1_intensifier(s, seed=0)
            same = all(
                bf.value_hash == mf.value_hash
                for bf, mf in zip(
                    sorted(s.packet.get_all_facts(), key=lambda f: f.fact_id),
                    sorted(v1_mut.packet.get_all_facts(), key=lambda f: f.fact_id),
                )
            )
            if same:
                v1_no_ops.append(s.metadata.scenario_id)

        # v2 must bite at least 3 scenarios that v1 was a no-op on.
        v2_bites: list[str] = []
        for sid in v1_no_ops:
            s = registry.by_scenario_id(sid)
            v2_mut = severity_intensifier_v2_transform(s, seed=0)
            different = any(
                bf.value_hash != mf.value_hash
                for bf, mf in zip(
                    sorted(s.packet.get_all_facts(), key=lambda f: f.fact_id),
                    sorted(v2_mut.packet.get_all_facts(), key=lambda f: f.fact_id),
                )
            )
            if different:
                v2_bites.append(sid)

        assert len(v2_bites) >= 3, (
            f"v2 intensifier bit only {len(v2_bites)} of {len(v1_no_ops)} "
            f"v1-no-op framing scenarios; brief required >= 3. "
            f"v2 bites: {v2_bites}"
        )


# ---------------------------------------------------------------------------
# Roster shape
# ---------------------------------------------------------------------------


class TestV2Roster:
    def test_returns_six_operators(self):
        roster = get_v2_operator_set()
        assert len(roster) == 6

    def test_returns_OPERATORS_V2_constant(self):
        assert get_v2_operator_set() is OPERATORS_V2

    def test_unique_operator_names(self):
        names = [op.operator_name for op in OPERATORS_V2]
        assert len(set(names)) == len(names)

    def test_two_synonym_two_severity_two_framing(self):
        family_counts: dict[str, int] = {}
        for op in OPERATORS_V2:
            family_counts[op.family] = family_counts.get(op.family, 0) + 1
        assert family_counts == {"synonym": 2, "severity": 2, "framing": 2}

    def test_framing_operators_imported_by_identity_from_v1(self):
        v1_by_name = {op.operator_name: op for op in OPERATORS_V1}
        v2_by_name = {op.operator_name: op for op in OPERATORS_V2}
        # Identity (`is`) check, not equality. The framing ops in v2
        # roster must be the same Python objects as in v1.
        assert v2_by_name["framing_prefix_v1"] is v1_by_name["framing_prefix_v1"]
        assert v2_by_name["framing_suffix_v1"] is v1_by_name["framing_suffix_v1"]

    def test_four_new_operators_have_v2_suffix(self):
        v2_only_names = {
            op.operator_name
            for op in OPERATORS_V2
            if op.family in {"synonym", "severity"}
        }
        for name in v2_only_names:
            assert name.endswith("_v2"), (
                f"new operator {name!r} should have a _v2 suffix"
            )

    def test_v1_module_unchanged(self):
        # The v1 OPERATORS_V1 tuple must still be exactly 6 operators
        # with v1 names. Sanity check that the v2 module did not
        # accidentally mutate v1.
        names = [op.operator_name for op in OPERATORS_V1]
        assert names == [
            "synonym_substitution_conservative_v1",
            "synonym_substitution_aggressive_v1",
            "severity_intensifier_v1",
            "severity_decreaser_v1",
            "framing_prefix_v1",
            "framing_suffix_v1",
        ]


# ---------------------------------------------------------------------------
# Severity tables — structural shape checks
# ---------------------------------------------------------------------------


class TestSeverityTablesV2:
    def test_intensifier_v2_includes_v1_hedge_axis_keys(self):
        # The brief preserves these v1 entries verbatim in v2.
        for key in ("may", "might", "appears to", "possibly", "suspicious"):
            assert key in SEVERITY_INTENSIFIER_TABLE_V2

    def test_intensifier_v2_includes_normalization_axis_keys(self):
        # The brief pre-registers these new entries.
        for key in (
            "standard",
            "approved",
            "scheduled",
            "routine",
            "expected",
            "authorized",
        ):
            assert key in SEVERITY_INTENSIFIER_TABLE_V2

    def test_decreaser_v2_includes_normalization_axis_keys(self):
        for key in (
            "anomalous",
            "irregular",
            "unauthorized",
            "unscheduled",
            "unexpected",
        ):
            assert key in SEVERITY_DECREASER_TABLE_V2

    def test_decreaser_v2_includes_v1_hedge_axis_keys(self):
        for key in ("is", "definitely", "confirmed", "malicious"):
            assert key in SEVERITY_DECREASER_TABLE_V2

    def test_cleanly_inverse_pairs_round_trip(self):
        # Most normalization-axis pairs round-trip cleanly. Note that
        # the brief specifies a chain (authorized -> unauthorized ->
        # approved) for one axis, not a pair, so "authorized" is
        # excluded from this round-trip check by design.
        inverse_pairs = {
            "standard": "anomalous",
            "scheduled": "unscheduled",
            "expected": "unexpected",
            "routine": "irregular",
        }
        for k, v in inverse_pairs.items():
            assert SEVERITY_INTENSIFIER_TABLE_V2[k] == v
            assert SEVERITY_DECREASER_TABLE_V2[v] == k


# ---------------------------------------------------------------------------
# Sanity coverage on full registry_v3
# ---------------------------------------------------------------------------


class TestSanityCoverageOnRegistryV3:
    def test_no_skeleton_invariant_errors(self):
        registry = build_registry_v3()
        m = PairedScenarioMutator(operators=OPERATORS_V2)
        for scenario in registry.all_scenarios():
            # mutate_all rejects pairs that violate skeleton invariance
            # in MutatedScenarioPair.__post_init__. If any operator in
            # v2 produces a malformed pair, this test fails.
            m.mutate_all(scenario)

    def test_at_least_one_valid_pair_per_scenario(self):
        registry = build_registry_v3()
        m = PairedScenarioMutator(operators=OPERATORS_V2)
        zero_pair_scenarios: list[str] = []
        for scenario in registry.all_scenarios():
            pairs = m.mutate_all(scenario)
            if not pairs:
                zero_pair_scenarios.append(scenario.metadata.scenario_id)
        # Every scenario in registry_v3 has string-valued facts, so at
        # minimum the framing operators produce one pair each.
        assert zero_pair_scenarios == [], (
            f"v2 produced zero pairs on: {zero_pair_scenarios}"
        )
