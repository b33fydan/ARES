"""Tests for paired_scenario_mutator — Phase 7 / Session 058.

Covers:
    * MutationOperator construction and family validation.
    * MutatedScenarioPair invariants in __post_init__.
    * Six concrete v1 operators: each mutates value_hash, preserves
      skeleton_hash, and is deterministic given a fixed seed.
    * PairedScenarioMutator.mutate / mutate_all behavior including
      no-op skipping and unknown-operator handling.
    * Cross-operator sanity: every name unique, family in valid set.
    * Sanity-coverage on the full registry_v3: zero invariant errors,
      at least one valid pair per scenario.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta

import pytest

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.schemas.skeleton_equivalence import skeleton_hash
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutatedScenarioPair,
    MutationOperator,
    PairedScenarioMutator,
    SkeletonInvariantError,
    framing_prefix_transform,
    framing_suffix_transform,
    severity_decreaser_transform,
    severity_intensifier_transform,
    synonym_substitution_aggressive_transform,
    synonym_substitution_conservative_transform,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


_T0 = datetime(2026, 5, 8, 12, 0, 0)


# ---------------------------------------------------------------------------
# Synthetic fixtures
# ---------------------------------------------------------------------------


def _meta(scenario_id: str, fact_count: int = 1) -> ScenarioMetadata:
    return ScenarioMetadata(
        scenario_id=scenario_id,
        name=f"synthetic {scenario_id}",
        description="synthetic test fixture for mutator",
        mitre_attack_ids=("T1078",),
        mitre_tactic="initial-access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="mutator unit-test fixture",
    )


def _fact(
    *,
    fact_id: str = "f-001",
    entity_id: str = "host-A",
    field: str = "logon_type",
    value: object = "Approved remote logon performed by managed agent.",
    source_type: SourceType = SourceType.AUTH_LOG,
    timestamp: datetime | None = None,
) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=timestamp or _T0,
        provenance=Provenance(
            source_type=source_type,
            source_id="test-src",
            extracted_at=_T0,
        ),
    )


def _scenario(scenario_id: str, facts: list[Fact]) -> BenchmarkScenario:
    pkt = EvidencePacket(
        packet_id=scenario_id,
        time_window=TimeWindow(start=_T0, end=_T0 + timedelta(hours=1)),
    )
    for f in facts:
        pkt.add_fact(f)
    pkt.freeze()
    return BenchmarkScenario(
        metadata=_meta(scenario_id, fact_count=len(facts)),
        packet=pkt,
    )


def _prose_scenario() -> BenchmarkScenario:
    """Scenario with one prose-rich fact crafted to trigger all six v1
    operators: synonym lexicon hits, severity-intensifier keys, and
    severity-decreaser keys all appear."""
    return _scenario(
        "INJ-PROSE",
        [
            _fact(
                fact_id="f-001",
                value=(
                    "Standard remote logon session performed by managed "
                    "agent; the endpoint indicates suspicious activity is "
                    "highly suspicious and confirmed active."
                ),
            ),
        ],
    )


def _numeric_scenario() -> BenchmarkScenario:
    """Scenario with non-string values; v1 operators are no-ops."""
    return _scenario(
        "INJ-NUM",
        [_fact(fact_id="f-001", value=42)],
    )


# ---------------------------------------------------------------------------
# MutationOperator
# ---------------------------------------------------------------------------


class TestMutationOperator:
    def test_constructs_valid(self):
        op = MutationOperator(
            operator_name="op_x",
            family="synonym",
            description="x",
            transform=lambda s, seed: s,
        )
        assert op.operator_name == "op_x"

    def test_rejects_unknown_family(self):
        with pytest.raises(ValueError, match="family"):
            MutationOperator(
                operator_name="op_x",
                family="vibes",
                description="x",
                transform=lambda s, seed: s,
            )

    def test_rejects_empty_name(self):
        with pytest.raises(ValueError, match="operator_name"):
            MutationOperator(
                operator_name="",
                family="synonym",
                description="x",
                transform=lambda s, seed: s,
            )

    def test_is_frozen(self):
        op = OPERATORS_V1[0]
        with pytest.raises(FrozenInstanceError):
            op.operator_name = "renamed"  # type: ignore[misc]


# ---------------------------------------------------------------------------
# MutatedScenarioPair invariants
# ---------------------------------------------------------------------------


class TestPairInvariants:
    def test_valid_pair_constructs(self):
        baseline = _prose_scenario()
        mutated = framing_prefix_transform(baseline, seed=0)
        pair = MutatedScenarioPair(
            baseline_scenario=baseline,
            mutated_scenario=mutated,
            operator_applied=OPERATORS_V1[4],  # framing_prefix_v1
            skeleton_hash=skeleton_hash(baseline.packet),
            mutation_record=("f-001",),
        )
        assert pair.skeleton_hash == skeleton_hash(mutated.packet)

    def test_is_frozen(self):
        baseline = _prose_scenario()
        mutated = framing_prefix_transform(baseline, seed=0)
        pair = MutatedScenarioPair(
            baseline_scenario=baseline,
            mutated_scenario=mutated,
            operator_applied=OPERATORS_V1[4],
            skeleton_hash=skeleton_hash(baseline.packet),
        )
        with pytest.raises(FrozenInstanceError):
            pair.skeleton_hash = "x" * 32  # type: ignore[misc]

    def test_no_op_pair_rejected(self):
        baseline = _prose_scenario()
        with pytest.raises(SkeletonInvariantError, match="no-op"):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=baseline,  # identical
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_skeleton_break_field_change_rejected(self):
        baseline = _prose_scenario()
        mutated_facts = [
            _fact(fact_id="f-001", field="different_field", value="X"),
        ]
        mutated = _scenario("INJ-PROSE", mutated_facts)
        with pytest.raises(SkeletonInvariantError):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_skeleton_break_entity_id_change_rejected(self):
        baseline = _prose_scenario()
        mutated_facts = [
            _fact(fact_id="f-001", entity_id="host-Z", value="X"),
        ]
        mutated = _scenario("INJ-PROSE", mutated_facts)
        with pytest.raises(SkeletonInvariantError):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_skeleton_break_source_type_change_rejected(self):
        baseline = _prose_scenario()
        mutated_facts = [
            _fact(fact_id="f-001", source_type=SourceType.NETFLOW, value="X"),
        ]
        mutated = _scenario("INJ-PROSE", mutated_facts)
        with pytest.raises(SkeletonInvariantError):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_skeleton_break_timestamp_change_rejected(self):
        baseline = _prose_scenario()
        mutated_facts = [
            _fact(
                fact_id="f-001",
                value="X",
                timestamp=_T0 + timedelta(days=1),
            ),
        ]
        mutated = _scenario("INJ-PROSE", mutated_facts)
        with pytest.raises(SkeletonInvariantError, match="timestamp"):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_skeleton_break_fact_count_change_rejected(self):
        baseline = _prose_scenario()
        mutated_facts = [
            _fact(fact_id="f-001", value="X"),
            _fact(fact_id="f-002", entity_id="host-B", value="Y"),
        ]
        mutated = _scenario("INJ-PROSE", mutated_facts)
        # Adding a fact also changes the skeleton hash (more (fid, field,
        # entity, source) tuples in the canonical sort), so the hash
        # check fires first. The fact-count guard remains in production
        # as defense in depth.
        with pytest.raises(SkeletonInvariantError):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[0],
                skeleton_hash=skeleton_hash(baseline.packet),
            )

    def test_recorded_skeleton_hash_must_match(self):
        baseline = _prose_scenario()
        mutated = framing_prefix_transform(baseline, seed=0)
        with pytest.raises(SkeletonInvariantError, match="disagrees"):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[4],
                skeleton_hash="0" * 32,  # bogus
            )

    def test_mutation_record_must_be_tuple(self):
        baseline = _prose_scenario()
        mutated = framing_prefix_transform(baseline, seed=0)
        with pytest.raises(TypeError, match="tuple"):
            MutatedScenarioPair(
                baseline_scenario=baseline,
                mutated_scenario=mutated,
                operator_applied=OPERATORS_V1[4],
                skeleton_hash=skeleton_hash(baseline.packet),
                mutation_record=["f-001"],  # type: ignore[arg-type]
            )


# ---------------------------------------------------------------------------
# Per-operator behavior
# ---------------------------------------------------------------------------


_TRANSFORMS_TO_TEST = [
    ("synonym_substitution_conservative_v1", synonym_substitution_conservative_transform),
    ("synonym_substitution_aggressive_v1", synonym_substitution_aggressive_transform),
    ("severity_intensifier_v1", severity_intensifier_transform),
    ("severity_decreaser_v1", severity_decreaser_transform),
    ("framing_prefix_v1", framing_prefix_transform),
    ("framing_suffix_v1", framing_suffix_transform),
]


class TestOperatorMutates:
    """Each operator must change at least one Fact.value_hash on a
    prose-rich scenario."""

    @pytest.mark.parametrize("name,transform", _TRANSFORMS_TO_TEST)
    def test_transform_changes_value_hash_on_prose(self, name, transform):
        baseline = _prose_scenario()
        mutated = transform(baseline, seed=0)
        b_hashes = {f.fact_id: f.value_hash for f in baseline.packet.get_all_facts()}
        m_hashes = {f.fact_id: f.value_hash for f in mutated.packet.get_all_facts()}
        assert any(b_hashes[fid] != m_hashes[fid] for fid in b_hashes), (
            f"{name} did not change any Fact.value_hash"
        )


class TestOperatorPreservesSkeleton:
    @pytest.mark.parametrize("name,transform", _TRANSFORMS_TO_TEST)
    def test_skeleton_hash_unchanged(self, name, transform):
        baseline = _prose_scenario()
        mutated = transform(baseline, seed=0)
        assert skeleton_hash(baseline.packet) == skeleton_hash(mutated.packet), (
            f"{name} broke the skeleton hash"
        )


class TestOperatorDeterministic:
    @pytest.mark.parametrize("name,transform", _TRANSFORMS_TO_TEST)
    def test_same_seed_same_output(self, name, transform):
        baseline = _prose_scenario()
        a = transform(baseline, seed=42)
        b = transform(baseline, seed=42)
        a_values = {f.fact_id: f.value for f in a.packet.get_all_facts()}
        b_values = {f.fact_id: f.value for f in b.packet.get_all_facts()}
        assert a_values == b_values, (
            f"{name} non-deterministic across two runs at seed=42"
        )


class TestOperatorOutputsValidScenario:
    @pytest.mark.parametrize("name,transform", _TRANSFORMS_TO_TEST)
    def test_output_is_benchmark_scenario(self, name, transform):
        baseline = _prose_scenario()
        mutated = transform(baseline, seed=0)
        assert isinstance(mutated, BenchmarkScenario)
        assert mutated.metadata is baseline.metadata
        # Same fact_id set; same field/entity/source_type per fact.
        b_facts = {f.fact_id: f for f in baseline.packet.get_all_facts()}
        m_facts = {f.fact_id: f for f in mutated.packet.get_all_facts()}
        assert set(b_facts) == set(m_facts)
        for fid, b in b_facts.items():
            m = m_facts[fid]
            assert b.field == m.field
            assert b.entity_id == m.entity_id
            assert b.provenance.source_type == m.provenance.source_type
            assert b.timestamp == m.timestamp


class TestOperatorOnNumericValues:
    """Numeric (non-string) values should make every v1 operator a no-op."""

    @pytest.mark.parametrize("name,transform", _TRANSFORMS_TO_TEST)
    def test_numeric_value_is_no_op(self, name, transform):
        baseline = _numeric_scenario()
        mutated = transform(baseline, seed=0)
        b = next(iter(baseline.packet.get_all_facts()))
        m = next(iter(mutated.packet.get_all_facts()))
        assert b.value == m.value


# ---------------------------------------------------------------------------
# Mutator behavior
# ---------------------------------------------------------------------------


class TestMutatorBasic:
    def test_constructs_with_default_operators(self):
        m = PairedScenarioMutator()
        assert m.operators == OPERATORS_V1
        assert m.seed == 0
        assert len(m.operator_names()) == 6

    def test_rejects_empty_operators(self):
        with pytest.raises(ValueError, match="non-empty"):
            PairedScenarioMutator(operators=())

    def test_rejects_duplicate_operator_names(self):
        op = OPERATORS_V1[0]
        with pytest.raises(ValueError, match="unique"):
            PairedScenarioMutator(operators=(op, op))

    def test_mutate_unknown_operator_raises(self):
        m = PairedScenarioMutator()
        with pytest.raises(KeyError, match="not registered"):
            m.mutate(_prose_scenario(), "nonexistent_operator")


class TestMutateProducesValidPair:
    def test_returns_pair_with_correct_provenance(self):
        m = PairedScenarioMutator()
        baseline = _prose_scenario()
        pair = m.mutate(baseline, "framing_prefix_v1")
        assert pair.operator_applied.operator_name == "framing_prefix_v1"
        assert pair.skeleton_hash == skeleton_hash(baseline.packet)
        assert "f-001" in pair.mutation_record


class TestMutateAll:
    def test_returns_one_pair_per_operator_on_prose(self):
        m = PairedScenarioMutator()
        baseline = _prose_scenario()
        pairs = m.mutate_all(baseline)
        # All six operators hit a prose-rich scenario.
        assert len(pairs) == 6
        names = [p.operator_applied.operator_name for p in pairs]
        assert sorted(names) == sorted(op.operator_name for op in OPERATORS_V1)

    def test_skips_no_op_operators_silently(self):
        m = PairedScenarioMutator()
        baseline = _numeric_scenario()
        pairs = m.mutate_all(baseline)
        # Numeric values can't be mutated by v1 operators.
        assert pairs == ()

    def test_deterministic_across_two_instances(self):
        baseline = _prose_scenario()
        m1 = PairedScenarioMutator(seed=7)
        m2 = PairedScenarioMutator(seed=7)
        pairs1 = m1.mutate_all(baseline)
        pairs2 = m2.mutate_all(baseline)
        v1 = [
            tuple((f.fact_id, f.value) for f in p.mutated_scenario.packet.get_all_facts())
            for p in pairs1
        ]
        v2 = [
            tuple((f.fact_id, f.value) for f in p.mutated_scenario.packet.get_all_facts())
            for p in pairs2
        ]
        assert v1 == v2


# ---------------------------------------------------------------------------
# Cross-operator sanity
# ---------------------------------------------------------------------------


class TestRegistryV1:
    def test_all_operator_names_unique(self):
        names = [op.operator_name for op in OPERATORS_V1]
        assert len(set(names)) == len(names)

    def test_all_families_in_valid_set(self):
        valid = {"synonym", "severity", "framing"}
        for op in OPERATORS_V1:
            assert op.family in valid

    def test_six_operators_registered(self):
        assert len(OPERATORS_V1) == 6


# ---------------------------------------------------------------------------
# Sanity coverage on full registry_v3
# ---------------------------------------------------------------------------


class TestSanityCoverageOnRegistryV3:
    def test_no_skeleton_invariant_errors_across_corpus(self):
        registry = build_registry_v3()
        m = PairedScenarioMutator()
        # If any pair violates invariance, MutatedScenarioPair raises in
        # __post_init__ during mutate_all, which would fail this test.
        for scenario in registry.all_scenarios():
            m.mutate_all(scenario)

    def test_at_least_one_valid_pair_per_scenario(self):
        registry = build_registry_v3()
        m = PairedScenarioMutator()
        scenarios_with_zero_pairs: list[str] = []
        for scenario in registry.all_scenarios():
            pairs = m.mutate_all(scenario)
            if not pairs:
                scenarios_with_zero_pairs.append(scenario.metadata.scenario_id)
        # Every registry_v3 scenario has at least one string-valued
        # Fact, so all should produce >= 1 valid pair via at least the
        # framing_prefix or framing_suffix operators (which are
        # universally applicable to any string value).
        assert scenarios_with_zero_pairs == [], (
            f"scenarios produced zero valid pairs: {scenarios_with_zero_pairs}"
        )
