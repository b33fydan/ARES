"""Tests for operator_orthogonality audit — Phase 7 / Session 058.

Covers:
    * OrthogonalityReport dataclass invariants in __post_init__.
    * JSON round-trip preserves shape.
    * Synthetic-corpus PASS / FAIL behavior.
    * Live registry_v3 audit emits a valid report.
    * CLI writes the JSON artifact.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.operator_orthogonality import (
    DEFAULT_OUTPUT_PATH,
    MAX_ACCEPTABLE_APPLICABILITY_GAP,
    MAX_ACCEPTABLE_COLLISION_COUNT,
    OrthogonalityReport,
    audit_scenarios,
    main,
    write_report,
)
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    OPERATORS_V1,
    MutationOperator,
    PairedScenarioMutator,
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
        description="synthetic test fixture for orthogonality",
        mitre_attack_ids=("T1078",),
        mitre_tactic="initial-access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="orthogonality test fixture",
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


def _prose_scenario(sid: str = "INJ-A") -> BenchmarkScenario:
    return _scenario(
        sid,
        "Standard remote logon session performed by managed agent; "
        "the endpoint indicates suspicious activity is highly suspicious "
        "and confirmed active.",
    )


# ---------------------------------------------------------------------------
# OrthogonalityReport invariants
# ---------------------------------------------------------------------------


def _report(**overrides) -> OrthogonalityReport:
    base = dict(
        audit_version="v1",
        registry_label="test",
        n_scenarios=1,
        operators=("op_a", "op_b"),
        applicability_gap={"op_a": 0, "op_b": 0},
        pairwise_collision_matrix={"op_a__op_b": 0},
        max_acceptable_collision_count=2,
        max_acceptable_applicability_gap=10,
        decision="PASS",
        failed_pairs=(),
        failed_operators_by_gap=(),
    )
    base.update(overrides)
    return OrthogonalityReport(**base)


class TestReportInvariants:
    def test_constructs_valid_pass(self):
        r = _report()
        assert r.decision == "PASS"

    def test_constructs_valid_fail_via_collision(self):
        r = _report(
            pairwise_collision_matrix={"op_a__op_b": 5},
            decision="FAIL",
            failed_pairs=("op_a__op_b",),
        )
        assert r.decision == "FAIL"

    def test_rejects_unknown_decision(self):
        with pytest.raises(ValueError, match="decision"):
            _report(decision="MAYBE")

    def test_rejects_inconsistent_decision(self):
        # Supply matching failed_pairs so the failed_pairs check passes;
        # the inconsistent-decision check fires next.
        with pytest.raises(ValueError, match="inconsistent"):
            _report(
                pairwise_collision_matrix={"op_a__op_b": 5},
                failed_pairs=("op_a__op_b",),
                decision="PASS",  # should be FAIL
            )

    def test_rejects_failed_pairs_disagreeing_with_matrix(self):
        with pytest.raises(ValueError, match="failed_pairs"):
            _report(
                pairwise_collision_matrix={"op_a__op_b": 0},
                failed_pairs=("op_a__op_b",),  # nothing actually failed
                decision="FAIL",
            )

    def test_rejects_failed_ops_disagreeing_with_gaps(self):
        with pytest.raises(ValueError, match="failed_operators_by_gap"):
            _report(
                applicability_gap={"op_a": 0, "op_b": 0},
                failed_operators_by_gap=("op_a",),
                decision="FAIL",
            )


class TestReportSerialization:
    def test_to_dict_round_trip_shape(self):
        r = _report(
            pairwise_collision_matrix={"op_a__op_b": 5},
            decision="FAIL",
            failed_pairs=("op_a__op_b",),
        )
        d = r.to_dict()
        assert d["decision"] == "FAIL"
        assert d["failed_pairs"] == ["op_a__op_b"]
        assert d["decision_threshold"]["max_acceptable_collision_count"] == 2
        # JSON is dumpable.
        assert json.loads(json.dumps(d))["audit_version"] == "v1"


# ---------------------------------------------------------------------------
# audit_scenarios — synthetic
# ---------------------------------------------------------------------------


def _identity_op(name: str) -> MutationOperator:
    """Operator that returns the input scenario unchanged (no-op).

    Used to construct synthetic FAIL cases by gap.
    """

    def _no_op_transform(s, seed):
        _ = seed
        return s

    return MutationOperator(
        operator_name=name,
        family="synonym",
        description=f"identity {name}",
        transform=_no_op_transform,
    )


class TestAuditOnSynthetic:
    def test_pass_with_six_distinct_operators_on_prose(self):
        scenarios = [_prose_scenario("INJ-A"), _prose_scenario("INJ-B")]
        report = audit_scenarios(
            scenarios,
            registry_label="synthetic_pass",
            mutator=PairedScenarioMutator(operators=OPERATORS_V1),
        )
        # All 6 v1 operators bite this fixture; collisions should be 0
        # for every pair.
        assert all(
            v == 0 for v in report.pairwise_collision_matrix.values()
        ), f"unexpected collisions: {report.pairwise_collision_matrix}"
        assert all(
            gap == 0 for gap in report.applicability_gap.values()
        ), f"unexpected applicability gaps: {report.applicability_gap}"
        assert report.decision == "PASS"

    def test_fail_with_two_no_op_operators(self):
        scenarios = [_prose_scenario("INJ-A") for _ in range(15)]
        # Two no-op operators; both will accumulate gap = 15 > 10.
        ops = (_identity_op("op_dead_a"), _identity_op("op_dead_b"))
        report = audit_scenarios(
            scenarios,
            registry_label="synthetic_fail_gap",
            mutator=PairedScenarioMutator(operators=ops),
        )
        assert report.decision == "FAIL"
        assert set(report.failed_operators_by_gap) == {"op_dead_a", "op_dead_b"}

    def test_fail_with_colliding_operators(self):
        # Two operators that produce identical mutations on every prose
        # scenario must collide.
        from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
            framing_prefix_transform,
        )

        op1 = MutationOperator(
            operator_name="framing_prefix_alpha",
            family="framing",
            description="alpha",
            transform=framing_prefix_transform,
        )
        op2 = MutationOperator(
            operator_name="framing_prefix_beta",
            family="framing",
            description="beta (identical body)",
            transform=framing_prefix_transform,
        )
        scenarios = [_prose_scenario(f"INJ-{i}") for i in range(5)]
        report = audit_scenarios(
            scenarios,
            registry_label="synthetic_fail_collision",
            mutator=PairedScenarioMutator(operators=(op1, op2)),
        )
        assert report.decision == "FAIL"
        assert any(
            v > MAX_ACCEPTABLE_COLLISION_COUNT
            for v in report.pairwise_collision_matrix.values()
        )

    def test_collision_only_counted_when_both_apply(self):
        # If one operator is a no-op on a scenario, no collision is
        # recorded for that scenario. Verifies the audit doesn't
        # double-count gaps as collisions.
        from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
            framing_prefix_transform,
        )

        op_real = MutationOperator(
            operator_name="real_op",
            family="framing",
            description="real",
            transform=framing_prefix_transform,
        )
        op_dead = _identity_op("dead_op")
        scenarios = [_prose_scenario("INJ-A")]
        report = audit_scenarios(
            scenarios,
            registry_label="synthetic_mixed",
            mutator=PairedScenarioMutator(operators=(op_real, op_dead)),
        )
        # The dead op can't produce a value-hash set, so collision = 0.
        key = "dead_op__real_op"
        assert report.pairwise_collision_matrix[key] == 0


# ---------------------------------------------------------------------------
# Live registry_v3
# ---------------------------------------------------------------------------


class TestLiveRegistryV3:
    def test_audit_runs_clean(self):
        registry = build_registry_v3()
        report = audit_scenarios(
            registry.all_scenarios(),
            registry_label="injection_registry_v3",
        )
        assert report.n_scenarios == 33
        assert len(report.operators) == 6
        # The report dataclass forbids inconsistent state, so simply
        # constructing it is the integrity check. The decision field
        # value is data, not pass/fail of this test.
        assert report.decision in {"PASS", "FAIL"}


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------


class TestWriteReport:
    def test_creates_directory_and_writes(self, tmp_path):
        target = tmp_path / "deep" / "out.json"
        report = _report()
        written = write_report(report, target)
        assert written == target
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded["audit_version"] == "v1"


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_main_writes_json(self, tmp_path, capsys):
        target = tmp_path / "audit.json"
        rc = main(["--output", str(target)])
        assert rc == 0
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded["registry_label"] == "injection_registry_v3"
        assert loaded["n_scenarios"] == 33
        captured = capsys.readouterr()
        assert "Operator orthogonality audit" in captured.out


# ---------------------------------------------------------------------------
# Module surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    def test_default_thresholds_are_pre_registered(self):
        assert MAX_ACCEPTABLE_COLLISION_COUNT == 2
        assert MAX_ACCEPTABLE_APPLICABILITY_GAP == 10

    def test_default_output_path_anchored_to_paper_3(self):
        assert "paper_3" in DEFAULT_OUTPUT_PATH.parts
        assert DEFAULT_OUTPUT_PATH.name == "operator_orthogonality_v1.json"
