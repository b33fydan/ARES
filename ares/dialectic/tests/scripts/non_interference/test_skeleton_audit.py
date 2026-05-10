"""Tests for the skeleton audit script.

Phase 7 / Session 057 / Step 1.

Covers:
    * Synthetic-corpus audit shape (groups, singletons, decision rule).
    * Live registry_v3 audit produces a SkeletonAuditReport that
      satisfies the dataclass invariants.
    * Timestamp-mismatch flag fires when only timestamps differ.
    * write_report round-trips JSON with the expected shape.
    * Decision rule honors the threshold parameter.
    * CLI main() exits 0 and emits the JSON file.
"""

from __future__ import annotations

import json
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.schemas.skeleton_equivalence import SkeletonEquivalentGroup
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference import skeleton_audit
from ares.dialectic.scripts.non_interference.skeleton_audit import (
    DECISION_THRESHOLD,
    SkeletonAuditReport,
    audit_scenarios,
    main,
    write_report,
)
from ares.dialectic.scripts.scenario_corpus import (
    BenchmarkScenario,
    ScenarioMetadata,
)


_T0 = datetime(2026, 5, 7, 12, 0, 0)


# ---------------------------------------------------------------------------
# Synthetic-scenario builders
# ---------------------------------------------------------------------------


def _meta(scenario_id: str, fact_count: int = 1) -> ScenarioMetadata:
    return ScenarioMetadata(
        scenario_id=scenario_id,
        name=f"synthetic {scenario_id}",
        description="synthetic test scenario for skeleton audit",
        mitre_attack_ids=("T1078",),
        mitre_tactic="initial-access",
        difficulty_tier=1,
        expected_verdict="THREAT_CONFIRMED",
        expected_winner="BALANCED",
        fact_count=fact_count,
        notes="audit unit-test fixture",
    )


def _fact(
    *,
    fact_id: str,
    entity_id: str = "host-A",
    field: str = "logon_type",
    value: object = "interactive",
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


def _scenario(
    scenario_id: str,
    facts: list[Fact],
) -> BenchmarkScenario:
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


# ---------------------------------------------------------------------------
# audit_scenarios — synthetic
# ---------------------------------------------------------------------------


class TestAuditOnSynthetic:
    def test_all_unique_scenarios_yield_zero_groups(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", field="logon_type")]),
            _scenario("INJ-B", [_fact(fact_id="f-001", field="process_name")]),
            _scenario("INJ-C", [_fact(fact_id="f-001", field="dst_ip")]),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic_unique"
        )
        assert report.n_scenarios == 3
        assert report.n_groups_size_ge_2 == 0
        assert report.n_singleton_skeletons == 3
        assert report.n_distinct_skeletons == 3
        assert report.decision == "mutator_path"
        assert report.singleton_scenario_ids == ("INJ-A", "INJ-B", "INJ-C")
        assert report.groups == ()

    def test_value_only_mutation_groups_together(self):
        # Two scenarios with identical skeletons but different values.
        scenarios = [
            _scenario("INJ-X", [_fact(fact_id="f-001", value="benign")]),
            _scenario("INJ-Y", [_fact(fact_id="f-001", value="malicious")]),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic_pair"
        )
        assert report.n_groups_size_ge_2 == 1
        assert report.n_singleton_skeletons == 0
        assert report.groups[0].scenario_ids == ("INJ-X", "INJ-Y")
        assert report.groups[0].size == 2
        assert report.groups[0].timestamp_mismatch is False

    def test_three_value_only_variants_same_group(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", value="a")]),
            _scenario("INJ-B", [_fact(fact_id="f-001", value="b")]),
            _scenario("INJ-C", [_fact(fact_id="f-001", value="c")]),
        ]
        report = audit_scenarios(scenarios, registry_label="synthetic_triple")
        assert report.n_groups_size_ge_2 == 1
        assert report.groups[0].size == 3
        assert report.groups[0].scenario_ids == ("INJ-A", "INJ-B", "INJ-C")

    def test_timestamp_mismatch_flagged_not_rejected(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", timestamp=_T0)]),
            _scenario(
                "INJ-B",
                [_fact(fact_id="f-001", timestamp=_T0 + timedelta(days=30))],
            ),
        ]
        report = audit_scenarios(scenarios, registry_label="synthetic_ts")
        # Same skeleton -> still grouped.
        assert report.n_groups_size_ge_2 == 1
        group = report.groups[0]
        assert group.timestamp_mismatch is True
        assert "f-001" in group.timestamp_mismatched_fact_ids

    def test_singletons_and_groups_coexist(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", value="a")]),
            _scenario("INJ-B", [_fact(fact_id="f-001", value="b")]),
            _scenario("INJ-C", [_fact(fact_id="f-001", field="dst_ip")]),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic_mixed"
        )
        assert report.n_groups_size_ge_2 == 1
        assert report.n_singleton_skeletons == 1
        assert report.singleton_scenario_ids == ("INJ-C",)


# ---------------------------------------------------------------------------
# Decision rule
# ---------------------------------------------------------------------------


class TestDecisionRule:
    def test_default_threshold_is_five(self):
        assert DECISION_THRESHOLD == 5

    def test_below_threshold_picks_mutator_path(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", value="a")]),
            _scenario("INJ-B", [_fact(fact_id="f-001", value="b")]),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic", decision_threshold=5
        )
        assert report.n_groups_size_ge_2 == 1
        assert report.decision == "mutator_path"

    def test_at_threshold_picks_harness_path(self):
        # Build 2 groups, threshold=2 => decision flips to harness.
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", value="a")]),
            _scenario("INJ-B", [_fact(fact_id="f-001", value="b")]),
            _scenario(
                "INJ-C",
                [_fact(fact_id="f-001", field="dst_ip", value="x")],
            ),
            _scenario(
                "INJ-D",
                [_fact(fact_id="f-001", field="dst_ip", value="y")],
            ),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic", decision_threshold=2
        )
        assert report.n_groups_size_ge_2 == 2
        assert report.decision == "harness_path"

    def test_threshold_zero_always_harness(self):
        scenarios = [
            _scenario("INJ-A", [_fact(fact_id="f-001", field="a")]),
        ]
        report = audit_scenarios(
            scenarios, registry_label="synthetic", decision_threshold=0
        )
        assert report.n_groups_size_ge_2 == 0
        assert report.decision == "harness_path"


# ---------------------------------------------------------------------------
# SkeletonAuditReport invariants
# ---------------------------------------------------------------------------


def _report(**overrides) -> SkeletonAuditReport:
    base = dict(
        registry_label="test",
        n_scenarios=2,
        n_distinct_skeletons=1,
        n_singleton_skeletons=0,
        n_groups_size_ge_2=1,
        decision_threshold=5,
        decision="mutator_path",
        groups=(
            SkeletonEquivalentGroup(
                group_id="GRP-aaaaaaaa",
                skeleton_hash="a" * 32,
                scenario_ids=("INJ-A", "INJ-B"),
                n_facts=1,
                timestamp_mismatch=False,
                timestamp_mismatched_fact_ids=(),
            ),
        ),
        singleton_scenario_ids=(),
    )
    base.update(overrides)
    return SkeletonAuditReport(**base)


class TestReportInvariants:
    def test_constructs_valid(self):
        r = _report()
        assert r.decision == "mutator_path"

    def test_rejects_unknown_decision(self):
        with pytest.raises(ValueError, match="decision"):
            _report(decision="float_path")

    def test_rejects_decision_inconsistent_with_count(self):
        # n_groups < threshold should be mutator_path, not harness_path.
        with pytest.raises(ValueError, match="inconsistent"):
            _report(decision="harness_path")

    def test_rejects_count_arithmetic_violation(self):
        with pytest.raises(ValueError, match="must equal"):
            _report(n_distinct_skeletons=5)


# ---------------------------------------------------------------------------
# write_report
# ---------------------------------------------------------------------------


class TestWriteReport:
    def test_creates_directory_and_writes_json(self, tmp_path):
        target = tmp_path / "deep" / "nested" / "out.json"
        report = _report()
        written = write_report(report, target)
        assert written == target
        assert target.exists()
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded["registry_label"] == "test"
        assert loaded["n_groups_size_ge_2"] == 1
        assert loaded["decision"] == "mutator_path"
        assert loaded["groups"][0]["scenario_ids"] == ["INJ-A", "INJ-B"]


# ---------------------------------------------------------------------------
# Live registry_v3
# ---------------------------------------------------------------------------


class TestLiveRegistryAudit:
    """Exercise the real registry_v3. No LLM calls. Pure replay."""

    def test_audit_runs_clean(self):
        registry = build_registry_v3()
        report = audit_scenarios(
            registry.all_scenarios(),
            registry_label="injection_registry_v3",
        )
        assert report.n_scenarios == 33
        assert report.n_distinct_skeletons >= 1
        assert (
            report.n_distinct_skeletons
            == report.n_singleton_skeletons + report.n_groups_size_ge_2
        )
        assert sum(g.size for g in report.groups) + report.n_singleton_skeletons == 33

    def test_decision_is_one_of_two_paths(self):
        registry = build_registry_v3()
        report = audit_scenarios(
            registry.all_scenarios(),
            registry_label="injection_registry_v3",
        )
        assert report.decision in {"harness_path", "mutator_path"}


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------


class TestCli:
    def test_main_writes_default_output(self, tmp_path, monkeypatch, capsys):
        target = tmp_path / "audit.json"
        rc = main(["--output", str(target)])
        assert rc == 0
        assert target.exists()
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded["registry_label"] == "injection_registry_v3"
        assert loaded["n_scenarios"] == 33
        captured = capsys.readouterr()
        assert "Skeleton audit on injection_registry_v3" in captured.out
        assert str(target) in captured.out

    def test_main_honors_custom_threshold(self, tmp_path):
        target = tmp_path / "audit.json"
        rc = main(["--output", str(target), "--threshold", "0"])
        assert rc == 0
        loaded = json.loads(target.read_text(encoding="utf-8"))
        assert loaded["decision_threshold"] == 0
        # With threshold 0, decision is always harness_path.
        assert loaded["decision"] == "harness_path"


# ---------------------------------------------------------------------------
# Module exposes the expected public surface
# ---------------------------------------------------------------------------


class TestModuleSurface:
    def test_default_output_path_anchored_to_repo(self):
        # Path should resolve under the docs/ tree.
        assert (
            "docs"
            in skeleton_audit.DEFAULT_OUTPUT_PATH.parts
        )
        assert (
            "paper_3"
            in skeleton_audit.DEFAULT_OUTPUT_PATH.parts
        )
        assert skeleton_audit.DEFAULT_OUTPUT_PATH.name == "skeleton_audit_v1.json"
