"""Tests for the leakage runner — Session 059.

Synthetic-trace tests (no live LLM). Covers:
    * Per-pair leakage computation handles all-zero and partial-leak
      cases correctly.
    * Cost circuit-breaker halts at the ceiling.
    * Anchor-test-guard halts when red.
    * Trace integrity: JSONL round-trip preserves cycle data.
    * Pre-flight estimator structure (without network).
"""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ares.dialectic.measurement.influence_leakage import InfluenceLeakage
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_COST_CEILING_USD,
    DEFAULT_PREFLIGHT_CYCLES,
    HALT_ANCHOR_TEST_FAILURE,
    HALT_COMPLETED,
    HALT_COST_CEILING,
    HALT_DETERMINISTIC_KILL,
    PRE_REGISTERED_OPERATOR_NAMES,
    CycleTrace,
    PairLeakageRecord,
    RunSummary,
    RunnerConfig,
    _compute_pair_leakage,
    _new_run_id,
    _resolve_operator,
    _select_preflight_pairs,
    _sha256_file,
    anchor_test_passes,
    run_full_measurement,
)


def _trace(
    *,
    is_baseline: bool = True,
    pipeline: str = "light",
    scenario_id: str = "INJ-001",
    operator_name: str | None = None,
    pair_index: int = 0,
    architect_message_type: str = "THESIS",
    architect_confidence: float = 0.9,
    architect_cited_facts: tuple[str, ...] = ("inj001-fact-001",),
    skeptic_message_type: str = "REBUTTAL_LIGHT",
    skeptic_confidence: float = 0.5,
    skeptic_cited_facts: tuple[str, ...] = (),
    skeptic_triggered_rules: tuple[str, ...] = ("default_floor",),
    oracle_outcome: str = "THREAT_CONFIRMED",
    oracle_confidence: float = 0.85,
    oracle_supporting_facts: tuple[str, ...] = ("inj001-fact-001",),
    final_outcome: str = "THREAT_CONFIRMED",
    final_confidence: float = 0.85,
    cost_usd: float = 0.05,
    tokens_in: int = 1000,
    tokens_out: int = 200,
    elapsed_ms: float = 4500.0,
    cycle_id: str = "test-cycle",
) -> CycleTrace:
    return CycleTrace(
        cycle_id=cycle_id,
        scenario_id=scenario_id,
        operator_name=operator_name,
        pair_index=pair_index,
        is_baseline=is_baseline,
        pipeline=pipeline,
        architect_message_type=architect_message_type,
        architect_confidence=architect_confidence,
        architect_cited_facts=architect_cited_facts,
        skeptic_message_type=skeptic_message_type,
        skeptic_confidence=skeptic_confidence,
        skeptic_cited_facts=skeptic_cited_facts,
        skeptic_triggered_rules=skeptic_triggered_rules,
        oracle_outcome=oracle_outcome,
        oracle_confidence=oracle_confidence,
        oracle_supporting_facts=oracle_supporting_facts,
        final_outcome=final_outcome,
        final_confidence=final_confidence,
        cost_usd=cost_usd,
        tokens_in=tokens_in,
        tokens_out=tokens_out,
        elapsed_ms=elapsed_ms,
    )


# ---------------------------------------------------------------------------
# Pre-registered operator set is locked
# ---------------------------------------------------------------------------


class TestPreRegisteredOperators:
    def test_three_operators_locked(self):
        assert PRE_REGISTERED_OPERATOR_NAMES == (
            "framing_prefix_v1",
            "framing_suffix_v1",
            "synonym_substitution_conservative_v2",
        )

    def test_resolve_operator_finds_each(self):
        for name in PRE_REGISTERED_OPERATOR_NAMES:
            op = _resolve_operator(name)
            assert op.operator_name == name

    def test_resolve_operator_unknown_raises(self):
        with pytest.raises(KeyError, match="unknown operator"):
            _resolve_operator("nonexistent_v99")


# ---------------------------------------------------------------------------
# Per-pair leakage
# ---------------------------------------------------------------------------


class TestPairLeakageAllZero:
    def test_identical_traces_yield_all_zero(self):
        baseline = _trace()
        mutated = _trace(is_baseline=False, operator_name="framing_prefix_v1")
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        for layer in record.leakages:
            assert layer.all_zero is True
        assert record.kill_fires is False
        assert record.first_diverging_layer is None


class TestPairLeakageVerdictChange:
    def test_verdict_change_at_oracle_layer(self):
        baseline = _trace(oracle_outcome="THREAT_CONFIRMED")
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            oracle_outcome="THREAT_DISMISSED",
            final_outcome="THREAT_DISMISSED",
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        oracle_layer = next(l for l in record.leakages if l.layer == "oracle")
        assert oracle_layer.verdict_changed is True
        assert record.kill_fires is True
        assert record.first_diverging_layer in {"architect", "oracle", "final_verdict"}


class TestPairLeakageConfidenceDrift:
    def test_drift_above_threshold_fires(self):
        baseline = _trace(architect_confidence=0.5)
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            architect_confidence=0.7,  # |Δ| = 0.20 > 0.10
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        arch = next(l for l in record.leakages if l.layer == "architect")
        assert arch.confidence_drift_exceeded is True

    def test_drift_at_threshold_does_not_fire(self):
        baseline = _trace(architect_confidence=0.5)
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            architect_confidence=0.6,  # |Δ| = 0.10 (strict >)
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        arch = next(l for l in record.leakages if l.layer == "architect")
        assert arch.confidence_drift_exceeded is False


class TestPairLeakageCitedFacts:
    def test_changed_supporting_fact_fires(self):
        baseline = _trace(oracle_supporting_facts=("inj001-fact-001",))
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            oracle_supporting_facts=("inj001-fact-002",),
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        oracle = next(l for l in record.leakages if l.layer == "oracle")
        assert oracle.cited_facts_changed is True


class TestPairLeakagePipelineMismatch:
    def test_mismatched_pipelines_raises(self):
        baseline = _trace(pipeline="light")
        mutated = _trace(
            is_baseline=False, operator_name="framing_prefix_v1", pipeline="llm"
        )
        with pytest.raises(ValueError, match="pipeline mismatch"):
            _compute_pair_leakage(
                baseline=baseline, mutated=mutated, pair_index=0
            )


class TestDualKillReadings:
    """The two readings exposed on PairLeakageRecord:
        kill_fires_narrow      = light_skeptic layer only (light pipeline)
        kill_fires_brief_broad = light_skeptic + oracle + final_verdict
                                 (light pipeline; excludes Architect)
    Both False on llm pipeline (only deterministic path can kill).
    """

    def test_narrow_only_fires_when_light_skeptic_leaks(self):
        # Baseline + mutated identical at Light Skeptic, but Oracle's
        # supporting facts differ (the cycle-6 cited_facts case).
        baseline = _trace(
            oracle_supporting_facts=("inj001-fact-001", "inj001-fact-002"),
        )
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            oracle_supporting_facts=("inj001-fact-002",),  # one fact dropped
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        # Light Skeptic byte-identical -> narrow kill False
        assert record.kill_fires_narrow is False
        # Oracle citation surface drifted -> brief_broad kill True
        assert record.kill_fires_brief_broad is True

    def test_narrow_fires_when_light_skeptic_drifts(self):
        baseline = _trace(skeptic_triggered_rules=("default_floor",))
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            skeptic_triggered_rules=("authorization_marker_present",),
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        assert record.kill_fires_narrow is True
        assert record.kill_fires_brief_broad is True

    def test_both_readings_false_when_no_leak(self):
        baseline = _trace()
        mutated = _trace(
            is_baseline=False, operator_name="framing_prefix_v1"
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        assert record.kill_fires_narrow is False
        assert record.kill_fires_brief_broad is False

    def test_both_readings_false_on_llm_pipeline(self):
        # Even if everything leaks, the LLM pipeline doesn't trigger
        # the deterministic-path kill criterion.
        baseline = _trace(pipeline="llm")
        mutated = _trace(
            pipeline="llm",
            is_baseline=False,
            operator_name="framing_prefix_v1",
            oracle_outcome="THREAT_DISMISSED",
            final_outcome="THREAT_DISMISSED",
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        assert record.kill_fires_narrow is False
        assert record.kill_fires_brief_broad is False
        # impl-broad still fires (any-layer reading) -- retained for
        # backwards compatibility / cycle-6 reproducibility.
        assert record.kill_fires is True


class TestPairRecordToDict:
    def test_round_trip_via_json(self):
        baseline = _trace()
        mutated = _trace(
            is_baseline=False,
            operator_name="framing_prefix_v1",
            oracle_outcome="THREAT_DISMISSED",
            final_outcome="THREAT_DISMISSED",
        )
        record = _compute_pair_leakage(
            baseline=baseline, mutated=mutated, pair_index=0
        )
        d = record.to_dict()
        assert json.dumps(d, sort_keys=True)  # serializable
        assert d["scenario_id"] == "INJ-001"
        assert d["operator_name"] == "framing_prefix_v1"
        assert d["kill_fires"] is True


# ---------------------------------------------------------------------------
# Trace integrity (JSONL round-trip)
# ---------------------------------------------------------------------------


class TestTraceJsonlRoundTrip:
    def test_to_dict_is_json_serializable(self):
        trace = _trace()
        d = trace.to_dict()
        s = json.dumps(d, sort_keys=True)
        loaded = json.loads(s)
        assert loaded["cycle_id"] == "test-cycle"
        assert loaded["architect_cited_facts"] == ["inj001-fact-001"]


# ---------------------------------------------------------------------------
# Cost circuit-breaker
# ---------------------------------------------------------------------------


class TestCostCircuitBreaker:
    """The circuit-breaker is implemented as the cost-ceiling check inside
    run_full_measurement's main loop. We verify it by mocking _run_one_cycle
    to return artificially-large costs and confirming halt_reason ==
    HALT_COST_CEILING."""

    def test_halts_when_baseline_exceeds_ceiling(self, tmp_path):
        # Each baseline cycle costs $25; ceiling is $20.
        def mock_run_cycle(**kwargs):
            return _trace(
                pipeline=kwargs["pipeline"],
                scenario_id=kwargs["scenario"].metadata.scenario_id,
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                pair_index=kwargs["pair_index"],
                cost_usd=25.0,
            ), 25.0

        with patch(
            "ares.dialectic.measurement.leakage_runner._run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = RunnerConfig(
                cost_ceiling_usd=20.0,
                pipelines=("light",),
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_full_measurement(config=config, client=MagicMock())
            assert summary.halt_reason == HALT_COST_CEILING
            assert summary.cycles_completed >= 1
            assert summary.total_cost_usd >= 20.0


# ---------------------------------------------------------------------------
# Halt on deterministic kill
# ---------------------------------------------------------------------------


class TestDeterministicKillScopedHalt:
    """Deterministic-path kill (brief broad reading) flips deterministic_active
    to False but does NOT halt the whole run. The LLM path continues
    under its own cost share. The kill is recorded in
    summary.deterministic_kill_fired; halt_reason stays HALT_COMPLETED
    unless cost or anchor halts."""

    def test_light_path_kill_skips_remaining_light_cycles_only(self, tmp_path):
        # Baseline: THREAT_CONFIRMED. Mutated: THREAT_DISMISSED.
        # On light path, this triggers brief_broad kill (oracle outcome
        # changed). LLM path mocks return matching outcomes => no kill.
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            pipeline = kwargs["pipeline"]
            if kwargs["is_baseline"]:
                return _trace(
                    pipeline=pipeline,
                    scenario_id=sid,
                    is_baseline=True,
                    operator_name=None,
                    pair_index=kwargs["pair_index"],
                    oracle_outcome="THREAT_CONFIRMED",
                    final_outcome="THREAT_CONFIRMED",
                    cost_usd=0.01,
                ), 0.01
            # mutated cycle
            if pipeline == "light":
                # cause kill on light path
                return _trace(
                    pipeline=pipeline,
                    scenario_id=sid,
                    is_baseline=False,
                    operator_name=kwargs["operator_name"],
                    pair_index=kwargs["pair_index"],
                    oracle_outcome="THREAT_DISMISSED",
                    final_outcome="THREAT_DISMISSED",
                    cost_usd=0.01,
                ), 0.01
            # LLM path: no kill
            return _trace(
                pipeline=pipeline,
                scenario_id=sid,
                is_baseline=False,
                operator_name=kwargs["operator_name"],
                pair_index=kwargs["pair_index"],
                oracle_outcome="THREAT_CONFIRMED",
                final_outcome="THREAT_CONFIRMED",
                cost_usd=0.01,
            ), 0.01

        with patch(
            "ares.dialectic.measurement.leakage_runner._run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = RunnerConfig(
                cost_ceiling_usd=20.0,
                pipelines=("llm", "light"),
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_full_measurement(config=config, client=MagicMock())
            assert summary.deterministic_kill_fired is True
            # The run completed (not halted by the kill).
            assert summary.halt_reason == HALT_COMPLETED
            # LLM path should have many records (one per scenario × ops).
            llm_records = [r for r in summary.pair_records if r.pipeline == "llm"]
            light_records = [
                r for r in summary.pair_records if r.pipeline == "light"
            ]
            assert len(llm_records) > 0, "LLM path should have run"
            # First scenario produced one light pair (the killing one);
            # subsequent scenarios should have skipped light pipeline.
            assert len(light_records) >= 1
            # If we have multiple scenarios, light count should be much
            # smaller than llm count after the kill.
            assert len(light_records) <= len(llm_records)


# ---------------------------------------------------------------------------
# Anchor-test guard
# ---------------------------------------------------------------------------


class TestAnchorTestGuard:
    def test_halts_when_anchor_red(self, tmp_path):
        with patch(
            "ares.dialectic.measurement.leakage_runner.anchor_test_passes",
            return_value=False,
        ):
            config = RunnerConfig(
                cost_ceiling_usd=20.0,
                pipelines=("light",),
                traces_root=tmp_path,
                skip_anchor_check=False,
            )
            summary = run_full_measurement(config=config, client=MagicMock())
            assert summary.halt_reason == HALT_ANCHOR_TEST_FAILURE
            assert summary.cycles_completed == 0
            assert summary.total_cost_usd == 0.0

    def test_real_anchor_test_passes_in_repo(self):
        # Sanity check: the in-repo anchor test should be green right now.
        assert anchor_test_passes() is True


# ---------------------------------------------------------------------------
# Pre-flight pair selection
# ---------------------------------------------------------------------------


class TestPreflightPairSelection:
    def test_returns_n_pairs(self):
        from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
        scenarios = list(build_registry_v3().all_scenarios())
        pairs = _select_preflight_pairs(
            scenarios, PRE_REGISTERED_OPERATOR_NAMES, n_pairs=5, seed=42
        )
        assert len(pairs) == 5

    def test_deterministic_with_seed(self):
        from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
        scenarios = list(build_registry_v3().all_scenarios())
        a = _select_preflight_pairs(
            scenarios, PRE_REGISTERED_OPERATOR_NAMES, n_pairs=5, seed=7
        )
        b = _select_preflight_pairs(
            scenarios, PRE_REGISTERED_OPERATOR_NAMES, n_pairs=5, seed=7
        )
        assert [(s.metadata.scenario_id, op) for s, op in a] == [
            (s.metadata.scenario_id, op) for s, op in b
        ]


# ---------------------------------------------------------------------------
# Run-id generation
# ---------------------------------------------------------------------------


class TestRunId:
    def test_unique(self):
        a = _new_run_id()
        b = _new_run_id()
        assert a != b

    def test_format(self):
        rid = _new_run_id()
        # Format: YYYYMMDD-HHMMSS-XXXXXX
        parts = rid.split("-")
        assert len(parts) == 3
        assert len(parts[0]) == 8  # YYYYMMDD
        assert len(parts[1]) == 6  # HHMMSS
        assert len(parts[2]) == 6  # hex


# ---------------------------------------------------------------------------
# SHA256 helper
# ---------------------------------------------------------------------------


class TestSha256:
    def test_known_content(self, tmp_path):
        path = tmp_path / "sample.txt"
        path.write_bytes(b"hello world")
        # echo -n 'hello world' | sha256sum
        expected = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
        assert _sha256_file(path) == expected
