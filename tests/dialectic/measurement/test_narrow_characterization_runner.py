"""Tests for the Session 060 narrow-characterization runner.

Synthetic-trace tests (no live LLM). Covers:
    * No halt on narrow fire (characterization mode).
    * Light path only — LLM path never invoked.
    * Cost circuit-breaker halts at $5 ceiling.
    * Anchor-test guard halts when red.
    * Pre-registered cost ceiling locked at $5.
"""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from ares.dialectic.measurement.narrow_characterization_runner import (
    NARROW_EXT_COST_CEILING_USD,
    NarrowCharacterizationConfig,
    NarrowExtendedSummary,
    run_narrow_characterization,
)
from ares.dialectic.measurement.leakage_runner import (
    HALT_ANCHOR_TEST_FAILURE,
    HALT_COMPLETED,
    HALT_COST_CEILING,
    CycleTrace,
)


def _trace(
    *,
    is_baseline: bool,
    operator_name: str | None,
    scenario_id: str,
    pair_index: int,
    skeptic_triggered_rules: tuple[str, ...] = ("default_floor",),
    skeptic_confidence: float = 0.5,
    oracle_outcome: str = "THREAT_CONFIRMED",
    cost_usd: float = 0.01,
) -> CycleTrace:
    return CycleTrace(
        cycle_id=f"test-{scenario_id}-{operator_name or 'baseline'}",
        scenario_id=scenario_id,
        operator_name=operator_name,
        pair_index=pair_index,
        is_baseline=is_baseline,
        pipeline="light",
        architect_message_type="THESIS",
        architect_confidence=0.9,
        architect_cited_facts=("fact-001",),
        skeptic_message_type="REBUTTAL_LIGHT",
        skeptic_confidence=skeptic_confidence,
        skeptic_cited_facts=(),
        skeptic_triggered_rules=skeptic_triggered_rules,
        oracle_outcome=oracle_outcome,
        oracle_confidence=0.85,
        oracle_supporting_facts=("fact-001",),
        final_outcome=oracle_outcome,
        final_confidence=0.85,
        cost_usd=cost_usd,
        tokens_in=1000,
        tokens_out=200,
        elapsed_ms=5000.0,
    )


# ---------------------------------------------------------------------------
# Pre-registered constants
# ---------------------------------------------------------------------------


class TestPreRegisteredConfig:
    def test_cost_ceiling_locked_at_5(self):
        assert NARROW_EXT_COST_CEILING_USD == 5.0

    def test_default_config_uses_locked_ceiling(self):
        config = NarrowCharacterizationConfig()
        assert config.cost_ceiling_usd == 5.0


# ---------------------------------------------------------------------------
# No halt on narrow fire (characterization discipline)
# ---------------------------------------------------------------------------


class TestNoHaltOnNarrowFire:
    """The defining discipline of Session 060: even if narrow fires
    repeatedly, the run continues to completion (or cost ceiling)."""

    def test_run_continues_through_repeated_narrow_fires(self, tmp_path):
        # Every mutated cycle has DIFFERENT triggered_rules from the
        # baseline. Light Skeptic action_changed fires on every pair.
        # The run must NOT halt; it must continue and record every pair.

        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            if kwargs["is_baseline"]:
                return _trace(
                    is_baseline=True,
                    operator_name=None,
                    scenario_id=sid,
                    pair_index=kwargs["pair_index"],
                    skeptic_triggered_rules=("default_floor",),
                ), 0.005
            # mutated -> different triggered rules => narrow fires
            return _trace(
                is_baseline=False,
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
                skeptic_triggered_rules=("authorization_marker_present",),
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )

            # Must complete (not halt on narrow fire)
            assert summary.halt_reason == HALT_COMPLETED
            # Up to 33 scenarios × 3 operators = 99 pairs. Some operators
            # no-op on some scenarios (per Session 058.5 orthogonality
            # audit: synonym_conservative_v2 gap=1, framing ops gap=0).
            # So we expect ≥ 95 evaluated, all narrow-fired.
            assert 95 <= summary.n_pairs_evaluated <= 99
            # Every evaluated pair fired narrow
            assert summary.n_pairs_narrow_fired == summary.n_pairs_evaluated
            assert summary.n_pairs_stable_narrow == 0
            assert summary.narrow_stability_rate == 0.0
            # Drift records captured for every fire
            assert len(summary.drift_records) == summary.n_pairs_evaluated

    def test_run_completes_with_zero_fires(self, tmp_path):
        # Every mutated cycle matches baseline rules => no fires.
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            return _trace(
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
                skeptic_triggered_rules=("default_floor",),
                skeptic_confidence=0.5,
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )

            assert summary.halt_reason == HALT_COMPLETED
            assert 95 <= summary.n_pairs_evaluated <= 99
            assert summary.n_pairs_narrow_fired == 0
            assert summary.n_pairs_stable_narrow == summary.n_pairs_evaluated
            assert summary.narrow_stability_rate == 1.0
            assert summary.narrow_stability_percent == 100.0
            assert len(summary.drift_records) == 0


# ---------------------------------------------------------------------------
# Light path only
# ---------------------------------------------------------------------------


class TestLightPathOnly:
    """Session 060 skips the LLM pipeline entirely."""

    def test_only_light_pipeline_invoked(self, tmp_path):
        observed_pipelines: list[str] = []

        def mock_run_cycle(**kwargs):
            observed_pipelines.append(kwargs["pipeline"])
            sid = kwargs["scenario"].metadata.scenario_id
            return _trace(
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            run_narrow_characterization(config=config, client=MagicMock())

            assert observed_pipelines, "no cycles invoked"
            assert all(p == "light" for p in observed_pipelines), (
                f"non-light pipeline invoked: {set(observed_pipelines)}"
            )


# ---------------------------------------------------------------------------
# Cost circuit-breaker
# ---------------------------------------------------------------------------


class TestCostCircuitBreaker:
    def test_halts_when_cost_exceeds_5_dollars(self, tmp_path):
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            return _trace(
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
                cost_usd=6.0,  # one cycle blows the $5 ceiling
            ), 6.0

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )

            assert summary.halt_reason == HALT_COST_CEILING
            assert summary.total_cost_usd >= 5.0


# ---------------------------------------------------------------------------
# Anchor guard
# ---------------------------------------------------------------------------


class TestAnchorGuard:
    def test_halts_when_anchor_red(self, tmp_path):
        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "anchor_test_passes",
            return_value=False,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=False,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )

            assert summary.halt_reason == HALT_ANCHOR_TEST_FAILURE
            assert summary.cycles_completed == 0
            assert summary.total_cost_usd == 0.0
            assert summary.anchor_test_passed_at_start is False


# ---------------------------------------------------------------------------
# Per-operator stats
# ---------------------------------------------------------------------------


class TestPerOperatorStats:
    def test_per_operator_breakdown(self, tmp_path):
        # Make framing_prefix_v1 fire narrow on every pair; the other
        # two stay stable.
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            if kwargs["is_baseline"]:
                return _trace(
                    is_baseline=True,
                    operator_name=None,
                    scenario_id=sid,
                    pair_index=kwargs["pair_index"],
                    skeptic_triggered_rules=("default_floor",),
                ), 0.005
            op = kwargs["operator_name"]
            rules = (
                ("authorization_marker_present",)
                if op == "framing_prefix_v1"
                else ("default_floor",)
            )
            return _trace(
                is_baseline=False,
                operator_name=op,
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
                skeptic_triggered_rules=rules,
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )

            per_op = summary.per_operator_stability()
            # framing ops have gap=0 (universally applicable) per Session
            # 058.5 audit → n_evaluated = 33. synonym_conservative_v2 has
            # gap=1 → n_evaluated = 32.
            assert per_op["framing_prefix_v1"]["n_evaluated"] == 33
            assert per_op["framing_prefix_v1"]["n_narrow_fired"] == 33
            assert per_op["framing_prefix_v1"]["n_stable"] == 0
            assert per_op["framing_suffix_v1"]["n_evaluated"] == 33
            assert per_op["framing_suffix_v1"]["n_stable"] == 33
            assert per_op["framing_suffix_v1"]["n_narrow_fired"] == 0
            assert per_op["synonym_substitution_conservative_v2"]["n_stable"] >= 30


# ---------------------------------------------------------------------------
# Summary shape + JSONL persistence
# ---------------------------------------------------------------------------


class TestSummaryShape:
    def test_summary_to_dict_serializable(self, tmp_path):
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            return _trace(
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )
            import json
            payload = summary.to_dict()
            # round-trip
            s = json.dumps(payload, sort_keys=True)
            loaded = json.loads(s)
            assert loaded["narrow_stability_percent"] == 100.0
            assert "per_operator_stability" in loaded
            assert 95 <= len(loaded["pair_records"]) <= 99

    def test_traces_jsonl_persisted(self, tmp_path):
        def mock_run_cycle(**kwargs):
            sid = kwargs["scenario"].metadata.scenario_id
            return _trace(
                is_baseline=kwargs["is_baseline"],
                operator_name=kwargs["operator_name"],
                scenario_id=sid,
                pair_index=kwargs["pair_index"],
            ), 0.005

        with patch(
            "ares.dialectic.measurement.narrow_characterization_runner."
            "_run_one_cycle",
            side_effect=mock_run_cycle,
        ):
            config = NarrowCharacterizationConfig(
                cost_ceiling_usd=5.0,
                traces_root=tmp_path,
                skip_anchor_check=True,
            )
            summary = run_narrow_characterization(
                config=config, client=MagicMock()
            )
            traces_path = Path(summary.traces_path)
            sha_path = Path(summary.sha256_path)
            assert traces_path.exists()
            assert sha_path.exists()
            lines = traces_path.read_text(encoding="utf-8").splitlines()
            # 33 baselines + (95..99) mutated cycles. Some operators
            # no-op on some scenarios per the 058.5 audit.
            assert 128 <= len(lines) <= 132
