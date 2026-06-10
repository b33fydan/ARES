# tests/dialectic/measurement/test_read_depth_tier4_anchor.py
from ares.dialectic.measurement.read_depth_tier4_anchor import (
    Tier4Config, run_tier4_anchor, estimate_cost_usd,
)
from ares.dialectic.measurement.read_depth_corpus import MALIGN_ENTRIES, BENIGN_ENTRIES
from ares.dialectic.measurement.read_depth_verdict import (
    FRAMING_ROBUST_MAX_X, HIGH_DETECTION_MIN_J,
)


def _perfect_detector_cycle(scenario, operator_name, is_baseline, resample_index):
    """Mock: catches every malign packet, never FPs, framing-invariant. cost=0.01"""
    sid = scenario.metadata.scenario_id
    is_malign = sid.startswith("RDF-M")
    return is_malign, 0.01


def test_estimate_cost_scales_with_k_and_operators():
    cfg = Tier4Config(k_resamples=20)
    # 4 malign*(1 baseline + 2 ops)*20 + 4 benign*1*20 = 240 + 80 = 320 cycles
    assert estimate_cost_usd(cfg, per_cycle_usd=0.0144) == round(320 * 0.0144, 4)


def test_perfect_detector_lands_on_high_detection_low_susceptibility():
    cfg = Tier4Config(k_resamples=8, seed=0)
    summary = run_tier4_anchor(cfg, cycle_fn=_perfect_detector_cycle)
    standalone = next(c for c in summary.coordinates if c.view == "standalone")
    assert standalone.tpr == 1.0 and standalone.fpr == 0.0
    assert standalone.youden_j == 1.0
    assert standalone.x_semantic == 0.0   # framing-invariant mock
    # A perfect, framing-invariant detector WOULD occupy the corner (falsifier path)
    assert standalone.x_semantic <= FRAMING_ROBUST_MAX_X
    assert standalone.youden_j >= HIGH_DETECTION_MIN_J


def test_susceptible_detector_moves_x_semantic():
    def flaky(scenario, operator_name, is_baseline, resample_index):
        sid = scenario.metadata.scenario_id
        is_malign = sid.startswith("RDF-M")
        # under any framing operator, flip malign->benign deterministically
        if is_malign and operator_name is not None:
            return False, 0.01
        return is_malign, 0.01
    cfg = Tier4Config(k_resamples=8, seed=0)
    summary = run_tier4_anchor(cfg, cycle_fn=flaky)
    standalone = next(c for c in summary.coordinates if c.view == "standalone")
    assert standalone.x_semantic > 0.0
    assert summary.total_cost_usd > 0.0
    assert summary.corpus_digest == "9401b7188ba790a5"
