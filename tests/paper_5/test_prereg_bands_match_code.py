# tests/paper_5/test_prereg_bands_match_code.py
"""SSOT guard: the Phase-3 pre-registration prose equals the code constants."""
from pathlib import Path

from ares.harness.provenance_tracker import (
    CONTAINMENT_DIRECTIONS,
    MIN_MATCH_LENGTH,
    TYPE_EXACT_KINDS,
)

_PREREG = (
    Path(__file__).resolve().parents[2]
    / "docs" / "paper_5" / "PREREGISTRATION_phase3_measurement.md"
)


def _prereg_text():
    return _PREREG.read_text(encoding="utf-8")


def test_prereg_file_exists():
    assert _PREREG.is_file()


def test_min_match_length_matches():
    assert f"MIN_MATCH_LENGTH = {MIN_MATCH_LENGTH}" in _prereg_text()


def test_type_exact_kinds_match():
    text = _prereg_text()
    for kind in TYPE_EXACT_KINDS:
        assert kind in text


def test_containment_directions_match():
    text = _prereg_text()
    for direction in CONTAINMENT_DIRECTIONS:
        assert direction in text


def _runner():
    import importlib.util
    cli = Path(__file__).resolve().parents[2] / "scripts" / "run_session_098.py"
    spec = importlib.util.spec_from_file_location("run_session_098", cli)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)  # main venv, no agentdojo
    return mod


def test_hard_ceiling_matches_runner():
    mod = _runner()
    assert f"HARD_CEILING_USD = {mod.HARD_CEILING_USD}" in _prereg_text() or \
           f"${mod.HARD_CEILING_USD}" in _prereg_text()


def test_selection_thresholds_match_runner():
    mod = _runner()
    text = _prereg_text()
    assert f"tau_asr = {mod._TAU_ASR}" in text
    assert f"tau_util = {mod._TAU_UTIL}" in text


def test_sweep_grid_matches_runner():
    mod = _runner()
    text = _prereg_text()
    for label, model_id in mod._SWEEP_MODELS.items():
        assert label in text and model_id in text
    for attack in mod._SWEEP_ATTACKS:
        assert attack in text
    for suite in mod._SWEEP_SUITES:
        assert suite in text


def test_stage1_arms_match_runner():
    mod = _runner()
    text = _prereg_text()
    for arm in mod._STAGE1_ARMS:
        assert arm in text


def test_model_name_resolution_matches_runner():
    mod = _runner()
    text = _prereg_text()
    assert mod._PIPE_NAME_SHIM in text
    assert mod._PROSE_MODEL in text
    assert f"max_tokens = {mod._MAX_TOKENS}" in text


def test_eligible_banking_ids_match_runner():
    mod = _runner()
    text = _prereg_text()
    for tid in mod._BANKING_ELIGIBLE_INJECTION_TASKS:
        assert tid in text


def test_sentinel_absent_until_stage_b_frozen():
    # The release token must NOT appear until N/N_benign/B_sweep are filled
    # (Stage B). Its presence is the runner's gate; a premature token would let
    # Stage-1 run on unfrozen parameters.
    mod = _runner()
    assert mod._PREREG_FROZEN_SENTINEL not in _prereg_text(), (
        "release token present but Stage-B numeric params not yet frozen"
    )
