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


def test_hard_ceiling_matches_runner():
    import importlib.util
    cli = Path(__file__).resolve().parents[2] / "scripts" / "run_session_098.py"
    spec = importlib.util.spec_from_file_location("run_session_098", cli)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    assert f"HARD_CEILING_USD = {mod.HARD_CEILING_USD}" in _prereg_text() or \
           f"${mod.HARD_CEILING_USD}" in _prereg_text()
