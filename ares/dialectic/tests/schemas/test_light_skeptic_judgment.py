"""Tests for LightSkepticJudgment — validation, frozen, serialization."""

from __future__ import annotations

import json
from dataclasses import FrozenInstanceError

import pytest

from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


def _j(**overrides) -> LightSkepticJudgment:
    base = dict(
        confidence=0.75,
        rationale=("rule_one: fired",),
        triggered_rules=("rule_one",),
        benign_score=0.25,
        malign_score=0.0,
    )
    base.update(overrides)
    return LightSkepticJudgment(**base)


class TestConfidenceValidation:
    def test_rejects_negative_confidence(self):
        with pytest.raises(ValueError, match="confidence"):
            _j(confidence=-0.01)

    def test_rejects_above_one(self):
        with pytest.raises(ValueError, match="confidence"):
            _j(confidence=1.01)

    def test_accepts_zero(self):
        assert _j(confidence=0.0).confidence == 0.0

    def test_accepts_one(self):
        assert _j(confidence=1.0).confidence == 1.0

    def test_accepts_mid_value(self):
        assert _j(confidence=0.5).confidence == 0.5


class TestScoreValidation:
    def test_benign_score_rejects_negative(self):
        with pytest.raises(ValueError, match="benign_score"):
            _j(benign_score=-0.1)

    def test_benign_score_rejects_above_one(self):
        with pytest.raises(ValueError, match="benign_score"):
            _j(benign_score=1.5)

    def test_malign_score_rejects_negative(self):
        with pytest.raises(ValueError, match="malign_score"):
            _j(malign_score=-0.1)

    def test_malign_score_rejects_above_one(self):
        with pytest.raises(ValueError, match="malign_score"):
            _j(malign_score=1.5)

    def test_scores_at_bounds_ok(self):
        assert _j(benign_score=1.0, malign_score=1.0, confidence=0.5).benign_score == 1.0


class TestTupleValidation:
    def test_rejects_list_rationale(self):
        with pytest.raises(TypeError, match="rationale"):
            _j(rationale=["entry"])

    def test_rejects_empty_rationale(self):
        with pytest.raises(ValueError, match="rationale"):
            _j(rationale=())

    def test_rejects_list_triggered_rules(self):
        with pytest.raises(TypeError, match="triggered_rules"):
            _j(triggered_rules=["rule"])

    def test_empty_triggered_rules_allowed_but_rationale_must_exist(self):
        # Triggered_rules may legitimately be empty in future expansions
        # (no rule fired but a default-floor rationale exists).
        j = _j(triggered_rules=(), rationale=("no_signal",))
        assert j.triggered_rules == ()
        assert j.rationale == ("no_signal",)


class TestFrozen:
    def test_cannot_mutate_confidence(self):
        j = _j()
        with pytest.raises(FrozenInstanceError):
            j.confidence = 0.1  # type: ignore[misc]

    def test_cannot_mutate_rationale(self):
        j = _j()
        with pytest.raises(FrozenInstanceError):
            j.rationale = ("x",)  # type: ignore[misc]

    def test_hashable(self):
        a = _j()
        b = _j()
        assert hash(a) == hash(b)


class TestSerialization:
    def test_to_dict_roundtrip(self):
        j = _j(rationale=("r1", "r2"), triggered_rules=("rule_one", "rule_two"))
        rebuilt = LightSkepticJudgment.from_dict(j.to_dict())
        assert rebuilt == j

    def test_to_dict_converts_tuples_to_lists(self):
        j = _j(rationale=("only",))
        d = j.to_dict()
        assert isinstance(d["rationale"], list)
        assert isinstance(d["triggered_rules"], list)

    def test_to_json_parses(self):
        j = _j()
        data = json.loads(j.to_json())
        assert data["confidence"] == 0.75

    def test_from_dict_with_string_numbers(self):
        d = {
            "confidence": "0.9",
            "rationale": ["x"],
            "triggered_rules": ["y"],
            "benign_score": "0.4",
            "malign_score": "0",
        }
        j = LightSkepticJudgment.from_dict(d)
        assert j.confidence == pytest.approx(0.9)
        assert j.benign_score == pytest.approx(0.4)
        assert j.malign_score == 0.0

    def test_roundtrip_preserves_score_fields(self):
        j = _j(benign_score=0.3, malign_score=0.2)
        rebuilt = LightSkepticJudgment.from_dict(j.to_dict())
        assert rebuilt.benign_score == 0.3
        assert rebuilt.malign_score == 0.2
