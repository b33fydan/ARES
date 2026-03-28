"""Tests for ares.dialectic.agents.strategies.prompts_v3.

Session 032: Validates v3 prompts contain the new calibration
and exhaustiveness requirements while preserving v2 foundations.
"""

from __future__ import annotations

import pytest

from ares.dialectic.agents.strategies.prompts_v3 import (
    ARCHITECT_SYSTEM_PROMPT_V3,
    NARRATOR_SYSTEM_PROMPT_V3,
    SKEPTIC_SYSTEM_PROMPT_V3,
)


class TestArchitectV3:
    """Tests for the v3 Architect prompt."""

    def test_contains_exhaustiveness_requirement(self):
        assert "MUST reference" in ARCHITECT_SYSTEM_PROMPT_V3 or \
               "every fact_id" in ARCHITECT_SYSTEM_PROMPT_V3

    def test_contains_evidence_organization(self):
        lower = ARCHITECT_SYSTEM_PROMPT_V3.lower()
        assert "supporting threat" in lower or "organize" in lower

    def test_preserves_closed_world_rule(self):
        assert "CLOSED WORLD" in ARCHITECT_SYSTEM_PROMPT_V3

    def test_preserves_json_output_format(self):
        assert "JSON array" in ARCHITECT_SYSTEM_PROMPT_V3

    def test_preserves_pattern_types(self):
        assert "PRIVILEGE_ESCALATION" in ARCHITECT_SYSTEM_PROMPT_V3

    def test_preserves_confidence_calibration(self):
        assert "0.8-1.0" in ARCHITECT_SYSTEM_PROMPT_V3

    def test_is_string_with_content(self):
        assert isinstance(ARCHITECT_SYSTEM_PROMPT_V3, str)
        assert len(ARCHITECT_SYSTEM_PROMPT_V3) > 100


class TestSkepticV3:
    """Tests for the v3 Skeptic prompt."""

    def test_contains_confidence_calibration_rules(self):
        assert "0.6" in SKEPTIC_SYSTEM_PROMPT_V3

    def test_contains_absence_not_evidence(self):
        lower = SKEPTIC_SYSTEM_PROMPT_V3.lower()
        assert "absence" in lower

    def test_contains_authorization_requirement(self):
        lower = SKEPTIC_SYSTEM_PROMPT_V3.lower()
        assert "authorized" in lower or "authorization" in lower

    def test_preserves_closed_world_rule(self):
        assert "CLOSED WORLD" in SKEPTIC_SYSTEM_PROMPT_V3

    def test_preserves_json_output_format(self):
        assert "JSON array" in SKEPTIC_SYSTEM_PROMPT_V3

    def test_preserves_explanation_types(self):
        assert "MAINTENANCE_WINDOW" in SKEPTIC_SYSTEM_PROMPT_V3

    def test_is_string_with_content(self):
        assert isinstance(SKEPTIC_SYSTEM_PROMPT_V3, str)
        assert len(SKEPTIC_SYSTEM_PROMPT_V3) > 100


class TestNarratorV3:
    """Tests for the v3 Narrator prompt."""

    def test_preserves_fact_id_requirement(self):
        assert "fact_ids" in NARRATOR_SYSTEM_PROMPT_V3

    def test_preserves_no_change_rule(self):
        assert "CANNOT change" in NARRATOR_SYSTEM_PROMPT_V3

    def test_is_string_with_content(self):
        assert isinstance(NARRATOR_SYSTEM_PROMPT_V3, str)
        assert len(NARRATOR_SYSTEM_PROMPT_V3) > 50
