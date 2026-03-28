"""Tests for ares.dialectic.agents.strategies.prompts_v4.

Session 034: Validates v4 prompts contain mixed-signal calibration
and that Skeptic/Narrator prompts are unchanged from v3.
"""

from __future__ import annotations

import pytest

from ares.dialectic.agents.strategies.prompts_v3 import (
    NARRATOR_SYSTEM_PROMPT_V3,
    SKEPTIC_SYSTEM_PROMPT_V3,
)
from ares.dialectic.agents.strategies.prompts_v4 import (
    ARCHITECT_SYSTEM_PROMPT_V4,
    NARRATOR_SYSTEM_PROMPT_V4,
    SKEPTIC_SYSTEM_PROMPT_V4,
)


class TestArchitectV4:
    """Tests for v4 Architect prompt — mixed-signal calibration."""

    def test_contains_mixed_signal_section(self):
        assert "MIXED-SIGNAL" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_contains_070_confidence_cap(self):
        assert "0.70" in ARCHITECT_SYSTEM_PROMPT_V4 or "below 0.70" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_contains_benign_context_awareness(self):
        lower = ARCHITECT_SYSTEM_PROMPT_V4.lower()
        assert "benign" in lower and "threat" in lower

    def test_contains_three_independent_facts_requirement(self):
        assert "3 or more" in ARCHITECT_SYSTEM_PROMPT_V4 or "3+" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_contains_ambiguity_range(self):
        assert "0.50-0.65" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_preserves_exhaustiveness_requirement(self):
        assert "MUST reference" in ARCHITECT_SYSTEM_PROMPT_V4 or "every fact_id" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_preserves_closed_world_rule(self):
        assert "CLOSED WORLD" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_preserves_json_output_format(self):
        assert "JSON array" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_preserves_pattern_types(self):
        assert "PRIVILEGE_ESCALATION" in ARCHITECT_SYSTEM_PROMPT_V4

    def test_is_string_with_content(self):
        assert isinstance(ARCHITECT_SYSTEM_PROMPT_V4, str)
        assert len(ARCHITECT_SYSTEM_PROMPT_V4) > 200


class TestSkepticV4Unchanged:
    """Verify v4 Skeptic prompt is identical to v3."""

    def test_skeptic_v4_equals_v3(self):
        assert SKEPTIC_SYSTEM_PROMPT_V4 == SKEPTIC_SYSTEM_PROMPT_V3

    def test_skeptic_v4_is_string(self):
        assert isinstance(SKEPTIC_SYSTEM_PROMPT_V4, str)
        assert len(SKEPTIC_SYSTEM_PROMPT_V4) > 100


class TestNarratorV4Unchanged:
    """Verify v4 Narrator prompt is identical to v3."""

    def test_narrator_v4_equals_v3(self):
        assert NARRATOR_SYSTEM_PROMPT_V4 == NARRATOR_SYSTEM_PROMPT_V3

    def test_narrator_v4_is_string(self):
        assert isinstance(NARRATOR_SYSTEM_PROMPT_V4, str)
        assert len(NARRATOR_SYSTEM_PROMPT_V4) > 50


class TestV4StrategyConstruction:
    """Verify v4 strategy wrappers construct without error."""

    def test_threat_analyzer_v4_constructs(self):
        from unittest.mock import MagicMock
        from ares.dialectic.agents.strategies.llm_strategy_v4 import LLMThreatAnalyzerV4
        mock_client = MagicMock()
        ta = LLMThreatAnalyzerV4(mock_client)
        assert ta is not None

    def test_explanation_finder_v4_constructs(self):
        from unittest.mock import MagicMock
        from ares.dialectic.agents.strategies.llm_strategy_v4 import LLMExplanationFinderV4
        mock_client = MagicMock()
        ef = LLMExplanationFinderV4(mock_client)
        assert ef is not None

    def test_narrative_generator_v4_constructs(self):
        from unittest.mock import MagicMock
        from ares.dialectic.agents.strategies.llm_strategy_v4 import LLMNarrativeGeneratorV4
        mock_client = MagicMock()
        ng = LLMNarrativeGeneratorV4(mock_client)
        assert ng is not None
