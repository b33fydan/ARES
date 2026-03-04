"""Tests for round 2+ prompt templates and context extraction.

All tests are deterministic — no LLM calls. Tests verify that:
- extract_debate_summary() produces concise, complete summaries
- Refinement prompts include base prompts + opponent arguments
- Prompts demand engagement rather than repetition
"""

from __future__ import annotations

from ares.dialectic.agents.strategies.multi_turn_prompts import (
    build_architect_refinement_prompt,
    build_narrator_multi_turn_prompt,
    build_skeptic_refinement_prompt,
    extract_debate_summary,
)
from ares.dialectic.agents.strategies.prompts import (
    ARCHITECT_SYSTEM_PROMPT,
    NARRATOR_SYSTEM_PROMPT,
    SKEPTIC_SYSTEM_PROMPT,
)
from ares.dialectic.messages.protocol import Phase

from .conftest import make_assertion, make_message


# =============================================================================
# extract_debate_summary Tests
# =============================================================================


class TestExtractDebateSummary:
    """Tests for debate message summarization."""

    def test_extract_debate_summary_returns_string(self):
        """Summary is a non-empty string."""
        msg = make_message(confidence=0.8)
        result = extract_debate_summary(msg)
        assert isinstance(result, str)
        assert len(result) > 0

    def test_extract_debate_summary_includes_confidence(self):
        """Summary includes the agent's confidence level."""
        msg = make_message(confidence=0.85)
        result = extract_debate_summary(msg)
        assert "85%" in result

    def test_extract_debate_summary_includes_fact_ids(self):
        """Summary includes fact_ids cited in assertions."""
        msg = make_message(fact_ids=("fact-001", "fact-002"))
        result = extract_debate_summary(msg)
        assert "fact-001" in result
        assert "fact-002" in result

    def test_extract_debate_summary_includes_assertion_type(self):
        """Summary includes assertion type labels."""
        msg = make_message()
        result = extract_debate_summary(msg)
        assert "ASSERT" in result

    def test_extract_debate_summary_includes_interpretation(self):
        """Summary includes assertion interpretations."""
        assertion = make_assertion(interpretation="Privilege escalation detected")
        msg = make_message(assertions=[assertion])
        result = extract_debate_summary(msg)
        assert "Privilege escalation detected" in result

    def test_extract_debate_summary_bounded_length(self):
        """Summary is concise — not unbounded even with many assertions."""
        assertions = [
            make_assertion(
                assertion_id=f"assert-{i:03d}",
                fact_ids=("fact-001",),
                interpretation=f"Test assertion number {i}",
            )
            for i in range(20)
        ]
        msg = make_message(assertions=assertions)
        result = extract_debate_summary(msg)
        # Should not be enormous — each line is short
        # 20 assertions * ~80 chars + header ≈ 1700 chars max
        assert len(result) < 3000

    def test_extract_debate_summary_includes_phase(self):
        """Summary includes the phase label."""
        msg = make_message(phase=Phase.ANTITHESIS)
        result = extract_debate_summary(msg)
        assert "ANTITHESIS" in result

    def test_extract_debate_summary_includes_unknowns(self):
        """Summary includes unknowns if present."""
        msg = make_message()
        msg.unknowns = ["Missing network logs", "Incomplete timeline"]
        result = extract_debate_summary(msg)
        assert "Missing network logs" in result


# =============================================================================
# build_architect_refinement_prompt Tests
# =============================================================================


class TestBuildArchitectRefinementPrompt:
    """Tests for Architect round 2+ prompt construction."""

    def test_build_architect_refinement_prompt_includes_base(self):
        """Refinement prompt starts with the base Architect system prompt."""
        skeptic_msg = make_message(
            source_agent="skeptic",
            phase=Phase.ANTITHESIS,
            confidence=0.6,
        )
        result = build_architect_refinement_prompt(
            round_number=2,
            previous_antithesis=skeptic_msg,
            base_system_prompt=ARCHITECT_SYSTEM_PROMPT,
        )
        assert ARCHITECT_SYSTEM_PROMPT in result

    def test_build_architect_refinement_prompt_includes_skeptic_summary(self):
        """Refinement prompt includes the Skeptic's arguments."""
        assertion = make_assertion(
            assertion_id="skep-assert-1",
            fact_ids=("fact-003",),
            interpretation="Known admin performing maintenance",
        )
        skeptic_msg = make_message(
            source_agent="skeptic",
            phase=Phase.ANTITHESIS,
            confidence=0.6,
            assertions=[assertion],
        )
        result = build_architect_refinement_prompt(
            round_number=2,
            previous_antithesis=skeptic_msg,
            base_system_prompt=ARCHITECT_SYSTEM_PROMPT,
        )
        assert "Known admin performing maintenance" in result
        assert "fact-003" in result

    def test_build_architect_refinement_prompt_includes_round_number(self):
        """Refinement prompt mentions the current round number."""
        skeptic_msg = make_message(phase=Phase.ANTITHESIS)
        result = build_architect_refinement_prompt(
            round_number=3,
            previous_antithesis=skeptic_msg,
            base_system_prompt=ARCHITECT_SYSTEM_PROMPT,
        )
        assert "round 3" in result.lower() or "ROUND 3" in result

    def test_build_architect_refinement_prompt_demands_engagement(self):
        """Refinement prompt explicitly demands engagement with arguments."""
        skeptic_msg = make_message(phase=Phase.ANTITHESIS)
        result = build_architect_refinement_prompt(
            round_number=2,
            previous_antithesis=skeptic_msg,
            base_system_prompt=ARCHITECT_SYSTEM_PROMPT,
        )
        assert "Address" in result or "address" in result
        assert "repeat" in result.lower()


# =============================================================================
# build_skeptic_refinement_prompt Tests
# =============================================================================


class TestBuildSkepticRefinementPrompt:
    """Tests for Skeptic round 2+ prompt construction."""

    def test_build_skeptic_refinement_prompt_includes_base(self):
        """Refinement prompt starts with the base Skeptic system prompt."""
        architect_msg = make_message(confidence=0.9)
        result = build_skeptic_refinement_prompt(
            round_number=2,
            previous_thesis=architect_msg,
            base_system_prompt=SKEPTIC_SYSTEM_PROMPT,
        )
        assert SKEPTIC_SYSTEM_PROMPT in result

    def test_build_skeptic_refinement_prompt_includes_architect_summary(self):
        """Refinement prompt includes the Architect's arguments."""
        assertion = make_assertion(
            assertion_id="arch-assert-1",
            fact_ids=("fact-001", "fact-002"),
            interpretation="Privilege escalation attack chain",
        )
        architect_msg = make_message(
            confidence=0.9,
            assertions=[assertion],
        )
        result = build_skeptic_refinement_prompt(
            round_number=2,
            previous_thesis=architect_msg,
            base_system_prompt=SKEPTIC_SYSTEM_PROMPT,
        )
        assert "Privilege escalation attack chain" in result
        assert "fact-001" in result


# =============================================================================
# build_narrator_multi_turn_prompt Tests
# =============================================================================


class TestBuildNarratorMultiTurnPrompt:
    """Tests for Narrator multi-turn prompt construction."""

    def test_build_narrator_multi_turn_prompt_notes_rounds(self):
        """Narrator prompt mentions total rounds."""
        result = build_narrator_multi_turn_prompt(
            total_rounds=3,
            termination_reason="CONFIDENCE_STABILIZED",
            base_system_prompt=NARRATOR_SYSTEM_PROMPT,
        )
        assert "3-round" in result or "3 round" in result

    def test_build_narrator_multi_turn_prompt_notes_termination(self):
        """Narrator prompt mentions termination reason."""
        result = build_narrator_multi_turn_prompt(
            total_rounds=2,
            termination_reason="NO_NEW_EVIDENCE",
            base_system_prompt=NARRATOR_SYSTEM_PROMPT,
        )
        assert "NO_NEW_EVIDENCE" in result

    def test_build_narrator_multi_turn_prompt_includes_base(self):
        """Narrator prompt includes base narrator system prompt."""
        result = build_narrator_multi_turn_prompt(
            total_rounds=2,
            termination_reason="MAX_TURNS_EXCEEDED",
            base_system_prompt=NARRATOR_SYSTEM_PROMPT,
        )
        assert NARRATOR_SYSTEM_PROMPT in result
