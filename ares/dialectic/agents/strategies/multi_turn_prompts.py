"""Round 2+ prompt templates and context extraction for multi-turn debate.

Session 014: Round-aware prompts that inject previous debate context,
enabling genuine dialectical engagement between Architect and Skeptic.

Round 1 uses standard prompts from prompts.py (imported at call site).
Round 2+ uses refinement prompts that include the opponent's previous
arguments via extract_debate_summary(), demanding engagement rather
than re-derivation.

Design principles:
- Base prompt carries forward (all calibration + closed-world constraints)
- Opponent arguments injected via concise summary, not raw message dump
- Agents explicitly instructed to engage with prior arguments
- Position change is allowed (agents can weaken their stance)
- Total prompt stays under ~2x single-turn length
"""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.messages.protocol import DialecticalMessage


def extract_debate_summary(message: DialecticalMessage) -> str:
    """Extract a concise summary of a debate message for inclusion in prompts.

    Extracts:
    - Agent role and confidence
    - Key assertions with their fact_id references
    - Overall position summary

    Returns a string suitable for embedding in a prompt (~200-400 tokens).
    The summary must be concise to avoid bloating context windows.

    Args:
        message: The DialecticalMessage to summarize.

    Returns:
        Formatted string summarizing the message content.
    """
    lines: list[str] = []

    # Header: agent role + confidence
    agent_role = message.source_agent
    phase_label = message.phase.value.upper()
    lines.append(
        f"[{phase_label}] Agent '{agent_role}' "
        f"(confidence: {message.confidence:.0%}):"
    )

    # Assertions with fact_ids and interpretations
    for assertion in message.assertions:
        fact_ids_str = ", ".join(sorted(assertion.fact_ids))
        lines.append(
            f"  - [{assertion.assertion_type.value.upper()}] "
            f"{assertion.interpretation} "
            f"(fact_ids: {fact_ids_str})"
        )

    # Unknowns if present
    if message.unknowns:
        lines.append(f"  Acknowledged unknowns: {', '.join(message.unknowns)}")

    return "\n".join(lines)


def build_architect_refinement_prompt(
    round_number: int,
    previous_antithesis: DialecticalMessage,
    base_system_prompt: str,
) -> str:
    """Build the Architect's system prompt for round 2+.

    Includes the base analysis instructions PLUS:
    - The Skeptic's previous counterarguments
    - Explicit instructions to engage with those counterarguments
    - Guidance to introduce overlooked evidence or adjust confidence
    - Prohibition against simply repeating round 1 output

    Args:
        round_number: Current debate round (2+).
        previous_antithesis: The Skeptic's message from the previous round.
        base_system_prompt: The standard ARCHITECT_SYSTEM_PROMPT.

    Returns:
        Complete system prompt for the Architect in round 2+.
    """
    skeptic_summary = extract_debate_summary(previous_antithesis)

    return (
        f"{base_system_prompt}\n\n"
        f"--- ROUND {round_number} REFINEMENT ---\n\n"
        f"This is round {round_number} of an iterative debate. "
        f"The Skeptic has challenged your previous analysis with the "
        f"following counterarguments:\n\n"
        f"{skeptic_summary}\n\n"
        f"INSTRUCTIONS FOR THIS ROUND:\n"
        f"1. Address the Skeptic's specific counterarguments — do NOT "
        f"simply repeat your round 1 analysis\n"
        f"2. If the Skeptic cited evidence of benign activity, either "
        f"explain why the threat interpretation is still stronger OR "
        f"lower your confidence accordingly\n"
        f"3. Introduce any overlooked evidence from the packet that "
        f"strengthens or weakens your position\n"
        f"4. You MAY adjust your confidence up or down based on the "
        f"Skeptic's arguments — intellectual honesty is valued\n"
        f"5. You MAY drop patterns that the Skeptic convincingly refuted "
        f"and add new patterns you missed in round 1\n\n"
        f"Respond with ONLY a JSON array (same format as round 1). "
        f"JSON array only."
    )


def build_skeptic_refinement_prompt(
    round_number: int,
    previous_thesis: DialecticalMessage,
    base_system_prompt: str,
) -> str:
    """Build the Skeptic's system prompt for round 2+.

    Includes the base explanation instructions PLUS:
    - The Architect's refined threat assessment
    - Instructions to address new claims
    - Guidance to strengthen, weaken, or add explanations

    Args:
        round_number: Current debate round (2+).
        previous_thesis: The Architect's message from the previous round.
        base_system_prompt: The standard SKEPTIC_SYSTEM_PROMPT.

    Returns:
        Complete system prompt for the Skeptic in round 2+.
    """
    architect_summary = extract_debate_summary(previous_thesis)

    return (
        f"{base_system_prompt}\n\n"
        f"--- ROUND {round_number} REFINEMENT ---\n\n"
        f"This is round {round_number} of an iterative debate. "
        f"The Architect has refined their threat assessment:\n\n"
        f"{architect_summary}\n\n"
        f"INSTRUCTIONS FOR THIS ROUND:\n"
        f"1. Address the Architect's specific claims — do NOT simply "
        f"repeat your round 1 explanations\n"
        f"2. If the Architect introduced new evidence or patterns, "
        f"propose benign explanations for those specifically\n"
        f"3. Strengthen explanations where you have additional supporting "
        f"evidence, weaken or drop those that the Architect refuted\n"
        f"4. You MAY adjust your confidence up or down based on the "
        f"Architect's arguments — intellectual honesty is valued\n"
        f"5. If the Architect's case is strong, it is acceptable to "
        f"lower your confidence rather than force weak explanations\n\n"
        f"Respond with ONLY a JSON array (same format as round 1). "
        f"JSON array only."
    )


def build_narrator_multi_turn_prompt(
    total_rounds: int,
    termination_reason: str,
    base_system_prompt: str,
) -> str:
    """Build the Narrator's prompt noting this was a multi-round debate.

    Less critical than Architect/Skeptic prompts — Narrator runs once
    at end. Just adds context that the verdict emerged from iterative
    debate.

    Args:
        total_rounds: Number of debate rounds completed.
        termination_reason: Why the debate terminated (e.g., "NO_NEW_EVIDENCE").
        base_system_prompt: The standard NARRATOR_SYSTEM_PROMPT.

    Returns:
        Complete system prompt for the Narrator.
    """
    return (
        f"{base_system_prompt}\n\n"
        f"DEBATE CONTEXT:\n"
        f"This verdict emerged from a {total_rounds}-round iterative "
        f"debate between the Architect and Skeptic. "
        f"The debate terminated due to: {termination_reason}. "
        f"Your explanation should reflect the depth of analysis that "
        f"multiple rounds of debate provided."
    )
