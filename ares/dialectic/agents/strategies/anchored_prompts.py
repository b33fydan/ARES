"""Conviction-anchored prompt templates for multi-turn debate.

Session 020: Protocol-level fixes for the debate asymmetry discovered in
Sessions 013-018. Three changes:

A. Architect Conviction Anchoring — only retreat on specific counter-evidence
B. Skeptic Obligation to Move — must acknowledge when rebutted
C. Structured Rebuttal Format — DISPUTED_CLAIMS format for Round 2+

These prompts replace the originals from multi_turn_prompts.py ONLY when
the anchored strategy classes are used. The originals remain as the
control group.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ares.dialectic.agents.strategies.multi_turn_prompts import (
    extract_debate_summary,
)
from ares.dialectic.agents.strategies.prompts import (
    ARCHITECT_SYSTEM_PROMPT,
    SKEPTIC_SYSTEM_PROMPT,
)

if TYPE_CHECKING:
    from ares.dialectic.messages.protocol import DialecticalMessage


# ------------------------------------------------------------------
# A. Architect Conviction Anchoring
# ------------------------------------------------------------------

_ARCHITECT_ANCHORING_BLOCK = """\

CONVICTION ANCHORING — READ CAREFULLY:
- Do NOT lower your confidence in response to general doubt or vague skepticism.
- Only lower your confidence when the Skeptic identifies a SPECIFIC piece of \
evidence (by fact description or entity) that directly contradicts a SPECIFIC \
claim you made.
- If the Skeptic raises a general concern ('this could be benign', 'there \
might be an innocent explanation') without citing specific evidence, HOLD \
your confidence.
- Retreating from a well-evidenced position without new counter-evidence is \
not calibration — it is capitulation."""


_ARCHITECT_ROUND2_ANCHORING = """\
Review the Skeptic's last response. Did they cite a specific fact that \
contradicts a specific claim of yours? If NO — maintain your confidence. \
If YES — adjust ONLY on the specific claim they rebutted, not your overall \
assessment."""


# ------------------------------------------------------------------
# B. Skeptic Obligation to Move
# ------------------------------------------------------------------

_SKEPTIC_OBLIGATION_BLOCK = """\

OBLIGATION TO MOVE — READ CAREFULLY:
- You MUST acknowledge when the Architect has successfully addressed one of \
your concerns.
- If the Architect presents evidence that directly rebuts a specific point \
you raised, you MUST lower your confidence on that point. Holding a position \
after it has been evidentially rebutted is not rigor — it is obstinacy.
- Your role is to stress-test, not to win. If the Architect's case is \
strong, say so."""


_SKEPTIC_ROUND2_OBLIGATION = """\
Review the Architect's last response. Did they present evidence that \
addresses a specific concern you raised? If YES — you MUST lower your \
confidence on that concern. If NO — explain specifically what evidence \
would change your mind."""


# ------------------------------------------------------------------
# C. Structured Rebuttal Format
# ------------------------------------------------------------------

_STRUCTURED_REBUTTAL_FORMAT = """\

RESPONSE FORMAT FOR THIS ROUND:
Before your JSON array, include a structured analysis block. The JSON \
array is STILL REQUIRED at the end — the analysis block helps you \
reason before committing to numbers.

DISPUTED_CLAIMS:
1. [Specific claim in contention]

CLAIM_1_ANALYSIS:
- Evidence supporting: [cite specific facts from the evidence]
- Evidence against: [cite specific facts or note absence]
- My confidence on this claim: [0.0-1.0]

OVERALL_CONFIDENCE: [0.0-1.0]
CONFIDENCE_DELTA: [+X.XX or -X.XX from last round]
DELTA_JUSTIFICATION: [Must cite specific facts if |delta| > 0.10]

After your analysis, respond with the JSON array (same format as round 1). \
JSON array only after the analysis."""


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------


def get_anchored_architect_system_prompt(
    round_number: int,
    previous_messages: list,
) -> str:
    """Build the Architect's system prompt with conviction anchoring.

    Round 1: Standard prompt + anchoring block.
    Round 2+: Standard prompt + anchoring block + opponent context +
              round-specific anchoring + structured rebuttal format.

    Args:
        round_number: Current debate round (1-indexed).
        previous_messages: List of DialecticalMessage from prior rounds.
            For round 2+, the last message from the Skeptic is used.

    Returns:
        Complete system prompt for the Architect.
    """
    base = ARCHITECT_SYSTEM_PROMPT + _ARCHITECT_ANCHORING_BLOCK

    if round_number <= 1 or not previous_messages:
        return base

    # Extract the most recent Skeptic message (last antithesis)
    previous_antithesis = previous_messages[-1]
    skeptic_summary = extract_debate_summary(previous_antithesis)

    return (
        f"{base}\n\n"
        f"--- ROUND {round_number} REFINEMENT ---\n\n"
        f"This is round {round_number} of an iterative debate. "
        f"The Skeptic has challenged your previous analysis with the "
        f"following counterarguments:\n\n"
        f"{skeptic_summary}\n\n"
        f"INSTRUCTIONS FOR THIS ROUND:\n"
        f"1. Address the Skeptic's specific counterarguments — do NOT "
        f"simply repeat your previous analysis\n"
        f"2. {_ARCHITECT_ROUND2_ANCHORING}\n"
        f"3. Introduce any overlooked evidence from the packet that "
        f"strengthens your position\n"
        f"4. You MAY adjust your confidence — but ONLY on claims where "
        f"the Skeptic cited specific counter-evidence\n"
        f"{_STRUCTURED_REBUTTAL_FORMAT}\n"
    )


def get_anchored_skeptic_system_prompt(
    round_number: int,
    previous_messages: list,
) -> str:
    """Build the Skeptic's system prompt with obligation to move.

    Round 1: Standard prompt + obligation block.
    Round 2+: Standard prompt + obligation block + opponent context +
              round-specific obligation + structured rebuttal format.

    Args:
        round_number: Current debate round (1-indexed).
        previous_messages: List of DialecticalMessage from prior rounds.
            For round 2+, the last message from the Architect is used.

    Returns:
        Complete system prompt for the Skeptic.
    """
    base = SKEPTIC_SYSTEM_PROMPT + _SKEPTIC_OBLIGATION_BLOCK

    if round_number <= 1 or not previous_messages:
        return base

    # Extract the most recent Architect message (last thesis)
    previous_thesis = previous_messages[-1]
    architect_summary = extract_debate_summary(previous_thesis)

    return (
        f"{base}\n\n"
        f"--- ROUND {round_number} REFINEMENT ---\n\n"
        f"This is round {round_number} of an iterative debate. "
        f"The Architect has refined their threat assessment:\n\n"
        f"{architect_summary}\n\n"
        f"INSTRUCTIONS FOR THIS ROUND:\n"
        f"1. Address the Architect's specific claims — do NOT simply "
        f"repeat your previous explanations\n"
        f"2. {_SKEPTIC_ROUND2_OBLIGATION}\n"
        f"3. Strengthen explanations where you have additional supporting "
        f"evidence, weaken or drop those that the Architect refuted\n"
        f"4. You MAY adjust your confidence — and you MUST lower it on "
        f"points the Architect successfully rebutted with evidence\n"
        f"{_STRUCTURED_REBUTTAL_FORMAT}\n"
    )
