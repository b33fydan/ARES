"""Oracle: The SYNTHESIS phase judge and narrator.

The Oracle consists of two components:
1. OracleJudge - A pure deterministic function that computes verdicts
2. OracleNarrator - An agent that explains the verdict in human terms

The critical invariant: The OracleNarrator CANNOT modify the verdict.
It can only explain what the OracleJudge has already decided.

OracleJudge is UNTOUCHED by the Strategy Pattern — verdicts stay deterministic.
Only OracleNarrator accepts a NarrativeGenerator strategy for explanation text.
"""

from __future__ import annotations

import uuid
from typing import Optional, TYPE_CHECKING

from ares.dialectic.agents.base import AgentBase
from ares.dialectic.agents.context import (
    AgentRole,
    DataRequest,
    DataRequests,
    RequestKind,
    RequestPriority,
    TurnContext,
)
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
    Priority,
)

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import NarrativeGenerator
    from ares.dialectic.evidence.packet import EvidencePacket


class OracleJudge:
    """Deterministic verdict computation.

    This is NOT an agent - it's a pure function with no state.
    The verdict is computed using a simple decision table:

    Scoring table (Phase 0 - simple):
    - THREAT_CONFIRMED: architect.confidence >= 0.7 AND skeptic.confidence < 0.5
    - THREAT_DISMISSED: skeptic.confidence >= 0.7 AND architect.confidence < 0.5
    - INCONCLUSIVE: otherwise

    The OracleJudge never considers narrative content - only the
    machine-checkable confidence scores and assertion counts.
    """

    # Thresholds for verdict determination
    CONFIRM_THRESHOLD = 0.7  # Architect confidence needed for confirmation
    DISMISS_THRESHOLD = 0.7  # Skeptic confidence needed for dismissal
    WEAK_THRESHOLD = 0.5  # Below this, the opposing side is considered weak

    @staticmethod
    def compute_verdict(
        architect_msg: DialecticalMessage,
        skeptic_msg: DialecticalMessage,
        packet: "EvidencePacket",
    ) -> Verdict:
        """Compute the deterministic verdict from the dialectical exchange.

        This is a pure function - same inputs always produce same outputs.
        The verdict is based solely on:
        1. Confidence scores from both agents
        2. Evidence coverage (fact IDs cited)
        3. Assertion counts

        Args:
            architect_msg: The Architect's HYPOTHESIS message
            skeptic_msg: The Skeptic's REBUTTAL message
            packet: The EvidencePacket for reference

        Returns:
            An immutable Verdict dataclass
        """
        arch_confidence = architect_msg.confidence
        skep_confidence = skeptic_msg.confidence

        # Collect supporting facts based on outcome
        arch_facts = architect_msg.get_all_fact_ids()
        skep_facts = skeptic_msg.get_all_fact_ids()

        # Compute outcome using decision table
        outcome, reasoning = OracleJudge._apply_decision_table(
            arch_confidence,
            skep_confidence,
            len(arch_facts),
            len(skep_facts),
        )

        # Determine supporting facts based on outcome
        if outcome == VerdictOutcome.THREAT_CONFIRMED:
            supporting_facts = frozenset(arch_facts)
            final_confidence = arch_confidence
        elif outcome == VerdictOutcome.THREAT_DISMISSED:
            supporting_facts = frozenset(skep_facts)
            final_confidence = skep_confidence
        else:
            # Inconclusive - include facts from both
            supporting_facts = frozenset(arch_facts | skep_facts)
            # Average confidence when inconclusive
            final_confidence = (arch_confidence + skep_confidence) / 2

        return Verdict(
            outcome=outcome,
            confidence=final_confidence,
            supporting_fact_ids=supporting_facts,
            architect_confidence=arch_confidence,
            skeptic_confidence=skep_confidence,
            reasoning=reasoning,
        )

    @staticmethod
    def _apply_decision_table(
        arch_conf: float,
        skep_conf: float,
        arch_fact_count: int,
        skep_fact_count: int,
    ) -> tuple[VerdictOutcome, str]:
        """Apply the decision table to determine verdict outcome.

        Args:
            arch_conf: Architect's confidence (0.0-1.0)
            skep_conf: Skeptic's confidence (0.0-1.0)
            arch_fact_count: Number of facts cited by Architect
            skep_fact_count: Number of facts cited by Skeptic

        Returns:
            Tuple of (VerdictOutcome, reasoning string)
        """
        # Primary decision: Confidence comparison
        if (
            arch_conf >= OracleJudge.CONFIRM_THRESHOLD
            and skep_conf < OracleJudge.WEAK_THRESHOLD
        ):
            return (
                VerdictOutcome.THREAT_CONFIRMED,
                f"Architect confidence ({arch_conf:.2f}) exceeds threshold "
                f"({OracleJudge.CONFIRM_THRESHOLD}) while Skeptic confidence "
                f"({skep_conf:.2f}) is below weak threshold ({OracleJudge.WEAK_THRESHOLD})",
            )

        if (
            skep_conf >= OracleJudge.DISMISS_THRESHOLD
            and arch_conf < OracleJudge.WEAK_THRESHOLD
        ):
            return (
                VerdictOutcome.THREAT_DISMISSED,
                f"Skeptic confidence ({skep_conf:.2f}) exceeds threshold "
                f"({OracleJudge.DISMISS_THRESHOLD}) while Architect confidence "
                f"({arch_conf:.2f}) is below weak threshold ({OracleJudge.WEAK_THRESHOLD})",
            )

        # Secondary decision: Strong evidence from one side with weak opposition
        if arch_conf >= OracleJudge.CONFIRM_THRESHOLD and arch_fact_count > skep_fact_count * 2:
            return (
                VerdictOutcome.THREAT_CONFIRMED,
                f"Architect has high confidence ({arch_conf:.2f}) with significantly "
                f"more evidence ({arch_fact_count} vs {skep_fact_count} facts)",
            )

        if skep_conf >= OracleJudge.DISMISS_THRESHOLD and skep_fact_count > arch_fact_count * 2:
            return (
                VerdictOutcome.THREAT_DISMISSED,
                f"Skeptic has high confidence ({skep_conf:.2f}) with significantly "
                f"more evidence ({skep_fact_count} vs {arch_fact_count} facts)",
            )

        # Default: Inconclusive
        return (
            VerdictOutcome.INCONCLUSIVE,
            f"Neither side has decisive advantage. Architect: {arch_conf:.2f} "
            f"({arch_fact_count} facts), Skeptic: {skep_conf:.2f} ({skep_fact_count} facts)",
        )


class OracleNarrator(AgentBase):
    """SYNTHESIS phase agent that explains the verdict.

    The OracleNarrator receives a locked Verdict and generates a
    human-readable explanation. It CANNOT modify the verdict - only
    explain it.

    Constraints:
    - Receives locked Verdict (cannot modify)
    - Must cite fact_ids in explanation
    - Produces VERDICT message type

    Rule-based (Phase 0): Template-based explanation from verdict + facts
    LLM seam: Future enhancement for natural language
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        verdict: Optional[Verdict] = None,
        max_memory_size: int = 100,
        *,
        narrative_generator: Optional["NarrativeGenerator"] = None,
    ) -> None:
        """Initialize the OracleNarrator.

        Args:
            agent_id: Optional custom agent ID
            verdict: The locked verdict to explain (required for acting)
            max_memory_size: Maximum working memory entries
            narrative_generator: Strategy for narrative generation.
                Defaults to RuleBasedNarrativeGenerator.
        """
        super().__init__(agent_id=agent_id, max_memory_size=max_memory_size)
        self._locked_verdict: Optional[Verdict] = verdict
        if narrative_generator is None:
            from ares.dialectic.agents.strategies.rule_based import (
                RuleBasedNarrativeGenerator,
            )

            narrative_generator = RuleBasedNarrativeGenerator()
        self._narrative_generator = narrative_generator

    @property
    def role(self) -> AgentRole:
        """The OracleNarrator acts in the SYNTHESIS phase."""
        return AgentRole.ORACLE

    @property
    def verdict(self) -> Optional[Verdict]:
        """The locked verdict (read-only)."""
        return self._locked_verdict

    def set_verdict(self, verdict: Verdict) -> None:
        """Set the verdict to explain.

        This should only be called before act() and cannot be
        changed once the agent has produced output.

        Args:
            verdict: The verdict to explain
        """
        if self._messages_produced > 0:
            raise RuntimeError(
                "Cannot change verdict after OracleNarrator has produced output"
            )
        self._locked_verdict = verdict

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[DialecticalMessage], DataRequests]:
        """Compose a VERDICT message explaining the judgment.

        Args:
            context: The TurnContext for this turn

        Returns:
            Tuple of (VERDICT message, data requests)
        """
        if self._locked_verdict is None:
            return None, (
                DataRequest(
                    request_id=f"req-{uuid.uuid4().hex[:8]}",
                    kind=RequestKind.ADDITIONAL_CONTEXT,
                    description="No verdict provided to explain",
                    reason="OracleNarrator requires a computed verdict",
                    priority=RequestPriority.CRITICAL,
                ),
            )

        if self._evidence_packet is None:
            return None, (
                DataRequest(
                    request_id=f"req-{uuid.uuid4().hex[:8]}",
                    kind=RequestKind.MISSING_FACT,
                    description="No evidence packet bound",
                    reason="OracleNarrator needs packet for fact references",
                    priority=RequestPriority.CRITICAL,
                ),
            )

        return self._build_verdict_message(context), ()

    def _build_verdict_message(
        self,
        context: TurnContext,
    ) -> DialecticalMessage:
        """Build the VERDICT message explaining the judgment.

        Args:
            context: The current turn context

        Returns:
            A DialecticalMessage of type VERDICT
        """
        verdict = self._locked_verdict
        assert verdict is not None  # Checked in _compose_impl

        builder = MessageBuilder(
            source_agent=self.agent_id,
            packet_id=context.packet_id,
            cycle_id=context.cycle_id,
        )

        builder.set_target("broadcast")
        builder.set_phase(Phase.SYNTHESIS)
        builder.set_turn(context.turn_number)
        builder.set_type(MessageType.VERDICT)
        builder.set_priority(Priority.CRITICAL)
        builder.set_confidence(verdict.confidence)

        # Create primary verdict assertion
        if verdict.supporting_fact_ids:
            fact_ids = tuple(verdict.supporting_fact_ids)
        elif self._evidence_packet:
            # Fallback to any available fact
            fact_ids = tuple(self._evidence_packet.fact_ids)[:1]
        else:
            fact_ids = ()

        if fact_ids:
            verdict_assertion = Assertion(
                assertion_id="verdict-001-outcome",
                assertion_type=AssertionType.ASSERT,
                fact_ids=fact_ids,
                interpretation=self._generate_verdict_interpretation(verdict),
                operator="==",
                threshold=verdict.outcome.value,
            )
            builder.add_assertion(verdict_assertion)

        # Add confidence explanation assertion
        if len(fact_ids) >= 2:
            confidence_assertion = Assertion.link_facts(
                assertion_id="verdict-002-confidence",
                fact_ids=list(fact_ids[:5]),  # Limit to first 5 facts
                interpretation=self._generate_confidence_explanation(verdict),
            )
            builder.add_assertion(confidence_assertion)

        # Generate narrative explanation
        narrative = self._generate_narrative(verdict)
        builder.set_narrative(narrative)

        return builder.build()

    def _generate_verdict_interpretation(self, verdict: Verdict) -> str:
        """Generate the interpretation string for the verdict assertion.

        Args:
            verdict: The verdict to interpret

        Returns:
            Human-readable interpretation
        """
        if verdict.outcome == VerdictOutcome.THREAT_CONFIRMED:
            return (
                f"Threat hypothesis CONFIRMED with {verdict.confidence:.0%} confidence. "
                f"Evidence supports malicious activity."
            )
        elif verdict.outcome == VerdictOutcome.THREAT_DISMISSED:
            return (
                f"Threat hypothesis DISMISSED with {verdict.confidence:.0%} confidence. "
                f"Benign explanations adequately explain observed activity."
            )
        else:
            return (
                f"Verdict INCONCLUSIVE with {verdict.confidence:.0%} confidence. "
                f"Neither threat nor benign interpretation is clearly supported."
            )

    def _generate_confidence_explanation(self, verdict: Verdict) -> str:
        """Generate explanation of confidence calculation.

        Args:
            verdict: The verdict with confidence scores

        Returns:
            Explanation of how confidence was determined
        """
        arch_conf = verdict.architect_confidence
        skep_conf = verdict.skeptic_confidence
        final_conf = verdict.confidence

        return (
            f"Confidence derived from Architect ({arch_conf:.0%}) vs "
            f"Skeptic ({skep_conf:.0%}). Final confidence: {final_conf:.0%}"
        )

    def _generate_narrative(self, verdict: Verdict) -> str:
        """Generate the full narrative explanation.

        Delegates to the pluggable NarrativeGenerator strategy.
        Default: RuleBasedNarrativeGenerator (identical to original template).

        Args:
            verdict: The verdict to explain

        Returns:
            Complete narrative explanation
        """
        return self._narrative_generator.generate_narrative(
            verdict, self._evidence_packet,
        )


def create_oracle_verdict(
    architect_msg: DialecticalMessage,
    skeptic_msg: DialecticalMessage,
    packet: "EvidencePacket",
) -> tuple[Verdict, OracleNarrator]:
    """Convenience function to compute verdict and create narrator.

    This combines the OracleJudge.compute_verdict() call with
    creating an OracleNarrator ready to explain the verdict.

    Args:
        architect_msg: The Architect's HYPOTHESIS message
        skeptic_msg: The Skeptic's REBUTTAL message
        packet: The EvidencePacket for reference

    Returns:
        Tuple of (Verdict, OracleNarrator ready to act)
    """
    verdict = OracleJudge.compute_verdict(architect_msg, skeptic_msg, packet)
    narrator = OracleNarrator(verdict=verdict)
    narrator.observe(packet)
    return verdict, narrator
