"""ArchitectAgent: The THESIS phase threat hypothesis generator.

The Architect observes an EvidencePacket and proposes threat hypotheses
based on pluggable pattern detection (Strategy Pattern). The default
strategy is rule-based with no LLM involvement.

The Architect's job is to find evidence of malicious activity and
construct a well-supported hypothesis that something suspicious occurred.
"""

from __future__ import annotations

import uuid
from typing import List, Optional, TYPE_CHECKING

from ares.dialectic.agents.base import AgentBase
from ares.dialectic.agents.context import (
    AgentRole,
    DataRequest,
    DataRequests,
    RequestKind,
    RequestPriority,
    TurnContext,
)
from ares.dialectic.agents.patterns import AnomalyPattern, PatternType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
    Priority,
)

if TYPE_CHECKING:
    from ares.dialectic.agents.strategies.protocol import ThreatAnalyzer
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.evidence.fact import Fact


class ArchitectAgent(AgentBase):
    """THESIS phase agent that proposes threat hypotheses.

    Accepts an optional ThreatAnalyzer strategy at construction.
    Default: RuleBasedThreatAnalyzer (deterministic, zero behavior change).

    - Scan facts for anomaly indicators via strategy
    - Build HYPOTHESIS message with ASSERT and LINK assertions
    - Confidence = evidence_density (more corroborating facts = higher confidence)
    """

    def __init__(
        self,
        agent_id: Optional[str] = None,
        max_memory_size: int = 100,
        *,
        threat_analyzer: Optional["ThreatAnalyzer"] = None,
    ) -> None:
        """Initialize the ArchitectAgent.

        Args:
            agent_id: Unique identifier for this agent instance.
            max_memory_size: Maximum entries in working memory.
            threat_analyzer: Strategy for anomaly detection.
                Defaults to RuleBasedThreatAnalyzer.
        """
        super().__init__(agent_id=agent_id, max_memory_size=max_memory_size)
        if threat_analyzer is None:
            from ares.dialectic.agents.strategies.rule_based import (
                RuleBasedThreatAnalyzer,
            )

            threat_analyzer = RuleBasedThreatAnalyzer()
        self._threat_analyzer = threat_analyzer

    # Patterns that indicate privilege escalation
    PRIVILEGE_INDICATORS = frozenset({
        "admin", "administrator", "system", "root", "nt authority",
        "elevated", "high_integrity", "privilege_escalation"
    })

    # Process names commonly abused by attackers
    SUSPICIOUS_PROCESSES = frozenset({
        "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe", "bash.exe", "wsl.exe"
    })

    # Fields that indicate credential access
    CREDENTIAL_FIELDS = frozenset({
        "lsass", "sam", "security", "ntds", "credential", "password",
        "mimikatz", "sekurlsa", "kerberos", "ntlm"
    })

    # Fields indicating lateral movement
    LATERAL_INDICATORS = frozenset({
        "remote", "rdp", "ssh", "wmi", "psexec", "winrm", "smb",
        "lateral", "pivot", "hop"
    })

    # Service-related indicators
    SERVICE_INDICATORS = frozenset({
        "service", "sc.exe", "services.msc", "svchost", "daemon",
        "systemd", "initd", "autorun", "startup"
    })

    @property
    def role(self) -> AgentRole:
        """The Architect acts in the THESIS phase."""
        return AgentRole.ARCHITECT

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[DialecticalMessage], DataRequests]:
        """Compose a HYPOTHESIS message based on detected anomalies.

        Args:
            context: The TurnContext for this turn

        Returns:
            Tuple of (HYPOTHESIS message, data requests)
        """
        if self._evidence_packet is None:
            # Should not happen if observe() was called, but be defensive
            return None, (
                DataRequest(
                    request_id=f"req-{uuid.uuid4().hex[:8]}",
                    kind=RequestKind.MISSING_FACT,
                    description="No evidence packet bound",
                    reason="Architect cannot analyze without evidence",
                    priority=RequestPriority.CRITICAL,
                ),
            )

        # Detect anomalies using rule-based logic
        anomalies = self._detect_anomalies(self._evidence_packet)

        if not anomalies:
            # No anomalies detected - return a low-confidence observation
            return self._build_no_threat_message(context), ()

        # Build hypothesis from detected anomalies
        return self._build_hypothesis_message(context, anomalies), ()

    def _detect_anomalies(self, packet: "EvidencePacket") -> List[AnomalyPattern]:
        """Detect anomaly patterns in the evidence.

        Delegates to the pluggable ThreatAnalyzer strategy.
        Default: RuleBasedThreatAnalyzer (identical to original inline logic).

        Args:
            packet: The EvidencePacket to analyze

        Returns:
            List of detected AnomalyPattern instances
        """
        return self._threat_analyzer.analyze_threats(packet)

    def _build_hypothesis_message(
        self,
        context: TurnContext,
        anomalies: List[AnomalyPattern],
    ) -> DialecticalMessage:
        """Build a HYPOTHESIS message from detected anomalies.

        Converts AnomalyPattern instances into structured assertions
        and calculates overall confidence based on evidence coverage.

        Args:
            context: The current turn context
            anomalies: List of detected anomalies

        Returns:
            A DialecticalMessage of type HYPOTHESIS
        """
        builder = MessageBuilder(
            source_agent=self.agent_id,
            packet_id=context.packet_id,
            cycle_id=context.cycle_id,
        )

        builder.set_target("broadcast")
        builder.set_phase(Phase.THESIS)
        builder.set_turn(context.turn_number)
        builder.set_type(MessageType.HYPOTHESIS)
        builder.set_priority(Priority.HIGH)

        # Convert anomalies to assertions
        all_fact_ids: set[str] = set()
        weighted_confidence = 0.0
        total_weight = 0.0

        for i, anomaly in enumerate(anomalies):
            # Create ASSERT assertion for the pattern detection
            assertion = Assertion(
                assertion_id=f"hyp-{i:03d}-{anomaly.pattern_type.value}",
                assertion_type=AssertionType.ASSERT,
                fact_ids=tuple(anomaly.fact_ids),
                interpretation=anomaly.description,
                operator="detected",
                threshold=anomaly.pattern_type.value,
            )
            builder.add_assertion(assertion)

            all_fact_ids.update(anomaly.fact_ids)
            weight = len(anomaly.fact_ids)
            weighted_confidence += anomaly.confidence * weight
            total_weight += weight

        # Add LINK assertion if multiple anomalies reference overlapping facts
        if len(anomalies) > 1:
            shared_facts = set.intersection(*[set(a.fact_ids) for a in anomalies])
            if shared_facts:
                link_assertion = Assertion.link_facts(
                    assertion_id="link-001-multi-pattern",
                    fact_ids=list(shared_facts),
                    interpretation="Multiple threat patterns share common evidence, suggesting coordinated attack",
                )
                builder.add_assertion(link_assertion)

        # Calculate overall confidence
        if total_weight > 0:
            base_confidence = weighted_confidence / total_weight
        else:
            base_confidence = 0.3

        # Boost confidence if multiple patterns detected
        pattern_bonus = min(0.2, (len(anomalies) - 1) * 0.05)
        overall_confidence = min(1.0, base_confidence + pattern_bonus)

        builder.set_confidence(overall_confidence)

        # Build narrative (LOW TRUST - for human consumption only)
        pattern_names = [a.pattern_type.value for a in anomalies]
        builder.set_narrative(
            f"Detected {len(anomalies)} threat pattern(s): {', '.join(pattern_names)}. "
            f"Based on {len(all_fact_ids)} supporting facts."
        )

        return builder.build()

    def _build_no_threat_message(
        self,
        context: TurnContext,
    ) -> DialecticalMessage:
        """Build a low-confidence message when no anomalies are detected.

        Args:
            context: The current turn context

        Returns:
            A DialecticalMessage indicating no threats found
        """
        builder = MessageBuilder(
            source_agent=self.agent_id,
            packet_id=context.packet_id,
            cycle_id=context.cycle_id,
        )

        builder.set_target("broadcast")
        builder.set_phase(Phase.THESIS)
        builder.set_turn(context.turn_number)
        builder.set_type(MessageType.OBSERVATION)
        builder.set_priority(Priority.LOW)
        builder.set_confidence(0.1)

        # Need at least one assertion for the message to be valid
        # Use a minimal assertion referencing any available fact
        if self._evidence_packet and self._evidence_packet.fact_ids:
            any_fact_id = next(iter(self._evidence_packet.fact_ids))
            assertion = Assertion(
                assertion_id="obs-001-no-threat",
                assertion_type=AssertionType.ASSERT,
                fact_ids=(any_fact_id,),
                interpretation="No significant threat indicators detected in available evidence",
                operator="==",
                threshold="benign",
            )
            builder.add_assertion(assertion)

        builder.set_narrative(
            "Initial scan of evidence did not reveal significant threat indicators. "
            "Activity appears within normal operational parameters."
        )
        builder.add_unknown("Additional context may reveal hidden threats")

        return builder.build()
