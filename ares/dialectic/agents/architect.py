"""ArchitectAgent: The THESIS phase threat hypothesis generator.

The Architect observes an EvidencePacket and proposes threat hypotheses
based on rule-based pattern detection. This is a deterministic agent
with no LLM involvement - all reasoning is encoded in detection rules.

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
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.evidence.fact import Fact


class ArchitectAgent(AgentBase):
    """THESIS phase agent that proposes threat hypotheses.

    Rule-based logic (no LLM):
    - Scan facts for anomaly indicators
    - Look for: elevated_privileges, unusual_process_spawn, lateral_movement,
      service_modification, credential_access patterns
    - Build HYPOTHESIS message with ASSERT and LINK assertions
    - Confidence = evidence_density (more corroborating facts = higher confidence)

    LLM seam: ReasoningStrategy protocol for future swap
    """

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

        Scans all facts for indicators of suspicious activity.
        Each detection rule checks for specific patterns and produces
        an AnomalyPattern if matched.

        Args:
            packet: The EvidencePacket to analyze

        Returns:
            List of detected AnomalyPattern instances
        """
        anomalies: List[AnomalyPattern] = []

        # Collect facts by field for efficient analysis
        facts_by_field: dict[str, list["Fact"]] = {}
        for fact in packet.get_all_facts():
            field_lower = fact.field.lower()
            if field_lower not in facts_by_field:
                facts_by_field[field_lower] = []
            facts_by_field[field_lower].append(fact)

        # Check for privilege escalation
        priv_anomaly = self._check_privilege_escalation(packet, facts_by_field)
        if priv_anomaly:
            anomalies.append(priv_anomaly)

        # Check for suspicious processes
        proc_anomalies = self._check_suspicious_processes(packet, facts_by_field)
        anomalies.extend(proc_anomalies)

        # Check for credential access
        cred_anomaly = self._check_credential_access(packet, facts_by_field)
        if cred_anomaly:
            anomalies.append(cred_anomaly)

        # Check for lateral movement
        lateral_anomaly = self._check_lateral_movement(packet, facts_by_field)
        if lateral_anomaly:
            anomalies.append(lateral_anomaly)

        # Check for service abuse
        service_anomaly = self._check_service_abuse(packet, facts_by_field)
        if service_anomaly:
            anomalies.append(service_anomaly)

        return anomalies

    def _check_privilege_escalation(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for privilege escalation indicators.

        Looks for:
        - User gaining admin/system privileges
        - Process running with elevated integrity
        - Privilege field changes
        """
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        # Check privilege-related fields
        for field, facts in facts_by_field.items():
            for indicator in self.PRIVILEGE_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.15

        # Check values for privilege indicators
        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.PRIVILEGE_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.1

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return AnomalyPattern(
                pattern_type=PatternType.PRIVILEGE_ESCALATION,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description=f"Privilege escalation indicators detected in {len(supporting_facts)} facts",
            )

        return None

    def _check_suspicious_processes(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> List[AnomalyPattern]:
        """Check for suspicious process execution.

        Looks for:
        - Known attack tools
        - LOLBins (living off the land binaries)
        - Unusual parent-child relationships
        """
        anomalies: List[AnomalyPattern] = []
        process_facts: dict[str, set[str]] = {}  # process_name -> fact_ids

        # Find process-related facts
        for field, facts in facts_by_field.items():
            if "process" in field or "command" in field or "executable" in field:
                for fact in facts:
                    value_str = str(fact.value).lower()
                    for proc in self.SUSPICIOUS_PROCESSES:
                        if proc.lower() in value_str:
                            if proc not in process_facts:
                                process_facts[proc] = set()
                            process_facts[proc].add(fact.fact_id)

        # Check values directly for process names
        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for proc in self.SUSPICIOUS_PROCESSES:
                if proc.lower() in value_str:
                    if proc not in process_facts:
                        process_facts[proc] = set()
                    process_facts[proc].add(fact.fact_id)

        # Create anomaly for each suspicious process found
        for proc_name, fact_ids in process_facts.items():
            if fact_ids:
                confidence = min(1.0, 0.3 + (len(fact_ids) * 0.1))
                anomalies.append(
                    AnomalyPattern(
                        pattern_type=PatternType.SUSPICIOUS_PROCESS,
                        fact_ids=frozenset(fact_ids),
                        confidence=confidence,
                        description=f"Suspicious process execution: {proc_name}",
                    )
                )

        return anomalies

    def _check_credential_access(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for credential access indicators.

        Looks for:
        - LSASS access
        - SAM/SECURITY hive access
        - Credential dumping tools
        """
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        # Check field names for credential indicators
        for field, facts in facts_by_field.items():
            for indicator in self.CREDENTIAL_FIELDS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        # Check values for credential indicators
        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.CREDENTIAL_FIELDS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.3:
            confidence = min(1.0, evidence_strength)
            return AnomalyPattern(
                pattern_type=PatternType.CREDENTIAL_ACCESS,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description=f"Credential access indicators detected in {len(supporting_facts)} facts",
            )

        return None

    def _check_lateral_movement(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for lateral movement indicators.

        Looks for:
        - Remote authentication
        - Network connections to internal hosts
        - Protocol abuse (SMB, WMI, RDP, etc.)
        """
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        # Check field names for lateral movement indicators
        for field, facts in facts_by_field.items():
            for indicator in self.LATERAL_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.15

        # Check values for lateral movement indicators
        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.LATERAL_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.1

        if supporting_facts and evidence_strength >= 0.25:
            confidence = min(1.0, evidence_strength)
            return AnomalyPattern(
                pattern_type=PatternType.LATERAL_MOVEMENT,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description=f"Lateral movement indicators detected in {len(supporting_facts)} facts",
            )

        return None

    def _check_service_abuse(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for service abuse indicators.

        Looks for:
        - Service creation/modification
        - Unusual service commands
        - Persistence mechanisms
        """
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        # Check field names for service indicators
        for field, facts in facts_by_field.items():
            for indicator in self.SERVICE_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.15

        # Check values for service indicators
        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.SERVICE_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.1

        if supporting_facts and evidence_strength >= 0.25:
            confidence = min(1.0, evidence_strength)
            return AnomalyPattern(
                pattern_type=PatternType.SERVICE_ABUSE,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description=f"Service abuse indicators detected in {len(supporting_facts)} facts",
            )

        return None

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
