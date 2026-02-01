"""SkepticAgent: The ANTITHESIS phase counter-argument generator.

The Skeptic challenges the Architect's threat claims by finding benign
explanations for the observed activity. This is a deterministic agent
with no LLM involvement - all reasoning is encoded in detection rules.

The Skeptic's job is to play devil's advocate - finding legitimate
reasons why the activity might not be malicious, even if it looks
suspicious on the surface.
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
from ares.dialectic.agents.patterns import BenignExplanation, ExplanationType
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


class SkepticAgent(AgentBase):
    """ANTITHESIS phase agent that challenges threat claims.

    Rule-based logic (no LLM):
    - Receive Architect's message via receive()
    - For each assertion, check for benign explanations
    - Look for: maintenance_window, known_admin_activity, scheduled_task,
      software_update, legitimate_remote_access
    - Build REBUTTAL message with counter-assertions and ALT alternatives
    - Confidence inversely weighted to Architect's evidence gaps
    """

    # Maintenance-related indicators
    MAINTENANCE_INDICATORS = frozenset({
        "maintenance", "scheduled", "planned", "window", "downtime",
        "outage", "update", "patch", "upgrade"
    })

    # Known admin activity indicators
    ADMIN_INDICATORS = frozenset({
        "admin", "administrator", "sysadmin", "it_staff", "helpdesk",
        "service_account", "automation", "ansible", "puppet", "chef",
        "terraform", "deployment"
    })

    # Scheduled task indicators
    SCHEDULED_INDICATORS = frozenset({
        "cron", "scheduled", "task", "job", "timer", "recurring",
        "automated", "batch", "nightly", "daily", "weekly"
    })

    # Software update indicators
    UPDATE_INDICATORS = frozenset({
        "update", "upgrade", "patch", "hotfix", "security_update",
        "windows_update", "apt", "yum", "pip", "npm", "install"
    })

    # Legitimate remote access indicators
    REMOTE_ACCESS_INDICATORS = frozenset({
        "vpn", "authorized", "approved", "ticket", "change_request",
        "jump_host", "bastion", "citrix", "remote_desktop"
    })

    # Security tool indicators
    SECURITY_TOOL_INDICATORS = frozenset({
        "antivirus", "edr", "siem", "scanner", "vulnerability",
        "pentest", "security", "audit", "compliance", "crowdstrike",
        "defender", "symantec", "mcafee", "nessus", "qualys"
    })

    # Development activity indicators
    DEV_INDICATORS = frozenset({
        "developer", "development", "dev", "test", "staging",
        "sandbox", "debug", "ide", "vscode", "visual_studio"
    })

    # Backup activity indicators
    BACKUP_INDICATORS = frozenset({
        "backup", "restore", "archive", "snapshot", "veeam",
        "commvault", "netbackup", "rsync", "robocopy"
    })

    @property
    def role(self) -> AgentRole:
        """The Skeptic acts in the ANTITHESIS phase."""
        return AgentRole.SKEPTIC

    def _compose_impl(
        self,
        context: TurnContext,
    ) -> tuple[Optional[DialecticalMessage], DataRequests]:
        """Compose a REBUTTAL message challenging the Architect's claims.

        Args:
            context: The TurnContext for this turn

        Returns:
            Tuple of (REBUTTAL message, data requests)
        """
        if self._evidence_packet is None:
            return None, (
                DataRequest(
                    request_id=f"req-{uuid.uuid4().hex[:8]}",
                    kind=RequestKind.MISSING_FACT,
                    description="No evidence packet bound",
                    reason="Skeptic cannot analyze without evidence",
                    priority=RequestPriority.CRITICAL,
                ),
            )

        # Get the Architect's message from working memory
        architect_message = self._get_architect_message()
        if architect_message is None:
            return None, (
                DataRequest(
                    request_id=f"req-{uuid.uuid4().hex[:8]}",
                    kind=RequestKind.ADDITIONAL_CONTEXT,
                    description="No Architect message received",
                    reason="Skeptic needs Architect's hypothesis to challenge",
                    priority=RequestPriority.HIGH,
                ),
            )

        # Find benign explanations for the activity
        explanations = self._find_benign_explanations(
            architect_message,
            self._evidence_packet,
        )

        # Build rebuttal message
        return self._build_rebuttal_message(
            context,
            architect_message,
            explanations,
        ), ()

    def _get_architect_message(self) -> Optional[DialecticalMessage]:
        """Retrieve the Architect's message from working memory.

        Returns:
            The most recent Architect message, or None if not found
        """
        for entry in reversed(self._working_memory):
            if hasattr(entry.content, "phase") and hasattr(entry.content, "message_type"):
                msg = entry.content
                if msg.phase == Phase.THESIS and msg.message_type in (
                    MessageType.HYPOTHESIS,
                    MessageType.OBSERVATION,
                ):
                    return msg
        return None

    def _find_benign_explanations(
        self,
        architect_msg: DialecticalMessage,
        packet: "EvidencePacket",
    ) -> List[BenignExplanation]:
        """Find benign explanations for the Architect's claims.

        For each assertion in the Architect's message, check if there's
        evidence that could explain the activity as benign.

        Args:
            architect_msg: The Architect's hypothesis message
            packet: The EvidencePacket to analyze

        Returns:
            List of BenignExplanation instances
        """
        explanations: List[BenignExplanation] = []

        # Collect all evidence characteristics
        facts_by_field: dict[str, list["Fact"]] = {}
        for fact in packet.get_all_facts():
            field_lower = fact.field.lower()
            if field_lower not in facts_by_field:
                facts_by_field[field_lower] = []
            facts_by_field[field_lower].append(fact)

        # Check for maintenance window
        maint_exp = self._check_maintenance_window(packet, facts_by_field)
        if maint_exp:
            explanations.append(maint_exp)

        # Check for known admin activity
        admin_exp = self._check_known_admin(packet, facts_by_field)
        if admin_exp:
            explanations.append(admin_exp)

        # Check for scheduled tasks
        sched_exp = self._check_scheduled_task(packet, facts_by_field)
        if sched_exp:
            explanations.append(sched_exp)

        # Check for software updates
        update_exp = self._check_software_update(packet, facts_by_field)
        if update_exp:
            explanations.append(update_exp)

        # Check for legitimate remote access
        remote_exp = self._check_legitimate_remote(packet, facts_by_field)
        if remote_exp:
            explanations.append(remote_exp)

        # Check for security tools
        security_exp = self._check_security_tool(packet, facts_by_field)
        if security_exp:
            explanations.append(security_exp)

        # Check for development activity
        dev_exp = self._check_development_activity(packet, facts_by_field)
        if dev_exp:
            explanations.append(dev_exp)

        # Check for backup activity
        backup_exp = self._check_backup_activity(packet, facts_by_field)
        if backup_exp:
            explanations.append(backup_exp)

        return explanations

    def _check_maintenance_window(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity occurred during a maintenance window."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.MAINTENANCE_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.MAINTENANCE_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.MAINTENANCE_WINDOW,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity coincides with scheduled maintenance window",
            )
        return None

    def _check_known_admin(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity was performed by known administrators."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.ADMIN_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.ADMIN_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.KNOWN_ADMIN,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity performed by known administrative account or process",
            )
        return None

    def _check_scheduled_task(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity matches known scheduled task patterns."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.SCHEDULED_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.SCHEDULED_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.SCHEDULED_TASK,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity matches pattern of scheduled/automated task",
            )
        return None

    def _check_software_update(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity is related to software updates."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.UPDATE_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.UPDATE_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.SOFTWARE_UPDATE,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity consistent with software update or patching",
            )
        return None

    def _check_legitimate_remote(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if remote access is legitimate."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.REMOTE_ACCESS_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.REMOTE_ACCESS_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.LEGITIMATE_REMOTE_ACCESS,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Remote access appears to be authorized/legitimate",
            )
        return None

    def _check_security_tool(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity is from security tools."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.SECURITY_TOOL_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.25

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.SECURITY_TOOL_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.2

        if supporting_facts and evidence_strength >= 0.25:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.SECURITY_TOOL,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity attributed to legitimate security tool operation",
            )
        return None

    def _check_development_activity(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity is development-related."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.DEV_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.DEV_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.DEVELOPMENT_ACTIVITY,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity consistent with normal development operations",
            )
        return None

    def _check_backup_activity(
        self,
        packet: "EvidencePacket",
        facts_by_field: dict[str, list["Fact"]],
    ) -> Optional[BenignExplanation]:
        """Check if activity is backup-related."""
        supporting_facts: set[str] = set()
        evidence_strength = 0.0

        for field, facts in facts_by_field.items():
            for indicator in self.BACKUP_INDICATORS:
                if indicator in field:
                    for fact in facts:
                        supporting_facts.add(fact.fact_id)
                        evidence_strength += 0.2

        for fact in packet.get_all_facts():
            value_str = str(fact.value).lower()
            for indicator in self.BACKUP_INDICATORS:
                if indicator in value_str:
                    supporting_facts.add(fact.fact_id)
                    evidence_strength += 0.15

        if supporting_facts and evidence_strength >= 0.2:
            confidence = min(1.0, evidence_strength)
            return BenignExplanation(
                explanation_type=ExplanationType.AUTOMATED_BACKUP,
                fact_ids=frozenset(supporting_facts),
                confidence=confidence,
                description="Activity matches automated backup operation patterns",
            )
        return None

    def _build_rebuttal_message(
        self,
        context: TurnContext,
        architect_msg: DialecticalMessage,
        explanations: List[BenignExplanation],
    ) -> DialecticalMessage:
        """Build a REBUTTAL message challenging the Architect's claims.

        Args:
            context: The current turn context
            architect_msg: The Architect's hypothesis
            explanations: List of benign explanations found

        Returns:
            A DialecticalMessage of type REBUTTAL
        """
        builder = MessageBuilder(
            source_agent=self.agent_id,
            packet_id=context.packet_id,
            cycle_id=context.cycle_id,
        )

        builder.set_target("broadcast")
        builder.set_phase(Phase.ANTITHESIS)
        builder.set_turn(context.turn_number)
        builder.set_type(MessageType.REBUTTAL)
        builder.set_priority(Priority.HIGH)
        builder.reply_to(architect_msg.message_id)

        all_fact_ids: set[str] = set()
        weighted_confidence = 0.0
        total_weight = 0.0

        # Create REBUTTAL assertions for weak points in Architect's claims
        for i, assertion in enumerate(architect_msg.assertions):
            # Look for evidence gaps in Architect's assertions
            gaps = self._find_assertion_gaps(assertion)
            if gaps:
                gap_assertion = Assertion(
                    assertion_id=f"reb-{i:03d}-gap",
                    assertion_type=AssertionType.ASSERT,
                    fact_ids=assertion.fact_ids,  # Reference same facts
                    interpretation=f"Architect's claim has evidence gaps: {gaps}",
                    operator="insufficient",
                    threshold="evidence",
                )
                builder.add_assertion(gap_assertion)
                all_fact_ids.update(assertion.fact_ids)

        # Create ALT assertions for benign explanations
        for i, explanation in enumerate(explanations):
            alt_assertion = Assertion.alternative(
                assertion_id=f"alt-{i:03d}-{explanation.explanation_type.value}",
                fact_ids=list(explanation.fact_ids),
                interpretation=explanation.description,
            )
            builder.add_assertion(alt_assertion)

            all_fact_ids.update(explanation.fact_ids)
            weight = len(explanation.fact_ids)
            weighted_confidence += explanation.confidence * weight
            total_weight += weight

        # If no specific rebuttals, add a general challenge
        if not builder._assertions:
            # Challenge based on evidence coverage
            architect_facts = architect_msg.get_all_fact_ids()
            if self._evidence_packet:
                all_facts = self._evidence_packet.fact_ids
                uncovered = all_facts - architect_facts
                if uncovered:
                    # Reference at least one uncovered fact
                    sample_fact = next(iter(uncovered))
                    challenge = Assertion(
                        assertion_id="reb-001-coverage",
                        assertion_type=AssertionType.ASSERT,
                        fact_ids=(sample_fact,),
                        interpretation="Architect's analysis did not consider all available evidence",
                        operator="<",
                        threshold=f"{len(architect_facts)}/{len(all_facts)} facts analyzed",
                    )
                    builder.add_assertion(challenge)
                    all_fact_ids.add(sample_fact)
                else:
                    # All facts covered - use any fact for a placeholder assertion
                    any_fact = next(iter(architect_facts)) if architect_facts else None
                    if any_fact:
                        challenge = Assertion(
                            assertion_id="reb-001-alternative",
                            assertion_type=AssertionType.ASSERT,
                            fact_ids=(any_fact,),
                            interpretation="Alternative interpretations exist for the observed activity",
                            operator="exists",
                            threshold="alternative_explanation",
                        )
                        builder.add_assertion(challenge)
                        all_fact_ids.add(any_fact)

        # Calculate confidence
        if explanations:
            if total_weight > 0:
                base_confidence = weighted_confidence / total_weight
            else:
                base_confidence = 0.3

            # Boost for multiple explanations
            explanation_bonus = min(0.2, (len(explanations) - 1) * 0.05)
            overall_confidence = min(1.0, base_confidence + explanation_bonus)
        else:
            # No strong benign explanations - lower confidence
            overall_confidence = 0.3 - (architect_msg.confidence * 0.1)
            overall_confidence = max(0.1, overall_confidence)

        builder.set_confidence(overall_confidence)

        # Build narrative
        if explanations:
            exp_names = [e.explanation_type.value for e in explanations]
            builder.set_narrative(
                f"Challenge to Architect's hypothesis based on {len(explanations)} "
                f"benign explanation(s): {', '.join(exp_names)}. "
                f"Activity may be legitimate."
            )
        else:
            builder.set_narrative(
                "Challenging Architect's claims due to evidence gaps and "
                "insufficient corroboration. Alternative explanations possible."
            )

        return builder.build()

    def _find_assertion_gaps(self, assertion: Assertion) -> Optional[str]:
        """Find evidence gaps in an assertion.

        Args:
            assertion: The assertion to analyze

        Returns:
            Description of gaps, or None if assertion is well-supported
        """
        # Check for minimal evidence
        if len(assertion.fact_ids) < 2:
            return "single fact insufficient for pattern confirmation"

        # Check for missing corroboration
        if assertion.assertion_type == AssertionType.ASSERT:
            if not assertion.operator or not assertion.threshold:
                return "assertion lacks specific criteria"

        return None
