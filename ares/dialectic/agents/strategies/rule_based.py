"""Rule-based strategy implementations.

Mechanically extracted from ArchitectAgent, SkepticAgent, and OracleNarrator.
These classes produce IDENTICAL behavior to the original inline methods.
They exist to satisfy the Strategy Pattern — the 926 existing tests serve
as a regression suite proving the extraction is lossless.
"""

from __future__ import annotations

from typing import Dict, List, Optional, TYPE_CHECKING

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    BenignExplanation,
    ExplanationType,
    PatternType,
    Verdict,
    VerdictOutcome,
)

if TYPE_CHECKING:
    from ares.dialectic.evidence.fact import Fact
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


class RuleBasedThreatAnalyzer:
    """Extracted from ArchitectAgent._detect_anomalies(). Zero behavior change.

    Scans all facts for indicators of suspicious activity using static
    indicator sets. Each detection rule checks for specific patterns
    and produces an AnomalyPattern if matched.
    """

    # Patterns that indicate privilege escalation
    PRIVILEGE_INDICATORS = frozenset({
        "admin", "administrator", "system", "root", "nt authority",
        "elevated", "high_integrity", "privilege_escalation",
    })

    # Process names commonly abused by attackers
    SUSPICIOUS_PROCESSES = frozenset({
        "cmd.exe", "powershell.exe", "pwsh.exe", "cscript.exe", "wscript.exe",
        "mshta.exe", "regsvr32.exe", "rundll32.exe", "certutil.exe",
        "bitsadmin.exe", "msiexec.exe", "bash.exe", "wsl.exe",
    })

    # Fields that indicate credential access
    CREDENTIAL_FIELDS = frozenset({
        "lsass", "sam", "security", "ntds", "credential", "password",
        "mimikatz", "sekurlsa", "kerberos", "ntlm",
    })

    # Fields indicating lateral movement
    LATERAL_INDICATORS = frozenset({
        "remote", "rdp", "ssh", "wmi", "psexec", "winrm", "smb",
        "lateral", "pivot", "hop",
    })

    # Service-related indicators
    SERVICE_INDICATORS = frozenset({
        "service", "sc.exe", "services.msc", "svchost", "daemon",
        "systemd", "initd", "autorun", "startup",
    })

    def analyze_threats(self, packet: "EvidencePacket") -> List[AnomalyPattern]:
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
        facts_by_field: Dict[str, List["Fact"]] = {}
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
        facts_by_field: Dict[str, List["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for privilege escalation indicators."""
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
        facts_by_field: Dict[str, List["Fact"]],
    ) -> List[AnomalyPattern]:
        """Check for suspicious process execution."""
        anomalies: List[AnomalyPattern] = []
        process_facts: Dict[str, set[str]] = {}  # process_name -> fact_ids

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
        facts_by_field: Dict[str, List["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for credential access indicators."""
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
        facts_by_field: Dict[str, List["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for lateral movement indicators."""
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
        facts_by_field: Dict[str, List["Fact"]],
    ) -> Optional[AnomalyPattern]:
        """Check for service abuse indicators."""
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


class RuleBasedExplanationFinder:
    """Extracted from SkepticAgent._find_benign_explanations(). Zero behavior change.

    Checks evidence for benign indicators that could explain observed
    activity as legitimate. The architect_msg parameter exists for
    protocol compatibility but is not used by the rule-based implementation.
    """

    # Maintenance-related indicators
    MAINTENANCE_INDICATORS = frozenset({
        "maintenance", "scheduled", "planned", "window", "downtime",
        "outage", "update", "patch", "upgrade",
    })

    # Known admin activity indicators
    ADMIN_INDICATORS = frozenset({
        "admin", "administrator", "sysadmin", "it_staff", "helpdesk",
        "service_account", "automation", "ansible", "puppet", "chef",
        "terraform", "deployment",
    })

    # Scheduled task indicators
    SCHEDULED_INDICATORS = frozenset({
        "cron", "scheduled", "task", "job", "timer", "recurring",
        "automated", "batch", "nightly", "daily", "weekly",
    })

    # Software update indicators
    UPDATE_INDICATORS = frozenset({
        "update", "upgrade", "patch", "hotfix", "security_update",
        "windows_update", "apt", "yum", "pip", "npm", "install",
    })

    # Legitimate remote access indicators
    REMOTE_ACCESS_INDICATORS = frozenset({
        "vpn", "authorized", "approved", "ticket", "change_request",
        "jump_host", "bastion", "citrix", "remote_desktop",
    })

    # Security tool indicators
    SECURITY_TOOL_INDICATORS = frozenset({
        "antivirus", "edr", "siem", "scanner", "vulnerability",
        "pentest", "security", "audit", "compliance", "crowdstrike",
        "defender", "symantec", "mcafee", "nessus", "qualys",
    })

    # Development activity indicators
    DEV_INDICATORS = frozenset({
        "developer", "development", "dev", "test", "staging",
        "sandbox", "debug", "ide", "vscode", "visual_studio",
    })

    # Backup activity indicators
    BACKUP_INDICATORS = frozenset({
        "backup", "restore", "archive", "snapshot", "veeam",
        "commvault", "netbackup", "rsync", "robocopy",
    })

    def find_explanations(
        self,
        architect_msg: "DialecticalMessage",
        packet: "EvidencePacket",
    ) -> List[BenignExplanation]:
        """Find benign explanations for the observed activity.

        The architect_msg is accepted for protocol compatibility but
        not used by the rule-based implementation — it analyzes the
        packet holistically.

        Args:
            architect_msg: The Architect's hypothesis (unused by rule-based)
            packet: The EvidencePacket to analyze

        Returns:
            List of BenignExplanation instances
        """
        explanations: List[BenignExplanation] = []

        # Collect all evidence characteristics
        facts_by_field: Dict[str, List["Fact"]] = {}
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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
        facts_by_field: Dict[str, List["Fact"]],
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


class RuleBasedNarrativeGenerator:
    """Extracted from OracleNarrator._generate_narrative(). Zero behavior change.

    Template-based narrative generation from verdict fields.
    The packet, architect_msg, and skeptic_msg parameters exist for
    protocol compatibility but are not used by the rule-based implementation.
    """

    def generate_narrative(
        self,
        verdict: Verdict,
        packet: "EvidencePacket",
        architect_msg: Optional["DialecticalMessage"] = None,
        skeptic_msg: Optional["DialecticalMessage"] = None,
    ) -> str:
        """Generate the full narrative explanation.

        Args:
            verdict: The verdict to explain
            packet: The EvidencePacket (unused by rule-based)
            architect_msg: The Architect's message (unused by rule-based)
            skeptic_msg: The Skeptic's message (unused by rule-based)

        Returns:
            Complete narrative explanation
        """
        parts = []

        # Opening statement
        if verdict.outcome == VerdictOutcome.THREAT_CONFIRMED:
            parts.append(
                "VERDICT: THREAT CONFIRMED. "
                "Analysis indicates the observed activity is likely malicious."
            )
        elif verdict.outcome == VerdictOutcome.THREAT_DISMISSED:
            parts.append(
                "VERDICT: THREAT DISMISSED. "
                "Analysis indicates the observed activity is likely benign."
            )
        else:
            parts.append(
                "VERDICT: INCONCLUSIVE. "
                "Analysis could not determine whether activity is malicious or benign."
            )

        # Reasoning from the verdict
        parts.append(f"Basis: {verdict.reasoning}")

        # Evidence summary
        fact_count = len(verdict.supporting_fact_ids)
        parts.append(f"Supporting evidence: {fact_count} fact(s) analyzed.")

        # Confidence breakdown
        parts.append(
            f"Confidence analysis: Architect proposed at {verdict.architect_confidence:.0%}, "
            f"Skeptic challenged at {verdict.skeptic_confidence:.0%}."
        )

        return " ".join(parts)
