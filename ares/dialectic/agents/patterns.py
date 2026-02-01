"""Pattern dataclasses for agent reasoning.

This module defines the supporting data structures used by agents
during threat detection and benign explanation generation.

These are the "vocabulary" agents use to communicate their findings
in a machine-checkable format.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import FrozenSet


class PatternType(Enum):
    """Types of anomaly patterns agents can detect.

    These represent threat indicators that suggest malicious activity.
    """

    PRIVILEGE_ESCALATION = "privilege_escalation"
    LATERAL_MOVEMENT = "lateral_movement"
    SUSPICIOUS_PROCESS = "suspicious_process"
    SERVICE_ABUSE = "service_abuse"
    CREDENTIAL_ACCESS = "credential_access"
    DATA_EXFILTRATION = "data_exfiltration"
    PERSISTENCE_MECHANISM = "persistence_mechanism"
    DEFENSE_EVASION = "defense_evasion"


class ExplanationType(Enum):
    """Types of benign explanations for observed activity.

    These represent innocent reasons why threat-like activity might occur.
    """

    MAINTENANCE_WINDOW = "maintenance_window"
    KNOWN_ADMIN = "known_admin"
    SCHEDULED_TASK = "scheduled_task"
    SOFTWARE_UPDATE = "software_update"
    LEGITIMATE_REMOTE_ACCESS = "legitimate_remote_access"
    SECURITY_TOOL = "security_tool"
    DEVELOPMENT_ACTIVITY = "development_activity"
    AUTOMATED_BACKUP = "automated_backup"


class VerdictOutcome(Enum):
    """Possible outcomes from the Oracle's verdict computation.

    These are the three possible final states of a dialectical cycle:
    - THREAT_CONFIRMED: Evidence strongly supports malicious activity
    - THREAT_DISMISSED: Benign explanation adequately explains activity
    - INCONCLUSIVE: Neither side has sufficient evidence to prevail
    """

    THREAT_CONFIRMED = "threat_confirmed"
    THREAT_DISMISSED = "threat_dismissed"
    INCONCLUSIVE = "inconclusive"


@dataclass(frozen=True)
class AnomalyPattern:
    """A detected anomaly pattern in the evidence.

    Represents a threat indicator identified by the Architect during
    evidence analysis. Each pattern is grounded in specific facts
    from the EvidencePacket.

    Attributes:
        pattern_type: The category of anomaly detected
        fact_ids: Fact IDs from the EvidencePacket that support this pattern
        confidence: How confident the detection is (0.0 to 1.0)
        description: Human-readable description of what was detected
    """

    pattern_type: PatternType
    fact_ids: FrozenSet[str]
    confidence: float
    description: str

    def __post_init__(self) -> None:
        """Validate pattern invariants."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not self.fact_ids:
            raise ValueError("AnomalyPattern must reference at least one fact")
        if not self.description:
            raise ValueError("AnomalyPattern must have a description")


@dataclass(frozen=True)
class BenignExplanation:
    """A benign explanation for observed activity.

    Represents an innocent reason for activity that might otherwise
    appear malicious. Used by the Skeptic to challenge threat claims.

    Attributes:
        explanation_type: The category of benign explanation
        fact_ids: Fact IDs from the EvidencePacket that support this explanation
        confidence: How confident the explanation is (0.0 to 1.0)
        description: Human-readable description of the explanation
    """

    explanation_type: ExplanationType
    fact_ids: FrozenSet[str]
    confidence: float
    description: str

    def __post_init__(self) -> None:
        """Validate explanation invariants."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not self.fact_ids:
            raise ValueError("BenignExplanation must reference at least one fact")
        if not self.description:
            raise ValueError("BenignExplanation must have a description")


@dataclass(frozen=True)
class Verdict:
    """The Oracle's final verdict on a dialectical cycle.

    This is an immutable judgment that integrates the Architect's claims
    and the Skeptic's challenges. Once computed, it cannot be modified.

    Attributes:
        outcome: The final determination (THREAT_CONFIRMED, THREAT_DISMISSED, INCONCLUSIVE)
        confidence: Overall confidence in the verdict (0.0 to 1.0)
        supporting_fact_ids: Facts that support the winning position
        architect_confidence: The Architect's claim confidence
        skeptic_confidence: The Skeptic's rebuttal confidence
        reasoning: Deterministic explanation of how the verdict was reached
    """

    outcome: VerdictOutcome
    confidence: float
    supporting_fact_ids: FrozenSet[str]
    architect_confidence: float
    skeptic_confidence: float
    reasoning: str

    def __post_init__(self) -> None:
        """Validate verdict invariants."""
        if not 0.0 <= self.confidence <= 1.0:
            raise ValueError(f"Confidence must be between 0.0 and 1.0, got {self.confidence}")
        if not 0.0 <= self.architect_confidence <= 1.0:
            raise ValueError(
                f"Architect confidence must be between 0.0 and 1.0, got {self.architect_confidence}"
            )
        if not 0.0 <= self.skeptic_confidence <= 1.0:
            raise ValueError(
                f"Skeptic confidence must be between 0.0 and 1.0, got {self.skeptic_confidence}"
            )
        if not self.reasoning:
            raise ValueError("Verdict must have reasoning")

    @property
    def is_conclusive(self) -> bool:
        """True if the verdict reached a definitive conclusion."""
        return self.outcome != VerdictOutcome.INCONCLUSIVE

    @property
    def threat_detected(self) -> bool:
        """True if the verdict confirms a threat."""
        return self.outcome == VerdictOutcome.THREAT_CONFIRMED
