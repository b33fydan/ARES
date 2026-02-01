"""Assertions - Machine-checkable claims for dialectical reasoning.

Assertions are structured claims that agents make during debates.
They must reference facts from an EvidencePacket, preventing
hallucination by grounding all claims in evidence.
"""

from dataclasses import dataclass
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple, TYPE_CHECKING

if TYPE_CHECKING:
    from ares.dialectic.evidence import EvidencePacket


class AssertionType(Enum):
    """Types of assertions agents can make.

    ASSERT: Single fact meets a condition (e.g., "port > 1024")
    LINK: Multiple facts form a causal/temporal chain
    ALT: Alternative explanation for observed facts
    """

    ASSERT = "assert"
    LINK = "link"
    ALT = "alt"


@dataclass(frozen=True)
class Assertion:
    """Immutable machine-checkable claim.

    Attributes:
        assertion_id: Unique identifier for this assertion.
        assertion_type: The type of claim being made.
        fact_ids: List of fact IDs from EvidencePacket that support this claim.
        operator: For ASSERT type - comparison operator (>, <, ==, etc.)
        threshold: For ASSERT type - value to compare against.
        interpretation: Human-readable explanation of what this assertion means.
    """

    assertion_id: str
    assertion_type: AssertionType
    fact_ids: Tuple[str, ...]  # Tuple for immutability
    interpretation: str
    operator: Optional[str] = None
    threshold: Optional[Any] = None

    def to_dict(self) -> Dict[str, Any]:
        """Serialize assertion to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "assertion_id": self.assertion_id,
            "assertion_type": self.assertion_type.value,
            "fact_ids": list(self.fact_ids),
            "interpretation": self.interpretation,
            "operator": self.operator,
            "threshold": self.threshold,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Assertion":
        """Deserialize assertion from dictionary.

        Args:
            data: Dictionary containing assertion fields.

        Returns:
            Assertion instance.
        """
        return cls(
            assertion_id=data["assertion_id"],
            assertion_type=AssertionType(data["assertion_type"]),
            fact_ids=tuple(data["fact_ids"]),
            interpretation=data["interpretation"],
            operator=data.get("operator"),
            threshold=data.get("threshold"),
        )

    def validate_against_packet(
        self, packet: "EvidencePacket"
    ) -> Tuple[bool, List[str]]:
        """Validate that all referenced facts exist in the packet.

        Args:
            packet: The EvidencePacket to validate against.

        Returns:
            Tuple of (is_valid, list of missing fact_ids).
        """
        return packet.validate_fact_ids(list(self.fact_ids))

    @classmethod
    def assert_condition(
        cls,
        assertion_id: str,
        fact_id: str,
        operator: str,
        threshold: Any,
        interpretation: str,
    ) -> "Assertion":
        """Factory for creating ASSERT type assertions.

        Args:
            assertion_id: Unique ID for this assertion.
            fact_id: The fact being evaluated.
            operator: Comparison operator (>, <, ==, >=, <=, !=).
            threshold: Value to compare against.
            interpretation: Human-readable meaning.

        Returns:
            Assertion of type ASSERT.
        """
        return cls(
            assertion_id=assertion_id,
            assertion_type=AssertionType.ASSERT,
            fact_ids=(fact_id,),
            operator=operator,
            threshold=threshold,
            interpretation=interpretation,
        )

    @classmethod
    def link_facts(
        cls,
        assertion_id: str,
        fact_ids: List[str],
        interpretation: str,
    ) -> "Assertion":
        """Factory for creating LINK type assertions.

        Args:
            assertion_id: Unique ID for this assertion.
            fact_ids: Facts that form a causal/temporal chain.
            interpretation: Human-readable meaning of the link.

        Returns:
            Assertion of type LINK.
        """
        return cls(
            assertion_id=assertion_id,
            assertion_type=AssertionType.LINK,
            fact_ids=tuple(fact_ids),
            interpretation=interpretation,
        )

    @classmethod
    def alternative(
        cls,
        assertion_id: str,
        fact_ids: List[str],
        interpretation: str,
    ) -> "Assertion":
        """Factory for creating ALT type assertions.

        Args:
            assertion_id: Unique ID for this assertion.
            fact_ids: Facts that support the alternative explanation.
            interpretation: Human-readable alternative explanation.

        Returns:
            Assertion of type ALT.
        """
        return cls(
            assertion_id=assertion_id,
            assertion_type=AssertionType.ALT,
            fact_ids=tuple(fact_ids),
            interpretation=interpretation,
        )
