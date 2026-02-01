"""Provenance tracking for evidence facts.

Provenance records the origin and extraction details of facts,
enabling traceability and audit trails in dialectical reasoning.
"""

from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional


class SourceType(Enum):
    """Types of data sources that can provide evidence."""

    NETFLOW = "netflow"
    SYSLOG = "syslog"
    PROCESS_LIST = "process_list"
    DNS_LOG = "dns_log"
    AUTH_LOG = "auth_log"
    GRAPH_COMPUTATION = "graph_computation"
    MANUAL = "manual"
    UNKNOWN = "unknown"


@dataclass(frozen=True)
class Provenance:
    """Immutable record of where a fact originated.

    Attributes:
        source_type: The type of data source.
        source_id: Unique identifier for the specific source instance.
        parser_version: Version of the parser that extracted this fact.
        raw_reference: Optional reference to the raw data (e.g., line number, offset).
        extracted_at: Timestamp when the fact was extracted.
    """

    source_type: SourceType
    source_id: str
    parser_version: str = "1.0.0"
    raw_reference: Optional[str] = None
    extracted_at: datetime = None

    def __post_init__(self) -> None:
        """Set default extracted_at if not provided."""
        if self.extracted_at is None:
            object.__setattr__(self, "extracted_at", datetime.utcnow())

    def to_dict(self) -> Dict[str, Any]:
        """Serialize provenance to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "source_type": self.source_type.value,
            "source_id": self.source_id,
            "parser_version": self.parser_version,
            "raw_reference": self.raw_reference,
            "extracted_at": self.extracted_at.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Provenance":
        """Deserialize provenance from dictionary.

        Args:
            data: Dictionary containing provenance fields.

        Returns:
            Provenance instance.
        """
        return cls(
            source_type=SourceType(data["source_type"]),
            source_id=data["source_id"],
            parser_version=data.get("parser_version", "1.0.0"),
            raw_reference=data.get("raw_reference"),
            extracted_at=datetime.fromisoformat(data["extracted_at"]),
        )

    @classmethod
    def manual(cls, source_id: str = "test", raw_reference: Optional[str] = None) -> "Provenance":
        """Factory method for creating manual/test provenance.

        Args:
            source_id: Identifier for the manual source.
            raw_reference: Optional reference string.

        Returns:
            Provenance instance with MANUAL source type.
        """
        return cls(
            source_type=SourceType.MANUAL,
            source_id=source_id,
            parser_version="1.0.0",
            raw_reference=raw_reference,
            extracted_at=datetime.utcnow(),
        )
