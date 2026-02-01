"""Fact representation for evidence system.

Facts are atomic units of evidence that agents can cite during
dialectical debates. Each fact is immutable and self-verifying.
"""

import hashlib
import json
from dataclasses import dataclass
from datetime import datetime
from enum import Enum
from typing import Any, Dict, Optional

from .provenance import Provenance


class EntityType(Enum):
    """Types of entities that facts can describe."""

    NODE = "node"
    EDGE = "edge"


def _compute_value_hash(value: Any) -> str:
    """Compute a deterministic hash of a value.

    Args:
        value: Any JSON-serializable value.

    Returns:
        First 16 characters of SHA256 hash.
    """
    # Serialize value to JSON with sorted keys for determinism
    serialized = json.dumps(value, sort_keys=True, default=str)
    hash_bytes = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return hash_bytes[:16]


@dataclass(frozen=True)
class Fact:
    """Immutable atomic unit of evidence.

    Attributes:
        fact_id: Unique identifier for this fact.
        entity_id: ID of the entity this fact describes.
        entity_type: Whether the entity is a NODE or EDGE.
        field: The attribute or property name.
        value: The value of the attribute (any JSON-serializable type).
        timestamp: When this fact was observed/recorded.
        provenance: Origin and extraction details.
        value_hash: Auto-computed SHA256 hash of the value (first 16 chars).
    """

    fact_id: str
    entity_id: str
    entity_type: EntityType
    field: str
    value: Any
    timestamp: datetime
    provenance: Provenance
    value_hash: str = None

    def __post_init__(self) -> None:
        """Compute value_hash if not provided."""
        if self.value_hash is None:
            computed_hash = _compute_value_hash(self.value)
            object.__setattr__(self, "value_hash", computed_hash)

    def verify_hash(self) -> bool:
        """Verify that the stored hash matches the value.

        Returns:
            True if hash is valid, False if corrupted.
        """
        expected = _compute_value_hash(self.value)
        return self.value_hash == expected

    def matches(
        self, entity_id: Optional[str] = None, field: Optional[str] = None
    ) -> bool:
        """Check if this fact matches the given criteria.

        Args:
            entity_id: If provided, fact must have this entity_id.
            field: If provided, fact must have this field name.

        Returns:
            True if all provided criteria match.
        """
        if entity_id is not None and self.entity_id != entity_id:
            return False
        if field is not None and self.field != field:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        """Serialize fact to dictionary.

        Returns:
            Dictionary representation suitable for JSON serialization.
        """
        return {
            "fact_id": self.fact_id,
            "entity_id": self.entity_id,
            "entity_type": self.entity_type.value,
            "field": self.field,
            "value": self.value,
            "timestamp": self.timestamp.isoformat(),
            "provenance": self.provenance.to_dict(),
            "value_hash": self.value_hash,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "Fact":
        """Deserialize fact from dictionary.

        Args:
            data: Dictionary containing fact fields.

        Returns:
            Fact instance.
        """
        return cls(
            fact_id=data["fact_id"],
            entity_id=data["entity_id"],
            entity_type=EntityType(data["entity_type"]),
            field=data["field"],
            value=data["value"],
            timestamp=datetime.fromisoformat(data["timestamp"]),
            provenance=Provenance.from_dict(data["provenance"]),
            value_hash=data["value_hash"],
        )
