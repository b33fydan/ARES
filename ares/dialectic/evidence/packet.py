"""EvidencePacket - Container for dialectical evidence.

The EvidencePacket is a frozen collection of facts that agents must
reference during dialectical debates. It enforces a "closed world" -
agents can only cite facts that exist in the packet.
"""

import hashlib
import json
from collections import defaultdict
from dataclasses import dataclass
from datetime import datetime
from typing import Any, Dict, List, Optional, Set, Tuple

from .fact import Fact


class EvidencePacketError(Exception):
    """Base exception for evidence packet errors."""

    pass


class FactNotFoundError(EvidencePacketError):
    """Raised when a fact is not found in the packet."""

    def __init__(self, fact_id: str) -> None:
        self.fact_id = fact_id
        super().__init__(f"Fact not found: {fact_id}")


class PacketFrozenError(EvidencePacketError):
    """Raised when attempting to modify a frozen packet."""

    def __init__(self) -> None:
        super().__init__("Cannot modify frozen evidence packet")


class DuplicateFactError(EvidencePacketError):
    """Raised when adding a fact with duplicate ID."""

    def __init__(self, fact_id: str) -> None:
        self.fact_id = fact_id
        super().__init__(f"Duplicate fact ID: {fact_id}")


@dataclass
class TimeWindow:
    """Time range for evidence collection.

    Attributes:
        start: Start of the time window (inclusive).
        end: End of the time window (inclusive).
    """

    start: datetime
    end: datetime

    def contains(self, timestamp: datetime) -> bool:
        """Check if a timestamp falls within this window.

        Args:
            timestamp: The timestamp to check.

        Returns:
            True if timestamp is within [start, end].
        """
        return self.start <= timestamp <= self.end

    def to_dict(self) -> Dict[str, str]:
        """Serialize time window to dictionary.

        Returns:
            Dictionary with ISO format timestamps.
        """
        return {
            "start": self.start.isoformat(),
            "end": self.end.isoformat(),
        }

    @classmethod
    def from_dict(cls, data: Dict[str, str]) -> "TimeWindow":
        """Deserialize time window from dictionary.

        Args:
            data: Dictionary with start and end timestamps.

        Returns:
            TimeWindow instance.
        """
        return cls(
            start=datetime.fromisoformat(data["start"]),
            end=datetime.fromisoformat(data["end"]),
        )


class EvidencePacket:
    """Container for evidence facts used in dialectical reasoning.

    The EvidencePacket collects facts and can be frozen to create
    an immutable evidence base. Once frozen, no facts can be added
    and a snapshot_id is computed for integrity verification.

    Attributes:
        SCHEMA_VERSION: Version of the packet schema.
    """

    SCHEMA_VERSION = "1.0.0"

    def __init__(self, packet_id: str, time_window: TimeWindow) -> None:
        """Initialize an evidence packet.

        Args:
            packet_id: Unique identifier for this packet.
            time_window: Time range covered by this evidence.
        """
        self.packet_id = packet_id
        self.time_window = time_window

        # Internal state
        self._facts: Dict[str, Fact] = {}
        self._frozen: bool = False
        self._snapshot_id: Optional[str] = None

        # Indexes for efficient queries
        self._by_entity: Dict[str, List[str]] = defaultdict(list)
        self._by_field: Dict[str, List[str]] = defaultdict(list)

    def add_fact(self, fact: Fact) -> None:
        """Add a fact to the packet.

        Args:
            fact: The fact to add.

        Raises:
            PacketFrozenError: If the packet is frozen.
            DuplicateFactError: If a fact with this ID already exists.
        """
        if self._frozen:
            raise PacketFrozenError()

        if fact.fact_id in self._facts:
            raise DuplicateFactError(fact.fact_id)

        self._facts[fact.fact_id] = fact

        # Update indexes
        self._by_entity[fact.entity_id].append(fact.fact_id)
        self._by_field[fact.field].append(fact.fact_id)

    def freeze(self) -> str:
        """Freeze the packet and compute snapshot ID.

        Once frozen, no more facts can be added. The snapshot_id
        is a hash of all facts, providing integrity verification.

        Returns:
            The computed snapshot_id (32 character hex string).
        """
        if self._frozen:
            return self._snapshot_id

        self._frozen = True
        self._snapshot_id = self._compute_snapshot_id()
        return self._snapshot_id

    def _compute_snapshot_id(self) -> str:
        """Compute deterministic hash of packet contents.

        Returns:
            32 character hex string.
        """
        # Sort fact IDs for determinism
        sorted_ids = sorted(self._facts.keys())

        # Create a list of (fact_id, value_hash) pairs
        hash_data = [(fid, self._facts[fid].value_hash) for fid in sorted_ids]

        # Serialize and hash
        serialized = json.dumps(hash_data, sort_keys=True)
        full_hash = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
        return full_hash[:32]

    def get_fact(self, fact_id: str) -> Fact:
        """Retrieve a fact by ID.

        Args:
            fact_id: The ID of the fact to retrieve.

        Returns:
            The fact with the given ID.

        Raises:
            FactNotFoundError: If the fact doesn't exist.
        """
        if fact_id not in self._facts:
            raise FactNotFoundError(fact_id)
        return self._facts[fact_id]

    def has_fact(self, fact_id: str) -> bool:
        """Check if a fact exists in the packet.

        Args:
            fact_id: The ID to check.

        Returns:
            True if the fact exists.
        """
        return fact_id in self._facts

    def validate_fact_ids(self, fact_ids: List[str]) -> Tuple[bool, List[str]]:
        """Validate a list of fact IDs against the packet.

        Args:
            fact_ids: List of fact IDs to validate.

        Returns:
            Tuple of (all_valid, list of invalid IDs).
        """
        invalid = [fid for fid in fact_ids if fid not in self._facts]
        return (len(invalid) == 0, invalid)

    def get_facts_by_entity(self, entity_id: str) -> List[Fact]:
        """Get all facts for a specific entity.

        Args:
            entity_id: The entity ID to filter by.

        Returns:
            List of facts for this entity.
        """
        fact_ids = self._by_entity.get(entity_id, [])
        return [self._facts[fid] for fid in fact_ids]

    def get_facts_by_field(self, field: str) -> List[Fact]:
        """Get all facts with a specific field name.

        Args:
            field: The field name to filter by.

        Returns:
            List of facts with this field.
        """
        fact_ids = self._by_field.get(field, [])
        return [self._facts[fid] for fid in fact_ids]

    def get_facts_in_time_range(self, start: datetime, end: datetime) -> List[Fact]:
        """Get facts within a time range.

        Args:
            start: Start of range (inclusive).
            end: End of range (inclusive).

        Returns:
            List of facts with timestamps in range.
        """
        return [
            fact
            for fact in self._facts.values()
            if start <= fact.timestamp <= end
        ]

    def get_all_facts(self) -> List[Fact]:
        """Get all facts in the packet.

        Returns:
            List of all facts.
        """
        return list(self._facts.values())

    def get_entities(self) -> Set[str]:
        """Get all unique entity IDs.

        Returns:
            Set of entity IDs.
        """
        return set(self._by_entity.keys())

    def get_fields(self) -> Set[str]:
        """Get all unique field names.

        Returns:
            Set of field names.
        """
        return set(self._by_field.keys())

    @property
    def fact_ids(self) -> Set[str]:
        """Get all fact IDs in the packet.

        Returns:
            Set of fact IDs.
        """
        return set(self._facts.keys())

    @property
    def fact_count(self) -> int:
        """Get the number of facts in the packet.

        Returns:
            Number of facts.
        """
        return len(self._facts)

    @property
    def is_frozen(self) -> bool:
        """Check if the packet is frozen.

        Returns:
            True if frozen.
        """
        return self._frozen

    @property
    def snapshot_id(self) -> Optional[str]:
        """Get the snapshot ID (only set after freezing).

        Returns:
            Snapshot ID or None if not frozen.
        """
        return self._snapshot_id

    def summary(self) -> Dict[str, Any]:
        """Get a summary of the packet.

        Returns:
            Dictionary with packet statistics.
        """
        return {
            "packet_id": self.packet_id,
            "schema_version": self.SCHEMA_VERSION,
            "fact_count": self.fact_count,
            "entity_count": len(self.get_entities()),
            "field_count": len(self.get_fields()),
            "is_frozen": self._frozen,
            "snapshot_id": self._snapshot_id,
            "time_window": self.time_window.to_dict(),
        }

    def to_dict(self) -> Dict[str, Any]:
        """Serialize packet to dictionary.

        Returns:
            Dictionary representation.
        """
        return {
            "schema_version": self.SCHEMA_VERSION,
            "packet_id": self.packet_id,
            "time_window": self.time_window.to_dict(),
            "facts": [fact.to_dict() for fact in self._facts.values()],
            "frozen": self._frozen,
            "snapshot_id": self._snapshot_id,
        }

    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> "EvidencePacket":
        """Deserialize packet from dictionary.

        Args:
            data: Dictionary containing packet data.

        Returns:
            EvidencePacket instance.

        Raises:
            ValueError: If snapshot_id verification fails for frozen packets.
        """
        packet = cls(
            packet_id=data["packet_id"],
            time_window=TimeWindow.from_dict(data["time_window"]),
        )

        # Add all facts
        for fact_data in data["facts"]:
            fact = Fact.from_dict(fact_data)
            packet.add_fact(fact)

        # Restore frozen state
        if data["frozen"]:
            computed_id = packet.freeze()
            if data["snapshot_id"] != computed_id:
                raise ValueError(
                    f"Snapshot ID mismatch: expected {data['snapshot_id']}, "
                    f"computed {computed_id}"
                )

        return packet
