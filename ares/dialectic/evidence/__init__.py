# Evidence Module
"""Evidence management for dialectical reasoning."""

from .provenance import Provenance, SourceType
from .fact import Fact, EntityType
from .packet import (
    EvidencePacket,
    TimeWindow,
    EvidencePacketError,
    FactNotFoundError,
    PacketFrozenError,
    DuplicateFactError,
)

__all__ = [
    "Provenance",
    "SourceType",
    "Fact",
    "EntityType",
    "EvidencePacket",
    "TimeWindow",
    "EvidencePacketError",
    "FactNotFoundError",
    "PacketFrozenError",
    "DuplicateFactError",
]
