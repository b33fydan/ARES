"""Immutable, provenance-tagged capture of untrusted harness input.

Mirrors ARES's EvidencePacket/Provenance discipline (content-addressed,
frozen, trust-labelled) adapted to a generic tool/web/file/MCP output. The
trust label is the ARES Provenance.source_type; anything not explicitly in
TRUSTED_SOURCE_TYPES (including UNKNOWN) is untrusted by default (fail-safe).
"""
import hashlib
import json
from dataclasses import dataclass

from ares.dialectic.evidence import Provenance, SourceType

TRUSTED_SOURCE_TYPES = frozenset({SourceType.MANUAL})


def is_trusted(provenance: Provenance) -> bool:
    return provenance.source_type in TRUSTED_SOURCE_TYPES


def _hash_content(content: str) -> str:
    serialized = json.dumps(content, sort_keys=True, default=str)
    return hashlib.sha256(serialized.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class CapturedRecord:
    record_id: str
    content: str
    provenance: Provenance
    content_hash: str = None

    def __post_init__(self) -> None:
        if self.content_hash is None:
            object.__setattr__(self, "content_hash", _hash_content(self.content))

    @property
    def trusted(self) -> bool:
        return is_trusted(self.provenance)


def capture(record_id: str, content: str, provenance: Provenance) -> CapturedRecord:
    return CapturedRecord(record_id=record_id, content=content, provenance=provenance)
