"""HashChain — tamper-evident audit log.

Each link hashes its content together with the previous link's hash,
creating an append-only chain where any modification invalidates all
subsequent entries.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

from ares.dialectic.coordinator.orchestrator import CycleResult
from ares.dialectic.messages.protocol import DialecticalMessage

GENESIS_HASH = "0" * 64  # SHA256-length zero string — the chain anchor


@dataclass(frozen=True)
class ChainLink:
    """A single link in the hash chain.

    Attributes:
        content_hash: SHA256 of the canonical serialization of the content.
        prev_chain_hash: Chain hash of the previous link (GENESIS_HASH for first).
        chain_hash: SHA256(prev_chain_hash + content_hash).
        sequence_number: Monotonic position in the chain (0-indexed).
    """

    content_hash: str
    prev_chain_hash: str
    chain_hash: str
    sequence_number: int


class HashChain:
    """Tamper-evident hash chain for audit integrity.

    Each link hashes its content together with the previous link's hash,
    creating an append-only chain where any modification invalidates all
    subsequent entries.
    """

    def __init__(self) -> None:
        self._head_hash: str = GENESIS_HASH
        self._sequence: int = 0

    def add(self, content_hash: str) -> ChainLink:
        """Add a new link to the chain.

        Args:
            content_hash: SHA256 of the content being chained.

        Returns:
            A ChainLink with the computed chain_hash.
        """
        prev = self._head_hash
        chain_hash = self.compute_chain_hash(prev, content_hash)
        link = ChainLink(
            content_hash=content_hash,
            prev_chain_hash=prev,
            chain_hash=chain_hash,
            sequence_number=self._sequence,
        )
        self._head_hash = chain_hash
        self._sequence += 1
        return link

    @staticmethod
    def compute_chain_hash(prev_hash: str, content_hash: str) -> str:
        """SHA256(prev_hash + content_hash). Deterministic, pure function.

        Args:
            prev_hash: The previous chain hash.
            content_hash: The content hash for this link.

        Returns:
            64-character hex digest.
        """
        combined = (prev_hash + content_hash).encode("utf-8")
        return hashlib.sha256(combined).hexdigest()

    @staticmethod
    def verify_link(link: ChainLink, expected_prev_hash: str) -> bool:
        """Verify that a ChainLink is valid given its expected predecessor.

        Args:
            link: The chain link to verify.
            expected_prev_hash: What prev_chain_hash should be.

        Returns:
            True if the link is valid.
        """
        if link.prev_chain_hash != expected_prev_hash:
            return False
        expected_chain = HashChain.compute_chain_hash(
            link.prev_chain_hash, link.content_hash
        )
        return link.chain_hash == expected_chain

    @staticmethod
    def compute_content_hash(cycle_result: CycleResult) -> str:
        """Canonical SHA256 of the FULL CycleResult.

        Covers ALL stored fields to prevent partial tampering.

        Algorithm:
        1. Build a primitive-only dict from CycleResult
        2. Sort all dict keys recursively
        3. json.dumps(dict, sort_keys=True, separators=(',', ':'))
        4. SHA256 the UTF-8 bytes

        Float formatting: f"{value:.10f}" for deterministic representation.
        None handling: JSON null for missing narrator_message.

        Args:
            cycle_result: The CycleResult to hash.

        Returns:
            64-character hex digest.
        """
        canonical = _build_canonical_dict(cycle_result)
        serialized = json.dumps(canonical, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(serialized.encode("utf-8")).hexdigest()

    @property
    def head_hash(self) -> str:
        """Current head of the chain."""
        return self._head_hash

    @property
    def sequence(self) -> int:
        """Current sequence number (number of links added)."""
        return self._sequence

    def restore(self, head_hash: str, sequence: int) -> None:
        """Restore chain state from a pre-populated backend.

        Args:
            head_hash: The chain head hash to resume from.
            sequence: The sequence number to resume from.
        """
        self._head_hash = head_hash
        self._sequence = sequence


# ------------------------------------------------------------------
# Private serialization helpers
# ------------------------------------------------------------------


def _format_float(value: float) -> str:
    """Format a float to 10 decimal places for deterministic hashing."""
    return f"{value:.10f}"


def _serialize_assertion(assertion: Any) -> Dict[str, Any]:
    """Serialize an Assertion to a primitive dict for hashing."""
    return {
        "assertion_id": assertion.assertion_id,
        "assertion_type": assertion.assertion_type.value,
        "fact_ids": sorted(assertion.fact_ids),
        "interpretation": assertion.interpretation,
        "operator": assertion.operator,
        "threshold": assertion.threshold,
    }


def _serialize_message(msg: DialecticalMessage) -> Dict[str, Any]:
    """Serialize a DialecticalMessage to a primitive dict for hashing."""
    cited_fact_ids = sorted(msg.get_all_fact_ids())
    assertions = [_serialize_assertion(a) for a in msg.assertions]
    # Sort assertions by assertion_id for determinism
    assertions.sort(key=lambda a: a["assertion_id"])

    return {
        "message_id": msg.message_id,
        "source_agent": msg.source_agent,
        "target_agent": msg.target_agent,
        "phase": msg.phase.value,
        "turn_number": msg.turn_number,
        "message_type": msg.message_type.value,
        "confidence": _format_float(msg.confidence),
        "assertions": assertions,
        "cited_fact_ids": cited_fact_ids,
        "narrative": msg.narrative,
    }


def _build_canonical_dict(cr: CycleResult) -> Dict[str, Any]:
    """Build the canonical primitive-only dict from a CycleResult."""
    v = cr.verdict
    return {
        "cycle_id": cr.cycle_id,
        "packet_id": cr.packet_id,
        "duration_ms": cr.duration_ms,
        "started_at": cr.started_at.isoformat(),
        "completed_at": cr.completed_at.isoformat(),
        "verdict": {
            "outcome": v.outcome.value,
            "confidence": _format_float(v.confidence),
            "reasoning": v.reasoning,
            "architect_confidence": _format_float(v.architect_confidence),
            "skeptic_confidence": _format_float(v.skeptic_confidence),
            "supporting_fact_ids": sorted(v.supporting_fact_ids),
        },
        "architect_message": _serialize_message(cr.architect_message),
        "skeptic_message": _serialize_message(cr.skeptic_message),
        "narrator_message": (
            _serialize_message(cr.narrator_message)
            if cr.narrator_message is not None
            else None
        ),
    }
