"""Session 057 frozen schema for skeleton-equivalence audits.

Phase 7 / Step 1 anchor schema. Defines the *skeleton* of an evidence
packet — the typed-field tuple that is held constant across attacker-
controlled value mutations — and the equivalence-class container the
audit emits.

Skeleton hash semantics
-----------------------
The skeleton hash deliberately **excludes** ``Fact.value`` and
``Fact.value_hash`` so that a skeleton-preserving mutation (the same
typed evidence with attacker-controlled prose substituted) lands in the
same equivalence class.

Per the SESSION_057 spec, the skeleton is keyed on::

    (fact_id, field, entity_id, source_type)

over fact_ids sorted lexicographically. ``timestamp`` is **not** part of
the hash; some framing scenarios re-anchor temporally and we want those
flagged for inspection rather than rejected. The audit records the
timestamp-mismatch state separately on the group.

The packet hash (from :meth:`EvidencePacket.freeze`) is *expected* to
differ across skeleton-equivalent variants, because every Fact carries a
different ``value_hash``. The skeleton hash here is the orthogonal
identity used for grouping.

Frozen-dataclass discipline (per CLAUDE.md): every dataclass in this
module is ``frozen=True``. ``SkeletonEquivalentGroup`` validates its
contract in ``__post_init__``.
"""

from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Any, Iterable, Mapping

if TYPE_CHECKING:  # pragma: no cover - import-only typing aid
    from ares.dialectic.evidence.packet import EvidencePacket


# ---------------------------------------------------------------------------
# Skeleton hash
# ---------------------------------------------------------------------------


def _skeleton_tuple(packet: "EvidencePacket") -> tuple[tuple[str, str, str, str], ...]:
    """Build the canonical typed-field tuple for an evidence packet.

    Each Fact contributes one ``(fact_id, field, entity_id, source_type)``
    quadruple. The result is sorted by ``fact_id`` for determinism and
    excludes ``value`` / ``value_hash`` / ``timestamp``.

    Args:
        packet: An EvidencePacket (frozen or unfrozen — we only read).

    Returns:
        A tuple of typed-field quadruples, sorted by fact_id.
    """
    facts = sorted(packet.get_all_facts(), key=lambda f: f.fact_id)
    return tuple(
        (
            fact.fact_id,
            fact.field,
            fact.entity_id,
            fact.provenance.source_type.value,
        )
        for fact in facts
    )


def skeleton_hash(packet: "EvidencePacket") -> str:
    """Compute the deterministic skeleton hash of an evidence packet.

    Two scenarios produce the same skeleton hash iff they share the same
    ``(fact_id, field, entity_id, source_type)`` tuple set across every
    Fact, regardless of ``value`` / ``timestamp``.

    Args:
        packet: An EvidencePacket.

    Returns:
        A 32-character hex string (first 32 chars of SHA-256).
    """
    serialized = json.dumps(_skeleton_tuple(packet), sort_keys=True)
    digest = hashlib.sha256(serialized.encode("utf-8")).hexdigest()
    return digest[:32]


def skeleton_timestamps(packet: "EvidencePacket") -> tuple[tuple[str, str], ...]:
    """Build the canonical timestamp tuple keyed by fact_id.

    Used by audits to flag (not reject) timestamp-mismatched pairs. Sort
    order matches :func:`_skeleton_tuple` so the i-th entry refers to
    the same Fact.

    Args:
        packet: An EvidencePacket.

    Returns:
        A tuple of ``(fact_id, ISO-formatted timestamp)`` pairs.
    """
    facts = sorted(packet.get_all_facts(), key=lambda f: f.fact_id)
    return tuple((fact.fact_id, fact.timestamp.isoformat()) for fact in facts)


# ---------------------------------------------------------------------------
# SkeletonEquivalentGroup
# ---------------------------------------------------------------------------


@dataclass(frozen=True)
class SkeletonEquivalentGroup:
    """One equivalence class produced by the skeleton audit.

    A group is the set of scenarios in the corpus that share an identical
    skeleton hash. The audit records the group whenever ``len(scenario_ids)
    >= 2``; singleton classes are reported separately as a count, not as
    materialized groups.

    Attributes:
        group_id: Stable identifier for this group, derived from the
            skeleton hash. Format: ``"GRP-<hash[:8]>"``.
        skeleton_hash: The 32-char skeleton hash all members share.
        scenario_ids: Sorted tuple of scenario_ids in the group.
        n_facts: Number of Facts in the shared skeleton.
        timestamp_mismatch: True iff at least one pair of members
            disagrees on the per-fact timestamp tuple. Members are still
            in the group when this is True (per spec: flagged, not
            rejected).
        timestamp_mismatched_fact_ids: Sorted tuple of fact_ids whose
            timestamp differs across at least one pair. Empty when
            ``timestamp_mismatch`` is False.
    """

    group_id: str
    skeleton_hash: str
    scenario_ids: tuple[str, ...]
    n_facts: int
    timestamp_mismatch: bool
    timestamp_mismatched_fact_ids: tuple[str, ...]

    def __post_init__(self) -> None:
        if not isinstance(self.scenario_ids, tuple):
            raise TypeError(
                "scenario_ids must be a tuple, "
                f"got {type(self.scenario_ids).__name__}"
            )
        if not isinstance(self.timestamp_mismatched_fact_ids, tuple):
            raise TypeError(
                "timestamp_mismatched_fact_ids must be a tuple, "
                f"got {type(self.timestamp_mismatched_fact_ids).__name__}"
            )
        if len(self.scenario_ids) < 2:
            raise ValueError(
                "SkeletonEquivalentGroup requires at least 2 scenario_ids; "
                f"got {len(self.scenario_ids)}. Singletons are tracked as "
                "counts, not materialized groups."
            )
        if len(set(self.scenario_ids)) != len(self.scenario_ids):
            raise ValueError(
                f"scenario_ids must be unique; got {self.scenario_ids!r}"
            )
        if tuple(sorted(self.scenario_ids)) != self.scenario_ids:
            raise ValueError(
                "scenario_ids must be sorted lexicographically; "
                f"got {self.scenario_ids!r}"
            )
        if self.n_facts < 1:
            raise ValueError(f"n_facts must be >= 1; got {self.n_facts}")
        if len(self.skeleton_hash) != 32:
            raise ValueError(
                f"skeleton_hash must be 32 hex chars; got {self.skeleton_hash!r}"
            )
        if not self.timestamp_mismatch and self.timestamp_mismatched_fact_ids:
            raise ValueError(
                "timestamp_mismatched_fact_ids must be empty when "
                "timestamp_mismatch is False"
            )
        if self.timestamp_mismatch and not self.timestamp_mismatched_fact_ids:
            raise ValueError(
                "timestamp_mismatched_fact_ids must be non-empty when "
                "timestamp_mismatch is True"
            )

    @property
    def size(self) -> int:
        """Number of scenarios in this group."""
        return len(self.scenario_ids)

    def to_dict(self) -> dict[str, Any]:
        payload = asdict(self)
        payload["scenario_ids"] = list(self.scenario_ids)
        payload["timestamp_mismatched_fact_ids"] = list(
            self.timestamp_mismatched_fact_ids
        )
        return payload

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> "SkeletonEquivalentGroup":
        return cls(
            group_id=str(data["group_id"]),
            skeleton_hash=str(data["skeleton_hash"]),
            scenario_ids=tuple(str(x) for x in data["scenario_ids"]),
            n_facts=int(data["n_facts"]),
            timestamp_mismatch=bool(data["timestamp_mismatch"]),
            timestamp_mismatched_fact_ids=tuple(
                str(x) for x in data["timestamp_mismatched_fact_ids"]
            ),
        )


def make_group_id(skeleton_hash_value: str) -> str:
    """Build a stable group_id from a skeleton hash.

    Args:
        skeleton_hash_value: The 32-char skeleton hash.

    Returns:
        A ``"GRP-<hash[:8]>"`` string.
    """
    if len(skeleton_hash_value) < 8:
        raise ValueError(
            f"skeleton_hash_value must be >= 8 chars; got {skeleton_hash_value!r}"
        )
    return f"GRP-{skeleton_hash_value[:8]}"


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


__all__ = [
    "SkeletonEquivalentGroup",
    "make_group_id",
    "skeleton_hash",
    "skeleton_timestamps",
]


def all_scenarios_have_unique_skeleton(
    packets: Iterable["EvidencePacket"],
) -> bool:
    """Convenience predicate: are all skeletons in this corpus distinct?

    Args:
        packets: An iterable of EvidencePackets.

    Returns:
        True iff every packet has a unique skeleton hash.
    """
    seen: set[str] = set()
    for packet in packets:
        h = skeleton_hash(packet)
        if h in seen:
            return False
        seen.add(h)
    return True
