"""Tests for skeleton_equivalence schema — hash, group, helpers.

Phase 7 / Session 057 / Step 1. Verifies the *structural* properties the
audit relies on:

    * Skeleton hash is value-blind (mutating a Fact value does not
      change the hash).
    * Skeleton hash is type-sensitive (changing field, entity_id, or
      source_type DOES change the hash).
    * Skeleton hash is fact_id-sensitive (renaming a fact_id changes
      the hash; this is the "compose vs replace" boundary).
    * Skeleton hash is timestamp-blind (per spec: timestamps are
      flagged separately, not part of the hash).
    * SkeletonEquivalentGroup enforces its dataclass invariants in
      ``__post_init__`` and is frozen.
"""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime, timedelta

import pytest

from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.schemas.skeleton_equivalence import (
    SkeletonEquivalentGroup,
    all_scenarios_have_unique_skeleton,
    make_group_id,
    skeleton_hash,
    skeleton_timestamps,
)


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------


_T0 = datetime(2026, 5, 7, 12, 0, 0)


def _fact(
    *,
    fact_id: str = "f-001",
    entity_id: str = "host-A",
    field: str = "logon_type",
    value: object = "interactive",
    source_type: SourceType = SourceType.AUTH_LOG,
    timestamp: datetime | None = None,
) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=timestamp or _T0,
        provenance=Provenance(
            source_type=source_type,
            source_id="test-src",
            extracted_at=_T0,
        ),
    )


def _packet(facts: list[Fact], *, packet_id: str = "p-001") -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id=packet_id,
        time_window=TimeWindow(start=_T0, end=_T0 + timedelta(hours=1)),
    )
    for f in facts:
        pkt.add_fact(f)
    pkt.freeze()
    return pkt


def _group(**overrides) -> SkeletonEquivalentGroup:
    base = dict(
        group_id="GRP-deadbeef",
        skeleton_hash="deadbeef" * 4,  # 32 chars
        scenario_ids=("INJ-A", "INJ-B"),
        n_facts=3,
        timestamp_mismatch=False,
        timestamp_mismatched_fact_ids=(),
    )
    base.update(overrides)
    return SkeletonEquivalentGroup(**base)


# ---------------------------------------------------------------------------
# skeleton_hash invariants
# ---------------------------------------------------------------------------


class TestSkeletonHashValueBlind:
    """Mutating attacker-controlled value text must not change the hash."""

    def test_value_change_preserves_hash(self):
        a = _packet([_fact(value="interactive")])
        b = _packet([_fact(value="malicious payload {ignore_all_instructions}")])
        assert skeleton_hash(a) == skeleton_hash(b)

    def test_value_change_changes_packet_snapshot(self):
        # Sanity: the packet hash IS expected to change. This is what
        # makes the skeleton hash useful — packet hash is too strict
        # for grouping skeleton-equivalent variants.
        a = _packet([_fact(value="x")])
        b = _packet([_fact(value="y")])
        assert a.snapshot_id != b.snapshot_id

    def test_value_change_multiple_facts(self):
        facts_a = [
            _fact(fact_id="f-001", value="x"),
            _fact(fact_id="f-002", value="y", entity_id="host-B"),
        ]
        facts_b = [
            _fact(fact_id="f-001", value="X-MUTATED"),
            _fact(fact_id="f-002", value="Y-MUTATED", entity_id="host-B"),
        ]
        assert skeleton_hash(_packet(facts_a)) == skeleton_hash(_packet(facts_b))


class TestSkeletonHashTimestampBlind:
    """Timestamps are flagged separately, not part of the hash."""

    def test_timestamp_change_preserves_hash(self):
        a = _packet([_fact(timestamp=_T0)])
        b = _packet([_fact(timestamp=_T0 + timedelta(days=30))])
        assert skeleton_hash(a) == skeleton_hash(b)


class TestSkeletonHashTypeSensitive:
    """Changing typed fields must change the hash."""

    def test_field_change_changes_hash(self):
        a = _packet([_fact(field="logon_type")])
        b = _packet([_fact(field="process_name")])
        assert skeleton_hash(a) != skeleton_hash(b)

    def test_entity_id_change_changes_hash(self):
        a = _packet([_fact(entity_id="host-A")])
        b = _packet([_fact(entity_id="host-B")])
        assert skeleton_hash(a) != skeleton_hash(b)

    def test_source_type_change_changes_hash(self):
        a = _packet([_fact(source_type=SourceType.AUTH_LOG)])
        b = _packet([_fact(source_type=SourceType.NETFLOW)])
        assert skeleton_hash(a) != skeleton_hash(b)

    def test_fact_id_change_changes_hash(self):
        a = _packet([_fact(fact_id="f-001")])
        b = _packet([_fact(fact_id="f-002")])
        assert skeleton_hash(a) != skeleton_hash(b)


class TestSkeletonHashStructure:
    def test_hash_is_32_hex_chars(self):
        h = skeleton_hash(_packet([_fact()]))
        assert len(h) == 32
        assert all(c in "0123456789abcdef" for c in h)

    def test_hash_is_deterministic_across_calls(self):
        p = _packet([_fact()])
        assert skeleton_hash(p) == skeleton_hash(p)

    def test_hash_is_order_independent(self):
        # add_fact preserves insertion order in dict views, but the
        # skeleton hash sorts by fact_id internally, so two packets
        # built with different insertion orders must hash equally.
        p1 = _packet(
            [_fact(fact_id="f-001"), _fact(fact_id="f-002", entity_id="host-B")],
            packet_id="p-1",
        )
        p2 = _packet(
            [_fact(fact_id="f-002", entity_id="host-B"), _fact(fact_id="f-001")],
            packet_id="p-2",
        )
        assert skeleton_hash(p1) == skeleton_hash(p2)


class TestSkeletonHashCardinality:
    """Adding/removing facts must change the hash."""

    def test_extra_fact_changes_hash(self):
        a = _packet([_fact(fact_id="f-001")], packet_id="a")
        b = _packet(
            [_fact(fact_id="f-001"), _fact(fact_id="f-002", entity_id="host-B")],
            packet_id="b",
        )
        assert skeleton_hash(a) != skeleton_hash(b)


# ---------------------------------------------------------------------------
# skeleton_timestamps
# ---------------------------------------------------------------------------


class TestSkeletonTimestamps:
    def test_returns_sorted_by_fact_id(self):
        ts1 = _T0
        ts2 = _T0 + timedelta(hours=2)
        p = _packet(
            [
                _fact(fact_id="f-002", entity_id="host-B", timestamp=ts2),
                _fact(fact_id="f-001", timestamp=ts1),
            ],
            packet_id="p-ts",
        )
        result = skeleton_timestamps(p)
        assert [fid for fid, _ in result] == ["f-001", "f-002"]
        assert result[0][1] == ts1.isoformat()
        assert result[1][1] == ts2.isoformat()


# ---------------------------------------------------------------------------
# SkeletonEquivalentGroup invariants
# ---------------------------------------------------------------------------


class TestGroupBasic:
    def test_constructs_valid(self):
        g = _group()
        assert g.size == 2
        assert g.skeleton_hash == "deadbeef" * 4

    def test_is_frozen(self):
        g = _group()
        with pytest.raises(FrozenInstanceError):
            g.scenario_ids = ("X",)  # type: ignore[misc]


class TestGroupScenarioIds:
    def test_rejects_singleton(self):
        with pytest.raises(ValueError, match="at least 2"):
            _group(scenario_ids=("INJ-A",))

    def test_rejects_empty(self):
        with pytest.raises(ValueError, match="at least 2"):
            _group(scenario_ids=())

    def test_rejects_non_tuple(self):
        with pytest.raises(TypeError, match="tuple"):
            _group(scenario_ids=["INJ-A", "INJ-B"])  # type: ignore[arg-type]

    def test_rejects_unsorted(self):
        with pytest.raises(ValueError, match="sorted"):
            _group(scenario_ids=("INJ-B", "INJ-A"))

    def test_rejects_duplicates(self):
        with pytest.raises(ValueError, match="unique"):
            _group(scenario_ids=("INJ-A", "INJ-A"))


class TestGroupHashShape:
    def test_rejects_short_hash(self):
        with pytest.raises(ValueError, match="32 hex"):
            _group(skeleton_hash="abc123")


class TestGroupNFacts:
    def test_rejects_zero_facts(self):
        with pytest.raises(ValueError, match="n_facts"):
            _group(n_facts=0)

    def test_rejects_negative_facts(self):
        with pytest.raises(ValueError, match="n_facts"):
            _group(n_facts=-1)


class TestGroupTimestampInvariant:
    def test_mismatch_false_with_nonempty_list_rejected(self):
        with pytest.raises(ValueError, match="must be empty"):
            _group(timestamp_mismatch=False, timestamp_mismatched_fact_ids=("f-001",))

    def test_mismatch_true_with_empty_list_rejected(self):
        with pytest.raises(ValueError, match="must be non-empty"):
            _group(timestamp_mismatch=True, timestamp_mismatched_fact_ids=())

    def test_mismatch_true_with_list_accepted(self):
        g = _group(
            timestamp_mismatch=True,
            timestamp_mismatched_fact_ids=("f-001", "f-002"),
        )
        assert g.timestamp_mismatch is True
        assert g.timestamp_mismatched_fact_ids == ("f-001", "f-002")

    def test_mismatched_fact_ids_must_be_tuple(self):
        with pytest.raises(TypeError, match="tuple"):
            _group(
                timestamp_mismatch=True,
                timestamp_mismatched_fact_ids=["f-001"],  # type: ignore[arg-type]
            )


class TestGroupSerialization:
    def test_to_dict_round_trip(self):
        g = _group(
            timestamp_mismatch=True,
            timestamp_mismatched_fact_ids=("f-001",),
        )
        d = g.to_dict()
        # Lists in serialization, tuples on rehydration.
        assert d["scenario_ids"] == ["INJ-A", "INJ-B"]
        assert d["timestamp_mismatched_fact_ids"] == ["f-001"]
        rehydrated = SkeletonEquivalentGroup.from_dict(d)
        assert rehydrated == g


# ---------------------------------------------------------------------------
# make_group_id
# ---------------------------------------------------------------------------


class TestMakeGroupId:
    def test_uses_first_8_chars(self):
        assert make_group_id("a" * 32) == "GRP-aaaaaaaa"

    def test_rejects_short_hash(self):
        with pytest.raises(ValueError, match=">= 8 chars"):
            make_group_id("abc")


# ---------------------------------------------------------------------------
# all_scenarios_have_unique_skeleton
# ---------------------------------------------------------------------------


class TestAllUnique:
    def test_unique_returns_true(self):
        a = _packet([_fact(field="logon_type")], packet_id="a")
        b = _packet([_fact(field="process_name")], packet_id="b")
        assert all_scenarios_have_unique_skeleton([a, b]) is True

    def test_collision_returns_false(self):
        a = _packet([_fact(value="x")], packet_id="a")
        b = _packet([_fact(value="y")], packet_id="b")
        assert all_scenarios_have_unique_skeleton([a, b]) is False

    def test_empty_returns_true(self):
        assert all_scenarios_have_unique_skeleton([]) is True
