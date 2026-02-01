"""Tests for EvidencePacket class."""

import pytest
from datetime import datetime, timedelta

from ares.dialectic.evidence.packet import (
    EvidencePacket,
    TimeWindow,
    EvidencePacketError,
    FactNotFoundError,
    PacketFrozenError,
    DuplicateFactError,
)
from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType


def make_provenance() -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    field: str = "ip_address",
    value: any = "192.168.1.1",
    timestamp: datetime = None,
) -> Fact:
    """Create a test fact instance."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=timestamp,
        provenance=make_provenance(),
    )


def make_time_window() -> TimeWindow:
    """Create a test time window."""
    return TimeWindow(
        start=datetime(2024, 1, 1, 0, 0, 0),
        end=datetime(2024, 1, 31, 23, 59, 59),
    )


def make_packet(packet_id: str = "packet-001") -> EvidencePacket:
    """Create a test evidence packet."""
    return EvidencePacket(packet_id=packet_id, time_window=make_time_window())


class TestTimeWindow:
    """Tests for TimeWindow class."""

    def test_contains_timestamp_in_range(self) -> None:
        """contains returns True for timestamp in range."""
        window = TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        )
        assert window.contains(datetime(2024, 1, 15)) is True

    def test_contains_timestamp_at_start(self) -> None:
        """contains returns True for timestamp at start boundary."""
        window = TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        )
        assert window.contains(datetime(2024, 1, 1)) is True

    def test_contains_timestamp_at_end(self) -> None:
        """contains returns True for timestamp at end boundary."""
        window = TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        )
        assert window.contains(datetime(2024, 1, 31)) is True

    def test_contains_timestamp_before_range(self) -> None:
        """contains returns False for timestamp before range."""
        window = TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        )
        assert window.contains(datetime(2023, 12, 31)) is False

    def test_contains_timestamp_after_range(self) -> None:
        """contains returns False for timestamp after range."""
        window = TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        )
        assert window.contains(datetime(2024, 2, 1)) is False

    def test_serialization_roundtrip(self) -> None:
        """TimeWindow survives serialization roundtrip."""
        original = TimeWindow(
            start=datetime(2024, 1, 15, 10, 30, 0),
            end=datetime(2024, 1, 15, 18, 45, 30),
        )
        serialized = original.to_dict()
        restored = TimeWindow.from_dict(serialized)

        assert restored.start == original.start
        assert restored.end == original.end


class TestEvidencePacketCreation:
    """Tests for EvidencePacket creation."""

    def test_creation_with_id_and_time_window(self) -> None:
        """Packet is created with correct ID and time window."""
        window = make_time_window()
        packet = EvidencePacket(packet_id="test-packet", time_window=window)

        assert packet.packet_id == "test-packet"
        assert packet.time_window == window

    def test_initial_state_not_frozen(self) -> None:
        """New packet is not frozen."""
        packet = make_packet()
        assert packet.is_frozen is False

    def test_initial_state_no_snapshot_id(self) -> None:
        """New packet has no snapshot_id."""
        packet = make_packet()
        assert packet.snapshot_id is None

    def test_initial_state_empty(self) -> None:
        """New packet has no facts."""
        packet = make_packet()
        assert packet.fact_count == 0
        assert len(packet.fact_ids) == 0


class TestEvidencePacketAddFact:
    """Tests for adding facts to packets."""

    def test_add_fact_increases_count(self) -> None:
        """Adding a fact increases fact_count."""
        packet = make_packet()
        fact = make_fact()

        packet.add_fact(fact)

        assert packet.fact_count == 1

    def test_add_multiple_facts(self) -> None:
        """Multiple facts can be added."""
        packet = make_packet()

        packet.add_fact(make_fact(fact_id="fact-001"))
        packet.add_fact(make_fact(fact_id="fact-002"))
        packet.add_fact(make_fact(fact_id="fact-003"))

        assert packet.fact_count == 3

    def test_add_duplicate_fact_raises_error(self) -> None:
        """Adding duplicate fact_id raises DuplicateFactError."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="duplicate"))

        with pytest.raises(DuplicateFactError) as exc_info:
            packet.add_fact(make_fact(fact_id="duplicate", value="different"))

        assert exc_info.value.fact_id == "duplicate"


class TestEvidencePacketGetFact:
    """Tests for retrieving facts."""

    def test_get_fact_returns_correct_fact(self) -> None:
        """get_fact returns the correct fact."""
        packet = make_packet()
        fact = make_fact(fact_id="target", value="target-value")
        packet.add_fact(fact)

        retrieved = packet.get_fact("target")

        assert retrieved.value == "target-value"

    def test_get_fact_not_found_raises_error(self) -> None:
        """get_fact raises FactNotFoundError for missing fact."""
        packet = make_packet()

        with pytest.raises(FactNotFoundError) as exc_info:
            packet.get_fact("nonexistent")

        assert exc_info.value.fact_id == "nonexistent"


class TestEvidencePacketHasFact:
    """Tests for has_fact method."""

    def test_has_fact_returns_true_for_existing(self) -> None:
        """has_fact returns True for existing fact."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="exists"))

        assert packet.has_fact("exists") is True

    def test_has_fact_returns_false_for_missing(self) -> None:
        """has_fact returns False for missing fact."""
        packet = make_packet()

        assert packet.has_fact("missing") is False


class TestEvidencePacketFreeze:
    """Tests for freezing packets."""

    def test_freeze_sets_frozen_flag(self) -> None:
        """freeze sets is_frozen to True."""
        packet = make_packet()
        packet.add_fact(make_fact())

        packet.freeze()

        assert packet.is_frozen is True

    def test_freeze_returns_snapshot_id(self) -> None:
        """freeze returns the snapshot_id."""
        packet = make_packet()
        packet.add_fact(make_fact())

        snapshot_id = packet.freeze()

        assert snapshot_id is not None
        assert len(snapshot_id) == 32

    def test_freeze_sets_snapshot_id_property(self) -> None:
        """freeze sets the snapshot_id property."""
        packet = make_packet()
        packet.add_fact(make_fact())

        returned_id = packet.freeze()

        assert packet.snapshot_id == returned_id

    def test_freeze_is_idempotent(self) -> None:
        """Calling freeze multiple times returns same ID."""
        packet = make_packet()
        packet.add_fact(make_fact())

        first_id = packet.freeze()
        second_id = packet.freeze()

        assert first_id == second_id

    def test_cannot_add_to_frozen_packet(self) -> None:
        """Adding fact to frozen packet raises PacketFrozenError."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="initial"))
        packet.freeze()

        with pytest.raises(PacketFrozenError):
            packet.add_fact(make_fact(fact_id="new"))

    def test_snapshot_id_is_deterministic(self) -> None:
        """Same facts produce same snapshot_id."""
        packet1 = make_packet(packet_id="packet-1")
        packet2 = make_packet(packet_id="packet-2")

        # Add same facts to both
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        for i in range(3):
            packet1.add_fact(make_fact(fact_id=f"fact-{i}", value=f"value-{i}", timestamp=timestamp))
            packet2.add_fact(make_fact(fact_id=f"fact-{i}", value=f"value-{i}", timestamp=timestamp))

        id1 = packet1.freeze()
        id2 = packet2.freeze()

        assert id1 == id2


class TestEvidencePacketValidateFactIds:
    """Tests for validate_fact_ids method."""

    def test_validate_all_valid_ids(self) -> None:
        """validate_fact_ids returns (True, []) for all valid IDs."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="fact-001"))
        packet.add_fact(make_fact(fact_id="fact-002"))

        is_valid, invalid = packet.validate_fact_ids(["fact-001", "fact-002"])

        assert is_valid is True
        assert invalid == []

    def test_validate_some_invalid_ids(self) -> None:
        """validate_fact_ids returns (False, invalid_list) for invalid IDs."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="fact-001"))

        is_valid, invalid = packet.validate_fact_ids(["fact-001", "missing-1", "missing-2"])

        assert is_valid is False
        assert set(invalid) == {"missing-1", "missing-2"}

    def test_validate_empty_list(self) -> None:
        """validate_fact_ids with empty list returns (True, [])."""
        packet = make_packet()

        is_valid, invalid = packet.validate_fact_ids([])

        assert is_valid is True
        assert invalid == []


class TestEvidencePacketIndexQueries:
    """Tests for index-based queries."""

    def test_get_facts_by_entity(self) -> None:
        """get_facts_by_entity returns facts for specific entity."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="f1", entity_id="node-A", field="ip"))
        packet.add_fact(make_fact(fact_id="f2", entity_id="node-A", field="hostname"))
        packet.add_fact(make_fact(fact_id="f3", entity_id="node-B", field="ip"))

        facts = packet.get_facts_by_entity("node-A")

        assert len(facts) == 2
        assert {f.fact_id for f in facts} == {"f1", "f2"}

    def test_get_facts_by_entity_empty(self) -> None:
        """get_facts_by_entity returns empty list for unknown entity."""
        packet = make_packet()
        packet.add_fact(make_fact(entity_id="node-A"))

        facts = packet.get_facts_by_entity("unknown")

        assert facts == []

    def test_get_facts_by_field(self) -> None:
        """get_facts_by_field returns facts with specific field."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="f1", field="ip_address"))
        packet.add_fact(make_fact(fact_id="f2", field="ip_address"))
        packet.add_fact(make_fact(fact_id="f3", field="hostname"))

        facts = packet.get_facts_by_field("ip_address")

        assert len(facts) == 2
        assert {f.fact_id for f in facts} == {"f1", "f2"}

    def test_get_facts_by_field_empty(self) -> None:
        """get_facts_by_field returns empty list for unknown field."""
        packet = make_packet()
        packet.add_fact(make_fact(field="ip_address"))

        facts = packet.get_facts_by_field("unknown_field")

        assert facts == []

    def test_get_facts_in_time_range(self) -> None:
        """get_facts_in_time_range returns facts within range."""
        packet = make_packet()
        base_time = datetime(2024, 1, 15, 12, 0, 0)

        packet.add_fact(make_fact(fact_id="f1", timestamp=base_time))
        packet.add_fact(make_fact(fact_id="f2", timestamp=base_time + timedelta(hours=1)))
        packet.add_fact(make_fact(fact_id="f3", timestamp=base_time + timedelta(hours=5)))

        facts = packet.get_facts_in_time_range(
            start=base_time,
            end=base_time + timedelta(hours=2),
        )

        assert len(facts) == 2
        assert {f.fact_id for f in facts} == {"f1", "f2"}

    def test_get_facts_in_time_range_empty(self) -> None:
        """get_facts_in_time_range returns empty for out-of-range."""
        packet = make_packet()
        packet.add_fact(make_fact(timestamp=datetime(2024, 1, 15, 12, 0, 0)))

        facts = packet.get_facts_in_time_range(
            start=datetime(2024, 2, 1),
            end=datetime(2024, 2, 28),
        )

        assert facts == []


class TestEvidencePacketCollections:
    """Tests for collection access methods."""

    def test_get_entities(self) -> None:
        """get_entities returns all unique entity IDs."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="f1", entity_id="node-A"))
        packet.add_fact(make_fact(fact_id="f2", entity_id="node-B"))
        packet.add_fact(make_fact(fact_id="f3", entity_id="node-A"))

        entities = packet.get_entities()

        assert entities == {"node-A", "node-B"}

    def test_get_fields(self) -> None:
        """get_fields returns all unique field names."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="f1", field="ip"))
        packet.add_fact(make_fact(fact_id="f2", field="hostname"))
        packet.add_fact(make_fact(fact_id="f3", field="ip"))

        fields = packet.get_fields()

        assert fields == {"ip", "hostname"}

    def test_get_all_facts(self) -> None:
        """get_all_facts returns all facts."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="f1"))
        packet.add_fact(make_fact(fact_id="f2"))
        packet.add_fact(make_fact(fact_id="f3"))

        facts = packet.get_all_facts()

        assert len(facts) == 3
        assert {f.fact_id for f in facts} == {"f1", "f2", "f3"}

    def test_fact_ids_property(self) -> None:
        """fact_ids property returns set of all fact IDs."""
        packet = make_packet()
        packet.add_fact(make_fact(fact_id="alpha"))
        packet.add_fact(make_fact(fact_id="beta"))
        packet.add_fact(make_fact(fact_id="gamma"))

        assert packet.fact_ids == {"alpha", "beta", "gamma"}


class TestEvidencePacketSerialization:
    """Tests for packet serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        """to_dict includes all packet fields."""
        packet = make_packet(packet_id="test-packet")
        packet.add_fact(make_fact())

        result = packet.to_dict()

        assert result["packet_id"] == "test-packet"
        assert result["schema_version"] == "1.0.0"
        assert "time_window" in result
        assert "facts" in result
        assert result["frozen"] is False
        assert result["snapshot_id"] is None

    def test_roundtrip_unfrozen(self) -> None:
        """Unfrozen packet survives serialization roundtrip."""
        original = make_packet()
        original.add_fact(make_fact(fact_id="f1", value="v1"))
        original.add_fact(make_fact(fact_id="f2", value="v2"))

        serialized = original.to_dict()
        restored = EvidencePacket.from_dict(serialized)

        assert restored.packet_id == original.packet_id
        assert restored.fact_count == 2
        assert restored.is_frozen is False

    def test_roundtrip_frozen(self) -> None:
        """Frozen packet survives serialization roundtrip."""
        original = make_packet()
        original.add_fact(make_fact(fact_id="f1", value="v1"))
        original_snapshot = original.freeze()

        serialized = original.to_dict()
        restored = EvidencePacket.from_dict(serialized)

        assert restored.is_frozen is True
        assert restored.snapshot_id == original_snapshot

    def test_frozen_roundtrip_verifies_snapshot(self) -> None:
        """Deserializing frozen packet verifies snapshot_id."""
        packet = make_packet()
        packet.add_fact(make_fact())
        packet.freeze()

        serialized = packet.to_dict()
        # Tamper with snapshot_id
        serialized["snapshot_id"] = "tampered_id_12345678901234"

        with pytest.raises(ValueError) as exc_info:
            EvidencePacket.from_dict(serialized)

        assert "Snapshot ID mismatch" in str(exc_info.value)


class TestEvidencePacketSummary:
    """Tests for summary method."""

    def test_summary_contains_expected_fields(self) -> None:
        """summary returns expected statistics."""
        packet = make_packet(packet_id="summary-test")
        packet.add_fact(make_fact(fact_id="f1", entity_id="e1", field="ip"))
        packet.add_fact(make_fact(fact_id="f2", entity_id="e2", field="ip"))
        packet.add_fact(make_fact(fact_id="f3", entity_id="e1", field="hostname"))

        summary = packet.summary()

        assert summary["packet_id"] == "summary-test"
        assert summary["schema_version"] == "1.0.0"
        assert summary["fact_count"] == 3
        assert summary["entity_count"] == 2
        assert summary["field_count"] == 2
        assert summary["is_frozen"] is False
        assert summary["snapshot_id"] is None
        assert "time_window" in summary

    def test_summary_after_freeze(self) -> None:
        """summary reflects frozen state."""
        packet = make_packet()
        packet.add_fact(make_fact())
        snapshot_id = packet.freeze()

        summary = packet.summary()

        assert summary["is_frozen"] is True
        assert summary["snapshot_id"] == snapshot_id


class TestExceptions:
    """Tests for custom exceptions."""

    def test_evidence_packet_error_is_base(self) -> None:
        """All packet exceptions inherit from EvidencePacketError."""
        assert issubclass(FactNotFoundError, EvidencePacketError)
        assert issubclass(PacketFrozenError, EvidencePacketError)
        assert issubclass(DuplicateFactError, EvidencePacketError)

    def test_fact_not_found_error_message(self) -> None:
        """FactNotFoundError has descriptive message."""
        error = FactNotFoundError("missing-fact-123")
        assert "missing-fact-123" in str(error)

    def test_duplicate_fact_error_message(self) -> None:
        """DuplicateFactError has descriptive message."""
        error = DuplicateFactError("duplicate-id")
        assert "duplicate-id" in str(error)
