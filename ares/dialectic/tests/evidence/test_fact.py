"""Tests for Fact class."""

import pytest
from datetime import datetime
from dataclasses import FrozenInstanceError

from ares.dialectic.evidence.fact import Fact, EntityType
from ares.dialectic.evidence.provenance import Provenance, SourceType


def make_provenance(source_id: str = "test-source") -> Provenance:
    """Create a test provenance instance."""
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id=source_id,
        extracted_at=datetime(2024, 1, 15, 12, 0, 0),
    )


def make_fact(
    fact_id: str = "fact-001",
    entity_id: str = "node-001",
    entity_type: EntityType = EntityType.NODE,
    field: str = "ip_address",
    value: any = "192.168.1.1",
    timestamp: datetime = None,
    provenance: Provenance = None,
) -> Fact:
    """Create a test fact instance."""
    if timestamp is None:
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
    if provenance is None:
        provenance = make_provenance()
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=entity_type,
        field=field,
        value=value,
        timestamp=timestamp,
        provenance=provenance,
    )


class TestEntityType:
    """Tests for EntityType enum."""

    def test_node_type_exists(self) -> None:
        """NODE entity type is defined."""
        assert EntityType.NODE.value == "node"

    def test_edge_type_exists(self) -> None:
        """EDGE entity type is defined."""
        assert EntityType.EDGE.value == "edge"


class TestFactImmutability:
    """Tests for Fact immutability."""

    def test_cannot_modify_fact_id(self) -> None:
        """Fact fact_id cannot be modified after creation."""
        fact = make_fact()
        with pytest.raises(FrozenInstanceError):
            fact.fact_id = "new-id"

    def test_cannot_modify_entity_id(self) -> None:
        """Fact entity_id cannot be modified after creation."""
        fact = make_fact()
        with pytest.raises(FrozenInstanceError):
            fact.entity_id = "new-entity"

    def test_cannot_modify_value(self) -> None:
        """Fact value cannot be modified after creation."""
        fact = make_fact()
        with pytest.raises(FrozenInstanceError):
            fact.value = "new-value"

    def test_cannot_modify_value_hash(self) -> None:
        """Fact value_hash cannot be modified after creation."""
        fact = make_fact()
        with pytest.raises(FrozenInstanceError):
            fact.value_hash = "tampered"


class TestFactHashComputation:
    """Tests for automatic hash computation."""

    def test_hash_is_auto_computed(self) -> None:
        """value_hash is automatically computed when not provided."""
        fact = make_fact(value="test-value")
        assert fact.value_hash is not None
        assert len(fact.value_hash) == 16

    def test_hash_is_hex_string(self) -> None:
        """value_hash is a valid hex string."""
        fact = make_fact(value="test-value")
        # Should not raise - all chars are valid hex
        int(fact.value_hash, 16)

    def test_hash_determinism_same_value(self) -> None:
        """Same value produces same hash."""
        fact1 = make_fact(fact_id="fact-001", value="identical")
        fact2 = make_fact(fact_id="fact-002", value="identical")
        assert fact1.value_hash == fact2.value_hash

    def test_hash_differs_for_different_values(self) -> None:
        """Different values produce different hashes."""
        fact1 = make_fact(value="value-a")
        fact2 = make_fact(value="value-b")
        assert fact1.value_hash != fact2.value_hash

    def test_hash_determinism_complex_dict(self) -> None:
        """Complex dict values produce deterministic hashes."""
        value = {"nested": {"key": "value"}, "list": [1, 2, 3]}
        fact1 = make_fact(fact_id="fact-001", value=value)
        fact2 = make_fact(fact_id="fact-002", value=value)
        assert fact1.value_hash == fact2.value_hash

    def test_hash_dict_key_order_independent(self) -> None:
        """Dict hash is independent of key insertion order."""
        # Python 3.7+ dicts maintain insertion order, but our hash should be key-sorted
        value1 = {"b": 2, "a": 1}
        value2 = {"a": 1, "b": 2}
        fact1 = make_fact(fact_id="fact-001", value=value1)
        fact2 = make_fact(fact_id="fact-002", value=value2)
        assert fact1.value_hash == fact2.value_hash


class TestFactHashVerification:
    """Tests for hash verification."""

    def test_verify_hash_returns_true_for_valid(self) -> None:
        """verify_hash returns True for unmodified fact."""
        fact = make_fact(value="test-value")
        assert fact.verify_hash() is True

    def test_verify_hash_with_complex_value(self) -> None:
        """verify_hash works with complex nested values."""
        value = {
            "ports": [22, 80, 443],
            "metadata": {"os": "linux", "version": "5.4"},
        }
        fact = make_fact(value=value)
        assert fact.verify_hash() is True


class TestFactMatches:
    """Tests for matches() filtering method."""

    def test_matches_with_no_criteria(self) -> None:
        """matches() with no criteria returns True."""
        fact = make_fact()
        assert fact.matches() is True

    def test_matches_entity_id_correct(self) -> None:
        """matches() returns True when entity_id matches."""
        fact = make_fact(entity_id="target-node")
        assert fact.matches(entity_id="target-node") is True

    def test_matches_entity_id_incorrect(self) -> None:
        """matches() returns False when entity_id doesn't match."""
        fact = make_fact(entity_id="target-node")
        assert fact.matches(entity_id="other-node") is False

    def test_matches_field_correct(self) -> None:
        """matches() returns True when field matches."""
        fact = make_fact(field="ip_address")
        assert fact.matches(field="ip_address") is True

    def test_matches_field_incorrect(self) -> None:
        """matches() returns False when field doesn't match."""
        fact = make_fact(field="ip_address")
        assert fact.matches(field="hostname") is False

    def test_matches_both_criteria(self) -> None:
        """matches() with both criteria requires both to match."""
        fact = make_fact(entity_id="node-001", field="ip_address")
        assert fact.matches(entity_id="node-001", field="ip_address") is True
        assert fact.matches(entity_id="node-001", field="hostname") is False
        assert fact.matches(entity_id="node-002", field="ip_address") is False


class TestFactSerialization:
    """Tests for Fact serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        """to_dict includes all fact fields."""
        timestamp = datetime(2024, 1, 15, 10, 30, 0)
        prov = make_provenance()
        fact = Fact(
            fact_id="fact-123",
            entity_id="node-456",
            entity_type=EntityType.NODE,
            field="hostname",
            value="server.example.com",
            timestamp=timestamp,
            provenance=prov,
        )

        result = fact.to_dict()

        assert result["fact_id"] == "fact-123"
        assert result["entity_id"] == "node-456"
        assert result["entity_type"] == "node"
        assert result["field"] == "hostname"
        assert result["value"] == "server.example.com"
        assert result["timestamp"] == "2024-01-15T10:30:00"
        assert "provenance" in result
        assert result["value_hash"] == fact.value_hash

    def test_serialization_roundtrip(self) -> None:
        """Fact survives serialization roundtrip."""
        original = make_fact(
            fact_id="roundtrip-fact",
            entity_id="entity-xyz",
            entity_type=EntityType.NODE,
            field="status",
            value="active",
        )

        serialized = original.to_dict()
        restored = Fact.from_dict(serialized)

        assert restored.fact_id == original.fact_id
        assert restored.entity_id == original.entity_id
        assert restored.entity_type == original.entity_type
        assert restored.field == original.field
        assert restored.value == original.value
        assert restored.timestamp == original.timestamp
        assert restored.value_hash == original.value_hash
        assert restored.provenance.source_id == original.provenance.source_id

    def test_roundtrip_preserves_hash(self) -> None:
        """Serialization roundtrip preserves the value_hash."""
        original = make_fact(value="preserve-hash-test")
        original_hash = original.value_hash

        serialized = original.to_dict()
        restored = Fact.from_dict(serialized)

        assert restored.value_hash == original_hash
        assert restored.verify_hash() is True


class TestFactComplexValues:
    """Tests for Facts with complex values."""

    def test_dict_value(self) -> None:
        """Fact can store dict values."""
        value = {"key": "value", "number": 42}
        fact = make_fact(value=value)
        assert fact.value == value
        assert fact.verify_hash() is True

    def test_list_value(self) -> None:
        """Fact can store list values."""
        value = [1, 2, 3, "four", {"five": 5}]
        fact = make_fact(value=value)
        assert fact.value == value
        assert fact.verify_hash() is True

    def test_nested_complex_value(self) -> None:
        """Fact can store deeply nested values."""
        value = {
            "level1": {
                "level2": {
                    "level3": ["a", "b", "c"],
                },
            },
            "array": [{"nested": True}],
        }
        fact = make_fact(value=value)
        assert fact.value == value
        assert fact.verify_hash() is True

    def test_complex_value_roundtrip(self) -> None:
        """Complex values survive serialization roundtrip."""
        value = {
            "ports": [22, 80, 443],
            "services": {"ssh": True, "http": True},
        }
        original = make_fact(value=value)

        serialized = original.to_dict()
        restored = Fact.from_dict(serialized)

        assert restored.value == value
        assert restored.verify_hash() is True


class TestFactEdgeEntity:
    """Tests for Facts with EDGE entity type."""

    def test_edge_entity_type(self) -> None:
        """Fact can represent edge entities."""
        fact = make_fact(
            entity_id="edge-001",
            entity_type=EntityType.EDGE,
            field="weight",
            value=0.95,
        )
        assert fact.entity_type == EntityType.EDGE
        assert fact.entity_id == "edge-001"

    def test_edge_entity_serialization(self) -> None:
        """Edge entity type serializes correctly."""
        fact = make_fact(entity_type=EntityType.EDGE)

        serialized = fact.to_dict()
        assert serialized["entity_type"] == "edge"

        restored = Fact.from_dict(serialized)
        assert restored.entity_type == EntityType.EDGE


class TestFactEquality:
    """Tests for Fact equality."""

    def test_equal_facts_are_equal(self) -> None:
        """Identical facts compare equal."""
        timestamp = datetime(2024, 1, 15, 12, 0, 0)
        prov = make_provenance()

        fact1 = Fact(
            fact_id="fact-001",
            entity_id="node-001",
            entity_type=EntityType.NODE,
            field="ip",
            value="10.0.0.1",
            timestamp=timestamp,
            provenance=prov,
        )
        fact2 = Fact(
            fact_id="fact-001",
            entity_id="node-001",
            entity_type=EntityType.NODE,
            field="ip",
            value="10.0.0.1",
            timestamp=timestamp,
            provenance=prov,
        )

        assert fact1 == fact2

    def test_different_facts_not_equal(self) -> None:
        """Facts with different values are not equal."""
        fact1 = make_fact(value="value-a")
        fact2 = make_fact(value="value-b")
        assert fact1 != fact2
