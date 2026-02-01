"""Tests for Assertion class."""

import pytest
from datetime import datetime
from dataclasses import FrozenInstanceError

from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.evidence import (
    EvidencePacket,
    Fact,
    Provenance,
    SourceType,
    EntityType,
    TimeWindow,
)


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
) -> Fact:
    """Create a test fact instance."""
    return Fact(
        fact_id=fact_id,
        entity_id=entity_id,
        entity_type=EntityType.NODE,
        field=field,
        value=value,
        timestamp=datetime(2024, 1, 15, 12, 0, 0),
        provenance=make_provenance(),
    )


def make_packet_with_facts(*fact_ids: str) -> EvidencePacket:
    """Create a packet with facts having the given IDs."""
    packet = EvidencePacket(
        packet_id="test-packet",
        time_window=TimeWindow(
            start=datetime(2024, 1, 1),
            end=datetime(2024, 1, 31),
        ),
    )
    for fid in fact_ids:
        packet.add_fact(make_fact(fact_id=fid))
    return packet


class TestAssertionType:
    """Tests for AssertionType enum."""

    def test_assert_type_exists(self) -> None:
        """ASSERT type is defined."""
        assert AssertionType.ASSERT.value == "assert"

    def test_link_type_exists(self) -> None:
        """LINK type is defined."""
        assert AssertionType.LINK.value == "link"

    def test_alt_type_exists(self) -> None:
        """ALT type is defined."""
        assert AssertionType.ALT.value == "alt"

    def test_all_assertion_types(self) -> None:
        """All expected assertion types are defined."""
        expected = {"ASSERT", "LINK", "ALT"}
        actual = {member.name for member in AssertionType}
        assert actual == expected


class TestAssertionImmutability:
    """Tests for Assertion immutability."""

    def test_cannot_modify_assertion_id(self) -> None:
        """Assertion assertion_id cannot be modified."""
        assertion = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        with pytest.raises(FrozenInstanceError):
            assertion.assertion_id = "new-id"

    def test_cannot_modify_assertion_type(self) -> None:
        """Assertion assertion_type cannot be modified."""
        assertion = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        with pytest.raises(FrozenInstanceError):
            assertion.assertion_type = AssertionType.LINK

    def test_cannot_modify_fact_ids(self) -> None:
        """Assertion fact_ids cannot be modified."""
        assertion = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        with pytest.raises(FrozenInstanceError):
            assertion.fact_ids = ("f2",)

    def test_cannot_modify_interpretation(self) -> None:
        """Assertion interpretation cannot be modified."""
        assertion = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        with pytest.raises(FrozenInstanceError):
            assertion.interpretation = "modified"


class TestAssertionSerialization:
    """Tests for Assertion serialization."""

    def test_to_dict_contains_all_fields(self) -> None:
        """to_dict includes all assertion fields."""
        assertion = Assertion(
            assertion_id="assert-001",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("fact-001",),
            interpretation="Port is above 1024",
            operator=">",
            threshold=1024,
        )

        result = assertion.to_dict()

        assert result["assertion_id"] == "assert-001"
        assert result["assertion_type"] == "assert"
        assert result["fact_ids"] == ["fact-001"]
        assert result["interpretation"] == "Port is above 1024"
        assert result["operator"] == ">"
        assert result["threshold"] == 1024

    def test_serialization_roundtrip(self) -> None:
        """Assertion survives serialization roundtrip."""
        original = Assertion(
            assertion_id="link-001",
            assertion_type=AssertionType.LINK,
            fact_ids=("f1", "f2", "f3"),
            interpretation="Causal chain from login to exfil",
        )

        serialized = original.to_dict()
        restored = Assertion.from_dict(serialized)

        assert restored.assertion_id == original.assertion_id
        assert restored.assertion_type == original.assertion_type
        assert restored.fact_ids == original.fact_ids
        assert restored.interpretation == original.interpretation

    def test_roundtrip_with_operator_and_threshold(self) -> None:
        """Serialization preserves operator and threshold."""
        original = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="f1",
            operator=">=",
            threshold=100,
            interpretation="Value at least 100",
        )

        serialized = original.to_dict()
        restored = Assertion.from_dict(serialized)

        assert restored.operator == ">="
        assert restored.threshold == 100

    def test_roundtrip_without_operator_and_threshold(self) -> None:
        """Serialization handles None operator and threshold."""
        original = Assertion.link_facts(
            assertion_id="a1",
            fact_ids=["f1", "f2"],
            interpretation="Linked facts",
        )

        serialized = original.to_dict()
        restored = Assertion.from_dict(serialized)

        assert restored.operator is None
        assert restored.threshold is None


class TestAssertConditionFactory:
    """Tests for assert_condition factory method."""

    def test_creates_assert_type(self) -> None:
        """assert_condition creates ASSERT type."""
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="f1",
            operator=">",
            threshold=1024,
            interpretation="Port above 1024",
        )
        assert assertion.assertion_type == AssertionType.ASSERT

    def test_sets_single_fact_id(self) -> None:
        """assert_condition sets single fact_id."""
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="target-fact",
            operator="==",
            threshold="expected",
            interpretation="Equals expected",
        )
        assert assertion.fact_ids == ("target-fact",)

    def test_sets_operator(self) -> None:
        """assert_condition sets operator."""
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="f1",
            operator="!=",
            threshold=0,
            interpretation="Not zero",
        )
        assert assertion.operator == "!="

    def test_sets_threshold(self) -> None:
        """assert_condition sets threshold."""
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="f1",
            operator="<",
            threshold=500,
            interpretation="Less than 500",
        )
        assert assertion.threshold == 500

    def test_supports_all_operators(self) -> None:
        """assert_condition supports all comparison operators."""
        operators = [">", "<", "==", ">=", "<=", "!="]
        for op in operators:
            assertion = Assertion.assert_condition(
                assertion_id=f"a-{op}",
                fact_id="f1",
                operator=op,
                threshold=1,
                interpretation=f"Using {op}",
            )
            assert assertion.operator == op


class TestLinkFactsFactory:
    """Tests for link_facts factory method."""

    def test_creates_link_type(self) -> None:
        """link_facts creates LINK type."""
        assertion = Assertion.link_facts(
            assertion_id="link-001",
            fact_ids=["f1", "f2"],
            interpretation="Causal chain",
        )
        assert assertion.assertion_type == AssertionType.LINK

    def test_sets_multiple_fact_ids(self) -> None:
        """link_facts sets multiple fact_ids."""
        assertion = Assertion.link_facts(
            assertion_id="link-001",
            fact_ids=["f1", "f2", "f3", "f4"],
            interpretation="Chain of events",
        )
        assert assertion.fact_ids == ("f1", "f2", "f3", "f4")

    def test_no_operator_set(self) -> None:
        """link_facts does not set operator."""
        assertion = Assertion.link_facts(
            assertion_id="link-001",
            fact_ids=["f1", "f2"],
            interpretation="Link",
        )
        assert assertion.operator is None

    def test_no_threshold_set(self) -> None:
        """link_facts does not set threshold."""
        assertion = Assertion.link_facts(
            assertion_id="link-001",
            fact_ids=["f1", "f2"],
            interpretation="Link",
        )
        assert assertion.threshold is None


class TestAlternativeFactory:
    """Tests for alternative factory method."""

    def test_creates_alt_type(self) -> None:
        """alternative creates ALT type."""
        assertion = Assertion.alternative(
            assertion_id="alt-001",
            fact_ids=["f1"],
            interpretation="Alternative explanation",
        )
        assert assertion.assertion_type == AssertionType.ALT

    def test_sets_fact_ids(self) -> None:
        """alternative sets fact_ids."""
        assertion = Assertion.alternative(
            assertion_id="alt-001",
            fact_ids=["f1", "f2"],
            interpretation="Could be benign",
        )
        assert assertion.fact_ids == ("f1", "f2")

    def test_sets_interpretation(self) -> None:
        """alternative sets interpretation."""
        assertion = Assertion.alternative(
            assertion_id="alt-001",
            fact_ids=["f1"],
            interpretation="Routine backup activity",
        )
        assert assertion.interpretation == "Routine backup activity"


class TestValidateAgainstPacket:
    """Tests for validate_against_packet method."""

    def test_valid_when_all_facts_exist(self) -> None:
        """Returns valid when all fact_ids exist in packet."""
        packet = make_packet_with_facts("f1", "f2", "f3")
        assertion = Assertion.link_facts(
            assertion_id="a1",
            fact_ids=["f1", "f2"],
            interpretation="Link",
        )

        is_valid, missing = assertion.validate_against_packet(packet)

        assert is_valid is True
        assert missing == []

    def test_invalid_when_facts_missing(self) -> None:
        """Returns invalid with missing fact_ids when facts don't exist."""
        packet = make_packet_with_facts("f1")
        assertion = Assertion.link_facts(
            assertion_id="a1",
            fact_ids=["f1", "f2", "f3"],
            interpretation="Link",
        )

        is_valid, missing = assertion.validate_against_packet(packet)

        assert is_valid is False
        assert set(missing) == {"f2", "f3"}

    def test_valid_single_fact(self) -> None:
        """Validates single fact assertion correctly."""
        packet = make_packet_with_facts("target-fact")
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="target-fact",
            operator=">",
            threshold=0,
            interpretation="Positive",
        )

        is_valid, missing = assertion.validate_against_packet(packet)

        assert is_valid is True
        assert missing == []

    def test_invalid_single_fact_missing(self) -> None:
        """Returns invalid when single fact doesn't exist."""
        packet = make_packet_with_facts("other-fact")
        assertion = Assertion.assert_condition(
            assertion_id="a1",
            fact_id="missing-fact",
            operator=">",
            threshold=0,
            interpretation="Positive",
        )

        is_valid, missing = assertion.validate_against_packet(packet)

        assert is_valid is False
        assert missing == ["missing-fact"]


class TestAssertionEmptyFactIds:
    """Tests for assertions with empty fact_ids."""

    def test_empty_fact_ids_allowed(self) -> None:
        """Empty fact_ids tuple is allowed (for edge cases)."""
        assertion = Assertion(
            assertion_id="empty-001",
            assertion_type=AssertionType.ALT,
            fact_ids=(),
            interpretation="No facts needed for this claim",
        )
        assert assertion.fact_ids == ()

    def test_empty_fact_ids_validates_true(self) -> None:
        """Empty fact_ids validates as true (nothing to check)."""
        packet = make_packet_with_facts("f1")
        assertion = Assertion(
            assertion_id="empty-001",
            assertion_type=AssertionType.ALT,
            fact_ids=(),
            interpretation="Abstract claim",
        )

        is_valid, missing = assertion.validate_against_packet(packet)

        assert is_valid is True
        assert missing == []


class TestAssertionEquality:
    """Tests for Assertion equality."""

    def test_equal_assertions_are_equal(self) -> None:
        """Identical assertions compare equal."""
        a1 = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
            operator=">",
            threshold=10,
        )
        a2 = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
            operator=">",
            threshold=10,
        )
        assert a1 == a2

    def test_different_assertions_not_equal(self) -> None:
        """Different assertions do not compare equal."""
        a1 = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        a2 = Assertion(
            assertion_id="a2",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("f1",),
            interpretation="test",
        )
        assert a1 != a2

    def test_assertion_is_hashable(self) -> None:
        """Assertions can be used in sets."""
        assertion = Assertion(
            assertion_id="a1",
            assertion_type=AssertionType.LINK,
            fact_ids=("f1", "f2"),
            interpretation="test",
        )

        assertion_set = {assertion}
        assert assertion in assertion_set
