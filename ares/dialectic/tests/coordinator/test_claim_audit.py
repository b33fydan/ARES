"""Tests for ClaimAuditor — Session 023.

Comprehensive tests covering construction, support level classification,
audit verdict logic, edge cases, miscalibration_ratio, immutability,
and integration with existing types.
"""

from __future__ import annotations

import pytest
from datetime import datetime, timedelta

from ares.dialectic.coordinator.claim_audit import (
    AuditVerdict,
    ClaimAuditDetail,
    ClaimAuditResult,
    ClaimAuditor,
    ClaimSupport,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import (
    DialecticalMessage,
    MessageType,
    Phase,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _ts() -> datetime:
    return datetime(2026, 1, 1, 12, 0, 0)


def _make_fact(fact_id: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id="host-1",
        entity_type=EntityType.NODE,
        field="event",
        value="test",
        timestamp=_ts(),
        provenance=Provenance(
            source_type=SourceType.SYSLOG,
            source_id="test-src",
            extracted_at=_ts(),
        ),
    )


def _make_packet(fact_ids: list[str]) -> EvidencePacket:
    tw = TimeWindow(start=_ts() - timedelta(hours=1), end=_ts())
    pkt = EvidencePacket(packet_id="pkt-001", time_window=tw)
    for fid in fact_ids:
        pkt.add_fact(_make_fact(fid))
    pkt.freeze()
    return pkt


def _make_assertion(
    assertion_id: str = "a1",
    fact_ids: tuple[str, ...] = ("f1",),
    interpretation: str = "test claim",
    assertion_type: AssertionType = AssertionType.ASSERT,
) -> Assertion:
    return Assertion(
        assertion_id=assertion_id,
        assertion_type=assertion_type,
        fact_ids=fact_ids,
        interpretation=interpretation,
    )


def _make_message(
    assertions: list[Assertion] | None = None,
    confidence: float = 0.80,
) -> DialecticalMessage:
    return DialecticalMessage(
        message_id="msg-001",
        timestamp=_ts(),
        source_agent="architect",
        target_agent="oracle",
        confidence=confidence,
        assertions=assertions or [],
        phase=Phase.THESIS,
        message_type=MessageType.HYPOTHESIS,
    )


# ===========================================================================
# Construction and defaults
# ===========================================================================

class TestClaimAuditorConstruction:
    """Test ClaimAuditor construction and defaults."""

    def test_default_threshold(self) -> None:
        a = ClaimAuditor()
        assert a.miscalibration_threshold == 0.5

    def test_custom_threshold(self) -> None:
        a = ClaimAuditor(miscalibration_threshold=0.3)
        assert a.miscalibration_threshold == 0.3

    def test_invalid_threshold_above_one_raises(self) -> None:
        with pytest.raises(ValueError, match="miscalibration_threshold"):
            ClaimAuditor(miscalibration_threshold=1.5)

    def test_invalid_threshold_negative_raises(self) -> None:
        with pytest.raises(ValueError, match="miscalibration_threshold"):
            ClaimAuditor(miscalibration_threshold=-0.1)

    def test_repr(self) -> None:
        a = ClaimAuditor()
        assert "ClaimAuditor" in repr(a)
        assert "0.5" in repr(a)

    def test_threshold_at_zero_valid(self) -> None:
        a = ClaimAuditor(miscalibration_threshold=0.0)
        assert a.miscalibration_threshold == 0.0

    def test_threshold_at_one_valid(self) -> None:
        a = ClaimAuditor(miscalibration_threshold=1.0)
        assert a.miscalibration_threshold == 1.0


# ===========================================================================
# Support level classification
# ===========================================================================

class TestSupportLevelClassification:
    """Test per-claim support level assignment."""

    def test_supported_two_facts(self) -> None:
        """Claim citing 2 existing facts -> SUPPORTED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2"])
        msg = _make_message(assertions=[_make_assertion("a1", ("f1", "f2"))])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.SUPPORTED
        assert result.claim_details[0].fact_count == 2

    def test_supported_three_facts(self) -> None:
        """Claim citing 3 existing facts -> SUPPORTED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2", "f3"])
        msg = _make_message(assertions=[_make_assertion("a1", ("f1", "f2", "f3"))])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.SUPPORTED

    def test_weak_one_fact(self) -> None:
        """Claim citing 1 existing fact -> WEAK."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[_make_assertion("a1", ("f1",))])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.WEAK
        assert result.claim_details[0].fact_count == 1

    def test_unsupported_no_valid_facts(self) -> None:
        """Claim citing facts not in packet -> UNSUPPORTED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[_make_assertion("a1", ("f99", "f100"))])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.UNSUPPORTED
        assert result.claim_details[0].fact_count == 0

    def test_mixed_valid_invalid_facts(self) -> None:
        """Claim citing 1 valid + 1 invalid fact -> WEAK."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[_make_assertion("a1", ("f1", "f99"))])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.WEAK
        assert result.claim_details[0].fact_count == 1

    def test_claim_detail_fields(self) -> None:
        """ClaimAuditDetail captures assertion metadata correctly."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2"])
        assertion = _make_assertion(
            "a1", ("f1", "f2"),
            interpretation="escalation detected",
            assertion_type=AssertionType.LINK,
        )
        msg = _make_message(assertions=[assertion])

        result = auditor.audit(msg, pkt)
        detail = result.claim_details[0]
        assert detail.assertion_type == AssertionType.LINK
        assert detail.claim_text == "escalation detected"
        assert detail.cited_fact_ids == ("f1", "f2")


# ===========================================================================
# Audit verdict logic
# ===========================================================================

class TestAuditVerdictLogic:
    """Test aggregate audit verdict behavior."""

    def test_all_supported_confirmed(self) -> None:
        """All claims supported -> CONFIRMED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2", "f3", "f4"])
        msg = _make_message(assertions=[
            _make_assertion("a1", ("f1", "f2")),
            _make_assertion("a2", ("f3", "f4")),
        ])

        result = auditor.audit(msg, pkt)
        assert result.audit_verdict == AuditVerdict.CONFIRMED
        assert result.miscalibration_ratio == 0.0

    def test_all_unsupported_miscalibrated(self) -> None:
        """All claims unsupported -> MISCALIBRATED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[
            _make_assertion("a1", ("f99",)),
            _make_assertion("a2", ("f100",)),
        ])

        result = auditor.audit(msg, pkt)
        assert result.audit_verdict == AuditVerdict.MISCALIBRATED
        assert result.miscalibration_ratio == 1.0

    def test_exactly_at_threshold_confirmed(self) -> None:
        """Ratio exactly at threshold (0.5) -> CONFIRMED (> not >=)."""
        auditor = ClaimAuditor(miscalibration_threshold=0.5)
        pkt = _make_packet(["f1", "f2"])
        msg = _make_message(assertions=[
            _make_assertion("a1", ("f1", "f2")),  # SUPPORTED
            _make_assertion("a2", ("f99",)),       # UNSUPPORTED
        ])

        result = auditor.audit(msg, pkt)
        # ratio = 1/2 = 0.5, threshold is 0.5, 0.5 > 0.5 is False
        assert result.audit_verdict == AuditVerdict.CONFIRMED

    def test_just_above_threshold_miscalibrated(self) -> None:
        """Ratio just above threshold -> MISCALIBRATED."""
        auditor = ClaimAuditor(miscalibration_threshold=0.3)
        pkt = _make_packet(["f1", "f2"])
        msg = _make_message(assertions=[
            _make_assertion("a1", ("f1", "f2")),  # SUPPORTED
            _make_assertion("a2", ("f99",)),       # UNSUPPORTED
        ])

        result = auditor.audit(msg, pkt)
        # ratio = 1/2 = 0.5, threshold is 0.3 -> MISCALIBRATED
        assert result.audit_verdict == AuditVerdict.MISCALIBRATED

    def test_aggregate_counts(self) -> None:
        """Verify all aggregate counts are correct."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2", "f3"])
        msg = _make_message(assertions=[
            _make_assertion("a1", ("f1", "f2")),  # SUPPORTED (2)
            _make_assertion("a2", ("f3",)),        # WEAK (1)
            _make_assertion("a3", ("f99",)),       # UNSUPPORTED (0)
        ])

        result = auditor.audit(msg, pkt)
        assert result.claims_total == 3
        assert result.claims_supported == 1
        assert result.claims_weak == 1
        assert result.claims_unsupported == 1
        assert result.miscalibration_ratio == pytest.approx(2.0 / 3.0)


# ===========================================================================
# Edge cases
# ===========================================================================

class TestEdgeCases:
    """Edge case tests."""

    def test_zero_assertions_confirmed(self) -> None:
        """No assertions -> CONFIRMED with ratio 0.0."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[])

        result = auditor.audit(msg, pkt)
        assert result.claims_total == 0
        assert result.audit_verdict == AuditVerdict.CONFIRMED
        assert result.miscalibration_ratio == 0.0
        assert result.claim_details == ()

    def test_assertion_with_empty_fact_ids(self) -> None:
        """Assertion citing zero facts -> UNSUPPORTED."""
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        msg = _make_message(assertions=[_make_assertion("a1", ())])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].support_level == ClaimSupport.UNSUPPORTED
        assert result.claim_details[0].fact_count == 0

    def test_empty_packet_all_unsupported(self) -> None:
        """Empty packet -> all claims unsupported."""
        auditor = ClaimAuditor()
        pkt = _make_packet([])
        msg = _make_message(assertions=[_make_assertion("a1", ("f1",))])

        result = auditor.audit(msg, pkt)
        assert result.claims_unsupported == 1
        assert result.audit_verdict == AuditVerdict.MISCALIBRATED


# ===========================================================================
# Immutability
# ===========================================================================

class TestImmutability:
    """Test that all output types are frozen."""

    def test_claim_audit_detail_frozen(self) -> None:
        detail = ClaimAuditDetail(
            assertion_type=AssertionType.ASSERT,
            claim_text="test",
            cited_fact_ids=("f1",),
            support_level=ClaimSupport.SUPPORTED,
            fact_count=1,
        )
        with pytest.raises(AttributeError):
            detail.fact_count = 5  # type: ignore[misc]

    def test_claim_audit_result_frozen(self) -> None:
        result = ClaimAuditResult(
            claims_total=1,
            claims_supported=1,
            claims_weak=0,
            claims_unsupported=0,
            audit_verdict=AuditVerdict.CONFIRMED,
            claim_details=(),
            miscalibration_ratio=0.0,
        )
        with pytest.raises(AttributeError):
            result.claims_total = 99  # type: ignore[misc]

    def test_claim_details_tuple(self) -> None:
        result = ClaimAuditResult(
            claims_total=0,
            claims_supported=0,
            claims_weak=0,
            claims_unsupported=0,
            audit_verdict=AuditVerdict.CONFIRMED,
            claim_details=(),
            miscalibration_ratio=0.0,
        )
        assert isinstance(result.claim_details, tuple)


# ===========================================================================
# Integration with existing types
# ===========================================================================

class TestIntegration:
    """Integration tests with real Assertion and EvidencePacket types."""

    def test_link_assertion_type_preserved(self) -> None:
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1", "f2"])
        assertion = Assertion.link_facts("link-1", ["f1", "f2"], "causal chain")
        msg = _make_message(assertions=[assertion])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].assertion_type == AssertionType.LINK
        assert result.claim_details[0].claim_text == "causal chain"

    def test_alt_assertion_type_preserved(self) -> None:
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        assertion = Assertion.alternative("alt-1", ["f1"], "benign explanation")
        msg = _make_message(assertions=[assertion])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].assertion_type == AssertionType.ALT

    def test_assert_condition_type(self) -> None:
        auditor = ClaimAuditor()
        pkt = _make_packet(["f1"])
        assertion = Assertion.assert_condition(
            "cond-1", "f1", ">", 1024, "port above 1024"
        )
        msg = _make_message(assertions=[assertion])

        result = auditor.audit(msg, pkt)
        assert result.claim_details[0].assertion_type == AssertionType.ASSERT
        assert result.claim_details[0].support_level == ClaimSupport.WEAK
