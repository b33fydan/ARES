"""Tests for the opt-in Verdict supporting_fact_ids sanitizer."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents import OracleJudge, Phase, Verdict, VerdictOutcome
from ares.dialectic.agents.oracle import OracleNarrator
from ares.dialectic.agents.verdict_sanitizer import (
    create_sanitized_oracle_verdict,
    relevant_fact_ids,
    sanitize_verdict,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2026, 5, 31, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 5, 31, 12, 0, 0),
        provenance=_prov(),
    )


def _packet(field_by_id: dict[str, str]) -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="sanitizer-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in field_by_id.items():
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _verdict(outcome: VerdictOutcome, supporting: set[str]) -> Verdict:
    return Verdict(
        outcome=outcome,
        confidence=0.8,
        supporting_fact_ids=frozenset(supporting),
        architect_confidence=0.85,
        skeptic_confidence=0.3,
        reasoning="r",
    )


def _msg(source, phase, mtype, fact_ids, confidence, turn):
    b = MessageBuilder(
        source_agent=source, packet_id="sanitizer-pkt", cycle_id="c",
    )
    b.set_phase(phase)
    b.set_turn(turn)
    b.set_type(mtype)
    b.set_confidence(confidence)
    b.add_assertion(
        Assertion(
            assertion_id="a",
            assertion_type=AssertionType.ASSERT,
            fact_ids=tuple(fact_ids),
            interpretation="i",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


class _EmptyPacket:
    """Minimal stand-in to exercise the empty-packet branch in isolation."""

    def get_all_facts(self):
        return []


# --- relevant_fact_ids: THREAT_CONFIRMED ---

def test_confirmed_selects_max_stage_facts():
    pkt = _packet({"f-recon": "src_ip", "f-scan": "port_scan", "f-exec": "data"})
    # stages: src_ip=0, port_scan=1, data=2 -> max stage 2 -> {f-exec}
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_CONFIRMED) == frozenset(
        {"f-exec"}
    )


def test_confirmed_includes_all_ties_at_top_stage():
    pkt = _packet({"f-e1": "data", "f-e2": "payload", "f-recon": "src_ip"})
    # data=2, payload=2 (both default), src_ip=0 -> {f-e1, f-e2}
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_CONFIRMED) == frozenset(
        {"f-e1", "f-e2"}
    )


# --- relevant_fact_ids: THREAT_DISMISSED ---

def test_dismissed_selects_authorization_fields():
    pkt = _packet({"f-auth": "authorization", "f-exec": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-auth"}
    )


def test_dismissed_counts_benign_indicator_fields_as_exculpatory():
    pkt = _packet({"f-benign": "normal_login", "f-exec": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-benign"}
    )


def test_dismissed_falls_back_to_whole_packet_when_no_exculpatory():
    pkt = _packet({"f-exec": "data", "f-scan": "port_scan"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-exec", "f-scan"}
    )


# --- relevant_fact_ids: INCONCLUSIVE + empty ---

def test_inconclusive_returns_all_facts():
    pkt = _packet({"f-a": "src_ip", "f-b": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.INCONCLUSIVE) == frozenset(
        {"f-a", "f-b"}
    )


def test_empty_packet_returns_empty_frozenset():
    assert relevant_fact_ids(_EmptyPacket(), VerdictOutcome.THREAT_CONFIRMED) == frozenset()


# --- sanitize_verdict ---

def test_sanitize_replaces_only_supporting_fact_ids():
    pkt = _packet({"f-exec": "data", "f-recon": "src_ip"})
    v = _verdict(VerdictOutcome.THREAT_CONFIRMED, supporting={"bogus-1", "bogus-2"})
    s = sanitize_verdict(v, pkt)
    # supporting set is re-derived (max-stage = data) ...
    assert s.supporting_fact_ids == frozenset({"f-exec"})
    # ... and every other field is preserved verbatim.
    assert s.outcome == v.outcome
    assert s.confidence == v.confidence
    assert s.architect_confidence == v.architect_confidence
    assert s.skeptic_confidence == v.skeptic_confidence
    assert s.reasoning == v.reasoning


def test_sanitize_returns_new_instance_leaving_original_unchanged():
    pkt = _packet({"f-a": "data"})
    v = _verdict(VerdictOutcome.INCONCLUSIVE, supporting={"x"})
    s = sanitize_verdict(v, pkt)
    assert s is not v
    assert v.supporting_fact_ids == frozenset({"x"})  # original untouched
    assert s.supporting_fact_ids == frozenset({"f-a"})
