"""Inverse of the Oracle passthrough anchor: proves that, on the opt-in
sanitized path, Architect citation-drift NO LONGER reaches
Verdict.supporting_fact_ids, while the decision surface stays preserved.

Complements (never edits) test_oracle_supporting_fact_ids_passthrough.py:
that anchor locks the *leak* on the default path; this one locks the *fix*
on the sanitized path.
"""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents import Phase, VerdictOutcome
from ares.dialectic.agents.verdict_sanitizer import create_sanitized_oracle_verdict
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="anchor",
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


def _packet() -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="invariance-anchor-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    # A1,A2 are stage 2 (default 'data'); A3,B1 are stage 0 ('src_ip').
    for fid, field in (
        ("A1", "data"), ("A2", "data"), ("A3", "src_ip"), ("B1", "src_ip"),
    ):
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _arch(fact_ids):
    b = MessageBuilder(
        source_agent="architect", packet_id="invariance-anchor-pkt", cycle_id="c",
    )
    b.set_phase(Phase.THESIS)
    b.set_turn(1)
    b.set_type(MessageType.HYPOTHESIS)
    b.set_confidence(0.85)
    b.add_assertion(
        Assertion(
            assertion_id="hyp",
            assertion_type=AssertionType.ASSERT,
            fact_ids=tuple(fact_ids),
            interpretation="threat",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


def _skeptic():
    b = MessageBuilder(
        source_agent="skeptic", packet_id="invariance-anchor-pkt", cycle_id="c",
    )
    b.set_phase(Phase.ANTITHESIS)
    b.set_turn(2)
    b.set_type(MessageType.REBUTTAL)
    b.set_confidence(0.3)
    b.add_assertion(
        Assertion(
            assertion_id="alt",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("B1",),
            interpretation="benign",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


def test_architect_drift_does_not_propagate_after_sanitization():
    pkt = _packet()
    skep = _skeptic()
    arch_baseline = _arch(("A1", "A2", "A3"))
    arch_mutated = _arch(("A2", "A3"))  # framing-drifted citation set

    v_base, _ = create_sanitized_oracle_verdict(arch_baseline, skep, pkt)
    v_mut, _ = create_sanitized_oracle_verdict(arch_mutated, skep, pkt)

    # Decision surface preserved across the drift.
    assert v_base.outcome == v_mut.outcome == VerdictOutcome.THREAT_CONFIRMED
    assert v_base.confidence == v_mut.confidence

    # Explanation surface NO LONGER drifts (the fix): both equal the
    # packet-derived max-stage set {A1, A2}, regardless of what the
    # Architect cited. (On the default path these would be {A1,A2,A3}
    # vs {A2,A3} -- different -- which the passthrough anchor locks.)
    assert v_base.supporting_fact_ids == v_mut.supporting_fact_ids
    assert v_base.supporting_fact_ids == frozenset({"A1", "A2"})
