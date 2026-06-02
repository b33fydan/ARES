"""run_production_cycle: single-turn production cycle, sanitized by default."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.verdict_sanitizer import relevant_fact_ids
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.agents.strategies.production_cycle import run_production_cycle
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="prod-test",
        extracted_at=datetime(2026, 6, 1, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 6, 1, 12, 0, 0),
        provenance=_prov(),
    )


def _confirmed_packet() -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="prod-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in (("f-recon", "src_ip"), ("f-scan", "port_scan"), ("f-exec", "data")):
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _analyzer(fact_ids, confidence: float = 0.85) -> MagicMock:
    m = MagicMock()
    m.analyze_threats.return_value = [
        AnomalyPattern(
            pattern_type=PatternType.PRIVILEGE_ESCALATION,
            fact_ids=frozenset(fact_ids),
            confidence=confidence,
            description="stub anomaly",
        ),
    ]
    return m


def _finder_empty() -> MagicMock:
    m = MagicMock()
    m.find_explanations.return_value = []
    return m


def test_production_cycle_sanitizes_by_default():
    pkt = _confirmed_packet()
    res = run_production_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Sanitized cited set out of the box (no flag passed by the caller).
    assert res.verdict.supporting_fact_ids == frozenset({"f-exec"})
    assert res.verdict.supporting_fact_ids == relevant_fact_ids(pkt, res.verdict.outcome)


def test_production_cycle_matches_flagged_underlying():
    pkt = _confirmed_packet()
    prod = run_production_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    flagged = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    assert prod.verdict.outcome == flagged.verdict.outcome
    assert prod.verdict.confidence == flagged.verdict.confidence
    assert prod.verdict.supporting_fact_ids == flagged.verdict.supporting_fact_ids
