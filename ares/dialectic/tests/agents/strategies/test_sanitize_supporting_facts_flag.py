"""Opt-in sanitize_supporting_facts flag on the production cycles.

Offline/deterministic (MagicMock strategies; no live LLM). Default path
(flag off) stays leaky (Architect citations pass through); flag on
re-derives supporting_fact_ids from the packet via verdict_sanitizer.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.verdict_sanitizer import (
    relevant_fact_ids,
    sanitize_verdict,
)
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


# --- inline helpers (per the project's inline-helpers test convention) ---

def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="flag-test",
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


def _packet(field_by_id: dict[str, str], packet_id: str = "flag-pkt") -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id=packet_id,
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in field_by_id.items():
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _confirmed_packet() -> EvidencePacket:
    # stages (per _STAGE_MAP): src_ip=0, port_scan=1, data=2 (default).
    # max-stage set = {f-exec}; architect will cite the low-stage facts.
    return _packet({"f-recon": "src_ip", "f-scan": "port_scan", "f-exec": "data"})


def _analyzer(fact_ids, confidence: float = 0.85) -> MagicMock:
    """Stub ThreatAnalyzer citing a chosen fact set at a chosen confidence."""
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
    """Stub ExplanationFinder with no benign explanations -> low Skeptic conf."""
    m = MagicMock()
    m.find_explanations.return_value = []
    return m


# --- live cycle ---

def test_live_cycle_flag_off_is_leaky():
    pkt = _confirmed_packet()
    res = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Default path cites what the Architect cited (the leak).
    assert res.verdict.supporting_fact_ids == frozenset({"f-recon", "f-scan"})


def test_live_cycle_flag_on_is_sanitized():
    pkt = _confirmed_packet()
    res = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Sanitized = packet max-stage set, NOT the architect's citations.
    assert res.verdict.supporting_fact_ids == frozenset({"f-exec"})
    assert res.verdict.supporting_fact_ids == relevant_fact_ids(pkt, res.verdict.outcome)


def test_live_cycle_flag_preserves_decision():
    pkt = _confirmed_packet()
    off = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    on = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    # Decision determinism: outcome + confidence unchanged.
    assert off.verdict.outcome == on.verdict.outcome
    assert off.verdict.confidence == on.verdict.confidence
    # on == sanitize(off): the flag transforms only the cited set.
    assert on.verdict.supporting_fact_ids == sanitize_verdict(off.verdict, pkt).supporting_fact_ids
    assert off.verdict.supporting_fact_ids != on.verdict.supporting_fact_ids
