# ares/dialectic/tests/agents/test_light_skeptic_v2_structured.py
"""Tests for Light Skeptic v2 tier 1 (structural)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_structured import (
    RULE_HIGH_STAGE_NO_AUTH,
    RULE_HIGH_THREAT_FIELD,
    evaluate,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"f-{i:03d}", entity_id=f"e-{i}", entity_type=EntityType.NODE,
            field=field, value=value, timestamp=datetime(2026, 1, 1, 0, 30),
            provenance=prov))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_high_threat_field_fires():
    packet = _packet([("credential_dump", "lsass")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD in j.triggered_rules
    assert j.malign_score >= 0.4


def test_high_stage_without_auth_fires():
    # process_name is unmapped → stage 2; no authorization fact present.
    packet = _packet([("process_name", "x.exe")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_STAGE_NO_AUTH in j.triggered_rules


def test_high_stage_suppressed_when_authorized():
    packet = _packet([("process_name", "x.exe"), ("change_ticket", "CR-1")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_STAGE_NO_AUTH not in j.triggered_rules


def test_blind_to_value_borne_attack():
    # The frontier's whole point: malice in the VALUE, generic field name.
    # Tier 1 does not read the value, so M1 (high-threat field) must NOT fire.
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD not in j.triggered_rules


def test_low_stage_benign_not_malign():
    packet = _packet([("patch_applied", "KB-1")])  # benign field, stage 0
    j = evaluate(packet, _arch())
    assert RULE_HIGH_THREAT_FIELD not in j.triggered_rules
    assert RULE_HIGH_STAGE_NO_AUTH not in j.triggered_rules
    assert j.malign_score == 0.0
