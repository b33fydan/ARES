# ares/dialectic/tests/agents/test_light_skeptic_v2_common.py
"""Tests for the shared v2 malign-rule scaffolding."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_common import (
    MalignHit,
    assemble_judgment,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment


def _packet(field_value_pairs):
    packet = EvidencePacket(
        packet_id="t-packet",
        time_window=TimeWindow(
            start=datetime(2026, 1, 1, 0, 0, 0),
            end=datetime(2026, 1, 1, 1, 0, 0),
        ),
    )
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="src", parser_version="1.0.0"
    )
    for i, (field, value) in enumerate(field_value_pairs):
        packet.add_fact(Fact(
            fact_id=f"fact-{i:03d}", entity_id=f"ent-{i}",
            entity_type=EntityType.NODE, field=field, value=value,
            timestamp=datetime(2026, 1, 1, 0, 30, 0), provenance=prov,
        ))
    packet.freeze()
    return packet


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t-packet", cycle_id="c1")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def _always_fires(_packet):
    return MalignHit(rule_id="m_test", weight=0.4, rationale="m_test: fired")


def _never_fires(_packet):
    return None


def test_malign_lowers_confidence_below_benign_only():
    # change_ticket → v1 benign R1 (+0.4) and R3 low-stage (+0.2).
    packet = _packet([("change_ticket", "CR-1")])
    j = assemble_judgment(packet, _arch(), (_always_fires,))
    assert isinstance(j, LightSkepticJudgment)
    assert j.malign_score == 0.4
    assert "m_test" in j.triggered_rules
    # benign 0.6, malign 0.4 → 0.5 + 0.6 - 0.4 = 0.7
    assert j.confidence == 0.7


def test_no_signal_falls_back_to_default_floor():
    # process_name+command_line → no v1 benign rule, no malign rule fires.
    packet = _packet([("process_name", "evil.exe"), ("command_line", "evil.exe")])
    j = assemble_judgment(packet, _arch(), (_never_fires,))
    assert j.triggered_rules == ("default_floor",)
    assert j.confidence == 0.5
    assert j.benign_score == 0.0
    assert j.malign_score == 0.0


def test_default_floor_dropped_when_malign_fires_without_benign():
    packet = _packet([("process_name", "evil.exe")])  # no benign signal
    j = assemble_judgment(packet, _arch(), (_always_fires,))
    assert "default_floor" not in j.triggered_rules
    assert "m_test" in j.triggered_rules
    # benign 0.0, malign 0.4 → 0.5 + 0.0 - 0.4 = 0.1
    assert j.confidence == 0.1


def test_malign_score_clamped_to_one():
    packet = _packet([("process_name", "evil.exe")])
    heavy = (
        lambda p: MalignHit("m_a", 0.7, "a"),
        lambda p: MalignHit("m_b", 0.7, "b"),
    )
    j = assemble_judgment(packet, _arch(), heavy)
    assert j.malign_score == 1.0
    assert j.confidence == 0.0  # 0.5 + 0 - 1.0 clamped
