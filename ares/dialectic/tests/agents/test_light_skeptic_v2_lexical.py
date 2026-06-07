# ares/dialectic/tests/agents/test_light_skeptic_v2_lexical.py
"""Tests for Light Skeptic v2 tier 2 (lexical / string-value)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_lexical import (
    RULE_CRED_ACCESS_TOOLING,
    RULE_EXE_IN_USER_PATH,
    RULE_INEFFECTIVE_PATCH,
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


def test_exe_in_user_path_fires_on_real_value():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH in j.triggered_rules


def test_cred_access_tooling_fires_on_command_line():
    packet = _packet([
        ("command_line", "procdump.exe -ma lsass.exe C:\\Temp\\lsass.dmp"),
    ])
    j = evaluate(packet, _arch())
    assert RULE_CRED_ACCESS_TOOLING in j.triggered_rules


def test_exe_in_system_path_does_not_fire():
    # System32 is not user-writable → no exe-in-user-path violation.
    packet = _packet([("process_name", "C:\\Windows\\System32\\svchost.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH not in j.triggered_rules


def test_ineffective_patch_fires_when_threat_signal_present():
    packet = _packet([
        ("patch_applied", "KB5001"),
        ("command_line", "mimikatz sekurlsa::logonpasswords"),
    ])
    j = evaluate(packet, _arch())
    assert RULE_INEFFECTIVE_PATCH in j.triggered_rules


def test_non_string_value_is_skipped():
    # value=Any; a non-string value must not crash the string rules.
    packet = _packet([("file_size_bytes", 134217728)])
    j = evaluate(packet, _arch())  # must not raise
    assert RULE_EXE_IN_USER_PATH not in j.triggered_rules


def test_clean_benign_packet_no_malign():
    packet = _packet([("normal_login", "user jdoe 09:00")])
    j = evaluate(packet, _arch())
    assert j.malign_score == 0.0
