# ares/dialectic/tests/agents/test_light_skeptic_v2_canonical.py
"""Tests for Light Skeptic v2 tier 3 (canonical)."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents.light_skeptic_v2_canonical import (
    RULE_EXE_IN_USER_PATH,
    canonicalize,
    evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
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


def test_canonicalize_folds_separators_and_synonyms():
    assert canonicalize("C:\\Users\\Public\\X.EXE") == "c:/users/public/x.exe"
    assert "exe" in canonicalize("dropped a BINARY in the folder")
    assert "temp" in canonicalize("the Temporary directory")


def test_catches_synonym_variant_that_lexical_misses():
    # "binary" (standalone) in a user path, no ".exe" literal → tier 2 misses;
    # tier 3 folds binary->exe and catches it.
    packet = _packet([("file_created", "binary written to C:\\Users\\Public\\")])
    assert RULE_EXE_IN_USER_PATH not in lexical_evaluate(packet, _arch()).triggered_rules
    assert RULE_EXE_IN_USER_PATH in evaluate(packet, _arch()).triggered_rules


def test_still_catches_plain_exe_in_user_path():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    j = evaluate(packet, _arch())
    assert RULE_EXE_IN_USER_PATH in j.triggered_rules


def test_non_string_value_skipped():
    packet = _packet([("file_size_bytes", 999)])
    j = evaluate(packet, _arch())  # must not raise
    assert j.malign_score == 0.0
