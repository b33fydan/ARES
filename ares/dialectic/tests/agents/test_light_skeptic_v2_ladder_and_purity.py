# ares/dialectic/tests/agents/test_light_skeptic_v2_ladder_and_purity.py
"""Ladder registry contract + cross-tier purity guards (S086 Phase A)."""
from __future__ import annotations

import importlib
import inspect
from datetime import datetime

from ares.dialectic.agents import light_skeptic
from ares.dialectic.agents.light_skeptic_v2_ladder import (
    DETERMINISTIC_TIERS,
    LADDER_ORDER,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase
from ares.dialectic.schemas.light_skeptic_judgment import LightSkepticJudgment

_V2_MODULES = (
    "ares.dialectic.agents.light_skeptic_v2_common",
    "ares.dialectic.agents.light_skeptic_v2_structured",
    "ares.dialectic.agents.light_skeptic_v2_lexical",
    "ares.dialectic.agents.light_skeptic_v2_canonical",
    "ares.dialectic.agents.light_skeptic_v2_ladder",
)


def _packet(pairs):
    packet = EvidencePacket(
        packet_id="t", time_window=TimeWindow(
            start=datetime(2026, 1, 1), end=datetime(2026, 1, 1, 1)))
    prov = Provenance(
        source_type=SourceType.SYSLOG, source_id="s", parser_version="1.0.0")
    for i, (field, value) in enumerate(pairs):
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


def test_ladder_order_is_five_rungs():
    assert LADDER_ORDER == (
        "v1_field", "v2_structured", "v2_lexical", "v2_canonical", "llm_semantic",
    )


def test_deterministic_tiers_are_callable_and_return_judgment():
    packet = _packet([("process_name", "C:\\Users\\Public\\procdump.exe")])
    for tier_id, fn in DETERMINISTIC_TIERS.items():
        j = fn(packet, _arch())
        assert isinstance(j, LightSkepticJudgment), tier_id


def test_deterministic_tiers_exclude_llm_anchor():
    # tier 4 is registered by name in LADDER_ORDER but NOT built here.
    assert "llm_semantic" not in DETERMINISTIC_TIERS
    assert set(DETERMINISTIC_TIERS) == {
        "v1_field", "v2_structured", "v2_lexical", "v2_canonical",
    }


def test_no_v2_module_imports_anthropic():
    for name in _V2_MODULES:
        mod = importlib.import_module(name)
        src = inspect.getsource(mod)
        assert "import anthropic" not in src, name
        assert "from anthropic" not in src, name


def test_no_v2_module_touches_network_or_random_or_fs():
    forbidden = ("import requests", "import socket", "import random",
                 "open(", "urllib")
    for name in _V2_MODULES:
        mod = importlib.import_module(name)
        src = inspect.getsource(mod)
        for token in forbidden:
            assert token not in src, f"{name} contains forbidden '{token}'"


def test_determinism_same_input_same_output():
    packet = _packet([("command_line", "mimikatz sekurlsa::logonpasswords")])
    for fn in DETERMINISTIC_TIERS.values():
        first = fn(packet, _arch()).to_json()
        second = fn(packet, _arch()).to_json()
        assert first == second


def test_v1_behaviour_unchanged_by_v2_presence():
    # Guard: importing the v2 ladder must not perturb v1's output. Known v1
    # value: change_ticket → R1(0.4)+R3(0.2) benign → 0.5+0.6 = 1.1 clamp 1.0.
    packet = _packet([("change_ticket", "CR-1")])
    assert light_skeptic.evaluate(packet, _arch()).confidence == 1.0
