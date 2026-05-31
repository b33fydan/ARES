import pytest
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.measurement.architect_framing_control import (
    highest_stage_fact_id, build_positive_control_scenario, choose_control_drop_fact,
)


def _first_multi_fact_scenario():
    for s in build_registry_v3().all_scenarios():
        if len(s.packet.get_all_facts()) >= 2:
            return s
    raise AssertionError("no multi-fact scenario in registry v3")


def test_highest_stage_fact_is_a_real_fact_id():
    s = _first_multi_fact_scenario()
    fid = highest_stage_fact_id(s.packet)
    assert fid in {f.fact_id for f in s.packet.get_all_facts()}


def test_control_drops_exactly_one_fact_and_keeps_metadata():
    s = _first_multi_fact_scenario()
    dropped = highest_stage_fact_id(s.packet)
    ctrl = build_positive_control_scenario(s)
    base_ids = {f.fact_id for f in s.packet.get_all_facts()}
    ctrl_ids = {f.fact_id for f in ctrl.packet.get_all_facts()}
    assert ctrl_ids == base_ids - {dropped}
    assert ctrl.metadata.scenario_id == s.metadata.scenario_id
    assert ctrl.packet.is_frozen


def test_control_requires_two_facts():
    s = _first_multi_fact_scenario()
    from ares.dialectic.evidence.packet import EvidencePacket
    one = EvidencePacket(packet_id="p", time_window=s.packet.time_window)
    one.add_fact(s.packet.get_all_facts()[0])
    from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario
    tiny = BenchmarkScenario(metadata=s.metadata, packet=one)
    with pytest.raises(ValueError, match="at least 2 facts"):
        build_positive_control_scenario(tiny)


def test_choose_control_drop_fact_prefers_a_cited_fact():
    s = _first_multi_fact_scenario()
    facts = [f.fact_id for f in s.packet.get_all_facts()]
    cited = [frozenset({facts[1]})] * 3        # baseline cites only the 2nd fact
    assert choose_control_drop_fact(s.packet, cited) == facts[1]


def test_choose_control_drop_fact_none_when_no_overlap():
    s = _first_multi_fact_scenario()
    assert choose_control_drop_fact(s.packet, [frozenset({"not-a-real-fact"})]) is None


def test_build_control_with_explicit_drop():
    s = _first_multi_fact_scenario()
    facts = [f.fact_id for f in s.packet.get_all_facts()]
    ctrl = build_positive_control_scenario(s, drop_fact_id=facts[0])
    ctrl_ids = {f.fact_id for f in ctrl.packet.get_all_facts()}
    assert facts[0] not in ctrl_ids
    assert ctrl_ids == set(facts) - {facts[0]}


def test_build_control_rejects_unknown_drop_fact():
    s = _first_multi_fact_scenario()
    with pytest.raises(ValueError, match="not present"):
        build_positive_control_scenario(s, drop_fact_id="nope")
