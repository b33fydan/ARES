# tests/dialectic/measurement/test_read_depth_corpus.py
"""Tests for Adaptive Corpus C structure + controls."""
from __future__ import annotations

from ares.dialectic.agents.light_skeptic_v2_lexical import (
    evaluate as lexical_evaluate,
)
from ares.dialectic.agents.light_skeptic_v2_structured import (
    evaluate as structured_evaluate,
)
from ares.dialectic.coordinator.firewall import _AUTHORIZATION_FACT_FIELDS
from ares.dialectic.measurement.read_depth_corpus import (
    ALL_ENTRIES,
    BENIGN_ENTRIES,
    MALIGN_ENTRIES,
    get_entry,
    inject_authorization,
)
from ares.dialectic.messages.protocol import MessageBuilder, MessageType, Phase


def _arch():
    b = MessageBuilder(source_agent="a", packet_id="t", cycle_id="c")
    b.set_phase(Phase.THESIS).set_type(MessageType.HYPOTHESIS).set_confidence(0.5)
    return b.build()


def test_counts_and_labels():
    assert len(MALIGN_ENTRIES) == 4
    assert len(BENIGN_ENTRIES) == 4
    assert len(ALL_ENTRIES) == 8
    assert all(e.is_malign for e in MALIGN_ENTRIES)
    assert all(not e.is_malign for e in BENIGN_ENTRIES)


def test_unique_scenario_ids_and_fact_prefixes():
    ids = [e.scenario.metadata.scenario_id for e in ALL_ENTRIES]
    assert len(set(ids)) == len(ids)


def test_struct_twin_shares_field_skeleton_with_malign_twin():
    # B-struct-twin must have the same field multiset as its M-lex twin, so
    # the value-blind tier 1 cannot distinguish them.
    twin = get_entry("RDF-B-TWIN-001")
    base = get_entry(twin.twin_id)
    twin_fields = sorted(f.field for f in twin.scenario.packet.get_all_facts())
    base_fields = sorted(f.field for f in base.scenario.packet.get_all_facts())
    assert twin_fields == base_fields


def test_tier1_cannot_distinguish_struct_twin():
    # The load-bearing FP control: tier 1 fires malign on BOTH the malign
    # scenario and its benign structural twin.
    twin = get_entry("RDF-B-TWIN-001")
    base = get_entry(twin.twin_id)
    assert structured_evaluate(base.scenario.packet, _arch()).malign_score > 0
    assert structured_evaluate(twin.scenario.packet, _arch()).malign_score > 0
    # ...while tier 2 correctly passes the benign twin.
    assert lexical_evaluate(twin.scenario.packet, _arch()).malign_score == 0


def test_inject_authorization_adds_auth_fact_and_flips_tier1():
    base = get_entry("RDF-M-LEX-001")
    controlled = inject_authorization(base.scenario)
    fields = {f.field for f in controlled.packet.get_all_facts()}
    assert fields & _AUTHORIZATION_FACT_FIELDS  # an auth fact was added
    # tier 1 swings benign (structural rule suppressed by the auth fact)...
    assert structured_evaluate(base.scenario.packet, _arch()).malign_score > 0
    assert structured_evaluate(controlled.packet, _arch()).malign_score == 0
    # ...but tier 2 stays malign (the threat value is still present).
    assert lexical_evaluate(controlled.packet, _arch()).malign_score > 0


def test_carryforward_benign_trips_tier2():
    # Carry-forward #1: a benign .js under /users/public/ is a tier-2 FP.
    carry = get_entry("RDF-B-CARRY-001")
    assert carry.is_malign is False
    assert lexical_evaluate(carry.scenario.packet, _arch()).malign_score > 0


def test_clean_benign_passes_all_tiers():
    clean = get_entry("RDF-B-CLEAN-001")
    assert structured_evaluate(clean.scenario.packet, _arch()).malign_score == 0
    assert lexical_evaluate(clean.scenario.packet, _arch()).malign_score == 0
