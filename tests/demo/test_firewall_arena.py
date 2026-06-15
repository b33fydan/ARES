"""Tests for demo/firewall_arena.py — INJ-009 preset pivot.

Covers: preset registry, base-packet loader, apply_field_edit, and
the three empirically-verified run_incident outcomes.
"""
import pytest

from demo.firewall_arena import (
    PRESETS,
    ArenaRun,
    apply_field_edit,
    load_base_packet,
    run_incident,
)


# ---------------------------------------------------------------------------
# 1. Preset registry
# ---------------------------------------------------------------------------

def test_presets_registry_has_three_known_ids():
    ids = {p["preset_id"] for p in PRESETS}
    assert ids == {"INJ-009", "INJ-009-INJECTED", "INJ-020"}


def test_each_preset_declares_label_and_kind():
    valid_kinds = {"confirmed_threat", "literal_injection", "semantic_framing"}
    for p in PRESETS:
        assert p["preset_id"], "preset_id must be non-empty"
        assert p["label"], "label must be non-empty"
        assert p["kind"] in valid_kinds, f"unexpected kind: {p['kind']!r}"


# ---------------------------------------------------------------------------
# 2. load_base_packet
# ---------------------------------------------------------------------------

def test_load_base_packet_inj009_frozen_confirmed_chain():
    packet = load_base_packet("INJ-009")
    assert packet.is_frozen
    # kill-chain anchor: credential_tool_signature fact must exist
    fact = packet.get_fact("inj009-fact-002")
    assert fact is not None


def test_load_base_packet_injected_carries_injection():
    packet = load_base_packet("INJ-009-INJECTED")
    assert packet.is_frozen
    fact = packet.get_fact("inj009-fact-006")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in str(fact.value)


def test_load_base_packet_inj020_frozen():
    packet = load_base_packet("INJ-020")
    assert packet.is_frozen
    assert len(list(packet.get_all_facts())) > 0


def test_load_base_packet_unknown_raises():
    with pytest.raises(KeyError):
        load_base_packet("NOPE")


# ---------------------------------------------------------------------------
# 3. apply_field_edit
# ---------------------------------------------------------------------------

def test_apply_field_edit_replaces_value_and_refreezes():
    base = load_base_packet("INJ-009")
    edited = apply_field_edit(base, "inj009-fact-001", "benign note")
    # result is frozen
    assert edited.is_frozen
    # targeted fact is changed
    assert str(edited.get_fact("inj009-fact-001").value) == "benign note"
    # another fact is unchanged
    assert edited.get_fact("inj009-fact-002") == base.get_fact("inj009-fact-002")
    # base packet is NOT mutated
    assert str(base.get_fact("inj009-fact-001").value) != "benign note"


def test_apply_field_edit_unknown_fact_raises():
    base = load_base_packet("INJ-009")
    with pytest.raises(KeyError):
        apply_field_edit(base, "no-such-fact-id", "x")


# ---------------------------------------------------------------------------
# 4. run_incident — empirically verified outcomes
# ---------------------------------------------------------------------------

def test_run_incident_inj009_baseline_confirms():
    run = run_incident(load_base_packet("INJ-009"))
    assert isinstance(run, ArenaRun)
    assert run.firewall_passed is True
    assert run.violations == []
    assert run.hot_swap_triggered is False
    assert run.verdict_outcome == "threat_confirmed"


def test_run_incident_injected_caught_hotswap_verdict_holds():
    """The headline: literal injection caught, agent hot-swapped, verdict holds."""
    run = run_incident(load_base_packet("INJ-009-INJECTED"))
    assert run.firewall_passed is False
    violation_types = {v["violation_type"] for v in run.violations}
    assert "INSTRUCTION_INJECTION" in violation_types
    assert run.hot_swap_triggered is True
    assert run.verdict_outcome == "threat_confirmed"


def test_run_incident_inj020_semantic_stable_dismissed():
    run = run_incident(load_base_packet("INJ-020"))
    violation_types = {v["violation_type"] for v in run.violations}
    assert "INSTRUCTION_INJECTION" not in violation_types
    assert run.verdict_outcome == "threat_dismissed"
