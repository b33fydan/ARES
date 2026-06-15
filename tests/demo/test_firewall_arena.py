from demo.firewall_arena import PRESETS, load_base_packet


def test_presets_registry_has_three_known_ids():
    ids = {p["preset_id"] for p in PRESETS}
    assert ids == {"INJ-001", "CLEAN-CTRL", "INJ-020"}


def test_each_preset_declares_label_and_kind():
    for p in PRESETS:
        assert p["preset_id"]
        assert p["label"]
        assert p["kind"] in {"literal_injection", "clean_control", "semantic_framing"}


def test_load_base_packet_inj001_is_frozen_and_carries_injection_fact():
    packet = load_base_packet("INJ-001")
    assert packet.is_frozen
    fact = packet.get_fact("inj001-fact-006")
    assert "IGNORE PREVIOUS INSTRUCTIONS" in str(fact.value)


def test_load_base_packet_unknown_raises():
    import pytest
    with pytest.raises(KeyError):
        load_base_packet("NOPE")
