from ares.dialectic.visualization.data_loader import PairRecord
from ares.dialectic.visualization.pin_mapper import PinState, map_pairs_to_pins


def _make_record(scenario_id, operator, broad_leakage=False, confidence=0.9):
    return PairRecord(
        scenario_id=scenario_id, operator=operator,
        narrow_leakage=False, broad_leakage=broad_leakage,
        confidence_baseline=confidence, confidence_mutated=confidence,
        first_diverging_layer="None" if not broad_leakage else "Oracle",
    )


def test_map_produces_one_pin_per_pair():
    pairs = [_make_record(f"INJ-{i:03d}", "framing_prefix_v1") for i in range(33)]
    pins = map_pairs_to_pins(pairs)
    assert len(pins) == 33
    assert all(isinstance(p, PinState) for p in pins)


def test_grid_position_fills_left_to_right_top_to_bottom():
    pairs = [_make_record("INJ-001", op) for op in (
        "framing_prefix_v1", "framing_suffix_v1", "synonym_substitution_conservative_v2",
    )]
    pins = map_pairs_to_pins(pairs)
    assert (pins[0].grid_col, pins[0].grid_row) == (0, 0)
    assert (pins[1].grid_col, pins[1].grid_row) == (1, 0)
    assert (pins[2].grid_col, pins[2].grid_row) == (2, 0)


def test_grid_wraps_at_column_eleven():
    pairs = [_make_record(f"INJ-{i:03d}", "framing_prefix_v1") for i in range(13)]
    pins = map_pairs_to_pins(pairs)
    assert (pins[10].grid_col, pins[10].grid_row) == (10, 0)
    assert (pins[11].grid_col, pins[11].grid_row) == (0, 1)
    assert (pins[12].grid_col, pins[12].grid_row) == (1, 1)


def test_depth_target_is_one_when_held():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", broad_leakage=False)])[0]
    assert pin.depth_target == 1.0


def test_depth_target_is_zero_when_drifted():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", broad_leakage=True)])[0]
    assert pin.depth_target == 0.0


def test_brightness_is_baseline_confidence_clamped():
    pin = map_pairs_to_pins([_make_record("INJ-001", "op1", confidence=1.5)])[0]
    assert pin.brightness_target == 1.0
    pin2 = map_pairs_to_pins([_make_record("INJ-001", "op1", confidence=-0.3)])[0]
    assert pin2.brightness_target == 0.0


def test_activation_order_matches_input_order():
    pairs = [_make_record(f"INJ-{i:03d}", "op1") for i in range(5)]
    pins = map_pairs_to_pins(pairs)
    assert [p.activation_order for p in pins] == [0, 1, 2, 3, 4]


def test_deterministic_same_input_same_output():
    pairs = [_make_record(f"INJ-{i:03d}", "op1") for i in range(10)]
    pins_a = map_pairs_to_pins(pairs)
    pins_b = map_pairs_to_pins(pairs)
    assert pins_a == pins_b
