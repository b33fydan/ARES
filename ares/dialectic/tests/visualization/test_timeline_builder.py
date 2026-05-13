import json
from ares.dialectic.visualization.pin_mapper import PinState
from ares.dialectic.visualization.timeline_builder import (
    Timeline, GridSpec, TimelinePin,
    build_timeline, timeline_to_json,
    DEFAULT_STAGGER_MS, DEFAULT_FINAL_HOLD_MS,
)


def _make_pin(i, held=True):
    return PinState(
        grid_col=i % 11, grid_row=i // 11,
        depth_target=1.0 if held else 0.0,
        brightness_target=0.9,
        activation_order=i,
        first_diverging_layer="None" if held else "Oracle",
    )


def test_build_timeline_produces_one_pin_per_state():
    states = [_make_pin(i) for i in range(99)]
    timeline = build_timeline(states)
    assert len(timeline.pins) == 99


def test_activation_ms_uses_stagger():
    states = [_make_pin(i) for i in range(5)]
    timeline = build_timeline(states)
    expected = [0, DEFAULT_STAGGER_MS, 2 * DEFAULT_STAGGER_MS,
                3 * DEFAULT_STAGGER_MS, 4 * DEFAULT_STAGGER_MS]
    assert [p.activation_ms for p in timeline.pins] == expected


def test_duration_ms_accounts_for_full_sweep_plus_hold():
    states = [_make_pin(i) for i in range(99)]
    timeline = build_timeline(states)
    last_activation = 98 * DEFAULT_STAGGER_MS
    per_pin_life = 200 + 300 + 600  # emerge + pulse + settle
    assert timeline.duration_ms == last_activation + per_pin_life + DEFAULT_FINAL_HOLD_MS


def test_grid_spec_matches_spec_values():
    timeline = build_timeline([_make_pin(0)])
    assert timeline.grid.cols == 11
    assert timeline.grid.rows == 9
    assert timeline.grid.spacing_units == 5.6


def test_timeline_to_json_round_trip():
    timeline = build_timeline([_make_pin(0), _make_pin(1, held=False)])
    json_str = timeline_to_json(timeline)
    parsed = json.loads(json_str)
    assert parsed["version"] == "1"
    assert parsed["grid"]["cols"] == 11
    assert len(parsed["pins"]) == 2
    assert parsed["pins"][0]["depth_target"] == 1.0
    assert parsed["pins"][1]["depth_target"] == 0.0


def test_deterministic_same_input_same_json():
    states = [_make_pin(i) for i in range(20)]
    json_a = timeline_to_json(build_timeline(states))
    json_b = timeline_to_json(build_timeline(states))
    assert json_a == json_b
