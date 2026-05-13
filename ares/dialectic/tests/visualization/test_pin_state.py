from dataclasses import FrozenInstanceError

import pytest
from ares.dialectic.visualization.pin_mapper import PinState


def test_pin_state_is_frozen():
    pin = PinState(
        grid_col=0, grid_row=0,
        depth_target=1.0, brightness_target=0.78,
        activation_order=0, first_diverging_layer="None",
    )
    with pytest.raises(FrozenInstanceError):
        pin.grid_col = 1


def test_pin_state_grid_bounds():
    """grid_col is 0..10 and grid_row is 0..8 for an 11x9 grid."""
    pin = PinState(grid_col=10, grid_row=8,
                   depth_target=0.0, brightness_target=0.0,
                   activation_order=98, first_diverging_layer="Architect")
    assert pin.grid_col == 10
    assert pin.grid_row == 8


def test_pin_state_depth_is_binary_zero_or_one():
    """Per spec, depth_target is 0.0 (drifted) or 1.0 (held)."""
    for depth in (0.0, 1.0):
        pin = PinState(grid_col=0, grid_row=0,
                       depth_target=depth, brightness_target=0.5,
                       activation_order=0, first_diverging_layer="None")
        assert pin.depth_target == depth
