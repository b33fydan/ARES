from dataclasses import FrozenInstanceError

import pytest
from ares.dialectic.visualization.timeline_builder import Timeline, TimelinePin, GridSpec


def test_timeline_is_frozen():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    timeline = Timeline(version="1", duration_ms=45000, grid=grid, pins=())
    with pytest.raises(FrozenInstanceError):
        timeline.duration_ms = 50000


def test_timeline_pins_is_immutable_tuple():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    pin = TimelinePin(col=0, row=0, depth_target=1.0,
                      brightness_target=0.8, activation_ms=0,
                      diverging_layer="None")
    timeline = Timeline(version="1", duration_ms=45000, grid=grid, pins=(pin,))
    assert isinstance(timeline.pins, tuple)


def test_grid_spec_is_frozen():
    grid = GridSpec(cols=11, rows=9, spacing_units=5.6)
    with pytest.raises(FrozenInstanceError):
        grid.cols = 10
