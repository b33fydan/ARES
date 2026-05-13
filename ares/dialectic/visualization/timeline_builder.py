"""Builds the timeline.json artifact from PinState objects."""

from __future__ import annotations

import json
from dataclasses import dataclass

from ares.dialectic.visualization.data_loader import DivergingLayer
from ares.dialectic.visualization.pin_mapper import PinState

# ---------------------------------------------------------------------------
# Animation timing constants (all values in milliseconds)
# ---------------------------------------------------------------------------
DEFAULT_STAGGER_MS: int = 400
DEFAULT_EMERGE_MS: int = 200
DEFAULT_PULSE_MS: int = 300
DEFAULT_SETTLE_MS: int = 600
DEFAULT_FINAL_HOLD_MS: int = 4000

# ---------------------------------------------------------------------------
# Grid constants
# ---------------------------------------------------------------------------
_GRID_COLS: int = 11
_GRID_ROWS: int = 9
_GRID_SPACING: float = 5.6


@dataclass(frozen=True)
class GridSpec:
    cols: int
    rows: int
    spacing_units: float


@dataclass(frozen=True)
class TimelinePin:
    col: int
    row: int
    depth_target: float
    brightness_target: float
    activation_ms: int
    diverging_layer: DivergingLayer


@dataclass(frozen=True)
class Timeline:
    version: str
    duration_ms: int
    grid: GridSpec
    pins: tuple[TimelinePin, ...]


def build_timeline(
    states: list[PinState],
    stagger_ms: int = DEFAULT_STAGGER_MS,
    emerge_ms: int = DEFAULT_EMERGE_MS,
    pulse_ms: int = DEFAULT_PULSE_MS,
    settle_ms: int = DEFAULT_SETTLE_MS,
    final_hold_ms: int = DEFAULT_FINAL_HOLD_MS,
) -> Timeline:
    """Sequence PinStates into an animation timeline.

    Each PinState becomes one TimelinePin whose activation_ms is determined
    by its activation_order multiplied by stagger_ms.  The total duration
    accounts for the last pin's activation plus the per-pin animation life
    (emerge + pulse + settle) and a final hold period.
    """
    pins: tuple[TimelinePin, ...] = tuple(
        TimelinePin(
            col=s.grid_col,
            row=s.grid_row,
            depth_target=s.depth_target,
            brightness_target=s.brightness_target,
            activation_ms=s.activation_order * stagger_ms,
            diverging_layer=s.first_diverging_layer,
        )
        for s in states
    )
    last_activation = max((p.activation_ms for p in pins), default=0)
    per_pin_life = emerge_ms + pulse_ms + settle_ms
    duration_ms = last_activation + per_pin_life + final_hold_ms
    return Timeline(
        version="1",
        duration_ms=duration_ms,
        grid=GridSpec(cols=_GRID_COLS, rows=_GRID_ROWS, spacing_units=_GRID_SPACING),
        pins=pins,
    )


def timeline_to_json(timeline: Timeline) -> str:
    """Serialize Timeline to deterministic JSON (sorted keys, 2-space indent)."""
    payload = {
        "version": timeline.version,
        "duration_ms": timeline.duration_ms,
        "grid": {
            "cols": timeline.grid.cols,
            "rows": timeline.grid.rows,
            "spacing_units": timeline.grid.spacing_units,
        },
        "pins": [
            {
                "col": p.col,
                "row": p.row,
                "depth_target": p.depth_target,
                "brightness_target": p.brightness_target,
                "activation_ms": p.activation_ms,
                "diverging_layer": p.diverging_layer,
            }
            for p in timeline.pins
        ],
    }
    return json.dumps(payload, indent=2, sort_keys=True)
