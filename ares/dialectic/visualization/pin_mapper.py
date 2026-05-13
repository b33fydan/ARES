"""Maps PairRecord -> PinState for the 11x9 pinscreen grid."""

from __future__ import annotations

from dataclasses import dataclass

from ares.dialectic.visualization.data_loader import DivergingLayer, PairRecord

GRID_COLS = 11
GRID_ROWS = 9


@dataclass(frozen=True)
class PinState:
    """One pin's final-state values, ready for the timeline."""

    grid_col: int          # 0..10
    grid_row: int          # 0..8
    depth_target: float    # 1.0 = held, 0.0 = drifted
    brightness_target: float  # 0.0..1.0, baseline confidence
    activation_order: int  # 0..98
    first_diverging_layer: DivergingLayer


def map_pairs_to_pins(pairs: list[PairRecord]) -> list[PinState]:
    """Deterministic transform from PairRecords to PinStates.

    Each pair becomes one pin. Grid fills left-to-right, top-to-bottom.
    Depth is binary (1.0 held, 0.0 drifted). Brightness is clamped confidence.
    """
    pins: list[PinState] = []
    for i, pair in enumerate(pairs):
        col = i % GRID_COLS
        row = i // GRID_COLS
        depth = 0.0 if pair.broad_leakage else 1.0
        brightness = max(0.0, min(1.0, pair.confidence_baseline))
        pins.append(
            PinState(
                grid_col=col,
                grid_row=row,
                depth_target=depth,
                brightness_target=brightness,
                activation_order=i,
                first_diverging_layer=pair.first_diverging_layer,
            )
        )
    return pins
