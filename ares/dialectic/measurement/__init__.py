"""Phase 7 / Session 059 — InfluenceLeakage measurement package.

Houses the 4-bit leakage schema, the dual-path runner, and the report
renderer. Pre-registered values (weights, drift threshold, kill
direction, operator set) are locked at v1 and live as module-level
constants. Operator content stays in
``ares/dialectic/scripts/non_interference/`` (v1 + v2 mutators);
this package consumes them, never modifies them.
"""

from __future__ import annotations
