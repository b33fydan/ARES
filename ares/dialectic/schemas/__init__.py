"""Schema module — frozen dataclasses for benchmark result persistence.

Holds immutable result types that cross the boundary between runners,
analysis tools, and persistence. Each schema is self-validating via
``__post_init__`` and provides explicit ``to_dict``/``from_dict`` helpers
so JSON round-trips are losslessly verifiable.
"""

from __future__ import annotations

from ares.dialectic.schemas.framing_benchmark_result import (
    FramingBenchmarkResult,
)

__all__ = ["FramingBenchmarkResult"]
