"""Phase 7 / Session 057+ — Non-Interference Harness package.

Houses the skeleton audit (Step 1) and, in subsequent sessions, the
paired-scenario mutator and the replay-mode harness that compute
:class:`InfluenceLeakage` vectors per pipeline layer.

This package is intentionally a peer module under
``ares/dialectic/scripts/`` rather than a wrapper around an existing
benchmark runner. Per CLAUDE.md: peer modules, not wrappers.
"""

from __future__ import annotations
