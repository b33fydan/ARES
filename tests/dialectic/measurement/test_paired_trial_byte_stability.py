"""Anchor test for the Paper 3 Finding 1 narrow byte-stability result.

Locks the 98/98 paired-trial byte-stability outcome against the
canonical Session 060 narrow leakage run on disk at::

    data/paper_3/leakage_runs/20260510-224622-154556/

This is the empirical leg of Paper 3 Finding 1 (Light Skeptic
byte-stability). The corresponding *source-level* anchor is at
``ares/dialectic/tests/agents/test_light_skeptic_anchor.py`` (the
``_ = architect_output`` discard at ``light_skeptic.py:185``); this
file's anchor verifies that the source discipline holds in practice
across 98 adversarial paired trials.

DO NOT modify this test to make a refactor pass. If the byte-stability
claim ever weakens, the published Paper 3 result is wrong; either
re-run the narrow characterization to update the canonical artifact or
revert the change.

Distinct from ``test_narrow_characterization_runner.py``, which tests
the runner's *plumbing* (config locks, no-halt-on-narrow-fire,
cost circuit-breaker). This file tests the runner's *output* against a
pinned on-disk fixture.
"""

from __future__ import annotations

import hashlib
import json
from collections import defaultdict
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[3]
CANONICAL_RUN_DIR = (
    REPO_ROOT / "data" / "paper_3" / "leakage_runs"
    / "20260510-224622-154556"
)
TRACES_PATH = CANONICAL_RUN_DIR / "traces.jsonl"
SHA256_PATH = CANONICAL_RUN_DIR / "traces.sha256"


# Locked outcomes from Session 060's narrow-extended run.
EXPECTED_TOTAL_CYCLES = 131  # 33 baselines + 98 mutated
EXPECTED_BASELINE_COUNT = 33  # one per scenario in injection_registry_v3
EXPECTED_MUTATED_COUNT = 98   # 33 + 33 + 32 per operator
EXPECTED_PAIR_COUNT = 98
EXPECTED_NARROW_FIRES = 0
EXPECTED_OPERATORS = frozenset({
    "framing_prefix_v1",
    "framing_suffix_v1",
    "synonym_substitution_conservative_v2",
})


# The four Light-Skeptic-relevant fields. Byte-stability under the
# Paper 3 narrow claim means these are tuple-equal between every
# (baseline, mutated) pair.
_LIGHT_SKEPTIC_FIELDS = (
    "skeptic_message_type",
    "skeptic_triggered_rules",
    "skeptic_confidence",
    "skeptic_cited_facts",
)


# =============================================================================
# Fixtures
# =============================================================================


@pytest.fixture(scope="module")
def raw_traces() -> list[dict]:
    return [
        json.loads(line)
        for line in TRACES_PATH.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


@pytest.fixture(scope="module")
def pairs(raw_traces) -> list[tuple[dict, dict]]:
    """Build (baseline, mutated) pairs keyed on scenario_id.

    Each scenario contributes one baseline (operator_name=None) and N
    mutated cycles (one per operator). Each (scenario_id, operator)
    becomes one pair.
    """
    baselines: dict[str, dict] = {}
    mutated: list[dict] = []
    for trace in raw_traces:
        if trace["pipeline"] != "light":
            continue
        if trace["is_baseline"]:
            baselines[trace["scenario_id"]] = trace
        else:
            mutated.append(trace)
    out: list[tuple[dict, dict]] = []
    for m in mutated:
        b = baselines.get(m["scenario_id"])
        if b is None:
            continue
        out.append((b, m))
    return out


def _light_skeptic_tuple(trace: dict) -> tuple:
    """Extract the four Light Skeptic output fields as a comparable
    tuple. ``skeptic_cited_facts`` and ``skeptic_triggered_rules`` are
    coerced to tuples for hashability and order-stable comparison."""
    return (
        trace["skeptic_message_type"],
        tuple(trace["skeptic_triggered_rules"]),
        trace["skeptic_confidence"],
        tuple(trace["skeptic_cited_facts"]),
    )


# =============================================================================
# Canonical-artifact integrity
# =============================================================================


class TestCanonicalArtifactIntegrity:
    """The pinned on-disk run is the source of truth for the
    narrow byte-stability claim. These tests catch any silent
    tampering with the file."""

    def test_traces_file_exists(self) -> None:
        assert TRACES_PATH.exists(), (
            f"Canonical narrow run missing at {TRACES_PATH}"
        )

    def test_sha256_manifest_exists(self) -> None:
        assert SHA256_PATH.exists(), (
            f"SHA256 manifest missing at {SHA256_PATH}"
        )

    def test_traces_match_recorded_sha256(self) -> None:
        recorded = SHA256_PATH.read_text(encoding="utf-8").strip().split()[0]
        h = hashlib.sha256(TRACES_PATH.read_bytes()).hexdigest()
        assert h == recorded, (
            f"Recorded sha256 {recorded} does not match recomputed "
            f"{h}. The canonical narrow leakage run has been "
            f"modified — re-run Session 060 or revert the change."
        )

    def test_total_cycle_count_locked(self, raw_traces) -> None:
        assert len(raw_traces) == EXPECTED_TOTAL_CYCLES


# =============================================================================
# Run-shape invariants
# =============================================================================


class TestRunShapeInvariants:
    def test_only_light_pipeline_is_present(self, raw_traces) -> None:
        """Session 060 ran the light pipeline only (cost ceiling $5,
        light-path invariant). Any other pipeline indicates wrong
        artifact."""
        pipelines = {t["pipeline"] for t in raw_traces}
        assert pipelines == {"light"}, (
            f"Expected only light pipeline; got {pipelines}"
        )

    def test_baseline_count_locked(self, raw_traces) -> None:
        baselines = [t for t in raw_traces if t["is_baseline"]]
        assert len(baselines) == EXPECTED_BASELINE_COUNT

    def test_mutated_count_locked(self, raw_traces) -> None:
        mutated = [t for t in raw_traces if not t["is_baseline"]]
        assert len(mutated) == EXPECTED_MUTATED_COUNT

    def test_operator_set_locked(self, raw_traces) -> None:
        operators = {
            t["operator_name"]
            for t in raw_traces
            if not t["is_baseline"]
        }
        assert operators == EXPECTED_OPERATORS

    def test_pair_count_is_98(self, pairs) -> None:
        assert len(pairs) == EXPECTED_PAIR_COUNT, (
            f"Expected {EXPECTED_PAIR_COUNT} pairs from the canonical "
            f"narrow run; built {len(pairs)}."
        )


# =============================================================================
# Byte-stability claim — the load-bearing assertions
# =============================================================================


class TestNarrowByteStability:
    """The Paper 3 Finding 1 lock: 98/98 paired trials have byte-equal
    Light Skeptic output between baseline and mutated."""

    def test_all_98_pairs_byte_stable(self, pairs) -> None:
        unstable: list[tuple[str, str, tuple, tuple]] = []
        for baseline, mutated in pairs:
            b_tuple = _light_skeptic_tuple(baseline)
            m_tuple = _light_skeptic_tuple(mutated)
            if b_tuple != m_tuple:
                unstable.append((
                    baseline["scenario_id"],
                    mutated["operator_name"],
                    b_tuple,
                    m_tuple,
                ))
        assert not unstable, (
            f"Narrow byte-stability claim failed on "
            f"{len(unstable)} of {EXPECTED_PAIR_COUNT} pairs: "
            f"{unstable[:3]}"
        )

    def test_narrow_fires_count_is_zero(self, pairs) -> None:
        narrow_fires = sum(
            1 for b, m in pairs
            if _light_skeptic_tuple(b) != _light_skeptic_tuple(m)
        )
        assert narrow_fires == EXPECTED_NARROW_FIRES, (
            f"Narrow-fires count {narrow_fires} != "
            f"{EXPECTED_NARROW_FIRES}. Paper 3 Finding 1 reports "
            f"101/0 across the full chain (98 here + 2 from Session "
            f"059 + 1 from Session 059 run 1)."
        )

    def test_skeptic_cited_facts_empty_across_run(self, raw_traces) -> None:
        """Side-anchor on the Light Skeptic primitive: with
        ``_ = architect_output`` in place, the deterministic Skeptic
        never cites facts. If skeptic_cited_facts is ever non-empty in
        the canonical artifact, the discard at light_skeptic.py:185
        has been undone or the rule engine has grown a citation
        side-channel."""
        non_empty = [
            (t["scenario_id"], t["operator_name"], t["skeptic_cited_facts"])
            for t in raw_traces
            if t["skeptic_cited_facts"]
        ]
        assert not non_empty, (
            "Light Skeptic emitted cited facts in the canonical "
            "narrow run — the discard primitive has regressed: "
            f"{non_empty[:3]}"
        )


# =============================================================================
# Per-operator decomposition (matches LEAKAGE_REPORT §2 per-bit table)
# =============================================================================


class TestPerOperatorDecomposition:
    """The narrow stability rate is unanimous across all three
    operators (33 + 33 + 32 = 98). The LEAKAGE_REPORT §2 cells for the
    light pipeline are all zero."""

    def test_framing_prefix_v1_pair_count(self, pairs) -> None:
        n = sum(1 for _, m in pairs if m["operator_name"] == "framing_prefix_v1")
        assert n == 33

    def test_framing_suffix_v1_pair_count(self, pairs) -> None:
        n = sum(1 for _, m in pairs if m["operator_name"] == "framing_suffix_v1")
        assert n == 33

    def test_synonym_substitution_conservative_v2_pair_count(
        self, pairs
    ) -> None:
        """v2 conservative synonym operator is a no-op on one
        scenario (per Session 058.5 audit), hence 32 not 33."""
        n = sum(
            1 for _, m in pairs
            if m["operator_name"] == "synonym_substitution_conservative_v2"
        )
        assert n == 32

    def test_each_operator_byte_stable_unanimously(self, pairs) -> None:
        by_operator: dict[str, list[bool]] = defaultdict(list)
        for baseline, mutated in pairs:
            stable = _light_skeptic_tuple(baseline) == _light_skeptic_tuple(mutated)
            by_operator[mutated["operator_name"]].append(stable)
        for op, results in by_operator.items():
            unstable = sum(1 for r in results if not r)
            assert unstable == 0, (
                f"Operator {op}: {unstable} of {len(results)} pairs "
                f"narrow-unstable (expected 0)"
            )
