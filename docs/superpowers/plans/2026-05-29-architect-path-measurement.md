# Architect-Path Framing-Sensitivity Measurement — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a controlled, offline-testable measurement that isolates how much of the Architect's framing-induced cited-fact divergence exceeds the LLM's own sampling noise floor, on Sonnet 4.6, via repeated-baseline resampling — with a positive control.

**Architecture:** Pure, fully-unit-tested core (Jaccard metrics, permutation/bootstrap stats, S059 scenario selection, positive-control packet construction, frozen schema) + a thin runner that reuses the existing `_run_one_cycle(pipeline="llm")` from `leakage_runner.py` as the resample primitive (apples-to-apples with the 60–78% figure), gated by a cost-ceiling preflight + anchor test. New files only; no existing file is modified. The runner accepts an injectable `cycle_fn` so the orchestration is testable with zero API calls.

**Tech Stack:** Python 3.11, stdlib only (`statistics`, `random`, `json`, `dataclasses`, `pathlib`) — no scipy/numpy. `pytest`. Reuses ARES `leakage_runner`, `paired_scenario_mutator`, `injection_registry_v3`, `EvidencePacket`, `light_skeptic` stage map.

**Spec:** `docs/superpowers/specs/2026-05-29-architect-path-measurement-design.md`

**Branch:** `session/077-architect-framing-measurement` (already created). Commit per task; squash-merge after zero regressions.

---

## File Structure

| File | Responsibility |
|---|---|
| `ares/dialectic/measurement/architect_framing_schema.py` | Frozen dataclasses: `ArchitectFramingConfig`, `ResampleRecord`, `OperatorFramingResult`, `ScenarioFramingResult`, `ArchitectFramingSummary`; condition helpers; constants. |
| `ares/dialectic/measurement/architect_framing_metrics.py` | Pure metric/stats functions: `jaccard_distance`, `within_distances`, `cross_distances`, `permutation_pvalue`, `bootstrap_ci_median_diff`, `classify_operator`. |
| `ares/dialectic/measurement/architect_framing_selection.py` | `select_diverging_scenarios(traces_path)` — parse S059 traces.jsonl, return scenario IDs whose Architect cited-facts diverged under mutation. |
| `ares/dialectic/measurement/architect_framing_control.py` | `highest_stage_fact_id(packet)`, `build_positive_control_scenario(baseline)` — drop the top kill-chain-stage fact. |
| `ares/dialectic/measurement/architect_framing_runner.py` | `run_preflight`, `run_measurement` — orchestrate resampling via injectable `cycle_fn` (default `_run_one_cycle`), accumulate cost, compute results, persist traces. |
| `ares/dialectic/measurement/architect_framing_report.py` | `write_report(summary)` — markdown renderer. |
| `scripts/run_session_077.py` | CLI mirroring `run_session_075.py` (`_load_env`, preflight → `--confirm-live` gate, cost-ceiling guard, anchor guard). |
| `tests/dialectic/measurement/test_architect_framing_*.py` | One test module per source file (deterministic parts; live path behind `@pytest.mark.live_llm`). |

**Reused symbols (verified):**
- `leakage_runner`: `_run_one_cycle(*, scenario, pipeline, client, cycle_id, pair_index, is_baseline, operator_name) -> (CycleTrace, float)`, `_resolve_operator(name) -> MutationOperator`, `PRE_REGISTERED_OPERATOR_NAMES`, `DEFAULT_MODEL = "claude-sonnet-4-20250514"`, `DEFAULT_TRACES_ROOT`, `CycleTrace`, `anchor_test_passes()`.
- `CycleTrace` fields used: `architect_cited_facts: tuple[str,...]`, `architect_confidence: float`, `final_outcome: str`, `oracle_supporting_facts: tuple[str,...]`, `cost_usd: float`, `elapsed_ms: float`.
- `client_factory`: `make_client(provider, model=None)`, `VALID_PROVIDERS`, `PROVIDER_DEFAULTS`, `AnyLLMClient`.
- `injection_registry_v3.build_registry_v3()` → `.all_scenarios()` → `BenchmarkScenario(metadata=ScenarioMetadata(scenario_id, ...), packet=EvidencePacket)`.
- `paired_scenario_mutator`: `PairedScenarioMutator(operators)`, `.mutate(baseline_scenario, operator_name) -> MutatedScenarioPair` (raises `SkeletonInvariantError` on no-op); `MutatedScenarioPair.mutated_scenario`.
- `EvidencePacket(packet_id, time_window)`, `.add_fact(fact)`, `.get_all_facts() -> List[Fact]`, `.freeze() -> str`, public attrs `.packet_id`, `.time_window`.
- `light_skeptic._STAGE_MAP: dict[str,int]`, `light_skeptic._DEFAULT_STAGE = 2`.

---

### Task 1: Schema dataclasses

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_schema.py`
- Test: `tests/dialectic/measurement/test_architect_framing_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_schema.py
import pytest
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, framing_condition, CONDITION_BASELINE, CONDITION_CONTROL,
    ARCHITECT_FRAMING_HARD_CEILING_USD,
)
from ares.dialectic.measurement.leakage_runner import PRE_REGISTERED_OPERATOR_NAMES


def test_defaults_are_pre_registered():
    cfg = ArchitectFramingConfig(s059_traces_path="x")
    assert cfg.operator_names == PRE_REGISTERED_OPERATOR_NAMES
    assert cfg.k_resamples == 8
    assert cfg.provider == "anthropic"

def test_condition_helpers():
    assert framing_condition("framing_prefix_v1") == "framing:framing_prefix_v1"
    assert CONDITION_BASELINE == "baseline"
    assert CONDITION_CONTROL == "control"

def test_k_resamples_must_be_at_least_two():
    with pytest.raises(ValueError, match="k_resamples"):
        ArchitectFramingConfig(s059_traces_path="x", k_resamples=1)

def test_cost_ceiling_hard_capped():
    with pytest.raises(ValueError, match="cost_ceiling"):
        ArchitectFramingConfig(s059_traces_path="x",
                               cost_ceiling_usd=ARCHITECT_FRAMING_HARD_CEILING_USD + 1)

def test_invalid_provider_rejected():
    with pytest.raises(ValueError, match="provider"):
        ArchitectFramingConfig(s059_traces_path="x", provider="bogus")
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_schema.py -q`
Expected: FAIL with `ModuleNotFoundError: ...architect_framing_schema`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_schema.py
"""Frozen schema for the Architect-path framing-sensitivity measurement (Session 077)."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ares.dialectic.agents.strategies.client_factory import VALID_PROVIDERS
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_MODEL, DEFAULT_TRACES_ROOT, PRE_REGISTERED_OPERATOR_NAMES,
)

CONDITION_BASELINE: str = "baseline"
CONDITION_CONTROL: str = "control"
ARCHITECT_FRAMING_HARD_CEILING_USD: float = 8.0  # tighter than leakage runner's 20.0

VERDICT_REAL: str = "framing_channel_real"
VERDICT_NOISE: str = "within_noise"
VERDICT_INCONCLUSIVE: str = "inconclusive"


def framing_condition(operator_name: str) -> str:
    return f"framing:{operator_name}"


@dataclass(frozen=True)
class ArchitectFramingConfig:
    s059_traces_path: Path
    scenario_ids: tuple[str, ...] = ()          # () => auto-select from S059 traces
    k_resamples: int = 8
    max_scenarios: int = 6                       # budget guard; no silent truncation (logged)
    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    model: str = DEFAULT_MODEL
    provider: str = "anthropic"
    cost_ceiling_usd: float = 6.0
    traces_root: Path = DEFAULT_TRACES_ROOT
    seed: int = 0

    def __post_init__(self) -> None:
        if self.k_resamples < 2:
            raise ValueError(f"k_resamples must be >= 2, got {self.k_resamples}")
        if not self.operator_names:
            raise ValueError("operator_names must be non-empty")
        if self.provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")
        if self.cost_ceiling_usd > ARCHITECT_FRAMING_HARD_CEILING_USD:
            raise ValueError(
                f"cost_ceiling_usd {self.cost_ceiling_usd} exceeds hard cap "
                f"{ARCHITECT_FRAMING_HARD_CEILING_USD}"
            )


@dataclass(frozen=True)
class ResampleRecord:
    scenario_id: str
    condition: str                       # baseline | framing:<op> | control
    resample_index: int
    architect_cited_facts: tuple[str, ...]
    architect_confidence: float
    final_outcome: str
    oracle_supporting_facts: tuple[str, ...]
    cost_usd: float
    elapsed_ms: float

    def to_dict(self) -> dict:
        return {
            "scenario_id": self.scenario_id,
            "condition": self.condition,
            "resample_index": self.resample_index,
            "architect_cited_facts": list(self.architect_cited_facts),
            "architect_confidence": self.architect_confidence,
            "final_outcome": self.final_outcome,
            "oracle_supporting_facts": list(self.oracle_supporting_facts),
            "cost_usd": self.cost_usd,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class OperatorFramingResult:
    operator_name: str
    n_cross: int
    cross_median: float
    within_median: float
    effect_size: float                   # cross_median - within_median
    p_value: float
    ci_low: float
    ci_high: float
    verdict: str                         # VERDICT_REAL | VERDICT_NOISE | VERDICT_INCONCLUSIVE


@dataclass(frozen=True)
class ScenarioFramingResult:
    scenario_id: str
    within_distances: tuple[float, ...]
    control_distances: tuple[float, ...]
    control_exceeds_noise: bool
    operator_results: tuple[OperatorFramingResult, ...]
    skipped_operators: tuple[str, ...] = field(default_factory=tuple)  # no-op mutations


@dataclass(frozen=True)
class ArchitectFramingSummary:
    run_id: str
    timestamp_iso: str
    git_sha: str
    provider: str
    model: str
    k_resamples: int
    operator_names: tuple[str, ...]
    scenario_results: tuple[ScenarioFramingResult, ...]
    deferred_scenario_ids: tuple[str, ...]   # selected but not run (budget) — logged, not silent
    control_valid: bool
    total_cost_usd: float
    halt_reason: str
    traces_path: str
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_schema.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_schema.py tests/dialectic/measurement/test_architect_framing_schema.py
git commit -m "feat(s077): architect-framing measurement schema

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: Jaccard + distance partitioning

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_metrics.py`
- Test: `tests/dialectic/measurement/test_architect_framing_metrics.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_metrics.py
from ares.dialectic.measurement.architect_framing_metrics import (
    jaccard_distance, within_distances, cross_distances,
)

def test_jaccard_identical_is_zero():
    assert jaccard_distance(frozenset({"a", "b"}), frozenset({"a", "b"})) == 0.0

def test_jaccard_disjoint_is_one():
    assert jaccard_distance(frozenset({"a"}), frozenset({"b"})) == 1.0

def test_jaccard_both_empty_is_zero():
    assert jaccard_distance(frozenset(), frozenset()) == 0.0

def test_jaccard_half():
    # {a,b} vs {a,c}: intersection 1, union 3 -> 1 - 1/3
    assert abs(jaccard_distance(frozenset({"a","b"}), frozenset({"a","c"})) - (2/3)) < 1e-9

def test_within_distances_count():
    sets = [frozenset({"a"}), frozenset({"a"}), frozenset({"b"})]
    d = within_distances(sets)
    assert len(d) == 3            # C(3,2)
    assert sorted(d) == [0.0, 1.0, 1.0]

def test_cross_distances_count():
    base = [frozenset({"a"}), frozenset({"a"})]
    mut = [frozenset({"b"}), frozenset({"b"}), frozenset({"b"})]
    d = cross_distances(base, mut)
    assert len(d) == 6            # 2 x 3
    assert all(x == 1.0 for x in d)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_metrics.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_metrics.py
"""Pure metric + stats functions for the Architect-path framing measurement.

Stdlib only. No LLM. No I/O. Fully deterministic given inputs (+ seed for bootstrap/perm).
"""
from __future__ import annotations

import random
from statistics import median
from typing import Sequence


def jaccard_distance(a: frozenset[str], b: frozenset[str]) -> float:
    union = a | b
    if not union:
        return 0.0
    return 1.0 - len(a & b) / len(union)


def within_distances(sets: Sequence[frozenset[str]]) -> list[float]:
    """All pairwise Jaccard distances among the resample sets (the noise floor)."""
    n = len(sets)
    return [
        jaccard_distance(sets[i], sets[j])
        for i in range(n) for j in range(i + 1, n)
    ]


def cross_distances(
    baseline_sets: Sequence[frozenset[str]],
    mutated_sets: Sequence[frozenset[str]],
) -> list[float]:
    """All baseline x mutated Jaccard distances."""
    return [jaccard_distance(b, m) for b in baseline_sets for m in mutated_sets]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_metrics.py -q`
Expected: PASS (6 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_metrics.py tests/dialectic/measurement/test_architect_framing_metrics.py
git commit -m "feat(s077): jaccard + distance partitioning metrics

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: Permutation test, bootstrap CI, operator classification

**Files:**
- Modify: `ares/dialectic/measurement/architect_framing_metrics.py` (append functions)
- Test: `tests/dialectic/measurement/test_architect_framing_metrics.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/dialectic/measurement/test_architect_framing_metrics.py
from ares.dialectic.measurement.architect_framing_metrics import (
    permutation_pvalue, bootstrap_ci_median_diff, classify_operator,
)
from ares.dialectic.measurement.architect_framing_schema import (
    VERDICT_REAL, VERDICT_NOISE, VERDICT_INCONCLUSIVE,
)

def test_permutation_pvalue_clear_separation_is_small():
    within = [0.0] * 10
    cross = [1.0] * 10
    p = permutation_pvalue(cross, within, n_perm=500, seed=0)
    assert p < 0.05

def test_permutation_pvalue_identical_is_large():
    within = [0.2, 0.3, 0.25, 0.2]
    cross = [0.2, 0.3, 0.25, 0.2]
    p = permutation_pvalue(cross, within, n_perm=500, seed=0)
    assert p > 0.2

def test_bootstrap_ci_brackets_positive_effect():
    within = [0.0] * 8
    cross = [1.0] * 8
    lo, hi = bootstrap_ci_median_diff(cross, within, n_boot=500, seed=0)
    assert lo > 0.0 and hi > 0.0

def test_classify_real_when_significant_and_positive():
    within = [0.0] * 10
    cross = [1.0] * 10
    v = classify_operator(cross, within, n_perm=300, n_boot=300, seed=0)
    assert v.verdict == VERDICT_REAL
    assert v.effect_size > 0.0

def test_classify_noise_when_no_separation():
    within = [0.3, 0.3, 0.3, 0.3]
    cross = [0.3, 0.3, 0.3, 0.3]
    v = classify_operator(cross, within, n_perm=300, n_boot=300, seed=0)
    assert v.verdict in (VERDICT_NOISE, VERDICT_INCONCLUSIVE)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_metrics.py -q`
Expected: FAIL with `ImportError: cannot import name 'permutation_pvalue'`.

- [ ] **Step 3: Write minimal implementation (append to metrics module)**

```python
# append to ares/dialectic/measurement/architect_framing_metrics.py
from ares.dialectic.measurement.architect_framing_schema import (
    OperatorFramingResult, VERDICT_REAL, VERDICT_NOISE, VERDICT_INCONCLUSIVE,
)

_P_THRESHOLD = 0.05


def permutation_pvalue(
    cross: Sequence[float], within: Sequence[float], *, n_perm: int = 2000, seed: int = 0
) -> float:
    """Two-sided permutation test on the difference of medians (cross - within)."""
    if not cross or not within:
        return 1.0
    observed = abs(median(cross) - median(within))
    pool = list(cross) + list(within)
    n_cross = len(cross)
    rng = random.Random(seed)
    hits = 0
    for _ in range(n_perm):
        rng.shuffle(pool)
        diff = abs(median(pool[:n_cross]) - median(pool[n_cross:]))
        if diff >= observed - 1e-12:
            hits += 1
    return hits / n_perm


def bootstrap_ci_median_diff(
    cross: Sequence[float], within: Sequence[float],
    *, n_boot: int = 2000, seed: int = 0, alpha: float = 0.05,
) -> tuple[float, float]:
    """Percentile bootstrap CI for median(cross) - median(within)."""
    if not cross or not within:
        return (0.0, 0.0)
    rng = random.Random(seed)
    cross = list(cross)
    within = list(within)
    diffs = []
    for _ in range(n_boot):
        bc = [rng.choice(cross) for _ in cross]
        bw = [rng.choice(within) for _ in within]
        diffs.append(median(bc) - median(bw))
    diffs.sort()
    lo_i = int((alpha / 2) * n_boot)
    hi_i = min(n_boot - 1, int((1 - alpha / 2) * n_boot))
    return (diffs[lo_i], diffs[hi_i])


def classify_operator(
    cross: Sequence[float], within: Sequence[float],
    *, n_perm: int = 2000, n_boot: int = 2000, seed: int = 0,
    operator_name: str = "",
) -> OperatorFramingResult:
    """Decide whether framing exceeds the noise floor for one operator."""
    cm = median(cross) if cross else 0.0
    wm = median(within) if within else 0.0
    effect = cm - wm
    p = permutation_pvalue(cross, within, n_perm=n_perm, seed=seed)
    lo, hi = bootstrap_ci_median_diff(cross, within, n_boot=n_boot, seed=seed)
    if p < _P_THRESHOLD and effect > 0.0 and lo > 0.0:
        verdict = VERDICT_REAL
    elif p >= _P_THRESHOLD and hi <= 0.0:
        verdict = VERDICT_NOISE
    elif p >= _P_THRESHOLD and effect <= 0.0:
        verdict = VERDICT_NOISE
    else:
        verdict = VERDICT_INCONCLUSIVE
    return OperatorFramingResult(
        operator_name=operator_name, n_cross=len(cross),
        cross_median=cm, within_median=wm, effect_size=effect,
        p_value=p, ci_low=lo, ci_high=hi, verdict=verdict,
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_metrics.py -q`
Expected: PASS (11 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_metrics.py tests/dialectic/measurement/test_architect_framing_metrics.py
git commit -m "feat(s077): permutation test + bootstrap CI + operator classification

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Scenario selection from S059 traces

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_selection.py`
- Test: `tests/dialectic/measurement/test_architect_framing_selection.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_selection.py
import json
from pathlib import Path
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios


def _write(tmp_path, rows):
    p = tmp_path / "traces.jsonl"
    p.write_text("\n".join(json.dumps(r) for r in rows), encoding="utf-8")
    return p

def test_selects_only_llm_scenarios_that_diverged(tmp_path):
    rows = [
        # INJ-001 diverges on llm path
        {"pipeline": "llm", "scenario_id": "INJ-001", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["f1", "f2"]},
        {"pipeline": "llm", "scenario_id": "INJ-001", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["f1"]},
        # INJ-002 stable on llm path
        {"pipeline": "llm", "scenario_id": "INJ-002", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["a"]},
        {"pipeline": "llm", "scenario_id": "INJ-002", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["a"]},
        # light-path divergence must be IGNORED
        {"pipeline": "light", "scenario_id": "INJ-003", "is_baseline": True,
         "operator_name": None, "architect_cited_facts": ["x"]},
        {"pipeline": "light", "scenario_id": "INJ-003", "is_baseline": False,
         "operator_name": "framing_prefix_v1", "architect_cited_facts": ["y"]},
    ]
    p = _write(tmp_path, rows)
    assert select_diverging_scenarios(p) == ["INJ-001"]

def test_missing_file_returns_empty(tmp_path):
    assert select_diverging_scenarios(tmp_path / "nope.jsonl") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_selection.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_selection.py
"""Select pilot scenarios: those whose Architect cited-facts diverged under
mutation on the LLM path in a prior leakage run (e.g. S059 Sonnet traces)."""
from __future__ import annotations

import json
from pathlib import Path


def select_diverging_scenarios(traces_path: Path | str) -> list[str]:
    path = Path(traces_path)
    if not path.exists():
        return []

    baseline: dict[str, frozenset[str]] = {}
    mutated: dict[str, list[frozenset[str]]] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        r = json.loads(line)
        if r.get("pipeline") != "llm":
            continue
        sid = r["scenario_id"]
        cited = frozenset(r.get("architect_cited_facts") or [])
        if r.get("is_baseline"):
            baseline[sid] = cited
        else:
            mutated.setdefault(sid, []).append(cited)

    diverged = []
    for sid, base in baseline.items():
        if any(m != base for m in mutated.get(sid, [])):
            diverged.append(sid)
    return sorted(diverged)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_selection.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_selection.py tests/dialectic/measurement/test_architect_framing_selection.py
git commit -m "feat(s077): S059-trace scenario selection (LLM-path divergence)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Positive-control packet construction

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_control.py`
- Test: `tests/dialectic/measurement/test_architect_framing_control.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_control.py
import pytest
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.measurement.architect_framing_control import (
    highest_stage_fact_id, build_positive_control_scenario,
)

def _first_multi_fact_scenario():
    for s in build_registry_v3().all_scenarios():
        if len(s.packet.get_all_facts()) >= 2:
            return s
    raise AssertionError("no multi-fact scenario in registry v3")

def test_highest_stage_fact_is_a_real_fact_id():
    s = _first_multi_fact_scenario()
    fid = highest_stage_fact_id(s.packet)
    assert fid in {f.fact_id for f in s.packet.get_all_facts()}

def test_control_drops_exactly_one_fact_and_keeps_metadata():
    s = _first_multi_fact_scenario()
    dropped = highest_stage_fact_id(s.packet)
    ctrl = build_positive_control_scenario(s)
    base_ids = {f.fact_id for f in s.packet.get_all_facts()}
    ctrl_ids = {f.fact_id for f in ctrl.packet.get_all_facts()}
    assert ctrl_ids == base_ids - {dropped}
    assert ctrl.metadata.scenario_id == s.metadata.scenario_id
    assert ctrl.packet.is_frozen()

def test_control_requires_two_facts():
    s = _first_multi_fact_scenario()
    # build a single-fact packet by hand is overkill; assert guard via the helper
    from ares.dialectic.evidence.packet import EvidencePacket
    one = EvidencePacket(packet_id="p", time_window=s.packet.time_window)
    one.add_fact(s.packet.get_all_facts()[0])
    from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario
    tiny = BenchmarkScenario(metadata=s.metadata, packet=one)
    with pytest.raises(ValueError, match="at least 2 facts"):
        build_positive_control_scenario(tiny)
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_control.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_control.py
"""Positive control: drop the highest kill-chain-stage fact from a scenario's
packet — a structured change that SHOULD move the Architect's cited-fact set.
Used to prove the measurement pipeline can register a real change (closes the
'can the alarm even ring?' gap)."""
from __future__ import annotations

from ares.dialectic.agents.light_skeptic import _STAGE_MAP, _DEFAULT_STAGE
from ares.dialectic.evidence.packet import EvidencePacket
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario


def highest_stage_fact_id(packet) -> str:
    """fact_id of the highest-stage fact; deterministic tie-break by fact_id."""
    facts = packet.get_all_facts()
    if not facts:
        raise ValueError("packet has no facts")
    return max(
        facts,
        key=lambda f: (_STAGE_MAP.get(f.field, _DEFAULT_STAGE), f.fact_id),
    ).fact_id


def build_positive_control_scenario(baseline: BenchmarkScenario) -> BenchmarkScenario:
    facts = baseline.packet.get_all_facts()
    if len(facts) < 2:
        raise ValueError("positive control requires a packet with at least 2 facts")
    drop = highest_stage_fact_id(baseline.packet)
    ctrl = EvidencePacket(
        packet_id=f"{baseline.packet.packet_id}-ctrl",
        time_window=baseline.packet.time_window,
    )
    for f in facts:
        if f.fact_id != drop:
            ctrl.add_fact(f)
    ctrl.freeze()
    return BenchmarkScenario(metadata=baseline.metadata, packet=ctrl)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_control.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_control.py tests/dialectic/measurement/test_architect_framing_control.py
git commit -m "feat(s077): positive-control packet (drop top-stage fact)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 6: Runner — preflight cost estimate (injectable cycle_fn)

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_runner.py`
- Test: `tests/dialectic/measurement/test_architect_framing_runner.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_runner.py
from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingConfig
from ares.dialectic.measurement.architect_framing_runner import run_preflight, total_cycles_for
from ares.dialectic.measurement.leakage_runner import CycleTrace


def _trace(cost=0.02, cited=("f1",)):
    return CycleTrace(
        cycle_id="c", scenario_id="INJ-001", operator_name=None, pair_index=0,
        is_baseline=True, pipeline="llm", architect_message_type="hypothesis",
        architect_confidence=0.9, architect_cited_facts=tuple(cited),
        skeptic_message_type="rebuttal", skeptic_confidence=0.3,
        skeptic_cited_facts=(), skeptic_triggered_rules=(),
        oracle_outcome="threat_confirmed", oracle_confidence=0.9,
        oracle_supporting_facts=tuple(cited), final_outcome="threat_confirmed",
        final_confidence=0.9, cost_usd=cost, tokens_in=10, tokens_out=10, elapsed_ms=100.0,
    )

def _stub_cycle_fn(**kwargs):
    return _trace(cost=0.02), 0.02

def test_total_cycles_formula():
    # K*(2 + n_ops) per scenario: baseline K + control K + n_ops*K
    assert total_cycles_for(n_scenarios=3, k=8, n_ops=3) == 3 * 8 * 5

def test_preflight_estimates_and_flags_over_ceiling(tmp_path):
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001", "INJ-002", "INJ-003"),
        k_resamples=8, max_scenarios=6, cost_ceiling_usd=1.0,  # tiny ceiling
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=3)
    # 3 scenarios * 8 * 5 = 120 cycles * $0.02 = $2.4 > $1.0 ceiling
    assert res["exceeds_ceiling"] is True
    assert res["estimated_total_cost_usd"] > 1.0
    assert res["avg_cost_per_cycle_usd"] == 0.02

def test_preflight_under_ceiling(tmp_path):
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001",),
        k_resamples=2, max_scenarios=6, cost_ceiling_usd=6.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=2)
    # 1 scenario * 2 * 5 = 10 cycles * 0.02 = 0.20 < 6.0
    assert res["exceeds_ceiling"] is False
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_runner.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_runner.py
"""Runner for the Architect-path framing-sensitivity measurement (Session 077).

Reuses leakage_runner._run_one_cycle (pipeline='llm') as the resample primitive,
so the noise floor is measured on the SAME cycle that produced the 60-78% figure.
The orchestration accepts an injectable cycle_fn for offline testing.
"""
from __future__ import annotations

import logging
from typing import Any, Callable

from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingConfig
from ares.dialectic.measurement.leakage_runner import _run_one_cycle

logger = logging.getLogger("ares.measurement.architect_framing")

CycleFn = Callable[..., tuple[Any, float]]   # mirrors _run_one_cycle


def total_cycles_for(*, n_scenarios: int, k: int, n_ops: int) -> int:
    """K baseline + K control + n_ops*K framing, per scenario."""
    return n_scenarios * k * (2 + n_ops)


def run_preflight(
    *,
    config: ArchitectFramingConfig,
    client: Any,
    cycle_fn: CycleFn = _run_one_cycle,
    n_samples: int = 3,
) -> dict[str, Any]:
    """Sample a few llm cycles, estimate per-cycle cost, extrapolate the full run."""
    from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3

    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}
    sample_ids = [sid for sid in config.scenario_ids if sid in by_id][:n_samples]

    sample_costs: list[float] = []
    for i, sid in enumerate(sample_ids):
        try:
            _, cost = cycle_fn(
                scenario=by_id[sid], pipeline="llm", client=client,
                cycle_id=f"preflight-{i:02d}", pair_index=i,
                is_baseline=True, operator_name=None,
            )
            sample_costs.append(cost)
        except Exception as exc:  # noqa: BLE001
            logger.warning("preflight sample %s failed: %s", sid, exc)

    n_scenarios = min(len(config.scenario_ids), config.max_scenarios)
    n_cycles = total_cycles_for(
        n_scenarios=n_scenarios, k=config.k_resamples, n_ops=len(config.operator_names)
    )
    if not sample_costs:
        return {"status": "no_samples", "estimated_total_cost_usd": None,
                "exceeds_ceiling": True, "n_cycles": n_cycles,
                "cost_ceiling_usd": config.cost_ceiling_usd, "avg_cost_per_cycle_usd": None}

    avg = sum(sample_costs) / len(sample_costs)
    est = avg * n_cycles
    return {
        "status": "ok",
        "avg_cost_per_cycle_usd": avg,
        "n_cycles": n_cycles,
        "n_scenarios": n_scenarios,
        "estimated_total_cost_usd": est,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": est > config.cost_ceiling_usd,
    }
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_runner.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_runner.py tests/dialectic/measurement/test_architect_framing_runner.py
git commit -m "feat(s077): framing-runner preflight cost estimator

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 7: Runner — full resample measurement (injectable cycle_fn)

**Files:**
- Modify: `ares/dialectic/measurement/architect_framing_runner.py` (append `run_measurement` + helpers)
- Test: `tests/dialectic/measurement/test_architect_framing_runner.py` (append)

- [ ] **Step 1: Write the failing test (append)**

```python
# append to tests/dialectic/measurement/test_architect_framing_runner.py
from ares.dialectic.measurement.architect_framing_runner import run_measurement
from ares.dialectic.measurement.architect_framing_schema import VERDICT_REAL

def _make_condition_aware_cycle_fn():
    """Stub: baseline/framing return a stable cited set; control returns a
    very different set -> control must exceed noise, framing within noise."""
    def fn(*, scenario, pipeline, client, cycle_id, pair_index, is_baseline, operator_name):
        if operator_name == "__control__":
            cited = ("zzz",)            # disjoint from baseline -> big distance
        else:
            cited = ("f1", "f2", "f3")  # identical across baseline + framing -> zero distance
        return _trace(cost=0.001, cited=cited), 0.001
    return fn

def test_run_measurement_offline_control_fires_framing_quiet(tmp_path):
    # one real multi-fact scenario so the control builder works
    from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
    sid = next(s.metadata.scenario_id for s in build_registry_v3().all_scenarios()
               if len(s.packet.get_all_facts()) >= 2)
    cfg = ArchitectFramingConfig(
        s059_traces_path="x", scenario_ids=(sid,), k_resamples=4,
        max_scenarios=6, cost_ceiling_usd=6.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(),
                              cycle_fn=_make_condition_aware_cycle_fn())
    assert summary.control_valid is True
    sr = summary.scenario_results[0]
    assert sr.control_exceeds_noise is True
    # framing identical to baseline -> not "real"
    assert all(op.verdict != VERDICT_REAL for op in sr.operator_results)
    assert summary.halt_reason == "completed"
    assert (tmp_path / summary.run_id / "traces.jsonl").exists()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_runner.py::test_run_measurement_offline_control_fires_framing_quiet -q`
Expected: FAIL with `ImportError: cannot import name 'run_measurement'`.

- [ ] **Step 3: Write minimal implementation (append to runner)**

```python
# append to ares/dialectic/measurement/architect_framing_runner.py
import json
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path

from ares.dialectic.agents.strategies.client_factory import make_client
from ares.dialectic.measurement.architect_framing_control import build_positive_control_scenario
from ares.dialectic.measurement.architect_framing_metrics import (
    classify_operator, cross_distances, within_distances,
)
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingSummary, CONDITION_BASELINE, CONDITION_CONTROL, ResampleRecord,
    ScenarioFramingResult, framing_condition,
)
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator, SkeletonInvariantError,
)
from ares.dialectic.measurement.leakage_runner import _resolve_operator

_CONTROL_SENTINEL = "__control__"


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _resample(scenario, *, client, cycle_fn, condition, operator_name, k, sink):
    """Run k llm cycles on `scenario`; return list[frozenset] of cited facts."""
    sets: list[frozenset[str]] = []
    for j in range(k):
        trace, cost = cycle_fn(
            scenario=scenario, pipeline="llm", client=client,
            cycle_id=f"{scenario.metadata.scenario_id}-{condition}-{j}-{uuid.uuid4().hex[:4]}",
            pair_index=j, is_baseline=(condition == CONDITION_BASELINE),
            operator_name=operator_name,
        )
        cited = frozenset(trace.architect_cited_facts)
        sets.append(cited)
        sink.append(ResampleRecord(
            scenario_id=scenario.metadata.scenario_id, condition=condition,
            resample_index=j, architect_cited_facts=tuple(sorted(cited)),
            architect_confidence=trace.architect_confidence,
            final_outcome=trace.final_outcome,
            oracle_supporting_facts=tuple(sorted(trace.oracle_supporting_facts)),
            cost_usd=cost, elapsed_ms=trace.elapsed_ms,
        ))
    return sets


def run_measurement(
    *, config: ArchitectFramingConfig, client=None, cycle_fn: CycleFn = _run_one_cycle,
) -> ArchitectFramingSummary:
    if client is None:
        client = make_client(config.provider, model=config.model)

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}

    selected = list(config.scenario_ids) or select_diverging_scenarios(config.s059_traces_path)
    selected = [sid for sid in selected if sid in by_id]
    to_run = selected[: config.max_scenarios]
    deferred = tuple(selected[config.max_scenarios:])

    mutator = PairedScenarioMutator(
        operators=tuple(_resolve_operator(n) for n in config.operator_names)
    )

    records: list[ResampleRecord] = []
    scenario_results: list[ScenarioFramingResult] = []
    total_cost = 0.0
    halt_reason = "completed"

    for sid in to_run:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = "cost_ceiling"
            deferred = deferred + (sid,)
            continue
        base = by_id[sid]
        base_sets = _resample(base, client=client, cycle_fn=cycle_fn,
                              condition=CONDITION_BASELINE, operator_name=None,
                              k=config.k_resamples, sink=records)
        within = within_distances(base_sets)

        op_results = []
        skipped = []
        for op_name in config.operator_names:
            try:
                pair = mutator.mutate(base, op_name)
            except SkeletonInvariantError:
                skipped.append(op_name)        # no-op mutation on this scenario
                continue
            mut_sets = _resample(pair.mutated_scenario, client=client, cycle_fn=cycle_fn,
                                 condition=framing_condition(op_name), operator_name=op_name,
                                 k=config.k_resamples, sink=records)
            cross = cross_distances(base_sets, mut_sets)
            op_results.append(classify_operator(cross, within, seed=config.seed,
                                                 operator_name=op_name))

        # positive control
        try:
            ctrl = build_positive_control_scenario(base)
            ctrl_sets = _resample(ctrl, client=client, cycle_fn=cycle_fn,
                                  condition=CONDITION_CONTROL, operator_name=_CONTROL_SENTINEL,
                                  k=config.k_resamples, sink=records)
            ctrl_cross = cross_distances(base_sets, ctrl_sets)
            within_max = max(within) if within else 0.0
            control_exceeds = (sum(ctrl_cross) / len(ctrl_cross)) > within_max if ctrl_cross else False
        except ValueError:
            ctrl_cross, control_exceeds = [], False

        scenario_results.append(ScenarioFramingResult(
            scenario_id=sid, within_distances=tuple(within),
            control_distances=tuple(ctrl_cross), control_exceeds_noise=control_exceeds,
            operator_results=tuple(op_results), skipped_operators=tuple(skipped),
        ))
        total_cost = sum(r.cost_usd for r in records)

    # persist traces
    traces_dir = Path(config.traces_root) / run_id
    traces_dir.mkdir(parents=True, exist_ok=True)
    traces_path = traces_dir / "traces.jsonl"
    with traces_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), sort_keys=True) + "\n")

    control_valid = bool(scenario_results) and all(
        s.control_exceeds_noise for s in scenario_results
    )
    return ArchitectFramingSummary(
        run_id=run_id, timestamp_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        git_sha=_git_sha(), provider=config.provider, model=config.model,
        k_resamples=config.k_resamples, operator_names=config.operator_names,
        scenario_results=tuple(scenario_results), deferred_scenario_ids=deferred,
        control_valid=control_valid, total_cost_usd=total_cost,
        halt_reason=halt_reason, traces_path=str(traces_path),
    )
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_runner.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_runner.py tests/dialectic/measurement/test_architect_framing_runner.py
git commit -m "feat(s077): full resample measurement loop (offline-testable)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 8: Markdown report renderer

**Files:**
- Create: `ares/dialectic/measurement/architect_framing_report.py`
- Test: `tests/dialectic/measurement/test_architect_framing_report.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_architect_framing_report.py
from ares.dialectic.measurement.architect_framing_report import render_report
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingSummary, ScenarioFramingResult, OperatorFramingResult,
    VERDICT_REAL, VERDICT_NOISE,
)

def _summary(control_valid=True, verdict=VERDICT_REAL):
    op = OperatorFramingResult(
        operator_name="framing_prefix_v1", n_cross=64, cross_median=0.5,
        within_median=0.1, effect_size=0.4, p_value=0.01, ci_low=0.2, ci_high=0.6,
        verdict=verdict,
    )
    sr = ScenarioFramingResult(
        scenario_id="INJ-001", within_distances=(0.1,), control_distances=(0.9,),
        control_exceeds_noise=True, operator_results=(op,), skipped_operators=(),
    )
    return ArchitectFramingSummary(
        run_id="r1", timestamp_iso="t", git_sha="abc", provider="anthropic",
        model="claude-sonnet-4-20250514", k_resamples=8,
        operator_names=("framing_prefix_v1",), scenario_results=(sr,),
        deferred_scenario_ids=(), control_valid=control_valid, total_cost_usd=4.2,
        halt_reason="completed", traces_path="x/traces.jsonl",
    )

def test_report_includes_verdict_and_control_banner():
    md = render_report(_summary())
    assert "framing_channel_real" in md
    assert "INJ-001" in md
    assert "Positive control" in md
    assert "$4.2" in md

def test_report_warns_when_control_invalid():
    md = render_report(_summary(control_valid=False))
    assert "VOID" in md or "void" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_report.py -q`
Expected: FAIL with `ModuleNotFoundError`.

- [ ] **Step 3: Write minimal implementation**

```python
# ares/dialectic/measurement/architect_framing_report.py
"""Markdown renderer for the Architect-path framing measurement."""
from __future__ import annotations

from pathlib import Path

from ares.dialectic.measurement.architect_framing_schema import ArchitectFramingSummary


def render_report(summary: ArchitectFramingSummary) -> str:
    lines: list[str] = []
    lines.append(f"# Architect-Path Framing Measurement — {summary.run_id}")
    lines.append("")
    lines.append(f"- provider/model: {summary.provider} / {summary.model}")
    lines.append(f"- K resamples: {summary.k_resamples}")
    lines.append(f"- git: {summary.git_sha}  |  cost: ${summary.total_cost_usd:.2f}"
                 f"  |  halt: {summary.halt_reason}")
    if not summary.control_valid:
        lines.append("")
        lines.append("> **RUN VOID** — positive control did not exceed the noise floor "
                     "on at least one scenario; the harness cannot be trusted to register "
                     "a real change. Treat framing verdicts below as unreliable.")
    if summary.deferred_scenario_ids:
        lines.append("")
        lines.append(f"> Deferred (budget): {', '.join(summary.deferred_scenario_ids)} "
                     "— selected but not measured this run (not silently dropped).")
    lines.append("")
    for sr in summary.scenario_results:
        lines.append(f"## {sr.scenario_id}")
        lines.append(f"Positive control exceeds noise: **{sr.control_exceeds_noise}**")
        if sr.skipped_operators:
            lines.append(f"No-op operators (skipped): {', '.join(sr.skipped_operators)}")
        lines.append("")
        lines.append("| operator | effect | p | 95% CI | verdict |")
        lines.append("|---|---|---|---|---|")
        for op in sr.operator_results:
            lines.append(
                f"| {op.operator_name} | {op.effect_size:+.3f} | {op.p_value:.3f} "
                f"| [{op.ci_low:+.3f}, {op.ci_high:+.3f}] | {op.verdict} |"
            )
        lines.append("")
    return "\n".join(lines)


def write_report(summary: ArchitectFramingSummary) -> Path:
    path = Path(summary.traces_path).parent / f"ARCHITECT_FRAMING_{summary.run_id}.md"
    path.write_text(render_report(summary), encoding="utf-8")
    return path
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_architect_framing_report.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/architect_framing_report.py tests/dialectic/measurement/test_architect_framing_report.py
git commit -m "feat(s077): framing measurement markdown report

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 9: CLI — `scripts/run_session_077.py`

**Files:**
- Create: `scripts/run_session_077.py`
- Test: `tests/dialectic/measurement/test_run_session_077_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_run_session_077_cli.py
import importlib.util, sys
from pathlib import Path

_CLI = Path(__file__).resolve().parents[3] / "scripts" / "run_session_077.py"

def _load():
    spec = importlib.util.spec_from_file_location("run_session_077", _CLI)
    mod = importlib.util.module_from_spec(spec)
    sys.modules["run_session_077"] = mod
    spec.loader.exec_module(mod)
    return mod

def test_cost_ceiling_above_hard_cap_refused(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--preflight-only", "--cost-ceiling", "99"])
    assert rc == 2

def test_dry_run_makes_no_calls(capsys):
    mod = _load()
    rc = mod.main(["--provider", "anthropic", "--dry-run"])
    assert rc == 0
    assert "dry run" in capsys.readouterr().out.lower()
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_077_cli.py -q`
Expected: FAIL (file not found / import error).

- [ ] **Step 3: Write minimal implementation**

```python
# scripts/run_session_077.py
"""Session 077 — Architect-path framing-sensitivity measurement CLI.

Mirrors run_session_075.py: UTF-16 .env load, anchor guard, preflight ->
--confirm-live gate, cost-ceiling hard cap.
"""
from __future__ import annotations

import argparse
import logging
import os
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))


def _load_env() -> int:
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return 0
    with open(env_path, "r", encoding="utf-16") as f:
        content = f.read()
    loaded = 0
    for line in content.strip().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            if key.strip() and value.strip():
                os.environ[key.strip()] = value.strip()
                loaded += 1
    return loaded


from ares.dialectic.agents.strategies.client_factory import PROVIDER_DEFAULTS, VALID_PROVIDERS
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, ARCHITECT_FRAMING_HARD_CEILING_USD,
)
from ares.dialectic.measurement.architect_framing_runner import run_measurement, run_preflight
from ares.dialectic.measurement.architect_framing_report import write_report
from ares.dialectic.measurement.leakage_runner import DEFAULT_TRACES_ROOT, anchor_test_passes

_DEFAULT_S059 = DEFAULT_TRACES_ROOT / "20260510-193950-f401a8" / "traces.jsonl"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s :: %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Session 077 — Architect framing measurement")
    p.add_argument("--provider", required=True, choices=sorted(VALID_PROVIDERS))
    p.add_argument("--model", default=None)
    p.add_argument("--k", type=int, default=8)
    p.add_argument("--max-scenarios", type=int, default=6)
    p.add_argument("--s059-traces", default=str(_DEFAULT_S059))
    p.add_argument("--cost-ceiling", type=float, default=6.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > ARCHITECT_FRAMING_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${ARCHITECT_FRAMING_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    model = args.model or PROVIDER_DEFAULTS[args.provider]

    print("[1/3] anchor-test guard ...")
    if not anchor_test_passes():
        print("[FATAL] anchor test RED; halting before spend.", file=sys.stderr)
        return 3
    print("       anchor green [ok]")

    if args.dry_run:
        print("[done] dry run complete; anchor green; no LLM calls made.")
        return 0

    cfg = ArchitectFramingConfig(
        s059_traces_path=Path(args.s059_traces), k_resamples=args.k,
        max_scenarios=args.max_scenarios, model=model, provider=args.provider,
        cost_ceiling_usd=args.cost_ceiling,
    )
    # auto-select scenarios for the preflight estimate
    from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
    sids = tuple(select_diverging_scenarios(cfg.s059_traces_path))
    cfg = ArchitectFramingConfig(
        s059_traces_path=cfg.s059_traces_path, scenario_ids=sids, k_resamples=cfg.k_resamples,
        max_scenarios=cfg.max_scenarios, model=cfg.model, provider=cfg.provider,
        cost_ceiling_usd=cfg.cost_ceiling_usd,
    )
    print(f"[config] provider={args.provider} model={model} k={args.k} "
          f"scenarios={len(sids)} (cap {args.max_scenarios}) ceiling=${args.cost_ceiling}")

    print("[2/3] pre-flight estimator ...")
    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(args.provider, model=model)
    pf = run_preflight(config=cfg, client=client)
    print(f"   est total: ${pf.get('estimated_total_cost_usd')}  "
          f"cycles: {pf.get('n_cycles')}  exceeds_ceiling: {pf.get('exceeds_ceiling')}")
    if pf.get("exceeds_ceiling"):
        print("[HALT] preflight exceeds ceiling; live run not initiated.", file=sys.stderr)
        return 4

    if args.preflight_only or not args.confirm_live:
        print("[done] pre-flight complete. Pass --confirm-live to run.")
        return 0

    print("[3/3] LIVE measurement ...")
    summary = run_measurement(config=cfg, client=client)
    report = write_report(summary)
    print(f"control_valid: {summary.control_valid}  cost: ${summary.total_cost_usd:.2f}")
    print(f"report: {report}")
    print(f"traces: {summary.traces_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_077_cli.py -q`
Expected: PASS (2 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/run_session_077.py tests/dialectic/measurement/test_run_session_077_cli.py
git commit -m "feat(s077): run_session_077 CLI (preflight-gated, cost-capped)

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 10: Full-suite regression + dry-run smoke; hand off to live preflight

**Files:** none (verification only)

- [ ] **Step 1: Run the whole suite — zero regressions**

Run: `python -m pytest tests ares -q`
Expected: all prior tests pass + the new modules' tests; `0 failed`. Record the new passing count (was 4,113 + new tests).

- [ ] **Step 2: Dry-run the CLI (no LLM)**

Run: `python scripts/run_session_077.py --provider anthropic --dry-run`
Expected: prints env-load line, anchor green, "dry run complete"; exit 0.

- [ ] **Step 3: Update CLAUDE.md test floor + Key Code Locations**

Edit `CLAUDE.md`: bump the passing-test floor to the new count from Step 1, and add the five `architect_framing_*` modules + `run_session_077.py` under "Multi-model measurement"/a new "Architect-path measurement (Session 077)" subsection.
Run: `python -m pytest tests/test_claude_md_freshness.py -q` → PASS.

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(s077): bump test floor + register architect-framing modules

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

- [ ] **Step 5: STOP — live run is Dan-gated**

Do NOT run live. Report to Dan and run, with his GO:
`python scripts/run_session_077.py --provider anthropic --preflight-only`
Surface the preflight cost estimate. Only on Dan's explicit GO run `--confirm-live`. After the live run, review the report's **control_valid** banner first — if VOID, the framing verdicts are unreliable and we debug the control before trusting anything.

---

## Self-Review

**Spec coverage:** RQ + verdict rule (Task 3 `classify_operator` + report) ✓; repeated-baseline resampling (Task 7 `_resample` baseline K + framing K) ✓; Jaccard primary metric (Task 2) ✓; secondary verdict/`supporting_fact_ids` recorded (Task 1 `ResampleRecord`, Task 7) ✓; positive control + void condition (Task 5 + Task 7 `control_exceeds_noise` + Task 8 VOID banner) ✓; stats with effect size + CI, honest about small K (Task 3) ✓; scenario selection from S059 (Task 4) ✓; new files only / no existing file modified (all tasks; CLAUDE.md doc-only edit in Task 10 is additive) ✓; cost ceiling + preflight + anchor (Task 6 + Task 9) ✓; Sonnet-only pilot, ~K=8 (defaults) ✓; no silent truncation (`deferred_scenario_ids` + report) ✓.

**Placeholder scan:** none — every code step is complete and runnable.

**Type consistency:** `ArchitectFramingConfig`, `ResampleRecord`, `OperatorFramingResult`, `ScenarioFramingResult`, `ArchitectFramingSummary` fields are used identically across Tasks 1/7/8; `classify_operator(...) -> OperatorFramingResult` (Task 3) consumed in Task 7; `_run_one_cycle` kwargs match the verified signature; `run_preflight`/`run_measurement`/`render_report`/`write_report` signatures match their tests.

**Known pilot limitation (documented, not a gap):** at full-cycle cost the budget bounds the pilot to ~K=8 × ≤6 scenarios (Task 6 formula + `max_scenarios`); the preflight halts if the estimate exceeds the ceiling, and unmeasured selected scenarios are logged as deferred. Raising scope is a config change for a follow-up run.
