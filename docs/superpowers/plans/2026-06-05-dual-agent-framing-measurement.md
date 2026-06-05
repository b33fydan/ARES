# Dual-Agent Framing Measurement (S084) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build a dual-agent framing-sensitivity harness that records both the Architect's and the Skeptic's cited facts per resampled cycle, runs the S077 noise-floor / cross-distance / positive-control machinery on each agent, quantifies the paired mirror (Architect collapse vs Skeptic expand), and then runs it live over the 17 Architect-diverging scenarios.

**Architecture:** Five new files under `ares/dialectic/measurement/` + `scripts/`, plus co-located offline tests. Nothing existing is modified — the live cycle's `CycleTrace` already carries `skeptic_cited_facts`. The metrics, positive-control, scenario-selection, and `_run_one_cycle` primitives are reused by import from the S077 / S059 modules.

**Tech Stack:** Python 3.11, frozen dataclasses, stdlib-only stats (reused from `architect_framing_metrics`), pytest with an injectable `cycle_fn` for offline tests, Anthropic Sonnet 4 for the live run.

**Spec:** `docs/superpowers/specs/2026-06-05-dual-agent-framing-measurement-design.md`

---

## File structure

| File | Responsibility |
|---|---|
| `ares/dialectic/measurement/dual_agent_framing_schema.py` | Frozen config + record/result dataclasses. |
| `ares/dialectic/measurement/dual_agent_framing_mirror.py` | Pure mirror logic (`direction`, `modal_set`, `classify_mirror`, `build_mirror_record`). |
| `ares/dialectic/measurement/dual_agent_framing_runner.py` | `total_cycles_for`, `_resample_dual`, `run_preflight`, `run_measurement`. |
| `ares/dialectic/measurement/dual_agent_framing_report.py` | `render_report` (pure) + `write_report` (writes `.md`, returns path). |
| `scripts/run_session_084.py` | CLI: `.env` load, anchor guard, preflight → `--confirm-live` gate, hard cost cap. |
| `tests/dialectic/measurement/test_dual_agent_framing_{schema,mirror,runner,report,cli}.py` | Offline, deterministic, `$0`. |

Reused by import (DO NOT modify): `architect_framing_metrics`, `architect_framing_control`, `architect_framing_selection`, `architect_framing_schema` (`OperatorFramingResult`, `VERDICT_*`, `CONDITION_*`, `framing_condition`), `leakage_runner` (`_run_one_cycle`, `_resolve_operator`, `CycleTrace`, `DEFAULT_MODEL`, `DEFAULT_TRACES_ROOT`, `PRE_REGISTERED_OPERATOR_NAMES`, `anchor_test_passes`), `injection_registry_v3`, `paired_scenario_mutator`, `client_factory`.

---

## Task 1: Schema module

**Files:**
- Create: `ares/dialectic/measurement/dual_agent_framing_schema.py`
- Test: `tests/dialectic/measurement/test_dual_agent_framing_schema.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/dialectic/measurement/test_dual_agent_framing_schema.py
import pytest

from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, DUAL_AGENT_FRAMING_HARD_CEILING_USD,
    DualAgentFramingConfig, DualAgentResampleRecord,
)


def test_record_to_dict_has_both_columns_as_lists():
    rec = DualAgentResampleRecord(
        scenario_id="INJ-020", condition="baseline", resample_index=0,
        architect_cited_facts=("a1", "a2"), skeptic_cited_facts=("s1",),
        architect_confidence=0.9, skeptic_confidence=0.3,
        final_outcome="threat_dismissed", oracle_supporting_facts=("s1",),
        cost_usd=0.01, elapsed_ms=12.0,
    )
    d = rec.to_dict()
    assert d["architect_cited_facts"] == ["a1", "a2"]
    assert d["skeptic_cited_facts"] == ["s1"]
    assert isinstance(d["architect_cited_facts"], list)
    assert isinstance(d["skeptic_cited_facts"], list)


def test_config_rejects_small_k():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(s059_traces_path="x", k_resamples=1)


def test_config_rejects_ceiling_over_hard_cap():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(
            s059_traces_path="x",
            cost_ceiling_usd=DUAL_AGENT_FRAMING_HARD_CEILING_USD + 1.0,
        )


def test_config_rejects_unknown_provider():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(s059_traces_path="x", provider="nope")


def test_agent_constants():
    assert AGENT_ARCHITECT == "architect"
    assert AGENT_SKEPTIC == "skeptic"
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_schema.py -q`
Expected: FAIL — `ModuleNotFoundError: dual_agent_framing_schema`.

- [ ] **Step 3: Write the module**

```python
# ares/dialectic/measurement/dual_agent_framing_schema.py
"""Frozen schema for the dual-agent framing-sensitivity measurement (Session 084).

Peer of architect_framing_schema. Records BOTH agents' cited facts per resample
(the live CycleTrace already carries skeptic_cited_facts), so one run measures the
Architect path, the Skeptic path, and the paired mirror.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

from ares.dialectic.agents.strategies.client_factory import VALID_PROVIDERS
from ares.dialectic.measurement.architect_framing_schema import OperatorFramingResult
from ares.dialectic.measurement.leakage_runner import (
    DEFAULT_MODEL, DEFAULT_TRACES_ROOT, PRE_REGISTERED_OPERATOR_NAMES,
)

DUAL_AGENT_FRAMING_HARD_CEILING_USD: float = 40.0
AGENT_ARCHITECT: str = "architect"
AGENT_SKEPTIC: str = "skeptic"


@dataclass(frozen=True)
class DualAgentFramingConfig:
    s059_traces_path: Path
    scenario_ids: tuple[str, ...] = ()
    k_resamples: int = 20
    max_scenarios: int = 17
    operator_names: tuple[str, ...] = PRE_REGISTERED_OPERATOR_NAMES
    model: str = DEFAULT_MODEL
    provider: str = "anthropic"
    cost_ceiling_usd: float = 32.0
    traces_root: Path = DEFAULT_TRACES_ROOT
    seed: int = 0

    def __post_init__(self) -> None:
        if self.k_resamples < 2:
            raise ValueError(f"k_resamples must be >= 2, got {self.k_resamples}")
        if not self.operator_names:
            raise ValueError("operator_names must be non-empty")
        if self.provider not in VALID_PROVIDERS:
            raise ValueError(f"provider must be one of {sorted(VALID_PROVIDERS)}")
        if self.cost_ceiling_usd > DUAL_AGENT_FRAMING_HARD_CEILING_USD:
            raise ValueError(
                f"cost_ceiling_usd {self.cost_ceiling_usd} exceeds hard cap "
                f"{DUAL_AGENT_FRAMING_HARD_CEILING_USD}"
            )


@dataclass(frozen=True)
class DualAgentResampleRecord:
    scenario_id: str
    condition: str
    resample_index: int
    architect_cited_facts: tuple[str, ...]
    skeptic_cited_facts: tuple[str, ...]
    architect_confidence: float
    skeptic_confidence: float
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
            "skeptic_cited_facts": list(self.skeptic_cited_facts),
            "architect_confidence": self.architect_confidence,
            "skeptic_confidence": self.skeptic_confidence,
            "final_outcome": self.final_outcome,
            "oracle_supporting_facts": list(self.oracle_supporting_facts),
            "cost_usd": self.cost_usd,
            "elapsed_ms": self.elapsed_ms,
        }


@dataclass(frozen=True)
class AgentFramingResult:
    agent: str
    within_distances: tuple[float, ...]
    control_distances: tuple[float, ...]
    control_exceeds_noise: bool
    operator_results: tuple[OperatorFramingResult, ...]


@dataclass(frozen=True)
class MirrorRecord:
    scenario_id: str
    operator_name: str
    architect_jaccard: float
    architect_direction: str
    skeptic_jaccard: float
    skeptic_direction: str
    mirror_class: str


@dataclass(frozen=True)
class ScenarioDualFramingResult:
    scenario_id: str
    architect: AgentFramingResult
    skeptic: AgentFramingResult
    mirror: tuple[MirrorRecord, ...]
    skipped_operators: tuple[str, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class DualAgentFramingSummary:
    run_id: str
    timestamp_iso: str
    git_sha: str
    provider: str
    model: str
    k_resamples: int
    operator_names: tuple[str, ...]
    scenario_results: tuple[ScenarioDualFramingResult, ...]
    deferred_scenario_ids: tuple[str, ...]
    control_valid_architect: bool
    control_valid_skeptic: bool
    total_cost_usd: float
    halt_reason: str
    traces_path: str
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_schema.py -q`
Expected: PASS (5 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/dual_agent_framing_schema.py tests/dialectic/measurement/test_dual_agent_framing_schema.py
git commit -m "feat(s084): dual-agent framing schema (both-agent resample record)"
```

---

## Task 2: Mirror module

**Files:**
- Create: `ares/dialectic/measurement/dual_agent_framing_mirror.py`
- Test: `tests/dialectic/measurement/test_dual_agent_framing_mirror.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/dialectic/measurement/test_dual_agent_framing_mirror.py
from ares.dialectic.measurement.dual_agent_framing_mirror import (
    build_mirror_record, classify_mirror, direction, modal_set,
)


def test_direction_cases():
    assert direction(frozenset("abc"), frozenset("abc")) == "none"
    assert direction(frozenset("abc"), frozenset("c")) == "collapse"
    assert direction(frozenset("c"), frozenset("abc")) == "expand"
    assert direction(frozenset("ab"), frozenset("bc")) == "swap"


def test_modal_set_picks_most_common_with_deterministic_tiebreak():
    a, b = frozenset({"x"}), frozenset({"y"})
    # 2x a, 2x b -> tie -> lexicographically smallest sorted tuple wins ("x" < "y")
    assert modal_set([a, b, a, b]) == a
    # clear majority
    assert modal_set([a, a, b]) == a
    assert modal_set([]) == frozenset()


def test_classify_mirror_truth_table():
    assert classify_mirror("none", "none") == "none"
    assert classify_mirror("collapse", "none") == "single"
    assert classify_mirror("none", "expand") == "single"
    assert classify_mirror("collapse", "collapse") == "aligned"
    assert classify_mirror("collapse", "expand") == "opposed"
    assert classify_mirror("expand", "collapse") == "opposed"
    assert classify_mirror("collapse", "swap") == "mixed"
    assert classify_mirror("swap", "expand") == "mixed"


def test_build_mirror_record_opposed():
    rec = build_mirror_record(
        scenario_id="INJ-020", operator_name="framing_prefix_v1",
        arch_base_sets=[frozenset({"f1", "f2", "f3"})] * 3,
        arch_framed_sets=[frozenset({"f3"})] * 3,
        skep_base_sets=[frozenset({"f1", "f2", "f3"})] * 3,
        skep_framed_sets=[frozenset({"f1", "f2", "f3", "f4"})] * 3,
    )
    assert rec.architect_direction == "collapse"
    assert rec.skeptic_direction == "expand"
    assert rec.mirror_class == "opposed"
    assert abs(rec.architect_jaccard - (1 - 1 / 3)) < 1e-9
    assert abs(rec.skeptic_jaccard - (1 - 3 / 4)) < 1e-9
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_mirror.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the module**

```python
# ares/dialectic/measurement/dual_agent_framing_mirror.py
"""Pure mirror-pattern logic for the dual-agent framing measurement (Session 084).

Stdlib only. No LLM, no I/O. Quantifies the S083 dual-agent mirror: the Architect
collapses its cited-fact set toward the contested fact while the Skeptic expands
toward it (mirror_class == "opposed").
"""
from __future__ import annotations

from collections import Counter
from typing import Sequence

from ares.dialectic.measurement.architect_framing_metrics import jaccard_distance
from ares.dialectic.measurement.dual_agent_framing_schema import MirrorRecord

DIR_NONE = "none"
DIR_COLLAPSE = "collapse"
DIR_EXPAND = "expand"
DIR_SWAP = "swap"

MIRROR_NONE = "none"
MIRROR_SINGLE = "single"
MIRROR_ALIGNED = "aligned"
MIRROR_OPPOSED = "opposed"
MIRROR_MIXED = "mixed"


def direction(baseline: frozenset[str], framed: frozenset[str]) -> str:
    drop = baseline - framed
    add = framed - baseline
    if not drop and not add:
        return DIR_NONE
    if drop and not add:
        return DIR_COLLAPSE
    if add and not drop:
        return DIR_EXPAND
    return DIR_SWAP


def modal_set(sets: Sequence[frozenset[str]]) -> frozenset[str]:
    if not sets:
        return frozenset()
    counts = Counter(sets)
    top = max(counts.values())
    tied = [s for s, c in counts.items() if c == top]
    return min(tied, key=lambda s: tuple(sorted(s)))


def classify_mirror(arch_dir: str, skep_dir: str) -> str:
    if arch_dir == DIR_NONE and skep_dir == DIR_NONE:
        return MIRROR_NONE
    if arch_dir == DIR_NONE or skep_dir == DIR_NONE:
        return MIRROR_SINGLE
    if arch_dir == skep_dir:
        return MIRROR_ALIGNED
    if {arch_dir, skep_dir} == {DIR_COLLAPSE, DIR_EXPAND}:
        return MIRROR_OPPOSED
    return MIRROR_MIXED


def build_mirror_record(
    *,
    scenario_id: str,
    operator_name: str,
    arch_base_sets: Sequence[frozenset[str]],
    arch_framed_sets: Sequence[frozenset[str]],
    skep_base_sets: Sequence[frozenset[str]],
    skep_framed_sets: Sequence[frozenset[str]],
) -> MirrorRecord:
    a_b, a_f = modal_set(arch_base_sets), modal_set(arch_framed_sets)
    s_b, s_f = modal_set(skep_base_sets), modal_set(skep_framed_sets)
    a_dir, s_dir = direction(a_b, a_f), direction(s_b, s_f)
    return MirrorRecord(
        scenario_id=scenario_id,
        operator_name=operator_name,
        architect_jaccard=jaccard_distance(a_b, a_f),
        architect_direction=a_dir,
        skeptic_jaccard=jaccard_distance(s_b, s_f),
        skeptic_direction=s_dir,
        mirror_class=classify_mirror(a_dir, s_dir),
    )
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_mirror.py -q`
Expected: PASS (4 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/dual_agent_framing_mirror.py tests/dialectic/measurement/test_dual_agent_framing_mirror.py
git commit -m "feat(s084): pure dual-agent mirror logic (direction + classify_mirror)"
```

---

## Task 3: Runner — helpers, resample, preflight

**Files:**
- Create: `ares/dialectic/measurement/dual_agent_framing_runner.py`
- Test: `tests/dialectic/measurement/test_dual_agent_framing_runner.py`

- [ ] **Step 1: Write the failing tests (preflight + formula)**

```python
# tests/dialectic/measurement/test_dual_agent_framing_runner.py
import json

from ares.dialectic.measurement.architect_framing_schema import VERDICT_REAL
from ares.dialectic.measurement.dual_agent_framing_runner import (
    run_measurement, run_preflight, total_cycles_for,
)
from ares.dialectic.measurement.dual_agent_framing_schema import DualAgentFramingConfig
from ares.dialectic.measurement.leakage_runner import CycleTrace
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3


def _dual_trace(*, cost, arch, skep, outcome="threat_dismissed"):
    return CycleTrace(
        cycle_id="c", scenario_id="INJ-XXX", operator_name=None, pair_index=0,
        is_baseline=True, pipeline="llm", architect_message_type="hypothesis",
        architect_confidence=0.9, architect_cited_facts=tuple(arch),
        skeptic_message_type="rebuttal", skeptic_confidence=0.3,
        skeptic_cited_facts=tuple(skep), skeptic_triggered_rules=(),
        oracle_outcome=outcome, oracle_confidence=0.9,
        oracle_supporting_facts=tuple(skep), final_outcome=outcome,
        final_confidence=0.9, cost_usd=cost, tokens_in=10, tokens_out=10, elapsed_ms=100.0,
    )


def _stub_cycle_fn(**kwargs):
    return _dual_trace(cost=0.02, arch=("a1",), skep=("s1",)), 0.02


def test_total_cycles_formula():
    assert total_cycles_for(n_scenarios=17, k=20, n_ops=3) == 17 * 20 * 5


def test_preflight_flags_over_ceiling():
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001", "INJ-002", "INJ-003"),
        k_resamples=20, max_scenarios=17, cost_ceiling_usd=1.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=3)
    assert res["exceeds_ceiling"] is True
    assert res["avg_cost_per_cycle_usd"] == 0.02
    assert res["n_cycles"] == total_cycles_for(n_scenarios=3, k=20, n_ops=3)


def test_preflight_under_ceiling():
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=("INJ-001",),
        k_resamples=2, max_scenarios=17, cost_ceiling_usd=32.0,
    )
    res = run_preflight(config=cfg, client=object(), cycle_fn=_stub_cycle_fn, n_samples=1)
    assert res["exceeds_ceiling"] is False
```

NOTE: `test_preflight_flags_over_ceiling` asserts `n_cycles` is computed for `min(len(selected), max_scenarios) = min(3, 17) = 3` scenarios.

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_runner.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the runner's top half (helpers + resample + preflight)**

```python
# ares/dialectic/measurement/dual_agent_framing_runner.py
"""Runner for the dual-agent framing-sensitivity measurement (Session 084).

Reuses leakage_runner._run_one_cycle (pipeline='llm') as the resample primitive,
recording BOTH architect_cited_facts and skeptic_cited_facts per cycle, so one run
yields the Architect-path verdict, the Skeptic-path verdict, and the paired mirror.
Accepts an injectable cycle_fn for offline testing.
"""
from __future__ import annotations

import dataclasses
import json
import logging
import subprocess
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable

from ares.dialectic.agents.strategies.client_factory import make_client
from ares.dialectic.measurement.architect_framing_control import (
    build_positive_control_scenario, choose_control_drop_fact,
)
from ares.dialectic.measurement.architect_framing_metrics import (
    classify_operator, cross_distances, within_distances,
)
from ares.dialectic.measurement.architect_framing_schema import (
    CONDITION_BASELINE, CONDITION_CONTROL, framing_condition,
)
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.measurement.dual_agent_framing_mirror import build_mirror_record
from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, AgentFramingResult, DualAgentFramingConfig,
    DualAgentFramingSummary, DualAgentResampleRecord, ScenarioDualFramingResult,
)
from ares.dialectic.measurement.leakage_runner import _resolve_operator, _run_one_cycle
from ares.dialectic.scripts.injection_registry_v3 import build_registry_v3
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    PairedScenarioMutator, SkeletonInvariantError,
)

logger = logging.getLogger("ares.measurement.dual_agent_framing")

CycleFn = Callable[..., tuple[Any, float]]
_CONTROL_SENTINEL = "__control__"


def total_cycles_for(*, n_scenarios: int, k: int, n_ops: int) -> int:
    """K baseline + K control + n_ops*K framing, per scenario."""
    return n_scenarios * k * (2 + n_ops)


def _git_sha() -> str:
    try:
        return subprocess.check_output(
            ["git", "rev-parse", "--short", "HEAD"], text=True
        ).strip()
    except Exception:  # noqa: BLE001
        return "unknown"


def _selected_ids(config: DualAgentFramingConfig, by_id: dict) -> list[str]:
    selected = list(config.scenario_ids) or select_diverging_scenarios(config.s059_traces_path)
    return [sid for sid in selected if sid in by_id]


def _resample_dual(scenario, *, client, cycle_fn, condition, operator_name, k, sink):
    """Run k llm cycles; return (arch_sets, skep_sets) as list[frozenset]; append records."""
    arch_sets: list[frozenset[str]] = []
    skep_sets: list[frozenset[str]] = []
    for j in range(k):
        trace, cost = cycle_fn(
            scenario=scenario, pipeline="llm", client=client,
            cycle_id=f"{scenario.metadata.scenario_id}-{condition}-{j}-{uuid.uuid4().hex[:4]}",
            pair_index=j, is_baseline=(condition == CONDITION_BASELINE),
            operator_name=operator_name,
        )
        a = frozenset(trace.architect_cited_facts)
        s = frozenset(trace.skeptic_cited_facts)
        arch_sets.append(a)
        skep_sets.append(s)
        sink.append(DualAgentResampleRecord(
            scenario_id=scenario.metadata.scenario_id, condition=condition,
            resample_index=j,
            architect_cited_facts=tuple(sorted(a)),
            skeptic_cited_facts=tuple(sorted(s)),
            architect_confidence=trace.architect_confidence,
            skeptic_confidence=trace.skeptic_confidence,
            final_outcome=trace.final_outcome,
            oracle_supporting_facts=tuple(sorted(trace.oracle_supporting_facts)),
            cost_usd=cost, elapsed_ms=trace.elapsed_ms,
        ))
    return arch_sets, skep_sets


def run_preflight(
    *, config: DualAgentFramingConfig, client: Any,
    cycle_fn: CycleFn = _run_one_cycle, n_samples: int = 3,
) -> dict[str, Any]:
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}
    selected = _selected_ids(config, by_id)
    sample_ids = selected[:n_samples]

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

    n_scenarios = min(len(selected), config.max_scenarios)
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
        "status": "ok", "avg_cost_per_cycle_usd": avg, "n_cycles": n_cycles,
        "n_scenarios": n_scenarios, "estimated_total_cost_usd": est,
        "cost_ceiling_usd": config.cost_ceiling_usd,
        "exceeds_ceiling": est > config.cost_ceiling_usd,
    }
```

- [ ] **Step 4: Run to verify the preflight tests pass**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_runner.py -q`
Expected: the three preflight/formula tests PASS; the measurement tests added in Task 4 do not exist yet.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/dual_agent_framing_runner.py tests/dialectic/measurement/test_dual_agent_framing_runner.py
git commit -m "feat(s084): dual-agent runner — resample + preflight"
```

---

## Task 4: Runner — `run_measurement`

**Files:**
- Modify: `ares/dialectic/measurement/dual_agent_framing_runner.py` (append `run_measurement`)
- Test: `tests/dialectic/measurement/test_dual_agent_framing_runner.py` (append)

- [ ] **Step 1: Append the failing tests**

```python
# append to tests/dialectic/measurement/test_dual_agent_framing_runner.py

def _two_valid_sids(n=2):
    return [s.metadata.scenario_id for s in build_registry_v3().all_scenarios()
            if len(s.packet.get_all_facts()) >= 2][:n]


def _mirror_cycle_fn():
    """baseline: both cite {f1,f2,f3}; framing: architect collapses to {f3},
    skeptic expands to {f1,f2,f3,f4}; control: both cite {zzz} (far from baseline)."""
    def fn(*, scenario, pipeline, client, cycle_id, pair_index, is_baseline, operator_name):
        if operator_name == "__control__":
            return _dual_trace(cost=0.001, arch=("zzz",), skep=("zzz",)), 0.001
        if operator_name is None:
            return _dual_trace(cost=0.001, arch=("f1", "f2", "f3"), skep=("f1", "f2", "f3")), 0.001
        return _dual_trace(cost=0.001, arch=("f3",), skep=("f1", "f2", "f3", "f4")), 0.001
    return fn


def test_dual_measurement_mirror_opposed_and_both_columns_persisted(tmp_path):
    sid = _two_valid_sids(1)[0]
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=(sid,), k_resamples=4,
        max_scenarios=17, cost_ceiling_usd=32.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(), cycle_fn=_mirror_cycle_fn())
    sr = summary.scenario_results[0]
    assert summary.control_valid_architect is True
    assert summary.control_valid_skeptic is True
    assert all(op.verdict == VERDICT_REAL for op in sr.architect.operator_results)
    assert all(op.verdict == VERDICT_REAL for op in sr.skeptic.operator_results)
    assert sr.mirror[0].architect_direction == "collapse"
    assert sr.mirror[0].skeptic_direction == "expand"
    assert sr.mirror[0].mirror_class == "opposed"
    assert summary.halt_reason == "completed"

    traces = (tmp_path / summary.run_id / "traces.jsonl")
    rows = [json.loads(l) for l in traces.read_text(encoding="utf-8").splitlines()]
    assert rows and all("architect_cited_facts" in r and "skeptic_cited_facts" in r for r in rows)
    assert (tmp_path / summary.run_id / "summary.json").exists()


def test_dual_measurement_defers_when_capped(tmp_path):
    sids = _two_valid_sids(2)
    assert len(sids) == 2
    cfg = DualAgentFramingConfig(
        s059_traces_path="x", scenario_ids=tuple(sids), k_resamples=2,
        max_scenarios=1, cost_ceiling_usd=32.0, traces_root=tmp_path,
    )
    summary = run_measurement(config=cfg, client=object(), cycle_fn=_mirror_cycle_fn())
    assert len(summary.scenario_results) == 1
    assert summary.deferred_scenario_ids == (sids[1],)
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_runner.py -q`
Expected: FAIL — `run_measurement` not defined.

- [ ] **Step 3: Append `run_measurement` to the runner**

```python
# append to ares/dialectic/measurement/dual_agent_framing_runner.py

def run_measurement(
    *, config: DualAgentFramingConfig, client=None, cycle_fn: CycleFn = _run_one_cycle,
) -> DualAgentFramingSummary:
    if client is None:
        client = make_client(config.provider, model=config.model)

    run_id = f"{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}-{uuid.uuid4().hex[:6]}"
    registry = build_registry_v3()
    by_id = {s.metadata.scenario_id: s for s in registry.all_scenarios()}

    selected = _selected_ids(config, by_id)
    to_run = selected[: config.max_scenarios]
    deferred = tuple(selected[config.max_scenarios:])

    mutator = PairedScenarioMutator(
        operators=tuple(_resolve_operator(n) for n in config.operator_names)
    )

    records: list[DualAgentResampleRecord] = []
    scenario_results: list[ScenarioDualFramingResult] = []
    total_cost = 0.0
    halt_reason = "completed"

    for sid in to_run:
        if total_cost >= config.cost_ceiling_usd:
            halt_reason = "cost_ceiling"
            deferred = deferred + (sid,)
            continue
        base = by_id[sid]
        arch_base, skep_base = _resample_dual(
            base, client=client, cycle_fn=cycle_fn, condition=CONDITION_BASELINE,
            operator_name=None, k=config.k_resamples, sink=records)
        arch_within = within_distances(arch_base)
        skep_within = within_distances(skep_base)

        arch_ops, skep_ops, mirror_records, skipped = [], [], [], []
        for op_name in config.operator_names:
            try:
                pair = mutator.mutate(base, op_name)
            except SkeletonInvariantError:
                skipped.append(op_name)
                continue
            arch_framed, skep_framed = _resample_dual(
                pair.mutated_scenario, client=client, cycle_fn=cycle_fn,
                condition=framing_condition(op_name), operator_name=op_name,
                k=config.k_resamples, sink=records)
            arch_ops.append(classify_operator(
                cross_distances(arch_base, arch_framed), arch_within,
                seed=config.seed, operator_name=op_name))
            skep_ops.append(classify_operator(
                cross_distances(skep_base, skep_framed), skep_within,
                seed=config.seed, operator_name=op_name))
            mirror_records.append(build_mirror_record(
                scenario_id=sid, operator_name=op_name,
                arch_base_sets=arch_base, arch_framed_sets=arch_framed,
                skep_base_sets=skep_base, skep_framed_sets=skep_framed))

        # single joint positive control: drop the most-jointly-cited fact.
        arch_ctrl_cross: list[float] = []
        skep_ctrl_cross: list[float] = []
        arch_ctrl_exceeds = skep_ctrl_exceeds = False
        try:
            drop_fid = choose_control_drop_fact(base.packet, arch_base + skep_base)
            ctrl = build_positive_control_scenario(base, drop_fact_id=drop_fid)
            arch_ctrl, skep_ctrl = _resample_dual(
                ctrl, client=client, cycle_fn=cycle_fn, condition=CONDITION_CONTROL,
                operator_name=_CONTROL_SENTINEL, k=config.k_resamples, sink=records)
            arch_ctrl_cross = cross_distances(arch_base, arch_ctrl)
            skep_ctrl_cross = cross_distances(skep_base, skep_ctrl)
            acv = classify_operator(arch_ctrl_cross, arch_within,
                                    seed=config.seed, operator_name=_CONTROL_SENTINEL)
            scv = classify_operator(skep_ctrl_cross, skep_within,
                                    seed=config.seed, operator_name=_CONTROL_SENTINEL)
            arch_ctrl_exceeds = acv.effect_size > 0.0 and acv.p_value < 0.05
            skep_ctrl_exceeds = scv.effect_size > 0.0 and scv.p_value < 0.05
        except ValueError:
            pass

        scenario_results.append(ScenarioDualFramingResult(
            scenario_id=sid,
            architect=AgentFramingResult(
                agent=AGENT_ARCHITECT, within_distances=tuple(arch_within),
                control_distances=tuple(arch_ctrl_cross),
                control_exceeds_noise=arch_ctrl_exceeds, operator_results=tuple(arch_ops)),
            skeptic=AgentFramingResult(
                agent=AGENT_SKEPTIC, within_distances=tuple(skep_within),
                control_distances=tuple(skep_ctrl_cross),
                control_exceeds_noise=skep_ctrl_exceeds, operator_results=tuple(skep_ops)),
            mirror=tuple(mirror_records),
            skipped_operators=tuple(skipped),
        ))
        total_cost = sum(r.cost_usd for r in records)

    traces_dir = Path(config.traces_root) / run_id
    traces_dir.mkdir(parents=True, exist_ok=True)
    traces_path = traces_dir / "traces.jsonl"
    with traces_path.open("w", encoding="utf-8") as fh:
        for r in records:
            fh.write(json.dumps(r.to_dict(), sort_keys=True) + "\n")

    control_valid_architect = bool(scenario_results) and all(
        s.architect.control_exceeds_noise for s in scenario_results)
    control_valid_skeptic = bool(scenario_results) and all(
        s.skeptic.control_exceeds_noise for s in scenario_results)

    summary = DualAgentFramingSummary(
        run_id=run_id,
        timestamp_iso=datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        git_sha=_git_sha(), provider=config.provider, model=config.model,
        k_resamples=config.k_resamples, operator_names=config.operator_names,
        scenario_results=tuple(scenario_results), deferred_scenario_ids=deferred,
        control_valid_architect=control_valid_architect,
        control_valid_skeptic=control_valid_skeptic,
        total_cost_usd=total_cost, halt_reason=halt_reason, traces_path=str(traces_path),
    )
    (traces_dir / "summary.json").write_text(
        json.dumps(dataclasses.asdict(summary), indent=2, sort_keys=True), encoding="utf-8")
    return summary
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_runner.py -q`
Expected: PASS (all runner tests).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/dual_agent_framing_runner.py tests/dialectic/measurement/test_dual_agent_framing_runner.py
git commit -m "feat(s084): dual-agent run_measurement — per-agent verdicts + joint control + mirror"
```

---

## Task 5: Report module

**Files:**
- Create: `ares/dialectic/measurement/dual_agent_framing_report.py`
- Test: `tests/dialectic/measurement/test_dual_agent_framing_report.py`

- [ ] **Step 1: Write the failing tests**

```python
# tests/dialectic/measurement/test_dual_agent_framing_report.py
from ares.dialectic.measurement.architect_framing_schema import (
    OperatorFramingResult, VERDICT_REAL,
)
from ares.dialectic.measurement.dual_agent_framing_report import (
    render_report, write_report,
)
from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, AgentFramingResult, DualAgentFramingSummary,
    MirrorRecord, ScenarioDualFramingResult,
)


def _op(name, verdict=VERDICT_REAL):
    return OperatorFramingResult(
        operator_name=name, n_cross=16, cross_median=0.5, within_median=0.0,
        effect_size=0.5, p_value=0.001, ci_low=0.3, ci_high=0.7, verdict=verdict,
    )


def _summary(*, skep_control_ok=True, traces_path="t/traces.jsonl"):
    sr = ScenarioDualFramingResult(
        scenario_id="INJ-020",
        architect=AgentFramingResult(
            agent=AGENT_ARCHITECT, within_distances=(0.0,), control_distances=(1.0,),
            control_exceeds_noise=True, operator_results=(_op("framing_prefix_v1"),)),
        skeptic=AgentFramingResult(
            agent=AGENT_SKEPTIC, within_distances=(0.0,), control_distances=(1.0,),
            control_exceeds_noise=skep_control_ok, operator_results=(_op("framing_prefix_v1"),)),
        mirror=(MirrorRecord(
            scenario_id="INJ-020", operator_name="framing_prefix_v1",
            architect_jaccard=0.8, architect_direction="collapse",
            skeptic_jaccard=0.4, skeptic_direction="expand", mirror_class="opposed"),),
        skipped_operators=(),
    )
    return DualAgentFramingSummary(
        run_id="20260605-000000-abcdef", timestamp_iso="2026-06-05T00:00:00Z",
        git_sha="deadbee", provider="anthropic", model="claude-sonnet-4-20250514",
        k_resamples=20, operator_names=("framing_prefix_v1",), scenario_results=(sr,),
        deferred_scenario_ids=(), control_valid_architect=True,
        control_valid_skeptic=skep_control_ok, total_cost_usd=24.8,
        halt_reason="completed", traces_path=traces_path,
    )


def test_render_contains_both_agent_tables_and_mirror():
    text = render_report(_summary())
    assert "Architect path" in text
    assert "Skeptic path" in text
    assert "mirror" in text.lower()
    assert "opposed" in text
    assert "INJ-020" in text


def test_render_flags_control_unvalidated_agent():
    text = render_report(_summary(skep_control_ok=False))
    assert "control-unvalidated" in text
    assert "INJ-020 (skeptic)" in text


def test_write_report_writes_md_next_to_traces(tmp_path):
    traces = tmp_path / "traces.jsonl"
    traces.write_text("", encoding="utf-8")
    summary = _summary(traces_path=str(traces))
    out = write_report(summary)
    assert out.endswith(".md")
    assert "DUAL_AGENT_FRAMING_" in out
    from pathlib import Path
    assert Path(out).exists()
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_report.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the module**

```python
# ares/dialectic/measurement/dual_agent_framing_report.py
"""Markdown report renderer for the dual-agent framing measurement (Session 084)."""
from __future__ import annotations

from collections import Counter
from pathlib import Path

from ares.dialectic.measurement.dual_agent_framing_schema import DualAgentFramingSummary


def _agent_table(summary: DualAgentFramingSummary, attr: str, title: str) -> str:
    lines = [f"### {title} — per-operator verdicts\n",
             "| scenario | operator | within med | cross med | effect | p | verdict |",
             "|---|---|---|---|---|---|---|"]
    for s in summary.scenario_results:
        ar = getattr(s, attr)
        for op in ar.operator_results:
            lines.append(
                f"| {s.scenario_id} | {op.operator_name} | {op.within_median:.3f} | "
                f"{op.cross_median:.3f} | {op.effect_size:+.3f} | {op.p_value:.3f} | {op.verdict} |"
            )
    return "\n".join(lines)


def _mirror_table(summary: DualAgentFramingSummary) -> str:
    lines = ["### Dual-agent mirror — paired direction by condition\n",
             "| scenario | operator | arch jac | arch dir | skep jac | skep dir | mirror |",
             "|---|---|---|---|---|---|---|"]
    for s in summary.scenario_results:
        for m in s.mirror:
            lines.append(
                f"| {m.scenario_id} | {m.operator_name} | {m.architect_jaccard:.2f} | "
                f"{m.architect_direction} | {m.skeptic_jaccard:.2f} | {m.skeptic_direction} | "
                f"{m.mirror_class} |"
            )
    return "\n".join(lines)


def _control_section(summary: DualAgentFramingSummary) -> str:
    lines = ["### Positive-control validity\n",
             f"- control_valid_architect: **{summary.control_valid_architect}**",
             f"- control_valid_skeptic: **{summary.control_valid_skeptic}**"]
    flagged = []
    for s in summary.scenario_results:
        if not s.architect.control_exceeds_noise:
            flagged.append(f"{s.scenario_id} (architect)")
        if not s.skeptic.control_exceeds_noise:
            flagged.append(f"{s.scenario_id} (skeptic)")
    if flagged:
        lines.append("- control-unvalidated (result flagged): " + ", ".join(flagged))
    else:
        lines.append("- all scenarios control-valid for both agents")
    return "\n".join(lines)


def _mirror_summary(summary: DualAgentFramingSummary) -> str:
    c: Counter = Counter()
    for s in summary.scenario_results:
        for m in s.mirror:
            c[m.mirror_class] += 1
    parts = ", ".join(f"{k}={v}" for k, v in sorted(c.items()))
    return f"### Mirror summary\n\nmirror-class counts across all conditions: {parts or '(none)'}"


def render_report(summary: DualAgentFramingSummary) -> str:
    header = (
        f"# Dual-Agent Framing Measurement — {summary.run_id}\n\n"
        f"- git_sha: {summary.git_sha}\n"
        f"- provider/model: {summary.provider} / {summary.model}\n"
        f"- K resamples: {summary.k_resamples}\n"
        f"- operators: {', '.join(summary.operator_names)}\n"
        f"- scenarios: {len(summary.scenario_results)} "
        f"(deferred: {len(summary.deferred_scenario_ids)})\n"
        f"- total cost: ${summary.total_cost_usd:.2f}\n"
        f"- halt: {summary.halt_reason}\n"
    )
    return "\n\n".join([
        header,
        _agent_table(summary, "architect", "Architect path"),
        _agent_table(summary, "skeptic", "Skeptic path"),
        _mirror_table(summary),
        _control_section(summary),
        _mirror_summary(summary),
    ]) + "\n"


def write_report(summary: DualAgentFramingSummary) -> str:
    text = render_report(summary)
    out = Path(summary.traces_path).parent / f"DUAL_AGENT_FRAMING_{summary.run_id}.md"
    out.write_text(text, encoding="utf-8")
    return str(out)
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_report.py -q`
Expected: PASS (3 passed).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/measurement/dual_agent_framing_report.py tests/dialectic/measurement/test_dual_agent_framing_report.py
git commit -m "feat(s084): dual-agent framing markdown report"
```

---

## Task 6: CLI script

**Files:**
- Create: `scripts/run_session_084.py`
- Test: `tests/dialectic/measurement/test_dual_agent_framing_cli.py`

- [ ] **Step 1: Write the failing test (fast, no network — hard-cap rejection happens before the anchor guard)**

```python
# tests/dialectic/measurement/test_dual_agent_framing_cli.py
from scripts.run_session_084 import main


def test_cli_rejects_cost_ceiling_over_hard_cap(capsys):
    rc = main(["--provider", "anthropic", "--cost-ceiling", "9999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_cli.py -q`
Expected: FAIL — module not found.

- [ ] **Step 3: Write the CLI (mirrors `scripts/run_session_077.py`)**

```python
# scripts/run_session_084.py
"""Session 084 — Dual-agent framing-sensitivity measurement CLI.

Mirrors run_session_077.py: UTF-16 .env load, anchor guard, preflight ->
--confirm-live gate, cost-ceiling hard cap. Records BOTH agents' cited facts and
the paired mirror.
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
from ares.dialectic.measurement.dual_agent_framing_schema import (
    DualAgentFramingConfig, DUAL_AGENT_FRAMING_HARD_CEILING_USD,
)
from ares.dialectic.measurement.dual_agent_framing_runner import run_measurement, run_preflight
from ares.dialectic.measurement.dual_agent_framing_report import write_report
from ares.dialectic.measurement.architect_framing_selection import select_diverging_scenarios
from ares.dialectic.measurement.leakage_runner import DEFAULT_TRACES_ROOT, anchor_test_passes

_DEFAULT_S059 = DEFAULT_TRACES_ROOT / "20260510-193950-f401a8" / "traces.jsonl"


def main(argv: list[str] | None = None) -> int:
    logging.basicConfig(level=logging.INFO, format="[%(asctime)s] %(levelname)s :: %(message)s",
                        datefmt="%H:%M:%S")
    p = argparse.ArgumentParser(description="Session 084 — Dual-agent framing measurement")
    p.add_argument("--provider", required=True, choices=sorted(VALID_PROVIDERS))
    p.add_argument("--model", default=None)
    p.add_argument("--k", type=int, default=20)
    p.add_argument("--max-scenarios", type=int, default=17)
    p.add_argument("--s059-traces", default=str(_DEFAULT_S059))
    p.add_argument("--cost-ceiling", type=float, default=32.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > DUAL_AGENT_FRAMING_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${DUAL_AGENT_FRAMING_HARD_CEILING_USD}; refusing.", file=sys.stderr)
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

    sids = tuple(select_diverging_scenarios(Path(args.s059_traces)))
    cfg = DualAgentFramingConfig(
        s059_traces_path=Path(args.s059_traces), scenario_ids=sids, k_resamples=args.k,
        max_scenarios=args.max_scenarios, model=model, provider=args.provider,
        cost_ceiling_usd=args.cost_ceiling,
    )
    print(f"[config] provider={args.provider} model={model} k={args.k} "
          f"scenarios={len(sids)} (cap {args.max_scenarios}) ceiling=${args.cost_ceiling}")

    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(args.provider, model=model)

    print("[2/3] pre-flight estimator ...")
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
    print(f"control_valid arch/skep: {summary.control_valid_architect}/"
          f"{summary.control_valid_skeptic}  cost: ${summary.total_cost_usd:.2f}")
    print(f"report: {report}")
    print(f"traces: {summary.traces_path}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_cli.py -q`
Expected: PASS (1 passed).

- [ ] **Step 5: Commit**

```bash
git add scripts/run_session_084.py tests/dialectic/measurement/test_dual_agent_framing_cli.py
git commit -m "feat(s084): dual-agent framing CLI (preflight-gated, hard cost cap)"
```

---

## Task 7: Offline verification checkpoint (zero-regression)

**Files:** none (verification only)

- [ ] **Step 1: Run the full new test set + a broad slice**

Run: `python -m pytest tests/dialectic/measurement/ -q`
Expected: PASS — all new + existing measurement tests green.

- [ ] **Step 2: Confirm no existing file was modified**

Run: `git diff --name-only main...HEAD`
Expected: only NEW files under `ares/dialectic/measurement/dual_agent_framing_*.py`, `scripts/run_session_084.py`, `tests/dialectic/measurement/test_dual_agent_framing_*.py`, and the spec/plan docs. No pre-existing source file appears.

- [ ] **Step 3: Run the whole suite**

Run: `python -m pytest tests/ ares/ -q`
Expected: PASS, 0 failures; pass count = prior floor (3,937+) + the new tests. Record the new total for the CLAUDE.md floor update in Task 9.

---

## Task 8: LIVE run (gated — preflight checkpoint, then ~$25 spend)

**Files:** produces `data/paper_3/leakage_runs/<run_id>/` (traces.jsonl, summary.json, DUAL_AGENT_FRAMING_<run_id>.md)

> This task spends live API. Dan authorized the full run during brainstorming. Still gate on the preflight projection.

- [ ] **Step 1: Preflight only — confirm the projection lands near $25 and under ceiling**

Run: `python scripts/run_session_084.py --provider anthropic --preflight-only`
Expected: prints `est total: ~$24-26`, `cycles: 1700` (or fewer if a no-op operator drops a batch), `exceeds_ceiling: False`. If `exceeds_ceiling: True` or the projection is materially above ~$30, STOP and report to Dan before proceeding.

- [ ] **Step 2: Full live run**

Run: `python scripts/run_session_084.py --provider anthropic --confirm-live`
Expected: completes; prints `control_valid arch/skep`, `cost ~$25`, the report path, and the traces path. Wall time ~30-60 min.

- [ ] **Step 3: Sanity-read the result**

Run: `python -m pytest tests/dialectic/measurement/test_dual_agent_framing_report.py -q` (still green) and open the generated `DUAL_AGENT_FRAMING_<run_id>.md`. Confirm: the mirror table is populated; `control_valid_architect`/`control_valid_skeptic` reported; the Architect verdicts are broadly consistent with S082 (REAL on a similar subset — qualitative cross-check).

---

## Task 9: Writeup + CLAUDE.md + finish

**Files:**
- Create: `docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md`
- Modify: `CLAUDE.md` (floor, Key Code Locations, Branch, Where We Are)

- [ ] **Step 1: Write the result doc**

Summarize: per-agent REAL/NOISE verdict counts; the mirror-class tally (how many conditions `opposed`); control validity per agent + any flagged scenarios; the Architect-vs-S082 consistency note; honest caveats (single joint control; 17-scenario mirror set). Point to the run dir + report.

- [ ] **Step 2: Update CLAUDE.md**

Set the test-count floor to the Task 7 total. Add a "Dual-agent framing measurement (Phase 7 / Session 084)" block under Key Code Locations listing the five new modules + the CLI + the run dir. Add a Branch ground-truth line and a "Where We Are" bullet. If CLAUDE.md approaches the 40k ceiling, roll the oldest "Where We Are" bullet / full session down to `docs/SESSION_LOG.md` first (it was at ~38.1k post-S083).

- [ ] **Step 3: Run the freshness test + full suite**

Run: `python -m pytest tests/test_claude_md_freshness.py tests/dialectic/measurement/ -q`
Expected: PASS (floor + canonical-path + ISO-date checks green).

- [ ] **Step 4: Commit**

```bash
git add docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md CLAUDE.md data/paper_3/leakage_runs
git commit -m "docs(s084): dual-agent framing live result + CLAUDE.md ground-truth"
```

- [ ] **Step 5: Finish the branch**

Invoke the `superpowers:finishing-a-development-branch` skill: confirm zero regressions (`pytest tests/ ares/`), squash-merge `session/084-dual-agent-framing` to `main`, retain the branch on origin as an audit trail, then crystalize.

---

## Self-review

**Spec coverage:**
- §3 reuse / new-files-only → Task 1-6 create only new files; Task 7 Step 2 asserts no existing file changed. ✓
- §5 data model → Task 1 (all dataclasses + guards + to_dict). ✓
- §6 flow + joint control → Task 4 (`run_measurement`, joint `choose_control_drop_fact(packet, arch_base + skep_base)`, per-agent `control_exceeds_noise`). ✓
- §7 mirror → Task 2 (`direction`/`modal_set`/`classify_mirror`/`build_mirror_record`, exhaustive incl. `mixed`, deterministic tie-break). ✓
- §8 CLI + gating → Task 6 + Task 8. ✓
- §9 testing → Tasks 1-6 are TDD; the end-to-end mirror-opposed fixture is Task 4. ✓
- §10 deliverables/zero-regression/housekeeping → Tasks 7, 9. ✓
- §12 cross-checks → Task 8 Step 3 (Architect-vs-S082), mirror-paired-by-construction (Task 4 uses the same K cycles). ✓

**Known accepted gap:** the `SkeletonInvariantError` operator-skip path (spec §9) is implemented verbatim from the reviewed S077 runner but has no dedicated offline test — forcing a mutator no-op offline is brittle (the runner builds its own `PairedScenarioMutator`). It is exercised live in Task 8 and is a 3-line reuse of proven code. Acceptable; noted rather than hidden.

**Placeholder scan:** no TBD/TODO; every code step shows complete code; every run step shows the command + expected outcome. ✓

**Type consistency:** `DualAgentResampleRecord` field names match between schema (Task 1), `_resample_dual` (Task 3), and tests; `AgentFramingResult`/`ScenarioDualFramingResult`/`DualAgentFramingSummary` field names match between schema, `run_measurement` (Task 4), and report (Task 5). `write_report` returns `str` (path); CLI prints it. `run_preflight`/`run_measurement`/`total_cycles_for` signatures match between runner and tests/CLI. ✓
