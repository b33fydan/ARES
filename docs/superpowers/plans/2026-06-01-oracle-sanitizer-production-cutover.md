# Oracle Sanitizer Production Cutover — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Make the S078 Oracle `supporting_fact_ids` sanitizer live on the production path via an opt-in default-off flag on three cycles plus a sanitized-by-default `run_production_cycle` entrypoint, while the measurement/Paper-3 path stays leaky.

**Architecture:** Add a keyword-only `sanitize_supporting_facts: bool = False` to `run_cycle_with_strategies`, `run_guarded_cycle`, and `run_light_guarded_cycle`. When set, lazily import and apply `verdict_sanitizer.sanitize_verdict(verdict, packet)` immediately after `OracleJudge.compute_verdict(...)` and before the OracleNarrator is built. A new thin wrapper `run_production_cycle` calls the single-turn cycle with the flag on. Default-off ⇒ every existing caller (incl. the leakage measurement harness) is byte-identical.

**Tech Stack:** Python 3.11, pytest. Offline/deterministic tests only (MagicMock strategies; no live LLM).

**Spec:** `docs/superpowers/specs/2026-06-01-oracle-sanitizer-production-cutover-design.md`

---

## File Structure

**Modified (additive, default-preserving):**
- `ares/dialectic/agents/strategies/live_cycle.py` — `run_cycle_with_strategies`: +param, +seam.
- `ares/dialectic/agents/strategies/guarded_cycle.py` — `run_guarded_cycle`: +param, +seam.
- `ares/dialectic/agents/strategies/light_guarded_cycle.py` — `run_light_guarded_cycle`: +param, +seam.
- `CLAUDE.md` — last-updated, floor, Key Code Locations, S079 ledger, Branch.

**New:**
- `ares/dialectic/agents/strategies/production_cycle.py` — `run_production_cycle`.
- `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` — flag tests for all three cycles + cycle-level framing-invariance proof-of-fix.
- `ares/dialectic/tests/agents/strategies/test_production_cycle.py` — entrypoint tests.

**Untouched (must stay green):** `ares/dialectic/agents/oracle.py`, `ares/dialectic/agents/verdict_sanitizer.py`, `ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py`, `tests/dialectic/measurement/test_paired_trial_byte_stability.py`, `ares/dialectic/measurement/leakage_runner.py`.

**Note on imports/exports:** the sibling cycles are imported from their own modules (e.g. `from ares.dialectic.agents.strategies.guarded_cycle import run_guarded_cycle`), not re-exported from a package `__init__`. Follow that convention: `run_production_cycle` is imported from `ares.dialectic.agents.strategies.production_cycle`. No `__init__.py` change.

---

## Task 1: Flag on `run_cycle_with_strategies` (single-turn)

**Files:**
- Test: `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` (create)
- Modify: `ares/dialectic/agents/strategies/live_cycle.py`

- [ ] **Step 1: Write the failing test file**

Create `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py`:

```python
"""Opt-in sanitize_supporting_facts flag on the production cycles.

Offline/deterministic (MagicMock strategies; no live LLM). Default path
(flag off) stays leaky (Architect citations pass through); flag on
re-derives supporting_fact_ids from the packet via verdict_sanitizer.
"""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.verdict_sanitizer import (
    relevant_fact_ids,
    sanitize_verdict,
)
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


# --- inline helpers (per the project's inline-helpers test convention) ---

def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="flag-test",
        extracted_at=datetime(2026, 6, 1, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 6, 1, 12, 0, 0),
        provenance=_prov(),
    )


def _packet(field_by_id: dict[str, str], packet_id: str = "flag-pkt") -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id=packet_id,
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in field_by_id.items():
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _confirmed_packet() -> EvidencePacket:
    # stages (per _STAGE_MAP): src_ip=0, port_scan=1, data=2 (default).
    # max-stage set = {f-exec}; architect will cite the low-stage facts.
    return _packet({"f-recon": "src_ip", "f-scan": "port_scan", "f-exec": "data"})


def _analyzer(fact_ids, confidence: float = 0.85) -> MagicMock:
    """Stub ThreatAnalyzer citing a chosen fact set at a chosen confidence."""
    m = MagicMock()
    m.analyze_threats.return_value = [
        AnomalyPattern(
            pattern_type=PatternType.PRIVILEGE_ESCALATION,
            fact_ids=frozenset(fact_ids),
            confidence=confidence,
            description="stub anomaly",
        ),
    ]
    return m


def _finder_empty() -> MagicMock:
    """Stub ExplanationFinder with no benign explanations -> low Skeptic conf."""
    m = MagicMock()
    m.find_explanations.return_value = []
    return m


# --- live cycle ---

def test_live_cycle_flag_off_is_leaky():
    pkt = _confirmed_packet()
    res = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Default path cites what the Architect cited (the leak).
    assert res.verdict.supporting_fact_ids == frozenset({"f-recon", "f-scan"})


def test_live_cycle_flag_on_is_sanitized():
    pkt = _confirmed_packet()
    res = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Sanitized = packet max-stage set, NOT the architect's citations.
    assert res.verdict.supporting_fact_ids == frozenset({"f-exec"})
    assert res.verdict.supporting_fact_ids == relevant_fact_ids(pkt, res.verdict.outcome)


def test_live_cycle_flag_preserves_decision():
    pkt = _confirmed_packet()
    off = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    on = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    # Decision determinism: outcome + confidence unchanged.
    assert off.verdict.outcome == on.verdict.outcome
    assert off.verdict.confidence == on.verdict.confidence
    # on == sanitize(off): the flag transforms only the cited set.
    assert on.verdict.supporting_fact_ids == sanitize_verdict(off.verdict, pkt).supporting_fact_ids
    assert off.verdict.supporting_fact_ids != on.verdict.supporting_fact_ids
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -v`
Expected: the `flag_off` test PASSES (default behavior already exists), but `flag_on` and `preserves_decision` FAIL with `TypeError: run_cycle_with_strategies() got an unexpected keyword argument 'sanitize_supporting_facts'`.

- [ ] **Step 3: Add the parameter to the signature**

In `ares/dialectic/agents/strategies/live_cycle.py`, edit the `run_cycle_with_strategies` signature — add the keyword-only param after `include_narration`:

```python
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
    sanitize_supporting_facts: bool = False,
) -> CycleResult:
```

- [ ] **Step 4: Insert the sanitization seam**

In the same function, find the verdict-computation block that ends just before the SYNTHESIS comment:

```python
    # --- SYNTHESIS phase (optional narration) ---
    narrator_message: Optional[DialecticalMessage] = None
```

Insert, immediately ABOVE that `# --- SYNTHESIS phase (optional narration) ---` line:

```python
    # --- Optional supporting_fact_ids sanitization (opt-in, default off) ---
    # Re-derive the verdict's cited facts from the packet alone so framing
    # cannot move them. Done before the narrator so the narration cites the
    # sanitized set. Lazy import keeps the default path's import graph intact.
    if sanitize_supporting_facts:
        from ares.dialectic.agents.verdict_sanitizer import sanitize_verdict
        verdict = sanitize_verdict(verdict, packet)

```

(Also add one line to the docstring's Args, e.g. `sanitize_supporting_facts: If True, re-derive Verdict.supporting_fact_ids from the packet (framing-invariant). Default False = legacy passthrough.`)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -v`
Expected: all three live-cycle tests PASS.

- [ ] **Step 6: Commit**

```bash
git add ares/dialectic/agents/strategies/live_cycle.py ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py
git commit -m "feat(s079): opt-in sanitize_supporting_facts flag on run_cycle_with_strategies"
```

---

## Task 2: Flag on `run_guarded_cycle` (firewall + hot-swap)

**Files:**
- Modify: `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` (append)
- Modify: `ares/dialectic/agents/strategies/guarded_cycle.py`

- [ ] **Step 1: Append the failing guarded-cycle tests**

Read the test file, then append (after the live-cycle tests). It reuses the helpers already defined at the top of the file (`_confirmed_packet`, `_analyzer`, `_finder_empty`); add the import for the guarded cycle at the top with the other cycle imports:

```python
from ares.dialectic.agents.strategies.guarded_cycle import run_guarded_cycle
```

Appended tests:

```python
# --- guarded cycle ---

def test_guarded_cycle_flag_off_is_leaky():
    pkt = _confirmed_packet()
    res = run_guarded_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        firewall=None,
        enable_hot_swap=False,
    )
    v = res.cycle_result.verdict
    assert v.outcome == VerdictOutcome.THREAT_CONFIRMED
    assert v.supporting_fact_ids == frozenset({"f-recon", "f-scan"})


def test_guarded_cycle_flag_on_is_sanitized():
    pkt = _confirmed_packet()
    res = run_guarded_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        firewall=None,
        enable_hot_swap=False,
        sanitize_supporting_facts=True,
    )
    v = res.cycle_result.verdict
    assert v.outcome == VerdictOutcome.THREAT_CONFIRMED
    assert v.supporting_fact_ids == frozenset({"f-exec"})
    assert v.supporting_fact_ids == relevant_fact_ids(pkt, v.outcome)


def test_guarded_cycle_flag_preserves_decision():
    pkt = _confirmed_packet()
    off = run_guarded_cycle(
        pkt, threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(), firewall=None, enable_hot_swap=False,
    )
    on = run_guarded_cycle(
        pkt, threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(), firewall=None, enable_hot_swap=False,
        sanitize_supporting_facts=True,
    )
    off_v, on_v = off.cycle_result.verdict, on.cycle_result.verdict
    assert off_v.outcome == on_v.outcome
    assert off_v.confidence == on_v.confidence
    assert on_v.supporting_fact_ids == sanitize_verdict(off_v, pkt).supporting_fact_ids
    assert off_v.supporting_fact_ids != on_v.supporting_fact_ids
```

- [ ] **Step 2: Run the new tests to verify they fail**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -k guarded -v`
Expected: `flag_off` PASSES; `flag_on` and `preserves_decision` FAIL with `TypeError: run_guarded_cycle() got an unexpected keyword argument 'sanitize_supporting_facts'`.

- [ ] **Step 3: Add the parameter to the signature**

In `ares/dialectic/agents/strategies/guarded_cycle.py`, in `run_guarded_cycle`, add the keyword-only param after `include_narration`:

```python
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
    sanitize_supporting_facts: bool = False,
) -> GuardedCycleResult:
```

- [ ] **Step 4: Insert the sanitization seam**

Find the SYNTHESIS comment line in `run_guarded_cycle`:

```python
    # --- SYNTHESIS phase (optional narration) ---
    narrator_message: Optional[DialecticalMessage] = None
```

Insert immediately ABOVE it:

```python
    # --- Optional supporting_fact_ids sanitization (opt-in, default off) ---
    if sanitize_supporting_facts:
        from ares.dialectic.agents.verdict_sanitizer import sanitize_verdict
        verdict = sanitize_verdict(verdict, packet)

```

(Add the same one-line docstring Args note as Task 1.)

- [ ] **Step 5: Run the tests to verify they pass**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -k guarded -v`
Expected: all three guarded-cycle tests PASS.

- [ ] **Step 6: Commit**

```bash
git add ares/dialectic/agents/strategies/guarded_cycle.py ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py
git commit -m "feat(s079): opt-in sanitize_supporting_facts flag on run_guarded_cycle"
```

---

## Task 3: Flag on `run_light_guarded_cycle` (Light Skeptic)

**Files:**
- Modify: `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` (append)
- Modify: `ares/dialectic/agents/strategies/light_guarded_cycle.py`

- [ ] **Step 1: Append the failing light-cycle tests**

Add the import at the top with the other cycle imports:

```python
from ares.dialectic.agents.strategies.light_guarded_cycle import run_light_guarded_cycle
```

Append (outcome-agnostic: the Light Skeptic's deterministic judgment drives the outcome, so assert the contract for whatever outcome results):

```python
# --- light guarded cycle (Light Skeptic; outcome-agnostic assertions) ---

def test_light_cycle_flag_on_matches_rule_and_preserves_decision():
    pkt = _confirmed_packet()
    off = run_light_guarded_cycle(
        pkt, threat_analyzer=_analyzer(["f-recon", "f-scan"]), firewall=None,
    )
    on = run_light_guarded_cycle(
        pkt, threat_analyzer=_analyzer(["f-recon", "f-scan"]), firewall=None,
        sanitize_supporting_facts=True,
    )
    off_v, on_v = off.cycle_result.verdict, on.cycle_result.verdict
    # Fix: on-path cited set == the packet-derived rule for that outcome.
    assert on_v.supporting_fact_ids == relevant_fact_ids(pkt, on_v.outcome)
    # on == sanitize(off).
    assert on_v.supporting_fact_ids == sanitize_verdict(off_v, pkt).supporting_fact_ids
    # Decision determinism.
    assert off_v.outcome == on_v.outcome
    assert off_v.confidence == on_v.confidence
```

- [ ] **Step 2: Run the new test to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -k light -v`
Expected: FAIL with `TypeError: run_light_guarded_cycle() got an unexpected keyword argument 'sanitize_supporting_facts'`.

- [ ] **Step 3: Add the parameter to the signature**

In `ares/dialectic/agents/strategies/light_guarded_cycle.py`, in `run_light_guarded_cycle`, add the param after `include_narration`:

```python
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
    sanitize_supporting_facts: bool = False,
) -> LightGuardedCycleResult:
```

- [ ] **Step 4: Insert the sanitization seam**

Find the optional-narration comment in `run_light_guarded_cycle`:

```python
    # --- Optional narration ---
    narrator_message: Optional[DialecticalMessage] = None
```

Insert immediately ABOVE it:

```python
    # --- Optional supporting_fact_ids sanitization (opt-in, default off) ---
    if sanitize_supporting_facts:
        from ares.dialectic.agents.verdict_sanitizer import sanitize_verdict
        verdict = sanitize_verdict(verdict, packet)

```

(Add the same one-line docstring Args note.)

- [ ] **Step 5: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -k light -v`
Expected: PASS.

- [ ] **Step 6: Commit**

```bash
git add ares/dialectic/agents/strategies/light_guarded_cycle.py ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py
git commit -m "feat(s079): opt-in sanitize_supporting_facts flag on run_light_guarded_cycle"
```

---

## Task 4: Cycle-level framing-invariance proof-of-fix (test only)

**Files:**
- Modify: `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` (append)

No production change — this exercises the Task 1 flag. It is the cycle-boundary analog of `test_verdict_sanitizer_invariance_anchor.py`: two framings cite different facts (same count + confidence ⇒ same outcome); default path leaks (cited sets differ), sanitized path does not.

- [ ] **Step 1: Append the invariance test**

```python
# --- cycle-level framing invariance (before/after proof-of-fix) ---

def _invariance_packet() -> EvidencePacket:
    # Three stage-0 (src_ip) recon facts to draw two distinct 2-subsets from,
    # and two stage-2 (data) facts as the stable max-stage set.
    return _packet(
        {
            "f-r1": "src_ip", "f-r2": "src_ip", "f-r3": "src_ip",
            "f-exec": "data", "f-exec2": "data",
        },
        packet_id="inv-pkt",
    )


def test_cycle_framing_invariance_before_and_after():
    pkt = _invariance_packet()
    framing_a = ["f-r1", "f-r2"]
    framing_b = ["f-r2", "f-r3"]  # different identities, same count + confidence

    # Default path: the leak is visible — cited sets differ under reframing.
    off_a = run_cycle_with_strategies(
        pkt, threat_analyzer=_analyzer(framing_a), explanation_finder=_finder_empty(),
    )
    off_b = run_cycle_with_strategies(
        pkt, threat_analyzer=_analyzer(framing_b), explanation_finder=_finder_empty(),
    )
    assert off_a.verdict.outcome == off_b.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    assert off_a.verdict.supporting_fact_ids != off_b.verdict.supporting_fact_ids

    # Sanitized path: reframing no longer moves the cited set (the fix).
    on_a = run_cycle_with_strategies(
        pkt, threat_analyzer=_analyzer(framing_a), explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    on_b = run_cycle_with_strategies(
        pkt, threat_analyzer=_analyzer(framing_b), explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    assert on_a.verdict.supporting_fact_ids == on_b.verdict.supporting_fact_ids
    assert on_a.verdict.supporting_fact_ids == relevant_fact_ids(pkt, VerdictOutcome.THREAT_CONFIRMED)
    assert on_a.verdict.supporting_fact_ids == frozenset({"f-exec", "f-exec2"})

    # Decision surface preserved across the reframing.
    assert on_a.verdict.confidence == off_a.verdict.confidence
```

- [ ] **Step 2: Run the test to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py -k invariance -v`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py
git commit -m "test(s079): cycle-level framing-invariance proof-of-fix for the sanitize flag"
```

---

## Task 5: `run_production_cycle` entrypoint

**Files:**
- Create: `ares/dialectic/agents/strategies/production_cycle.py`
- Test: `ares/dialectic/tests/agents/strategies/test_production_cycle.py` (create)

- [ ] **Step 1: Write the failing test file**

Create `ares/dialectic/tests/agents/strategies/test_production_cycle.py`:

```python
"""run_production_cycle: single-turn production cycle, sanitized by default."""
from __future__ import annotations

from datetime import datetime
from unittest.mock import MagicMock

from ares.dialectic.agents.patterns import (
    AnomalyPattern,
    PatternType,
    VerdictOutcome,
)
from ares.dialectic.agents.verdict_sanitizer import relevant_fact_ids
from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies
from ares.dialectic.agents.strategies.production_cycle import run_production_cycle
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="prod-test",
        extracted_at=datetime(2026, 6, 1, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 6, 1, 12, 0, 0),
        provenance=_prov(),
    )


def _confirmed_packet() -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="prod-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in (("f-recon", "src_ip"), ("f-scan", "port_scan"), ("f-exec", "data")):
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _analyzer(fact_ids, confidence: float = 0.85) -> MagicMock:
    m = MagicMock()
    m.analyze_threats.return_value = [
        AnomalyPattern(
            pattern_type=PatternType.PRIVILEGE_ESCALATION,
            fact_ids=frozenset(fact_ids),
            confidence=confidence,
            description="stub anomaly",
        ),
    ]
    return m


def _finder_empty() -> MagicMock:
    m = MagicMock()
    m.find_explanations.return_value = []
    return m


def test_production_cycle_sanitizes_by_default():
    pkt = _confirmed_packet()
    res = run_production_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    assert res.verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Sanitized cited set out of the box (no flag passed by the caller).
    assert res.verdict.supporting_fact_ids == frozenset({"f-exec"})
    assert res.verdict.supporting_fact_ids == relevant_fact_ids(pkt, res.verdict.outcome)


def test_production_cycle_matches_flagged_underlying():
    pkt = _confirmed_packet()
    prod = run_production_cycle(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
    )
    flagged = run_cycle_with_strategies(
        pkt,
        threat_analyzer=_analyzer(["f-recon", "f-scan"]),
        explanation_finder=_finder_empty(),
        sanitize_supporting_facts=True,
    )
    assert prod.verdict.outcome == flagged.verdict.outcome
    assert prod.verdict.confidence == flagged.verdict.confidence
    assert prod.verdict.supporting_fact_ids == flagged.verdict.supporting_fact_ids
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_production_cycle.py -v`
Expected: FAIL at import — `ModuleNotFoundError: No module named 'ares.dialectic.agents.strategies.production_cycle'`.

- [ ] **Step 3: Write the entrypoint module**

Create `ares/dialectic/agents/strategies/production_cycle.py`:

```python
"""Production single-turn cycle: the leak-closed live path.

run_production_cycle is a thin peer of run_cycle_with_strategies with the
Oracle supporting_fact_ids sanitizer turned ON by default. It is the one
blessed entrypoint that emits framing-invariant Verdict.supporting_fact_ids.
The measurement/Paper-3 harness keeps the default (leaky) path and is
unaffected, because it calls the underlying cycles directly without the flag.
"""
from __future__ import annotations

from typing import Optional, TYPE_CHECKING

from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies

if TYPE_CHECKING:
    from ares.dialectic.coordinator.orchestrator import CycleResult
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.agents.strategies.protocol import (
        ExplanationFinder,
        NarrativeGenerator,
        ThreatAnalyzer,
    )


def run_production_cycle(
    packet: "EvidencePacket",
    *,
    threat_analyzer: "Optional[ThreatAnalyzer]" = None,
    explanation_finder: "Optional[ExplanationFinder]" = None,
    narrative_generator: "Optional[NarrativeGenerator]" = None,
    agent_id_prefix: str = "ares",
    include_narration: bool = True,
) -> "CycleResult":
    """Single-turn production cycle with sanitized supporting_fact_ids.

    Thin wrapper over run_cycle_with_strategies with
    sanitize_supporting_facts=True. Argument semantics are identical to that
    function; this entrypoint exists so production callers get the leak-closed
    behavior by default while the measurement path stays on the leaky default.
    """
    return run_cycle_with_strategies(
        packet,
        threat_analyzer=threat_analyzer,
        explanation_finder=explanation_finder,
        narrative_generator=narrative_generator,
        agent_id_prefix=agent_id_prefix,
        include_narration=include_narration,
        sanitize_supporting_facts=True,
    )
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest ares/dialectic/tests/agents/strategies/test_production_cycle.py -v`
Expected: both tests PASS.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/strategies/production_cycle.py ares/dialectic/tests/agents/strategies/test_production_cycle.py
git commit -m "feat(s079): run_production_cycle entrypoint (sanitized by default)"
```

---

## Task 6: Full suite + CLAUDE.md ground-truth update

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Run the full suite and capture the passing count**

Run: `python -m pytest tests/ ares/dialectic/tests/ -q`
Expected: `0 failed`. Note the `N passed` count (was 4158 at `ca852bb`; expect 4158 + the new tests = ~4170).

- [ ] **Step 2: Confirm the untouched anchors are green**

Run:
```bash
python -m pytest ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py tests/dialectic/measurement/test_paired_trial_byte_stability.py ares/dialectic/tests/agents/test_verdict_sanitizer.py ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py -q
```
Expected: all PASS (no edits were made to `oracle.py` or the sanitizer; the leak/measurement contract is intact).

- [ ] **Step 3: Update CLAUDE.md ground truth**

Make these edits in `CLAUDE.md`:

1. Header `**Last updated:**` → `2026-06-02`.
2. `**Test count floor (passing):**` → the `N passed` value from Step 1 (a true minimum; the freshness test asserts `actual >= floor`, so never set it above the measured passing count).
3. Under `## Key Code Locations` → add to the strategies/cutover area:
   - `- Production cutover flag: \`sanitize_supporting_facts\` on \`run_cycle_with_strategies\` / \`run_guarded_cycle\` / \`run_light_guarded_cycle\` (opt-in, default off; lazy-applies \`verdict_sanitizer.sanitize_verdict\` after \`compute_verdict\`).`
   - `- Sanitized production entrypoint: \`ares/dialectic/agents/strategies/production_cycle.py\` — \`run_production_cycle\` (single-turn, sanitized by default).`
4. Add a Session 079 ledger entry under "Last 3 sessions (full)" (and roll the oldest full session to `docs/SESSION_LOG.md` if the ledger nears the 40k ceiling), summarizing: opt-in flag wired into the three production cycles + `run_production_cycle`; measurement/Paper-3 path unchanged (default off); offline-only; full suite `N`/75skip/0fail.
5. Update the `## Branch` section to note `session/079-oracle-sanitizer-production-cutover` and its merge once squashed.

- [ ] **Step 4: Verify the freshness self-test passes**

Run: `python -m pytest tests/test_claude_md_freshness.py -v`
Expected: all PASS (floor parseable + `actual >= floor`; canonical paths exist; last-updated is a valid past ISO date).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(s079): wire-in debrief + ground-truth (floor, key locations, ledger, branch)"
```

---

## Self-Review

**Spec coverage:**
- §1 seam on three cycles → Tasks 1, 2, 3. ✓
- §2 `run_production_cycle` entrypoint → Task 5. ✓
- §3 tests: off=leaky / on=sanitized / determinism → Tasks 1–3; cycle-level framing-invariance proof-of-fix → Task 4; entrypoint default-on + equivalence → Task 5; leak-persists/anchors-green guard → Task 6 Step 2. ✓
- §4 safety + docs: anchors untouched/green (Task 6 Step 2); CLAUDE.md floor/locations/ledger/branch (Task 6 Step 3). ✓
- Non-goals: `run_ablated_cycle` and `run_multi_turn_with_strategies` are never modified (not referenced in any task). ✓

**Placeholder scan:** No TBD/TODO; every code step shows complete code; every run step shows the exact command + expected result. ✓

**Type/name consistency:** `sanitize_supporting_facts` (param) vs `sanitize_verdict` (function) — distinct, used consistently. Result accessors consistent: `.verdict` for `run_cycle_with_strategies`/`run_production_cycle` (CycleResult); `.cycle_result.verdict` for `run_guarded_cycle`/`run_light_guarded_cycle`. Stub helpers (`_analyzer`, `_finder_empty`, `_confirmed_packet`) defined in Task 1 and reused in Tasks 2–4; re-defined inline in Task 5's separate file. ✓

**Determinism check:** single AnomalyPattern @0.85 ⇒ Architect msg confidence 0.85; empty ExplanationFinder ⇒ Skeptic confidence `0.3 - 0.85*0.1 = 0.215` (< 0.5) ⇒ THREAT_CONFIRMED ⇒ leaky cited set = Architect facts. Stage map: `src_ip=0, port_scan=1, data=2` ⇒ max-stage sanitized set is predictable. ✓
