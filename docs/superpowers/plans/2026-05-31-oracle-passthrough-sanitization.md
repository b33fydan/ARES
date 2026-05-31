# Oracle `supporting_fact_ids` Sanitization — Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add a deterministic, opt-in peer that re-derives `Verdict.supporting_fact_ids` from the EvidencePacket (not the Architect's framing-sensitive citations), closing the oracle-layer passthrough leak without touching `oracle.py` or Paper 3 reproducibility.

**Architecture:** One new pure-Python module `ares/dialectic/agents/verdict_sanitizer.py` with three functions — `relevant_fact_ids` (outcome-conditioned kill-chain rule over the packet), `sanitize_verdict` (frozen-dataclass copy replacing only `supporting_fact_ids`), and `create_sanitized_oracle_verdict` (opt-in factory mirroring `oracle.create_oracle_verdict`). Two new test files prove the rule and lock the fixed (drift-free) behavior. Nothing existing is modified.

**Tech Stack:** Python 3.11, pytest, frozen `dataclasses`. Reuses `_STAGE_MAP`/`_DEFAULT_STAGE` (`agents.light_skeptic`) and `_AUTHORIZATION_FACT_FIELDS`/`_BENIGN_INDICATOR_FIELDS` (`coordinator.firewall`).

**Spec:** `docs/superpowers/specs/2026-05-31-oracle-passthrough-sanitization-design.md`

---

## File Structure

| File | Responsibility |
|---|---|
| `ares/dialectic/agents/verdict_sanitizer.py` (NEW) | The three public functions. Pure, deterministic, no LLM, no state. |
| `ares/dialectic/tests/agents/test_verdict_sanitizer.py` (NEW) | Unit + integration tests for all three functions. |
| `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py` (NEW) | Documentary anchor: proves architect citation-drift no longer reaches `supporting_fact_ids`. Complements (never edits) the passthrough anchor. |
| `oracle.py`, `test_oracle_supporting_fact_ids_passthrough.py`, `firewall.py`, `light_skeptic.py`, cycles, `influence_leakage.py` | **UNTOUCHED.** |

Verified APIs (from existing code, do not re-discover):
- `Verdict` is `@dataclass(frozen=True)` with fields `outcome, confidence, supporting_fact_ids, architect_confidence, skeptic_confidence, reasoning`.
- `OracleJudge.compute_verdict(architect_msg, skeptic_msg, packet) -> Verdict`. CONFIRMED when `arch_conf>=0.7 and skep_conf<0.5`; final `confidence == arch_confidence`.
- `OracleNarrator(verdict=...)`; `.observe(packet)`; `.verdict` property returns the locked verdict.
- `EvidencePacket(packet_id=, time_window=TimeWindow(start=, end=))`; `.add_fact(fact)`; `.freeze()`; `.get_all_facts()`.
- `Fact(fact_id=, entity_id=, entity_type=, field=, value=, timestamp=, provenance=)`.
- Stages: `src_ip`→0, `port_scan`→1, unmapped (e.g. `data`, `payload`)→2 (`_DEFAULT_STAGE`). `authorization`∈`_AUTHORIZATION_FACT_FIELDS`; `normal_login`∈`_BENIGN_INDICATOR_FIELDS`.

---

### Task 1: `relevant_fact_ids` — the outcome-conditioned kill-chain rule

**Files:**
- Create: `ares/dialectic/agents/verdict_sanitizer.py`
- Test: `ares/dialectic/tests/agents/test_verdict_sanitizer.py`

- [ ] **Step 1: Write the failing tests + shared fixtures**

Create `ares/dialectic/tests/agents/test_verdict_sanitizer.py`:

```python
"""Tests for the opt-in Verdict supporting_fact_ids sanitizer."""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents import OracleJudge, Phase, Verdict, VerdictOutcome
from ares.dialectic.agents.oracle import OracleNarrator
from ares.dialectic.agents.verdict_sanitizer import (
    create_sanitized_oracle_verdict,
    relevant_fact_ids,
    sanitize_verdict,
)
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="test",
        extracted_at=datetime(2026, 5, 31, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 5, 31, 12, 0, 0),
        provenance=_prov(),
    )


def _packet(field_by_id: dict[str, str]) -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="sanitizer-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    for fid, field in field_by_id.items():
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _verdict(outcome: VerdictOutcome, supporting: set[str]) -> Verdict:
    return Verdict(
        outcome=outcome,
        confidence=0.8,
        supporting_fact_ids=frozenset(supporting),
        architect_confidence=0.85,
        skeptic_confidence=0.3,
        reasoning="r",
    )


def _msg(source, phase, mtype, fact_ids, confidence, turn):
    b = MessageBuilder(
        source_agent=source, packet_id="sanitizer-pkt", cycle_id="c",
    )
    b.set_phase(phase)
    b.set_turn(turn)
    b.set_type(mtype)
    b.set_confidence(confidence)
    b.add_assertion(
        Assertion(
            assertion_id="a",
            assertion_type=AssertionType.ASSERT,
            fact_ids=tuple(fact_ids),
            interpretation="i",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


class _EmptyPacket:
    """Minimal stand-in to exercise the empty-packet branch in isolation."""

    def get_all_facts(self):
        return []


# --- relevant_fact_ids: THREAT_CONFIRMED ---

def test_confirmed_selects_max_stage_facts():
    pkt = _packet({"f-recon": "src_ip", "f-scan": "port_scan", "f-exec": "data"})
    # stages: src_ip=0, port_scan=1, data=2 -> max stage 2 -> {f-exec}
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_CONFIRMED) == frozenset(
        {"f-exec"}
    )


def test_confirmed_includes_all_ties_at_top_stage():
    pkt = _packet({"f-e1": "data", "f-e2": "payload", "f-recon": "src_ip"})
    # data=2, payload=2 (both default), src_ip=0 -> {f-e1, f-e2}
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_CONFIRMED) == frozenset(
        {"f-e1", "f-e2"}
    )


# --- relevant_fact_ids: THREAT_DISMISSED ---

def test_dismissed_selects_authorization_fields():
    pkt = _packet({"f-auth": "authorization", "f-exec": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-auth"}
    )


def test_dismissed_counts_benign_indicator_fields_as_exculpatory():
    pkt = _packet({"f-benign": "normal_login", "f-exec": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-benign"}
    )


def test_dismissed_falls_back_to_whole_packet_when_no_exculpatory():
    pkt = _packet({"f-exec": "data", "f-scan": "port_scan"})
    assert relevant_fact_ids(pkt, VerdictOutcome.THREAT_DISMISSED) == frozenset(
        {"f-exec", "f-scan"}
    )


# --- relevant_fact_ids: INCONCLUSIVE + empty ---

def test_inconclusive_returns_all_facts():
    pkt = _packet({"f-a": "src_ip", "f-b": "data"})
    assert relevant_fact_ids(pkt, VerdictOutcome.INCONCLUSIVE) == frozenset(
        {"f-a", "f-b"}
    )


def test_empty_packet_returns_empty_frozenset():
    assert relevant_fact_ids(_EmptyPacket(), VerdictOutcome.THREAT_CONFIRMED) == frozenset()
```

- [ ] **Step 2: Run the tests to verify they fail**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -q`
Expected: collection error / `ModuleNotFoundError: ares.dialectic.agents.verdict_sanitizer` (module not created yet).

- [ ] **Step 3: Create the module with `relevant_fact_ids`**

Create `ares/dialectic/agents/verdict_sanitizer.py`:

```python
"""Deterministic, framing-invariant sanitizer for Verdict.supporting_fact_ids.

OracleJudge passes the Architect's (LLM-chosen, framing-sensitive) cited
fact-ids verbatim into Verdict.supporting_fact_ids (oracle.py:89/102/116). This
module provides an OPT-IN peer path that re-derives supporting_fact_ids from the
EvidencePacket alone, via a deterministic, outcome-conditioned kill-chain rule.
Because the rule depends only on the packet's fact-id set and per-fact `field`
(which framing mutations never change), the resulting set is invariant under
framing mutations.

oracle.py and its passthrough anchor test are intentionally UNTOUCHED — this is
a peer, not a modification. Callers opt in by using create_sanitized_oracle_verdict
in place of oracle.create_oracle_verdict.
"""
from __future__ import annotations

from dataclasses import replace
from typing import TYPE_CHECKING

from ares.dialectic.agents.light_skeptic import _DEFAULT_STAGE, _STAGE_MAP
from ares.dialectic.agents.oracle import OracleJudge, OracleNarrator
from ares.dialectic.agents.patterns import Verdict, VerdictOutcome
from ares.dialectic.coordinator.firewall import (
    _AUTHORIZATION_FACT_FIELDS,
    _BENIGN_INDICATOR_FIELDS,
)

if TYPE_CHECKING:
    from ares.dialectic.evidence.packet import EvidencePacket
    from ares.dialectic.messages.protocol import DialecticalMessage


_EXCULPATORY_FIELDS = _AUTHORIZATION_FACT_FIELDS | _BENIGN_INDICATOR_FIELDS


def relevant_fact_ids(
    packet: "EvidencePacket", outcome: VerdictOutcome
) -> frozenset[str]:
    """Deterministic, packet-only supporting-fact set, conditioned on outcome.

    - THREAT_CONFIRMED -> fact_ids at the maximum kill-chain stage present
      (per _STAGE_MAP; ties all included).
    - THREAT_DISMISSED -> fact_ids whose field is an authorization/benign
      (exculpatory) field; falls back to the whole packet if none present.
    - INCONCLUSIVE -> all fact_ids.

    Empty packet -> empty frozenset.
    """
    facts = packet.get_all_facts()
    if not facts:
        return frozenset()

    if outcome == VerdictOutcome.THREAT_CONFIRMED:
        stages = {f.fact_id: _STAGE_MAP.get(f.field, _DEFAULT_STAGE) for f in facts}
        top = max(stages.values())
        return frozenset(fid for fid, stage in stages.items() if stage == top)

    if outcome == VerdictOutcome.THREAT_DISMISSED:
        exculpatory = frozenset(
            f.fact_id for f in facts if f.field in _EXCULPATORY_FIELDS
        )
        return exculpatory or frozenset(f.fact_id for f in facts)

    return frozenset(f.fact_id for f in facts)
```

- [ ] **Step 4: Run the tests to verify they pass**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -q`
Expected: 7 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/verdict_sanitizer.py ares/dialectic/tests/agents/test_verdict_sanitizer.py
git commit -m "feat(s078): relevant_fact_ids - packet-derived kill-chain rule

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 2: `sanitize_verdict` — frozen-copy replacing only the cited set

**Files:**
- Modify: `ares/dialectic/agents/verdict_sanitizer.py`
- Test: `ares/dialectic/tests/agents/test_verdict_sanitizer.py` (append)

- [ ] **Step 1: Append the failing tests**

Append to `test_verdict_sanitizer.py`:

```python
# --- sanitize_verdict ---

def test_sanitize_replaces_only_supporting_fact_ids():
    pkt = _packet({"f-exec": "data", "f-recon": "src_ip"})
    v = _verdict(VerdictOutcome.THREAT_CONFIRMED, supporting={"bogus-1", "bogus-2"})
    s = sanitize_verdict(v, pkt)
    # supporting set is re-derived (max-stage = data) ...
    assert s.supporting_fact_ids == frozenset({"f-exec"})
    # ... and every other field is preserved verbatim.
    assert s.outcome == v.outcome
    assert s.confidence == v.confidence
    assert s.architect_confidence == v.architect_confidence
    assert s.skeptic_confidence == v.skeptic_confidence
    assert s.reasoning == v.reasoning


def test_sanitize_returns_new_instance_leaving_original_unchanged():
    pkt = _packet({"f-a": "data"})
    v = _verdict(VerdictOutcome.INCONCLUSIVE, supporting={"x"})
    s = sanitize_verdict(v, pkt)
    assert s is not v
    assert v.supporting_fact_ids == frozenset({"x"})  # original untouched
    assert s.supporting_fact_ids == frozenset({"f-a"})
```

- [ ] **Step 2: Run to verify they fail**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -k sanitize -q`
Expected: FAIL — `ImportError: cannot import name 'sanitize_verdict'` (or AttributeError).

- [ ] **Step 3: Add `sanitize_verdict` to the module**

Append to `verdict_sanitizer.py` (after `relevant_fact_ids`):

```python
def sanitize_verdict(verdict: Verdict, packet: "EvidencePacket") -> Verdict:
    """Return a copy of `verdict` with supporting_fact_ids re-derived from the
    packet (framing-invariant). Every other field is preserved."""
    return replace(
        verdict,
        supporting_fact_ids=relevant_fact_ids(packet, verdict.outcome),
    )
```

- [ ] **Step 4: Run to verify they pass**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -k sanitize -q`
Expected: 2 passed.

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/verdict_sanitizer.py ares/dialectic/tests/agents/test_verdict_sanitizer.py
git commit -m "feat(s078): sanitize_verdict - frozen copy, replaces only cited set

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 3: `create_sanitized_oracle_verdict` — the opt-in factory

**Files:**
- Modify: `ares/dialectic/agents/verdict_sanitizer.py`
- Test: `ares/dialectic/tests/agents/test_verdict_sanitizer.py` (append)

- [ ] **Step 1: Append the failing tests**

Append to `test_verdict_sanitizer.py`:

```python
# --- create_sanitized_oracle_verdict ---

def test_factory_sanitizes_and_narrator_holds_sanitized_verdict():
    pkt = _packet({"f-exec": "data", "f-recon": "src_ip", "f-scan": "port_scan"})
    # Architect cites the low-stage facts; the packet also holds f-exec (stage 2).
    arch = _msg(
        "architect", Phase.THESIS, MessageType.HYPOTHESIS,
        ["f-recon", "f-scan"], 0.85, 1,
    )
    skep = _msg(
        "skeptic", Phase.ANTITHESIS, MessageType.REBUTTAL, ["f-recon"], 0.3, 2,
    )
    verdict, narrator = create_sanitized_oracle_verdict(arch, skep, pkt)
    assert verdict.outcome == VerdictOutcome.THREAT_CONFIRMED
    # Sanitized = packet max-stage {f-exec}, NOT the architect's {f-recon, f-scan}.
    assert verdict.supporting_fact_ids == frozenset({"f-exec"})
    # The narrator is built from the sanitized verdict, so it cites the sanitized set.
    assert narrator.verdict is verdict
```

- [ ] **Step 2: Run to verify it fails**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -k factory -q`
Expected: FAIL — `ImportError: cannot import name 'create_sanitized_oracle_verdict'`.

- [ ] **Step 3: Add the factory to the module**

Append to `verdict_sanitizer.py`:

```python
def create_sanitized_oracle_verdict(
    architect_msg: "DialecticalMessage",
    skeptic_msg: "DialecticalMessage",
    packet: "EvidencePacket",
) -> tuple[Verdict, OracleNarrator]:
    """Opt-in peer of oracle.create_oracle_verdict: compute the deterministic
    verdict, sanitize its supporting_fact_ids, then build a narrator from the
    SANITIZED verdict so its explanation cites the sanitized set."""
    verdict = OracleJudge.compute_verdict(architect_msg, skeptic_msg, packet)
    sanitized = sanitize_verdict(verdict, packet)
    narrator = OracleNarrator(verdict=sanitized)
    narrator.observe(packet)
    return sanitized, narrator
```

- [ ] **Step 4: Run to verify it passes**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer.py -q`
Expected: 10 passed (all tests in the file).

- [ ] **Step 5: Commit**

```bash
git add ares/dialectic/agents/verdict_sanitizer.py ares/dialectic/tests/agents/test_verdict_sanitizer.py
git commit -m "feat(s078): create_sanitized_oracle_verdict - opt-in factory seam

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 4: Invariance anchor — lock the fixed (drift-free) behavior

This is a documentary regression-lock (the inverse of the passthrough anchor). It exercises the *completed* sanitizer, so it PASSES on first run — that is the proof-of-fix.

**Files:**
- Test: `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py` (NEW)

- [ ] **Step 1: Write the anchor test**

Create `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py`:

```python
"""Inverse of the Oracle passthrough anchor: proves that, on the opt-in
sanitized path, Architect citation-drift NO LONGER reaches
Verdict.supporting_fact_ids, while the decision surface stays preserved.

Complements (never edits) test_oracle_supporting_fact_ids_passthrough.py:
that anchor locks the *leak* on the default path; this one locks the *fix*
on the sanitized path.
"""
from __future__ import annotations

from datetime import datetime

from ares.dialectic.agents import Phase, VerdictOutcome
from ares.dialectic.agents.verdict_sanitizer import create_sanitized_oracle_verdict
from ares.dialectic.evidence.fact import EntityType, Fact
from ares.dialectic.evidence.packet import EvidencePacket, TimeWindow
from ares.dialectic.evidence.provenance import Provenance, SourceType
from ares.dialectic.messages.assertions import Assertion, AssertionType
from ares.dialectic.messages.protocol import MessageBuilder, MessageType


def _prov() -> Provenance:
    return Provenance(
        source_type=SourceType.MANUAL,
        source_id="anchor",
        extracted_at=datetime(2026, 5, 31, 12, 0, 0),
    )


def _fact(fact_id: str, field: str) -> Fact:
    return Fact(
        fact_id=fact_id,
        entity_id=f"node-{fact_id}",
        entity_type=EntityType.NODE,
        field=field,
        value="v",
        timestamp=datetime(2026, 5, 31, 12, 0, 0),
        provenance=_prov(),
    )


def _packet() -> EvidencePacket:
    pkt = EvidencePacket(
        packet_id="invariance-anchor-pkt",
        time_window=TimeWindow(
            start=datetime(2026, 5, 1, 0, 0, 0),
            end=datetime(2026, 5, 31, 23, 59, 59),
        ),
    )
    # A1,A2 are stage 2 (default 'data'); A3,B1 are stage 0 ('src_ip').
    for fid, field in (
        ("A1", "data"), ("A2", "data"), ("A3", "src_ip"), ("B1", "src_ip"),
    ):
        pkt.add_fact(_fact(fid, field))
    pkt.freeze()
    return pkt


def _arch(fact_ids):
    b = MessageBuilder(
        source_agent="architect", packet_id="invariance-anchor-pkt", cycle_id="c",
    )
    b.set_phase(Phase.THESIS)
    b.set_turn(1)
    b.set_type(MessageType.HYPOTHESIS)
    b.set_confidence(0.85)
    b.add_assertion(
        Assertion(
            assertion_id="hyp",
            assertion_type=AssertionType.ASSERT,
            fact_ids=tuple(fact_ids),
            interpretation="threat",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


def _skeptic():
    b = MessageBuilder(
        source_agent="skeptic", packet_id="invariance-anchor-pkt", cycle_id="c",
    )
    b.set_phase(Phase.ANTITHESIS)
    b.set_turn(2)
    b.set_type(MessageType.REBUTTAL)
    b.set_confidence(0.3)
    b.add_assertion(
        Assertion(
            assertion_id="alt",
            assertion_type=AssertionType.ASSERT,
            fact_ids=("B1",),
            interpretation="benign",
            operator="op",
            threshold="t",
        )
    )
    return b.build()


def test_architect_drift_does_not_propagate_after_sanitization():
    pkt = _packet()
    skep = _skeptic()
    arch_baseline = _arch(("A1", "A2", "A3"))
    arch_mutated = _arch(("A2", "A3"))  # framing-drifted citation set

    v_base, _ = create_sanitized_oracle_verdict(arch_baseline, skep, pkt)
    v_mut, _ = create_sanitized_oracle_verdict(arch_mutated, skep, pkt)

    # Decision surface preserved across the drift.
    assert v_base.outcome == v_mut.outcome == VerdictOutcome.THREAT_CONFIRMED
    assert v_base.confidence == v_mut.confidence

    # Explanation surface NO LONGER drifts (the fix): both equal the
    # packet-derived max-stage set {A1, A2}, regardless of what the
    # Architect cited. (On the default path these would be {A1,A2,A3}
    # vs {A2,A3} — different — which the passthrough anchor locks.)
    assert v_base.supporting_fact_ids == v_mut.supporting_fact_ids
    assert v_base.supporting_fact_ids == frozenset({"A1", "A2"})
```

- [ ] **Step 2: Run the anchor (expected PASS on first run — proof of fix)**

Run: `python -m pytest ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py -q`
Expected: 1 passed. (If it fails, the sanitizer is wrong — fix Tasks 1–3, do not weaken this test.)

- [ ] **Step 3: Commit**

```bash
git add ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py
git commit -m "test(s078): invariance anchor - architect drift no longer reaches verdict

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

### Task 5: Full-suite regression + passthrough-anchor-still-green check

Confirms zero regressions and — critically — that the *existing* passthrough anchor still passes, proving `oracle.py` was not modified (Paper 3 reproducibility intact).

**Files:** none (verification only).

- [ ] **Step 1: Confirm the passthrough anchor is untouched and green**

Run: `python -m pytest ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py -q`
Expected: all passed (the default-path leak is still locked — we added a peer, not a change).

- [ ] **Step 2: Run the full suite**

Run: `python -m pytest tests ares -q`
Expected: previous pass count + 11 new tests, 0 failed. (Baseline this session was 4147 passed / 75 skipped / 0 failed; expect ~4158 passed / 75 skipped / 0 failed.)

- [ ] **Step 3: Confirm CLAUDE.md self-validation still green**

Run: `python -m pytest tests/test_claude_md_freshness.py -q`
Expected: 5 passed (actual collected count is above the 3,937 floor; no floor change needed).

---

### Task 6: Register the new module in CLAUDE.md (project hygiene)

Matches the project pattern (e.g. S077 registered its modules under "Key Code Locations"). Documentation only; not validated by the freshness test, so low-risk.

**Files:**
- Modify: `CLAUDE.md` (add an entry under "### Architect-path measurement" / a new "### Verdict sanitization (Phase 7 / Session 078)" subsection in "Key Code Locations").

- [ ] **Step 1: Add the registration entry**

Under "## Key Code Locations", add a new subsection (place it after the "Multi-model measurement" block):

```markdown
### Verdict sanitization (Phase 7 / Session 078)
- Opt-in Oracle passthrough fix: `ares/dialectic/agents/verdict_sanitizer.py` — `relevant_fact_ids` (outcome-conditioned packet-derived kill-chain rule), `sanitize_verdict` (frozen copy, replaces only `supporting_fact_ids`), `create_sanitized_oracle_verdict` (opt-in factory peer of `oracle.create_oracle_verdict`). Deterministic; closes the Architect->Oracle `supporting_fact_ids` framing leak on the opt-in path. `oracle.py` + passthrough anchor untouched (Paper 3 reproducible on HEAD).
- Invariance anchor: `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py` (inverse of the passthrough anchor; locks the drift-free fixed behavior).
- Spec/plan: `docs/superpowers/specs/2026-05-31-oracle-passthrough-sanitization-design.md`, `docs/superpowers/plans/2026-05-31-oracle-passthrough-sanitization.md`.
```

- [ ] **Step 2: Verify freshness test still green**

Run: `python -m pytest tests/test_claude_md_freshness.py -q`
Expected: 5 passed.

- [ ] **Step 3: Commit**

```bash
git add CLAUDE.md
git commit -m "docs(s078): register verdict_sanitizer in Key Code Locations

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>"
```

---

## Self-Review

**1. Spec coverage:**
- §5.1 module placement → Task 1 Step 3 (module created in `agents/` with the exact imports). ✓
- §5.2 `relevant_fact_ids` (all 3 branches + edges) → Task 1 (CONFIRMED max-stage + ties; DISMISSED exculpatory + benign + fallback; INCONCLUSIVE; empty). ✓
- §5.2 `sanitize_verdict` → Task 2. ✓
- §5.2 `create_sanitized_oracle_verdict` → Task 3. ✓
- §6 by-construction invariance → Task 4 anchor proves baseline == mutated. ✓
- §7 testing plan (two files) → Tasks 1–4. ✓
- §3 oracle.py/anchor/Paper-3 untouched → Task 5 Step 1 explicitly re-runs the passthrough anchor. ✓

**2. Placeholder scan:** No TBD/TODO; every code step shows complete code; every run step shows the command + expected result. ✓

**3. Type consistency:** `relevant_fact_ids(packet, outcome)`, `sanitize_verdict(verdict, packet)`, `create_sanitized_oracle_verdict(architect_msg, skeptic_msg, packet)` — names/signatures identical across the spec, the module (Task 1/2/3 Step 3), and the tests. `VerdictOutcome.THREAT_CONFIRMED/THREAT_DISMISSED/INCONCLUSIVE`, `Verdict(...)` field names, and `narrator.verdict` all match the verified APIs above. ✓

**Note for the implementer:** the test fixtures rely on these `_STAGE_MAP` facts: `src_ip`=0, `port_scan`=1, `data`/`payload`=2 (default); and on `authorization`∈`_AUTHORIZATION_FACT_FIELDS`, `normal_login`∈`_BENIGN_INDICATOR_FIELDS`. If any of these constants are edited upstream, update the fixtures' field choices (not the assertions' intent).
