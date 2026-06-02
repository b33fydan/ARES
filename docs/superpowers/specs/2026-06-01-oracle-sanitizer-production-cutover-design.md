# Design — Oracle Sanitizer Production Cutover (Session 079)

**Date:** 2026-06-01
**Session:** 079
**Status:** Approved (brainstorm complete; ready for writing-plans)
**Parent work:** Session 078 built the opt-in `verdict_sanitizer.py` (`ed00cdb`). This session wires it into production.
**Crystal:** `E:\breadstick\crystals\ares-phase-seven\s078-oracle-sanitizer-merged-2026-06-01T17-14-38.md`

---

## 1. Problem

The Oracle's `Verdict.supporting_fact_ids` is the Architect's LLM-chosen, framing-sensitive
cited-fact set, copied verbatim through `OracleJudge.compute_verdict` (`oracle.py:89/102/116`).
This is the genuine, model-dependent leak measured in S059/S075 (60–78% LLM-path divergence):
two framings of the same packet yield different *cited* facts even though the decision is identical.

Session 078 built the fix — `ares/dialectic/agents/verdict_sanitizer.py` — a deterministic,
framing-invariant re-derivation of `supporting_fact_ids` from the packet alone. But it is
**opt-in and unused**: nothing in production consumes it. The default cycles still emit the
leaky set. The fix is inert.

**This session makes the fix live on the production path, without disturbing the measurement
harness or Paper 3's reproducibility.**

## 2. Findings from code exploration (these reframe the crystal's plan)

1. **The crystal's mechanism does not apply.** No production code calls
   `oracle.create_oracle_verdict` — only tests do. Every production cycle
   (`run_cycle_with_strategies`, `run_guarded_cycle`, `run_light_guarded_cycle`,
   `run_ablated_cycle`) *inlines* `OracleJudge.compute_verdict(...)` and then builds the
   `OracleNarrator` directly with a cycle-scoped `agent_id` and an injected
   `narrative_generator`. There is no factory to swap. The real seam is a single line:
   re-derive the cited set via `sanitize_verdict(verdict, packet)` right after `compute_verdict`,
   before the narrator is built.

2. **An unconditional in-place edit would break Paper 3.** The leakage measurement harness
   `ares/dialectic/measurement/leakage_runner.py::_run_one_cycle` calls `run_guarded_cycle`
   and `run_light_guarded_cycle` **directly** — the same functions production uses. Those
   measurements are the demonstrated-leak audit trail and Paper 3 Finding-2 reproducibility.
   So sanitization must be **selectable**: production clean, measurement leaky. (Hard constraint.)

3. **No firewall interaction** (resolves the crystal's open question). The firewall runs at the
   THESIS→ANTITHESIS junction on the *Architect message* (`firewall.validate(architect_message, packet)`),
   before any verdict exists; it never reads `verdict.supporting_fact_ids`. Sanitizing the
   verdict's cited set touches nothing the firewall sees.

4. **Decision determinism is preserved by construction.** `sanitize_verdict` replaces *only*
   `supporting_fact_ids` (`dataclasses.replace`). `outcome` and `confidence` are computed
   from agent confidences *before* the cited set is derived, so sanitization cannot change the
   decision — only the explanation surface.

## 3. Locked decisions (from brainstorm)

| Decision | Choice | Rationale |
|---|---|---|
| Mechanism | **Opt-in default-off flag** | Single-sources cycle logic; measurement keeps default → Paper 3 reproduces unchanged. Waives "new files only" for one additive, default-preserving keyword-only param. |
| Cycles flagged | `run_cycle_with_strategies`, `run_guarded_cycle`, `run_light_guarded_cycle` | The production + production-candidate single-turn paths. |
| Out of scope | `run_ablated_cycle`, `run_multi_turn_with_strategies` | Lab/ablation paths; "multi-turn stays in the lab." |
| Done bar | **Seam + sanitized-by-default production entrypoint** | A default-off flag nobody flips is still inert. A thin new entrypoint that defaults ON closes the gap without touching measurement/benchmark outputs. |
| Entrypoint wraps | **Single-turn `run_cycle_with_strategies`** | Matches CLAUDE.md "single-turn is production"; cleanest signature (no required `hot_swap_factory`). |
| Verification | **Offline-only, deterministic** | Invariance is true by construction (same epistemic status as S078); a live run would demonstrate, not discover. |

## 4. Design

### §1 — The seam (opt-in flag on the three cycles)

Add a keyword-only parameter to each of the three cycle functions:

```python
sanitize_supporting_facts: bool = False,
```

In each function, immediately after the `verdict = OracleJudge.compute_verdict(...)` block and
**before** the narrator block, insert:

```python
if sanitize_supporting_facts:
    from ares.dialectic.agents.verdict_sanitizer import sanitize_verdict
    verdict = sanitize_verdict(verdict, packet)
```

- **Lazy import**: when the flag is off, the import never fires; the default path keeps an
  identical import graph and identical behavior. (`live_cycle.py` does not currently import the
  firewall module that `verdict_sanitizer` transitively pulls in — lazy import keeps that
  coupling out of the default path.)
- Sanitizing here means the narrator and its synthesis `seen_fact_ids` (both derived from
  `verdict.supporting_fact_ids`) cite the clean set — **no narrator re-run, no extra LLM call.**
- The parameter is keyword-only (each signature already has a `*`), so the change is purely
  additive; every existing caller and the measurement harness are unaffected.

**Exact insertion points (current line numbers, for orientation only — match on code, not lines):**

| File | Function | Signature line | Insert after | Before |
|---|---|---|---|---|
| `ares/dialectic/agents/strategies/live_cycle.py` | `run_cycle_with_strategies` | ~40 | `compute_verdict` block (~152–161) | narrator block (~164) |
| `ares/dialectic/agents/strategies/guarded_cycle.py` | `run_guarded_cycle` | ~120 | `compute_verdict` block (~351–361) | narrator block (~364) |
| `ares/dialectic/agents/strategies/light_guarded_cycle.py` | `run_light_guarded_cycle` | ~192 | `compute_verdict` block (~304–314) | narrator block (~317) |

> Note: `run_multi_turn_with_strategies` in `live_cycle.py` is **not** flagged (lab path).

### §2 — The production entrypoint

New file: `ares/dialectic/agents/strategies/production_cycle.py`

```python
def run_production_cycle(
    packet,
    *,
    threat_analyzer=None,
    explanation_finder=None,
    narrative_generator=None,
    agent_id_prefix="ares",
    include_narration=True,
) -> CycleResult:
    """Production single-turn cycle with the Oracle supporting_fact_ids leak closed.

    Thin wrapper over run_cycle_with_strategies(..., sanitize_supporting_facts=True).
    This is the one blessed 'live, fixed' path.
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

- Mirrors the wrapped signature explicitly (self-documenting; no loose `**kwargs`).
- Brand new → nothing existing depends on its output → defaulting sanitization **on** here is
  regression-free.
- Export it following the sibling-cycle convention (verify `ares/dialectic/agents/strategies/__init__.py`
  and/or `ares/dialectic/agents/__init__.py`; if the other cycle entrypoints are not exported
  from a package `__init__`, leave `run_production_cycle` importable from its own module to match).

### §3 — Tests (offline-only, deterministic, zero LLM calls)

New test module(s) under `ares/dialectic/tests/agents/strategies/`. Helpers inline per file
(per the project's test-pattern convention). Use stub/RuleBased strategies — no `@pytest.mark.live_llm`.

**`test_sanitize_supporting_facts_flag.py`** — for each of the three flagged cycles:
- **Flag off (default) = legacy/leaky:** `result.verdict.supporting_fact_ids` equals the
  Architect/Skeptic-derived set (today's behavior). This is also the *leak-persists guard* that
  protects the measurement contract.
- **Flag on = sanitized:** `result.verdict.supporting_fact_ids == relevant_fact_ids(packet, outcome)`.
- **Decision-determinism lock:** `outcome` and `confidence` are identical off-vs-on.
- **Narrator cites the sanitized set:** with the flag on, the `narrator_message`'s fact_ids are
  drawn from the sanitized set (not the leaky one).
- **Cycle-level framing invariance (proof-of-fix):** a stub `ThreatAnalyzer` that cites two
  *different* fact subsets of the *same* packet while holding confidence constant (so the outcome
  is unchanged) → flag-on sanitized `supporting_fact_ids` identical across the two runs. This is
  the cycle-boundary analog of `test_verdict_sanitizer_invariance_anchor.py`.

**`test_production_cycle.py`** — for `run_production_cycle`:
- Sanitized by default: `supporting_fact_ids == relevant_fact_ids(packet, outcome)`.
- Equivalence: equals `run_cycle_with_strategies(..., sanitize_supporting_facts=True)` for the
  same inputs (modulo non-deterministic ids/timestamps — assert on verdict fields, not envelope).

### §4 — Safety & docs

- **Paper 3 / measurement reproduce unchanged.** `leakage_runner._run_one_cycle` keeps the
  default (flag off) → the leak still fires → Finding-2 intact. This is the entire reason for
  default-off.
- **Untouched and must stay green:** `ares/dialectic/agents/oracle.py`,
  `ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py` (passthrough anchor),
  `tests/dialectic/measurement/test_paired_trial_byte_stability.py` (byte-stability anchor).
- **Frozen dataclasses** throughout; `sanitize_verdict` uses `dataclasses.replace`.
- **Zero regressions** by construction (default-off + new entrypoint nothing depends on).
- **CLAUDE.md updates:** bump the declared test floor to the new passing count (honor the
  contract in `tests/test_claude_md_freshness.py`), add `production_cycle.py` + the flag to
  Key Code Locations, add an S079 ledger entry, update the "## Branch" line.

## 5. Non-goals / scope guards

- No change to `oracle.py`, `verdict_sanitizer.py`, the passthrough anchor, or the byte-stability anchor.
- No change to `run_ablated_cycle` or `run_multi_turn_with_strategies`.
- No change to any benchmark/analysis runner's recorded outputs (we do **not** flip existing
  runners on — that was the rejected "Flip existing runners ON" option).
- No live LLM measurement this session (offline-only; invariance is by construction).

## 6. Files touched

**Modified (additive, default-preserving):**
- `ares/dialectic/agents/strategies/live_cycle.py` — `run_cycle_with_strategies`: +param, +seam.
- `ares/dialectic/agents/strategies/guarded_cycle.py` — `run_guarded_cycle`: +param, +seam.
- `ares/dialectic/agents/strategies/light_guarded_cycle.py` — `run_light_guarded_cycle`: +param, +seam.
- `CLAUDE.md` — floor, Key Code Locations, ledger, Branch.

**New:**
- `ares/dialectic/agents/strategies/production_cycle.py` — `run_production_cycle`.
- `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py`.
- `ares/dialectic/tests/agents/strategies/test_production_cycle.py`.
- (possibly) export line in a strategies/agents `__init__.py`, per sibling convention.

## 7. Acceptance criteria

1. The three cycles accept `sanitize_supporting_facts: bool = False`; off-path behavior is
   byte-identical to HEAD (existing suite green, no edits to existing tests required).
2. Flag-on: `supporting_fact_ids == relevant_fact_ids(packet, outcome)`; `outcome`/`confidence`
   unchanged; narrator cites the sanitized set.
3. Cycle-level framing-invariance test passes (proof-of-fix at the cycle boundary).
4. `run_production_cycle` sanitizes by default and equals the flagged underlying cycle.
5. Passthrough anchor and byte-stability anchor remain green, unmodified.
6. Full suite green: `4158 + N new + 75 skip + 0 fail`; CLAUDE.md floor updated to match.

## 8. Risks & mitigations

| Risk | Mitigation |
|---|---|
| Accidental behavior change on the default path | Default-off + lazy import → default path identical, incl. import graph. Off-path equality tests lock it. |
| Contaminating the measurement / Paper 3 | Measurement never passes the flag; leak-persists guard test + existing anchors enforce it. |
| Circular import from `verdict_sanitizer` into `live_cycle` | Lazy import inside the `if` block; only loads when flag on. |
| "Production" ambiguity | Resolved: entrypoint wraps single-turn (CLAUDE.md "single-turn is production"); the guarded/light cycles still carry the flag for when those harnesses are run. |
| Flag/function name collision (`sanitize_verdict`) | Param is `sanitize_supporting_facts`; the imported function is `sanitize_verdict` — distinct names. |

## 9. References

- S078 spec/plan: `docs/superpowers/specs/2026-05-31-oracle-passthrough-sanitization-design.md`,
  `docs/superpowers/plans/2026-05-31-oracle-passthrough-sanitization.md`.
- Sanitizer + anchor: `ares/dialectic/agents/verdict_sanitizer.py`,
  `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py`.
- Leak measurement: `ares/dialectic/measurement/leakage_runner.py`.
