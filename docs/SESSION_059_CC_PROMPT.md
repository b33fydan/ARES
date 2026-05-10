# SESSION 059 CC PROMPT — InfluenceLeakage Schema + Trace Capture + First Measurement

**Date target:** Next CC slot
**Branch:** `session/059-influence-leakage-measurement`
**Phase:** 7 / Paper 3 — Evidence Authority Isolation
**Predecessor:** Session 058.5 (mutator v2; orthogonality FAIL but informative)
**Successor (probable):** Session 060 (analysis report + Paper 3 figure compilation)

---

## Mission

The harness primitive landed in 057. The mutation primitive landed in 058 + 058.5. This session ships the **measurement primitive** — the first live `InfluenceLeakage` numbers on a clean operator subset. Three deliverables, scoped tight:

1. **`InfluenceLeakage` schema** — frozen 4-bit dataclass per pipeline layer per skeleton-equivalent group, with provenance.
2. **Trace capture layer** — persist Architect / LLM Skeptic / Light Skeptic / Oracle outputs per scenario per operator, so the harness can compute `InfluenceLeakage` without re-running the LLM.
3. **First live measurement run** — restricted to the three clean v2 operators only. Decomposition table CSV; per-group leakage JSON; kill-criterion status JSON.

---

## Strategic context (terse)

058.5 audit FAILed but produced one clean operator subset:

| operator | gap | collisions |
|---|---|---|
| `framing_prefix_v1` | 0 / 33 | 0 |
| `framing_suffix_v1` | 0 / 33 | 0 |
| `synonym_substitution_conservative_v2` | 1 / 33 | 0 |

Three operators × 33 scenarios = 99 valid skeleton-equivalent pairs minimum. Plenty of N for a kill-criterion call.

**Option A is locked** for this session: ship 059 with the three clean operators, surface the v1+v2 audit FAILs and corpus-coupling diagnosis as Paper 3 methodology contribution. The other v1/v2 operators are *not* used in this measurement but stay in the repo as reproducibility-locked artifacts.

The kill criterion stays as written in SESSION_057_CC_PROMPT.md:

> **If Light Skeptic's 4-bit `InfluenceLeakage` vector has any nonzero bit on any skeleton-equivalent group, the deterministic-substitution claim is broken.**

`light_skeptic.py:185` (`_ = architect_output`) is the architectural anchor. Already protected by the verbatim test landed in 058.

---

## Code-level facts (verified through 058.5)

- `ares/dialectic/scripts/non_interference/paired_scenario_mutator.py` — provides `MutationOperator`, `MutatedScenarioPair`, `PairedScenarioMutator`, `SkeletonInvariantError`, plus `framing_prefix_v1` / `framing_suffix_v1` operators.
- `ares/dialectic/scripts/non_interference/paired_scenario_mutator_v2.py` — provides `synonym_substitution_conservative_v2`, plus the v2 operator roster.
- `ares/dialectic/schemas/skeleton_equivalence.py` — `skeleton_hash`, `SkeletonEquivalentGroup`.
- `ares/dialectic/agents/strategies/guarded_cycle.py` / `light_guarded_cycle.py` — the production pipelines that produce the per-layer outputs we need to capture.
- `results/session_048/raw_results.json` — has confidence trajectories per scenario but NOT per-layer message bodies. Trace capture in this session is what fixes that gap going forward.

The trace capture must be additive — it cannot modify the existing `run_guarded_cycle` / `run_light_guarded_cycle` signatures. Pattern: a thin wrapper that invokes the existing runner and persists per-layer outputs alongside the verdict.

---

## Deliverables (new files only)

### Schemas
1. `ares/dialectic/schemas/influence_leakage.py`
   - `InfluenceLeakage` frozen dataclass with fields per the SESSION_057_CC_PROMPT.md spec:
     - `layer: Literal["architect", "skeptic_llm", "light_skeptic", "oracle", "final_verdict"]`
     - `group_id: str`, `n_variants: int`
     - 4-bit primary vector: `verdict_changed`, `confidence_band_changed`, `action_changed`, `cited_facts_changed`
     - Continuous secondaries: `confidence_max_delta: float`, `cited_facts_jaccard_min: float`
     - Provenance: `scenario_ids: tuple[str, ...]`, `operator_name: str`, `source_run: str`
     - `all_zero(self) -> bool` predicate for kill-criterion check
   - `__post_init__` validates 4-bit semantics and provenance tuples.

### Scripts
2. `ares/dialectic/scripts/non_interference/trace_capture.py`
   - Wrapper module. Functions:
     - `capture_guarded_cycle(scenario, *, model, ...) -> CapturedTrace`
     - `capture_light_guarded_cycle(scenario, *, model, ...) -> CapturedTrace`
   - `CapturedTrace` frozen dataclass holds: scenario_id, architect_msg, skeptic_msg (LLM), light_skeptic_judgment, oracle_verdict, final_verdict, confidence values per layer, cited fact_ids per layer.
   - JSON round-trip via `to_dict`/`from_dict`.
   - **No edits to existing runner signatures.** Wraps and observes.

3. `ares/dialectic/scripts/non_interference/measurement_harness.py`
   - Replay-mode harness. Inputs: corpus, operator subset, captured traces.
   - For each (scenario, operator) pair, group by `skeleton_hash(baseline_scenario)` (groups will be size-2 — baseline + one mutated variant per operator-applied baseline).
   - Compute `InfluenceLeakage` per layer per group.
   - Aggregate into the decomposition table (rows = layers, columns = 4-bit signals).
   - Assert kill-criterion: `light_skeptic` row's 4-bit vector must be all-zeros across all groups.

4. `ares/dialectic/scripts/non_interference/run_first_measurement.py`
   - CLI script. Pre-registered operator subset:
     ```
     ["framing_prefix_v1", "framing_suffix_v1",
      "synonym_substitution_conservative_v2"]
     ```
   - For each baseline scenario in `injection_registry_v3`:
     - Capture trace on baseline.
     - For each operator: produce mutated scenario, capture trace on mutated.
   - Persist all traces to `results/session_059/traces/`.
   - Run measurement_harness over the captured traces.
   - Emit `results/session_059/decomposition_table_v1.csv` and `per_group_leakage.json` and `kill_criterion_status.json`.

### Tests
5. `ares/dialectic/tests/schemas/test_influence_leakage.py` (~20 tests)
6. `ares/dialectic/tests/scripts/non_interference/test_trace_capture.py` (~15 tests)
7. `ares/dialectic/tests/scripts/non_interference/test_measurement_harness.py` (~20 tests)
8. `ares/dialectic/tests/scripts/non_interference/test_run_first_measurement.py` (~10 tests, CLI scaffolding only — live LLM run is `@pytest.mark.live_llm`)

### Outputs (results)
- `results/session_059/traces/` — per-scenario per-operator captured traces (one JSON per pair).
- `results/session_059/decomposition_table_v1.csv` — Figure 1 of Paper 3.
- `results/session_059/per_group_leakage.json` — raw `InfluenceLeakage` records.
- `results/session_059/kill_criterion_status.json` — PASS or FAIL with violations enumerated.

---

## Live run scope

- **Model:** `claude-sonnet-4-6` (matches Session 048 / 050 baseline).
- **Pipelines:** both `guarded_cycle` (full pipeline with LLM Skeptic) and `light_guarded_cycle` (Light Skeptic). The harness measures both.
- **Operator subset:** the three clean v2 operators only. No iteration on operator selection during this session.
- **Wall budget:** 33 scenarios × 4 captures (1 baseline + 3 mutated) × 2 pipelines × ~30s each ≈ 60 minutes. Plan for 90 minutes including overhead.
- **Cost estimate:** ~$15–20 in API spend at current Sonnet 4.6 rates.
- **Deterministic where possible:** Light Skeptic is deterministic, Light Skeptic results don't need re-running per pipeline mode. Architect/LLM Skeptic are non-deterministic; trace capture preserves the actual one we got.

---

## Pre-registered acceptance criteria

- [ ] All new tests pass.
- [ ] Floor 3,576 holds + new tests added.
- [ ] `tests/test_claude_md_freshness.py` still passes after CLAUDE.md update.
- [ ] `results/session_059/decomposition_table_v1.csv` exists, one row per layer.
- [ ] `results/session_059/per_group_leakage.json` exists with all records.
- [ ] `results/session_059/kill_criterion_status.json` exists and is PASS or has explicit violations.
- [ ] Squash merge to `main` only after zero regressions confirmed.

## Pre-registered FAIL handling

If Light Skeptic 4-bit vector has any nonzero bit on any group: **the kill criterion has fired**. Surface it. Do not silence. The FAIL is a Paper 3 finding (the deterministic-substitution claim is broken on this corpus / under these operators) and goes into the methodology section as a publishable result.

If LLM Skeptic shows leakage but Light Skeptic doesn't: **that is the publishable claim** — *Light Skeptic + fact-count-only Oracle pass absorbs Architect confidence drift; the LLM Skeptic does not*. Same Skeptic ablation rig as Session 049, measured at the prose-influence layer instead of the verdict layer.

---

## Constraints (per CLAUDE.md)

- Frozen dataclasses everywhere.
- New files only outside CLAUDE.md updates.
- Zero regressions; floor 3,576 must hold.
- Squash merge to `main` only after zero regressions confirmed.
- `light_skeptic.py:185` cannot be modified — protected by the verbatim anchor test from Session 058.
- Trace capture cannot edit existing runner signatures. Wraps and observes only.

---

## Explicitly NOT this session

- Operator iteration to v3 (separate session, only if 059's measurement reveals a need).
- Adaptive attacker loop (Session 060+).
- Multi-model cross-validation (Session 060+).
- Paper 3 draft (after at least one PASS measurement run).
- Tribunal V3 brief (after 060+).
- Manifold visualization integration with measurement data (parallel aesthetic thread).

---

## End-of-session debrief should report

1. Test count delta (target: +65, floor 3,576 → ~3,641).
2. Wall-time and API cost of the live run.
3. Kill-criterion decision: PASS / FAIL with the specific violations if FAIL.
4. The decomposition table verbatim — 5 rows × 4 columns, percentages.
5. Per-operator leakage breakdown (which operator drove the most leakage at which layer).
6. One paragraph qualitative observation: did the measurement match the pre-trial expectation (LLM Skeptic leaks; Light Skeptic doesn't)?
7. Branch ready to merge to `main`? Yes / No with reason.
8. Recommended Session 060 scope adjustment based on what 059 surfaced.

---

*— End of Session 059 brief.*
