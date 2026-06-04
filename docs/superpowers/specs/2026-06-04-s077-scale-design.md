# S077 Scale — Architect-path framing measurement to all 17 @ K=20 (design)

**Date:** 2026-06-04
**Status:** approved (brainstorm) · **prep-only** (the live run is Dan-gated)
**Branch:** `session/082-s077-scale-prep`

## Goal
Convert the S077 pilot (K=8, 6/17 scenarios) into a uniform **K=20 measurement over all 17 diverging scenarios**, producing a single-K, publication-defensible dataset for the Architect-path framing finding. This session is **offline prep only**; the live ~$26.5 run is run by Dan behind the `--confirm-live` gate.

## Background
- S077 measures Architect cited-fact framing-divergence with LLM-sampling noise controlled: within/cross Jaccard distances, a mean-shift permutation test, a bootstrap CI, and a positive control (drop a baseline-cited fact). Pilot finding: divergence is **REAL but small** (Jaccard ~0.17–0.29) on 3/5 measurable scenarios, within-noise on 2/5 — far below the uncontrolled 60–78%.
- `select_diverging_scenarios` on the S059 Sonnet traces (`data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl`) returns **17** scenarios: INJ-001, 002, 006, 008, 009, 010, 012, 013, 014, 015, 019, 020, 024, 026, 028, 031, 032. The pilot ran the first 6 (incl. the unmeasurable INJ-008); 11 deferred.
- Real per-cycle cost from the pilot traces = **$0.0156/cycle**. `total_cycles_for(n=17, k=20, n_ops=3) = 17·20·5 = 1700` → **~$26.5** (pilot per-cycle, formula max; actual slightly lower due to no-op operator skips).

## Decisions (Dan-approved)
- **Run shape:** ALL 17 @ K=20, uniform. (Not deferred-only/mixed-K; not K=12 or K=30.)
- **Provider/model:** `anthropic` / Sonnet 4.6 — matches the pilot and the S059 selection traces (apples-to-apples with the 60–78% and the noise floor).
- **Include INJ-008** (it is in the pre-registered diverging set; excluding it would be cherry-picking — it may log inconclusive at K=20, which is itself an honest result).
- **Parameterization:** REUSE `run_session_077.py` with explicit CLI args; do **not** change its defaults. The only code change is raising the hard cap (the CLI refuses any `--cost-ceiling > $8` today).
- **Cost ceiling for the run:** `--cost-ceiling 35` (~30% margin over $26.5); **hard cap raised 8.0 → 40.0** (a sane runaway guard well above the run + margin).

## Changes
1. `ares/dialectic/measurement/architect_framing_schema.py`: `ARCHITECT_FRAMING_HARD_CEILING_USD` **8.0 → 40.0**. This is the **only** existing-file edit. It does not alter pilot behavior (the pilot used a $6 ceiling, still < 40) — it only widens the allowed ceiling band.

## Tests (TDD)
- **NEW** (`test_architect_framing_schema.py`): a ceiling between the old and new cap (e.g. **$35**) is accepted by `ArchitectFramingConfig` without raising. This test is **red under cap=8** (35 > 8 → raises) and **green under cap=40** — it locks the new capability and is the proof-of-change.
- **Existing cap tests stay valid by construction** (no edits): the schema test asserts `CONSTANT + 1` raises (still true at 41); the CLI test passes `--cost-ceiling 99` (> 40 → still refused).

## Offline prep deliverables (no spend)
- The hard-cap change + the new test; full suite (`tests/ ares/`) green / zero regressions.
- `python scripts/run_session_077.py --provider anthropic --dry-run` → anchor-test green, $0 (proves the harness is wired and the anchor guard holds).
- Run-plan doc `docs/superpowers/plans/2026-06-04-s077-scale-run-plan.md` (or alongside the plan): the exact `--confirm-live` command, the cost math, the `--preflight-only` ≈ $0.05 nuance, and what to watch in the output (`control_valid`, `halt_reason`, `deferred_scenario_ids`).

## No-spend boundary
Prep stops at `--dry-run` + the analytical estimate above. The **first spend is Dan's**: `--preflight-only` (samples 3 live cycles ≈ $0.05, refines the estimate) → review → `--confirm-live` (~$26.5).

## Out of scope
- The live measurement run itself (Dan-gated).
- Changing `run_session_077.py` defaults, or the metrics / selection / control / report logic.
- Any schema change beyond the single hard-cap constant.
