# Architect-Path Framing-Sensitivity Measurement — Design Spec

**Date:** 2026-05-29
**Session:** 077 (planned)
**Status:** Design approved (Dan, 2026-05-29); pending spec review → implementation plan
**Lane:** evidentiary integrity of machine judgment under adversarial pressure

## Motivation / background

Post-S076 verification (the adversarial tribunal over the returned 4.8 trajectory eval) established two things:

1. The **narrow** non-interference result (Light Skeptic, N=287, 100% stable) is invariant **by construction**, not empirical — the Light Skeptic reads only `fact.field` while the mutators vary only `fact.value` (disjoint sets), and 2 of the 4 narrow bits are hardcoded constants. A code-level theorem. (Caveat now recorded in CLAUDE.md.)
2. The genuine, model-dependent leak is the **Architect→Oracle path**. Under framing mutation the Architect's output diverged 60–78% across models (Sonnet 74.5%, GPT-4o 77.6%, Gemini 60.5%), and that divergence reaches the deterministic verdict because the Oracle copies the Architect's cited fact IDs verbatim into `supporting_fact_ids` (`ares/dialectic/agents/oracle.py:89,102,116`).

**The problem this spec addresses:** that 60–78% number is **uncontrolled** — it conflates genuine framing sensitivity with the Architect's ordinary run-to-run sampling non-determinism. No repeated-baseline or temperature control isolates the framing-attributable component. This spec defines a controlled measurement that does.

## Goal & non-goals

**Goal:** *Characterize.* Cleanly measure how much of the Architect's divergence is attributable to attacker framing vs. LLM sampling noise, and confirm whether the framing-attributable component propagates to the deterministic verdict through the Oracle passthrough.

**Non-goals (YAGNI):**
- NOT testing or building a fix (no sanitizing the passthrough; no production-architecture change). A fix is a possible separate follow-on spec.
- NOT multi-model in this pilot (Sonnet 4.6 only; cross-model is a documented extension).
- NOT touching the Light Skeptic / narrow path (settled as a theorem).

## Research question & success criterion

**RQ:** Of the Architect's ~74.5% baseline-vs-mutated cited-fact divergence on Sonnet 4.6, how much exceeds the model's own run-to-run noise floor — and does the excess reach `Oracle.supporting_fact_ids`?

**Verdict rule:** Framing is a real influence channel **iff** mutated-vs-baseline divergence significantly exceeds the baseline-vs-baseline noise floor. A **null result** (framing sits inside the noise envelope) is an equally valid, publishable outcome — it would mean the 60–78% was mostly sampling jitter.

## Method — repeated-baseline resampling

Sonnet 4.6, **production temperature** (the regime the security claim is about).

For each pilot scenario:

1. **Noise floor:** run the unmutated `EvidencePacket` through the Architect **K = 8** times → 8 cited-fact-ID sets. Pairwise Jaccard distances among the 8 (28 pairs) = that scenario's sampling-noise distribution.
2. **Framing:** for each pre-registered framing operator — `framing_prefix_v1`, `framing_suffix_v1`, `synonym_substitution_conservative_v2` — run the mutated packet through the Architect **K = 8** times → 8 cited-fact-ID sets.
3. **Effect:** compare mutated-vs-baseline **cross** Jaccard distances (8×8 = 64 per operator) against the baseline **within** distances (28). Framing effect = the cross-distribution shifted above the within-distribution.

## Metric

- **Primary:** Jaccard distance on the Architect's cited-fact-ID set — the set copied into `Oracle.supporting_fact_ids`, i.e. the leakage surface itself.
- **Secondary:** (a) threat verdict label (`THREAT_CONFIRMED` / `THREAT_DISMISSED`) — does it flip? (b) whether `supporting_fact_ids` actually changed downstream — confirms propagation to the deterministic side.

## Positive control (closes the measurement-integrity gap)

For each scenario, also run a **deliberately altered packet** that removes or replaces the scenario's **key incriminating fact** (defined per-scenario at build time as the highest kill-chain-stage fact, i.e. the one most load-bearing for a `THREAT_CONFIRMED` verdict). This is a real **structured** change — not framing — that *should* make the Architect cite a materially different fact set. It is constructed directly, bypassing the paired mutator (which raises `SkeletonInvariantError` on structural change, by design).

**Void condition:** if the positive control's divergence does NOT exceed the noise floor by a clear margin, the harness is insensitive and the run is **void** — reported as such, not papered over. This is the "can the alarm even ring?" guard the prior harness lacked.

## Statistical treatment

- **Per-scenario:** noise-floor distribution, per-operator framing distribution, control distribution; the gap quantified with a test statistic (Mann–Whitney U on cross vs within distances) and a bootstrap CI on the effect size.
- **Aggregate:** fraction of scenarios where framing significantly exceeds noise, per operator.
- **Honesty constraints:** K = 8 is small. Report effect sizes + intervals, label inconclusive cases inconclusive, and do not over-claim on p-values alone.

## Scenario selection (build-time)

Source: the Sonnet Architect-divergence traces from the **S059 broad run** (`data/paper_3/leakage_runs/20260510-193950-f401a8/`). Select the registry-v3 scenarios whose Architect-layer (cited-fact) output diverged under mutation (~10–15 expected). **Fallback:** if per-scenario Architect divergence is not cleanly recoverable from those traces, do a one-time full registry-v3 baseline pass and select scenarios with non-trivial Architect fact citations. The exact list is determined at build, recorded in the run's `summary.json` for reproducibility.

## Artifacts (architecture-clean; new files only)

- `ares/dialectic/measurement/architect_framing_runner.py` — `ArchitectFramingConfig` (frozen), resampled-record schema, `run_preflight`, `run_measurement`. Resamples the existing Architect invocation; reuses `EvidencePacket` + the paired mutator for framing variants; constructs the positive control directly.
- `ares/dialectic/measurement/architect_framing_report.py` — markdown renderer (noise floor vs framing vs control, per-operator verdicts, honesty caveats).
- `scripts/run_session_077.py` — CLI: `--dry-run`, `--preflight-only`, `--confirm-live`, `--cost-ceiling` (hard cap; preflight cost estimate printed before any live spend).
- Output: `data/paper_3/architect_framing_runs/<timestamp>/` (per-resample traces + `summary.json` + report).
- **Tests (deterministic parts only):** Jaccard metric, cross/within partitioning, control void-condition logic, preflight cost estimate, config validation. Live LLM path behind `@pytest.mark.live_llm`.

## Constraints respected

- Oracle stays deterministic — we only resample the **Architect** (already an LLM). No LLM added to the Oracle.
- Characterization only — no modification to existing files; no production-architecture change.
- Frozen dataclasses; new files only; zero regression; the S060 byte-stability anchor is untouched (separate run dir).
- Cost ceiling enforced. Pilot tier = Sonnet only, ~10–15 diverging scenarios, K = 8 (rough est. ~$3–6; firmed by preflight before any live spend).

## Deferred extensions (explicitly out of scope here)

- Cross-model (GPT-4o, Gemini) repeat — once the Sonnet pilot shows signal. Genuinely meaningful here (the Architect *is* model-dependent), unlike the narrow case.
- Fix-probe: sanitize the `supporting_fact_ids` passthrough and re-measure the broad-kill — separate spec.
