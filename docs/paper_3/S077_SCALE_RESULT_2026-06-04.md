# S077 Scale — Live Result (Architect-path framing, K=20, all 17 scenarios)

**Date:** 2026-06-04 · **Run:** `20260604-193410-9a21b3` · **Model:** Sonnet 4 (`claude-sonnet-4-20250514`) · **Cost:** $24.58 · **git:** 2418f46

## What we did
The S077 pilot measured Architect cited-fact framing-divergence (with LLM sampling noise controlled) at K=8 over 6 of 17 diverging scenarios, and found the effect "REAL but small" (Jaccard ~0.17–0.29). S082 raised the framing hard cap (`ARCHITECT_FRAMING_HARD_CEILING_USD` 8→40) so the same measurement could run **uniform K=20 over all 17 diverging scenarios** — a single-K, publication-defensible dataset. This is the live run of that scaled measurement.

- **Command:** `run_session_077.py --provider anthropic --k 20 --max-scenarios 17 --cost-ceiling 35 --confirm-live`
- **Run:** 1,680 cycles (1700 − 20 for INJ-009's one no-op operator), ~5h21m, `halt: completed` (0 deferrals), one transient HTTP 529 that self-recovered.
- **Method (unchanged from S077):** repeated-baseline resampling; Jaccard distance on the Architect's cited-fact set (the surface copied into `Oracle.supporting_fact_ids`); within-resample noise vs cross (framing) distance; mean-shift permutation test + bootstrap 95% CI; **positive control** = drop a baseline-cited fact (the control must exceed the noise floor for a scenario's verdicts to count).

## Result
- **15 / 17 scenarios are control-valid.** INJ-006 and INJ-010 had invalid positive controls → their verdicts are excluded as unreliable (pilot was 5/6 valid). `control_valid: False` in the summary is the AND-aggregate across all 17 — benign; the measurement is sound on the 15.
- **Framing channel is real on ~half the valid scenarios:** **11 `framing_channel_real` operator-verdicts across 7 of 15 scenarios** (INJ-001, 002, 012, 013, 014, 015, 020). The remaining 8 valid scenarios are `within_noise` / `inconclusive`.
- **Magnitude — pilot's "small" holds at the median, with a real heavy tail:** 8 of the 11 real verdicts sit at Jaccard **0.17–0.29** (the pilot band); **median ≈ 0.20**. But the larger N surfaces strongly-steerable scenarios the 6-scenario pilot missed:
  - **INJ-020 — all three operators at +0.80** (tight CI [0.80, 0.80], p=0.000): the standout, reliably framing-steerable.
  - **INJ-014 — prefix at +0.50.**

### Per-scenario summary (control-valid scenarios with a real channel)
| Scenario | real operators (effect) |
|---|---|
| INJ-001 | suffix +0.286 |
| INJ-002 | prefix +0.167, synonym +0.167 |
| INJ-012 | suffix +0.250 |
| INJ-013 | prefix +0.200, suffix +0.200 |
| INJ-014 | prefix +0.500 |
| INJ-015 | prefix +0.200 |
| INJ-020 | prefix +0.800, suffix +0.800, synonym +0.800 |

(Full per-operator table incl. p-values and CIs: `data/paper_3/leakage_runs/20260604-193410-9a21b3/ARCHITECT_FRAMING_20260604-193410-9a21b3.md`.)

## Interpretation
- The scale-up **confirms the deflated pilot finding**: with sampling noise controlled, Architect-path framing-divergence is real but median-small (~0.20 Jaccard), far below the uncontrolled 60–78% LLM-path headline (S059/S075).
- **What's new at full N:** the effect is **not uniformly tiny** — a minority of scenarios (notably INJ-020) are strongly and reliably framing-steerable across all operators. The channel exists and occasionally bites hard; the headline "small" describes the central tendency, not the tail.
- 2/17 scenarios remain unmeasurable (controls invalid: INJ-006, INJ-010) — their Architect citations are too unstable for the positive control to register signal.

## Caveats
- `inconclusive` is a mixed bucket: some are 0-effect/0-noise (operator near no-op on that scenario); INJ-032 shows large point effects (~0.83) but wide CIs (p≈0.07) — genuinely uncertain, not "small."
- This is **future-work / camera-ready input only**. It does **not** touch the frozen Paper 3 submission artifact.

## Artifacts
- Report: `data/paper_3/leakage_runs/20260604-193410-9a21b3/ARCHITECT_FRAMING_20260604-193410-9a21b3.md`
- Traces: `data/paper_3/leakage_runs/20260604-193410-9a21b3/traces.jsonl` (1,680 records)
