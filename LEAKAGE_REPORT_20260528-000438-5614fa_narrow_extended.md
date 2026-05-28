# LEAKAGE_REPORT — 20260528-000438-5614fa (narrow-extended)

## 1. Run metadata

- **run_id**: `20260528-000438-5614fa`
- **timestamp**: `2026-05-28T00:04:38Z`
- **git_sha**: `914c8d5`
- **provider**: `openai`
- **model**: `gpt-4o`
- **total_cost_usd**: `$1.0022`
- **cycles_completed**: `131`
- **halt_reason**: `completed`
- **anchor_test_at_start**: `pass`
- **anchor_test_at_end**: `pass`
- **operator_set**: `['framing_prefix_v1', 'framing_suffix_v1', 'synonym_substitution_conservative_v2']`
- **confidence_drift_threshold**: `0.1`
- **traces_path**: `C:\ares-phase-zero\data\paper_3\leakage_runs\20260528-000438-5614fa\traces.jsonl`
- **sha256_path**: `C:\ares-phase-zero\data\paper_3\leakage_runs\20260528-000438-5614fa\traces.sha256`
- **measurement_mode**: `characterization` (no halt on narrow fire; light path only)

## 2. Narrow stability rate

**Light Skeptic byte-stability on the deterministic path** across all skeleton-preserving paired mutations.

- **pairs_evaluated**: 98
- **pairs_stable_narrow**: 98
- **pairs_narrow_fired**: 0

- **narrow_stability_rate**: `98 / 98 = 1.0000`
- **narrow_stability_percent**: `100.00%`

## 3. Per-operator narrow stability rate

| operator | n_evaluated | n_stable | n_fired | stability_rate | stability_percent |
|---|---|---|---|---|---|
| `framing_prefix_v1` | 33 | 33 | 0 | 1.0000 | 100.00% |
| `framing_suffix_v1` | 33 | 33 | 0 | 1.0000 | 100.00% |
| `synonym_substitution_conservative_v2` | 32 | 32 | 0 | 1.0000 | 100.00% |

## 4. Per-pair record table (narrow fires only)

**No narrow fires observed.** Light Skeptic was byte-stable on every evaluated pair.

## 5. Cross-reference to Session 059

This run **extends only the narrow-reading characterization** of Paper 3's claim. The Session 059 run-2 report (`LEAKAGE_REPORT_20260510-193950-f401a8.md`) remains the canonical locked verdict for both readings:

- Session 059 narrow verdict (N=2 light pairs): `Paper 3 claim status (narrow / Light Skeptic only): ALIVE`
- Session 059 brief-broad verdict (N=2 light pairs): `Paper 3 claim status (brief_broad / Light + Oracle + Final): DEAD`

Session 060 expands the narrow N from 2 to the achievable bound under the cost ceiling. **The broad-reading verdict is unchanged by this run** and remains DEAD per the Oracle citation-surface passthrough finding documented in Session 059's debrief.

## 6. Paper 3 narrow-claim status

`Paper 3 narrow claim: HOLDS at 98/98 pairs (100.00%)`
