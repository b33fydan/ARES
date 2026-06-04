# S077 Scale — live run plan (Dan-gated)

**Prereqs (offline, done in prep):** hard cap raised 8→40; `--dry-run` anchor green; `.env` present with `ANTHROPIC_API_KEY` (UTF-16 LE).

**The command:**
```
python scripts/run_session_077.py --provider anthropic --k 20 --max-scenarios 17 --cost-ceiling 35 --confirm-live
```

**Cost math:** 17 scenarios × K=20 × (2+3 ops) = 1700 cycles × ~$0.0156/cycle (pilot rate) = **~$26.5**. Ceiling $35 ≈ 30% margin; hard cap $40 is the backstop. Actual is usually a touch lower (no-op operator mutations are skipped per scenario).

**Recommended sequence:**
1. `... --dry-run` — anchor-only, $0 (already verified in prep).
2. `... --preflight-only` — samples **3 live cycles (~$0.05)** and prints `estimated_total_cost_usd` + `exceeds_ceiling`. Eyeball the estimate.
3. If the estimate looks right, rerun with `--confirm-live` for the full ~$26.5 run.

**What to watch in the summary:**
- `control_valid` — want `True` (the positive control fired on every scenario; pilot was 5/6). If `False`, note which scenario's control did not exceed the noise floor.
- `halt_reason` — want `completed`. `cost_ceiling` means it stopped early; raise `--cost-ceiling` (≤ 40) and rerun.
- `deferred_scenario_ids` — want empty. Non-empty = scenarios skipped for budget (logged, never silent).
- `total_cost_usd` — should land near $26.5.

**Outputs:** traces at `data/paper_3/leakage_runs/<run_id>/traces.jsonl`; the markdown report path is printed at the end.

**Interpretation:** this run supersedes the pilot's 6 @ K=8. The finding to confirm at full N: framing-divergence is REAL but small (per-operator cross-vs-within Jaccard ~0.17–0.29), far below the uncontrolled 60–78%. Per-operator verdicts: `framing_channel_real` / `within_noise` / `inconclusive`. INJ-008 may log inconclusive (noise too high) — that is an honest, logged result, not a failure.
