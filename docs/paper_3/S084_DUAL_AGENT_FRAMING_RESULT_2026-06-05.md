# S084 — Dual-Agent Framing Measurement: LIVE Result (2026-06-05)

**Run:** `20260605-194137-713674` · Sonnet 4 (`claude-sonnet-4-20250514`) · K=20 × 17 scenarios × 3 operators · 1,700 cycles · **$24.41** · 0 deferred · `halt=completed`
**Artifacts:** `data/paper_3/leakage_runs/20260605-194137-713674/` (`traces.jsonl`, `summary.json`, `DUAL_AGENT_FRAMING_20260605-194137-713674.md`)
**Harness:** `ares/dialectic/measurement/dual_agent_framing_{schema,mirror,runner,report}.py` + `scripts/run_session_084.py` (S084 build).
**Status:** future-work / camera-ready input. **Frozen Paper 3 untouched.**

## What this measured

Promotes the S083 dual-agent *recon* to a rigorous, noise-controlled result. The live `CycleTrace` already carries both `architect_cited_facts` and `skeptic_cited_facts` per cycle, so one run records both agents per resample and runs the S077 machinery (within-distance noise floor, cross-distance framing shift, permutation p + bootstrap CI, positive control) on **each agent**, plus a paired **mirror** metric (Architect direction vs Skeptic direction on the same K cycles). Scenario set = the 17 Architect-diverging scenarios (same as S082), enabling an Architect-reproduction cross-check.

## Headline findings

### 1. The Architect path reproduces S082 exactly
S084's Architect `framing_channel_real` verdicts are **identical** to S082's 11 (`20260604-193410-9a21b3`): INJ-001/suffix, INJ-002/prefix, INJ-002/synonym, INJ-012/suffix, INJ-013/prefix, INJ-013/suffix, INJ-014/prefix (+0.50), INJ-015/prefix, INJ-020/{prefix,suffix,synonym} (+0.80). Independent resample → same result. The harness measures the real channel (internal-consistency cross-check passed).

### 2. The Skeptic path is rigorously framing-sensitive (new contribution)
Skeptic `framing_channel_real` on **9 conditions / 6 scenarios**: INJ-002/{prefix,synonym}, INJ-009/prefix, INJ-020/{prefix,suffix,synonym}, INJ-024/{suffix,synonym}, INJ-031/prefix. **Control-valid 17/17.** The Skeptic's explanation drift is now a measured, noise-controlled fact rather than a dismissed-verdict recon inference (S083 could only see it via the Oracle passthrough on 6 dismissed scenarios).

### 3. The mirror is real but concentrated — honest deflation of the S083 headline
Raw mirror-class counts across the 51 conditions: **`opposed=4, aligned=5, single=20, none=21`**.

The four raw `opposed` conditions are INJ-020/{prefix,suffix,synonym} and INJ-014/prefix. **But `mirror_class` is computed on modal-set *direction* only — it does not require each agent's drift to be statistically real.** Gating on per-agent verdicts:

- **INJ-020 (all three operators):** Architect **collapse 0.80** (REAL, p≈0, within=0.00) + Skeptic **expand 0.40** (REAL, p≈0, within=0.00), verdict `threat_dismissed` held. **Both agents' drift is statistically real and opposite.** This is the rock-solid opposed mirror.
- **INJ-014/prefix:** Architect collapse 0.67 (REAL) but Skeptic expand 0.20 is **within-noise** (Skeptic within=0.20, p=0.83). A near-miss, not a rigorous opposed mirror.

So S083's "explanation drift is dual-agent and mirror-image" deflates to the calibrated claim: **the opposed (Architect-collapse / Skeptic-expand) mirror is rigorous and operator-universal on INJ-020; elsewhere dual-agent drift is single-agent (20), aligned (5, e.g. INJ-002 both collapse), or absent (21).** Same deflation shape as S077/S082 turning the uncontrolled 60–78% into "real but small."

### 4. Positive-control validity — the honest flag fired
`control_valid_skeptic = True` (17/17). `control_valid_architect = False`, flagged **INJ-010 only** (16/17 Architect controls valid). INJ-010's Architect has a high intrinsic noise floor (within median 0.40) and the single *joint*-most-cited fact dropped by the control was not Architect-load-bearing there, so the control move (cross 0.00) did not clear that agent's noise. This is exactly the single-joint-control limitation documented in the spec (§6), surfaced rather than hidden. The Architect result on INJ-010 is therefore control-unvalidated; all other Architect scenarios and **all** Skeptic scenarios are control-validated.

## INJ-020: the camera-ready centerpiece
Now measured with a noise floor: Architect baseline within = 0.00 (cites all 5 facts every resample), collapses to the lone threat fact `inj020-fact-003` under every operator → cross 0.80, p≈0; Skeptic baseline within = 0.00, expands to include `inj020-fact-003` → cross 0.40, p≈0; `threat_dismissed` invariant. The S083 paraphrase-triggered citation collapse + dual-agent mirror is confirmed at full rigor, operator-universal, both directions statistically real.

## Caveats / camera-ready refinements
- **`mirror_class` should gate on per-agent verdicts** for a "rigorous opposed" count (would yield INJ-020 ×3). The current direction-only class is a useful raw lens but over-counts (INJ-014/prefix).
- **Single joint control** under-validates an agent when the jointly-cited drop fact isn't that agent's load-bearing fact and/or the agent's noise floor is high (INJ-010). Dual independent controls (drop an Architect-cited fact *and* a Skeptic-cited fact) would close this at ~+20% cost.
- 17 Architect-diverging scenarios only (the mirror set); Skeptic-diverging-but-not-Architect-diverging scenarios are out of frame by construction.

## Reproduce
`python scripts/run_session_084.py --provider anthropic --preflight-only` (estimate) → `--confirm-live` (full run). Report renders via `dual_agent_framing_report.render_report`. Offline harness tests: `pytest tests/dialectic/measurement/test_dual_agent_framing_*.py`.
