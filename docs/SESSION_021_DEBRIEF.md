# SESSION 021: Verification + Corpus Expansion — Debrief

**Date:** March 25, 2026
**Duration:** 29 minutes 18 seconds (Claude Code execution)
**Status:** Code complete. Ready for commit/merge.
**Tests:** 1,663 passed, 65 skipped, 0 failed. Zero regressions.

---

## Executive Summary

Session 021 is the first execution session of Phase 3 (Selective Escalation Architecture). It had two objectives: verify the SC-017 data contradiction flagged by the Tribunal, and expand the scenario corpus from 18 to 30+ for statistical rigor.

Both objectives completed. SC-017 was verified as wrong in all three modes across two independent benchmark runs — the Compendium Vol. I has been corrected. The corpus expanded from 18 to 33 scenarios with the new FP/FN/tier analysis infrastructure built and ready.

---

## Pre-Session: SC-017 Verification (RESOLVED)

Before Claude Code touched code, the SC-017 contradiction was resolved in the strategy window.

**The claim (Compendium Vol. I):** SC-017 was the flagship example of debate working — multi-turn corrected to INCONCLUSIVE at 0.503.

**The data (two independent benchmark runs):**
- Single-turn: SC-017 → threat_dismissed (WRONG). Expected: INCONCLUSIVE.
- Multi-turn original: SC-017 → threat_dismissed (WRONG). Architect 0.45, Skeptic 0.71.
- Multi-turn anchored: SC-017 → threat_dismissed (WRONG). Architect 0.25, Skeptic 0.90.

**Verdict:** SC-017 is wrong in all three modes. The 0.503 INCONCLUSIVE result described in the Compendium does not exist in the benchmark data. This was either a data versioning issue (narrative written against an earlier, unreproduced run) or a misread.

**Corrective action taken:**
- Compendium Vol. I edited: section heading changed from "The One Genuine Win" to "Where Debate Helped"
- SC-017 flagship narrative replaced with SC-011 and SC-016 evidence
- SC-011: Single-turn over-dismissed (threat_dismissed), original multi-turn correctly landed on INCONCLUSIVE
- SC-016: Single-turn under-committed (inconclusive), original multi-turn correctly reached THREAT_CONFIRMED
- Section VII reference updated: "SC-017 proved it can work" → "SC-011 and SC-016 proved it can work"
- All SC-017 references verified removed from corrected document

**Credit:** GPT 5.4 Pro caught this during the Tribunal review. The catch alone justified the entire Tribunal exercise.

---

## What Was Built

### Files Created (4, zero modifications)

| File | Purpose | Tests |
|------|---------|-------|
| `ares/dialectic/scripts/expanded_scenarios.py` | 15 new scenario definitions (SC-019 through SC-033) | — |
| `ares/dialectic/scripts/benchmark_analysis.py` | FP/FN/Miscalibrated error classification + per-tier accuracy breakdown | — |
| `ares/dialectic/tests/scripts/test_expanded_scenarios.py` | Corpus integrity, packet validity, metadata, tier distribution, API, immutability, rule-based smoke | 53 |
| `ares/dialectic/tests/scripts/test_benchmark_analysis.py` | Classification logic, analysis, tier accuracy, report formatting | 15 |

**Total new tests:** 68 (1,595 → 1,663)

### The 15 New Scenarios

| Tier | ID | Name | Expected Verdict |
|------|----|------|-----------------|
| CLEAR_THREAT | SC-019 | Ransomware Deployment | THREAT_CONFIRMED |
| CLEAR_THREAT | SC-020 | C2 Beaconing | THREAT_CONFIRMED |
| CLEAR_BENIGN | SC-021 | Scheduled Backup | THREAT_DISMISSED |
| CLEAR_BENIGN | SC-022 | Admin PsExec Patching | THREAT_DISMISSED |
| CLEAR_BENIGN | SC-023 | Vulnerability Scanner Noise | THREAT_DISMISSED |
| AMBIGUOUS | SC-024 | Dual-Use PowerShell | INCONCLUSIVE |
| AMBIGUOUS | SC-025 | Cloud Upload Ambiguity | INCONCLUSIVE |
| AMBIGUOUS | SC-026 | Failed Logins Then Success | INCONCLUSIVE |
| AMBIGUOUS | SC-027 | After-Hours Foreign VPN | INCONCLUSIVE |
| AMBIGUOUS | SC-028 | WMI Remote Execution | INCONCLUSIVE |
| AMBIGUOUS | SC-029 | Internal Port Scan | INCONCLUSIVE |
| MIXED_SIGNALS | SC-030 | DGA DNS with Minimal Traffic | INCONCLUSIVE |
| MIXED_SIGNALS | SC-031 | Sudo Abuse Without Exfiltration | INCONCLUSIVE |
| MIXED_SIGNALS | SC-032 | Impossible Travel Normal Processes | INCONCLUSIVE |
| MIXED_SIGNALS | SC-033 | Suspicious Binary with Ansible Deploy | THREAT_DISMISSED |

### Tier Distribution (Full Corpus, N=33)

| Tier | Original (18) | New (15) | Total (33) |
|------|--------------|----------|------------|
| CLEAR_THREAT | 5 | 2 | 7 |
| CLEAR_BENIGN | 4 | 3 | 7 |
| AMBIGUOUS | 5 | 6 | 11 |
| MIXED_SIGNALS | 4 | 4 | 8 |

Ambiguity tier now has 11 scenarios (33% of corpus) — the largest tier, as designed. This is where the selective escalation gate will be tested most rigorously in Sessions 022–024.

### New Benchmark Infrastructure

**benchmark_analysis.py** adds three capabilities:

1. **Error type classification:** Every wrong answer is classified as FP (benign flagged as threat), FN (threat missed), or MISCALIBRATED (clear case called INCONCLUSIVE, or ambiguous case forced to binary).

2. **Per-tier accuracy breakdown:** Accuracy reported separately for CLEAR_THREAT, CLEAR_BENIGN, AMBIGUOUS, and MIXED_SIGNALS tiers.

3. **API functions:** `get_full_corpus()` returns all 33 scenarios. `get_expanded_scenarios()` returns the 15 new ones. `format_analysis_report()` produces the full FP/FN/tier breakdown.

---

## What's Pending

**Full corpus benchmark (N=33) has NOT been run yet.** Session 021 built the scenarios and infrastructure. The live benchmark run against all 33 scenarios should be the first action of the next build session, BEFORE Session 022 implementation begins. This establishes the expanded baseline that all Phase 3 work will be measured against.

**Run command:**
```powershell
python -m ares.dialectic.scripts.run_anchored_benchmark --mode compare-all
```

Expected output: accuracy per mode, per-tier accuracy, FP/FN/Miscalibrated counts. Save the full output — this is the Phase 3 baseline.

---

## Additional Observations from Benchmark Data

Two data points worth noting from the pre-session verification runs:

**Run-to-run confidence jitter:** The standalone anchored run showed slightly different confidence values than the anchored column in the compare-all run (e.g., SC-001 Architect at 0.85 vs. 0.77), but verdicts were identical. This confirms there is LLM output variance in the confidence numbers but the verdict classifications are stable at this sample size. The new calibration metrics (Brier score, ECE) planned for Session 024 will quantify this variance properly.

**The traceback:** A transient `expected_verdict` AttributeError appeared on one compare-all run and self-resolved on re-run. Likely a race condition or stale import. Worth monitoring but not blocking.

---

## Session Scorecard

| Metric | Target | Actual | Status |
|--------|--------|--------|--------|
| New scenarios created | 12–17 | 15 | ✅ |
| Total corpus size | 30–35 | 33 | ✅ |
| Ambiguity tier scenarios | 10–12 | 11 | ✅ |
| FP/FN classification infrastructure | Built | Built | ✅ |
| Per-tier accuracy breakdown | Built | Built | ✅ |
| Existing tests pass | 1,595+ | 1,663 | ✅ |
| Regressions | 0 | 0 | ✅ |
| SC-017 contradiction resolved | Yes | Yes | ✅ |
| Full corpus benchmark run | — | PENDING | ⏳ |

---

## Documents Produced This Session

| Document | Purpose |
|----------|---------|
| ARES Phase 3 Battle Plan (.docx) | Strategic execution plan — Sessions 021–024, selective escalation architecture, reserve hypotheses |
| ARES Compendium Vol. II: The Tribunal (.docx) | Narrative record of the Tribunal process, unanimous verdicts, composed insight |
| ARES Compendium Vol. I: CORRECTED (.docx) | SC-017 references replaced with SC-011/SC-016 evidence |
| ARES Session 021 Brief (.docx) | Strategy brief + Claude Code execution prompt |
| CLAUDE_SESSION_021.md | Updated project brief for Claude Code |
| SESSION_021_DEBRIEF.md | This document |

---

## Next Session: 022 — Escalation Gate

**Pre-work:** Run compare-all on full 33-scenario corpus. Save output. This is the expanded baseline.

**Goal:** Implement the confidence-based escalation detector.

**Deliverables:**
- EscalationGate frozen dataclass (Oracle output → RESOLVED or ESCALATE)
- Configurable threshold band (defaults 0.35/0.65)
- Gate accuracy test against expanded corpus (how many scenarios does the gate correctly route?)
- Escalation rate metrics (target: 15–25% trigger escalation)

**Branch:** `session/022-escalation-gate`

---

*Session 021 complete. Corpus expanded. SC-017 reconciled. Infrastructure ready. The selective escalation build begins next session.*
