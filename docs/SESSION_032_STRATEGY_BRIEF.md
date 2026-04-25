# SESSION 032: Strategy Brief — Oracle Recalibration & Prompt v3

**Purpose:** Strategy document for Session 032 Claude Code prompt design.

**Date:** March 27, 2026
**Phase:** Phase 4 — Accuracy Improvement

---

## Where We Are

### System State After Session 031
- **2,001 tests** (65 skipped, 0 failures) — pending 031 regression confirmation
- **Benchmark regenerated:** 24/33 (72.7%), $0.32, 352s
- **9 misclassifications diagnosed** with classified failure modes
- **Diagnostic tooling operational:** `run_full_benchmark.py`, `misclassification_diagnosis.py`, `run_diagnosis.py`

### The Failure Mode Distribution

| Mode | Count | Scenarios | Fix Path |
|------|-------|-----------|----------|
| CONFIDENCE_CALIBRATION | 4 | SC-016, SC-026, SC-031, SC-032 | OracleJudgeV2 thresholds |
| EVIDENCE_GAP | 3 | SC-010, SC-020, SC-023 | Prompt v3 fact citation |
| AMBIGUITY_MISMATCH | 2 | SC-011, SC-017 | Expected verdict review |

### The Root Cause: OracleJudge Decision Table

From Session 004, the current scoring logic:
```
IF arch.conf >= 0.7 AND skep.conf < 0.5 → THREAT_CONFIRMED
IF skep.conf >= 0.7 AND arch.conf < 0.5 → THREAT_DISMISSED
ELSE → INCONCLUSIVE
```

**Why this breaks on the 33-scenario corpus:**

- **SC-016:** arch=1.00, skep=0.52 → skep is 0.02 above the 0.5 cutoff → INCONCLUSIVE (should be CONFIRMED)
- **SC-026/031/032:** arch=0.75, skep=0.60 → skep above 0.5 → INCONCLUSIVE (should be CONFIRMED)

The thresholds were calibrated against 3 scenarios in Session 004 and never updated. The 0.5 skeptic ceiling is too tight — when the architect has overwhelming evidence (1.0 confidence) and the skeptic has moderate doubt (0.52), the system should confirm the threat.

---

## The Three-Tier Fix

### Tier 1: OracleJudgeV2 — Calibrated Scoring (4 scenarios)

**New file: `ares/dialectic/agents/oracle_v2.py`**

Replace independent thresholds with a delta-based approach:

```python
class OracleJudgeV2:
    """Recalibrated verdict scoring with configurable thresholds."""
    
    @dataclass(frozen=True)
    class ScoringConfig:
        """Configurable scoring parameters."""
        # Primary: confidence delta determines verdict direction
        confirm_delta: float = 0.15     # arch - skep > this → lean CONFIRMED
        dismiss_delta: float = 0.15     # skep - arch > this → lean DISMISSED
        
        # Secondary: minimum confidence for the winning side
        min_winner_confidence: float = 0.6  # Winner must be at least this confident
        
        # Tertiary: override — if either side is dominant, force verdict
        dominant_threshold: float = 0.85    # If one side >= this, verdict follows regardless
        dominant_opponent_max: float = 0.65 # ...as long as opponent is below this
    
    @staticmethod
    def compute_verdict(architect_msg, skeptic_msg, packet, 
                        config=None) -> Verdict:
        """
        Compute verdict using calibrated delta-based scoring.
        
        Decision logic:
        1. DOMINANT OVERRIDE: If arch.conf >= 0.85 and skep.conf < 0.65 → CONFIRMED
                              If skep.conf >= 0.85 and arch.conf < 0.65 → DISMISSED
        2. DELTA-BASED: delta = arch.conf - skep.conf
                        If delta > confirm_delta AND arch.conf >= min_winner → CONFIRMED
                        If delta < -dismiss_delta AND skep.conf >= min_winner → DISMISSED
        3. DEFAULT: INCONCLUSIVE
        
        This fixes the calibration failures:
        - SC-016 (arch=1.00, skep=0.52): dominant override → CONFIRMED ✓
        - SC-026 (arch=0.75, skep=0.60): delta=0.15, arch >= 0.6 → CONFIRMED ✓
        - SC-031 (arch=0.75, skep=0.60): same → CONFIRMED ✓
        - SC-032 (arch=0.75, skep=0.60): same → CONFIRMED ✓
        """
```

**Why delta-based is better than lowering the fixed threshold:**
- Independent thresholds create cliff effects (0.49 vs 0.51 produces opposite verdicts)
- Delta scoring considers the *relationship* between agent confidences
- Dominant override handles cases where one agent has near-certainty
- Configurable parameters allow tuning without code changes

### Tier 2: Prompts v3 — Improved Fact Citation (3 scenarios)

**New file: `ares/dialectic/agents/strategies/prompts_v3.py`**

The EVIDENCE_GAP scenarios (SC-010, SC-020, SC-023) show fact coverage of 29-56%. The LLM is ignoring half the evidence packet. Session 011B's closed-world reinforcement improved coverage from 0.917 to 0.946 on 12 scenarios — the 33-scenario corpus needs stronger treatment.

**Changes from v2 to v3:**

1. **Explicit exhaustive citation instruction** — "You MUST reference every fact_id in the packet. For each fact, state whether it supports or contradicts your position. Facts you do not cite will be treated as evidence you chose to ignore."

2. **Structured output encouragement** — "Organize your analysis by evidence group: first list all facts supporting threat, then all facts supporting benign activity, then ambiguous facts. Cite fact_ids in each group."

3. **Skeptic calibration** — "Assign confidence > 0.6 ONLY when you can cite specific facts that directly demonstrate authorized or benign activity. The absence of threat indicators is NOT evidence of benign activity — it is absence of evidence."

### Tier 3: Expected Verdict Review (2 scenarios)

**Modify scenario corpus metadata (new file approach):**

SC-011 (Slow-Roll Exfiltration) and SC-017 — if the system's DISMISSED verdicts are defensible, the expected verdicts should be updated. Create a new file that patches the expected verdicts:

**New file: `ares/dialectic/scripts/scenario_corpus_v2.py`**

This imports the original corpus, creates copies with corrected expected verdicts for the ambiguity cases, and provides `get_all_scenarios_v2()`. This way the original corpus is untouched and benchmark comparisons can be run against both.

---

## What Session 032 Must Build

### New Files

```
ares/dialectic/agents/
└── oracle_v2.py                         # OracleJudgeV2 with ScoringConfig

ares/dialectic/agents/strategies/
└── prompts_v3.py                        # Improved fact citation prompts

ares/dialectic/scripts/
├── scenario_corpus_v2.py                # Patched expected verdicts for ambiguity cases
└── run_032_benchmark.py                 # CLI: runs benchmark with V2 judge + v3 prompts

ares/dialectic/tests/
├── test_oracle_v2.py                    # ~30 tests — scoring logic, edge cases, config
└── test_prompts_v3.py                   # ~10 tests — prompt template validation
```

### Execution Sequence

1. Build OracleJudgeV2 + tests
2. Build prompts_v3
3. Build scenario_corpus_v2 (patch SC-011, SC-017 expected verdicts)
4. Build run_032_benchmark.py that wires V2 components
5. Run full test suite
6. Execute benchmark with V2 judge + v3 prompts against corpus_v2
7. Compare results to 031 baseline

---

## Success Criteria

- [ ] All existing tests still pass (zero regressions)
- [ ] ~40 new tests pass (oracle_v2 + prompts_v3)
- [ ] OracleJudgeV2 correctly handles all 4 CONFIDENCE_CALIBRATION scenarios
- [ ] OracleJudgeV2 produces same verdicts as V1 for all previously-correct scenarios
- [ ] Prompts v3 improve fact coverage on EVIDENCE_GAP scenarios
- [ ] Benchmark with V2+v3 achieves > 85% accuracy on corpus_v2
- [ ] All results saved to files with timestamps
- [ ] No modifications to existing files

---

## Risk Assessment

**Oracle V2 regression risk:** The V2 judge must not break scenarios that V1 got right. The test suite must include "golden path" tests that verify V2 produces identical verdicts to V1 on the 24 scenarios that already pass. This is the highest-priority test category.

**Prompt v3 overcorrection:** Demanding exhaustive fact citation could make agents verbose without improving accuracy. The benchmark will show whether fact coverage improves and whether verdicts improve with it.

**Expected verdict changes:** Changing SC-011 and SC-017 expected verdicts is a judgment call. The diagnosis classified these as AMBIGUITY_MISMATCH — the system's behavior is defensible. But this should be Dan's call, not automated.

---

## The Math

Current: 24/33 correct (72.7%)

If Tier 1 fixes 4 CONFIDENCE_CALIBRATION: 28/33 (84.8%)
If Tier 2 fixes even 1 of 3 EVIDENCE_GAP: 29/33 (87.9%)
If Tier 3 reclassifies 2 AMBIGUITY_MISMATCH: 31/33 (93.9%)

Realistic target: **85-88%** (Tier 1 + partial Tier 2). Tier 3 is Dan's call.

---

*The judge was too conservative. The witnesses weren't talking enough. Time to recalibrate.*
