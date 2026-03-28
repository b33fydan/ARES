# ARES Development Project — CLAUDE.md

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework 
for cybersecurity defense. Three specialized agents (Architect, Skeptic, Oracle) 
analyze security events within a closed-world evidence architecture.

## Current Status
- **Phase 4: Accuracy Improvement** — IN PROGRESS
- **Tests:** 2,001 collected (65 skipped, 0 failures)
- **Sessions completed:** 001–031 (Session 032 next)
- **Benchmark (Session 031):** 24/33 (72.7%), $0.32
- **Diagnosed failures:** 4 CONFIDENCE_CALIBRATION, 3 EVIDENCE_GAP, 2 AMBIGUITY_MISMATCH
- **Visual pipeline:** Corpus-proven, 33/33 valid

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** — Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** — Not mysterious AI behavior
3. **Single-turn production pipeline** — Multi-turn debate degrades accuracy
4. **Frozen dataclasses everywhere** — Immutability as architectural constraint
5. **New files only** — Never modify existing files
6. **Zero regressions** — Non-negotiable across all sessions

## Development Commands
```powershell
.\venv\Scripts\Activate.ps1
python -m pytest ares/ -v
```

## Session 032 Goal
Fix 72.7% → 85%+ via three tiers:
1. OracleJudgeV2 with delta-based scoring (fixes 4 CONFIDENCE_CALIBRATION)
2. Prompts v3 with exhaustive fact citation (targets 3 EVIDENCE_GAP)
3. Corpus v2 with patched expected verdicts (resolves 2 AMBIGUITY_MISMATCH)

## OracleJudge V1 Decision Table (the problem)
```
IF arch >= 0.7 AND skep < 0.5 → CONFIRMED
IF skep >= 0.7 AND arch < 0.5 → DISMISSED
ELSE → INCONCLUSIVE
```
Failure: SC-016 (arch=1.00, skep=0.52) → INCONCLUSIVE because skep > 0.50 by 0.02

## OracleJudgeV2 Fix
Delta-based: dominant override (>0.85) + confidence delta (>0.15) + min winner threshold (>0.60)
