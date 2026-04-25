# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework
for cybersecurity defense. Phase 3: Selective Escalation Architecture.

## Current Status
- Phase 3, Session 024 (Session 3 of 4)
- 1,825 tests passing across 23 sessions, zero regressions
- Two-gate selective escalation architecture built:
  - EscalationGate (Session 022): detects uncertainty
  - MiscalibrationDetector (Session 023): detects overconfidence
  - ClaimAuditor (Session 023): per-claim evidence audit on flagged verdicts
- Expanded corpus of 33 scenarios operational
- Single-turn accuracy: 78.8%. Multi-turn: 75.8%
- Session 024 is the measurement session — does selective escalation beat single-turn?

## Tech Stack
- Python 3.11, Windows + PowerShell + venv
- Anthropic API (Claude Sonnet) for LLM strategies
- Redis for Memory Stream

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** — Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** — Not mysterious AI behavior
3. **All dataclasses frozen** — Immutability enforced at the type level
4. **New files only** — Never modify existing files
5. **Zero regressions** — Non-negotiable across all sessions
6. **Measurement before optimization** — Every change is benchmarked

## Two-Gate Architecture (Phase 3)
```
Single-Turn Verdict
    ├──→ EscalationGate: confidence in [0.35, 0.70] → ESCALATE (uncertainty)
    └──→ MiscalibrationDetector: 4 pattern checks → INSPECT (overconfidence)
              └──→ ClaimAuditor: per-claim support → CONFIRMED or MISCALIBRATED

If EITHER gate triggers → run multi-turn debate, use that verdict
If NEITHER triggers → accept single-turn verdict
```

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run tests
python -m pytest ares/ -v

# Run specific test file
python -m pytest ares/dialectic/tests/coordinator/test_calibration.py -v

# Run selective escalation benchmark (live LLM calls)
python -m ares.dialectic.scripts.run_selective_benchmark

# Run full benchmark (compare all modes)
python -m ares.dialectic.scripts.run_full_benchmark
```

## Session Progress
| Session | Component | Tests | Cumulative |
|---------|-----------|-------|------------|
| 001–010 | Phase 1: Core Architecture | 1,104 | 1,104 |
| 011–014 | Phase 2: Scenarios, Benchmarks, Prompts | 304 | 1,408 |
| 016–020 | Extractors + Anchored Debate | 187 | 1,595 |
| 021 | Corpus Expansion (18→33 scenarios) | 68 | 1,663 |
| 022 | EscalationGate + Full Benchmark | 73 | 1,736 |
| 023 | MiscalibrationDetector + ClaimAuditor | 89 | 1,825 |
| **024** | **Calibration Metrics + Selective Escalation** | **TBD** | **TBD** |

## Key Files (Phase 3)
- `ares/dialectic/coordinator/escalation.py` — EscalationGate (Session 022)
- `ares/dialectic/coordinator/miscalibration.py` — MiscalibrationDetector (Session 023)
- `ares/dialectic/coordinator/claim_audit.py` — ClaimAuditor (Session 023)
- `ares/dialectic/scripts/expanded_scenarios.py` — 15 new scenarios (Session 021)
- `ares/dialectic/scripts/benchmark_analysis.py` — FP/FN/tier analysis (Session 021)
- `ares/dialectic/scripts/run_full_benchmark.py` — 33-scenario runner (Session 022)
- `ares/dialectic/scripts/escalation_analysis.py` — Threshold sweep (Session 022)
- `ares/dialectic/scripts/miscalibration_analysis.py` — Combined gate analysis (Session 023)
