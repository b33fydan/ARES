# ARES Development Project — CLAUDE.md

## Context
Building ARES (Adversarial Reasoning Engine System) — a dialectical AI framework 
for cybersecurity defense. Three specialized agents (Architect, Skeptic, Oracle) 
analyze security events within a closed-world evidence architecture.

## Current Status
- **Phase 3: CONCLUDED** — Multi-turn thesis formally dead. Selective escalation built + benchmarked.
- **Phase 4: Visualization & Content Infrastructure** — IN PROGRESS
- **Tests:** 1,992 collected (1,927 passed, 65 skipped live LLM), 0 failures
- **Sessions completed:** 001–029 (Session 030 next)
- **Production accuracy:** 81.8% single-turn on 33-scenario corpus
- **Visual layer:** Event emitter + nw_wrld 3D modules shipped (Session 029)

## Tech Stack
- Python 3.11, Windows + PowerShell + venv
- Anthropic API (Claude) for LLM strategies
- WebSocket (visual emitter → nw_wrld)

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

## Session Workflow
1. Claude (strategy window) produces strategy brief + CC prompt
2. Dan hands CC prompt to fresh Claude Code instance
3. Dan reports results verbatim
4. Claude analyzes and produces next deliverable set

## Key Findings
- Multi-turn debate: 83.3% accuracy vs 91.7% single-turn (12-scenario pilot)
- Debate amplifies commitment bias without richer evidence
- Selective escalation (Phase 3): infrastructure complete, same negative result
- Single-turn ceiling on 33 scenarios: 81.8%
- Next accuracy lever: evidence extraction quality + prompt engineering
