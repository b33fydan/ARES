# CLAUDE.md — ARES Phase 6 Session 047

## Identity
ARES = Adversarial Reasoning Engine System. Cybersecurity threat analysis framework.
Location: `C:\ares-phase-zero`. Python 3.11. Anthropic API.

## What Just Happened
- Paper 1 drafted and published: "Structured Dialectical Debate Degrades LLM Accuracy in Cybersecurity Threat Analysis"
- Tribunal V2 (6 models unanimous): pivot to prompt injection resilience
- Debate chapter is CLOSED. Single-turn is production. Multi-turn stays in the lab.
- Current accuracy: 84.6% across 39 scenarios (33 SC + 6 PT)
- Test count: 2,903 passing, zero failures across 47 sessions
- **Phase 5 COMPLETE:** Injection resilience built, benchmarked, two new findings confirmed
- **Phase 6 Session 047 COMPLETE:** Category B corpus expanded from 4 to 19 scenarios (15 new), each with a distinct framing strategy; registry module aggregates scenarios across corpus files

## Phase 5 Results (Sessions 045–046)
- 12 adversarial scenarios (DIRECT / FRAMING / PROPAGATION)
- Oracle Firewall: deterministic, zero LLM calls, 4 violation types
- Guarded cycle: firewall checkpoint at Architect→Skeptic junction
- Hot-swap quarantine protocol: fresh Architect on raw evidence when taint detected
- **Live benchmark:** Detection 58.3%, Verdict accuracy 41.7%, 0 false positives
- **Finding 7:** Deterministic firewalls catch structure (100%) but are blind to semantic framing (0%)
- **Finding 8:** Agent replacement without evidence sanitization is insufficient against evidence-embedded framing

## Phase 6 Session 047 Deliverables
- 15 new framing-injection scenarios (INJ-013..027) in `injection_corpus_b_framing.py`
  - 5 strategy families (severity / authority / temporal / causal / narrative), each `framing_strategy` unique
  - Verdict mix: 10 THREAT_CONFIRMED · 2 THREAT_DISMISSED · 3 INCONCLUSIVE
  - `expected_firewall_detection=False` on all 15 — firewall-avoidance enforced by parametrized test
- Central `InjectionCorpusRegistry` (`injection_registry.py`) aggregating both corpus modules
  - 27 total scenarios: DIRECT=4 · FRAMING=19 · PROPAGATION=4
- 289 new tests (272 corpus-B + 17 registry); existing tree unchanged
- Runner wiring (`run_injection_benchmark.py` category dict) intentionally deferred

## Architecture Constraints (NON-NEGOTIABLE)
- Frozen dataclasses everywhere. No mutable state.
- New files only. Never modify existing files unless explicitly stated.
- Zero regressions. All existing tests must pass.
- Squash merge to main only after zero regressions confirmed.
- The OracleJudge is deterministic Python — NO LLM calls in the Oracle. Ever.
- EvidencePacket is the unit of truth. SHA256-verified. Immutable.

## Key Code Locations
- Injection highway: `ares/dialectic/agents/strategies/llm_strategy.py:411`
- Single-turn flow: `ares/dialectic/agents/strategies/live_cycle.py`
- **Guarded cycle:** `ares/dialectic/agents/strategies/guarded_cycle.py`
- **Oracle Firewall:** `ares/dialectic/coordinator/firewall.py`
- **Injection corpus (Categories A/B/C, 12 scenarios):** `ares/dialectic/scripts/injection_corpus.py`
- **Injection corpus — Category B framing expansion (15 scenarios):** `ares/dialectic/scripts/injection_corpus_b_framing.py`
- **Injection corpus registry:** `ares/dialectic/scripts/injection_registry.py`
- **Injection benchmark:** `ares/dialectic/scripts/run_injection_benchmark.py`
- **Phase 6 plan:** `docs/PHASE6_INJECTION_ARENA.md`
- Coordinator validator: `ares/dialectic/coordinator/validator.py`
- Oracle judge: `ares/dialectic/agents/oracle.py`
- Existing scenario corpus: `ares/dialectic/scripts/scenario_corpus.py`
- v5 prompts: `ares/dialectic/agents/strategies/prompts_v5.py`

## 8 Publishable Findings
1. Multi-turn debate degrades accuracy
2. General prompt engineering has ~80% ceiling
3. Domain concept frameworks break that ceiling (84.6%)
4. Domain teaching = largest single improvement
5. Scoring architecture provides marginal gains
6. Confidence calibration is source-agnostic without domain structure
7. **Deterministic firewalls are blind to semantic framing**
8. **Agent replacement without evidence sanitization is insufficient**

## Branch
`session-047-corpus-expansion-framing`
