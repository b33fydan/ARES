# CLAUDE.md — ARES Phase 6 (post-Session 051)

## Identity
ARES = Adversarial Reasoning Engine System. Cybersecurity threat analysis framework.
Location: `C:\ares-phase-zero`. Python 3.11. Anthropic API.

## Where We Are
- Paper 1 published: "Structured Dialectical Debate Degrades LLM Accuracy in Cybersecurity Threat Analysis"
- Paper 2 in drafting: figures + docx skeleton landed Session 051; prose is the next strategy window.
- Debate chapter is CLOSED. Single-turn is production. Multi-turn stays in the lab.
- Current accuracy on threat-analysis baseline: 84.6% across 39 scenarios (33 SC + 6 PT)
- Test count: **3,578 passing, zero regressions across 51 sessions**
- Phase 5 (Sessions 045–046): COMPLETE — injection resilience + Oracle Firewall + hot-swap
- Phase 6 (Sessions 047–051): COMPLETE — corpus expansion, full-corpus live benchmark, ablation, Light Skeptic

## Phase 5 Results (Sessions 045–046)
- 12 adversarial scenarios (DIRECT / FRAMING / PROPAGATION)
- Oracle Firewall: deterministic, zero LLM calls, 4 violation types
- Guarded cycle: firewall checkpoint at Architect→Skeptic junction
- Hot-swap quarantine protocol: fresh Architect on raw evidence when taint detected
- First live benchmark: Detection 58.3%, Verdict accuracy 41.7%, 0 false positives
- **Finding 7:** Deterministic firewalls catch structure (100%) but are blind to semantic framing (0%)
- **Finding 8:** Agent replacement without evidence sanitization is insufficient against evidence-embedded framing

## Phase 6 Results (Sessions 047–051)

### Session 047 — Category B framing corpus expansion + registry
- 15 new framing scenarios (INJ-013..027) in `injection_corpus_b_framing.py`
- 5 strategy families: severity / authority / temporal / causal / narrative
- `InjectionCorpusRegistry` aggregates 27 scenarios (DIRECT=4 · FRAMING=19 · PROPAGATION=4)

### Session 048 — Live benchmark on full 27-scenario corpus
- Production firewall-guarded single-turn cycle on claude-sonnet-4-6, 778s wall, 0 pipeline errors
- Family detection / verdict accuracy:
  - direct: 1.00 / 0.75
  - framing: 0.00 / 0.79 (19 scenarios)
  - propagation: 0.75 / 0.75
- Per-family accuracy >0.70: severity (1.00), temporal (1.00), causal (1.00), narrative (0.75). Authority sub-threshold at 0.67.
- **Confirms Finding 7 live on Sonnet 4.6**; surfaces candidate Finding 9 (Skeptic+Oracle rescues despite zero firewall detection)

### Session 049 — Skeptic ablation + authority family expansion
- **Finding 9 ablation:** ablated 0.6842 vs full 0.7895 (-10.53 pp) → **AMBIGUOUS**
  - Per-family: severity -33.33 pp, temporal -50.00 pp, narrative -25.00 pp, authority/causal ±0
  - 6 scenarios flipped; INJ-014 and INJ-020 (THREAT_DISMISSED) collapse to INCONCLUSIVE without Skeptic
- Authority expansion (INJ-028..030): all 3 correct; family n=6 accuracy = 0.833 (up from n=3 0.667)
- Tests: +244 (total 3,182)

### Session 050 — Light Skeptic + three-way benchmark + temporal expansion
- **Finding 11: SUPPORTED.** Deterministic Light Skeptic (pure Python, zero LLM calls) matches full-LLM Skeptic on framing accuracy:
  - full: 0.8400 (21/25) · ablated: 0.7200 (18/25) · light: 0.8400 (21/25), delta = 0.0000
  - Tie or match on every family. Authority tied at 0.833 (n=6). Temporal n=5 at 100%.
  - All three live acceptance gates pass: INJ-014 / INJ-020 reach THREAT_DISMISSED under light pipeline; INJ-006 stays INCONCLUSIVE.
- Temporal expansion (INJ-031..033) → registry_v3 = 33 scenarios
- Tests: +255 (total 3,437)

### Session 051 — Paper 2 figures + docx skeleton + number_check
- Documentation-only: 0 `ares/` changes, 0 LLM runs
- 5 figures (300 DPI), 13-section docx skeleton, 18-claim number_check (all PASS)
- Tests: +31 (total **3,578**)

## Architecture Constraints (NON-NEGOTIABLE)
- Frozen dataclasses everywhere. No mutable state.
- New files only. Never modify existing files unless explicitly stated.
- Zero regressions. All existing tests must pass.
- Squash merge to main only after zero regressions confirmed.
- The OracleJudge is deterministic Python — NO LLM calls in the Oracle. Ever.
- EvidencePacket is the unit of truth. SHA256-verified. Immutable.

## Key Code Locations

### Core pipeline
- Injection highway: `ares/dialectic/agents/strategies/llm_strategy.py:411`
- Single-turn flow: `ares/dialectic/agents/strategies/live_cycle.py`
- Guarded cycle (firewall + hot-swap): `ares/dialectic/agents/strategies/guarded_cycle.py`
- Ablated cycle (no Skeptic): `ares/dialectic/agents/strategies/ablated_cycle.py`
- Light guarded cycle (deterministic Skeptic): `ares/dialectic/agents/strategies/light_guarded_cycle.py`
- Coordinator validator: `ares/dialectic/coordinator/validator.py`
- Oracle Firewall: `ares/dialectic/coordinator/firewall.py`
- Oracle judge: `ares/dialectic/agents/oracle.py`
- Light Skeptic (pure Python rule engine): `ares/dialectic/agents/light_skeptic.py`

### Schemas
- `ares/dialectic/schemas/framing_benchmark_result.py` (v1, Session 048)
- `ares/dialectic/schemas/framing_benchmark_result_v2.py` (ablation, Session 049)
- `ares/dialectic/schemas/framing_benchmark_result_v3.py` (three-way, Session 050)
- `ares/dialectic/schemas/light_skeptic_judgment.py`

### Corpora & registries
- Categories A/B/C (12 scenarios): `ares/dialectic/scripts/injection_corpus.py`
- Category B framing expansion (15 scenarios, INJ-013..027): `ares/dialectic/scripts/injection_corpus_b_framing.py`
- Authority expansion (INJ-028..030): `ares/dialectic/scripts/injection_corpus_b_authority_expansion.py`
- Temporal expansion (INJ-031..033): `ares/dialectic/scripts/injection_corpus_b_temporal_expansion.py`
- Registry v1 (27 scenarios): `ares/dialectic/scripts/injection_registry.py`
- Registry v2 (30 scenarios): `ares/dialectic/scripts/injection_registry_v2.py`
- Registry v3 (33 scenarios): `ares/dialectic/scripts/injection_registry_v3.py`
- Existing scenario corpus: `ares/dialectic/scripts/scenario_corpus.py`

### Benchmark runners
- `ares/dialectic/scripts/run_injection_benchmark.py` (Session 046, 12-scenario)
- `ares/dialectic/scripts/run_full_corpus_benchmark.py` (Session 048, 27-scenario)
- `ares/dialectic/scripts/run_ablation_benchmark.py` (Session 049)
- `ares/dialectic/scripts/run_three_way_benchmark.py` (Session 050)

### Analysis reports
- `ares/dialectic/scripts/analysis/framing_strategy_report.py`
- `ares/dialectic/scripts/analysis/ablation_comparison_report.py`
- `ares/dialectic/scripts/analysis/three_way_comparison_report.py`

### Prompts & paper
- v5 prompts: `ares/dialectic/agents/strategies/prompts_v5.py`
- Phase 6 plan: `docs/PHASE6_INJECTION_ARENA.md`
- Paper 2 figures + skeleton + number_check: `docs/paper_2/`

### Live results
- `results/session_048/` — full 27-scenario raw + per-strategy CSV + summary
- `results/session_049/` — ablation deltas + family comparison
- `results/session_050/` — three-way deltas + Finding-11 verdict

## Publishable Findings
1. Multi-turn debate degrades accuracy
2. General prompt engineering has ~80% ceiling
3. Domain concept frameworks break that ceiling (84.6%)
4. Domain teaching = largest single improvement
5. Scoring architecture provides marginal gains
6. Confidence calibration is source-agnostic without domain structure
7. Deterministic firewalls are blind to semantic framing (confirmed live, Sonnet 4.6, 19 framing scenarios)
8. Agent replacement without evidence sanitization is insufficient
9. Skeptic+Oracle rescue of framing — **AMBIGUOUS** (-10.53 pp ablation; rescue is real but partial and family-uneven)
10. *(reserved)*
11. Deterministic Light Skeptic matches full-LLM Skeptic on framing (delta 0.00 across 25 scenarios) — **SUPPORTED**

## Branch
`main` — sessions 045–051 all squash-merged and pushed to `origin/main`.
Local-only branches `session-048..051` retained as historical refs (no upstream); safe to delete.
