# CLAUDE.md — ARES Phase 6 (post-Session 053)

**Last updated:** 2026-04-25
**Test count floor (passing):** 3,404

## Identity
ARES = Adversarial Reasoning Engine System. Cybersecurity threat analysis framework.
Location: `C:\ares-phase-zero`. Python 3.11. Anthropic API.

## Where We Are
- Paper 1 published: "The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate" (canonical PDF, 11 pages, see `docs/paper_1/CANONICAL.md`)
- Paper 2 v1.1 drafted: integrated prose + 5 figures + compiled references in a single 598 KB docx (Session 052)
- Debate chapter is CLOSED. Single-turn is production. Multi-turn stays in the lab.
- Current accuracy on threat-analysis baseline: 84.6% across 39 scenarios (33 SC + 6 PT)
- Phase 5 (Sessions 045–046): COMPLETE — injection resilience + Oracle Firewall + hot-swap
- Phase 6 (Sessions 047–051): COMPLETE — corpus expansion, full-corpus live benchmark, ablation, Light Skeptic
- Sessions 052–055: documentation reconciliation — Paper 2 v1.1 build pipeline, Paper 1 canonical decision, CLAUDE.md self-validation, citation audit + hallucination detection, Sabet remediation applied to v1.1 prose

## Canonical Artifacts
- **Paper 1:** `docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf`
- **Paper 1 reconciliation notes:** `docs/paper_1/CANONICAL.md`
- **Paper 2 v1.1 draft:** `docs/paper_2/PAPER2_DRAFT_v1_1.docx`
- **Paper 2 source markdown:** `docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md`
- **Paper 2 references:** `docs/paper_2/references.bib`
- **Phase 6 plan:** `docs/PHASE6_INJECTION_ARENA.md`

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

### Session 050 — Light Skeptic + three-way benchmark + temporal expansion
- **Finding 11: SUPPORTED.** Deterministic Light Skeptic (pure Python, zero LLM calls) matches full-LLM Skeptic on framing accuracy:
  - full: 0.8400 (21/25) · ablated: 0.7200 (18/25) · light: 0.8400 (21/25), delta = 0.0000
  - Tie or match on every family. Authority tied at 0.833 (n=6). Temporal n=5 at 100%.
  - All three live acceptance gates pass: INJ-014 / INJ-020 reach THREAT_DISMISSED under light pipeline; INJ-006 stays INCONCLUSIVE.
- Temporal expansion (INJ-031..033) → registry_v3 = 33 scenarios

### Session 051 — Paper 2 figures + docx skeleton + number_check
- Documentation-only: 0 `ares/` changes, 0 LLM runs
- 5 figures (300 DPI), 13-section docx skeleton, 18-claim number_check (all PASS)

## Sessions 052–053 — Documentation Reconciliation

### Session 052 — Paper 2 v1.1 prose integration + references compilation
- `build_v1_1.py` integrates prose from `docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md` into the v1 skeleton structure
- `build_references.py` compiles `docs/paper_2/references.bib` into the docx (ACM/AISec author-year)
- `number_check.py` extended with per-family three-way cells + prose-body substring checks (55/55 PASS)
- Source markdown placed at `docs/paper_2/source/` with 61 em-dashes scrubbed to commas
- Final: `PAPER2_DRAFT_v1_1.docx` (598 KB, 13 sections, 9 subsections, 5 figures), 55 new tests

### Session 053 — Paper 1 canonical reconciliation + CLAUDE.md freshness
- Paper 1 canonical decision: PDF is source of truth (`docs/paper_1/CANONICAL.md`)
- Title reconciliation: working title in CLAUDE.md was a paraphrase; canonical title is the long form on the PDF cover
- `gmys-casiano-2026` bib entry updated with canonical title and pointer to `CANONICAL.md`
- `tests/test_claude_md_freshness.py` makes CLAUDE.md self-validating: declared floor must be ≤ actual collected count, declared canonical paths must exist, last-updated must be a parseable ISO date

### Session 054 — Citation audit + hallucination detection
- Full enumeration of every citation in `PAPER2_DRAFT_v1_1.docx` (parenthetical + narrative forms, 6 total)
- 5/6 cite keys VERIFIED against authoritative sources; `sabet-2025` flagged HALLUCINATED (no paper by Sabet matches the cited claim across multiple search phrasings)
- Audit report: `docs/paper_2/citation_audit_report.md`
- Sabet remediation prep with 3 candidate v1.2 prose alternatives: `docs/paper_2/sabet_remediation_findings.md`
- Meta-finding footnote candidate (the hallucination is itself an instance of the semantic-framing failure class the paper describes): `docs/paper_2/meta_finding_footnote_candidate.md`
- `tests/paper_2/test_citation_existence.py`: 12 always-on structural tests + 3 env-gated network tests (ARES_RUN_NETWORK_TESTS); does NOT catch real-but-unrelated-paper substitution (semantic verification is future work)

### Session 055 — Sabet remediation + extract_citations helper patch
- B2 from `sabet_remediation_findings.md` applied to v1.1 source markdown: the (Sabet et al., 2025) sentence and 70-90% numerical claim replaced with a directional statement requiring no citation; `sabet-2025` removed from `references.bib`; v1.1 docx rebuilt; `Sabet` no longer appears anywhere in rendered prose or References section
- `build_references.extract_citations` extended to handle narrative form `Author et al. (YYYY)` (was paren-only; this is the bug that let Hossain and Lee silently drop from Session 052's coverage check)
- Regression test `test_extract_finds_all_v1_1_source_cite_keys` locks the helper contract: every cite key in the v1.1 source must round-trip through extract_citations + citation_to_bibkey to a known key
- Citation audit report extended with Remediation History section (the original HALLUCINATED finding preserved as the audit signal that surfaced the bug)
- 5 / 5 cite keys VERIFIED post-remediation; zero PLACEHOLDER entries in `references.bib`

## Architecture Constraints (NON-NEGOTIABLE)
- Frozen dataclasses everywhere. No mutable state.
- New files only. Never modify existing files unless explicitly stated.
- Zero regressions. All existing tests must pass.
- Squash merge to main only after zero regressions confirmed.
- The OracleJudge is deterministic Python — NO LLM calls in the Oracle. Ever.
- EvidencePacket is the unit of truth. SHA256-verified. Immutable.
- CLAUDE.md is self-validating ground truth: declared test floor and canonical paths are checked by `tests/test_claude_md_freshness.py`. Update floor and paths in this file rather than embedding them inline in session prompts.

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

### Paper tooling (Sessions 051–053)
- v5 prompts: `ares/dialectic/agents/strategies/prompts_v5.py`
- Paper 1 generator: `generate_paper.py` (kept for reproducibility; PDF is canonical)
- Paper 2 figures: `docs/paper_2/figures/make_figures.py`
- Paper 2 v1 skeleton builder: `docs/paper_2/build_skeleton.py`
- Paper 2 v1.1 prose integrator: `docs/paper_2/build_v1_1.py`
- Paper 2 references compiler: `docs/paper_2/build_references.py`
- Paper 2 number-check: `docs/paper_2/number_check.py` (caption + prose-body modes)

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
`main` — sessions 045–053 all squash-merged and pushed to `origin/main`.
Local-only branches `session-048..053` retained as historical refs (no upstream); safe to delete.
