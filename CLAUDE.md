# CLAUDE.md — ARES Phase 7 (post-Session 075)

**Last updated:** 2026-05-27
**Test count floor (passing):** 3,937

> Context-hygiene rule: this file holds current state + the last 3 sessions in full.
> Older session prose rolls off to `docs/SESSION_LOG.md` at the top of each session.
> 40k is a hard ceiling. If the ledger approaches it, roll the oldest full session down.

## Identity
ARES = Adversarial Reasoning Engine System. Cybersecurity threat analysis framework.
Location: `C:\ares-phase-zero`. Python 3.11. Multi-model LLM (Anthropic + OpenAI + Google Gemini).

## Workflow
- **CC (Claude Code) is the anchor.** Session briefs from Dan, execution by CC, debriefs in CLAUDE.md + Notion logs.
- **Claude-web is a consultant**, not the orchestrator. Dan adds session logs as markdown to Claude-web's project library.
- **Notion is a publish target**, not a coordination surface. Session logs posted after each commit.
- Decision locked Session 073-074 (2026-05-24) after diagnosing relay-drift from Sessions 061-072.

## Where We Are
- Paper 1 published: "The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent LLM Debate" (canonical PDF, 11 pages, see `docs/paper_1/CANONICAL.md`)
- Paper 2 v1.2 is canonical (Session 069).
- **Paper 3 v1.0 is COMPLETE** — prose, real figures (Session 073), all gates passing, acmart sigconf PDF ready for AISec '26 double-blind submission. Submission pipeline pending (anonymous.4open.science mirror, submission upload — Dan-manual).
- Debate chapter is CLOSED. Single-turn is production. Multi-turn stays in the lab.
- Current accuracy on threat-analysis baseline: 84.6% across 39 scenarios (33 SC + 6 PT)
- **Active direction: Step 5 — multi-model validation** (Sessions 074-075). Client infrastructure built (S074). Live measurements complete (S075): narrow ALIVE on Sonnet 4.6, GPT-4o, and Gemini 2.5 Pro. Cross-model comparison at `CROSS_MODEL_COMPARISON.md`.

### V4 Tribunal sequence (Phase 7 roadmap)
| Step | Plan | Status |
|---|---|---|
| 0 | Oracle-coupling rerun | DONE (pivoted → S057 skeleton audit) |
| 1 | Rule-satisfaction oracle | DONE (absorbed → S058 mutator) |
| 2 | NIH harness | DONE (→ S059-060 InfluenceLeakage) |
| 3 | Adaptive corpus C (3-5 sessions) | OPEN |
| 4 | Light Skeptic v2 (2-4 sessions) | OPEN |
| 5 | Multi-model validation (2-3 sessions) | **IN PROGRESS** (S074-075) |

Strategic docs: `docs/V4 Tribunal - *.md`, `docs/ARES_Tribunal_V3_Codex_Briefing.md`, `docs/Claude Code x Codex (1).md`, `docs/ARES Session Notes — Cube Sketches + Phase 7 Direction Locked (2026-05-05).md`

### Session ledger (condensed — full prose in `docs/SESSION_LOG.md`)
- Sessions 045–046 — Phase 5 COMPLETE: injection resilience + Oracle Firewall + hot-swap.
- Sessions 047–051 — Phase 6 COMPLETE: corpus expansion, full-corpus live benchmark, ablation, Light Skeptic.
- Sessions 052–055 — Documentation reconciliation: Paper 2 v1.1 build pipeline, Paper 1 canonical decision, CLAUDE.md self-validation, citation audit + hallucination detection, Sabet remediation.
- Session 056 — Pre-publish hardening: firewall fail-closed contract enforced at producer (FirewallVerdict invariant) + all three cycle consumers.
- Session 057 / Step 1 — Phase 7 opens. Skeleton-equivalence audit on `injection_registry_v3` (33 scenarios): 0 natural skeleton-equivalent groups. Decision: **mutator path forced**.
- Session 058 — Paired-scenario mutator v1 + orthogonality audit (**FAIL**) + verbatim anchor test at `light_skeptic.py:185`. Mutator path operational; v1 reproducibility-locked.
- Session 058.5 — Pre-registered v2 operator redesign. Orthogonality **FAIL but a different FAIL**: collision pairs 14 → 0; intensifier gap 31 → 13; decreaser regressed 20 → 24; aggressive synonym regressed 8 → 12. Diagnosable corpus-shape findings.
- Session 059 — First live InfluenceLeakage measurement. Dual-reading: **narrow (Light Skeptic only) ALIVE**, **broad (Light + Oracle + Final) DEAD**. Broad kill fired at Oracle `supporting_fact_ids` (Architect citation passthrough — sibling architectural finding). Run 2: $1.95 / 134 cycles / ~30 min.
- Session 060 — Narrow characterization: **100.00% stability (98/98 pairs)**, zero narrow fires across all three v2 operators. Total empirical N: 101 light pairs, zero narrow fires. $1.19 / ~16 min.
- Session 061 — 3D Pinscreen replay viewer: Python pipeline emits `pinscreen-timeline.json` (98 pins); Three.js page deployed via Netlify.
- Session 062 — Prism Labyrinth (Panel 1) renderer at `assets/ares/prism.html`. Data-driven; drift surfaces at Architect chamber per data.
- Session 063 — Prism Panel 2 (Confidence Trajectories): second view under a tab strip; shared timeline via `window.PrismState` event bus.
- Session 064 — Paper 3 v1.0 skeleton + build pipeline scaffolded. Title: "Decision Determinism, Explanation Drift". AISec at CCS. Three-leg story locked.
- Session 065 — Paper 3 v1.0 first prose (§5 + §6 of 11). 2,641 prose words. Floor 3,929 → 3,937.
- Sessions 066–068 — §7 + §4; §8/§9/§10 Discussion bloc; bibkey verification (4 verified: Greshake 2023, Guo 2024, Reiter 1978, Jacovi 2020).
- Session 069 GO 1 — Paper 2 v1.2 promoted to canonical. Adds fifth generalizable observation to §8: *deterministic verification converts semantic attacks into data integrity attacks rather than eliminating them*. number_check 55/55.
- Session 070 — Paper 3 final sections (Abstract + §1 + §2 + §3) + `references.bib` title reconcile. 1,912w new prose. Paper 3 prose feature-complete at ~8,404 body words.
- Session 071 — Paper 3 v1.0 docx built + verification-complete (37/37 PASS). Path A bibkey reconcile. Full suite 4,113+75skip+0fail.
- Session 072 — Paper 3 docx → acmart sigconf migration. pdftotext 25/25 PASS. 10 body / 11 overall. Docx pipeline retired.

### Last 3 sessions (full)
- Session 073: Paper 3 real figures — all 6 placeholder figures replaced with publication-quality vector PDFs. Squash-merged at `a60c35b`. **Phase 1 (audit)**: manifested all 6 figures — 3 DATA (fig_3 bar chart, fig_5/fig_6 code snippets), 3 DESIGN-REQUIRED (fig_1 pipeline architecture, fig_2 InfluenceLeakage 4-bit, fig_4 Verdict two-surface). Paper 2 `fig1_architecture.png` inspected: content-clean, metadata-clean (Matplotlib only), 300 DPI but raster; fresh anonymized vector render per directive. **Phase 2 (render)**: new `docs/paper_3/build_figures.py` renders all 6 to vector PDF at sigconf column widths. fig_3 locked to backed quantities only: 98/98 stable vs 73/98 diverge, matching locked prose substrings. All figures smaller than placeholders — no body page growth. Gates: pdftotext 25/25 PASS, tests/paper_3/ 99+3skip, full suite 3,863+75skip+0fail (3,938 collected, floor 3,937). Pages: **10 body / 11 overall** (unchanged). Session prompt updated with 4 strategy rulings (CSVs→source artifacts, 10/12 AISec limits confirmed, DESIGN-REQUIRED category for fig_1/2/4 with guardrails, fig_1 fresh render). **Paper 3 is now a complete submission artifact.** Strategic re-sync completed: diagnosed relay-drift from Sessions 061-072, reconciled V4 Tribunal sequence (Steps 0-2 done, 3-5 open), locked workflow decision (CC as anchor, Claude-web as consultant, Notion as publish target).
- Session 074: Multi-model client infrastructure for Step 5 (multi-model validation). New files: `openai_client.py`, `gemini_client.py`, `client_factory.py` — all share the `LLMResponse` interface from `client.py`. Provider factory dispatches on `"anthropic"` / `"openai"` / `"gemini"`. `RunnerConfig` gained `provider` field; `leakage_runner.py` factory sites updated to use `make_client()`. Smoke test: all three providers verified live (Sonnet 4.6 / GPT-4o / Gemini 2.5 Pro → PING_OK). Zero regressions (3,863+75skip+0fail). Committed `7a3e5aa`.
- Session 075: Step 5 live measurement runs — **narrow ALIVE across all three model families**. **GPT-4o**: 133 cycles, $1.66, narrow ALIVE (0/1), broad DEAD, LLM-path 76/98 diverge (77.6%). **Gemini 2.5 Pro**: 117 cycles, $2.04, narrow ALIVE (0/1), broad DEAD, LLM-path 52/86 diverge (60.5%). Both confirm the same structural findings as Sonnet 4.6 baseline: (1) Light Skeptic judgment-level output is stable under framing mutations regardless of LLM family, (2) broad kill fires at Oracle `supporting_fact_ids` passthrough (architectural, not model-dependent), (3) zero oracle/final_verdict divergence on LLM path. Gemini shows less Architect-layer framing sensitivity (60.5%) than Sonnet (74.5%) and GPT-4o (77.6%). Infrastructure: `scripts/run_session_075.py` CLI with `--provider` flag + UTF-16 `.env` loading; `RunSummary`/`NarrowExtendedSummary` gained `provider`/`model` fields; narrow runner adapted for multi-provider; `scripts/cross_model_comparison.py` renders 3-column comparison. Total Step 5 API spend: $5.65 ($1.95 + $1.66 + $2.04). Zero regressions (3,863+75skip+0fail).

## Canonical Artifacts
- **Paper 1:** `docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf`
- **Paper 1 reconciliation notes:** `docs/paper_1/CANONICAL.md`
- **Paper 2 v1.2 draft (canonical):** `docs/paper_2/PAPER2_DRAFT_v1_2.docx`
- **Paper 2 v1.2 source markdown:** `docs/paper_2/source/PAPER2_DRAFT_v1_2_source.md`
- **Paper 2 references:** `docs/paper_2/references.bib`
- **Paper 2 v1.1 (historical, retained for traceability):** `docs/paper_2/PAPER2_DRAFT_v1_1.docx`
- **Paper 3 v1.0 submission PDF (acmart sigconf, anonymized for AISec '26 double-blind):** `docs/paper_3/acmart_spike/paper_3_acmart.pdf`
- **Paper 3 v1.0 LaTeX source (generated from canonical markdown):** `docs/paper_3/acmart_spike/paper_3_acmart.tex`
- **Paper 3 v1.0 LaTeX build script:** `docs/paper_3/build_acmart.py`
- **Paper 3 v1.0 pdftotext substring gate:** `docs/paper_3/acmart_spike/verify_pdf_substrings.py`
- **Paper 3 v1.0 skeleton (structural scaffold):** `docs/paper_3/skeleton_v1_0.json`
- **Paper 3 v1.0 source markdown (canonical prose source, pandoc-style cite markers post-Session-072):** `docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md`
- **Paper 3 references:** `docs/paper_3/references.bib`
- **Paper 3 v1.0 docx (retired Session 072, archival only):** `docs/paper_3/retired/PAPER3_DRAFT_v1_0.docx`
- **Paper 3 v1.0 docx build script (retired Session 072):** `docs/paper_3/retired/build_v1_0_docx.py`
- **Paper 3 figure renderer:** `docs/paper_3/build_figures.py` (Session 073; 6 vector PDFs at `docs/paper_3/figures/fig_{1..6}.pdf`)
- **Phase 6 plan:** `docs/PHASE6_INJECTION_ARENA.md`

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
- `ares/dialectic/schemas/skeleton_equivalence.py` (Phase 7 / Session 057, skeleton hash + group)

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

### Non-interference harness (Phase 7)
- Skeleton audit script: `ares/dialectic/scripts/non_interference/skeleton_audit.py` (Session 057 / Step 1)
- Skeleton audit manifest: `docs/paper_3/skeleton_audit_v1.json`
- Paired-scenario mutator: `ares/dialectic/scripts/non_interference/paired_scenario_mutator.py` — `MutationOperator`, `MutatedScenarioPair`, `PairedScenarioMutator`, `SkeletonInvariantError`, `OPERATORS_V1` (Session 058)
- Paired-scenario mutator v2: `ares/dialectic/scripts/non_interference/paired_scenario_mutator_v2.py` — `OPERATORS_V2`, `get_v2_operator_set`, four new operators with disjoint lexicons + register-expanded severity tables (Session 058.5)
- Operator orthogonality audit: `ares/dialectic/scripts/non_interference/operator_orthogonality.py` — `OrthogonalityReport`, CLI with `--operator-set v1|v2` flag (Session 058 + 058.5 flag addition)
- Orthogonality manifest v1: `docs/paper_3/operator_orthogonality_v1.json` (FAIL)
- Orthogonality manifest v2: `docs/paper_3/operator_orthogonality_v2.json` (FAIL — different failure mode)
- Anchor test: `ares/dialectic/tests/agents/test_light_skeptic_anchor.py` — verbatim guard on `light_skeptic.py:185` (Session 058)

### Measurement (Phase 7 / Session 059)
- InfluenceLeakage schema: `ares/dialectic/measurement/influence_leakage.py` — 4-bit frozen dataclass, locked weights, kill threshold, drift threshold, layer enum, helper extractors
- Measurement runner: `ares/dialectic/measurement/leakage_runner.py` — `RunnerConfig`, `RunSummary`, `PairLeakageRecord` (with `kill_fires_narrow` / `kill_fires_brief_broad` predicates), `CycleTrace`, `run_preflight`, `run_full_measurement`, `anchor_test_passes`
- Measurement report: `ares/dialectic/measurement/leakage_report.py` — dual-verdict markdown renderer
- CLI: `scripts/run_session_059.py` — `--dry-run`, `--preflight-only`, `--confirm-live`, `--cost-ceiling` (capped at $20)
- Leakage manifests (run 2): `LEAKAGE_REPORT_20260510-193950-f401a8.md`, `data/paper_3/leakage_runs/20260510-193950-f401a8/`
- Leakage manifests (run 1, preserved as audit trail): `LEAKAGE_REPORT_20260510-184611-8e6e6d.md`, `data/paper_3/leakage_runs/20260510-184611-8e6e6d/`

### Narrow characterization (Phase 7 / Session 060)
- Narrow characterization runner: `ares/dialectic/measurement/narrow_characterization_runner.py` — `NarrowCharacterizationConfig`, `NarrowDriftRecord`, `NarrowExtendedSummary`, `run_preflight`, `run_narrow_characterization`. Cost ceiling locked at $5; light path only; no halt on narrow fire.
- Narrow report: `ares/dialectic/measurement/narrow_extended_report.py` — six-section rate-based markdown renderer with forbidden-phrase guard.
- CLI: `scripts/run_session_060.py` — `--dry-run`, `--preflight-only`, `--confirm-live`, `--cost-ceiling` capped at $5.
- Narrow-extended manifest: `LEAKAGE_REPORT_20260510-224622-154556_narrow_extended.md`, `data/paper_3/leakage_runs/20260510-224622-154556/`

### Visualization (Phase 7 / Sessions 061–063)
- 3D pinscreen pipeline: `ares/dialectic/visualization/` — `DataLoader`, `PinMapper`, `TimelineBuilder`; CLI `python -m ares.dialectic.visualization.build_timeline`; artifact `docs/marketing/pinscreen-timeline.json` (98 pins)
- v2 cycle-trace pipeline: `ares/dialectic/visualization/cycle_trace.py` + `cycle_trace_builder.py` + `build_cycle_timeline.py` (CLI); artifact `docs/marketing/prism-timeline.json` (98 pairs)
- JSON contract test: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (Session 062: 8 tests; Session 063: +4 tests, floor 3,733 → 3,737)
- Renderer (skyframe-main): `assets/ares/prism.html` + `prism.js` + `prism-timeline.json`; Panel 2 sibling files `prism-state.js` / `prism-tabs.js` / `prism-panel2.js`
- `ares.html` CTA wiring at skyframe-main repo root (Prism + Pinscreen links)
- Specs/plans under `docs/superpowers/specs/` and `docs/superpowers/plans/` (dated 2026-05-13, -19, -20)
- Parked sphere-chain attempt (do not regress to): `docs/marketing/prism-2026-05-14-sphere-chain.html`

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

### Paper 3 tooling (Phase 7 / Sessions 064–072)
- Paper 3 structural scaffold: `docs/paper_3/skeleton_v1_0.json` (Abstract + §1-§11; three-leg story; pre-registered numbers; verified vs unverified bibkeys; anchor-test index)
- Paper 3 references: `docs/paper_3/references.bib` (6 verified entries)
- Paper 3 build helpers: `docs/paper_3/build_references.py` (BibEntry/parse_bib + regression-locked `extract_citations`/`citation_to_bibkey` ported from Paper 2 Session 055)
- Paper 3 acmart LaTeX build: `docs/paper_3/build_acmart.py` (Session 072; pandoc cite-marker → natbib post-processing, acmauthoryear)
- Paper 3 acmart spike artifacts: `docs/paper_3/acmart_spike/` — `paper_3_acmart.{tex,pdf}`, `verify_pdf_substrings.py`, `page_audit.py`, `migrate_cites.py`
- Paper 3 number-check: `docs/paper_3/number_check.py` (11 skeleton-vs-source resolvers + prose-substring mode; 25 substrings locked)
- Paper 3 skeleton audit: `tests/paper_3/test_skeleton_audit.py` (49 structural tests)
- Paper 3 citation existence audit: `tests/paper_3/test_citation_existence.py` (16 always-on + 4 conditional)
- Paper 3 number-check tests: `tests/paper_3/test_number_check.py` (24 tests)
- Paper 3 Oracle passthrough anchor: `ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py` (11 tests at `oracle.py` lines 89+102+116)
- Paper 3 paired-trial byte-stability anchor: `tests/dialectic/measurement/test_paired_trial_byte_stability.py` (16 tests; SHA256 lock on Session 060 traces; 98/98 narrow assertion)

### Multi-model client infrastructure (Session 074)
- Client factory: `ares/dialectic/agents/strategies/client_factory.py` — `make_client(provider, model)`, `AnyLLMClient` union type, `VALID_PROVIDERS`
- OpenAI client: `ares/dialectic/agents/strategies/openai_client.py` — `OpenAIClient` wrapping Chat Completions API (default: `gpt-4o`)
- Gemini client: `ares/dialectic/agents/strategies/gemini_client.py` — `GeminiClient` wrapping `google.genai` SDK (default: `gemini-2.5-pro`)
- Anthropic client (unchanged): `ares/dialectic/agents/strategies/client.py` — `AnthropicClient`, `LLMResponse` (shared by all providers)
- `RunnerConfig.provider` field added to `leakage_runner.py` (default: `"anthropic"`)

### Multi-model measurement (Session 075)
- Session 075 CLI: `scripts/run_session_075.py` — `--provider`, `--model`, `--light-only`, UTF-16 `.env` loading
- Cross-model comparison: `scripts/cross_model_comparison.py` — auto-discovers runs, renders side-by-side markdown table
- GPT-4o traces: `data/paper_3/leakage_runs/20260527-121916-c543fa/`, report `LEAKAGE_REPORT_20260527-121916-c543fa.md`
- Gemini 2.5 Pro traces: `data/paper_3/leakage_runs/20260527-123857-c2d10f/`, report `LEAKAGE_REPORT_20260527-123857-c2d10f.md`
- Cross-model comparison: `CROSS_MODEL_COMPARISON.md` (auto-generated by `scripts/cross_model_comparison.py`)
- `RunSummary` and `NarrowExtendedSummary` gained `provider`/`model` fields; `summary.json` persisted alongside traces
- `NarrowCharacterizationConfig` gained `provider` field; both narrow runners use `make_client()` dispatch

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
`main` — sessions 045–073 all squash-merged and pushed to `origin/main`.
Session 074 committed `7a3e5aa` (multi-model infrastructure).
Session 075 on `session/075-multi-model-measurement` — all three model runs complete, commit pending.
Historical session branches retained locally (no upstream); safe to delete.