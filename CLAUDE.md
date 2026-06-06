# CLAUDE.md — ARES Phase 7 (post-Session 085)

**Last updated:** 2026-06-06
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
- **Paper 3 v1.0 is COMPLETE + submission-de-risked (S080)** — prose, real figures (Session 073), all gates passing, acmart sigconf PDF for AISec '26 double-blind. **S080 closed 3 submission blockers**: stale "Placeholder for spike measurement." captions stripped (B1); build_acmart reproducibility restored — it was silently regressing real figures to placeholder boxes (B2, empty-diff proof); figures re-rendered Type-1/TrueType, no more ACM-disliked Type 3 (B3). De-risk audit + CFP-verified checklist: `docs/paper_3/acmart_spike/SUBMISSION_DERISK_2026-06-02.md`. Remaining = Dan-manual: upload to the AISec HotCRP portal (**https://aisec26.hotcrp.com/**; single **firm** deadline 2026-07-24, **no** separate abstract registration — verified vs. CFP 2026-06-02) + optional anonymous.4open.science mirror (only if linking the repo; never print the real GitHub URL in the PDF). **B4 DONE** (post-S080, commit `c5724d6`): the `.docx` note-field was dropped from `references.bib`, so the Paper 2 self-cite renders "Preprint (2026)." only.
- Debate chapter is CLOSED. Single-turn is production. Multi-turn stays in the lab.
- Current accuracy on threat-analysis baseline: 84.6% across 39 scenarios (33 SC + 6 PT)
- **Step 5 — multi-model validation: DONE** (Sessions 074-076). Client infrastructure built (S074). Live measurements complete (S075): narrow ALIVE on Sonnet 4.6, GPT-4o, and Gemini 2.5 Pro. **Narrow characterization complete (S076): 100.00% stability on all three model families** — GPT-4o 98/98, Gemini 91/91, matching Sonnet baseline 98/98. Cross-model comparison at `CROSS_MODEL_COMPARISON.md`.
- ⚠️ **Narrow-result caveat (verified post-S076):** the N=287 / 100% narrow-stability figure is invariant *by construction*, not empirical — the Light Skeptic reads only `fact.field` while the mutators vary only `fact.value` (disjoint sets), and 2 of the 4 narrow bits are hardcoded constants. The cross-model framing is decorative (model family can't move the narrow metric). The genuine, model-dependent leak is the Architect→Oracle `supporting_fact_ids` passthrough (60–78% LLM-path divergence, S075). Does **not** affect Paper 3 (predates S074–076).
- **S081 — Paper 3 pre-flight sign-off: GO (2026-06-03).** Offline re-verification of the committed submission PDF at `5cd8d43`: full suite 4173/75skip/0fail (`tests/ ares/`), locked substrings 25/25, page budget body-10/overall-11, fonts 0-Type-3, anonymity clean (no `/Author`, `dc:creator`=Anonymous Author(s), Anon. headers), 0 placeholder text, 0 `.docx` path, no GitHub/email/ORCID leak, GenAI declaration present, no first-person self-citation. Closed both open B5 items with evidence: B5a self-cite renders the real name in one reference entry but is standard third-person practice (recommend leave as-is); B5b the 10pp body stands alone (Fig 2 never referenced in body; Fig 5 a lone parenthetical pointer). Prepped ready-to-paste anonymized-URL wording for the optional 4open mirror (NOT inserted — gated on the decision to link a repo + a recompile). No canonical artifact modified; no API spend. Squash-merged to `main` 2026-06-03 (commit `fa620cd`). Sign-off doc: `docs/paper_3/acmart_spike/PREFLIGHT_SIGNOFF_2026-06-03.md`. **Remaining = Dan-manual: HotCRP upload only.**
- **S082 — S077 scale DONE + LIVE RESULT (2026-06-04).** Raised the framing hard cap 8→40, then ran the Architect-path framing measurement uniform **K=20 over all 17 diverging scenarios** (run `20260604-193410-9a21b3`, $24.58, 1680 cycles, Sonnet 4; `run_session_077.py` reused unmodified). **Result: 15/17 scenarios control-valid (INJ-006/010 excluded); framing channel real on 7/15 scenarios (11 op-verdicts), median ~0.20 Jaccard — matches the K=8 pilot's 0.17–0.29 band — with a heavy tail (INJ-020 +0.80 on all three operators; INJ-014 prefix +0.50).** Confirms 'REAL but small' at full N; far below the uncontrolled 60–78%. Writeup `docs/paper_3/S077_SCALE_RESULT_2026-06-04.md`; squashes `6c9d648` (prep) + `034248c` (result). Future-work/camera-ready input; frozen Paper 3 untouched.
- **S083 — INJ-020 steerability root-caused (2026-06-05, analysis-only; no API/code/test changes).** S082's +0.80 heavy tail is a *paraphrase-triggered citation collapse*: the Architect cites all 5 facts at baseline and collapses to the lone threat fact `inj020-fact-003` under all three operators (Jaccard 0.80), `threat_dismissed` holding 100/100. NOT threat-amplification (operators generic/uniform/valence-opposite — the softening suffix still collapses) and NOT an Oracle passthrough (`architect_cited_facts` != `oracle_supporting_facts` in 100/100 — a separate surface — the outcome-conditioned `compute_verdict` records the *Skeptic's* facts for dismissed verdicts, so it's a different agent's channel that drifts oppositely; resolved S083). Writeup `docs/paper_3/S077_INJ020_STEERABILITY_2026-06-05.md` + reproducible `docs/paper_3/analyze_inj020_steerability.py`. Free offline recon (banked): the Skeptic's channel *mirrors* the Architect — it expands toward f3 while the Architect collapses toward it (Skeptic drifts in 10/17 conditions, 7/17 both agents), so explanation-drift is dual-agent; rigorous noise-controlled Skeptic-path numbers deferred to camera-ready. Camera-ready input; frozen Paper 3 untouched.
- **S084 — Dual-agent framing measurement DONE + LIVE RESULT (2026-06-05).** Promoted the S083 dual-agent recon to a rigorous, noise-controlled result. New peer harness `dual_agent_framing_{schema,mirror,runner,report}.py` + `scripts/run_session_084.py` records BOTH `architect_cited_facts` and `skeptic_cited_facts` per resample (the live `CycleTrace` already carries both) and runs the S077 noise-floor/cross-distance/positive-control machinery on each agent + a paired mirror metric. Live run `20260605-194137-713674` (K=20×17, Sonnet 4, **$24.41**, 1700 cycles). **Result: (1) Architect path reproduces S082's 11 REAL verdicts exactly; (2) Skeptic path rigorously framing-sensitive — REAL on 9 conditions/6 scenarios, control-valid 17/17 (the new contribution); (3) the opposed mirror (Architect collapse / Skeptic expand), gated on both agents' drift being REAL, = INJ-020 on all 3 operators (arch 0.80 / skep 0.40, verdict held) — concentrated, not universal (raw opposed=4/aligned=5/single=20/none=21); (4) honest flag `control_valid_architect=False` on INJ-010 only (high noise floor / joint drop-fact not Architect-load-bearing), Skeptic 17/17.** +18 offline tests. Writeup `docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md`. Future-work/camera-ready input; frozen Paper 3 untouched.
- **S085 — ARES-VISION "The Mirror" website hero: Part A DONE (squash-merged) + Part B staged (2026-06-06).** Public scrollytelling page off the S084 INJ-020 opposed mirror (Architect collapses to the threat fact `inj020-fact-003` / Skeptic expands to all 5 / verdict `threat_dismissed` held — real data). **Part A (ARES):** new deterministic adapter `ares/dialectic/visualization/mirror_journey_{schema,builder}.py` + `build_mirror_journey.py` → `docs/marketing/mirror-journey.json` (data-true from run `20260605-194137-713674`); +13 offline tests; full suite 4205+75skip+0fail; independently reviewed (APPROVE) + hardened (within-noise/p-value as sourced constants); no API spend. **Part B (skyframe-main, STAGED not deployed):** `assets/ares/mirror.{html,css,js}` + `mirror-journey.json` + "See it move →" link on `ares.html`; validated locally (serves + fetches). brainstorm→spec→plan→TDD→finishing; built live with Dan via the LAN visual companion. Remaining = Dan-manual: skyframe-main commit + deploy + set `#paper-link`.

### V4 Tribunal sequence (Phase 7 roadmap)
| Step | Plan | Status |
|---|---|---|
| 0 | Oracle-coupling rerun | DONE (pivoted → S057 skeleton audit) |
| 1 | Rule-satisfaction oracle | DONE (absorbed → S058 mutator) |
| 2 | NIH harness | DONE (→ S059-060 InfluenceLeakage) |
| 3 | Adaptive corpus C (3-5 sessions) | OPEN |
| 4 | Light Skeptic v2 (2-4 sessions) | OPEN |
| 5 | Multi-model validation (2-3 sessions) | **DONE** (S074-076: infra + live + narrow characterization) |

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
- Session 073 — Paper 3 real figures: 6 placeholder figures replaced with publication-quality vector PDFs. Paper 3 now a complete submission artifact. Strategic re-sync: diagnosed relay-drift, reconciled V4 Tribunal sequence.
- Session 074 — Multi-model client infrastructure for Step 5: `openai_client.py` + `gemini_client.py` + `client_factory.py` (shared `LLMResponse`); `RunnerConfig.provider`. All three providers smoke-tested live. Zero regressions. Committed `7a3e5aa`. (Full prose → `docs/SESSION_LOG.md`.)
- Session 075 — Step 5 live multi-model measurement: narrow ALIVE on Sonnet 4.6, GPT-4o, Gemini 2.5 Pro; broad kill at Oracle `supporting_fact_ids` passthrough on all three; LLM-path divergence 60.5–77.6%. $5.65 spend. Zero regressions. (Full prose → `docs/SESSION_LOG.md`.)
- Session 076 — Step 5 narrow characterization on GPT-4o + Gemini 2.5 Pro: **100.00% stability across three model families** (GPT-4o 98/98, Gemini 91/91, Sonnet 98/98; N=287, zero narrow fires). `scripts/run_session_076.py` + `cross_model_comparison.py`. $2.21 (Step 5 total $7.86). Zero regressions. (Full prose → `docs/SESSION_LOG.md`.)
- Session 077 — Architect-path framing measurement (controlled): isolates framing-attributable Architect cited-fact divergence from LLM sampling noise (Sonnet 4.6, K=8, Jaccard, positive control = drop most-cited fact). **Finding: framing-divergence REAL but small (Jaccard ~0.17–0.29) on 3/5 measurable, within-noise on 2/5 — far below the uncontrolled 60–78%.** Run 1 VOID → fixed → Run 2 PARTIAL (5/6 controls). $7.31. Squash `97bb66e`. (Full prose → `docs/SESSION_LOG.md`.)
- Session 078 — Oracle `supporting_fact_ids` sanitization (opt-in leak fix): new deterministic peer `ares/dialectic/agents/verdict_sanitizer.py` (outcome-conditioned kill-chain rule) re-derives the Verdict's cited-fact set, closing the S059/S075 Architect→Oracle framing leak. Opt-in (production consumed it at S079's cutover). Framing-invariant by construction. +11 tests. Squash `ed00cdb`. Also merged S077 (`97bb66e`). (Full prose → `docs/SESSION_LOG.md`.)
- Session 079 — Oracle `supporting_fact_ids` production cutover: wired the S078 opt-in sanitizer into production — opt-in default-off `sanitize_supporting_facts` flag on the three cycles + a sanitized-by-default `run_production_cycle` entrypoint. Measurement/Paper-3 keeps the leaky default → reproduces; decision determinism preserved by construction. +10 tests. Squash `6dae56f`. (Full prose → `docs/SESSION_LOG.md`.)
- Session 080 — Paper 3 submission de-risk + blocker fixes (B1+B2+B3): real-figure captions, build_acmart restored as the `.tex` source-of-truth (empty-diff proof), Type-1/TrueType fonts; +5 offline tests; squash `1c7fbb8`. B4 `.docx` note-field deanon cleanup squash `c5724d6`. (Full prose → `docs/SESSION_LOG.md`.)

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

### Multi-model measurement (Sessions 075-076)
- Session 075 CLI: `scripts/run_session_075.py` — `--provider`, `--model`, `--light-only`, UTF-16 `.env` loading
- Session 076 CLI: `scripts/run_session_076.py` — multi-provider narrow characterization (S060 pattern + S075 `.env`/`--provider`)
- Cross-model comparison: `scripts/cross_model_comparison.py` — auto-discovers runs, renders side-by-side markdown table
- GPT-4o full traces (S075): `data/paper_3/leakage_runs/20260527-121916-c543fa/`, report `LEAKAGE_REPORT_20260527-121916-c543fa.md`
- Gemini full traces (S075): `data/paper_3/leakage_runs/20260527-123857-c2d10f/`, report `LEAKAGE_REPORT_20260527-123857-c2d10f.md`
- GPT-4o narrow traces (S076): `data/paper_3/leakage_runs/20260528-000438-5614fa/`, report `LEAKAGE_REPORT_20260528-000438-5614fa_narrow_extended.md`
- Gemini narrow traces (S076): `data/paper_3/leakage_runs/20260528-000629-a3bf23/`, report `LEAKAGE_REPORT_20260528-000629-a3bf23_narrow_extended.md`
- Cross-model comparison: `CROSS_MODEL_COMPARISON.md` (auto-generated by `scripts/cross_model_comparison.py`)
- `RunSummary` and `NarrowExtendedSummary` gained `provider`/`model` fields; `summary.json` persisted alongside traces
- `NarrowCharacterizationConfig` gained `provider` field; both narrow runners use `make_client()` dispatch

### Architect-path measurement (Phase 7 / Session 077)
- Spec: `docs/superpowers/specs/2026-05-29-architect-path-measurement-design.md`; plan: `docs/superpowers/plans/2026-05-29-architect-path-measurement.md`
- Schema: `ares/dialectic/measurement/architect_framing_schema.py` — `ArchitectFramingConfig`, `ResampleRecord`, `OperatorFramingResult`, `ScenarioFramingResult`, `ArchitectFramingSummary`
- Metrics/stats: `ares/dialectic/measurement/architect_framing_metrics.py` — Jaccard, within/cross distances, mean-shift permutation test, bootstrap CI, `classify_operator`
- Scenario selection: `ares/dialectic/measurement/architect_framing_selection.py` — diverging scenarios from S059 LLM-path traces (17 found in Sonnet S059)
- Positive control: `ares/dialectic/measurement/architect_framing_control.py` — drop highest kill-chain-stage fact (closes the "no positive control" gap)
- Runner: `ares/dialectic/measurement/architect_framing_runner.py` — `run_preflight`, `run_measurement`; reuses `leakage_runner._run_one_cycle` (apples-to-apples with the 60–78%); injectable `cycle_fn` for offline tests
- Report: `ares/dialectic/measurement/architect_framing_report.py`; CLI: `scripts/run_session_077.py` (preflight-gated; $8 hard cost cap)
- Status: code complete + offline-tested (+29 tests → 4,142 pass / 0 fail); **live Sonnet pilot is Dan-gated** (run `--preflight-only` first)
- **S082 scale prep:** hard cap raised 8→40 for the uniform K=20/all-17 run (~$26.5); `run_session_077.py` reused. Spec/plan/run-plan dated `2026-06-04` under `docs/superpowers/{specs,plans}/`.

### Verdict sanitization (Phase 7 / Session 078)
- Opt-in Oracle passthrough fix: `ares/dialectic/agents/verdict_sanitizer.py` — `relevant_fact_ids` (outcome-conditioned packet-derived kill-chain rule), `sanitize_verdict` (frozen copy, replaces only `supporting_fact_ids`), `create_sanitized_oracle_verdict` (opt-in factory peer of `oracle.create_oracle_verdict`). Deterministic; closes the Architect→Oracle `supporting_fact_ids` framing leak on the opt-in path. `oracle.py` + passthrough anchor untouched (Paper 3 reproducible on HEAD).
- Tests: `ares/dialectic/tests/agents/test_verdict_sanitizer.py` (10 unit/integration) + `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py` (inverse of the passthrough anchor; locks the drift-free fixed behavior).
- Spec/plan: `docs/superpowers/specs/2026-05-31-oracle-passthrough-sanitization-design.md`, `docs/superpowers/plans/2026-05-31-oracle-passthrough-sanitization.md`.

### Production cutover (Phase 7 / Session 079)
- Opt-in flag: `sanitize_supporting_facts: bool = False` (keyword-only) on `run_cycle_with_strategies` (`live_cycle.py`), `run_guarded_cycle` (`guarded_cycle.py`), `run_light_guarded_cycle` (`light_guarded_cycle.py`). When set, lazy-imports and applies `verdict_sanitizer.sanitize_verdict(verdict, packet)` immediately after `OracleJudge.compute_verdict`, before the OracleNarrator. Default off → measurement/Paper-3 path (and all existing callers) byte-identical.
- Sanitized production entrypoint: `ares/dialectic/agents/strategies/production_cycle.py` — `run_production_cycle` (thin single-turn wrapper; `sanitize_supporting_facts=True` by default). The one blessed leak-closed path.
- Tests: `ares/dialectic/tests/agents/strategies/test_sanitize_supporting_facts_flag.py` (8 — off=leaky / on=sanitized / determinism per cycle + a cycle-level framing-invariance proof-of-fix) + `test_production_cycle.py` (2). Offline/deterministic.
- Spec/plan: `docs/superpowers/specs/2026-06-01-oracle-sanitizer-production-cutover-design.md`, `docs/superpowers/plans/2026-06-01-oracle-sanitizer-production-cutover.md`.

### Paper 3 submission de-risk (Phase 7 / Sessions 080–081)
- De-risk audit + CFP-verified pre-submission checklist: `docs/paper_3/acmart_spike/SUBMISSION_DERISK_2026-06-02.md` (supersedes the verification portions of `ANONYMIZATION_PLAN.md` item 4; carries the anonymous.4open.science mirror steps forward).
- Pre-flight sign-off (S081, 2026-06-03 — **GO**): `docs/paper_3/acmart_spike/PREFLIGHT_SIGNOFF_2026-06-03.md` (re-runs the §A/§D gate set at HEAD `5cd8d43`, resolves B5a + B5b with evidence, and carries the ready-to-paste anonymized-URL 4open Appendix-B wording in its §E).
- `docs/paper_3/build_acmart.py` — `render_figure_placeholder` now emits `\includegraphics[width=\textwidth|\columnwidth]{../figures/<id>.pdf}` (real S073 figures, not `\framebox`); `_FIGURE_ROSTER` captions stripped of the spike sentence. **Source of truth for the `.tex` again** — regenerate via `python -m docs.paper_3.build_acmart` (empty-diff against the committed `.tex` before the caption strip).
- `docs/paper_3/build_figures.py` — sets `matplotlib.rcParams["pdf.fonttype"]/["ps.fonttype"] = 42` (TrueType embedding, clears ACM-disliked Type 3). Plotting logic unchanged.
- Tests: `tests/paper_3/test_build_acmart_figures.py` (4 — includegraphics / width-per-span / no-placeholder / keep-descriptions) + `tests/paper_3/test_build_figures_fonttype.py` (1 — rcParam == 42). Offline/deterministic.
- Spec/plan: `docs/superpowers/specs/2026-06-02-paper3-submission-derisk-fixes-design.md`, `docs/superpowers/plans/2026-06-02-paper3-submission-derisk-fixes.md`.

### Dual-agent framing measurement (Phase 7 / Session 084)
- Spec/plan: `docs/superpowers/specs/2026-06-05-dual-agent-framing-measurement-design.md`, `docs/superpowers/plans/2026-06-05-dual-agent-framing-measurement.md`.
- Schema: `ares/dialectic/measurement/dual_agent_framing_schema.py` — `DualAgentFramingConfig`, `DualAgentResampleRecord` (both agents' cited facts), `AgentFramingResult`, `MirrorRecord`, `ScenarioDualFramingResult`, `DualAgentFramingSummary`.
- Mirror logic: `ares/dialectic/measurement/dual_agent_framing_mirror.py` — `direction`, `modal_set`, `classify_mirror` (opposed/aligned/single/mixed/none), `build_mirror_record`.
- Runner: `ares/dialectic/measurement/dual_agent_framing_runner.py` — `_resample_dual` (records both agents), `run_preflight`, `run_measurement`; reuses `architect_framing_{metrics,control,selection}` + `leakage_runner._run_one_cycle`; single joint control; per-agent control validity.
- Report + CLI: `ares/dialectic/measurement/dual_agent_framing_report.py`, `scripts/run_session_084.py` (preflight-gated; $40 hard cap). Tests: `tests/dialectic/measurement/test_dual_agent_framing_{schema,mirror,runner,report,cli}.py` (+18). Live result: run `20260605-194137-713674` ($24.41); writeup `docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md`.

### ARES-VISION "The Mirror" journey (Phase 7 / Session 085)
- Spec/plan: `docs/superpowers/specs/2026-06-06-ares-vision-mirror-journey-design.md`, `docs/superpowers/plans/2026-06-06-ares-vision-mirror-journey.md`.
- Data adapter (ARES): `ares/dialectic/visualization/mirror_journey_schema.py` (`AgentFraming`/`Hero`/`Landscape`/`MirrorJourney` + `mirror_journey_to_json`), `mirror_journey_builder.py` (`build_mirror_journey`, `jaccard_distance`; parses S084 traces by `condition`; INJ-020 modal sets; LANDSCAPE + within/p as sourced constants), `build_mirror_journey.py` (CLI). Artifact `docs/marketing/mirror-journey.json`; tests `ares/dialectic/tests/visualization/test_mirror_journey_{schema,builder,json_contract}.py` (+13).
- Renderer (skyframe-main, staged not deployed): `assets/ares/mirror.{html,css,js}` + `mirror-journey.json`; "See it move →" link in `ares.html` hero-CTAs; CTA "Explore the live data" → `prism.html`. Vanilla IntersectionObserver, no Three.js. Auto-memory `project-s085-ares-vision-mirror`.

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
`main` — sessions 045–084 all squash-merged and pushed to `origin/main`. Session 084 (`session/084-dual-agent-framing`, dual-agent framing measurement — both-agent harness + live result, run `20260605-194137-713674`) squash-merged to `main` 2026-06-05 (commit `75bb815`); `origin/session/084-dual-agent-framing` retained as the un-squashed audit trail. Session 083 (`session/083-inj020-steerability`, INJ-020 steerability deep-dive — analysis-only; no code/test changes) squash-merged to `main` 2026-06-05 (commit `ff6e7f1`); `origin/session/083-inj020-steerability` retained as the un-squashed audit trail. S083 follow-up `session/083-oracle-followup` (Oracle-divergence resolution — `compute_verdict` outcome-conditioned support rule) squash-merged to `main` 2026-06-05 (commit `8c743e3`); `origin/session/083-oracle-followup` retained as the un-squashed audit trail. S083 follow-up `session/083-skeptic-recon` (dual-agent drift recon — Skeptic mirrors the Architect, banked as future-work) squash-merged to `main` 2026-06-05 (commit `28e3b1e`); `origin/session/083-skeptic-recon` retained as the un-squashed audit trail. Session 082 (`session/082-s077-scale-prep`, S077 scale prep — raised the framing hard cap for the K=20/all-17 run) squash-merged to `main` 2026-06-04 (commit `6c9d648`); `origin/session/082-s077-scale-prep` retained as the un-squashed audit trail. Session 082's gated live run squash-merged to `main` 2026-06-04 (commit `034248c`, S077 scale result K=20/17); `origin/session/082-s077-scale-run` retained as the un-squashed audit trail. Session 081 (`session/081-paper3-preflight`, Paper 3 pre-flight sign-off — GO) squash-merged to `main` 2026-06-03 (commit `fa620cd`); `origin/session/081-paper3-preflight` retained as the un-squashed audit trail. Post-S080 follow-up `fix/paper3-b4-bib-note` (B4 bibliography deanon cleanup) squash-merged to `main` 2026-06-02 (commit `c5724d6`). Session 080 (`session/080-paper3-submission-derisk`) squash-merged to `main` 2026-06-02 (commit `1c7fbb8`); `origin/session/080-paper3-submission-derisk` retained as the un-squashed audit trail.
Sessions 045–082 per-session squash records: git history + `docs/SESSION_LOG.md`. Historical session branches retained locally (no upstream); safe to delete.