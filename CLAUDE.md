# CLAUDE.md — ARES Phase 7 (post-Session 065)

**Last updated:** 2026-05-21
**Test count floor (passing):** 3,937

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
- Session 056: pre-publish hardening — firewall fail-closed contract enforced at producer (FirewallVerdict invariant) and at all three cycle consumers (`run_guarded_cycle`, `run_ablated_cycle`, `run_light_guarded_cycle`)
- Session 057 / Step 1: Phase 7 opens — skeleton-equivalence audit on `injection_registry_v3` (33 scenarios). 0 natural skeleton-equivalent groups. Decision: **mutator path forced**. Pre-registered in `docs/paper_3/skeleton_audit_v1.json`.
- Session 058: paired-scenario mutator (v1) + orthogonality audit + verbatim anchor test for `light_skeptic.py:185`. Mutator path operational. Orthogonality decision: **FAIL** — synonym conservative/aggressive collide on 14/33; severity intensifier/decreaser applicability-gap fail (31/33 and 20/33). Framing operators clean. v1 is reproducibility-locked; revision goes to v2 in a future session. Anchor test in place.
- Session 058.5: pre-registered v2 operator redesign. Disjoint conservative/aggressive lexicons; severity tables expanded with normalization-axis entries. Framing operators imported from v1 by-identity. v2 audit decision: **FAIL** but a different FAIL from v1 — collision pair count dropped 14 → 0 (lexicon disjointness fix worked perfectly); intensifier gap dropped 31 → 13 (normalization-axis bite succeeded but still 3 over the ≤10 threshold). Decreaser regressed (20 → 24) and aggressive synonym regressed (8 → 12) — both diagnosable corpus-shape findings, see Session 058.5 entry below. Per the brief, no third iteration this session.
- Session 059: first live InfluenceLeakage measurement. Dual-reading verdict: **narrow (Light Skeptic only): ALIVE**, **broad (Light + Oracle + Final): DEAD**. Light Skeptic itself never leaked across 2 sampled light pairs; the broad-reading kill fired at Oracle's `supporting_fact_ids` (Architect citation passthrough — a sibling architectural finding not anticipated by the brief). Run 2 cost: $1.95 / 134 cycles / wall ~30min. Both readings disclosed transparently per discipline (no retcon).
- Session 060: narrow-reading characterization extends Paper 3's narrow N from 2 to 98 on the deterministic / light path. **100.00% narrow stability rate** (98/98 pairs, zero narrow fires across all three v2 operators). Total empirical N across runs: 101 light pairs, zero narrow fires. Cost $1.19, wall ~16 min. Characterization mode (no halt on narrow fire); halt scope explicitly authorized in the brief for this run only.
- Session 061: 3D Pinscreen replay viewer for Phase 7 — Python pipeline (DataLoader / PinMapper / TimelineBuilder + CLI) emits `docs/marketing/pinscreen-timeline.json` from Session 059 traces (98 pins; 97 held / 1 drifted at INJ-001 framing_suffix_v1 Oracle layer, matching the documented citation-passthrough finding). Standalone Three.js page at `skyframe-main/assets/ares/pinscreen.html` consumes the JSON; deployed live via Netlify. Both pipeline and renderer shipped this session.
- Session 062: Prism Labyrinth (Panel 1) renderer — production page at `skyframe-main/assets/ares/prism.html`, faithful port of the 2026-05-13 mockup against Session 059 data (98 cycles, 97 held / 1 drifted). Autoplay-first replay with scrubber takeover; full-kit interactivity (scrubber + operator dial + play/pause + click-to-focus). Drift surfaces at the **Architect** chamber per data (`first_diverging_layer="Architect"` for INJ-001 framing_suffix_v1); the mockup hardcoded Oracle as a storytelling shortcut, but the renderer is data-driven per spec § 4. ARES side adds one JSON contract test (8 tests). The 2026-05-14 sphere-chain attempt remains parked as a dated learning artifact.
- Session 063: Prism Panel 2 (Confidence Trajectories) renderer — second view in the existing `prism.html` under a tab strip with Panel 1. Each cycle becomes one primitive in (architect, skeptic, oracle) confidence space: arrow when confidence moved (~75/98 pairs), sphere when it held (~23/98). The single broad-leakage cycle sits at the held cluster as a glowing red sphere because Session 059's leakage was citation-surface drift, not confidence drift. Shared timeline via `window.PrismState` event bus; per-frame publish drives Panel 2's reveal in lockstep with Panel 1's autoplay. 4 new ARES JSON contract tests (floor 3,733 → 3,737); 3 new JS files + 2 modifications on skyframe-main. Panel 1 behavior unchanged.
- Session 064: Paper 3 v1.0 skeleton + build pipeline scaffolded (no prose yet). Working title locked: "Decision Determinism, Explanation Drift". Framing A from web Claude's brief; Skeptic-first section order; AISec at CCS venue; 11 numbered sections + Abstract; 8,650 target words core. Three-leg story: (1) narrow Light Skeptic byte-stability 98/98 [Session 060]; (2) Oracle `supporting_fact_ids` passthrough under THREAT_CONFIRMED [structural finding from Session 059]; (3) LLM-path bound — exact integer locked from `LEAKAGE_REPORT_20260510-193950-f401a8.md §3` at **73 of 98 (74.49%)** divergence somewhere, with architect 39 / skeptic_llm 34 / no_divergence 25. Two new anchor tests landed (Oracle passthrough at `oracle.py` lines 89+102+116; paired-trial byte-stability against canonical Session 060 traces with SHA256 lock); existing `test_light_skeptic_anchor.py` confirmed at `light_skeptic.py:185`. Build pipeline mirrors Paper 2: `references.bib` (2 verified entries), ported `extract_citations` + `citation_to_bibkey` helpers, `test_citation_existence.py` (16 always-on + 4 properly-skipped) with Sabet-discipline guards that block unverified bibkeys from leaking into the bib, `number_check.py` with 11 resolvers covering all pre-registered numbers + dormant prose-substring mode for Session 065+ activation. Brief's thematic bibkey naming (`gmys-casiano-2026-deterministic-skeptic`, `eth-can-ai-agents-agree`) deviated to canonical Author-Year (`gmys-casiano-2026`, `berdoz-rugli-wattenhofer-2026`) because the ported helpers produce canonical keys from natural prose cite forms — flagged for web Claude review. Floor raised 3,737 → 3,929 (+192 tests across 5 new test files; 5 new docs/paper_3 files). Zero regressions. Out of scope: prose writing, docx build, verifying the 5 Needed bibkeys (Session 065 work).
- Session 065: Paper 3 v1.0 first prose commit (§5 + §6 of 11 sections). Two-phase landing. **Phase A** (`36067bf`): five skeleton patches per web Claude's brief — added §6.6 "Conditional, not universal" subsection (250w); bumped §6 target_words 1500 → 1750 (paper total 8,650 → 8,900; corrected brief math error of "8,500 → 8,750"); added Table 3 (`tbl_3_verdict_class_passthrough_map`) with CC-verified branch line numbers (THREAT_CONFIRMED at `oracle.py:102`, THREAT_DISMISSED at line 105, INCONCLUSIVE at line 109); narrowed Fig 6 caption to `oracle.py:101-111` (the THREAT_CONFIRMED branch only; anchor test + numbers_preregistered keep the full 88-115 decide() scope); added `verdict_class_passthrough_map` to numbers_preregistered with the verdict-class→fact-source map locked. New resolver in `number_check.py` reads `oracle.py` and asserts the three explicit-assignment substrings exist, locking §6.6 against silent regression. All three oracle.py branches assign `supporting_facts` explicitly (no fall-through) — clean positive evidence for §6.6's conditional-not-universal claim. **Phase B (part 1)** (`70a433a`): first prose commit at `docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md` — drafted §5 Light Skeptic byte-stability (993 words; 5.1 result + 5.2 anchor at line 185 + 5.3 mechanism + 5.4 anchor test with side-channel on empty `skeptic_cited_facts`) and §6 Oracle passthrough (1,648 words across 6 subsections including the new §6.6). 2,641 prose words total. All locked substrings present (98, 98/98, 101/0, 185, 102, 105, 109, 88-115, 101-111, THREAT_*, supporting_fact_ids, `frozenset(arch_facts)`, INJ-001, framing_suffix_v1). Both verified bibkeys cited via natural prose: `(Gmys-Casiano, 2026)` for Paper 2 forward-ref + `(Berdoz, Rugli, and Wattenhofer, 2026)` for ETH corroboration. Session stopped at §6-close natural break per brief stop conditions. Floor raised 3,929 → 3,937 (+8 tests from Phase A; Phase B prose adds no test code). Zero regressions. Pushed to origin/main. Remaining for Session 066+: §7 (800w) → §4 (1200w) → §8+§9+§10 (1200+500+400w) → §3+§2 (500+700w) → §1 (600w) → Abstract (250w); ~6,150 words across the remaining 9 sections.

## Canonical Artifacts
- **Paper 1:** `docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf`
- **Paper 1 reconciliation notes:** `docs/paper_1/CANONICAL.md`
- **Paper 2 v1.1 draft:** `docs/paper_2/PAPER2_DRAFT_v1_1.docx`
- **Paper 2 source markdown:** `docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md`
- **Paper 2 references:** `docs/paper_2/references.bib`
- **Paper 3 v1.0 skeleton (structural scaffold):** `docs/paper_3/skeleton_v1_0.json`
- **Paper 3 v1.0 source markdown (in-progress prose):** `docs/paper_3/source/PAPER3_DRAFT_v1_0_source.md`
- **Paper 3 references:** `docs/paper_3/references.bib`
- **Phase 6 plan:** `docs/PHASE6_INJECTION_ARENA.md`

## Session 058 — Paired-scenario mutator + orthogonality audit + anchor test
- Origin: Session 057 audit forced the mutator path (0 natural skeleton-equivalent groups in registry_v3). Session 058 builds the synthetic-mutation primitive that makes paired-prose measurement possible, plus the orthogonality audit that catches operator-collapse failure modes.
- `paired_scenario_mutator.py` registers six v1 operators across three families (synonym / severity / framing). `MutatedScenarioPair.__post_init__` enforces skeleton invariance as a typed property: skeleton-hash equality, byte-identical (fact_id, field, entity_id, source_type, timestamp) tuples per Fact, ≥1 differing value_hash, and a hard `SkeletonInvariantError` on any violation. No-op pairs are rejected at the type boundary, not silently absorbed.
- `operator_orthogonality.py` runs the audit on registry_v3 and emits `docs/paper_3/operator_orthogonality_v1.json`. Decision is immutable per `OrthogonalityReport.__post_init__` (failed_pairs and failed_operators_by_gap must agree with thresholds and the matrix; decision must agree with both).
- Live audit result: **FAIL**. Synonym conservative ↔ aggressive collide on 14/33 (threshold ≤2). Severity intensifier no-op on 31/33; decreaser on 20/33 (threshold ≤10). Framing prefix/suffix universal (gap=0). Mechanism: synonym operators share lexicon/selection order and only differ on count budget — they collapse on facts with ≤3 lexicon hits. Severity tables target hedge language; the corpus prose uses softening framing instead. Per the v1 reproducibility lock, operators were NOT revised to chase a PASS — the FAIL is the data, and v2 redesign will land in a future session.
- Verbatim anchor test (`tests/agents/test_light_skeptic_anchor.py`): asserts the `_ = architect_output` line is present, on its expected line number (185), and is an executable statement, not a comment. Three tests, all passing. Anchor protects the Paper 3 kill-criterion against silent refactors.
- Brief stated `light_skeptic.py:184`; verified actual statement is line 185 (line 184 is its explanatory comment). EXPECTED_LINE_NUMBER set to 185 in the test as the deliberate ADR moment.
- 76 new tests across 3 files. Floor raised 3,464 → 3,540; actual collected count 3,464 → 3,540. Zero regressions. New files only — zero edits to existing `ares/` code outside this CLAUDE.md.

## Session 058.5 — Mutator v2 (pre-registered design correction)
- Origin: Session 058 audit FAIL on two specific design failure modes (synonym shared-lexicon coupling; severity register mismatch). 058.5 builds operator set v2 with two pre-registered design corrections; v1 module untouched on the reproducibility-locked record.
- `paired_scenario_mutator_v2.py` is a new module that imports `MutationOperator`, `PairedScenarioMutator`, `SkeletonInvariantError`, plus the framing operators `framing_prefix_v1` and `framing_suffix_v1` directly by-identity from v1. Four new operators land in v2: `synonym_substitution_conservative_v2` (general-English lexicon, e.g., system → platform, account → profile), `synonym_substitution_aggressive_v2` (cybersec-domain lexicon, e.g., compromise → breach, exfiltrate → extract), `severity_intensifier_v2` and `severity_decreaser_v2` (hedge axis preserved from v1 + normalization-axis entries that target attack-disguising language: standard → anomalous, approved → questionable, scheduled → unscheduled).
- Lexicon disjointness is enforced as a typed property: `set(CONSERVATIVE_LEXICON_V2.keys()).isdisjoint(set(AGGRESSIVE_LEXICON_V2.keys()))` and the equivalent value-set check are unit tests, not contracts. They passed on first run.
- `operator_orthogonality.py` gained a `--operator-set v1|v2` flag (the only edit to existing `ares/` code allowed by the brief). Default is `v1` and produces bit-identical output to the Session 058 audit JSON — verified via `git diff` on the regenerated v1 file showing zero divergence.
- Live v2 audit on registry_v3: **FAIL but a different FAIL from v1.**
  - Collision pair count: v1=14 → v2=**0**. Lexicon disjointness fix worked perfectly. THE pre-registered correction for the synonym failure mode succeeded.
  - Severity intensifier gap: v1=31 → v2=**13**. Normalization-axis bite succeeded; intensifier now applies to the framing-class scenarios it was a no-op on in v1. Still 3 over the ≤10 threshold but 18 closer.
  - Severity decreaser gap: v1=20 → v2=**24** (regressed). Diagnosis: the corpus contains *baseline*-normalized framing language (standard, approved, scheduled). v2 intensifier flips those to inverted forms; v2 decreaser is built to flip *inverted* forms back, but those rarely appear in baseline corpus state. Intensifier and decreaser are asymmetric against this corpus shape.
  - Aggressive synonym gap: v1=8 → v2=**12** (regressed). Diagnosis: corpus prose uses technical shibboleths (procdump, lsass, beacon) rather than generic cybersec vocabulary (compromise, exfiltrate, lateral). The brief's pre-registered example pairs miss the corpus's actual register.
  - Conservative synonym gap: v1=8 → v2=**1** (improved). Framing operators unchanged at 0/0.
- 36 new tests in `test_paired_scenario_mutator_v2.py`. Floor raised 3,540 → 3,576; actual collected count 3,540 → 3,576. Zero regressions. New file (mutator v2) plus single-flag edit to orthogonality CLI (default preserves v1 output bit-identically; no v1 module changes).

## Session 059 — InfluenceLeakage first measurement (dual-reading verdict)
- New package `ares/dialectic/measurement/` with `InfluenceLeakage` schema (4-bit frozen dataclass, locked weights 0.40/0.20/0.20/0.20, confidence-drift threshold |Δ|>0.10), `leakage_runner.py` (pair iteration, cost tracking via shared `LLMCallLogger`, halt logic, dual-criterion kill predicates), `leakage_report.py` (markdown renderer with discipline-enforced forbidden-phrase guard), `scripts/run_session_059.py` (CLI: `--dry-run`, `--preflight-only`, `--confirm-live`, `--cost-ceiling` refuses to raise above $20).
- Locked operator subset for measurement (Option A from 058.5 strategic call): `framing_prefix_v1`, `framing_suffix_v1`, `synonym_substitution_conservative_v2` — the three v2 operators with applicability gap ≤1 and zero pairwise collisions.
- Drafting-error resolution mid-session: the brief had internal tension between "Light Skeptic's InfluenceLeakage 4-bit vector" (narrow framing) and "deterministic path (OracleJudge + Light Skeptic)" (broad framing in the CC prompt). Initial implementation aggregated kill_fires across ALL layers including Architect, which fired on cycle 6 of run 1. Resolved per web Claude's framing: **no retcon** of either reading; both are computed per pair and reported transparently. `PairLeakageRecord.kill_fires_narrow` (Light Skeptic only) and `kill_fires_brief_broad` (Light + Oracle + Final Verdict; excludes Architect) are the two pre-registered readings.
- Halt-scope fix: deterministic-path kill flips a `deterministic_active` flag and breaks the operator loop only. The LLM path keeps running under its own cost share. `halt_reason` stays `HALT_COMPLETED` unless cost or anchor halts.
- Live measurement on `injection_registry_v3` (run 2, run_id `20260510-193950-f401a8`, 134 cycles, $1.9512, wall ~30min, anchor green throughout):
  - **Narrow verdict: FALSE** (Light Skeptic byte-stable across 2 sampled light pairs). `Paper 3 claim status (narrow / Light Skeptic only): ALIVE`.
  - **Broad verdict: TRUE** (1/2 light pairs leaked at Oracle layer via `supporting_fact_ids` Architect passthrough). `Paper 3 claim status (brief_broad / Light + Oracle + Final): DEAD`.
  - LLM path: 98 of 99 pairs completed (one operator no-op on one scenario). Architect first-diverging on 39 pairs (40%), Skeptic LLM on 34 (35%), no divergence on 25 (26%). Verdict label drift 16–27% per operator.
- Architectural finding (not anticipated by the brief): Oracle's `Verdict.supporting_fact_ids` is a passthrough of `architect_message.get_all_fact_ids()` (`oracle.py:88-98`). When the Architect cites a different fact set under attacker prose mutation, the Oracle's *decision* (outcome + confidence) is preserved deterministically, but the Oracle's *explanation surface* inherits the Architect's drift. This is a sibling-isolation problem worth a Paper 3 methodology section.
- Run 1 (run_id `20260510-184611-8e6e6d`, 6 cycles, $0.0863, halted on initial implementation's any-layer kill firing on Architect drift) is preserved verbatim on disk as the audit trail; the dual readings recompute correctly on those traces.
- 61 new tests across 2 files: `test_influence_leakage.py` (41 — locked-constants assertions, frozen invariants, 4-bit semantics, weighted scalar boundary tests, helper extractors) and `test_leakage_runner.py` (24 — per-pair leakage, dual kill readings, cost circuit-breaker, scoped halt, anchor-test guard, JSONL round-trip, SHA256). Floor raised 3,576 → 3,637; actual collected count 3,637. Zero regressions. New files only — zero edits to existing `ares/` code outside the measurement package.

## Session 060 — Narrow-reading characterization extension
- Origin: Session 059 narrow verdict (`Paper 3 narrow claim: ALIVE`) rested on only N=2 light pairs because the dual-criterion halt logic stopped further light cycles after the brief-broad kill fired. Strategically the headline claim deserved a stronger empirical bound. Session 060 brief explicitly authorized characterization mode: no halt on narrow fire, light path only, cost ceiling $5 (vs. $20 in 059).
- New module `ares/dialectic/measurement/narrow_characterization_runner.py` reuses Session 059 primitives (`_run_one_cycle`, `_compute_pair_leakage`, `anchor_test_passes`, `CycleTrace`, `PairLeakageRecord`) without modifying them. `NarrowCharacterizationConfig` locks the $5 ceiling and light-only pipeline. `NarrowDriftRecord` captures per-pair drift detail for any narrow fires.
- New module `ares/dialectic/measurement/narrow_extended_report.py` renders the six-section rate-based markdown report (metadata / narrow stability rate / per-operator breakdown / per-pair drift table / Session 059 cross-reference / Paper 3 narrow-claim status line). Forbidden-phrase guard preserved.
- CLI: `scripts/run_session_060.py` with `--dry-run`, `--preflight-only`, `--confirm-live`, `--cost-ceiling` capped at $5.
- Live run on `injection_registry_v3` (run_id `20260510-224622-154556`, 131 cycles, $1.1862, wall ~16 min, anchor green throughout, `halt_reason: completed`):
  - **Narrow stability rate: 98 / 98 = 100.00%**
  - Per-operator: `framing_prefix_v1` 33/33, `framing_suffix_v1` 33/33, `synonym_substitution_conservative_v2` 32/32 (1 no-op consistent with Session 058.5 audit).
  - Zero narrow fires across the full corpus. The Light Skeptic is empirically byte-stable under all three pre-registered v2 operators.
- Total empirical N for Paper 3's narrow claim across the chain: Session 059 run 1 (N=1) + Session 059 run 2 (N=2) + Session 060 (N=98) = **101 light pairs, zero narrow fires**. Paper 3 narrow-claim status: `HOLDS at 98/98 pairs (100.00%)`.
- The broad-reading verdict from Session 059 (`Paper 3 claim status (brief_broad / Light + Oracle + Final): DEAD`) is unchanged by Session 060. The Oracle citation-surface passthrough remains the documented sibling architectural finding for Paper 3's methodology section.
- 10 new tests in `test_narrow_characterization_runner.py` (pre-registered config locks, no-halt-on-narrow-fire across 33×3, light-path-only invariant, cost circuit-breaker, anchor guard, per-operator stats, JSONL persistence). Floor raised 3,637 → 3,647. Zero regressions. New files only — zero edits to existing `ares/` code outside the new modules.

## Session 057 / Step 1 — Skeleton-equivalence audit (Phase 7 opens)
- Origin: 2026-05-05 direction lock. Phase 7 / Paper 3 candidate is "Evidence Authority Isolation" — measure whether attacker-controlled prose can change verdicts/confidence/cited-facts when the structured evidence skeleton is held constant. Honeyfile lane occupied by Mantis (arXiv 2410.20911) and CHeaT (USENIX 2025); structural-defense lane occupied by ASPO and OpenClaw. Uncharted lane is influence-leakage measurement.
- Step 1 brief: SESSION_057_CC_PROMPT.md called for replay-mode harness against `results/session_048/` and `results/session_050/`. Verified at the start of the session that those artifacts contain only summarized per-scenario verdict rows — no per-layer Architect/Skeptic/Light/Oracle traces. Replay harness is therefore not viable from existing data; scope was narrowed to the audit step alone, with the build/measurement decision deferred to Session 058.
- Audit result on `injection_registry_v3` (33 scenarios): **0 natural skeleton-equivalent groups.** Every scenario has a unique `(fact_id, field, entity_id, source_type)` tuple set. Pre-registered decision rule `n_groups_size_ge_2 ≥ 5 → harness_path` evaluates to **`mutator_path`**.
- Implication for Session 058: `paired_scenario_mutator.py` is on the critical path. Skeleton-preserving mutation (synonym substitution / framing prefix-suffix) is the only way to produce skeleton-equivalent variants from this corpus. Decision is recorded in the audit JSON and is immutable per `SkeletonAuditReport.__post_init__`.
- 52 new tests across 2 files: `TestSkeletonHashValueBlind` / `TestSkeletonHashTimestampBlind` / `TestSkeletonHashTypeSensitive` / `TestSkeletonHashStructure` / `TestSkeletonHashCardinality` / `TestSkeletonTimestamps` / `TestGroup*` / `TestMakeGroupId` / `TestAllUnique` (28) in `test_skeleton_equivalence.py`; `TestAuditOnSynthetic` / `TestDecisionRule` / `TestReportInvariants` / `TestWriteReport` / `TestLiveRegistryAudit` / `TestCli` / `TestModuleSurface` (24) in `test_skeleton_audit.py`.
- New files only — zero edits to existing `ares/` code. Floor raised 3,404 → 3,464; actual collected count 3,412 → 3,464. Zero regressions.

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

### Visualization (Phase 7 / Session 061)
- 3D pinscreen pipeline: `ares/dialectic/visualization/` — `DataLoader`, `PinMapper`, `TimelineBuilder`
- CLI: `python -m ares.dialectic.visualization.build_timeline --traces <path> --output <path>`
- Generated artifact: `docs/marketing/pinscreen-timeline.json` (98 pins from Session 059)
- Design spec: `docs/superpowers/specs/2026-05-13-replay-viewer-pinscreen-3d-design.md`
- Implementation plan: `docs/superpowers/plans/2026-05-13-replay-viewer-pinscreen-3d.md`

### Visualization (Phase 7 / Session 062)
- v2 cycle-trace pipeline: `ares/dialectic/visualization/cycle_trace.py` (CycleSnapshot, PairTrace, CycleTimelineV2) + `cycle_trace_builder.py` (loader/assembler) + `build_cycle_timeline.py` (CLI)
- CLI: `python -m ares.dialectic.visualization.build_cycle_timeline --traces <path> --output <path>`
- Generated artifact: `docs/marketing/prism-timeline.json` (98 pairs from Session 059)
- JSON contract test: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (8 tests locking the renderer/pipeline interface)
- Renderer (skyframe-main): `assets/ares/prism.html` (chrome) + `assets/ares/prism.js` (scene + behavior) + `assets/ares/prism-timeline.json` (data copy)
- ares.html CTA wiring: `ares.html` at skyframe-main repo root (Prism link next to Pinscreen)
- Design spec: `docs/superpowers/specs/2026-05-19-prism-labyrinth-renderer-v2-design.md`
- Implementation plan: `docs/superpowers/plans/2026-05-19-prism-labyrinth-renderer-v2.md`
- Build-prep spec (earlier 2026-05-13): `docs/superpowers/specs/2026-05-13-prism-build-prep.md`
- Parked sphere-chain attempt (do not regress to): `docs/marketing/prism-2026-05-14-sphere-chain.html`

### Visualization (Phase 7 / Session 063)
- Panel 2 (Confidence Trajectories) renderer: tab-strip layout in existing `prism.html`. Three new sibling JS files on skyframe-main:
  - `assets/ares/prism-state.js` — event bus (`window.PrismState`: getState / publish / subscribe)
  - `assets/ares/prism-tabs.js` — tab UI, start/stop wiring (Panel 1 stays running when on Trajectories — see Architecture note below)
  - `assets/ares/prism-panel2.js` — Panel 2 scene + 98 primitives (75 arrows + 23 spheres in current data) + per-frame reveal + lazy scene init + start/stop
- `assets/ares/prism.js` surgical edits: 7 publish inserts (including per-frame diff-checked publish in `tickReplay` for cross-panel timeline sync), `window.__PRISM_TIMELINE_CACHE` exposed, `window.PrismPanel1 = {start, stop, isRunning}` with stoppable rAF
- JSON contract test additions: `ares/dialectic/tests/visualization/test_prism_timeline_json_contract.py` (4 new tests + 3 new constants + `REQUIRED_PAIR_KEYS` strengthened, floor 3,733 → 3,737)
- Design spec: `docs/superpowers/specs/2026-05-20-prism-panel2-confidence-trajectories-design.md`
- Implementation plan: `docs/superpowers/plans/2026-05-20-prism-panel2-confidence-trajectories.md`
- Architecture note: Panel 1's `tickReplay()` is the shared timeline driver. `prism-tabs.js` keeps Panel 1's rAF running when on Trajectories so the playhead advances and Panel 2's reveal stays in lockstep. Panel 1's hidden canvas costs ~1ms/frame of GPU; a cleaner design would lift `tickReplay` into a shared timeline module.

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

### Paper 3 tooling (Phase 7 / Session 064)
- Paper 3 structural scaffold: `docs/paper_3/skeleton_v1_0.json` (12 entries: Abstract + §1-§11; 8,650 target words core; three-leg story; pre-registered numbers; verified vs unverified bibkeys; anchor-test index)
- Paper 3 references: `docs/paper_3/references.bib` (2 verified entries: `gmys-casiano-2026` Paper 2 self-cite; `berdoz-rugli-wattenhofer-2026` ETH "Can AI Agents Agree?"; per Sabet-discipline, unverified entries stay out)
- Paper 3 build helpers: `docs/paper_3/build_references.py` (ported BibEntry/parse_bib + regression-locked `extract_citations`/`citation_to_bibkey` from Paper 2 Session 055 fix; docx integration deferred to Session 065)
- Paper 3 number-check: `docs/paper_3/number_check.py` (11 resolvers covering pre-registered numbers from skeleton + LEAKAGE_REPORT + traces.jsonl + source files; dormant prose-substring mode seeded for Session 065+)
- Paper 3 skeleton audit: `tests/paper_3/test_skeleton_audit.py` (49 structural tests locking the JSON schema)
- Paper 3 citation existence audit: `tests/paper_3/test_citation_existence.py` (16 always-on: 5 enumeration + 7 structural + 4 Sabet-discipline guards; 4 conditional: 1 docx-pending + 3 ARES_RUN_NETWORK_TESTS-gated)
- Paper 3 number-check tests: `tests/paper_3/test_number_check.py` (24 tests: smoke + per-resolver + claim engine + prose substring + report rendering)
- Paper 3 Oracle passthrough anchor: `ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py` (11 tests: source-level anchors at `oracle.py` lines 89+102+116 + behavioral anchors for THREAT_CONFIRMED passthrough + behavioral guards on THREAT_DISMISSED/INCONCLUSIVE non-passthrough branches)
- Paper 3 paired-trial byte-stability anchor: `tests/dialectic/measurement/test_paired_trial_byte_stability.py` (16 tests: SHA256 lock on canonical Session 060 traces + 33+33+32=98 pair count + 98/98 narrow byte-stability assertion + per-operator decomposition)

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
`main` — sessions 045–065 all squash-merged and pushed to `origin/main`.
Historical session branches retained locally (no upstream); safe to delete.