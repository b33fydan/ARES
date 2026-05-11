# CLAUDE.md — ARES Phase 7 (post-Session 060)

**Last updated:** 2026-05-10
**Test count floor (passing):** 3,647

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

## Session 056 — Pre-publish hardening (firewall fail-closed)
- Origin: external review (Cursor + Codex) flagged the silent fallthrough in `guarded_cycle.py:278-285` as a structural fail-open. Path was unreachable in current code due to an implicit cross-file invariant, but had no tests, no assertion, and no docstring contract.
- Producer-side fix: `FirewallVerdict.__post_init__` enforces the invariant `passed=False ⇒ sanitized_output is not None`. Constructing the bad shape now raises `ValueError`. Bad shape is impossible to instantiate via the dataclass.
- Consumer-side fix: all three cycle runners (`run_guarded_cycle`, `run_ablated_cycle`, `run_light_guarded_cycle`) now raise `CycleError` locally if they ever receive a fail verdict without a sanitized fallback. Defense in depth per Codex's "belt-and-suspenders" pushback — keeps the security property auditable per file rather than chasing the invariant across modules.
- 8 new tests across 4 files: `TestFirewallVerdictInvariant` (4) in `test_firewall.py`, `TestFirewallFailClosed` (2) in `test_guarded_cycle.py`, `TestFirewallFailClosed` (1 each) in `test_ablated_cycle.py` and `test_light_guarded_cycle.py`. The cycle tests use `MagicMock(spec=FirewallVerdict)` to bypass `__post_init__` and prove the consumer-side raise still fires if a future producer regression ever emits the bad shape.
- No behavior change for any reachable input. Floor 3,404 unchanged; actual collected count 3,404 → 3,412. Zero regressions.

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
