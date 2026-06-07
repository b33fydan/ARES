# Design — Read-Depth Robustness Frontier, Phase B (Adaptive Corpus C + offline perturbation harness)

**Date:** 2026-06-07
**Status:** Design approved (brainstorm complete) — pending spec review, then writing-plans
**Parent design:** [`2026-06-07-read-depth-robustness-frontier-design.md`](2026-06-07-read-depth-robustness-frontier-design.md) (the whole-study design; this spec details its **Phase B**, §6 + §8 + §14).
**Phase 7 mapping:** V4 Tribunal Step 3 (Adaptive Corpus C) + the measurement instrument for Step 4 (Light Skeptic v2).
**Predecessor:** Phase A SHIPPED on `main` (squash `59f59e5`) — the 4 deterministic tiers + ladder registry + 26 tests. The `malign_score` channel is alive.

---

## 1. What Phase B is (and is not)

Phase B builds the **measurement instrument** for the read-depth robustness frontier: a purpose-built corpus and an entirely **offline / deterministic / free** harness that emits, for each of the 4 deterministic rungs, an `(X, Y)` coordinate — `X` = framing-susceptibility, `Y` = detection power (`TPR − FPR`).

Phase B does **not** produce a frontier *verdict*. The trilemma is adjudicated in Phase C, which adds the pre-registration commit, the metered LLM anchor (tier 4), and the frontier report. Phase B's frozen corpus + operator set **are the fixtures** the Phase-C pre-registration locks onto — designing them honestly now is what lets the pre-registration be honest later.

---

## 2. The ladder as built — standalone tiers, not a cumulative ladder

The parent design (§3) describes detection as "non-decreasing up the ladder (tiers 1→2 *add* rules) → Y monotone by construction." **Phase A did not build it that way.** Each tier's `MALIGN_RULES` is disjoint:

- Tier 1 (`light_skeptic_v2_structured`): `high_threat_field` (M1, field ∈ `_HIGH_THREAT_FIELDS`) + `high_stage_no_auth` (M2, max kill-chain stage ≥ 2 ∧ no auth fact). Reads **field names + derived stage** — never values.
- Tier 2 (`light_skeptic_v2_lexical`): `exe_in_user_path` (L1) + `cred_access_tooling` (L2) + `ineffective_patch` (L3). Reads **string values** via regex. **Does not include M1/M2.**
- Tier 3 (`light_skeptic_v2_canonical`): the L1–L3 rules with canonicalize-then-match (`binary→exe`, `temporary→temp`, separator/case/whitespace folding).

So as built, tier 2 can **miss** what tier 1 catches (a structural-only scenario), and tier 2 **sheds** tier 1's false positives. This is the central methodological fact of Phase B.

### 2.1 Decision: report **both** views; cumulative is the headline

The structural rule `high_stage_no_auth` is **trigger-happy** — `_max_kill_chain_stage` returns `_DEFAULT_STAGE = 2` for any field not in `_STAGE_MAP`, and real telemetry field names (`process_name`, `command_line`, `lsass_access_granted`) are all unmapped. So tier 1 fires "malign" on essentially any high-stage scenario lacking an auth fact — **including value-benign ones it cannot read**. Consequences:

- **Standalone** tiers (each tier's `evaluate` exactly as built): on a value-benign-but-structurally-suspicious scenario, tier 1 false-positives while tier 2 correctly passes. `Y` can *rise* 1→2 because tier 2 escapes tier 1's FPR.
- **Cumulative** tiers (`tier 2 = M1∪M2∪L1..3`, modelling a deployed depth-N skeptic that keeps all shallower rules): tier 2 *inherits* tier 1's structural FPR, dragging `Y` back down.

These produce **opposite frontier shapes**, and the **gap between them is part of the finding**: a deterministic skeptic cannot simultaneously keep structural detection (cumulative), escape its false positives (standalone), and read content. That is the trilemma with teeth.

The harness computes **both** from the same per-tier verdicts (`cumulative` verdict = logical OR of malign verdicts up to that depth — near-zero extra cost). **Cumulative is the primary frontier** (models a real graded skeptic; reconciles with the parent design's "monotone" intent); **standalone is the diagnostic** that exposes the structural-FPR escape.

---

## 3. Adaptive Corpus C — purpose-built and stratified

Authored against MITRE-anchored injection **classes**; the independent oracle is **paraphrase-invariance** (does meaning-preserving perturbation move the verdict?), never "satisfies the four rules." Field names are **realistic telemetry** (`process_name`, `command_line`, `remote_logon`), *not* contorted to light up specific rules — if tier-1's `high_threat_field` rarely fires on a realistic schema, that is itself a finding, not a corpus bug.

~15–18 base scenarios, each a frozen `BenchmarkScenario` (authored via the `_make_fact` → `EvidencePacket.freeze()` pattern of `injection_corpus.py`), wrapped in a frozen `CorpusCEntry(scenario, is_malign, stratum, twin_id)`.

### 3.1 Malign set (value-borne signal, so the value-tiers can beat the blind baseline)

| Stratum | n | Signal | Predicted catch (standalone) |
|---|---|---|---|
| `M-lex` | 4–6 | threat in the **value** matching a tier-2 regex — e.g. `process_name: "C:\Users\Public\procdump.exe"`, `command_line: "procdump.exe -ma lsass.exe C:\Temp\lsass.dmp"` | tier 1 (structural, via M2) **and** tier 2/3 (by value) |
| `M-syn` | 2–3 | **synonym-obfuscated** value — e.g. `file_created: "binary dropped to C:\Users\Public\"` (no literal `.exe`) | tier 1 (M2); tier 2 **misses**; tier 3 **recovers** (`binary→exe`) — the tier-2→3 separator |
| `M-patch` | 2–3 | the genuinely bare **Class 4** — a `_BENIGN_INDICATOR_FIELDS` field (`patch_applied: "KB5038790 installed"`) **+** an active threat value in the same packet | tier 1 (M2); tier 2/3 via L3 `ineffective_patch` |

The audit of `injection_registry_v3` confirmed Classes 2/3/5 already have value-borne coverage but **only in scenarios where tier 1 also fires structurally** (so per-scenario detection gain is invisible), and **Class 4 is bare**. `M-lex` may reuse v3 facts (e.g. INJ-001/028) as raw material but is authored for measurability.

### 3.2 Benign control set (the FP / Y axis — the load-bearing control)

| Stratum | n | Construction | Purpose |
|---|---|---|---|
| `B-struct-twin` | 4–6 | **structurally identical** to an `M-lex` twin (stage ≥ 2, no auth) but **value-benign** (`process_name: "C:\Windows\System32\svchost.exe"`, maintenance logon, no ticket) | tier 1 **must** false-positive (value-blind); tier 2/3 **must** pass. This gap *is* the frontier's rise. |
| `B-carryforward` | 2–3 | **carry-forward #1** — benign `.com`/`.js` values in borderline paths, e.g. `url: "https://cdn.example.com/users/public/tracker.js"` (matches `_USER_WRITABLE_DIR` ∧ `_EXECUTABLE_EXT` for `.js`) | measure tier-2's `.com`/`.js`-as-executable FPR honestly; without these the FPR understates |
| `B-clean` | 2–3 | low-stage recon/auth-only facts | all tiers pass — sanity floor |

A benign twin that differs from its malign sibling **only in value cannot move tier 1** (tier 1 ignores values), so tier 1's FPR on `B-struct-twin` is ~maximal *by construction*. That is the value-blindness finding, made measurable.

### 3.3 Positive control — proves tiers aren't inert, and probes trilemma leg (c)

`inject_authorization(scenario)` adds a **genuine** authorization fact (e.g. `change_ticket`) to each `M-*` scenario. Predicted:

- **Tier 1** swings benign (M2 suppressed — it *trusts the structured claim*).
- **Tier 2/3** stay malign (the credential-dump value is still present — they *do not* trust the claim).

This maps the three tiers onto the trilemma's corners directly: tier 1 = framing-robust + content-blind + trusts structured claims; tier 2/3 = content-sensitive + claim-skeptical + framing-susceptible. (A non-inert tier *must* move under a structural change — the inverse of "framing must not move the verdict.")

### 3.4 Scope precision

- **Class 5** (post-exploitation-without-change-record) has **no implemented rule** (Phase A deferred it). Corpus C therefore has **no `M-` stratum for it** — it would be unmeasurable. Documented, not silently "covered."
- The corpus is **frozen** at Phase B close; it is a Phase-C pre-registration fixture.

---

## 4. Perturbation — two deterministic, offline families

Both families mutate `fact.value` while holding the structured skeleton constant (the NIH discipline), built on the existing `MutationOperator` dataclass so skeleton-invariance is enforced by `MutatedScenarioPair.__post_init__`.

- **Semantic-framing** — reuse `paired_scenario_mutator{,_v2}` operators (`framing_prefix/suffix`, `severity_intensifier/decreaser`, `synonym_substitution_*`). Predicted `x_semantic ≈ 0` for tiers 1–3 (substring matchers shrug off prose framing). This is the apples-to-apples "determinism is framing-robust" axis — the same perturbation that drifts the tier-4 LLM (S084) leaves the deterministic tiers fixed.
- **Lexical-evasion** — a **new** module of ~4–6 operators tuned to the tier-2/3 boundary: `exe↔binary/executable`, `temp↔temporary`, path-separator / extension / token-spacing obfuscation. Predicted: flips tier 2 (`x_lexical` up), tier 3 partially recovers (folds back), tier 1 untouched. The "reading values costs evadability" axis.

The two families measure different things and are **reported separately** (`x_semantic`, `x_lexical`) per tier.

---

## 5. Harness, metrics, schema

Entirely offline. The runner needs **no preflight, no cost gate, no client** — the opposite of `architect_framing_runner`. That absence is the point: deterministic tiers need no inferential statistics.

### 5.1 Metrics (exact arithmetic — no permutation/bootstrap)

- **Binarization** at the natural operating point **`malign_score > 0`** (any malign rule fired). Secondary: Youden-optimal threshold if it differs.
- **`cumulative` verdict** = OR of standalone malign verdicts up to that depth.
- **X (susceptibility)** — for each malign scenario, apply each operator in a family; `flip_rate = flips / perturbations-that-actually-mutated`. The mutator's **no-op rejection** keeps operators with nothing to evade out of the denominator (a no-op cannot count as robustness). Reported per family.
- **Y (detection)** = `TPR − FPR` (Youden's J), malign set vs. benign control set, at the same operating point.
- Secondary, recorded not headline: `malign_score`-magnitude drift under perturbation.

### 5.2 Schema (`read_depth_frontier_schema.py`, frozen dataclasses)

- `TierCoordinate(tier_id, view, x_semantic, x_lexical, tpr, fpr, youden_j, n_malign, n_benign)` — `view ∈ {standalone, cumulative}`.
- `ScenarioVerdictRecord(scenario_id, tier_id, view, is_malign, baseline_malign_verdict, malign_score, n_mut_semantic, flips_semantic, n_mut_lexical, flips_lexical)`.
- `FrontierSummary(coordinates, records, corpus_digest, semantic_operator_names, lexical_operator_names, config)`.
- All with `to_dict`/`from_dict` for JSON persistence (feeds the Phase-C visual-companion plot). A tier-4 coordinate slot exists in `LADDER_ORDER` but is **unpopulated** in Phase B.

---

## 6. File plan — all new; v1 / v3 / Phase-A modules stay byte-stable

| File | Role |
|---|---|
| `ares/dialectic/measurement/read_depth_corpus.py` | Corpus C scenarios + `CorpusCEntry` labels + `inject_authorization` positive-control builder. |
| `ares/dialectic/measurement/read_depth_evasion_operators.py` | ~4–6 lexical-evasion `MutationOperator`s (reuse the dataclass from `paired_scenario_mutator`). |
| `ares/dialectic/measurement/read_depth_frontier_schema.py` | Frozen result types (§5.2). |
| `ares/dialectic/measurement/read_depth_frontier_runner.py` | `run_frontier(config) -> FrontierSummary`. Pure offline; consumes `DETERMINISTIC_TIERS` + semantic operators + the new evasion operators. |
| `ares/dialectic/measurement/read_depth_frontier_report.py` | Markdown table (tier × view → X_sem, X_lex, TPR, FPR, J) + `(X, Y)` JSON emitter. |
| `scripts/run_session_087.py` | Thin CLI — runs the frontier, writes report + JSON. Gate-free (no `--confirm-live`; nothing costs anything). |

### 6.1 Reuse map (honest)

- **Reuse directly:** the `MutationOperator` / `PairedScenarioMutator` machinery + the semantic operators (`OPERATORS_V1/V2`); the `_make_fact` / `BenchmarkScenario` / `ScenarioMetadata` authoring pattern; `LightSkepticJudgment`; the `DETERMINISTIC_TIERS` ladder registry.
- **Pattern-match (do not import):** `architect_framing_runner` / `architect_framing_report` *structure* (runner/report shape), but simpler — no preflight, cost, or client.
- **Not used in Phase B:** `architect_framing_metrics` permutation/bootstrap, `architect_framing_selection`, `architect_framing_control` (drop-fact). These are Phase-C (LLM-anchor) tools. For the deterministic tiers the statistics collapse to exact arithmetic — and that is the result, not a shortcut.

---

## 7. Tests (~25–35 new, all offline / deterministic)

- **Corpus contract:** every entry labeled; each `B-struct-twin` shares its `M-lex` twin's field-skeleton but differs in value; `inject_authorization` adds an `_AUTHORIZATION_FACT_FIELDS` field.
- **Evasion operators:** each mutates its intended token; skeleton-invariant + deterministic; no-ops cleanly when the token is absent.
- **Metrics:** flip-rate denominator excludes no-ops; TPR/FPR/J; cumulative = OR composition.
- **Frontier sanity (the scientific contract):** pins the authored corpus to its predicted deterministic behavior — tier 0 `Y = 0`; tier-1 *standalone* FPRs on `B-struct-twin`; tier-2 standalone catches `M-lex`, misses `M-syn`; tier-3 catches `M-syn`; positive control flips tier-1's verdict but **not** tier-2/3's. Legitimate to assert because these tiers are exact; guards against a future corpus edit silently breaking the frontier.
- **Schema** round-trip; **runner** determinism + emits one coordinate per tier×view with the tier-4 slot absent.

---

## 8. Carry-forwards into Phase C (recorded, not Phase-B blockers)

- **Carry-forward #2:** the report + a code comment phrase "tier 1 is blind to value-borne attacks" precisely — true for `high_threat_field` (M1); `high_stage_no_auth` (M2) still fires via field-derived stage.
- **Pre-registration:** Phase B's frozen corpus + operator set are the committed fixtures; Phase C commits bands + falsifier before the tier-4 run.
- **LLM anchor reuse:** Phase C reuses the S084 run (`20260605-194137-713674`) for the overlapping scenario subset and tops up under a cost cap.

---

## 9. Definition of done (Phase B)

Corpus C (with negative + positive controls) authored and frozen; an offline harness emitting per-tier `(x_semantic, x_lexical, TPR, FPR, J)` for the 4 deterministic rungs in **both** views; ~25–35 new tests; full suite green (zero regressions); squash-merge to `main`. **No frontier verdict** — that needs the Phase-C anchor + pre-registration.

---

## 10. Decisions locked during this brainstorm (2026-06-07)

- **Corpus:** purpose-built **stratified** mini-corpus (not "reuse v3 + patch the bare class"), because tier-1's stage rule fires on nearly everything and most v3 scenarios are invisible to the value-tiers — a naive corpus yields a muddy frontier.
- **X axis:** **two families reported separately** — semantic-framing (reuse) + lexical-evasion (new operators) — because semantic paraphrase leaves the substring-matching tiers at `X ≈ 0`, so tier-2's predicted evadability is only testable by perturbing value tokens.
- **Tier semantics:** report **both** standalone and cumulative views; **cumulative is the headline**. The standalone↔cumulative gap is part of the finding.
- **Operating point:** `malign_score > 0`; Youden-J threshold secondary.
- **Positive control:** inject a genuine authorization fact (not the architect-framing drop-fact control).
- **Out of scope:** Class 5 (no rule); the LLM anchor, pre-registration, and frontier verdict (all Phase C); production wiring of any tier.
