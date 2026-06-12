# Design — OOV Evasion Judge-Robustness Audit (Read-Depth Frontier, Phase E)

**Date:** 2026-06-12
**Session:** 090
**Phase:** Read-Depth Robustness Frontier — Phase E (judge-robustness audit)
**Status:** design approved (2026-06-12); spec under review
**Branch:** `session/090-oov-judge-audit`
**Predecessor:** Session 089 Phase D1 (instrument, `66975b5`) + D2 (live verdict SUPPORTED_STRONG, `545160a`)

## 1. Motivation — the one load-bearing assumption

The S089 D2 live verdict (**SUPPORTED_STRONG**) rests entirely on one unverified premise: that the
Sonnet LLM-judge correctly ruled all 64 generated disguises *meaning-preserving*. The judge accepted
**all 64 with zero rejections** at every gate — which is precisely the smell worth investigating.

The verdict's logic: a disguise is an *evasion* iff (a) a human/judge still sees the original threat
(judge says "still malign") **and** (b) the deterministic `v2_canonical` matcher downgrades it to
benign. The failure mode that would falsely inflate the result is **judge leniency**: the judge waves
through a disguise that actually *neutered* the threat (a real SOC analyst would call it benign), so
`v2_canonical` correctly downgrading it gets miscounted as an "evasion."

This experiment stress-tests that premise. It does **not** change the verdict; it asks whether the
verdict survives independent scrutiny, turning SUPPORTED_STRONG from "instrument-sound" into
"paper-quotable."

Two known caveats from the D2 report are closed here: *single adversary/judge model* and *judge
dependence* (the meaning-preservation oracle is itself one LLM).

## 2. What this is NOT

- **Not a protocol change.** `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md` is frozen-on-commit
  and SSOT-guarded. Its "Adversary + judge: claude-sonnet-4 … judged still-malign" acceptance rule is
  untouched. The verdict re-run reproduces that protocol byte-for-byte.
- **Not a re-litigation of the verdict.** The audit sits *beside* the verdict as an additive
  confidence layer. Its own decision rule is pre-registered separately, before any independent judge runs.
- **Not a schema rewrite.** `read_depth_oov_schema.py` (`OOVFrontierSummary` and its digest) stays
  byte-identical. Persistence is a new sidecar artifact.

## 3. Architecture (Approach A — sidecar + standalone audit)

Two clean, separately-reproducible artifacts instead of one bloated verdict file:

```
 verdict re-run (frozen protocol, run_session_089 + persistence)
   ├── oov_summary.json        (UNCHANGED schema — the verdict)
   └── oov_disguises.json      (NEW sidecar — every candidate + its disguise text + judge outcome)
                                          │
                                          ▼
 audit (run_session_090, additive, does NOT gate the verdict)
   reconstruct disguised packets from frozen corpus + persisted rewrites
   → 2 independent judges (GPT-4o, Gemini 2.5 Pro) over evading disguises + controls
   ├── oov_audit.json          (machine — panel verdicts + audit classification)
   └── oov_audit_report.md      (human — original→disguised table + per-judge votes)
```

Rejected alternative (Approach B — extend `OOVFrontierSummary` with disguise + audit fields):
churns a frozen tested schema, changes `oov_summary.json` shape and its digest semantics, and conflates
"the verdict" with "our confidence in it." Approach A is the project idiom (peer modules, frozen
dataclasses, new files, one concern per script).

## 4. Persistence layer

### 4.1 `OOVDisguiseRecord` (new, frozen, serializable)

Captures **every generated candidate** — accepted and rejected. Rejected candidates are evidence about
judge strictness (the live run's zero rejections is the signal under investigation), so they are kept.

| field | type | source |
|---|---|---|
| `scenario_id` | str | malign entry |
| `arm` | str | `black` / `white` |
| `value_rewrites` | tuple[(str,str),…] | candidate disguise (fact_id, new_value) |
| `original_values` | tuple[(str,str),…] | original value of each rewritten fact (before→after pairing) |
| `skeleton_ok` | bool | validator |
| `novel` | bool | validator |
| `judge_malign` | Optional[bool] | Sonnet judge (None if gated out pre-judge) |
| `accepted` | bool | validator |
| `reject_reason` | str | validator |
| `canonical_flipped` | bool | runner (tier measurement) |
| `lexical_flipped` | bool | runner (tier measurement) |

`to_dict`/`from_dict` round-trip (mirrors the existing schema types). Tuples serialize as lists.

**Reproducibility:** we persist `value_rewrites`, not full packets. Frozen corpus (digest-checked) +
persisted rewrites + deterministic `apply_candidate` reconstruct each disguised packet exactly. No
redundant packet storage; the audit rebuilds disguised packets from the sidecar + corpus.

### 4.2 Sidecar artifact `oov_disguises.json`

```json
{ "corpus_digest": "...", "oov_corpus_digest": "...", "model": "...", "provider": "...",
  "k": 8, "verdict": "...", "records": [ {OOVDisguiseRecord}, ... ] }
```

Header digests let the audit assert it is reading disguises produced against the expected corpus.

### 4.3 Runner change (surgical, test-locked)

`read_depth_oov_runner.py` already builds every `OOVValidationResult` and computes `canon_flip`/`lex_flip`
— it just discards them. Change:

- New core function `run_oov_experiment_audited(cfg, *, generate_fn, judge_fn)
  -> tuple[OOVFrontierSummary, tuple[OOVDisguiseRecord, ...]]` that collects the per-candidate records
  (capturing `original_values` from the pre-rewrite scenario facts).
- `run_oov_experiment(...) -> OOVFrontierSummary` becomes a thin back-compat wrapper returning only the
  summary, so every existing runner test passes unchanged.

## 5. Verdict re-run

`scripts/run_session_089.py` gains a minimal addition: call `run_oov_experiment_audited`, then write the
new `oov_disguises.json` next to the unchanged `oov_summary.json` + `oov_report.md`. **Frozen prereg
protocol verbatim** — Sonnet 4 adversary + Sonnet judge, both arms, K=8 (~$0.11). This is run-2; run-1
stays as the shipped audit trail. Run-2 is paper-quotable because its disguises are inspectable.

## 6. Audit layer (`read_depth_oov_audit.py` + `scripts/run_session_090.py`)

### 6.1 Audit set + controls

- **Audit set:** the *evading* disguises — `accepted ∧ canonical_flipped`. These are the load-bearing
  ones (genuine-threat-claim that the matcher missed).
- **Positive control:** the original (un-disguised) malign packets for each evaded scenario. A
  discriminating judge must call these **malign**.
- **Negative control:** ≥1 benign structural twin from Corpus C (`read_depth_corpus`). A discriminating
  judge must call these **benign**. *This is the direct leniency test*: a judge that calls a benign
  twin "threat" is not discriminating, and its malign votes on the audit set are untrustworthy.

### 6.2 The panel + the Sonnet-degeneracy refinement

The panel is three judges using the **same frozen SOC-analyst prompt** as the verdict run (reuse
`make_live_judge_fn(model, provider)`, which is already provider-parameterized):

1. **Sonnet** — read from the persisted `judge_malign`. **Note (refinement from the design draft):** for
   every disguise in the audit set, `accepted` is true, which *requires* `judge_malign == True`. So
   Sonnet's vote is **always malign on the audit set by construction**. A "majority of 3" rule would
   therefore degenerate to "≥1 independent agrees." We instead rest confirmation on the **two
   independent judges**, with Sonnet reported for completeness/contrast only.
2. **GPT-4o** (OpenAI) — live independent vote.
3. **Gemini 2.5 Pro** (Google) — live independent vote.

### 6.3 Pre-registered decision rule (committed before the independents run)

Per evading disguise, classify on the two independents:
- **independent-confirmed (strong):** *both* GPT-4o and Gemini call it still-malign.
- **independent-split:** exactly one does.
- **independent-refuted:** neither does.

Per scenario (one of the evaded scenarios):
- **CONFIRMED** iff ≥1 of its evading disguises is *independent-confirmed (both)*.

Control gating (per independent judge):
- The judge must pass **both** controls (positive→malign, negative→benign) for its votes to count.
- If a judge fails a control, its votes are flagged untrustworthy; the audit verdict for that judge is
  reported and the run leans on the passing judge + the human.

Audit verdict:
- **ROBUST** — both independents pass controls **and** *every* evaded scenario is CONFIRMED → the
  SUPPORTED_STRONG verdict survives independent judging.
- **PARTIAL** — controls pass and ≥1 but not all evaded scenarios CONFIRMED → report which scenarios'
  evasions are judge-dependent.
- **REFUTED** — controls pass and *zero* evaded scenarios CONFIRMED → the evasions were Sonnet-leniency
  artifacts (a major finding; would retract SUPPORTED_STRONG).
- **INCONCLUSIVE** — a control fails for an independent judge (panel miscalibrated).

**Human is the tiebreaker, not overridden by the panel.** The human reads every *split* and *refuted*
disguise plus a random sample of *confirmed* ones (rendered original→disguised per fact, with the tier
flip and all three judges' votes) and records a final concurrence ROBUST/PARTIAL/REFUTED.

### 6.4 Outputs

- `oov_audit.json` — machine: per-disguise panel votes, per-scenario confirmation, control outcomes,
  audit verdict, cost.
- `oov_audit_report.md` — human: a table per evading disguise (original→disguised per fact, which tier
  flipped, GPT-4o / Gemini / Sonnet votes, classification) + the controls + the audit verdict + the
  spots the human must adjudicate.

## 7. New audit pre-registration

`docs/paper_4/PREREGISTRATION_oov_audit_phase_e.md` — states the audit set definition, both controls,
the two-independent panel, and the §6.3 decision rule and thresholds. The frozen D-phase prereg is
**not** modified. SSOT-guarded by a new test that asserts the prereg's bands match the code constants
(mirrors `tests/paper_4/test_oov_prereg_bands_match_code.py`).

**Sequencing (closes the "controls chosen post-hoc" critique).** The decision rule and control *design*
are independent of run-2's outcome ("for whatever scenarios run-2 evades, confirm each via both
independents; positive control = those scenarios' originals, negative control = benign twins"), so the
audit prereg is committed **before any live run** — before run-2 and before the independents. The
concrete control *membership* (which scenario ids) is then mechanically determined by run-2, not chosen.
The independent-judge run is the only step that sees audit data, and it happens strictly after the
prereg is frozen.

## 8. Folded-in code follow-ups (flagged by the S089 final review)

- **Provider-aware cost.** `read_depth_oov_validator._call_cost` hardcodes Sonnet pricing
  (`3.0/15.0 per 1M`). Replace with a small `(provider, model) → (price_in, price_out)` table used by
  both the verdict judge and the audit judges; an **unknown (provider, model) raises** (never silently
  mis-costs). Sonnet pricing preserved for the frozen verdict path.
- **Mid-run cost-abort.** Thread `cost_ceiling_usd` into `OOVConfig` (default = `READ_DEPTH_OOV_HARD_CEILING_USD`)
  and the audit config; abort the loop the moment accumulated cost crosses it. Today only the pre-run
  *estimate* is gated. A dedicated `CostCeilingExceeded` exception; both live CLIs surface it cleanly.

## 9. Files

**New**
- `ares/dialectic/measurement/read_depth_oov_audit.py` — `OOVDisguiseRecord`, sidecar load/write,
  audit-item selection, panel record types, `run_audit` (injectable judges), `classify_audit_verdict`,
  renderers, `(provider, model)` price table, `CostCeilingExceeded`.
- `scripts/run_session_090.py` — audit CLI mirroring `run_session_089.py`
  (`--dry-run`/`--preflight-only`/`--confirm-live`/`--cost-ceiling` ≤ $10/prereg-file gate, UTF-16 .env;
  `--judges` defaulting to `gpt-4o,gemini-2.5-pro`).
- `docs/paper_4/PREREGISTRATION_oov_audit_phase_e.md`.
- Tests (≈6 files): `test_read_depth_oov_audit_{schema,select,panel,verdict,report}.py`,
  `test_run_session_090_cli.py`, `test_read_depth_oov_audit_no_network_anchor.py` (source-text purity,
  suite-robust per the S089 gotcha), `tests/paper_4/test_oov_audit_prereg_bands_match_code.py`.

**Modified (surgical, test-locked; sanctioned by this session's goal)**
- `read_depth_oov_runner.py` — add `run_oov_experiment_audited`; back-compat wrapper; cost-abort.
- `read_depth_oov_validator.py` — provider-aware `_call_cost` + price table.
- `scripts/run_session_089.py` — write the `oov_disguises.json` sidecar.
- `CLAUDE.md` — test-floor bump + Phase E ledger line + Key Code Locations.

**Frozen (untouched):** `read_depth_oov_schema.py`, `PREREGISTRATION_oov_evasion_phase_d.md`.

## 10. Testing strategy

TDD, then subagent-driven build (implementer + spec + code-quality review per task; final Opus
whole-branch review), per the S089 method. All audit logic is offline/deterministic via **injected
judge fns** (no network in tests); the live panel is reached only through `make_live_judge_fn` behind
the CLI `--confirm-live` gate. Reuse the S089 patterns: UTF-16 `.env`, prereg-file gate, hard ceiling,
purity anchor via `inspect.getsource` (NOT `sys.modules`). Estimated ≈30–40 new offline tests; floor
4,150 → ≈4,185.

## 11. Cost & gating

- Verdict re-run: ~$0.11 (Sonnet, K=8, both arms) — unchanged frozen protocol.
- Audit: 2 independents × (|evading| ≈ 20–24 + ~6 control items) ≈ 50–60 judge calls ≈ **$1–3**.
- Both live paths: `--confirm-live` + committed prereg + cost ceiling (≤ $10 hard cap) + the new
  mid-run cost-abort. Total session live spend ≈ **$1.50–3.50**.

## 12. Out of scope (YAGNI)

- No third independent judge beyond GPT-4o + Gemini.
- No re-generation of disguises during the audit (audit reads the frozen sidecar only).
- No change to the deterministic gates (skeleton/novelty are provider-independent — not re-run).
- No relative "same-as-original" judge framing — the absolute "is the disguised packet still a threat"
  question matches the frozen judge and is the correct leniency test.

## 13. Open risks

- **Run-to-run variance.** The adversary is an LLM; run-2's evaded scenarios may differ from run-1's
  (K=8, 4 scenarios). Both runs are reported; the audit binds to run-2's disguises.
- **Independent-judge miscalibration.** Mitigated by the controls; a control failure yields
  INCONCLUSIVE for that judge rather than a false ROBUST/REFUTED.
- **Provider availability.** The audit needs live OpenAI + Google keys (present since S074–076);
  surfaced at preflight.
