# Design — OOV Adversarial Evasion Generator (Read-Depth Frontier, Phase D)

**Date:** 2026-06-11
**Status:** Design approved (brainstorm complete) — pending spec review, then writing-plans
**Phase 7 mapping:** Read-Depth Robustness Frontier, Phase D. Sequel to S088 Phase C.
**Session:** 089
**Intended artifact:** The decisive Paper 4 result. Resolves the one honest non-falsifier
the S088 verdict named.

---

## 1. The win condition

A **publishable verdict**, pre-registered before the run. S088 closed Phase C with the trilemma
**SUPPORTED**, but on one honest assumption: `v2_canonical`'s framing-robustness (`X_lexical = 0`) is
true **by construction**, because the only two Phase B evasion operators (`exe->binary`,
`temp->temporary`) are exactly the two folds hard-coded in tier-3's `_SYNONYMS` map
(`binary->exe`, `temporary->temp`). Tier 3 was built to undo precisely the disguises it was tested
against. This experiment turns `X_lexical` from a by-construction constant into a **measured
adversarial quantity**, and settles SUPPORTED vs FALSIFIED for real.

This is engineering only if we hand-pick the disguises (then "robust" or "evadable" is an artifact of
our choices, the same circularity that produced the asterisk). It is science because an **LLM
adversary** invents the disguises, a deterministic gate plus an independent LLM-judge validate them,
and the final measurement is deterministic and reproducible. The disguises are LLM-discovered, not
author-chosen; the measurement is byte-stable. Both halves of the circularity critique die.

## 2. The central question

Tier-3's synonym folding currently recovers exactly `binary` and `temporary`. **Does that recovery
generalize to disguises it was never built for?** S088 measured `v2_canonical` standalone at
`TPR = 1.000` (catches all 4/4 string-borne malign scenarios), so each is genuinely flippable. If a
meaning-preserving out-of-vocabulary (OOV) disguise drives canonical malign->benign on even one
scenario, canonicalization has a real hole. If canonical holds against an adversary actively trying to
break it, the robustness is earned, not assumed.

The four string-borne malign scenarios under attack (from Adaptive Corpus C,
`read_depth_corpus.py`):

| scenario | threat-bearing value(s) |
|---|---|
| `RDF-M-LEX-001` | `procdump.exe -ma lsass.exe C:\Temp\lsass.dmp`, `C:\Users\Public\procdump.exe` |
| `RDF-M-LEX-002` | `C:\Temp\update.exe`, `C:\Temp\update.exe written 1.2MB` |
| `RDF-M-SYN-001` | `binary dropped to C:\Users\Public\`, `loader running from public folder` |
| `RDF-M-PATCH-001` | `procdump.exe -ma lsass.exe`, `C:\Users\Public\procdump.exe` (+ benign `patch_applied`) |

## 3. The verdict direction (LOCKED — precision fix carried from S088)

The S088 verdict note (`docs/paper_4/S088_READ_DEPTH_FRONTIER_VERDICT_2026-06-10.md`) states the
direction two ways and one clause has the labels crossed ("`X_lexical > 0` -> FALSIFIED"). Under the
pre-registration's own definitions the rigorous reading is:

- **OOV evasion succeeds** (canonical flips malign->benign) -> canonical is **not** framing-robust ->
  it leaves the good corner -> **trilemma SUPPORTED** (now earned, not assumed).
- **OOV evasion fails** (canonical holds under adversarial disguises, detection intact) -> canonical
  genuinely occupies the good corner -> **trilemma FALSIFIED** -> "deterministic content-robustness is
  achievable; here is the recipe."

Both outcomes are publishable. This direction is frozen in the Phase D pre-registration before any
run.

## 4. Architecture and data flow

Five new peer modules (peers to the existing measurement modules, not wrappers). Linear pipeline:

```
malign scenario ──> [1] adversary generator ──> raw candidates
                         (black-box + white-box prompts, injectable generate_fn)
raw candidate ──────> [2] deterministic gate ──> skeleton-invariant? + novel (not in-vocab)?
gated candidate ────> [3] LLM-judge oracle ────> still genuinely malign to an analyst?
accepted candidate ─> [4] frozen OOV corpus ───> serialized + digest (reproducible)
frozen corpus ──────> [5] measurement + verdict > run the string ladder, record flip vs hold
```

1. **Adversary generator** (`read_depth_oov_generator.py`) — builds a **black-box** prompt (sees only
   the malign value strings + the goal: "rewrite so an automated keyword scanner misses it while a
   competent SOC analyst still reads the same threat") and a **white-box** prompt (additionally shows
   tier-3's regexes + `_SYNONYMS` map). Parses the LLM reply into per-fact value rewrites. Injectable
   `generate_fn` (offline tests mock it; the live client is lazy-imported, gated).
2. **Deterministic validity gate** (`read_depth_oov_validator.py`, free) — enforces
   **skeleton-invariance** by applying rewrites through the existing
   `paired_scenario_mutator._apply_value_replacements` (only `fact.value` strings change; fields,
   keys, structure identical). Plus a **novelty guard**: reject candidates whose canonicalized form
   reduces to a token already in the current in-vocab fold set, so we strictly test *new* disguises,
   not the two already measured.
3. **LLM-judge meaning-oracle** (`read_depth_oov_validator.py`, `judge_fn`) — "Would a competent SOC
   analyst still read this packet as the same threat (credential dumping / dropper-in-user-path /
   ineffective-patch)?" **Yes** -> accepted (a fair evasion attempt). **No** -> rejected (the disguise
   destroyed the meaning; not a fair test of the matcher). Independent prompt from the generator to
   limit adversary/judge collusion.
4. **Frozen OOV corpus** — accepted candidates serialized with a SHA256 digest (same discipline as
   Corpus C's `9401b7188ba790a5`). The verdict is reproducible offline forever once frozen.
5. **Measurement + verdict** (`read_depth_oov_runner.py` + `read_depth_oov_report.py`, free,
   deterministic) — run `light_skeptic_v2_{lexical,canonical}.evaluate` on each accepted evasion;
   record flip (malign_score -> 0) vs hold. Apply the pre-registered 3-way rule; render the report.

## 5. The two arms (graded threat model)

- **Black-box (primary, verdict-bearing):** adversary sees only the malign values and the goal, never
  the matcher internals. The realistic "blind attacker." A success here is the strongest SUPPORTED
  story.
- **White-box (steelman upper bound):** adversary additionally sees tier-3's source (regexes +
  synonym map). Survival here is the strongest possible FALSIFIED claim ("robust even against an
  adversary that can read its code").

Both run; cost stays trivial (4 scenarios x K x 2 arms). The arm an evasion came from is recorded on
every candidate.

## 6. Metrics

- **Verdict metric (scenario-level):** a malign scenario is **evaded** iff the adversary produced
  >= 1 accepted disguise that flips `v2_canonical` to benign. `adversarial_X_scenario` =
  (# evaded scenarios) / (# malign string scenarios = 4), per arm.
- **Magnitude metric (per-candidate flip-rate):** across all accepted candidates, the fraction that
  flip canonical. Higher N (K x 4 x 2), reported as the "how leaky" number beside the binary verdict.
  Reuses `read_depth_frontier_metrics.flip_rate`.
- **Detection-preservation rides the same metric:** a flip is simultaneously a susceptibility hit and
  a TPR loss, so one number drives both frontier axes. No separate Y run is needed; canonical's
  detection on the un-evaded corpus is already S088's `TPR = 1.000`.

## 7. The pre-registered 3-way decision rule (bands frozen before the run)

- **τ = "any hole."** A FALSIFIED / recipe-holds verdict requires `adversarial_X_scenario = 0` in the
  arm under test (0 of 4 scenarios evaded). A security defense with even one meaning-preserving hole
  is evadable. (Equivalent to a 0.10 threshold on the scenario rate, since the smallest non-zero rate
  is 0.25, but stated as a count rule for clarity.)
- **Graded outcome:**
  - canonical evaded in **black-box** -> **SUPPORTED, strongly** (a blind attacker beats it).
  - survives black-box, evaded in **white-box** -> **SUPPORTED, moderately** (robust to blind
    attackers, not to informed ones).
  - survives **both**, detection intact -> **FALSIFIED** (the deterministic content-robustness recipe
    is real).
- **Verdict coordinate:** `v2_canonical` (tier 3). `v2_lexical` (tier 2) is reported for frontier
  context (predicted trivially evaded — it has no canonicalizer). The LLM-semantic tier (tier 4)
  against OOV evasions is **out of scope** (re-introduces metered measurement and is not
  verdict-bearing; named future work).
- **Validity precondition:** the rule is only read on a non-empty accepted corpus in each arm. If the
  judge rejects everything (no fair evasion attempt was produced), that is an instrument failure, not
  a FALSIFIED verdict — logged and surfaced, not silently scored.

## 8. Architecture constraints (non-negotiable, per CLAUDE.md)

- **New files only.** No existing module modified. The tiers (`light_skeptic_v2_*`), corpus, mutator,
  and frontier metrics are imported, never edited. S088 artifacts stay byte-stable so Phase C
  reproduces on HEAD.
- **Frozen dataclasses** for every output type.
- **Determinism where it counts:** the LLM appears only in generation (step 1) and judging (step 3).
  Once the corpus is frozen, every measurement and the verdict are pure-Python and reproducible. The
  deterministic gate and the metrics carry **zero** LLM/network dependency (tested failure condition,
  mirroring the v1 anchor test).
- **Injectable seams:** `generate_fn` and `judge_fn` are parameters; offline tests pass deterministic
  fakes; the live client is lazy-imported behind the CLI gate (the S088 `make_live_cycle_fn` pattern).
- **Zero regressions;** squash-merge to main only after the full suite passes.
- **Pre-registration committed before the live run;** the runner refuses to fire live unless the
  pre-reg doc exists.

## 9. File plan

| file | role |
|---|---|
| `ares/dialectic/measurement/read_depth_oov_schema.py` | frozen dataclasses: `OOVCandidate`, `OOVValidationResult`, `OOVEvasionRecord`, `OOVArmSummary`, `OOVFrontierSummary`; `READ_DEPTH_OOV_HARD_CEILING_USD = 10.0` |
| `ares/dialectic/measurement/read_depth_oov_generator.py` | black-box / white-box prompt builders + candidate parser; injectable `generate_fn`; lazy live client |
| `ares/dialectic/measurement/read_depth_oov_validator.py` | deterministic skeleton-invariance gate + in-vocab novelty guard + LLM-judge interface (`judge_fn`) |
| `ares/dialectic/measurement/read_depth_oov_runner.py` | orchestrate generate -> validate -> freeze -> measure; `estimate_cost_usd`, `run_preflight`, `run_oov_experiment`; `make_live_generate_fn` / `make_live_judge_fn` (lazy) |
| `ares/dialectic/measurement/read_depth_oov_report.py` | render 3-way verdict + frontier coordinates + the "non-falsifier resolved" narrative |
| `scripts/run_session_089.py` | CLI: `--dry-run` / `--preflight-only` / `--confirm-live` / `--cost-ceiling` ($10 hard cap) / `--arm black\|white\|both`; UTF-16 `.env`; pre-reg-file gate |
| `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md` | the Phase D pre-registration, frozen before the run |

## 10. Reuse (imported, never modified)

- `read_depth_corpus.py` — the 4 malign scenarios and their values.
- `paired_scenario_mutator._apply_value_replacements` — skeleton-invariant value rewriting.
- `light_skeptic_v2_lexical.evaluate`, `light_skeptic_v2_canonical.evaluate` — the tiers under test;
  `light_skeptic_v2_canonical.canonicalize` + `_SYNONYMS` for the novelty guard and the white-box
  prompt.
- `read_depth_frontier_metrics.flip_rate` — the magnitude metric.
- `leakage_runner` client construction + `make_client` (Anthropic Sonnet 4).
- The `read_depth_tier4_anchor` injectable-fn + lazy-client + preflight + cost-ceiling pattern.

## 11. Error handling

- Unparseable LLM reply or non-skeleton-invariant candidate -> deterministic gate rejects, logged,
  excluded from the denominator.
- Judge-rejected candidate -> excluded (not a fair evasion attempt).
- Empty accepted corpus in an arm -> instrument-failure signal, **not** a verdict (see §7).
- Cost ceiling checked at preflight and re-checked mid-run; hard abort on breach.
- Live run refuses unless the pre-registration doc is present (discipline enforced in code).
- Frozen corpus digest for byte-stable reproduction.

## 12. Testing (zero regressions; suite floor rises)

- **Generator** (mocked `generate_fn`): black-box vs white-box prompt construction, candidate parse,
  output skeleton-invariance.
- **Validator:** skeleton-gate accept/reject, novelty guard (in-vocab fold rejected), LLM-judge
  interface (mocked `judge_fn`).
- **Runner** (mocked LLM): end-to-end generate -> validate -> measure, `estimate_cost_usd`, preflight
  gating, empty-corpus instrument-failure path.
- **Schema/contract**, **3-way decision-rule** (each band, including the empty-corpus guard), **CLI**.
- **SSOT:** a `tests/paper_4/` test that the pre-reg bands match the code constants (mirrors
  `test_prereg_bands_match_code.py`).
- **Anchor:** zero-LLM / zero-network on the deterministic gate + metrics.

## 13. Cost and feasibility

- Generation + judging are the only metered steps; all measurement is free.
- Batched generation (~8 to 16 calls, K disguises each) + per-candidate judging -> realistic spend
  ~$2 to $5. **$10 hard cap** (below S088's $15). `--dry-run` estimate first, preflight-gated,
  `--confirm-live` to spend. Model `claude-sonnet-4-20250514` (matches S088).
- Phase D1 (everything except the live run) is offline, deterministic, free.

## 14. Out of scope (YAGNI)

- Tier-4 (LLM-semantic) measured against OOV evasions — metered, not verdict-bearing; future work.
- Adversarial co-evolution to equilibrium (harden tier 3, re-attack, repeat) — the original frontier
  spec rejected this (§10) as a different paper.
- Wiring any hardened canonicalizer into production — this is a measurement study.
- Multi-model sweep of the adversary — one family (Sonnet 4) suffices for v1.
- Expanding Corpus C — the small-N caveat (§16) is stated honestly, not engineered away here.

## 15. Paper placement and reviewer risk

- **Resolves S088's non-falsifier:** Paper 4's spine result. The S088 SUPPORTED verdict rested on one
  named assumption; Phase D tests it head-on.
- **Spine line:** "LLM proposes, deterministic code disposes — and when an LLM is turned loose to
  invent disguises, the deterministic reader either holds (a real recipe) or bends (the attack was
  only relocated, never removed)."
- **Reviewer-risk flag:** the nearest critique is "your OOV disguises are also hand-picked." The
  defense is the architecture itself — disguises are LLM-discovered, gated by an independent judge,
  and the measurement is deterministic and frozen. Keep that load-bearing in the framing.

## 16. Honest caveats (stated up front in the pre-reg)

- **Small N:** four malign string-borne scenarios. The per-candidate flip-rate (§6) partly
  compensates with more data points, but the scenario-level verdict rests on a thin corpus. Stated as
  a limitation, not hidden.
- **Single model:** one adversary family. A disguise space larger than one model's imagination is
  unmeasured.
- **Judge dependence:** the meaning-preservation oracle is itself an LLM. A judge that is too lenient
  inflates the accepted corpus; too strict, deflates it. Mitigated by an independent prompt and by
  reporting reject rates, not eliminated.

## 17. Decisions locked during brainstorming (2026-06-11)

- Generator strategy: **LLM proposes, code disposes** (LLM adversary + deterministic gate + LLM-judge
  + frozen reproducible corpus).
- Adversary knowledge: **both arms, graded** (black-box primary, white-box steelman).
- Verdict direction: **OOV-evades => SUPPORTED, OOV-holds => FALSIFIED** (S088 label-cross corrected).
- τ: **any hole** (0 of 4 evaded required for FALSIFIED).
- Verdict tier: **`v2_canonical`**; lexical reported for context; tier-4 out of scope.
- Cost: **$10 hard cap**, generation + judging only, preflight-gated.

## 18. Success criteria

- Five deterministic-seam modules built, each independently tested, deterministic gate + metrics
  zero-LLM / zero-network, S088 artifacts byte-stable, zero regressions.
- A Phase D pre-registration (3-way bands + falsifier + caveats) committed before the live run.
- A frozen, digest-stamped OOV corpus and a measured `adversarial_X_scenario` for `v2_canonical` in
  both arms, with the per-candidate magnitude.
- A graded verdict: SUPPORTED (strongly / moderately) or FALSIFIED — a clean, calibrated, publishable
  resolution of the S088 non-falsifier.

## 19. Implementation phasing (note for writing-plans — scope D1 first)

- **Phase D1 (offline, free):** all five modules with injectable `generate_fn` / `judge_fn` + full
  offline tests + the committed Phase D pre-registration. Entirely mockable, zero spend. The first
  plan; de-risks the whole arc before any API call (mirrors how Phase A de-risked the frontier).
- **Phase D2 (metered, gated):** commit and review the pre-reg, then the live black + white-box run,
  freeze the OOV corpus, emit the graded verdict report.

Writing-plans should scope to **Phase D1 first**, not attempt both phases in one plan.
