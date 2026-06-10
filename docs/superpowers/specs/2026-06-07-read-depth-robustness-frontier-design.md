# Design — The Read-Depth Robustness Frontier (Light Skeptic v2 + Adaptive Corpus C)

**Date:** 2026-06-07
**Status:** Design approved (brainstorm complete) — pending spec review, then writing-plans
**Phase 7 mapping:** V4 Tribunal Step 4 (Light Skeptic v2) + Step 3 (Adaptive Corpus C), unified.
**Intended artifact:** A new falsifiable result — "Paper 4" fuel.

---

## 1. The win condition

A **publishable finding**, not a feature. "Add malign rules" is engineering — of course more rules
catch more. The science is the *trade-off* the rules expose, and what it reveals about the
architecture.

## 2. The finding (the central claim)

Paper 2's Finding 11 reported that the deterministic Light Skeptic *matches* the LLM Skeptic using
four **field-only** rules. The S076 post-hoc revealed that parity is partly **hollow**: the
field-only design is framing-invariant *by construction* because it never reads the
attacker-controlled `value` (`fact.field` is read at `light_skeptic.py:143`; `Fact.value: Any` at
`fact.py:58` is never touched). Its robustness is the robustness of a system that does not look.

**Central question:** *Was the deterministic skeptic's framing-robustness a real defense — or just
blindness? When you give it eyes (value-reading malign rules), does robustness survive?*

**The sharpened claim — a trilemma, not a feature gap.** A deterministic skeptic cannot read
attacker-controlled content in a way that is simultaneously (a) content-sensitive, (b)
framing-robust, and (c) not merely trusting the attacker's structured claim:

- Read **keys only** → blind (v1).
- Read **structured values** (bool/int/enum) → framing-robust, but you have relocated the attack to
  **data-integrity** (Paper 2's fifth generalizable observation, now demonstrated at the *skeptic*
  layer rather than the firewall).
- Read **string values** → you catch prose-borne signals but inherit framing-susceptibility.

**INJ-008 is the canonical illustration.** The LLM *hallucinated* a `patch_applied` field that does
not exist in the scenario. A deterministic structured-reader would not hallucinate it — but if an
attacker simply *added* a fake `patch_applied: true` fact, the deterministic reader would trust it.
Determinism kills the hallucination and exposes the data-integrity surface in the same move.

**Candidate escape hatch (parked as future work, not in scope):** `Fact.provenance` exists. Gating
reads on *trusted* provenance might partially recover robustness — flipping the story from "no free
lunch" to "the lunch costs a provenance model." Noted; deliberately out of scope for v1 to keep the
curve clean (see §10).

## 3. The instrument — the read-depth ladder

Five points on a single read-depth axis. Two are anchors that already exist; the three in the
middle constitute "Light Skeptic v2" as a family. **Detection is non-decreasing up the ladder**
(tiers 1→2 *add* rules; tier 3 *refines* tier 2's matching rather than adding rules), so Y is
monotone by construction and X is the quantity we actually measure. Tier 3 can buy back robustness
without losing detection.

| # | Tier | Reads | Build? | Predicted susceptibility (X) | Predicted detection (Y) |
|---|------|-------|--------|------------------------------|-------------------------|
| 0 | `v1` field-only | which keys exist | exists | ~0 (invariant) | low — blind to string-borne attacks |
| 1 | `v2-structured` | typed values (bool/int/enum) + fields | **new** | ~0 (a bool can't be paraphrased) | med — but *trusts* attacker-set structured facts |
| 2 | `v2-lexical` | string values via raw regex/keyword | **new** | med–high (evadable by paraphrase) | med–high |
| 3 | `v2-canonical` | tier-2 rules with normalize-then-match (case/path/synonym-lite) | **new** | med (partial recovery) | high |
| 4 | `LLM` semantic | string values by meaning | fresh Corpus-C run (S084 = machinery, not data) | high (drift — S084) | highest, but noisy + FP-prone |

### 3.1 The five malign-rule classes (from the V3 tribunal, Task 3)

1. High kill-chain stage activity **without** an authorization fact.
2. Executable creation in a **user-writable path**.
3. Credential-access tool / context **mismatch**.
4. **Ineffective/fake patch** claim that does not neutralize the active condition (the INJ-008 mode).
5. Post-exploitation indicators **without** a valid change record.

Rule→tier assignment is a plan-time detail (some classes are expressible at structured depth, others
require string reading). The ladder rung, not the exact rule count, is what is load-bearing. A
plan-time gate must confirm each rule is expressible against the existing evidence schema or flag the
schema extension precisely (the tribunal's open Task-3 question).

## 4. The two axes

- **X = framing-susceptibility.** Under meaning-preserving paraphrase of `fact.value`, does the
  malign verdict move? Primary metric: binary malign-classification **flip-rate** across K
  paraphrases. Secondary: magnitude drift of `malign_score`. **For tiers 1–3 this is exact — zero
  sampling noise** (deterministic code). That exactness is itself a selling point: the deterministic
  tiers need no inferential statistics at all; only the LLM anchor (tier 4) needs noise-controlled
  statistics — the noise-floor + permutation machinery S077/S084 already provide, to separate framing
  from sampling noise.
- **Y = detection power = TPR − FPR.** True-malign catch rate on the malign corpus **minus**
  false-positive rate on a **benign control set** (Youden's J). The subtraction *is* the tribunal's
  mandatory negative control: a tier that screams "malign" at everything scores Y≈0, not Y=high —
  robustness vs. rigidity, settled by construction.

### 4.1 The pre-registered hypothesis and falsifier

Plot all five tiers as (X, Y). **Pre-registered claim:** the top-left "good corner" (high detection,
low susceptibility) **stays empty**; as read-depth climbs, Y rises but X rises with it.

**Pre-registered falsifier (the honest exit):** if tier 1 or tier 3 lands *in* the good corner, the
trilemma is **false**, and we instead publish "deterministic content-robustness is achievable — here
is the recipe." Opposite punchline, equally publishable. Bands are committed *before* running.

## 5. The perturbation protocol

- **Primary: semantic paraphrase of `fact.value`** — meaning-preserving, framing-only. Reuse the
  S077/S084 operators (`generic` / `uniform` / `valence`) and their noise-floor + positive-control
  machinery (`architect_framing_metrics.py`, `architect_framing_control.py`).
- **Secondary (in scope per design decision): lexical/evasion mutation** — synonym substitution,
  path obfuscation, reordering — from the existing mutator
  (`paired_scenario_mutator{,_v2}.py`), aimed at tier 2 to demonstrate evasion specifically. This is
  what makes the *syntactic vs. semantic* distinction between tier 2 and tier 4 explicit.
- **Apples-to-apples:** the same perturbed inputs run through every tier → a common X axis.
- **Methodological gift:** the deterministic tiers read `value` directly, so they carry **no
  prose→kill-chain-stage inference** — they sidestep the "hidden coupling" the V4 tribunal flagged as
  making the Architect-path measurement suspect. Only the LLM anchor carries that coupling, and S084
  already controls for it. The ladder is *cleaner* than the Architect-path measurement.

## 6. Adaptive Corpus C — and the tribunal's open wound, closed

- **Job:** guarantee coverage of injection **classes whose malign signal lives in the `value`** (the
  five classes in §3.1) — otherwise detection-gain is unmeasurable, because v1 cannot be beaten on
  signals that are not present.
- **[SUPERSEDED by Phase B (S087): the strategy below was reversed — Corpus C is a purpose-built set of 8 fresh `RDF-*` scenarios with zero overlap with `injection_registry_v3`, not a reuse of v3. Design-time text retained for traceability.]**
- **Strategy (minimal authoring):** reuse `injection_registry_v3.py` (33 scenarios) as the base;
  audit it for class coverage; author targeted additions **only** where a class is bare. Add **benign
  twins** (same structured skeleton, benign value) as the FP/negative-control set, and a **positive
  control** (a structural change that *should* flip the verdict — e.g., injecting a genuine
  authorization fact into a malign scenario, so a non-inert tier must swing toward benign) to prove
  the tiers are not inert.
- **The rule-satisfaction-oracle resolution:** we author scenarios around real, observable injection
  **classes** (MITRE-anchored), *not* "scenarios that satisfy the four rules." The independent
  oracle is **paraphrase-invariance** (does framing move the verdict?), not the author's intuition.
  This converts the tribunal's circular "author-against-rules" (which tests author understanding)
  into a legitimate "author-against-classes." It is the principled answer they said was *still owed*.

## 7. Architecture constraints (non-negotiable, per CLAUDE.md)

- Tiers 1–3 are **peer modules** to `light_skeptic.py` (the "peers, not wrappers" pattern), each a
  pure-Python, deterministic, zero-LLM, zero-network rule engine. Importing `anthropic` inside them
  is a tested failure condition (mirroring the v1 anchor test).
- **Frozen dataclasses** for all outputs; reuse/extend `LightSkepticJudgment`
  (`light_skeptic_judgment.py`) — `malign_score` is already in the schema, currently dead-wired at
  0.0; v2 populates it.
- **New files only.** `light_skeptic.py` and its anchor test (`light_skeptic.py:185`) remain
  byte-stable so Paper 2 / S060 reproduce on HEAD.
- **Zero regressions**; squash-merge to main only after the full suite passes.
- Measurement reuses `leakage_runner._run_one_cycle` where the LLM anchor is involved, for
  apples-to-apples with prior numbers.

## 8. Component / file plan (indicative — finalized in writing-plans)

- `ares/dialectic/agents/light_skeptic_v2_structured.py` — tier 1 engine.
- `ares/dialectic/agents/light_skeptic_v2_lexical.py` — tier 2 engine.
- `ares/dialectic/agents/light_skeptic_v2_canonical.py` — tier 3 engine (normalize-then-match).
  (Exact module factoring — three files vs. one tiered module with a depth parameter — is a
  plan-time call; the constraint is that each tier is independently testable.)
- `ares/dialectic/measurement/read_depth_frontier_schema.py` — frozen result types (per-tier X/Y,
  per-scenario records, frontier summary).
- `ares/dialectic/measurement/read_depth_frontier_runner.py` — offline runner for tiers 0–3; LLM
  anchor via a fresh full Corpus-C run (not an S084 reuse/top-up; see §9).
- `ares/dialectic/measurement/read_depth_frontier_report.py` — markdown + frontier-coordinate
  emitter (feeds the eventual visual-companion plot).
- Corpus C additions alongside the existing registries (new file; v3 untouched).
- Tests: per-tier rule unit tests, anchor tests (no-LLM, no-network), schema/contract tests,
  byte-stability guard on v1.
- Pre-registration doc committed **before** the live tier-4 run.

## 9. Feasibility, cost, reuse

- Tiers 1–3 and the entire X/Y measurement for tiers 0–3 are **offline, deterministic, free**.
- **Honest cost driver:** the LLM anchor (tier 4) costs API proportional to `|Corpus C| × K`.
  **Correction (post-Phase-B, S087): this is a fresh, full Corpus-C run — *not* a reuse or "top-up" of S084.** Phase B replaced the "reuse `injection_registry_v3` as the base" plan with a purpose-built **Adaptive Corpus C** (8 fresh `RDF-*` scenarios). S084's run (`20260605-194137-713674`) measured 17 `INJ-*` scenarios from `injection_registry_v3` — **zero overlap** with Corpus C's `RDF-*` set — and carries **no benign control stratum**, so the frontier Y = TPR − FPR is *underivable* from it. **S084's legitimate residual role:** an out-of-corpus drift anchor, plus reuse of its framing operators and noise-floor/positive-control machinery (`architect_framing_{metrics,control}.py`) — *not* a source of tier-4 (X, Y) coordinates. **Estimated cost:** ~$7-12 for a full fresh Corpus-C anchor run (≈ $0.0144/cycle at S084's unit cost; Corpus C packets are smaller — 2-3 facts vs. ~6 for INJ — so the lower end is likely);
  bound it under a project cost ceiling (precedent: S082/S084 ran ~$24–25 at $40 cap).
  Claim is "the novel deterministic contribution is free; the baseline anchor is the only meter."
- Rough shape: LS v2 build ≈ 2–3 sessions; Corpus C + harness + measurement + report ≈ 2–3 sessions;
  interleavable. (Research estimates, not commitments.)

## 10. Out of scope (YAGNI)

- Provenance-gated reading (the §2 escape hatch) — a second axis; future work.
- Wiring v2 into the production cycle — this is a measurement study; production cutover is separate
  (cf. S078→S079 pattern) and only warranted if a tier proves itself.
- Adversarial co-evolution to equilibrium (the rejected "Approach 3") — Corpus C is authored once
  against classes, not iteratively hardened against the rules.
- Multi-model sweep of the deterministic tiers — they are model-independent by construction; only the
  LLM anchor has a model, and one family suffices for v1.

## 11. Paper placement and reviewer risk

- **Paper 2 → 4:** Paper 2 said the deterministic skeptic *matches* the LLM; Paper 4 says *why*
  (because blind) and *prices the un-blinding*.
- **Paper 3 → 4:** Paper 3 measured explanation drift in the LLM agents; Paper 4 asks whether
  determinism cures it (do the tiers' cited-fact sets stay stable under paraphrase?) — a
  deterministic counterpoint on the same axis.
- **Spine line:** *"LLM proposes, deterministic code disposes — but determinism relocates the attack
  to data-integrity, it does not remove it."* Paper 2's fifth observation, proven with a measured
  frontier.
- Default: **standalone Paper 4** (Paper 3 is frozen and on the 2026-07-24 clock).
- **Reviewer-risk flag (must be load-bearing in the framing):** the nearest critique is "isn't this
  Paper 2 again?" The defense is the *frontier itself*, the deterministic-exactness, and the Paper-3
  drift tie-in. If those three do not carry, the finding reads as a victory lap. Design to make them
  carry.

## 12. Decisions locked during brainstorming (2026-06-07)

- Goal: **publishable finding**.
- Finding-shape: **robustness frontier** (read-depth spectrum).
- Approach: **read-depth ladder** (trace the curve), not three-point MVP, not adversarial
  co-evolution.
- Ladder: **5 points** (v1 / structured / lexical / canonical / LLM) — confirmed.
- Y axis: **detection − FP** (single composite), not a 3D detection/FP split — confirmed.
- Perturbation: **both families** — semantic paraphrase (primary) + lexical-evasion (in scope).
- Corpus: **RESOLVED in Phase B (S087) → fuller fresh corpus** (Adaptive Corpus C, 8 `RDF-*`, zero overlap with v3). Design-time note: **minimal authoring** was *assumed* (reuse v3 + patch bare classes); the fuller fresh corpus
  available if the author prefers — *flagged for final confirmation*.

## 13. Success criteria

- Three deterministic v2 tiers built, each independently tested, each zero-LLM/zero-network, with v1
  byte-stable and zero regressions.
- A pre-registered frontier (bands + falsifier) committed before the live anchor run.
- A measured (X, Y) coordinate for all five tiers on Corpus C, with negative + positive controls.
- A verdict: trilemma **supported** (good corner empty) or **falsified** (a deterministic tier in
  the corner) — either way, a clean, calibrated, publishable result.

## 14. Implementation phasing (note for writing-plans)

This design is one coherent finding but a **multi-session arc**; the plan should be phased, and each
phase is its own session-branch + squash-merge:

- **Phase A — Light Skeptic v2 tiers (Step 4).** Build tiers 1–3 as deterministic peer modules with
  full unit/anchor tests. Entirely offline/free, self-contained, zero API. *This is the first
  executable unit and the natural first plan* — it de-risks the whole arc before any spend or corpus
  authoring, and is independently valuable even if the measurement is deferred.
- **Phase B — Adaptive Corpus C + perturbation harness (Step 3).** Author class-coverage additions +
  benign twins + positive control; wire the offline measurement runner for tiers 0–3.
- **Phase C — Pre-registration + LLM anchor + frontier report.** Commit bands/falsifier, run the
  fresh full Corpus-C tier-4 run (~$7-12, the only metered step; not an S084 reuse — see §9), emit the (X, Y) coordinates + report.

Writing-plans should scope to **Phase A first**, not attempt all three phases in one plan.
