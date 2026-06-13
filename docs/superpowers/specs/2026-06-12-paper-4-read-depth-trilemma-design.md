# Paper 4 Design — The Read-Depth Robustness Trilemma

**Date:** 2026-06-12
**Build session:** S092 (design only; build is a later session)
**Status:** DESIGN — brainstorming output, pending user review then writing-plans
**Author:** Daniel Gmys-Casiano (Skyframe Innovations)
**Venue:** TBD peer venue (AISec-family / security workshop or journal); **not** co-submitted with Paper 3 to the 2026-07-24 AISec slot. Build retains the Paper 3 acmart-sigconf pipeline so a venue switch is cheap.
**Evidence base:** Read-Depth Robustness Frontier, Phases A–E (Sessions S086–S090) + the S091 generator-cost fix. **No new measurement** — written entirely from closed artifacts.

---

## 0. In Plain Terms (layman's version — becomes the paper's plain-language anchor)

**The setup.** ARES reads a threat report and decides "is this a real attack or not?" Our earlier papers found a trap: if you let an AI do the reading, a clever attacker can *reword* the same threat and talk the AI out of the truth (or into a false alarm). The fix was to pull the AI out of the reading seat and replace it with a dumb, deterministic checker — fixed rules, no AI, so rewording cannot talk it out of anything. That worked for stability, but it bought a new problem: a dumb checker cannot read very deeply. It either misses subtle threats, or it "catches" them only by pattern-matching on surface structure the attacker himself controls.

**The question this paper asks.** Can we make the dumb checker smarter — give it eyes, let it read more deeply — without dragging the rewording weakness back in?

**What we did.** We built a ladder of checkers, from "barely reads anything" at the bottom up to "full AI reads by meaning" at the top. Then we measured every rung on three things at once: (1) does it actually catch real threats, (2) can it be fooled by a reworded threat, and (3) does it stay honest or does it just trust whatever structure the attacker baked into the data. And — the part that makes it credible — we wrote down the bet *before* running it: you cannot get all three at once. Pre-registering the bet means we cannot quietly move the goalposts after seeing the data.

**What happened.** The bet held. The smartest reader (the AI) caught the most threats but got talked out of a correct verdict by a single reworded sentence. The dumb readers resist rewording but either miss too much or cry wolf by trusting attacker structure. One dumb checker looked like it beat the trap — caught threats and shrugged off rewording. But we had flagged in advance that it might only resist the specific disguises it was built to undo. So we turned an AI adversary loose to invent brand-new disguises it had never seen. It beat that checker on 2 of 4 cases, proving its resistance was partly just blindness. Tellingly, it could not beat the cases that hinge on a named tool ("lsass", "procdump") — you cannot disguise those away and still mean them.

**The credibility seal.** Then the obvious worry: maybe the AI judge that ruled "yes, these disguises still mean the same threat" was just being a pushover. So we brought in two other labs' models — GPT-4o and Gemini — as independent judges, with calibration checks (do they correctly call obviously-harmless things harmless?). They agreed: the disguises are real threats, not a lenient-judge artifact.

**The one-line takeaway.** Removing the AI did not remove the attack — it relocated it. And climbing back toward smart reading re-opens the door. That tension is fundamental, not a bug you can patch. It is the ARES thesis, now measured on a ladder and stress-tested by an adversary.

---

## 1. Thesis and claim register

**Thesis (one sentence).** Giving a deterministic security verifier deeper reading so it detects more threats forces it to re-acquire *either* the framing vulnerability it was deployed to escape *or* a dependence on attacker-controllable structure — and empirically, across a five-rung read-depth ladder on a pre-registered adversarial corpus, no rung is simultaneously deep-reading, framing-robust, and data-integrity-clean; the lone apparent exception is defeated by a blind out-of-vocabulary adversary, and that defeat is independently corroborated by two judge families.

**Claim register (the honesty boundary — stated in §1 and §10 of the paper).** This is an *empirical, pre-registered frontier result*, not an impossibility proof. We claim the good corner is empty **as measured under the frozen bands**, on **Adaptive Corpus C** (8 scenarios), across **this** five-rung ladder, with the pipeline on one base-model family and a single OOV adversary model. "Trilemma" is the organizing claim, not a theorem. Pre-registration (bands frozen *before* the tier-4 run) is what converts the empty corner from curve-fit to credible.

## 2. The three properties (operationalized)

| Leg | Property | Metric | Frozen band |
|---|---|---|---|
| P1 | **Detection** (the payoff of reading deeper) | Youden's *J* = TPR − FPR, malign scenarios vs benign twins | high detection = **cumulative *J* ≥ 0.50** |
| P2 | **Framing-robustness** (survives meaning-preserving rewording) | *X*_sem = noise-gated majority-flip-rate under framing operators (permutation *p* < 0.05 gate); **extended by** *X*_lex / OOV-evadability (the S089 adversarial probe) | framing-robust = ***X*_sem ≤ 0.10** |
| P3 | **Data-integrity** (does not blindly trust attacker-structured data) | FPR-inheritance on the **cumulative** view: stacking readers inherits the worst component FPR | encoded *into* P1's cumulative-*J* penalty |

**Honesty nuance (stated explicitly, not hidden).** The frontier is plotted in **two axes** (*X*_sem × cumulative-*J*), and P3 is **baked into** the cumulative-*J* penalty — the structural tier's FPR = 0.75 caps the whole stack at *J* = 0.25. So "trilemma" = three properties, operationalized as a two-axis frontier where the third manifests as the cumulative cap. This is exactly what the Phase-C pre-registration says.

## 3. Contributions (numbered, Paper-3 style)

1. **The frontier + trilemma result** — a pre-registered 5-rung read-depth robustness frontier; the good corner is empty under frozen bands (S088, *SUPPORTED*).
2. **Adversarial refutation of the lone escape** — a blind OOV LLM adversary defeats deterministic canonicalization on 2/4 malign string scenarios; named-IOC matching resists, structural/synonym matching falls; white-box ≈ black-box (S089, *SUPPORTED_STRONG*).
3. **Independent-judge audit + reusable method (secondary)** — GPT-4o + Gemini with calibration controls corroborate the evasions are meaning-preserving threats, not lenient-judge artifacts (S090, *ROBUST*); and the "pre-registered frontier + LLM-proposes / code-disposes + independent audit" recipe as a transferable methodological contribution.

## 4. Structural approach

**Frontier-first + embedded refute** (chosen over a pure falsification-narrative and a two-act result-then-method). Conventional empirical shape — thesis, ladder + axes, pre-registered bands, measure all rungs (empty corner) — with the "candidate-defense-then-refute" device (`v2_canonical` → OOV → audit) living *inside* the Results sequence (§§5–7) where it is most dramatic. Reviewer-friendly skeleton; preserves the "we adversarially attacked our own best case" honesty. Method is its own short section (§8) plus a Discussion thread, matching the secondary-contribution weighting.

## 5. Section skeleton (target ~9.4k core words)

| § | Section | ~words | Role / key evidence | Bibkeys |
|---|---|---:|---|---|
| — | **Abstract** | 250 | Problem → counter-move → trilemma → 3 findings → reproducibility | self-cites |
| 1 | **Introduction** | 600 | Deterministic verifiers escape framing but go shallow; "read deeper?"; trilemma thesis; 3 contributions; roadmap | greshake-2023, guo-2024, Papers 1–3 |
| 2 | **Background** | 750 | Framing/indirect injection; multi-agent LLM; deterministic vs LLM verification; robustness frontiers + pre-registration in ML eval; OOV/evasion in detectors | greshake-2023, guo-2024, jacovi-goldberg-2020, +new |
| 3 | **The ARES Verifier and the Read-Depth Ladder** | 700 | Compress ARES pipeline (cite P2/P3); Light Skeptic; define the 5 rungs (v1_field → v2_structured → v2_lexical → v2_canonical → llm_semantic) — the object of study | gmys-casiano self-cites |
| 4 | **Methodology: A Pre-Registered Frontier** | 1200 | Adaptive Corpus C (8 scenarios + twins + controls); the P1/P2/P3 metrics; standalone vs cumulative views; frozen bands; decision rule (good corner). Subsections 4.1–4.5 | +new (pre-registration) |
| 5 | **Finding 1: The Good Corner Is Empty** | 1100 | Tier-4 live (S088): cumulative all rungs cap at *J* = 0.25; standalone contrast; LLM framing-flip *p* = 0.001; FPR-inheritance = the data-integrity leg. Ends by naming the lone escape → motivates §6 | — |
| 6 | **Finding 2: The Lone Escape Is Adversarially Defeated** *(load-bearing)* | 1400 | OOV generator (LLM-proposes / code-disposes); skeleton + novelty gate; black/white arms; canonical evaded 2/4; named-IOC resists; white ≈ black (S089). Subsections 6.1–6.5 | — |
| 7 | **Finding 3: Independent-Judge Audit** | 900 | Leniency threat; GPT-4o + Gemini panel; calibration controls; 15/18 both-confirmed, 3 splits at the meaning-dilution frontier; "both-independents" rule; ROBUST (S090) | — |
| 8 | **The Method as a Contribution** *(secondary)* | 550 | Generalize the recipe: pre-registered bands + LLM-proposes/code-disposes + independent audit w/ calibration. *(Open choice: could fold into §9 for strict Paper-3 parallelism.)* | — |
| 9 | **Discussion** | 1000 | The relocation thesis (ties to P1–P3 and Papers 1–3); not all deterministic rules equal (named-IOC vs structural/synonym); production verifier design; the honesty dividend of pre-registration | berdoz-rugli-wattenhofer-2026, self-cites |
| 10 | **Limitations** | 500 | 1 corpus / N=4 malign; single pipeline model family; single OOV adversary; SYN-001 has no benign twin; 2-axis op-of-3-property claim; "trilemma" is empirical, not a theorem | — |
| 11 | **Future Work** | 400 | Benign synonym-class twin; 2nd/3rd OOV adversary; larger corpus; other domains; named-IOC + semantic reading as a candidate corner-occupant | — |
| 12 | **References** | — | verified-only bib | — |
| — | *Appendix: Generative AI Use Declaration* | — | house pattern | — |

**Open choice flagged:** §8 standalone vs folded into §9. Default = standalone short section (signals contribution #3 clearly). Revisit at skeleton-build time.

## 6. Evidence-to-claim map (data provenance + pre-registered numbers)

Every load-bearing number is locked to a closed artifact and surfaced by `number_check` (mirrors Paper 3 discipline). Source notes: `docs/paper_4/S088_*`, `S089_*`, `S090_*`; data under `data/paper_4/read_depth_frontier/` and `data/paper_4/read_depth_oov/`.

**S088 (Finding 1):** cumulative *J* = 0.25 (all rungs, the cap); standalone *J* = 0/0.25/0.50/0.75/0.75 across the ladder; LLM *X*_sem = 0.125 [0.00, 0.38]; LLM TPR = 0.75, FPR = 0.00; `RDF-M-SYN-001` framing flip baseline 1.00 → 0.45, permutation *p* = 0.001; Corpus C digest `9401b7188ba790a5`; Sonnet 4, K = 20; spend \$3.23.

**S089 (Finding 2):** black + white arms, K = 8, 32 candidates/arm; canonical evaded `RDF-M-LEX-002` + `RDF-M-SYN-001` (2/4); adversarial *X* (scenario) = 0.500; per-candidate flip 0.344 (black) / 0.312 (white); named-IOC scenarios `RDF-M-LEX-001` + `RDF-M-PATCH-001` (lsass/procdump) zero flips both arms; OOV corpus `9900b91f707e2ef8`; spend \$0.1104.

**S090 (Finding 3):** verdict re-run reproduced SUPPORTED_STRONG (\$0.106, run-2 OOV corpus `a4ea1d0645152ffa`); independent audit ROBUST (\$0.0093); 18 evading disguises — 15 both-confirmed, 3 split (GPT-4o benign / Gemini + Sonnet malign); 4/4 calibration controls pass; GPT-4o is the stricter judge; total live spend \$0.115.

## 7. Figures and tables (proposed)

- **fig_1** — the read-depth ladder (5 rungs), conceptual diagram. *(host §3)*
- **fig_2** — THE money figure: the frontier plotted in 2 axes (*X*_sem × *J*), standalone vs cumulative panels, good-corner box drawn empty. *(host §5)*
- **fig_3** — OOV evasion result: per-scenario canonical flips (LEX-002 + SYN-001 evaded; LEX-001 + PATCH-001 resist), black vs white arms. *(host §6)*
- **fig_4** — the audit: calibration controls pass + 15/18 both-confirmed / 3 split, GPT-4o vs Gemini vs Sonnet. *(host §7)*
- **fig_5** — the method recipe: LLM-proposes/code-disposes pipeline (generate → skeleton+novelty gate → judge → verdict; + independent-audit panel). *(host §8)*
- **fig_6** *(optional)* — a worked OOV disguise (RDF-M-SYN-001 original vs evading disguise; what canonical matched vs missed), snippet style. *(host §6)*
- **tbl_1** — Adaptive Corpus C composition (8 scenarios: malign string + benign twins + controls). *(host §4)*
- **tbl_2** — frontier coordinates per rung (*X*_sem, TPR, FPR, *J*) in both views — the S088 result. *(host §5)*
- **tbl_3** — OOV per-arm summary (S089). *(host §6)*
- **tbl_4** — evading disguises + per-judge verdicts (S090). *(host §7)*

Renderer mirrors `docs/paper_3/build_figures.py` (matplotlib, `pdf.fonttype = 42` TrueType to avoid ACM-disliked Type 3).

## 8. Verification gates (build-time tests; mirror Paper 3)

- **Skeleton audit** — `tests/paper_4/test_skeleton_audit.py` over `docs/paper_4/skeleton_v1_0.json` (structural completeness, section order, claim/number presence).
- **Citation existence** — `tests/paper_4/test_citation_existence.py`: every `bibkeys_required` exists in a **verified-only** `docs/paper_4/references.bib`; unverified keys tracked in the skeleton JSON, never as bib placeholders (the Sabet-hallucination lesson).
- **Number-check** — `docs/paper_4/number_check.py` + `tests/paper_4/test_number_check.py`: lock the S088/S089/S090 figures listed in §6 against source notes + prose substrings.
- **PDF substring gate** — `docs/paper_4/.../verify_pdf_substrings.py`: pdftotext the built acmart PDF, assert the load-bearing substrings render.

## 9. Code-reality anchors (mostly already exist)

Unlike Paper 3 (which authored new anchor tests during the paper session), Paper 4's instruments are **already locked** from S086–S091. The paper cites tests that exist:

- Frozen-bands SSOT guards — `tests/paper_4/test_prereg_bands_match_code.py`, `test_oov_prereg_bands_match_code.py`, `test_oov_audit_prereg_bands_match_code.py`.
- OOV no-network + novelty/skeleton invariants — `tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py`, `..._validator.py`.
- Audit "both-independents" invariant — `CONFIRM_REQUIRES_BOTH_INDEPENDENTS` in `read_depth_oov_audit.py` (+ its tests).
- Ladder rung registry — `light_skeptic_v2_ladder.py` `DETERMINISTIC_TIERS` / `LADDER_ORDER` (+ tests).

**New anchors needed (if any):** likely none beyond a thin "skeleton claims map to existing anchors" cross-check. Confirm at build.

## 10. Bibliography plan

- **Reuse (verified, from Paper 3):** greshake-2023, guo-2024, jacovi-goldberg-2020, reiter-1978, berdoz-rugli-wattenhofer-2026.
- **Self-cites:** Papers 1, 2, 3. **Build detail:** Paper 4's bib needs disambiguated self-cite keys (Paper 3 reused `gmys-casiano-2026` for Paper 2 only; Paper 4 cites three prior works). Plan distinct keys (e.g. `gmys-casiano-2026a/b/c` or per-title keys) and verify round-trip through `extract_citations` / `citation_to_bibkey`.
- **New, to verify during build (never placeholder):** pre-registration / open-science in ML eval; adversarial evasion of ML detectors (OOD / evasion-attack canonical cite); robustness-frontier or detector-evasion prior art. Tracked in skeleton JSON `bibkeys_needed_unverified` until web-verified.

## 11. Scope cut (this session vs future)

- **This session (S092):** this design spec → review → implementation plan (writing-plans). **No prose, no skeleton JSON, no figures** — same cut as Paper 3 Session 064.
- **Build sessions (later):** generate `skeleton_v1_0.json` + verification gates + `references.bib` (verify new keys) + figures, then prose to feature-complete, then acmart build + PDF gates.
- **Explicitly out of scope:** any new measurement run. The result is closed at S086–S090. The benign synonym-class twin and a second OOV adversary are *Future Work*, not blockers.

## 12. Limitations (carried verbatim into §10 of the paper)

- Single corpus (Adaptive Corpus C); N = 4 malign string scenarios — small.
- Single base-model family for the pipeline (Sonnet 4); cross-model generalization untested for the frontier.
- Single OOV adversary model (Sonnet); a second adversary family would strengthen the evasion claim.
- `RDF-M-SYN-001` has no same-skeleton benign twin in Corpus C; its leniency control leans on the generic clean baseline (slightly weaker for the synonym class).
- The 3-property claim is operationalized on a 2-axis frontier (P3 enters via the cumulative cap), not three independent axes.
- "Trilemma" is an empirical, pre-registered frontier result on this setup — not a proven impossibility.

## 13. Open choices / notes

- Final title pick among the three candidates (lead: *Reading Deeper Re-Acquires the Attack: A Pre-Registered Read-Depth Robustness Trilemma for Deterministic Threat Verifiers*).
- §8 standalone vs folded into Discussion.
- Venue selection (deferred; build stays acmart-portable).
- Pending housekeeping to fold into this branch at session close: CLAUDE.md Branch-section squash records for S090 (`92cc0e6`, `0814e27`) + S091 (`bd72bdb`), and an S091 ledger line.
