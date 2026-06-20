# ARES-Harness: Deterministic Injection Defense for a Tool-Using Agent — Design Spec

**Date:** 2026-06-20
**Session:** 096 (first numbered research session after S095)
**Status:** Design approved by Dan 2026-06-20; spec under review before writing-plans.
**Branch:** `session/096-ares-harness-design`

> **North Star (Dan, 2026-06-20):** *find a way to protect ourselves — the agent — and our harness against prompt injection.* This arc reframes ARES's defense machinery from "protect ARES's own threat-analysis verdict" to "protect a tool-using agent harness against indirect prompt injection."

---

## 1. Context & motivation

ARES's V4 Tribunal roadmap (Steps 0–5) and the read-depth robustness frontier (S086–S090, Paper 4) are **closed**. The pre-validated roadmap is exhausted; the next research direction is open. Dan set the North Star to harness-protection.

A deep code-grounded scout (S096 exploration workflow, 5 readers + synthesis + adversarial critic) surfaced three load-bearing facts:

1. **We have a real, code-verified hole.** The "blessed" production entrypoint `run_production_cycle` (`production_cycle.py:41`) wraps `run_cycle_with_strategies`, **not** `run_guarded_cycle` — so it runs **neither the firewall nor hot-swap**, only the citation sanitizer. And even the firewall, when run, scans only facts the Architect *cites* (`firewall.py:251`) — an uncited poisoned fact is never inspected (this is why demo INJ-001 cannot fire). Today the production path has no syntactic injection gate by default.
2. **The read-depth result hands us one genuinely robust mechanism.** OOV experiments (S089/S090, independently audited ROBUST) found a clean asymmetry: **named-IOC matching** (`lsass`/`procdump`) resisted *every* meaning-preserving evasion in both arms, while structural/synonym/canonical matching was evaded on 2/4. White-box ≈ black-box, so evadability is intrinsic to the *rule type*, not secrecy.
3. **ARES's genuinely novel angle is the conclusion/decision-integrity surface.** The entire published SOTA (CaMeL, dual-LLM, spotlighting, instruction-hierarchy, StruQ, SecAlign, IFC) guards the **action surface**. ARES's deterministic-verifier + evidence-binding angle targets whether the *decision/conclusion* survives poisoned-but-authorized data — an under-explored axis. The regex firewall + IOC lexicon themselves are **not** novel (Rebuff/Sigma/YARA class); the novelty is the *combination* and the *target*.

The critic's sharpest point: every ARES result to date was measured on ARES's own threat-analysis corpus, **never on a real tool-using-agent injection surface**. Without an external-benchmark anchor (AgentDojo / InjecAgent / BIPIA), any "we protect the harness" claim is asserted, not demonstrated.

## 2. Goal & success criteria

Build **and measure** a deterministic injection-defense layer for a tool-using agent — a real hardened harness *and* a publishable result (Paper 5).

Success =
- A composable, default-on **ARES-Harness middleware + deterministic action-authorization gate** that an integrator can wrap around a tool-using agent.
- A **pre-registered, benchmark-anchored measurement** showing attack-success-rate (ASR) under the defense vs an undefended baseline, plus a benign-utility / false-block cost, on a standard indirect-injection benchmark.
- An **extension metric** (conclusion-integrity) that the standard benchmarks do not score — ARES's novelty.
- Honest scoping: the deterministic scan is a syntactic pre-filter; the *guarantee* is provenance isolation + the deterministic gate, framed explicitly against CaMeL/dual-LLM as the decision-integrity axis.

## 3. Threat model

- **Defender:** a tool-using agent harness that ingests untrusted content (tool outputs, web pages, file contents, MCP results) into its reasoning context and emits tool calls.
- **Attacker:** controls the *content* of an untrusted source (indirect / second-order prompt injection). The payload is provenance-valid and (if hashed) hash-valid — integrity ≠ trust. The attacker's goal is to (a) trigger an unauthorized/harmful tool call, or (b) corrupt the agent's final decision/answer.
- **In scope:** indirect injection via untrusted tool/web/file/MCP content; literal injection strings; meaning-preserving (paraphrase/OOV) evasions of deterministic detectors; provenance-blind trust.
- **Out of scope (named, not solved):** semantic framing with no detectable signature (the read-depth trilemma says deterministic deep-reading cannot close this — we isolate by provenance + gate instead of trying to detect it); attacks on the model weights / training; supply-chain compromise of the tools themselves.

## 4. Locked decisions (brainstorm, 2026-06-20)

1. **Arc goal:** both, sequenced — harden the harness *and* publish (defense + Paper 5).
2. **Threat surface:** generic tool-using agent, anchored to a standard indirect-injection benchmark (AgentDojo or InjecAgent), extended with ARES's conclusion-integrity measure.
3. **Defense scope:** full stack — the ARES-Harness middleware *and* the deterministic, LLM-free action-authorization gate (the novel core).
4. **Sequencing:** Approach A — spike-gated spine-first. Feasibility spike + undefended baseline gates the arc; build offline/$0; a single gated live run (≤ $25, Dan-triggered, ARES-style hard cap).
5. **Architecture constraints (ARES non-negotiables):** new peer entrypoint, existing cycles untouched, leaky measurement default kept **byte-identical** (Paper-3/4 reproducibility); frozen dataclasses; the action gate is deterministic Python with **no LLM, ever**.

## 5. Architecture

A middleware sits between untrusted content sources and the agent's reasoning context; a deterministic gate sits between the agent's proposed actions and execution. Five deterministic, ARES-ported stages plus the agent (the only LLM in the trusted path):

```
UNTRUSTED INPUT PATH
  Untrusted sources (tool·web·file·MCP)
    → ① Capture (freeze · SHA256 · SourceType trust label)
    → ② Ingress scan (normalize → fail-on-any literal-injection scan over ALL content)
        ↑ ④ named-IOC rung feeds the scan (OOV-evasion-resistant detector)
    → ③ Quarantine (inert-render by trust; redact span + hot-swap on a hit)
    → AGENT (reasons over sanitized, inert, provenance-tagged data)

ACTION PATH
  Agent proposes call (action·args)
    → ⑤ Action gate ((action, args, arg-provenance) → allow/deny; deterministic, NO LLM)
    → Execute ✓  |  Deny ✕
```

The load-bearing subtlety: untrusted content is rendered **inert by provenance** (control-data separation) before the agent reads it, and the agent's output is gated on **code-checkable facts** (action, args, arg-provenance) — never on the model's free-text justification. The injection can reach the agent's eyes as quoted data; it cannot reach the decision.

## 6. Components — peer modules, frozen dataclasses

All new files under a new `harness/` package (exact path TBD in plan; sibling to existing `ares/dialectic/...`). None edit existing cycles.

| Module | Role | Ports / reuses |
|---|---|---|
| `capture.py` | `CapturedRecord` — frozen, SHA256-hashed, `SourceType`-tagged wrapper for any tool/web/file/MCP output | `EvidencePacket.freeze` (`packet.py:151-182`), `Provenance` (`provenance.py:13-48`) |
| `ingress_scan.py` | Normalization (NFKC fold, homoglyph map, zero-width/whitespace strip, leetspeak) **then** fail-on-any literal-injection scan over *all* captured content (not just cited) | the real `OracleFirewall` via the `scan_raw_text` path (`firewall_arena.py:270-289`) |
| `ioc_anchor.py` | First-class named-IOC detector — anchors on indicator specificity (the only family that survived OOV evasion, S089/S090); coverage-audited | `_CRED_TOOLING` lexicon promoted out of `light_skeptic_v2_lexical.py:45-49` |
| `quarantine.py` | Provenance-conditioned **inert rendering** of untrusted content + span redaction + **hot-swap-with-data-quarantine** (redact the offending bytes at the record, then respawn) | `firewall.sanitize` (`firewall.py:307-353`), `guarded_cycle` hot-swap (`guarded_cycle.py:227-314`) |
| `action_gate.py` | **The novel core.** Deterministic, LLM-free `authorize(action, args, arg_provenance) → Decision`. See §7. | conceptual analogue of `OracleJudge` (`oracle.py`, "no LLM, ever") |
| `middleware.py` | The single default-on hardened entrypoint composing ①–⑤; emits a structured `HarnessTrace` (auditable, like the arena's `ArenaTrace`) | new peer, modeled on `run_production_cycle` |
| `adapters/<bench>.py` | Binds the middleware into the chosen benchmark's agent loop | — |

## 7. The action-authorization gate (the risky novel piece — detailed)

The gate is the contribution that distinguishes ARES from regex-filter SOTA. It must be deterministic, pure, frozen-dataclass, and **never consult model-produced text**.

**Inputs:** the proposed `(action, args)` plus, for each argument, the **provenance** of the data it was derived from (carried forward from `CapturedRecord` through the agent — the agent must surface which captured records informed each arg; where it cannot, the arg is treated as untrusted-derived by default — fail-safe).

**Policy model — taint propagation + capability classes:**
- Each tool/action is assigned a **capability class** at registration: `READ_ONLY` (safe), `WRITE_LOCAL`, `IRREVERSIBLE` (delete, overwrite), `EXFIL_SHAPED` (send-external, network egress, post). (Class assignment is config, not model-decided.)
- An argument is **tainted** if any captured record it derives from has an untrusted `SourceType` (web / UNKNOWN / external).
- **Decision rule (deterministic):**
  - `READ_ONLY` → allow regardless of taint.
  - `WRITE_LOCAL` / `IRREVERSIBLE` / `EXFIL_SHAPED` with a tainted arg → **deny** (or escalate to human-confirm if an escalation hook is wired) — an untrusted source must not be able to choose the target of a privileged action.
  - Same classes with only trusted args → allow.
- The rule is **monotone in taint** (more taint never loosens the decision) and depends only on `(class, taint-of-args)` — both code-checkable — so it cannot be argued out of its decision by injected text.

**Why this is the novel bit:** CaMeL enforces capability/data-flow over an explicit interpreter program; ARES's gate is a lighter, single-hop, frozen-dataclass policy keyed on provenance-taint of the *arguments of an LLM-proposed call*, reusing ARES's existing provenance + deterministic-decider invariants. The defensible claim is **decision-integrity under provenance** (cite CaMeL explicitly to position, not re-derive).

**Design risks (carried to the plan):** (a) provenance-of-args plumbing — the agent must thread which records informed each arg; the fail-safe default (untrusted unless proven trusted) handles gaps but may over-deny. (b) capability-class taxonomy must be small and unambiguous. (c) over-denial is the FPR cost — measured, pre-registered.

## 8. Data flow

Untrusted source → `Capture` (record + provenance) → `Ingress scan` (normalize → fail-on-any) → [injection? → `Quarantine`: redact span + hot-swap on the sanitized record] → inert-rendered into agent context by provenance → agent proposes `(action, args)` → `Action gate` (action, args, arg-provenance) → allow → execute / deny → block. Every step appends to a structured `HarnessTrace`.

## 9. Measurement & Paper 5

- **Phase 0 spike (gates the arc):** confirm AgentDojo/InjecAgent are runnable here (Windows, Python, model backend via ARES's existing clients, license, offline-ability); capture **undefended** ASR + benign-task utility. If neither external benchmark is runnable at acceptable cost, fall back to a **faithful ARES-built testbed mapped to the benchmark's threat model** (decision recorded at spike-end).
- **Primary metric:** ASR-under-defense vs undefended baseline on tasks-with-injection (the benchmark's native action-authorization surface).
- **Extension metric (novelty):** **conclusion-integrity** — does the agent's final answer/decision stay correct under injection even when an action is attempted (a surface AgentDojo/InjecAgent do not score).
- **Cost metric:** benign-task success + **false-block rate** (the S088 FPR=0.75 ceiling predicts a fail-on-any gate bites here). The acceptable band is **pre-registered before the live run**, SSOT-guarded by a test (the read-depth frontier pattern).
- **Ablations:** turn each component off (scan / IOC / quarantine / gate) and re-measure to attribute the protection.
- **Adversarial validation:** point the existing S089 OOV adversary at the *production* `OracleFirewall` and the new IOC rung to measure their real evadable set (cheap, high-information; reuses `read_depth_oov_{generator,validator}`).
- **Budget:** build is offline/$0; one gated live run ≤ $25 (Dan-triggered, hard cap, `--confirm-live` pattern).

## 10. Invariants & constraints

- **Fail-closed everywhere:** a scan error or gate-deny blocks, never passes (the `FirewallVerdict` invariant generalized).
- **New peer entrypoint**; existing cycles untouched; the leaky measurement default stays **byte-identical** (a regression/anchor test asserts existing cycle outputs are unchanged → Paper-3/4 reproducibility mechanically guaranteed).
- Action gate is **pure, deterministic, no LLM**; all outputs frozen dataclasses.
- **Honest scoping is a first-class requirement, not a footnote:** the regex scan is a syntactic pre-filter; semantic framing remains a known miss. The paper leads with provenance-isolation + the deterministic gate as the guarantee and cites CaMeL/dual-LLM/spotlighting head-on so the contribution reads as the decision-integrity axis, not a re-derivation of guardrail filtering.

## 11. Testing strategy

- TDD per module; offline unit tests.
- **Anchor tests:** leaky-default byte-stability; action-gate determinism + monotone-in-taint; fail-on-any scan behavior; normalization round-trips; provenance-taint propagation correctness (including the fail-safe default).
- **Adversarial tests:** the S089 OOV adversary aimed at the firewall + IOC rung (evadable-set measurement).
- **Benchmark integration tests** behind a live gate (`@pytest.mark.live_llm` style).
- Zero regressions; full suite green before any squash-merge.

## 12. Phasing / decomposition

This is **multi-phase — larger than one spec→plan→session.** The spec covers the whole design; implementation decomposes, each phase its own plan:

- **Phase 0** — feasibility spike + undefended baseline (gates the arc; benchmark-runnability decision recorded).
- **Phase 1** — middleware: `capture` + `ingress_scan` + `ioc_anchor` + `quarantine` (offline/TDD/$0).
- **Phase 2** — `action_gate` + `middleware` composition (offline/TDD/$0).
- **Phase 3** — benchmark adapter + pre-registration + the gated live measurement (≤$25).
- **Phase 4** — ablations + Paper 5 build (scaffold → figures → prose → acmart, reusing the Paper 3/4 pipeline).

**The first implementation plan covers Phase 0 + Phase 1 only.** Later phases get their own plans (gated on Phase 0's runnability verdict).

## 13. Novelty positioning vs SOTA

| System | Surface guarded | ARES delta |
|---|---|---|
| CaMeL (DeepMind) | tool-call authorization via capability/IFC interpreter | ARES gate is a lighter single-hop provenance-taint policy; ARES *also* targets decision/conclusion-integrity, not just action authorization |
| Dual-LLM / quarantined-LLM (Willison) | channel separation | ARES makes provenance load-bearing on a hashed evidence record + adds the deterministic decider |
| Spotlighting / datamarking (MS) | prompt-level data marking by the same model | ARES enforces inert-rendering by provenance outside the model + a code-level gate |
| Instruction hierarchy / StruQ / SecAlign | learned, model-bound priority | ARES is verifiable deterministic code, not a learned behavior |
| Rebuff / Vigil / NeMo / IOC matching | signature filters | **Not novel** — ARES inherits their paraphrase-evadability (measured at S089); used only as the deterministic substrate, with the read-depth trilemma as the honest accounting of its limits |

**Defensible contribution:** the *combination* (deterministic verifier + evidence/provenance binding + named-IOC anchoring + hot-swap-with-data-quarantine + a deterministic action gate) and the *target* (decision-integrity for a tool-using agent), measured on a community benchmark with a pre-registered cost band.

## 14. Risks & mitigations

- **External-benchmark runnability is the load-bearing unknown** → Phase 0 spike gates the whole arc; fallback to a faithful ARES-built testbed mapped to the benchmark threat model.
- **Fail-on-any ingress scan FPR on benign tool output** (S088 FPR ceiling) → scope the fail-on-any pass to high-precision families (INSTRUCTION_INJECTION + STRUCTURAL_BREAK only); pre-register the acceptable false-block band.
- **"This is plumbing, not research"** → the action gate is a new mechanism; the benchmark anchor + conclusion-integrity metric + ablations make it an evaluated result, not a refactor.
- **Re-derivation pushback (CaMeL)** → cite head-on; frame as the orthogonal decision-integrity axis.
- **Provenance-of-args plumbing gap** → fail-safe default (untrusted unless proven trusted); measured over-denial cost.
- **Hot-swap re-poisoning** (fresh agent re-reads same bytes) → pair respawn with data-quarantine (redact at the record first) — built in by design.

## 15. Open questions (resolve in plan / at spike)

- **AgentDojo vs InjecAgent** as the primary anchor — decide at the Phase-0 spike on runnability + fit (AgentDojo = dynamic tool-use, the CaMeL/SecAlign standard; InjecAgent = lighter, indirect-injection-into-tool-agents). Recommendation pending the spike.
- Exact `harness/` package location and naming within the repo tree.
- Capability-class taxonomy granularity (start minimal: READ_ONLY / WRITE_LOCAL / IRREVERSIBLE / EXFIL_SHAPED).
- Whether Phase 0 also runs the firewall-fuzz (S089 adversary at the production firewall) or that lands in Phase 1.

## 16. References (arXiv IDs from a training-knowledge survey — VERIFY before any paper use, per ARES verified-only-bib discipline)

- Debenedetti et al., *Defeating Prompt Injections by Design* (CaMeL), arXiv 2503.18813 (2025).
- Willison, *The Dual LLM pattern* (simonwillison.net, Apr 2023).
- Hines et al., *Spotlighting* (Microsoft), arXiv 2403.14720 (2024).
- Wallace et al., *The Instruction Hierarchy* (OpenAI), arXiv 2404.13208 (2024).
- Chen et al., *StruQ*, arXiv 2402.06363 (2024); *SecAlign*, arXiv 2410.05451 (2024).
- Debenedetti et al., *AgentDojo*, arXiv 2406.13352 (NeurIPS 2024 D&B); Zhan et al., *InjecAgent*, arXiv 2403.02691; Yi et al., *BIPIA*, arXiv 2312.14197; Toyer et al., *TensorTrust*, arXiv 2311.01011.

---

*Scout artifact (S096 exploration workflow): 5 readers + synthesis + adversarial critic; run `wf_560e4ddb-278`. This spec honors the critic's central correction — anchor to an external indirect-injection benchmark and lead the paper with decision-integrity, not the regex filter.*
