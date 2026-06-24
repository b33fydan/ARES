# Session 099 — CC Prompt: ARES-Harness Phase 3 **gated live run** (AgentDojo measurement)

**Arc:** ARES-Harness (defense + Paper 5). **This session = the one gated live measurement that completes Phase 3.** Phase 4 (Paper 5) is a later, offline session.
**Prereq state:** Phase 3 *offline* build is complete, reviewed (opus whole-branch: ready-to-merge), and full-suite green (4,352 pass / 76 skip / 0 fail / 0 collection errors). Built in Session 098 via subagent-driven TDD.
**Real spend:** YES — this is the only Phase-3 session that costs money. Hard cap **$25**, gated behind `--confirm-live`. Do not run anything live until the pre-registration is frozen (see §4).

---

## 0. Starting state & branch

- **If Session 098 was closed/merged to `main`** (the offline Phase 3 squash): branch fresh from `main` →
  `git checkout main && git pull && git checkout -b session/099-ares-harness-phase-3-live`
- **If 098 is NOT yet merged**: the offline code lives on `session/098-ares-harness-phase-3` at commit **`1452a01`**. Either close 098 first (run the `ares-session-close` skill on it) or branch from `1452a01`. Prefer closing 098 first — keeps the offline build as its own clean commit on `main` (matches the S089/S090 instrument-then-live precedent).
- **bench-venv:** the live runner needs AgentDojo v1.2 / `agentdojo-0.1.35` in the isolated, gitignored `.scratch/bench-venv`. It may have been cleaned. If absent, rebuild it per `docs/paper_5/PHASE0_BENCHMARK_RUNNABILITY_2026-06-20.md` (isolated venv; this account serves only claude-4.x, so AgentDojo's frozen 3.x model enum needs the `AnthropicLLM` element-bypass + `pipe.name` shim documented there). The main venv must stay agentdojo-free (the import-isolation guard depends on it).

## 1. What Phase 3 offline already gives you (do NOT rebuild)

All under `ares/harness/` (pure-ARES, no agentdojo import) + `scripts/run_session_098.py` (the runner):

| Component | What it does |
|---|---|
| `ares/harness/provenance_tracker.py` | `derive_arg_sources(args, captured_records) -> {arg: (SourceType,...)}` — value-tracks the **raw** captured bytes; canonicalize (normalize→casefold + ws-stripped IBAN) → type-exact (iban/email/url) or containment (≥`MIN_MATCH_LENGTH`=4); no-match→`(MANUAL,)`. **Never reads a model trust label.** |
| `ares/harness/adapters/agentdojo_policy.py` | `banking_policy() -> ToolPolicy` (all 11 banking tools classified; unknown→fail-closed IRREVERSIBLE). Slack/travel policies are NOT built yet — add them the same way (see §5) if the sweep selects those suites. |
| `ares/harness/adapters/agentdojo_elements.py` | **Duck-typed, no agentdojo import.** `GateTracker` (per-task mutable sink: `.decisions`, `.raw_outputs` keyed by tool_call_id, `.reset()`), `GatedToolsExecutor(real_executor, policy, tracker)` (gate→partition→execute-allowed-via-real-executor→stash-raw-output→denied-dicts; fail-closed; threads the real gate reason into the denied `error`), `AresIngressElement()` (trailing-block in-place capture→scan→redact→inert_render), `build_denied_result(tool_call, reason=None)`. |
| `scripts/run_session_098.py` | Runner/CLI. **`_run_live()` is a stub that raises `NotImplementedError` — THIS SESSION FILLS IT IN.** Offline surface done: `HARD_CEILING_USD=25.0`, `_load_env` (UTF-16 `.env`), `estimate_cost_usd`, `build_arg_parser`, `_run_preflight`, `main` (exit codes: cost>cap→2, `--dry-run`→0, `--preflight-only`→0, no-`--confirm-live`→1). **All agentdojo imports must stay LAZY inside `_run_live`/its helpers** — the CLI test `tests/harness/test_run_session_098_cli.py` exec_modules the runner in the main venv and an AST scan forbids module-level agentdojo. |
| `docs/paper_5/PREREGISTRATION_phase3_measurement.md` | Pre-reg with the SSOT-locked containment-rule + cost-cap constants frozen; the **sweep/selection/metric/N/τ section is bracketed and MUST be filled + frozen before Stage-1** (§4). |
| guards | `tests/harness/test_harness_import_isolation.py` (whole-tree source scan + subprocess behavioral import) + the CLI AST scan. Keep them green. |

**Reuse (unchanged): the Phase-2 gate** `ares/harness/action_gate.py` (`authorize(action, policy)` keyed only on `(capability_class, arg-taint)`, no LLM) and Phase-1 `capture`/`ingress_scan`/`quarantine`/`normalize`.

**Load-bearing caveat (the whole reason for harness-side provenance):** the gate trusts the `arg_sources` it's handed; its fail-safe covers *omission* not *mislabeling*. So `_run_live` MUST populate provenance **harness-side via `GatedToolsExecutor`'s value-tracking of raw bytes** — never from model self-report. This is already how `GatedToolsExecutor` works; do not bypass it.

## 2. The job (design SSOT: `docs/superpowers/specs/2026-06-23-ares-harness-phase-3-agentdojo-measurement-design.md` §3, §3b, §6, §8, §9)

Implement `_run_live()` against the real AgentDojo pipeline and execute one gated run:

1. **Build the pipeline manually** (our defense isn't in AgentDojo's `DEFENSES`):
   `ToolsExecutionLoop([ GatedToolsExecutor(real_executor, policy, tracker), AresIngressElement(), llm ])`, then
   `pipeline = AgentPipeline([ SystemMessage, InitQuery, llm, tools_loop ])`.
2. **Set `pipeline.name = "claude-3-5-sonnet-20241022"`** — a `MODEL_NAMES` *key* (the Phase-0 workaround; the real calls still hit the claude-4.x element). A bare prose name makes `load_attack("important_instructions", …)` raise. The prose `{model}` value ("Claude") is pre-registered.
3. **Entrypoint = `run_task_with_injection_tasks`** directly (no per-injection utility precheck → honest cost model).
4. **Drain the tracker per task** (`run_task_with_pipeline` discards `extra_args` — the trace seam is the tracker object you injected, read by reference after each task, **reset per task**). The tracker feeds the `HarnessTrace`, the false-block rate, and the guarantee panel.
5. Run the **Stage-0 sweep → selection → Stage-1 arms** (§3 below) and write results.

### §3b integration contracts (frozen — assert, don't rediscover)
- **Denied tool-result** carries all five Required `ChatToolResultMessage` fields (already done in `build_denied_result`): `role`, `tool_call` (same object), `tool_call_id`, `error`, `content=[{"type":"text","content":""}]` (one-element list). A malformed message → swallowed `ValidationError` → silent re-run every resume (burns budget) + Phase-4 loader crash.
- **Content is `list[MessageContentBlock]` both directions.** Inbound flatten = join non-None block contents with `\n` (AgentDojo `get_text_content_as_str`), NOT `block[0]` (already handled by `_text_of_content`). Outbound re-wrap to `[{"type":"text","content":text}]` (already handled by `AresIngressElement`).
- **`AresIngressElement` mutates in place and returns the same `messages` list** (the loop rebinds from the return; a detached list drops the executor's appended results).
- An **integration test (bench-venv, behind `--confirm-live`)**: a ≥2-turn end-to-end on the selected cell — composed pipeline runs, `load_attack("important_instructions", …)` resolves, the gate denies a real injected privileged call, a denied + a sanitized message round-trip through the real `AnthropicLLM` serializer next turn without error, the tracker is populated after `run_task_with_pipeline`.

## 3. Measurement (one gated run — design §8)

- **Stage 0 — cell-selection sweep** (cheap, live, pre-registered rule + scope). Grid: `{haiku-4-5, sonnet-4-6} × {important_instructions, tool_knowledge} × {banking, slack, travel}` at a tiny per-cell N. **Selection universe restricted to environment-state action-attack injection tasks** (deterministic filter: injection tasks whose `ground_truth(env)` contains a policy-privileged tool call AND whose security oracle decides on `post_environment` state or the proposed-call trace, NOT `model_output` text alone — excludes travel `InjectionTask6` etc.), applied at **injection-task granularity**. Then the **pre-registered mechanical rule**: cheapest cell with undefended ASR ≥ τ_asr AND undefended utility ≥ τ_util. Contingency (pre-registered): if no cell clears the bar, the result stands on the deterministic-guarantee spine.
- **Stage 1 — arms on the selected cell** (with-injection): `undefended`, `full_defense`, ablations `scan_off`/`quarantine_off`/`gate_off`/`normalize_off` (NOT `ioc_off` — IOC is observational-only in the shipped wiring; null by construction). Plus a **separate benign (no-injection) pass** through each blocking arm for the false-block rate (`run_task_without_injection_tasks`).
- **Metrics:** ASR per scoped oracle panel; utility + utility cost; **false-block rate from the tracker sink**; **conclusion-integrity = echo-check** (final answer doesn't echo the planted claim; reported only where the AgentDojo oracle is NOT itself an output-echo check) + the `{security==False ∧ utility==False}` cross-tab as a secondary native view; **guarantee panel** = gate-on ASR = 0 by construction on the scoped task class across the model row.
- **Honest stats:** at N≈15–25 the single-arm ASR CI is ~±22pp and the delta ~±31pp → the ASR-delta panel is a **small-N headroom illustration**, the ablation is **exploratory**; the **guarantee spine is N-independent** (ASR=0 by construction) and carries the paper.

## 4. Pre-registration freezing protocol (do this BEFORE any Stage-1 spend)

1. Run a **real preflight rollout** on the selected model+suite to measure mean turns × per-call input (incl. that suite's tool-schema tokens, re-sent uncached every turn — banking ≈1,220 tok, travel ≈3,750 tok). **Refit `estimate_cost_usd`** from this (the S098 value is a placeholder).
2. Solve **N, N_benign, B_sweep** against ($25 − B_sweep); give the sweep its own sub-cap so it can't eat the Stage-1 allocation.
3. **Freeze into `docs/paper_5/PREREGISTRATION_phase3_measurement.md`**: the sweep grid, the env-state action-attack filter + eligible injection-task IDs per suite, the oracle-type partition, τ_asr/τ_util + no-cell contingency, the metric definitions (incl. false-block numerator/denominator + tracker-sink source; conclusion-integrity echo-rule + echo-oracle exclusion), the acceptable false-block band, N/N_benign/B_sweep.
4. **Extend `tests/paper_5/test_prereg_bands_match_code.py`** to SSOT-lock any newly frozen numeric constants that get a code home, then re-run it green. **No live run on an un-pinned constant.**
5. Decide (flagged to Dan in the design §13): whether to enable §6 step-7 assistant-message stripping for slack (extends the guarantee to the trace oracle). Default: report the env-state guarantee on banking-class; treat slack descriptively unless stripping is enabled.

## 5. If the sweep selects slack/travel
Build `slack_policy()`/`travel_policy()` in `agentdojo_policy.py` exactly like `banking_policy()` — explicit tool→CapabilityClass mapping enumerated from `agentdojo.default_suites.v1.{slack,travel}.task_suite.TOOLS`, with an `EXPECTED_*` set + an audit test, and a bench-venv audit asserting the mapping covers the suite's live `runtime.functions`. (Banking is fully specified; it carries the guarantee spine.)

## 6. Run order
```bash
# (after pre-reg frozen + SSOT test green, in .scratch/bench-venv)
python scripts/run_session_098.py --preflight-only         # offline checks (main venv ok)
python scripts/run_session_098.py --dry-run                # refit cost estimate
python scripts/run_session_098.py --confirm-live --cost-ceiling 25
```
Hard `--cost-ceiling` mid-run abort is the real safety net regardless of estimate accuracy.

## 7. Deliverables
- Result note `docs/paper_5/S099_PHASE3_MEASUREMENT_RESULT_<date>.md` (guarantee panel + ASR-delta + conclusion-integrity + ablations + honest stats caveat).
- Raw artifacts under `data/paper_5/`.
- `_run_live` body committed (agentdojo imports stay lazy; CLI import-isolation guard + whole-suite green).
- Pre-registration frozen + SSOT test extended & green.
- Session-close: CLAUDE.md ledger + squash-merge to `main` (confirm before push) + Notion debrief + crystalize, via `ares-session-close`.

## 8. Non-negotiables (carry from the arc)
- The action gate stays deterministic / **no LLM, ever**. Provenance derived **harness-side from raw bytes**, never model self-report. Fail-closed everywhere. New-files-only except `_run_live` in the runner (this branch's own file) + the prereg doc + the SSOT test + policy additions. Leaky measurement default + existing cycles byte-identical. **Main venv stays agentdojo-free; the three-layer import-isolation guard stays green.** Zero regressions before squash.

## 9. References
- Design SSOT: `docs/superpowers/specs/2026-06-23-ares-harness-phase-3-agentdojo-measurement-design.md` (§3 seam, §3b contracts, §5 provenance, §6 gated executor, §8 measurement, §9 pre-reg, §12 risks).
- Plan (offline build, incl. Task 8 step 5 = this live step): `docs/superpowers/plans/2026-06-23-ares-harness-phase-3.md`.
- Phase 0 notes: `docs/paper_5/PHASE0_BENCHMARK_RUNNABILITY_2026-06-20.md` (bench-venv + AgentDojo shim), `docs/paper_5/PHASE0_BASELINE_2026-06-20.md` (undefended baseline + design corrections).
- Arc spec: `docs/superpowers/specs/2026-06-20-ares-harness-injection-defense-design.md`.
- Offline Phase 3 head commit: `1452a01` on `session/098-ares-harness-phase-3`.
