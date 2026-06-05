# S084 — Dual-Agent Framing-Sensitivity Measurement (design)

**Date:** 2026-06-05
**Session:** 084
**Thread:** ares-phase-seven (Paper 3 camera-ready / future-work input)
**Status:** approved (brainstorming) — pending plan
**Parent:** S083 `inj020-dual-agent-drift` crystal; promotes the dual-agent drift *recon* to a rigorous result.

## 1. Motivation

S083 banked a qualitative finding: explanation drift under framing is **dual-agent and mirror-image** — the Architect *collapses* its cited-fact set toward the contested threat fact while the Skeptic *expands* its set to include that fact, even as the decision (`threat_dismissed`) stays firm. That recon was limited:

- It read the Skeptic's facts off `oracle_supporting_facts`, which only equals the Skeptic's cited set for **DISMISSED** verdicts (the outcome-conditioned `compute_verdict`, `oracle.py:100-109`) → only **6** scenarios were observable.
- It had **no noise floor and no positive control** — raw modal-set Jaccard only.

**Key discovery (verified S084 brainstorming, offline, $0):** the live cycle's `CycleTrace` already carries `skeptic_cited_facts` directly (`leakage_runner.py:137`, populated at `:352` via `skep.get_all_fact_ids()`), on **every** LLM cycle regardless of outcome. Inspecting the committed S059 traces (`data/paper_3/leakage_runs/20260510-193950-f401a8/`): `skeptic_cited_facts` is non-empty in **131/131** LLM rows, differs from `architect_cited_facts` in **107/131 (82%)**, and moves baseline→mutated in **23/33** scenarios. The recon's gotcha was about S077's persisted `ResampleRecord` (architect column only), **not** the underlying cycle. The Skeptic's drift is directly measurable with the same machinery S077 used for the Architect.

## 2. Decisions locked (this session)

| Decision | Choice | Why |
|---|---|---|
| Scope | **Dual-agent paired** | One run records both agents' cited facts + a paired mirror metric on identical cycles. Same core API cost as Skeptic-only (recording the second column adds zero LLM calls). |
| Delivery | **Build + full live run** | Produce the rigorous result this session, not just the harness. Dan-authorized. |
| Defaults | K=20, 17 Architect-diverging scenarios, 3 pre-registered operators, Sonnet 4 | Matches the S082 scale run → enables an Architect-reproduction cross-check and a same-scenario mirror. |
| Control | **Single joint control**, per-agent validity | See §6. Keeps the run at ~1,700 cycles / ~$25. |

## 3. Architecture & reuse (NON-NEGOTIABLE: new files only)

The cycle already emits both agents' facts, so **no existing file is modified.** Reused by import, unchanged:

- `ares.dialectic.measurement.leakage_runner._run_one_cycle` — live `pipeline="llm"` cycle; returns a `CycleTrace` with `architect_cited_facts`, `skeptic_cited_facts`, `*_confidence`, `final_outcome`, `oracle_supporting_facts`, `elapsed_ms`, `cost_usd`.
- `ares.dialectic.measurement.architect_framing_metrics` — `jaccard_distance`, `within_distances`, `cross_distances`, `permutation_pvalue`, `bootstrap_ci_median_diff`, `classify_operator`. Agent-agnostic (operate on `frozenset[str]`).
- `ares.dialectic.measurement.architect_framing_control` — `choose_control_drop_fact(packet, baseline_cited_sets)`, `build_positive_control_scenario(baseline, drop_fact_id)`, `highest_stage_fact_id`.
- `ares.dialectic.measurement.architect_framing_selection.select_diverging_scenarios` — the default scenario set (Architect-diverging from the S059 traces; 17 on Sonnet).
- `ares.dialectic.measurement.architect_framing_schema` — `OperatorFramingResult`, `VERDICT_REAL/_NOISE/_INCONCLUSIVE`, `framing_condition`, `CONDITION_BASELINE`, `CONDITION_CONTROL`.
- `architect_framing_runner._resample` is **not** reused (it records the architect column only); we write a dual-recording resample.
- `paired_scenario_mutator.PairedScenarioMutator` / `SkeletonInvariantError`; `injection_registry_v3.build_registry_v3`; `leakage_runner._resolve_operator`.

**Five new files** + offline tests (tests co-located at `tests/dialectic/measurement/test_dual_agent_framing_*.py`, matching the S077 layout).

## 4. New files

| File | Responsibility |
|---|---|
| `ares/dialectic/measurement/dual_agent_framing_schema.py` | Frozen config + record/result dataclasses (§5). |
| `ares/dialectic/measurement/dual_agent_framing_mirror.py` | Pure stdlib mirror logic: `direction`, `modal_set`, `classify_mirror`, `build_mirror_record` (§7). |
| `ares/dialectic/measurement/dual_agent_framing_runner.py` | `run_preflight`, `run_measurement`, dual-recording `_resample_dual`; orchestration + persistence (§6). |
| `ares/dialectic/measurement/dual_agent_framing_report.py` | Markdown renderer: per-agent verdict tables + the mirror table + per-agent control validity. |
| `scripts/run_session_084.py` | CLI: `.env` load, `--preflight-only`, `--confirm-live`, `--cost-ceiling`, `--k`, `--max-scenarios`, `--provider`, `--model` (§8). |

## 5. Data model (frozen dataclasses)

```
DUAL_AGENT_FRAMING_HARD_CEILING_USD = 40.0
AGENT_ARCHITECT = "architect"
AGENT_SKEPTIC   = "skeptic"

DualAgentFramingConfig(frozen):
    s059_traces_path: Path
    scenario_ids: tuple[str, ...] = ()        # () => select_diverging_scenarios
    k_resamples: int = 20                      # __post_init__: >= 2
    max_scenarios: int = 17                    # budget guard; deferred IDs logged, never silent
    operator_names: tuple[str,...] = PRE_REGISTERED_OPERATOR_NAMES
    model: str = DEFAULT_MODEL                 # Sonnet 4
    provider: str = "anthropic"               # __post_init__: in VALID_PROVIDERS
    cost_ceiling_usd: float = 32.0            # __post_init__: <= HARD_CEILING
    traces_root: Path = DEFAULT_TRACES_ROOT
    seed: int = 0

DualAgentResampleRecord(frozen):
    scenario_id, condition, resample_index,
    architect_cited_facts: tuple[str,...], skeptic_cited_facts: tuple[str,...],
    architect_confidence: float, skeptic_confidence: float,
    final_outcome: str, oracle_supporting_facts: tuple[str,...],
    cost_usd: float, elapsed_ms: float
    # to_dict(): tuples -> lists (JSONL row)

AgentFramingResult(frozen):
    agent: str                                 # architect | skeptic
    within_distances: tuple[float,...]
    control_distances: tuple[float,...]
    control_exceeds_noise: bool
    operator_results: tuple[OperatorFramingResult,...]   # reused S077 type

MirrorRecord(frozen):
    scenario_id, operator_name,
    architect_jaccard: float, architect_direction: str,   # none|collapse|expand|swap
    skeptic_jaccard: float,  skeptic_direction: str,
    mirror_class: str                          # opposed | aligned | single | mixed | none

ScenarioDualFramingResult(frozen):
    scenario_id,
    architect: AgentFramingResult,
    skeptic: AgentFramingResult,
    mirror: tuple[MirrorRecord,...],
    skipped_operators: tuple[str,...]

DualAgentFramingSummary(frozen):
    run_id, timestamp_iso, git_sha, provider, model,
    k_resamples, operator_names,
    scenario_results: tuple[ScenarioDualFramingResult,...],
    deferred_scenario_ids: tuple[str,...],
    control_valid_architect: bool, control_valid_skeptic: bool,
    total_cost_usd, halt_reason, traces_path
```

## 6. Measurement flow + positive control

`total_cycles_for(n_scenarios, k, n_ops) = n_scenarios * k * (2 + n_ops)` (baseline + control + n_ops framing). At 17/20/3 → 1,700 cycles ≈ **$25** (≈ S082's $24.58 / 1,680).

Per scenario in the selected set (cap `max_scenarios`; remainder → `deferred_scenario_ids`):
1. **Baseline:** K cycles via `_run_one_cycle(pipeline="llm")`. For each, append a `DualAgentResampleRecord` with *both* columns. Collect `arch_base_sets` and `skep_base_sets` (`list[frozenset]`).
2. **Noise floor:** `within_distances(arch_base_sets)` and `within_distances(skep_base_sets)` — independent per agent.
3. **Framing (per operator):** `mutator.mutate(scenario, op)` (skip + log on `SkeletonInvariantError`); K framed cycles; `cross_distances(base, framed)` per agent → `classify_operator(cross, within, seed)` per agent → `OperatorFramingResult`. Build a `MirrorRecord` from the modal sets (§7).
4. **Positive control (single, joint):** `choose_control_drop_fact(packet, arch_base_sets + skep_base_sets)` → the fact most frequently cited across *both* agents' baselines; `build_positive_control_scenario` drops it; K control cycles; compute control cross-distance per agent and require `effect>0 and p<0.05` vs *that agent's* within → `control_exceeds_noise` per agent. `ValueError` (no citable fact) → control distances empty, `control_exceeds_noise=False`.
5. Assemble `ScenarioDualFramingResult`. Track `total_cost`; on `>= cost_ceiling_usd`, halt (`halt_reason="cost_ceiling"`), append remaining to `deferred`.

Persist all records to `traces_root/<run_id>/traces.jsonl` (sorted-key JSON, one row/cycle) + `summary.json`. `control_valid_architect` / `control_valid_skeptic` = AND over scenarios' per-agent `control_exceeds_noise`.

**Control rationale.** The two agents' baseline citations overlap heavily, so the most-jointly-cited fact almost always moves both → per-agent control validity at single-control cost. If an agent's control empirically lands within-noise on a scenario, that agent's result on that scenario is **flagged control-unvalidated** in the report (honest, not silent) rather than auto-escalating to a second control (which would require a re-run). Dual independent controls (drop an Architect-cited fact *and* a Skeptic-cited fact, +K cycles/scenario, ~+20%) is a documented future option, not this run.

## 7. Mirror metric (`dual_agent_framing_mirror.py`, pure/stdlib)

- `direction(baseline: frozenset, framed: frozenset) -> str`: `none` (equal), `collapse` (only drops), `expand` (only adds), `swap` (both) — the S083 recon's `classify`, now first-class and unit-tested.
- `modal_set(sets: Sequence[frozenset]) -> frozenset`: the most-common set; ties broken deterministically by the lexicographically smallest `tuple(sorted(s))` among the tied sets (Counter order is not relied upon). The per-condition representative.
- `classify_mirror(arch_dir, skep_dir) -> str` — total over all 16 direction pairs: `none` (both `none`); `single` (exactly one `none`); `aligned` (both non-`none` and equal); `opposed` (the pair `{collapse, expand}` — the headline); `mixed` (any other both-non-`none` combination, e.g. one agent `swap`).
- `build_mirror_record(scenario_id, op, arch_base_sets, arch_framed_sets, skep_base_sets, skep_framed_sets) -> MirrorRecord`: Jaccard between modal baseline and modal framed per agent + directions + mirror class. Paired by construction (both columns come from the same K cycles).

## 8. CLI & cost gating (`scripts/run_session_084.py`, mirrors `run_session_077.py`)

- UTF-16 `.env` loading (S075 pattern) for `ANTHROPIC_API_KEY`.
- Flags: `--preflight-only`, `--confirm-live`, `--cost-ceiling` (clamped to `DUAL_AGENT_FRAMING_HARD_CEILING_USD`), `--k` (20), `--max-scenarios` (17), `--provider`/`--model`.
- **Run order:** preflight (a few sample cycles → extrapolate via `total_cycles_for`) → print projected cost vs ceiling → require `--confirm-live` for the full run. Operator: preflight, confirm ~$25 projection lands under ceiling, then full run.

## 9. Testing (TDD; all offline, $0, deterministic)

Injectable `cycle_fn: CycleFn` (same signature as `_run_one_cycle`) returns synthetic `(CycleTrace, cost)` with scripted `architect_cited_facts` / `skeptic_cited_facts` per `condition`. Cases:

- **schema**: `DualAgentResampleRecord.to_dict` round-trip (both columns → lists); config `__post_init__` guards (k>=2, provider, ceiling<=hard cap).
- **mirror**: `direction` on equal/collapse/expand/swap fixtures; `classify_mirror` truth table; `modal_set` tie-break; `build_mirror_record` on a scripted Architect-collapse / Skeptic-expand → `architect_direction="collapse"`, `skeptic_direction="expand"`, `mirror_class="opposed"`.
- **runner**: dual-recording resample persists both columns; per-agent within/cross wiring; joint-control fact selection + per-agent `control_exceeds_noise`; cost accounting + `deferred_scenario_ids` when `max_scenarios` < selected; `SkeletonInvariantError` → operator skipped + logged; preflight extrapolation via `total_cycles_for`.
- **report**: renders per-agent verdict tables + mirror table; surfaces a control-unvalidated flag; no crash on empty/partial results.
- **reuse anchor**: assert the runner imports `classify_operator`/`choose_control_drop_fact` from the S077 modules (not a re-implementation) — guards the "new files only" contract.

## 10. Deliverables, zero-regression, housekeeping

- New files only → full suite (`pytest tests/ ares/`) stays green; floor rises by the new test count (update CLAUDE.md floor at close).
- Live result writeup → `docs/paper_3/S084_DUAL_AGENT_FRAMING_RESULT_2026-06-05.md` (per-agent verdicts + mirror table + control validity + Architect-vs-S082 sanity note). Traces + `summary.json` under `data/paper_3/leakage_runs/<run_id>/`.
- Branch `session/084-dual-agent-framing`; squash-merge after zero regressions confirmed. **Frozen Paper 3 untouched.**
- CLAUDE.md at close: floor, a Key Code Locations block for the new modules, Branch ground-truth, and a "Where We Are" line. Watch the 40k ceiling (roll oldest down if needed).

## 11. Out of scope / future options

- Dual independent positive controls (per-agent guaranteed validity, +~20% cost).
- Skeptic-diverging scenario selection (the 23/33 set) — this run reuses the Architect-17 for the paired mirror.
- Folding S084 into Paper 3 camera-ready — only after the 2026-07-24 accept/reject.
- Per-operator INJ-020 deep dive (already root-caused in S083; this run quantifies it with a noise floor).

## 12. Cross-checks baked in

- **Architect reproduction:** recording `architect_cited_facts` on the same 17/3/K=20 should reproduce S082's Architect verdicts within sampling noise — a qualitative internal-consistency check surfaced in the report.
- **Mirror is paired:** both agents' modal sets per condition come from the *same* K cycles, so the collapse-vs-expand contrast is not confounded by cross-run sampling differences (the recon's weakness).
