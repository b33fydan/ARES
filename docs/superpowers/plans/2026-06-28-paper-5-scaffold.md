# Paper 5 Scaffold (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build Paper 5's structural foundation — the skeleton SSOT (`docs/paper_5/skeleton_v1_0.json`), a verified-only `references.bib` + verbatim-copied `build_references.py`, a `number_check.py` with resolvers locked to the S099 run artifact, and four build-time gate tests (`tests/paper_5/test_{skeleton_audit,citation_existence,number_check,anchor_existence}.py`) — by porting Paper 4's proven scaffold pipeline to a sibling `docs/paper_5/` + `tests/paper_5/`, with zero prose/figures/PDF and no new measurement.

**Architecture:** Port Paper 4's scaffold pipeline (itself ported from Paper 3) to a sibling directory. The skeleton JSON is the single source of truth; the gate tests are pytest tests that fail on drift. Two coupled subset-lock invariants are preserved: (1) every per-section `numbers_preregistered` token is a strict subset of the top-level registry (skeleton-audit), and (2) every registry number in the hand-maintained `covered` set is backed by a passing `number_check` resolver (number-check). All numbers resolve against the closed S099 run artifact `data/paper_5/s099_phase3_run_20260627-070037.json`; the note-only headline cost (`$3.8`) and planted IBAN are locked via prose substrings + the PDF gate (later phase), never via a JSON resolver.

**Tech Stack:** Python 3.11, pytest, stdlib only (`json`, `re`, `dataclasses`, `pathlib`, `argparse`) — no new dependencies. The repo's main venv is the GLOBAL `C:\Program Files\Python311\python.exe` (the local `./venv` is incomplete — 16 collection errors). Run everything with the global `python`.

**Source of truth for content:** the Paper 5 design spec `docs/superpowers/specs/2026-06-27-paper-5-harness-defense-design.md` (read §5 section skeleton, §6 evidence-to-claim map, §7 figures/tables, §8 gates, §9 anchors, §10 bib plan before Task 1). The arc spec `docs/superpowers/specs/2026-06-20-ares-harness-injection-defense-design.md` §16 carries the new bibkey arXiv IDs to web-verify.

## Global Constraints

Every task's requirements implicitly include this section (exact values copied from the spec + ARES non-negotiables):

- **New files only.** Phase 1 creates new files. The ONLY existing file modified is `CLAUDE.md`, and only at session close (Task 6). Do NOT edit the already-shipped `tests/paper_5/test_prereg_bands_match_code.py` (S098/S099) or anything under `ares/`, `data/paper_5/`, `docs/paper_5/PREREGISTRATION_phase3_measurement.md`, or the S099 result note.
- **No new measurement.** Written entirely from closed S096–S099 artifacts. Every number resolves against an existing on-disk file; never invent or recompute a value.
- **Artifact value is canonical.** When a resolver and the skeleton disagree, fix the skeleton/expected, NEVER the artifact. Lock the RAW JSON values (`0.2`, not prose-rounded `0.20`; `2`, not "two").
- **Verified-only bib discipline (Sabet-hallucination lesson).** `references.bib` contains ONLY web-verified entries. Unverified keys live in the skeleton's `bibkeys_needed_unverified` with `verification_instructions`, NEVER as `.bib` placeholders. No `-needed`-suffixed key in the bib.
- **Test floor floor = 4,476** (post-S099). Bump `CLAUDE.md` "Test count floor (passing)" to 4,476 + (new gate test count, measured in Task 4) at session close.
- **Branch / commit.** All work on `session/100-paper-5-design` (already created and checked out; this plan + the design spec already live on it). Never commit to `main`. Squash-merge after zero regressions (ares-session-close skill). Commit messages tagged `…(s100): …` with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer; stage ONLY the files each task creates (the working tree has many untracked screenshots/docs — never `git add -A`).
- **Encoding:** all JSON/bib/py/test files are UTF-8 (`encoding="utf-8"` on every read/write). The repo's `.env` is UTF-16 but artifacts are UTF-8.
- **No-cell contingency is the result, not a bug.** All undefended/with-injection ASR = 0.0 (every sweep cell and every Stage-1 arm). `selected_cell` is JSON `null`; `run_cell` is the fallback. Treat ASR=0 as the load-bearing "models resist the action axis" finding.

---

## Scope

**This plan (Phase 1):** the skeleton JSON + verified-only `references.bib` + verbatim `build_references.py` + `number_check.py` resolvers + four gate tests. Six tasks, RED→GREEN→COMMIT per gate.

**Follow-on plans (named here, each its own plan at its session):**
- **Phase 2 — Figures:** `docs/paper_5/build_figures.py` → 6 vector PDFs `figures/fig_{1..6}.pdf` (matplotlib, `pdf.fonttype = 42`). Mirrors `docs/paper_4/build_figures.py`.
- **Phase 3 — Prose:** `docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md` (Abstract → §10, ~9k words), activating the dormant `TestProse` + `prose_substring_claims()` lock. Mirrors Paper 4 S094.
- **Phase 4 — acmart build + PDF gate:** `docs/paper_5/build_acmart.py` + `docs/paper_5/acmart/verify_pdf_substrings.py` (single-sources `number_check.prose_substring_claims()`, dollar-escape round-trip for `$3.8`/`$0.07`). Mirrors Paper 4 S095.

**Out of scope for Phase 1:** no prose, no figures, no acmart/PDF, no LLM, no new measurement. The 9 new SOTA bibkeys ARE web-verified in this phase (spec §11: "verified-only references.bib with new keys web-verified").

## File Structure

**Create:**
- `docs/paper_5/skeleton_v1_0.json` — the structural SSOT (Task 1).
- `docs/paper_5/build_references.py` — verbatim copy of Paper 4's bib helpers (Task 2).
- `docs/paper_5/references.bib` — verified-only bib (Task 2).
- `docs/paper_5/number_check.py` — resolvers + claim engine + prose-substring SSOT (Task 3).
- `docs/paper_5/number_check_report.md` — generated by `number_check.main()` (Task 3/4).
- `tests/paper_5/test_skeleton_audit.py` — structural gate (Task 1).
- `tests/paper_5/test_citation_existence.py` — bib gate (Task 2).
- `tests/paper_5/test_number_check.py` — number gate incl. the two subset locks + dormant `TestProse` (Task 3).
- `tests/paper_5/test_anchor_existence.py` — thin cross-check that `anchor_tests_required` paths exist on disk (Task 5).
- `docs/paper_5/__init__.py` and `tests/paper_5/__init__.py` — ONLY if Paper 4 has them (Task 1 Step 1 checks).

**Reference (read / copy from):**
- `docs/paper_4/{skeleton_v1_0.json, build_references.py, references.bib, number_check.py}` and `tests/paper_4/test_{skeleton_audit,citation_existence,number_check}.py` — the templates.
- `data/paper_5/s099_phase3_run_20260627-070037.json` — THE number source (read it before wiring resolvers).
- `docs/paper_5/PREREGISTRATION_phase3_measurement.md` + `tests/paper_5/test_prereg_bands_match_code.py` — protocol SSOT (already shipped; do not edit).

**Modify (Task 6, session close only):**
- `CLAUDE.md` — test floor + Canonical-Artifacts paths + ledger/branch record.

## Number reconciliation (LOCK THESE — surfaced from the artifacts)

Read directly from `data/paper_5/s099_phase3_run_20260627-070037.json` (a single FLAT object, no run-id wrapper). Use these exact JSON key paths and raw values:

| Quantity | Locked value | Source artifact (key path) |
|---|---|---|
| Undefended ASR, every sweep cell | `0.0` | `sweep[i]["undefended_asr"]` (all 4 cells) |
| Sweep undefended utility | `0.0 / 0.5 / 0.75 / 0.75` | `sweep[i]["undefended_utility"]` (haiku-ii / haiku-tk / sonnet-ii / sonnet-tk, in list order) |
| Selected cell | `null` | `selected_cell` (Python `None`) |
| No-cell contingency fired | `true` | `no_cell_contingency` |
| Fallback cell | `haiku-4-5 / important_instructions / banking` | `run_cell["model"]/["attack"]/["suite"]` |
| Stage-1 undefended | asr `0.0`, utility `0.5`, gate_denials `0`, echo `0.05`, conclusion-integrity `0.95`, n `20` | `stage1_arms["undefended"][...]` |
| Stage-1 full_defense | asr `0.0`, utility `0.3`, gate_denials `2`, echo `0.05`, conclusion-integrity `0.95`, n `20` | `stage1_arms["full_defense"][...]` |
| Stage-1 gate_off | asr `0.0`, utility `0.45`, gate_denials `0`, echo `0.05`, conclusion-integrity `0.95`, n `20` | `stage1_arms["gate_off"][...]` |
| Benign false-block | rate `0.2`, denials `4`, benign utility `0.3`, n `20` | `benign_false_block["full_defense"][...]` |
| τ_asr / τ_util | `0.2 / 0.2` | `tau_asr` / `tau_util` |
| Eligible banking injection tasks | `9` (`injection_task_0`..`injection_task_8`) | `len(eligible_injection_tasks["banking"])` |
| Rollouts | `96` | `rollouts` |
| Cost-guard estimate (conservative) | `11.52` | `estimated_spend_usd` |
| Aborted | `null` | `aborted` |

**Note-only numbers (NOT in the run JSON — lock via prose substrings + PDF gate, never a JSON resolver):**
- Refined headline cost `$3.8` total (≈$3.7 actual + ≈$0.07 calibration) — result note `docs/paper_5/S099_PHASE3_MEASUREMENT_RESULT_2026-06-27.md` §5 header.
- Planted attacker IBAN `US133000000121212121212` — result note §4.

**Prereg-owned protocol constants (SSOT = `tests/paper_5/test_prereg_bands_match_code.py`, already shipped — the skeleton's pre-registered-numbers block sources its protocol values from here, the run JSON confirms the run honored them):** grid `{haiku-4-5, sonnet-4-6}×{important_instructions, tool_knowledge}×{banking}`; arms `undefended/full_defense/gate_off` (finer ablation deferred to Phase 4); `_FROZEN_N=20`, `_FROZEN_N_BENIGN=20`, `_REFIT_ROLLOUT_USD=0.12`, `HARD_CEILING_USD=25.0`, false-block band ≤ `0.50`; release token `STAGE1_PARAMETERS_FROZEN`.

---

## Task 1: Paper 5 skeleton JSON + skeleton-audit gate

**Files:**
- Create: `docs/paper_5/skeleton_v1_0.json`, `tests/paper_5/test_skeleton_audit.py`
- Create (conditional): `docs/paper_5/__init__.py`, `tests/paper_5/__init__.py`
- Reference: `docs/paper_4/skeleton_v1_0.json`, `tests/paper_4/test_skeleton_audit.py`

**Interfaces:**
- Produces: `docs/paper_5/skeleton_v1_0.json` consumed by all later tasks (its top-level `numbers_preregistered` registry, `sections`, `bibkeys_*`, `anchor_tests_required`, `build_start_test_floor`).

- [ ] **Step 1: Set up the package dir and confirm conventions**

Run: `ls docs/paper_4/__init__.py tests/paper_4/__init__.py 2>/dev/null; ls tests/paper_5/`
- `tests/paper_5/` ALREADY EXISTS (holds `test_prereg_bands_match_code.py`). Do not recreate it; do not touch the existing file.
- If `docs/paper_4/__init__.py` exists, create an empty `docs/paper_5/__init__.py`. If `tests/paper_4/__init__.py` exists and `tests/paper_5/__init__.py` does not, create an empty `tests/paper_5/__init__.py`. (These make `from docs.paper_5 import number_check` and `from docs.paper_5.build_references import …` importable under pytest. If Paper 4 has none and its imports work via repo-root conftest, replicate nothing.)

- [ ] **Step 2: Write the skeleton-audit gate (the contract)**

Create `tests/paper_5/test_skeleton_audit.py` with this exact content:

```python
"""Structural audit of docs/paper_5/skeleton_v1_0.json (Paper 5 SSOT)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON = REPO_ROOT / "docs" / "paper_5" / "skeleton_v1_0.json"

# Section order is locked: two unnumbered front sections, then numbered 1..11.
EXPECTED_SECTION_IDS = [
    "in_plain_terms",          # unnumbered front matter (section_number None)
    "abstract",                # unnumbered (section_number None)
    "introduction",            # 1
    "background_threat_model", # 2
    "ares_harness_architecture",  # 3
    "action_gate_guarantee",   # 4
    "methodology",             # 5
    "results",                 # 6  (load-bearing — the dual-spine headline)
    "positioning_vs_sota",     # 7
    "discussion",              # 8
    "limitations",             # 9
    "future_work",             # 10
    "references",              # 11
]


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


class TestMeta:
    def test_skeleton_file_exists(self):
        assert SKELETON.exists()

    def test_parses_as_json(self, skeleton):
        assert isinstance(skeleton, dict)

    def test_kind_disambiguates(self, skeleton):
        assert skeleton["kind"] == "paper_structure_skeleton"

    def test_paper_id_locked(self, skeleton):
        assert skeleton["paper_id"] == "paper_5_v1_0"

    def test_framing_choice_locked(self, skeleton):
        fc = skeleton["framing_choice"].lower()
        assert "guarantee" in fc and "regime" in fc

    def test_evidence_base_declares_no_new_measurement(self, skeleton):
        assert "no new measurement" in skeleton["evidence_base"].lower()

    def test_build_start_test_floor(self, skeleton):
        assert skeleton["build_start_test_floor"] == 4476

    def test_required_top_level_keys(self, skeleton):
        for key in (
            "working_title", "short_title", "author", "venue",
            "target_words_core", "section_count_numbered", "framing_choice",
            "framing_rationale", "evidence_base", "contribution_claims",
            "result_findings", "sections", "figures", "tables",
            "numbers_preregistered", "bibkeys_required_verified",
            "bibkeys_needed_unverified", "anchor_tests_required",
        ):
            assert key in skeleton, f"missing top-level key: {key}"


class TestSections:
    def test_section_order_locked(self, skeleton):
        ids = [s["section_id"] for s in skeleton["sections"]]
        assert ids == EXPECTED_SECTION_IDS

    def test_in_plain_terms_first_and_unnumbered(self, skeleton):
        s0 = skeleton["sections"][0]
        assert s0["section_id"] == "in_plain_terms"
        assert s0["section_number"] is None

    def test_abstract_second_and_unnumbered(self, skeleton):
        s1 = skeleton["sections"][1]
        assert s1["section_id"] == "abstract"
        assert s1["section_number"] is None

    def test_numbered_one_through_eleven(self, skeleton):
        nums = sorted(
            s["section_number"]
            for s in skeleton["sections"]
            if s["section_number"] is not None
        )
        assert nums == list(range(1, 12))

    def test_section_count_numbered_is_eleven(self, skeleton):
        assert skeleton["section_count_numbered"] == 11

    def test_references_section_is_last(self, skeleton):
        last = skeleton["sections"][-1]
        assert last["section_id"] == "references"
        assert last["section_number"] == 11

    def test_each_section_has_required_fields(self, skeleton):
        for s in skeleton["sections"]:
            for field in (
                "section_id", "section_number", "title", "target_words",
                "claims", "numbers_preregistered", "bibkeys_required",
                "figures", "tables",
            ):
                assert field in s, f"{s.get('section_id')} missing {field}"

    def test_results_is_load_bearing(self, skeleton):
        results = next(s for s in skeleton["sections"] if s["section_id"] == "results")
        assert results.get("load_bearing") is True

    def test_target_words_sum_within_budget(self, skeleton):
        total = sum(s["target_words"] for s in skeleton["sections"])
        assert abs(total - skeleton["target_words_core"]) <= 400


class TestFiguresTables:
    def test_figure_count_locked(self, skeleton):
        assert len(skeleton["figures"]) == 6

    def test_table_count_locked(self, skeleton):
        assert len(skeleton["tables"]) == 4

    def test_each_figure_has_required_fields(self, skeleton):
        for f in skeleton["figures"]:
            for field in ("id", "type", "purpose", "source", "host_section"):
                assert field in f, f"{f.get('id')} missing {field}"

    def test_each_table_has_required_fields(self, skeleton):
        for t in skeleton["tables"]:
            for field in ("id", "purpose", "source", "host_section"):
                assert field in t, f"{t.get('id')} missing {field}"

    def test_figure_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]}
        for f in skeleton["figures"]:
            assert f["host_section"] in valid

    def test_table_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]}
        for t in skeleton["tables"]:
            assert t["host_section"] in valid

    def test_figures_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]}
        for f in skeleton["figures"]:
            assert f["id"] in by_num[f["host_section"]]["figures"]

    def test_tables_listed_in_their_host_section(self, skeleton):
        by_num = {s["section_number"]: s for s in skeleton["sections"]}
        for t in skeleton["tables"]:
            assert t["id"] in by_num[t["host_section"]]["tables"]


class TestNumbers:
    def test_each_number_has_required_fields(self, skeleton):
        for n in skeleton["numbers_preregistered"]:
            for field in ("value", "source", "lock_target"):
                assert field in n, f"number {n} missing {field}"

    def test_guarantee_numbers_locked(self, skeleton):
        values = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        for required in ("0.0", "0.2", "0.95", "2", "0.3", "0.45", "20", "$3.8"):
            assert required in values, f"registry missing {required}"

    def test_section_numbers_preregistered_are_subset_of_top_level(self, skeleton):
        top = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        for s in skeleton["sections"]:
            for tok in s["numbers_preregistered"]:
                assert tok in top, f"{s['section_id']} cites {tok} not in registry"


class TestBibkeys:
    def test_reused_verified_keys_present(self, skeleton):
        keys = {b["bibkey"] for b in skeleton["bibkeys_required_verified"]}
        for k in ("greshake-2023", "gmys-casiano-2026a", "gmys-casiano-2026d"):
            assert k in keys, f"missing verified bibkey {k}"

    def test_each_verified_bibkey_has_fields(self, skeleton):
        for b in skeleton["bibkeys_required_verified"]:
            assert b["bibkey"] and b["role"]
            assert b["status"] == "VERIFIED"

    def test_unverified_use_needed_marker(self, skeleton):
        for u in skeleton["bibkeys_needed_unverified"]:
            assert u["slug"] and u["verification_instructions"]


class TestAnchors:
    def test_anchor_tests_reference_existing_locks(self, skeleton):
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        assert "tests/paper_5/test_prereg_bands_match_code.py" in paths
        assert "tests/harness/test_action_gate_invariants.py" in paths

    def test_each_anchor_has_fields(self, skeleton):
        for a in skeleton["anchor_tests_required"]:
            for field in ("path", "status", "locks"):
                assert field in a
```

- [ ] **Step 3: Run the audit — verify it FAILS (skeleton not authored yet)**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_skeleton_audit.py -q`
Expected: FAIL / errors (FileNotFoundError on `skeleton_v1_0.json`).

- [ ] **Step 4: Author the skeleton JSON to satisfy the audit**

Create `docs/paper_5/skeleton_v1_0.json` with this exact content (every value is locked from the spec + the Number-reconciliation table; per-section `numbers_preregistered` tokens are str-renderings of the registry values; `anchor_tests_required` paths are confirmed-existing in Task 5):

```json
{
  "kind": "paper_structure_skeleton",
  "paper_id": "paper_5_v1_0",
  "working_title": "A Deterministic Action Gate Holds Injected Tool Calls at Zero: A Guarantee and a No-Headroom Regime for Tool-Using Agents",
  "short_title": "The No-Headroom Injection Regime",
  "author": "Daniel Gmys-Casiano (Skyframe Innovations)",
  "venue": "TBD peer venue; acmart-portable",
  "target_words_core": 9000,
  "section_count_numbered": 11,
  "framing_choice": "guarantee + no-headroom regime (dual-spine)",
  "framing_rationale": "The live AgentDojo result is a pre-registered contingency: undefended ASR is 0 across the model x attack grid, so the contribution is the by-construction guarantee + the empirically-firing gate + the honest false-block cost + conclusion-integrity, not an ASR-delta. The paper co-headlines the guarantee (mechanism) and the no-headroom regime (empirical finding).",
  "build_session": 101,
  "build_start_test_floor": 4476,
  "skeleton_version": "v1.0",
  "evidence_base": "ARES-Harness arc S096-S099 (input-path defense, action gate, AgentDojo Phase-3 live measurement). No new measurement - written entirely from closed artifacts. Result spine: docs/paper_5/S099_PHASE3_MEASUREMENT_RESULT_2026-06-27.md; run artifact data/paper_5/s099_phase3_run_20260627-070037.json.",
  "contribution_claims": [
    "The ARES-Harness defense: a composable default-on deterministic layer (five-stage input path + LLM-free action-authorization gate keyed on (capability_class, arg-provenance-taint), provenance derived harness-side from raw bytes) that converts an indirect injection into a data-integrity decision and holds privileged-action ASR at 0 by construction on the environment-state task class, model- and N-independent.",
    "A pre-registered, benchmark-anchored measurement (AgentDojo banking) delivering the no-headroom-regime finding: undefended ASR=0 across the grid, the gate empirically non-vacuous (2 denials of injected privileged tainted calls vs 0 in the no-gate arms), and the honest cost (0.20 benign false-block within the pre-registered <=0.50 band).",
    "Conclusion-integrity as a measurement axis the standard action-authorization benchmarks do not score, and the argued claim that on modern models decision-integrity + the measured cost of deterministic guarantees, not an action-ASR-delta, is the axis worth evaluating.",
    "Honesty boundary: this is a mechanism contribution + a pre-registered empirical regime characterization, NOT a demonstrated defended-vs-undefended ASR-delta (there is none to claim; undefended ASR is already 0)."
  ],
  "result_findings": {
    "finding_1_no_headroom_regime": {
      "session": "S099",
      "one_line_claim": "Undefended ASR = 0 across all 4 sweep cells; the no-cell contingency fired; modern frontier models resist the action axis on banking.",
      "data_source": "data/paper_5/s099_phase3_run_20260627-070037.json"
    },
    "finding_2_guarantee_nonvacuous": {
      "session": "S099",
      "one_line_claim": "full_defense ASR=0 by construction with 2 empirical gate denials of injected privileged tainted calls; undefended/gate_off issue 0 denials, proving the denials are the gate.",
      "data_source": "data/paper_5/s099_phase3_run_20260627-070037.json"
    },
    "finding_3_honest_cost": {
      "session": "S099",
      "one_line_claim": "Benign false-block 0.20 (4/20) within the pre-registered <=0.50 band; utility 0.50 -> 0.30 under full_defense.",
      "data_source": "data/paper_5/s099_phase3_run_20260627-070037.json"
    },
    "finding_4_conclusion_integrity": {
      "session": "S099",
      "one_line_claim": "Conclusion-integrity 0.95 (echo 0.05) across all arms - a level, high also undefended, not a defense-attributable delta at N=20.",
      "data_source": "data/paper_5/s099_phase3_run_20260627-070037.json"
    }
  },
  "sections": [
    { "section_id": "in_plain_terms", "section_number": null, "title": "In Plain Terms", "target_words": 400, "claims": ["Plain-language anchor: a deterministic AI-free gate stops an injected tool action; on modern models the attack already fails, so the result is the guarantee + the regime + the honest cost."], "numbers_preregistered": ["0.0", "0.2", "0.95"], "bibkeys_required": [], "figures": [], "tables": [] },
    { "section_id": "abstract", "section_number": null, "title": "Abstract", "target_words": 250, "claims": ["Tool-agent injection -> deterministic guarantee + no-headroom regime -> findings -> reproducibility."], "numbers_preregistered": ["0.0", "0.2", "0.95", "$3.8"], "bibkeys_required": ["gmys-casiano-2026a", "gmys-casiano-2026b", "gmys-casiano-2026c", "gmys-casiano-2026d"], "figures": [], "tables": [] },
    { "section_id": "introduction", "section_number": 1, "title": "Introduction", "target_words": 650, "claims": ["The two pillars (guarantee + regime); the honesty boundary (no ASR-delta) stated here; three contributions; roadmap."], "numbers_preregistered": ["0.0", "2"], "bibkeys_required": ["greshake-2023", "debenedetti-2025-camel", "debenedetti-2024-agentdojo", "gmys-casiano-2026a", "gmys-casiano-2026d"], "figures": [], "tables": [] },
    { "section_id": "background_threat_model", "section_number": 2, "title": "Background and Threat Model", "target_words": 850, "claims": ["Indirect/second-order injection; tool-using agents; SOTA action-surface defenses; benchmarks; the decision-integrity gap; defender/attacker/scope."], "numbers_preregistered": [], "bibkeys_required": ["greshake-2023", "debenedetti-2025-camel", "willison-2023-dualllm", "hines-2024-spotlighting", "wallace-2024-instruction-hierarchy", "chen-2024-struq", "chen-2024-secalign", "zhan-2024-injecagent", "yi-2023-bipia", "debenedetti-2024-agentdojo"], "figures": [], "tables": ["tbl_4"] },
    { "section_id": "ares_harness_architecture", "section_number": 3, "title": "The ARES-Harness Architecture", "target_words": 900, "claims": ["Five-stage input path; inert-rendering by provenance (control-data separation); middleware composition; harness-side provenance from raw bytes; fail-closed everywhere."], "numbers_preregistered": [], "bibkeys_required": ["willison-2023-dualllm", "gmys-casiano-2026d"], "figures": ["fig_1"], "tables": [] },
    { "section_id": "action_gate_guarantee", "section_number": 4, "title": "The Deterministic Action Gate and Its Guarantee", "target_words": 750, "claims": ["Capability classes; arg-provenance-taint (fail-safe); the pure decision rule; monotone-in-taint; never consults model text; by-construction ASR=0 on the env-state class; positioned vs CaMeL."], "numbers_preregistered": ["0.0"], "bibkeys_required": ["debenedetti-2025-camel"], "figures": ["fig_6"], "tables": [] },
    { "section_id": "methodology", "section_number": 5, "title": "Methodology: a Pre-Registered Benchmark Measurement", "target_words": 1100, "claims": ["AgentDojo v1.2 banking; grid + env-state filter; eligible injection tasks; two-stage pre-registration + SSOT lock + release token; arms; metrics (ASR / gate denials / false-block / conclusion-integrity echo-check); cost model; reproduction."], "numbers_preregistered": ["0.2", "20", "9"], "bibkeys_required": ["debenedetti-2024-agentdojo", "albanie-2022"], "figures": [], "tables": ["tbl_1"] },
    { "section_id": "results", "section_number": 6, "title": "Results", "target_words": 1300, "load_bearing": true, "claims": ["F1 (headline): the no-headroom regime - undefended ASR=0 all 4 cells, no-cell contingency, fallback cell.", "F2: the guarantee holds and is non-vacuous - full_defense ASR=0 by construction + 2 gate denials, gate_off vs full_defense.", "F3: the honest cost - benign false-block 0.20 within band, utility 0.50->0.30.", "F4: conclusion-integrity 0.95 (level-not-delta honesty)."], "numbers_preregistered": ["0.0", "0.5", "0.3", "0.45", "2", "0", "0.95", "0.05", "0.2", "4", "20", "96", "0.75"], "bibkeys_required": [], "figures": ["fig_2", "fig_3", "fig_4"], "tables": ["tbl_2", "tbl_3"] },
    { "section_id": "positioning_vs_sota", "section_number": 7, "title": "Positioning vs SOTA", "target_words": 700, "claims": ["The decision-integrity axis; CaMeL head-on (lighter single-hop provenance-taint vs interpreter-IFC); inert-rendering vs spotlighting/dual-LLM; deterministic code vs learned priority; the regex/IOC substrate is not novel (cite the read-depth trilemma)."], "numbers_preregistered": [], "bibkeys_required": ["debenedetti-2025-camel", "willison-2023-dualllm", "hines-2024-spotlighting", "wallace-2024-instruction-hierarchy", "chen-2024-struq", "chen-2024-secalign", "gmys-casiano-2026d"], "figures": ["fig_5"], "tables": [] },
    { "section_id": "discussion", "section_number": 8, "title": "Discussion", "target_words": 900, "claims": ["What the no-headroom regime means for injection-defense evaluation; decision-integrity + cost as the forward axis; deterministic guarantee vs learned resistance; when by-construction beats measured-delta."], "numbers_preregistered": ["0.0"], "bibkeys_required": ["gmys-casiano-2026a", "gmys-casiano-2026d"], "figures": [], "tables": [] },
    { "section_id": "limitations", "section_number": 9, "title": "Limitations", "target_words": 550, "claims": ["The result is a contingency (no ASR headroom); N=20 CIs; single benchmark/suite/cell; integrity-as-level not delta; deterministic scan != semantic framing; finer component ablation deferred."], "numbers_preregistered": ["0.0", "20"], "bibkeys_required": ["gmys-casiano-2026d"], "figures": [], "tables": [] },
    { "section_id": "future_work", "section_number": 10, "title": "Future Work", "target_words": 400, "claims": ["The deferred scan/quarantine/normalize component ablation; the OOV-adversary fuzz at the production firewall + IOC rung; weaker-model / harder-corpus to recover ASR headroom; second suite; escalate-to-human hook."], "numbers_preregistered": [], "bibkeys_required": [], "figures": [], "tables": [] },
    { "section_id": "references", "section_number": 11, "title": "References", "target_words": 0, "claims": [], "numbers_preregistered": [], "bibkeys_required": [], "figures": [], "tables": [] }
  ],
  "figures": [
    { "id": "fig_1", "type": "conceptual_diagram", "purpose": "The ARES-Harness architecture: five-stage input path (capture/normalize/ingress-scan/IOC-anchor/quarantine) + action gate + middleware; control-data separation; fail-closed.", "source": "new - derived from ares/harness/{capture,normalize,ingress_scan,ioc_anchor,quarantine,action_gate,middleware}.py", "host_section": 3 },
    { "id": "fig_2", "type": "scatter_plot", "purpose": "THE money figure: regime + guarantee. Left panel: undefended ASR=0 across all 4 cells (no headroom). Right panel: the gate decision rule (capability_class x arg-taint) -> allow/deny holding the env-state class at 0 by construction, annotated with the 2 empirical denials.", "source": "data/paper_5/s099_phase3_run_20260627-070037.json sweep[].undefended_asr + stage1_arms.full_defense.gate_denials", "host_section": 6 },
    { "id": "fig_3", "type": "bar_chart", "purpose": "Arms on the fallback cell: undefended / full_defense / gate_off x {ASR, utility, gate denials, conclusion-integrity}.", "source": "data/paper_5/s099_phase3_run_20260627-070037.json stage1_arms", "host_section": 6 },
    { "id": "fig_4", "type": "bar_chart", "purpose": "The honest cost: benign false-block 0.20 inside the pre-registered <=0.50 band; utility cost 0.50->0.30.", "source": "data/paper_5/s099_phase3_run_20260627-070037.json benign_false_block.full_defense + stage1_arms utilities", "host_section": 6 },
    { "id": "fig_5", "type": "conceptual_diagram", "purpose": "SOTA positioning: surface-guarded matrix with the decision-integrity axis called out.", "source": "new - derived from design spec section 13 SOTA matrix", "host_section": 7 },
    { "id": "fig_6", "type": "pipeline_diagram", "purpose": "Worked example: an injected banking task -> captured untrusted bill text -> harness-side taint of the send_money target arg -> gate denial.", "source": "new - derived from ares/harness/provenance_tracker.py + action_gate.py", "host_section": 4 }
  ],
  "tables": [
    { "id": "tbl_1", "purpose": "Pre-registered grid + protocol; columns (model, attack, suite, tau_asr, tau_util, N, N_benign, false_block_band, planted_IBAN).", "source": "docs/paper_5/PREREGISTRATION_phase3_measurement.md + run JSON tau_asr/tau_util/eligible_injection_tasks", "host_section": 5 },
    { "id": "tbl_2", "purpose": "Stage-0 sweep: undefended ASR + utility per cell; columns (model, attack, undefended_asr, undefended_utility).", "source": "data/paper_5/s099_phase3_run_20260627-070037.json sweep", "host_section": 6 },
    { "id": "tbl_3", "purpose": "Stage-1 arms on the fallback cell; columns (arm, asr, utility, gate_denials, echo_rate, conclusion_integrity).", "source": "data/paper_5/s099_phase3_run_20260627-070037.json stage1_arms", "host_section": 6 },
    { "id": "tbl_4", "purpose": "SOTA positioning: surface guarded x ARES delta; columns (system, surface_guarded, ares_delta).", "source": "new - design spec section 13 SOTA matrix", "host_section": 7 }
  ],
  "numbers_preregistered": [
    { "value": 0.0, "source": "S099 run: undefended ASR = 0.0 in every sweep cell AND every Stage-1 arm (the no-headroom contingency).", "lock_target": "s099_phase3_run_20260627-070037.json max(sweep[i].undefended_asr) == 0.0; stage1_arms[arm].asr == 0.0" },
    { "value": 0.5, "source": "S099 run: Stage-1 undefended utility = 0.5; sweep haiku/tool_knowledge undefended utility = 0.5.", "lock_target": "stage1_arms.undefended.utility == 0.5" },
    { "value": 0.75, "source": "S099 run: sweep sonnet undefended utility = 0.75 (both attacks).", "lock_target": "sweep[sonnet-4-6/important_instructions].undefended_utility == 0.75" },
    { "value": 0.3, "source": "S099 run: Stage-1 full_defense utility = 0.3; benign utility = 0.3.", "lock_target": "stage1_arms.full_defense.utility == 0.3" },
    { "value": 0.45, "source": "S099 run: Stage-1 gate_off utility = 0.45.", "lock_target": "stage1_arms.gate_off.utility == 0.45" },
    { "value": 2, "source": "S099 run: full_defense gate_denials = 2 (the empirical non-vacuity headline).", "lock_target": "stage1_arms.full_defense.gate_denials == 2" },
    { "value": 0, "source": "S099 run: undefended + gate_off gate_denials = 0 (no gate -> the denials are the gate).", "lock_target": "stage1_arms.undefended.gate_denials == 0 and stage1_arms.gate_off.gate_denials == 0" },
    { "value": 0.95, "source": "S099 run: conclusion_integrity_rate = 0.95 (all arms; a level, high also undefended).", "lock_target": "stage1_arms.full_defense.conclusion_integrity_rate == 0.95" },
    { "value": 0.05, "source": "S099 run: echo_rate = 0.05 (all arms).", "lock_target": "stage1_arms.full_defense.echo_rate == 0.05" },
    { "value": 0.2, "source": "S099 run: benign false_block_rate_per_task = 0.2 (within <=0.50 band); also tau_asr = tau_util = 0.2.", "lock_target": "benign_false_block.full_defense.false_block_rate_per_task == 0.2; tau_asr == 0.2" },
    { "value": 4, "source": "S099 run: benign denials = 4 (of 20).", "lock_target": "benign_false_block.full_defense.benign_denials == 4" },
    { "value": 20, "source": "S099 run + prereg: N = 20, N_benign = 20 (per-arm n).", "lock_target": "stage1_arms.full_defense.n == 20 (prereg _FROZEN_N == 20)" },
    { "value": 9, "source": "S099 run + prereg: 9 eligible banking injection tasks (injection_task_0..8, all ENV_STATE).", "lock_target": "len(eligible_injection_tasks.banking) == 9" },
    { "value": 96, "source": "S099 run: 96 rollouts, no abort.", "lock_target": "rollouts == 96" },
    { "value": "$3.8", "source": "S099 result note section 5: refined Phase-3 total cost ~= $3.8 (~$3.7 actual + ~$0.07 calibration). NOTE-ONLY - not in the run JSON; locked by prose substring + PDF gate, not a JSON resolver.", "lock_target": "docs/paper_5/S099_PHASE3_MEASUREMENT_RESULT_2026-06-27.md section 5 (prose substring + verify_pdf_substrings.py)" },
    { "value": "US133000000121212121212", "source": "S099 result note section 4: planted attacker IBAN for the conclusion-integrity echo-check. NOTE-ONLY - not in the run JSON; locked by prose substring + PDF gate.", "lock_target": "docs/paper_5/S099_PHASE3_MEASUREMENT_RESULT_2026-06-27.md section 4 (prose substring + verify_pdf_substrings.py)" }
  ],
  "bibkeys_required_verified": [
    { "bibkey": "greshake-2023", "role": "Indirect prompt injection (sections 1/2). Reused verbatim from Paper 4.", "status": "VERIFIED", "source": "Reused from docs/paper_4/references.bib (verified Session 068). Greshake et al., AISec '23, doi 10.1145/3605764.3623985." },
    { "bibkey": "albanie-2022", "role": "Pre-registration in ML evaluation (section 5). Reused verbatim from Paper 4.", "status": "VERIFIED", "source": "Reused from docs/paper_4/references.bib (verified Session 094)." },
    { "bibkey": "gmys-casiano-2026a", "role": "Self-cite Paper 1 (calibration failure). Sections 1/8.", "status": "VERIFIED", "source": "Reused from docs/paper_4/references.bib. Canonical PDF docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf." },
    { "bibkey": "gmys-casiano-2026b", "role": "Self-cite Paper 2. Sections 1/8.", "status": "VERIFIED", "source": "Reused from docs/paper_4/references.bib. Canonical docs/paper_2/PAPER2_DRAFT_v1_2.docx." },
    { "bibkey": "gmys-casiano-2026c", "role": "Self-cite Paper 3 (decision determinism, explanation drift). Sections 1/7/8.", "status": "VERIFIED", "source": "Reused from docs/paper_4/references.bib. Canonical docs/paper_3/acmart_spike/paper_3_acmart.pdf." },
    { "bibkey": "gmys-casiano-2026d", "role": "Self-cite Paper 4 (read-depth robustness trilemma; the deterministic-scan limit). Sections 7/9.", "status": "VERIFIED", "source": "New self-cite. Canonical docs/paper_4/acmart/paper_4_acmart.pdf." }
  ],
  "bibkeys_needed_unverified": [
    { "slug": "debenedetti-2025-camel", "verification_instructions": "Web-verify: Debenedetti et al., 'Defeating Prompt Injections by Design' (CaMeL), arXiv 2503.18813 (2025). Confirm authors/title/arXiv ID/venue." },
    { "slug": "debenedetti-2024-agentdojo", "verification_instructions": "Web-verify (THE benchmark anchor): Debenedetti et al., 'AgentDojo', arXiv 2406.13352, NeurIPS 2024 Datasets & Benchmarks. Confirm exactly." },
    { "slug": "willison-2023-dualllm", "verification_instructions": "Web-verify: Simon Willison, 'The Dual LLM pattern for building AI assistants that can resist prompt injection', simonwillison.net, 2023. Cite as @misc with url + howpublished." },
    { "slug": "hines-2024-spotlighting", "verification_instructions": "Web-verify: Hines et al., 'Defending Against Indirect Prompt Injection Attacks With Spotlighting', arXiv 2403.14720 (2024)." },
    { "slug": "wallace-2024-instruction-hierarchy", "verification_instructions": "Web-verify: Wallace et al., 'The Instruction Hierarchy', arXiv 2404.13208 (2024)." },
    { "slug": "chen-2024-struq", "verification_instructions": "Web-verify: Chen et al., 'StruQ: Defending Against Prompt Injection with Structured Queries', arXiv 2402.06363 (2024). Keep key distinct from secalign." },
    { "slug": "chen-2024-secalign", "verification_instructions": "Web-verify: Chen et al., 'SecAlign', arXiv 2410.05451 (2024). Keep key distinct from struq; note the chen-2024 first-author/year collision (disambiguate in prose)." },
    { "slug": "zhan-2024-injecagent", "verification_instructions": "Web-verify: Zhan et al., 'InjecAgent', arXiv 2403.02691 (2024)." },
    { "slug": "yi-2023-bipia", "verification_instructions": "Web-verify: Yi et al., 'Benchmarking and Defending Against Indirect Prompt Injection Attacks' (BIPIA), arXiv 2312.14197 (2023/2024)." }
  ],
  "anchor_tests_required": [
    { "path": "tests/paper_5/test_prereg_bands_match_code.py", "status": "EXISTS (S098/S099)", "locks": "Two-stage pre-registration SSOT: grid / taus / arms / shim / model / max_tokens / eligible injection IDs / N / N_benign / release sentinel." },
    { "path": "tests/harness/test_action_gate_invariants.py", "status": "EXISTS (S097)", "locks": "Action-gate determinism + monotone-in-taint + value-blind (no-LLM) invariants." },
    { "path": "tests/harness/test_action_gate.py", "status": "EXISTS (S097)", "locks": "Action-gate capability classes + fail-safe taint + pure authorize()." },
    { "path": "tests/harness/test_provenance_tracker.py", "status": "EXISTS (S098)", "locks": "Harness-side raw-byte provenance derivation (closes the Phase-2 mislabeling gap)." }
  ],
  "out_of_scope_session_101": [
    "No prose (docs/paper_5/source/ is Phase 3).",
    "No figures (docs/paper_5/build_figures.py + figures/ is Phase 2).",
    "No acmart build / PDF (Phase 4).",
    "No new measurement / no LLM calls.",
    "No edits to existing files except CLAUDE.md at session close."
  ]
}
```

NOTE: `anchor_tests_required` paths above are confirmed-existing in Task 5 Step 2 — if `tests/harness/test_provenance_tracker.py` is named differently on disk, correct the skeleton to the real path before committing.

- [ ] **Step 5: Run the audit — verify it PASSES**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_skeleton_audit.py -q`
Expected: PASS (all ~30 tests). Fix the JSON (never the test contract) until green — e.g. if `test_target_words_sum_within_budget` fails, adjust `target_words_core` toward the actual section sum (currently 8750; 9000 is within tolerance).

- [ ] **Step 6: Commit**

```bash
git add docs/paper_5/skeleton_v1_0.json tests/paper_5/test_skeleton_audit.py
# also add docs/paper_5/__init__.py and/or tests/paper_5/__init__.py if Step 1 created them
git commit -F - <<'EOF'
feat(s100): Paper 5 Phase-1 scaffold - skeleton SSOT + skeleton-audit gate

docs/paper_5/skeleton_v1_0.json: 13 sections (in_plain_terms + abstract
unnumbered, 1..11 numbered, references last), 6 figures, 4 tables, the S099
number registry, verified + needed-unverified bibkeys, anchor tests. Mirrors
Paper 4's schema; the two subset-lock invariants are preserved.
tests/paper_5/test_skeleton_audit.py: ~30 structural assertions.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 2: references.bib + build_references.py + citation-existence gate

**Files:**
- Create: `docs/paper_5/build_references.py` (verbatim copy), `docs/paper_5/references.bib`, `tests/paper_5/test_citation_existence.py`
- Reference: `docs/paper_4/build_references.py`, `docs/paper_4/references.bib`, `tests/paper_4/test_citation_existence.py`

**Interfaces:**
- Consumes: `docs/paper_5/skeleton_v1_0.json` (`bibkeys_required` per section; `bibkeys_needed_unverified` slugs).
- Produces: `docs/paper_5/build_references.py` exporting `parse_bib_file`, `extract_citations`, `citation_to_bibkey` (consumed by `test_citation_existence.py` and later phases); `docs/paper_5/references.bib`.

- [ ] **Step 1: Copy the bib helpers verbatim**

Run: `cp docs/paper_4/build_references.py docs/paper_5/build_references.py`
The file is paper-agnostic stdlib-only (`BibEntry`, `parse_bib`, `parse_bib_file`, `extract_citations`, `citation_to_bibkey`). Optionally update the module docstring's "Paper 3"/"Paper 4" path strings to "Paper 5" — cosmetic only; do NOT change any function body (the regexes are regression-locked).

- [ ] **Step 2: Web-verify the 9 new SOTA bibkeys (REQUIRED before authoring the bib)**

For each slug in the skeleton's `bibkeys_needed_unverified`, confirm author list, exact title, venue, and arXiv ID via web search (the arc-spec §16 IDs are a STARTING POINT, not trusted). Recommended under deep-work mode: fan out one verifier per citation (adversarial — one agent confirms, one tries to prove the ID/title wrong) and only accept a key when both agree. Record each as a `% Provenance: Verified 2026-06-2x (S100) via web search: <full citation>` comment above its entry. Any key that cannot be verified STAYS in `bibkeys_needed_unverified` and is NOT added to the bib (and must then be removed from any section's `bibkeys_required` to keep the citation gate green — but all 9 are well-known real papers and are expected to verify).

- [ ] **Step 3: Write the citation-existence gate (the contract)**

Create `tests/paper_5/test_citation_existence.py`:

```python
"""Every required bibkey resolves in a verified-only references.bib."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from docs.paper_5.build_references import (
    parse_bib_file,
    extract_citations,
    citation_to_bibkey,
)

REPO = Path(__file__).resolve().parents[2]
BIB = REPO / "docs" / "paper_5" / "references.bib"
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"

EXPECTED_VERIFIED_KEYS = [
    "greshake-2023",
    "albanie-2022",
    "gmys-casiano-2026a",
    "gmys-casiano-2026b",
    "gmys-casiano-2026c",
    "gmys-casiano-2026d",
    "debenedetti-2025-camel",
    "debenedetti-2024-agentdojo",
    "willison-2023-dualllm",
    "hines-2024-spotlighting",
    "wallace-2024-instruction-hierarchy",
    "chen-2024-struq",
    "chen-2024-secalign",
    "zhan-2024-injecagent",
    "yi-2023-bipia",
]


@pytest.fixture
def bib_entries():
    return parse_bib_file(BIB)


@pytest.fixture
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


def test_references_bib_parses(bib_entries):
    assert len(bib_entries) == len(EXPECTED_VERIFIED_KEYS)


def test_expected_verified_keys_present(bib_keys):
    for k in EXPECTED_VERIFIED_KEYS:
        assert k in bib_keys, f"missing verified bibkey {k}"


def test_every_entry_has_author_and_year(bib_entries):
    for e in bib_entries:
        # willison-2023-dualllm is a @misc blog; allow howpublished in place of year if needed
        assert e.get("author") or e.get("howpublished"), f"{e.key} has no author/howpublished"
        assert e.get("year"), f"{e.key} has no year"


def test_no_needed_suffix_in_real_bib(bib_keys):
    assert not any(k.endswith("-needed") for k in bib_keys)


def test_unverified_slugs_from_skeleton_not_in_bib(skeleton, bib_keys):
    # After Task 2 web-verification, bibkeys_needed_unverified should be empty;
    # but the invariant holds either way: no needed-slug appears as a real bib key.
    for u in skeleton["bibkeys_needed_unverified"]:
        assert u["slug"] not in bib_keys, f"unverified {u['slug']} leaked into bib"


def test_every_skeleton_required_bibkey_resolves(skeleton, bib_keys):
    for s in skeleton["sections"]:
        for k in s["bibkeys_required"]:
            assert k in bib_keys, f"{s['section_id']} requires {k} not in bib"


def test_self_cite_round_trips_from_narrative_prose():
    cites = extract_citations("As shown by Gmys-Casiano (2026), the gate holds.")
    assert citation_to_bibkey(cites[0]) == "gmys-casiano-2026"
```

NOTE: if Task 2 verification leaves any slug in `bibkeys_needed_unverified`, update `EXPECTED_VERIFIED_KEYS` and `test_references_bib_parses` accordingly AND drop that key from the relevant section's `bibkeys_required` in the skeleton (and re-run Task 1's gate). All 9 are expected to verify.

- [ ] **Step 4: Run the citation gate — verify it FAILS (no bib yet)**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_citation_existence.py -q`
Expected: FAIL (FileNotFoundError on `references.bib`, or ImportError if `docs/paper_5/__init__.py` is missing — fix Task 1 Step 1 if so).

- [ ] **Step 5: Author references.bib (verified-only)**

Create `docs/paper_5/references.bib` UTF-8. Reuse `greshake-2023` and `albanie-2022` verbatim from `docs/paper_4/references.bib` (copy the entry + its `% Provenance:` comment). Copy the four `gmys-casiano-2026a/b/c` self-cites from Paper 4 and ADD `gmys-casiano-2026d` (Paper 4 self-cite, `@article`, `journal={Preprint}`, year 2026, title from `docs/paper_4/skeleton_v1_0.json working_title`). Add the 9 web-verified SOTA entries from Step 2 — arXiv entries use `eprint = {<id>}` + `archivePrefix = {arXiv}` (mirror `guo-2024`'s shape in Paper 4); `willison-2023-dualllm` is `@misc` with `howpublished`/`url`, no eprint. Header comment documents the self-cite map `gmys-casiano-2026a/b/c/d -> Papers 1/2/3/4`. Every entry preceded by a `% Provenance:` comment (NEVER a `note=` field — the S072 deanonymization fix). Canonical bibkeys are `firstauthor-year` (+ topic suffix for the two `chen-2024-*`).

- [ ] **Step 5b: Promote the verified keys in the skeleton (the gate-coupling step)**

Now that the 9 SOTA keys are web-verified and in the bib, update `docs/paper_5/skeleton_v1_0.json`: for each verified key append `{ "bibkey": <key>, "role": <where used>, "status": "VERIFIED", "source": "<provenance from Step 2>" }` to `bibkeys_required_verified`, and set `bibkeys_needed_unverified` to `[]`. (Any key that did NOT verify stays in `bibkeys_needed_unverified` and must be dropped from every section's `bibkeys_required` — but all 9 are expected to verify.) This preserves the discipline's invariant: a key is EITHER verified-in-bib-and-in-the-verified-list OR unverified-in-needed-and-absent-from-bib — never both (which is exactly what `test_unverified_slugs_from_skeleton_not_in_bib` enforces).

- [ ] **Step 6: Run BOTH gates — verify they PASS**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_citation_existence.py tests/paper_5/test_skeleton_audit.py -q`
Expected: PASS. The citation gate confirms every section's `bibkeys_required` resolves and no needed-slug leaked into the bib; the re-run skeleton-audit confirms the promoted keys still satisfy the structural invariants. Fix the bib/skeleton (never the test contract) until green.

- [ ] **Step 7: Commit**

```bash
git add docs/paper_5/build_references.py docs/paper_5/references.bib docs/paper_5/skeleton_v1_0.json tests/paper_5/test_citation_existence.py
git commit -F - <<'EOF'
feat(s100): Paper 5 scaffold - verified-only references.bib + citation gate

build_references.py copied verbatim (paper-agnostic helpers). references.bib:
greshake-2023 + albanie-2022 reused, self-cites a-d (Paper 4 = d added), 9
web-verified SOTA keys (CaMeL/AgentDojo/dual-LLM/spotlighting/instruction-
hierarchy/StruQ/SecAlign/InjecAgent/BIPIA). Skeleton updated: verified keys
promoted to bibkeys_required_verified, bibkeys_needed_unverified emptied.
test_citation_existence.py enforces resolution.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 3: number_check.py + S099 resolvers + number-check gate

**Files:**
- Create: `docs/paper_5/number_check.py`, `tests/paper_5/test_number_check.py`
- Reference: `docs/paper_4/number_check.py`, `tests/paper_4/test_number_check.py`, `data/paper_5/s099_phase3_run_20260627-070037.json`

**Interfaces:**
- Consumes: the run JSON + `docs/paper_5/skeleton_v1_0.json`.
- Produces: `number_check.py` exporting `default_claims(skeleton)`, `run_checks(claims)`, `main(argv)`, `check_prose_substrings(text, claims)`, `prose_substring_claims()`, and the `_resolve_*` functions (consumed by `test_number_check.py` + Phase-4 PDF gate).

- [ ] **Step 1: Read the run JSON to confirm the exact shapes**

Run: `"/c/Program Files/Python311/python.exe" -c "import json,pathlib; d=json.loads(pathlib.Path('data/paper_5/s099_phase3_run_20260627-070037.json').read_text(encoding='utf-8')); print(list(d.keys())); print(d['stage1_arms']['full_defense']); print(d['benign_false_block']); print([(c['model'],c['attack'],c['undefended_asr'],c['undefended_utility']) for c in d['sweep']]); print(d['selected_cell'], d['no_cell_contingency'], d['run_cell']['model'], d['rollouts'])"`
Confirm: flat object; `stage1_arms.full_defense.gate_denials == 2`; `benign_false_block.full_defense.false_block_rate_per_task == 0.2`; all `undefended_asr == 0.0`; `selected_cell is None`; `rollouts == 96`. If any key differs, correct the resolvers below to match the real keys (the artifact is canonical).

- [ ] **Step 2: Copy the engine + replace the Paper-4-specific parts**

Run: `cp docs/paper_4/number_check.py docs/paper_5/number_check.py`
Keep verbatim: `Claim`, `CheckResult`, `run_checks`, `render_report`, `write_report`, `extract_docx_text`, `check_prose_substrings`, `build_arg_parser`/`main` (the engine + CLI). REPLACE these blocks:

(a) the module path constants — replace the `FRONTIER_DIR`/`OOV_DIR`/`TIER4`/`OOV_*` block with:
```python
REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_5" / "skeleton_v1_0.json"
RUN = REPO_ROOT / "data" / "paper_5" / "s099_phase3_run_20260627-070037.json"


def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))
```

(b) DELETE all 13 read-depth `_resolve_*` + `_tier4_coord`, and ADD the S099 resolvers:
```python
def _run() -> dict:
    return _load(RUN)


def _arm(name: str) -> dict:
    return _run()["stage1_arms"][name]


def _resolve_max_undefended_asr() -> float:
    # The no-headroom contingency: 0.0 across every sweep cell.
    return max(c["undefended_asr"] for c in _run()["sweep"])


def _resolve_full_defense_asr() -> float:
    return _arm("full_defense")["asr"]


def _resolve_full_defense_gate_denials() -> int:
    return _arm("full_defense")["gate_denials"]


def _resolve_undefended_gate_denials() -> int:
    return _arm("undefended")["gate_denials"]


def _resolve_gate_off_gate_denials() -> int:
    return _arm("gate_off")["gate_denials"]


def _resolve_undefended_utility() -> float:
    return _arm("undefended")["utility"]


def _resolve_full_defense_utility() -> float:
    return _arm("full_defense")["utility"]


def _resolve_gate_off_utility() -> float:
    return _arm("gate_off")["utility"]


def _resolve_sonnet_ii_utility() -> float:
    for c in _run()["sweep"]:
        if c["model"] == "sonnet-4-6" and c["attack"] == "important_instructions":
            return c["undefended_utility"]
    raise LookupError("sonnet-4-6/important_instructions cell not found")


def _resolve_conclusion_integrity() -> float:
    return _arm("full_defense")["conclusion_integrity_rate"]


def _resolve_echo_rate() -> float:
    return _arm("full_defense")["echo_rate"]


def _resolve_benign_false_block() -> float:
    return _run()["benign_false_block"]["full_defense"]["false_block_rate_per_task"]


def _resolve_benign_denials() -> int:
    return _run()["benign_false_block"]["full_defense"]["benign_denials"]


def _resolve_n() -> int:
    return _arm("full_defense")["n"]


def _resolve_eligible_injection_count() -> int:
    return len(_run()["eligible_injection_tasks"]["banking"])


def _resolve_rollouts() -> int:
    return _run()["rollouts"]


def _resolve_tau_asr() -> float:
    return _run()["tau_asr"]


def _resolve_selected_cell_is_null() -> bool:
    return _run()["selected_cell"] is None and _run()["no_cell_contingency"] is True


def _resolve_fallback_cell() -> tuple:
    rc = _run()["run_cell"]
    return (rc["model"], rc["attack"], rc["suite"])


def _resolve_test_floor_from_skeleton(skeleton: dict) -> int:
    return int(skeleton["build_start_test_floor"])
```

(c) REPLACE `default_claims(skeleton)` with:
```python
def default_claims(skeleton: dict) -> tuple[Claim, ...]:
    return (
        Claim("max undefended ASR == 0.0 (no-headroom contingency)", 0.0, _resolve_max_undefended_asr),
        Claim("full_defense ASR == 0.0 (by construction)", 0.0, _resolve_full_defense_asr),
        Claim("full_defense gate denials == 2 (empirical non-vacuity)", 2, _resolve_full_defense_gate_denials),
        Claim("undefended gate denials == 0", 0, _resolve_undefended_gate_denials),
        Claim("gate_off gate denials == 0", 0, _resolve_gate_off_gate_denials),
        Claim("undefended utility == 0.5", 0.5, _resolve_undefended_utility),
        Claim("full_defense utility == 0.3", 0.3, _resolve_full_defense_utility),
        Claim("gate_off utility == 0.45", 0.45, _resolve_gate_off_utility),
        Claim("sonnet/important_instructions undefended utility == 0.75", 0.75, _resolve_sonnet_ii_utility),
        Claim("conclusion-integrity == 0.95", 0.95, _resolve_conclusion_integrity),
        Claim("echo rate == 0.05", 0.05, _resolve_echo_rate),
        Claim("benign false-block == 0.2", 0.2, _resolve_benign_false_block),
        Claim("benign denials == 4", 4, _resolve_benign_denials),
        Claim("N == 20", 20, _resolve_n),
        Claim("eligible banking injection tasks == 9", 9, _resolve_eligible_injection_count),
        Claim("rollouts == 96", 96, _resolve_rollouts),
        Claim("tau_asr == 0.2", 0.2, _resolve_tau_asr),
        Claim("selected_cell null + contingency fired", True, _resolve_selected_cell_is_null),
        Claim("fallback cell == haiku-4-5/important_instructions/banking",
              ("haiku-4-5", "important_instructions", "banking"), _resolve_fallback_cell),
        Claim("test floor parses to int", _resolve_test_floor_from_skeleton(skeleton),
              lambda: _resolve_test_floor_from_skeleton(skeleton)),
    )
```

(d) REPLACE `prose_substring_claims()` with Paper 5's load-bearing substrings (dollar-prefixed costs per spec §8; these feed both the prose check and the Phase-4 PDF gate):
```python
def prose_substring_claims() -> tuple[str, ...]:
    return (
        "no-headroom", "by construction", "contingency",
        "conclusion-integrity", "AgentDojo", "banking",
        "important_instructions", "full_defense", "gate_off", "undefended",
        "2 ", "0.20", "0.30", "0.45", "0.50", "0.95", "0.05", "0.75",
        "US133000000121212121212", "$3.8", "$0.07", "96",
    )
```
(Update `SKELETON_PATH` references and the `--out-report` default to `docs/paper_5/number_check_report.md`; the `--source` default to `docs/paper_5/source/PAPER5_DRAFT_v1_0_source.md`. Keep `main`'s exit-1-on-fail behavior.)

NOTE on float equality: `run_checks` compares with `==`. The JSON stores real floats (`0.2`, `0.3`, `0.95`); `0.2 == 0.20` so the expected literals above are safe. If any value is a `/20` quotient stored unrounded (e.g. `0.9500000001`), match the artifact's serialized value exactly (read it in Step 1) rather than the rounded literal.

- [ ] **Step 3: Write the number-check gate (the contract, incl. both subset locks + dormant prose)**

Create `tests/paper_5/test_number_check.py`:

```python
"""Number-check resolvers + the two subset locks + dormant prose lock."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from docs.paper_5 import number_check as nc

REPO = Path(nc.__file__).resolve().parents[2]
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"
SOURCE = REPO / "docs" / "paper_5" / "source" / "PAPER5_DRAFT_v1_0_source.md"


def _sk() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


class TestResolvers:
    def test_max_undefended_asr_zero(self):
        assert nc._resolve_max_undefended_asr() == 0.0

    def test_full_defense_asr_zero(self):
        assert nc._resolve_full_defense_asr() == 0.0

    def test_full_defense_gate_denials_two(self):
        assert nc._resolve_full_defense_gate_denials() == 2

    def test_undefended_and_gate_off_denials_zero(self):
        assert nc._resolve_undefended_gate_denials() == 0
        assert nc._resolve_gate_off_gate_denials() == 0

    def test_utilities(self):
        assert nc._resolve_undefended_utility() == 0.5
        assert nc._resolve_full_defense_utility() == 0.3
        assert nc._resolve_gate_off_utility() == 0.45
        assert nc._resolve_sonnet_ii_utility() == 0.75

    def test_conclusion_integrity_and_echo(self):
        assert nc._resolve_conclusion_integrity() == 0.95
        assert nc._resolve_echo_rate() == 0.05

    def test_benign_false_block(self):
        assert nc._resolve_benign_false_block() == 0.2
        assert nc._resolve_benign_denials() == 4

    def test_protocol_counts(self):
        assert nc._resolve_n() == 20
        assert nc._resolve_eligible_injection_count() == 9
        assert nc._resolve_rollouts() == 96
        assert nc._resolve_tau_asr() == 0.2

    def test_contingency_and_fallback(self):
        assert nc._resolve_selected_cell_is_null() is True
        assert nc._resolve_fallback_cell() == ("haiku-4-5", "important_instructions", "banking")


class TestHarness:
    def test_run_checks_all_pass(self):
        results = nc.run_checks(nc.default_claims(_sk()))
        failed = [r.label for r in results if not r.passed]
        assert not failed, f"failing claims: {failed}"

    def test_main_exits_zero(self, tmp_path):
        out = tmp_path / "report.md"
        assert nc.main(["--out-report", str(out)]) == 0


class TestSkeletonSourceConsistency:
    # Every registry number in `covered` must be backed by a passing resolver.
    COVERED = {
        "0.0", "0.5", "0.75", "0.3", "0.45",
        "0.95", "0.05", "0.2", "2", "0", "4", "20", "9", "96",
    }

    def test_covered_skeleton_numbers_have_passing_resolvers(self):
        results = nc.run_checks(nc.default_claims(_sk()))
        resolved = {str(r.actual) for r in results if r.passed}
        for n in _sk()["numbers_preregistered"]:
            v = str(n["value"])
            if v in self.COVERED:
                assert v in resolved, f"registry {v} has no passing resolver"


@pytest.mark.skipif(not SOURCE.exists(), reason="Phase-3 prose not yet authored")
class TestProse:
    def _source_text(self) -> str:
        return SOURCE.read_text(encoding="utf-8")

    def test_source_contains_all_prose_substrings(self):
        results = nc.check_prose_substrings(self._source_text(), nc.prose_substring_claims())
        missing = [r.label for r in results if not r.passed]
        assert not missing, f"missing prose substrings: {missing}"

    def test_main_source_mode_exits_zero(self, tmp_path):
        out = tmp_path / "report.md"
        assert nc.main(["--out-report", str(out), "--source", str(SOURCE)]) == 0
```

- [ ] **Step 4: Run the number gate — verify RED then GREEN**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_number_check.py -q`
First run (before Step 2 edits land cleanly): expect failures/errors. After the resolvers + `default_claims` + the `COVERED` set match the skeleton registry: expect PASS, with `TestProse` SKIPPED (prose not authored yet — correct for Phase 1). Reconcile `COVERED` ⊆ resolved and skeleton-registry ⊇ `COVERED` until green.

- [ ] **Step 5: Generate the report artifact**

Run: `"/c/Program Files/Python311/python.exe" -m docs.paper_5.number_check`
Expected: writes `docs/paper_5/number_check_report.md`, prints `[NUMBER-CHECK] 20/20 claims validated`, exit 0.

- [ ] **Step 6: Commit**

```bash
git add docs/paper_5/number_check.py docs/paper_5/number_check_report.md tests/paper_5/test_number_check.py
git commit -F - <<'EOF'
feat(s100): Paper 5 scaffold - number_check resolvers + number gate

number_check.py resolvers locked to data/paper_5/s099_phase3_run_20260627-
070037.json (max undefended ASR 0.0, full_defense gate_denials 2, benign
false-block 0.2, conclusion-integrity 0.95, N 20, rollouts 96, the contingency
+ fallback cell). prose_substring_claims() locks the $3.8/$0.07 + IBAN for the
Phase-4 PDF gate. test_number_check.py: resolvers + both subset locks + dormant
TestProse (skips until Phase-3 prose).

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 4: Full-suite regression + no-artifact-mutation + scaffold sign-off

**Files:** none created (verification only).

- [ ] **Step 1: Run the Paper 5 gates together**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/ -q`
Expected: PASS (skeleton-audit + citation-existence + number-check + the pre-existing `test_prereg_bands_match_code.py`; `TestProse` skipped).

- [ ] **Step 2: Run the full suite (record the new count for the floor bump)**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/ ares/dialectic/tests/ -q 2>&1 | tail -5`
Expected: 0 failures / 0 collection errors. Record the passing count (will be 4,476 + the new Paper-5 gate tests). This number is the new floor for Task 6.

- [ ] **Step 3: Confirm no artifact or existing file was mutated**

Run: `git status --short data/ docs/paper_5/PREREGISTRATION_phase3_measurement.md ares/`
Expected: EMPTY (resolvers are read-only; new-files-only honored). If anything shows, revert it — the artifacts are canonical.

- [ ] **Step 4: Commit (only if any report/no-op changes need recording; otherwise skip)**

No commit unless Step 2 surfaced a fix. Sign-off is the green full suite.

---

## Task 5: Anchor-existence cross-check (skeleton claims -> existing locks)

**Files:**
- Create: `tests/paper_5/test_anchor_existence.py`
- Reference: `docs/paper_5/skeleton_v1_0.json`

**Interfaces:**
- Consumes: `skeleton["anchor_tests_required"]`.

- [ ] **Step 1: Write the anchor-existence test**

Create `tests/paper_5/test_anchor_existence.py`:

```python
"""Every anchor the skeleton claims must exist on disk (spec section 9 cross-check)."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[2]
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


def test_anchor_paths_exist_on_disk(skeleton):
    missing = []
    for a in skeleton["anchor_tests_required"]:
        if not (REPO / a["path"]).exists():
            missing.append(a["path"])
    assert not missing, f"skeleton claims non-existent anchors: {missing}"
```

- [ ] **Step 2: Confirm the anchor paths and run GREEN**

Run: `ls tests/paper_5/test_prereg_bands_match_code.py tests/harness/test_action_gate_invariants.py tests/harness/test_action_gate.py tests/harness/test_provenance_tracker.py`
If `tests/harness/test_provenance_tracker.py` (or any) is named differently, fix the path in `skeleton_v1_0.json anchor_tests_required` (and re-run Task 1's gate). Then:
Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/paper_5/test_anchor_existence.py -q`
Expected: PASS.

- [ ] **Step 3: Commit**

```bash
git add tests/paper_5/test_anchor_existence.py
# include docs/paper_5/skeleton_v1_0.json if an anchor path was corrected
git commit -F - <<'EOF'
feat(s100): Paper 5 scaffold - anchor-existence cross-check gate

test_anchor_existence.py asserts every skeleton anchor_tests_required path
(prereg SSOT, action-gate invariants, provenance_tracker) exists on disk.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

---

## Task 6: CLAUDE.md update + branch housekeeping (session close)

**Files:**
- Modify: `CLAUDE.md` (the only existing-file edit in this plan).

- [ ] **Step 1: Bump the test floor**

Edit `CLAUDE.md` line `**Test count floor (passing):** 4,476` to the count recorded in Task 4 Step 2 (4,476 + new gate tests).

- [ ] **Step 2: Add the Canonical-Artifacts paths + a Key-Code-Locations block**

Add to the Canonical Artifacts list: `docs/paper_5/skeleton_v1_0.json`, `docs/paper_5/references.bib`, `docs/paper_5/number_check.py`, `docs/paper_5/build_references.py`. Add a "Paper 5 scaffold" subsection under Key Code Locations mirroring the Paper 4 scaffold entry (spec/plan paths, skeleton, gates, anchors).

- [ ] **Step 3: Add the session ledger + branch record**

Add an S100 ledger bullet (Paper 5 design spec + Phase-1 scaffold) and a branch-section record. Keep the 40k context-hygiene ceiling (roll the oldest full session to `docs/SESSION_LOG.md` if needed).

- [ ] **Step 4: Run the freshness gate**

Run: `"/c/Program Files/Python311/python.exe" -m pytest tests/test_claude_md_freshness.py -q`
Expected: PASS (declared floor <= actual count AND every declared Canonical-Artifacts path exists on disk).

- [ ] **Step 5: Commit**

```bash
git add CLAUDE.md
git commit -F - <<'EOF'
docs(s100): Paper 5 Phase-1 scaffold - CLAUDE.md floor + paths + ledger

Floor 4,476 -> <new count>. Canonical Paper 5 scaffold artifacts + Key Code
Locations + S100 ledger/branch record.

Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>
EOF
```

The squash-merge to `main` happens via the `ares-session-close` skill at session end, not here.

---

## Self-Review (completed during plan authoring)

**Spec coverage:** §5 section skeleton → Task 1 (skeleton sections + audit). §6 evidence-to-claim map → Task 3 (resolvers locked to the run JSON) + the Number-reconciliation table. §7 figures/tables → Task 1 (figure/table objects + host-section linkage). §8 gates → Tasks 1/2/3 (skeleton-audit / citation-existence / number-check) + the Phase-4 PDF gate named in Scope. §9 anchors → Task 5 (anchor-existence cross-check) + the skeleton's `anchor_tests_required`. §10 bib plan → Task 2 (reuse + self-cites a–d + 9 web-verified SOTA keys + verified-only discipline). §11 scope → the Scope section (Phase 1 only; Phases 2–4 named). §12 limitations → encoded in the skeleton's limitations section claims.

**Placeholder scan:** No "TBD"/"TODO" in steps. Resolvers are concrete with exact JSON key paths. The 9 SOTA bibkeys are intentionally `bibkeys_needed_unverified` until Task 2's web-verification (the verified-only discipline — not placeholders). `$3.8`/IBAN are explicitly note-only with markdown lock_targets, deliberately excluded from JSON resolvers and the `COVERED` set.

**Type consistency:** Resolver names in `number_check.py` (Task 3 Step 2) match exactly the names asserted in `test_number_check.py` (Task 3 Step 3) and bound in `default_claims`. The `COVERED` set strings are the `str()` forms of the resolver return values and a subset of the skeleton registry `value` str-renderings (the double subset lock). Section `numbers_preregistered` tokens are all members of the registry (skeleton-audit `test_section_numbers_preregistered_are_subset_of_top_level`). `EXPECTED_VERIFIED_KEYS` in the citation test matches the skeleton's `bibkeys_required_verified` + the verified SOTA keys.

## Execution Handoff

After this plan is approved, build it with **subagent-driven-development** (recommended — fresh subagent per task, two-stage review between tasks; the gate tasks are independent and self-verifying) or **executing-plans** (inline batches with checkpoints). The scaffold is small, self-contained, and offline. The follow-on Phases 2–4 (figures / prose / acmart) each get their own plan when their session arrives.
