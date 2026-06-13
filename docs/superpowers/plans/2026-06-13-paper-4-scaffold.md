# Paper 4 Scaffold (Phase 1) Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the Paper 4 structural scaffold — `skeleton_v1_0.json`, a verified-only `references.bib`, and three verification gates (skeleton audit, citation existence, number-check) — that lock the paper's structure and every load-bearing number against the closed S086–S090 artifacts, with zero prose.

**Architecture:** Port Paper 3's proven scaffold pipeline (`docs/paper_3/{skeleton_v1_0.json,build_references.py,number_check.py}` + `tests/paper_3/test_{skeleton_audit,citation_existence,number_check}.py`) to a sibling `docs/paper_4/` + `tests/paper_4/`. The skeleton JSON is the single source of truth; the gates are pytest tests that fail if the JSON, the bib, or the result artifacts drift. No new measurement — resolvers read the existing `data/paper_4/` artifacts.

**Tech Stack:** Python 3.11, pytest, stdlib only (`json`, `re`, `dataclasses`, `pathlib`). No new dependencies.

**Source of truth for content:** the design spec `docs/superpowers/specs/2026-06-12-paper-4-read-depth-trilemma-design.md` (thesis, P1/P2/P3 axes, §5 section table, §6 evidence map, §10 limitations). Read it before Task 1.

---

## Scope

**This plan (Phase 1):** scaffold + gates only. Produces a structurally-validated, number-locked, gate-passing paper skeleton with **no prose, no figures, no PDF**. Self-contained and fully testable. Mirrors Paper 3 Session 064.

**Follow-on plans (named here, written when their session arrives):**
- **Phase 2 — Figures:** `docs/paper_4/build_figures.py` → 6 vector PDFs (`fig_1..6`), matplotlib `pdf.fonttype = 42`. Mirrors `docs/paper_3/build_figures.py`.
- **Phase 3 — Prose:** author `docs/paper_4/source/PAPER4_DRAFT_v1_0_source.md` section-by-section; activate `number_check` prose-substring mode. Mirrors Paper 3 Sessions 065–070.
- **Phase 4 — acmart build + PDF gate:** `build_acmart.py` + `verify_pdf_substrings.py`. Mirrors Paper 3 Sessions 071–073.

**Out of scope for Phase 1:** any LLM/measurement call; figures; prose; acmart/PDF; verifying new bibkeys (they stay tracked-as-unverified in the skeleton until Phase 3, per Paper 3 discipline).

---

## File Structure

**Create:**
- `docs/paper_4/skeleton_v1_0.json` — structural scaffold (SSOT). ~12 sections + abstract; numbers_preregistered; bibkeys; figures; tables; anchor-test index.
- `docs/paper_4/references.bib` — verified-only bibliography (5 reused + 3 self-cites). Pristine: no placeholders.
- `docs/paper_4/build_references.py` — bib parser + citation helpers. **Verbatim copy** of `docs/paper_3/build_references.py` (pure, paper-agnostic).
- `docs/paper_4/number_check.py` — number-check harness (ported) + Paper-4 resolvers reading `data/paper_4/` artifacts.
- `docs/paper_4/number_check_report.md` — generated report (gitignored-style artifact, but committed like Paper 3's).
- `tests/paper_4/__init__.py` — empty (only if `tests/paper_3/` has one; check first).
- `tests/paper_4/test_skeleton_audit.py` — structural tests on the skeleton JSON.
- `tests/paper_4/test_citation_existence.py` — bib parses, verified keys present, unverified tracked-not-in-bib, identifier formats.
- `tests/paper_4/test_number_check.py` — per-resolver + harness tests.

**Reference (read / copy from):**
- `docs/paper_3/skeleton_v1_0.json`, `build_references.py`, `number_check.py`
- `tests/paper_3/test_skeleton_audit.py`, `test_citation_existence.py`, `test_number_check.py`

**Modify (Task 6, session close only):**
- `CLAUDE.md` — add Paper 4 artifacts to Canonical Artifacts + Key Code Locations; bump test floor; add Branch-section squash records for S090 (`92cc0e6`, `0814e27`), S091 (`bd72bdb`), and this scaffold's squash.

---

## Number reconciliation (LOCK THESE — surfaced from the artifacts)

The skeleton's `numbers_preregistered` and the `number_check` resolvers MUST use these exact on-disk values (not the prose-rounded ones in the verdict notes):

| Quantity | Locked value | Source artifact (key) |
|---|---|---|
| S088 LLM standalone Youden J | `0.75` | `tier4_summary.json` coordinates[view=standalone].youden_j |
| S088 LLM standalone X_semantic | `0.125` | `tier4_summary.json` coordinates[standalone].x_semantic |
| S088 LLM cumulative Youden J (the cap) | `0.25` | `tier4_summary.json` coordinates[cumulative].youden_j |
| S088 SYN-001 framing-flip p-value | `0.0005` (suffix; prefix `0.0015`) | `tier4_summary.json` records[SYN-001].operator_records |
| S088 deterministic standalone J ladder | `0.0, 0.25, 0.50, 0.75` (v1_field→v2_canonical) | `frontier_coordinates.json` (read at build to confirm keys) |
| S088 cost | `3.2279` (prose: `$3.23`) | `tier4_summary.json` total_cost_usd |
| S088 corpus digest | `9401b7188ba790a5` | `tier4_summary.json` corpus_digest |
| OOV verdict | `SUPPORTED_STRONG` | `oov_summary.json` verdict |
| OOV K | `8` | `oov_summary.json` k |
| OOV scenarios evaded (both arms) | `RDF-M-LEX-002`, `RDF-M-SYN-001` (2 of 4) | `oov_summary.json` arm_summaries[*].scenarios_evaded |
| OOV adversarial X (per scenario, both arms) | `0.5` | `oov_summary.json` arm_summaries[*].adversarial_x_scenario |
| OOV per-candidate flip (run-2) | black `0.28125`, white `0.2903…` | `oov_summary.json` arm_summaries[*].per_candidate_flip_rate |
| OOV cost (run-2) | `0.106` | `oov_summary.json` total_cost_usd |
| OOV corpus digest (run-2) | `a4ea1d0645152ffa` | `oov_summary.json` oov_corpus_digest |
| Audit verdict | `ROBUST` | `oov_audit.json` audit_verdict |
| Audit controls | 4, all pass | `oov_audit.json` controls / controls_passed |
| Audit evading split | 18 total = 15 `independent_confirmed` + 3 `independent_split` | `oov_audit.json` evading[*].classification |
| Audit per-scenario confirmed | LEX-002 true, SYN-001 true | `oov_audit.json` per_scenario_confirmed |
| Audit cost | `0.0093` | `oov_audit.json` total_cost_usd |
| Total live spend | `0.115` (`0.106 + 0.0093`) | derived |

**Prose note for Phase 3:** state the original S089 run (corpus `9900b91f707e2ef8`, `$0.1104`, flip `0.344`/`0.312`) as the first observation, then run-2 as the persisted+audited canonical run. Only run-2 is number-checked (it is what is on disk).

---

## Task 1: Paper 4 skeleton JSON + skeleton-audit gate

**Files:**
- Create: `tests/paper_4/test_skeleton_audit.py`
- Create: `docs/paper_4/skeleton_v1_0.json`
- Reference: `tests/paper_3/test_skeleton_audit.py`, `docs/paper_3/skeleton_v1_0.json`, spec §5

- [ ] **Step 1: Create `tests/paper_4/` and copy the audit test as a starting point**

```bash
mkdir -p tests/paper_4
# If tests/paper_3/__init__.py exists, mirror it:
test -f tests/paper_3/__init__.py && cp tests/paper_3/__init__.py tests/paper_4/__init__.py || true
cp tests/paper_3/test_skeleton_audit.py tests/paper_4/test_skeleton_audit.py
```

- [ ] **Step 2: Rewrite `tests/paper_4/test_skeleton_audit.py` for Paper 4 locks**

Keep the Paper 3 test *structure* (a `skeleton` fixture loading the JSON; grouped test classes). Change the locked values to Paper 4's. The full required assertions:

```python
import json
from pathlib import Path
import pytest

REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON = REPO_ROOT / "docs" / "paper_4" / "skeleton_v1_0.json"

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
        assert skeleton["paper_id"] == "paper_4_v1_0"
    def test_framing_choice_locked(self, skeleton):
        assert "trilemma" in skeleton["framing_choice"].lower()
    def test_required_top_level_keys(self, skeleton):
        for key in ("working_title", "short_title", "author", "venue",
                    "target_words_core", "section_count_numbered",
                    "contribution_claims", "three_finding_story", "sections",
                    "figures", "tables", "numbers_preregistered",
                    "bibkeys_required_verified", "bibkeys_needed_unverified",
                    "anchor_tests_required"):
            assert key in skeleton, key

class TestSections:
    def test_section_count_locked(self, skeleton):
        assert skeleton["section_count_numbered"] == 12
    def test_abstract_first_and_unnumbered(self, skeleton):
        s0 = skeleton["sections"][0]
        assert s0["section_id"] == "abstract"
        assert s0["section_number"] is None
    def test_numbered_one_through_twelve(self, skeleton):
        nums = [s["section_number"] for s in skeleton["sections"]
                if s["section_number"] is not None]
        assert nums == list(range(1, 13))
    def test_references_section_is_last(self, skeleton):
        assert skeleton["sections"][-1]["section_id"] == "references"
        assert skeleton["sections"][-1]["section_number"] == 12
    def test_each_section_has_required_fields(self, skeleton):
        for s in skeleton["sections"]:
            for f in ("section_id", "section_number", "title",
                      "target_words", "claims", "numbers_preregistered",
                      "bibkeys_required", "figures", "tables"):
                assert f in s, (s["section_id"], f)
    def test_three_findings_present(self, skeleton):
        ids = {s["section_id"] for s in skeleton["sections"]}
        assert {"finding_1_empty_corner", "finding_2_oov_defeat",
                "finding_3_independent_audit"} <= ids
    def test_finding_2_is_load_bearing(self, skeleton):
        f2 = next(s for s in skeleton["sections"]
                  if s["section_id"] == "finding_2_oov_defeat")
        assert f2.get("load_bearing") is True
    def test_target_words_sum_within_budget(self, skeleton):
        total = sum(s["target_words"] for s in skeleton["sections"])
        assert abs(total - skeleton["target_words_core"]) <= 400

class TestFiguresTables:
    def test_figure_count_locked(self, skeleton):
        assert len(skeleton["figures"]) == 6
    def test_table_count_locked(self, skeleton):
        assert len(skeleton["tables"]) == 4
    def test_each_figure_has_required_fields(self, skeleton):
        for fig in skeleton["figures"]:
            for f in ("id", "type", "purpose", "host_section"):
                assert f in fig, (fig.get("id"), f)
    def test_figure_host_sections_valid(self, skeleton):
        valid = {s["section_number"] for s in skeleton["sections"]
                 if s["section_number"] is not None}
        for fig in skeleton["figures"]:
            assert fig["host_section"] in valid

class TestNumbers:
    def test_each_number_has_required_fields(self, skeleton):
        for n in skeleton["numbers_preregistered"]:
            assert "value" in n and "source" in n and "lock_target" in n
    def test_trilemma_cap_locked(self, skeleton):
        vals = {str(n["value"]) for n in skeleton["numbers_preregistered"]}
        assert "0.25" in vals      # cumulative Youden J cap
        assert "SUPPORTED_STRONG" in vals
        assert "ROBUST" in vals
        assert "0.0005" in vals    # precise SYN-001 flip p-value

class TestBibkeys:
    def test_verified_keys_present(self, skeleton):
        keys = {b["bibkey"] for b in skeleton["bibkeys_required_verified"]}
        for reused in ("greshake-2023", "guo-2024", "jacovi-goldberg-2020",
                       "reiter-1978", "berdoz-rugli-wattenhofer-2026"):
            assert reused in keys, reused
    def test_each_verified_bibkey_has_fields(self, skeleton):
        for b in skeleton["bibkeys_required_verified"]:
            for f in ("bibkey", "role", "status"):
                assert f in b
            assert b["status"] == "VERIFIED"
    def test_unverified_use_needed_marker(self, skeleton):
        # New keys are tracked here until Phase 3 web-verification.
        for b in skeleton["bibkeys_needed_unverified"]:
            assert "slug" in b and "verification_instructions" in b

class TestAnchors:
    def test_anchor_tests_reference_existing_locks(self, skeleton):
        paths = {a["path"] for a in skeleton["anchor_tests_required"]}
        # Paper 4's code-reality is already locked from S086-S091:
        assert any("test_oov_prereg_bands_match_code" in p for p in paths)
        assert any("test_read_depth_oov_no_network_anchor" in p for p in paths)
```

- [ ] **Step 3: Run the audit test, verify it FAILS (no skeleton yet)**

Run: `python -m pytest tests/paper_4/test_skeleton_audit.py -q`
Expected: FAIL/ERROR — `skeleton_v1_0.json` does not exist.

- [ ] **Step 4: Author `docs/paper_4/skeleton_v1_0.json`**

Use `docs/paper_3/skeleton_v1_0.json` as the structural template. Populate from spec §5 (sections), §6 (numbers), §3 (contributions), §10 (limitations). Required concrete content:

- **meta:** `kind="paper_structure_skeleton"`, `paper_id="paper_4_v1_0"`, `working_title` = the lead title from spec §13, `short_title="The Read-Depth Robustness Trilemma"`, `author="Daniel Gmys-Casiano (Skyframe Innovations)"`, `venue="TBD peer venue; acmart-portable"`, `target_words_core=9400`, `section_count_numbered=12`, `framing_choice="trilemma-as-result; frontier-first + embedded refute"`, `build_start_test_floor` = the test floor at build start (read from CLAUDE.md at build time).
- **contribution_claims:** the 3 from spec §3 (frontier+trilemma SUPPORTED; OOV refutation SUPPORTED_STRONG; audit ROBUST + reusable method).
- **three_finding_story:** `finding_1` (S088, empty corner, `data/paper_4/read_depth_frontier/tier4_summary.json` + `frontier_coordinates.json`), `finding_2` (S089 run-2, OOV defeat, `data/paper_4/read_depth_oov/oov_summary.json`), `finding_3` (S090, audit, `data/paper_4/read_depth_oov/oov_audit.json`).
- **sections:** 13 entries (abstract + 12 numbered) matching spec §5 exactly. IDs: `abstract`, `introduction`(1), `background`(2), `ares_verifier_ladder`(3), `methodology`(4), `finding_1_empty_corner`(5), `finding_2_oov_defeat`(6, `load_bearing: true`), `finding_3_independent_audit`(7), `method_contribution`(8), `discussion`(9), `limitations`(10), `future_work`(11), `references`(12). Each: `target_words` from spec §5, `claims` (derive 3–5 from the spec row + the matching verdict note), `numbers_preregistered` (the value strings hosted in that section), `bibkeys_required`, `figures`, `tables`. Word targets must sum to within 400 of 9400.
- **figures (6):** `fig_1` ladder (host §3), `fig_2` frontier 2-axis standalone/cumulative (host §5), `fig_3` OOV per-scenario flips (host §6), `fig_4` audit controls+confirmed/split (host §7), `fig_5` method pipeline (host §8), `fig_6` worked OOV disguise (host §6). Each: `id`, `type`, `purpose`, `source`, `host_section`.
- **tables (4):** `tbl_1` Corpus C composition (§4), `tbl_2` frontier coordinates both views (§5), `tbl_3` OOV per-arm summary (§6), `tbl_4` evading disguises + per-judge verdicts (§7).
- **numbers_preregistered:** one entry per row of the Number-reconciliation table above; each `{value, source, lock_target}`.
- **bibkeys_required_verified:** the 5 reused entries (copy role/status/source from `docs/paper_3/skeleton_v1_0.json`) + 3 self-cites `gmys-casiano-2026a` (Paper 1), `gmys-casiano-2026b` (Paper 2), `gmys-casiano-2026c` (Paper 3) — status VERIFIED, source = the canonical paper docs.
- **bibkeys_needed_unverified:** 3 placeholders-as-slugs (NOT in bib): `preregistration-ml-eval-needed`, `evasion-attacks-detectors-needed`, `robustness-frontier-needed`, each with `verification_instructions` (web-search target).
- **anchor_tests_required:** reference the existing locks (no new tests): `tests/paper_4/test_oov_prereg_bands_match_code.py`, `tests/paper_4/test_oov_audit_prereg_bands_match_code.py`, `tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py`, `ares/dialectic/agents/light_skeptic_v2_ladder.py` registry. Each `{path, status, locks}`.

- [ ] **Step 5: Run the audit test, verify it PASSES**

Run: `python -m pytest tests/paper_4/test_skeleton_audit.py -q`
Expected: PASS (all assertions green). Fix the JSON until green.

- [ ] **Step 6: Commit**

```bash
git add tests/paper_4/test_skeleton_audit.py docs/paper_4/skeleton_v1_0.json
git commit -F - <<'EOF'
feat(s093): Paper 4 skeleton JSON + skeleton-audit gate

12-section frontier-first scaffold (read-depth robustness trilemma),
numbers locked to on-disk S088/S089-run2/S090 artifacts. No prose.
EOF
```

---

## Task 2: `references.bib` + `build_references.py` + citation-existence gate

**Files:**
- Create: `docs/paper_4/build_references.py` (verbatim copy of Paper 3's)
- Create: `docs/paper_4/references.bib`
- Create: `tests/paper_4/test_citation_existence.py`
- Reference: `docs/paper_3/{build_references.py,references.bib}`, `tests/paper_3/test_citation_existence.py`

- [ ] **Step 1: Copy the bib helpers verbatim (they are paper-agnostic)**

```bash
cp docs/paper_3/build_references.py docs/paper_4/build_references.py
```
No edits needed — `parse_bib`, `extract_citations`, `citation_to_bibkey` are pure.

- [ ] **Step 2: Author `docs/paper_4/references.bib` (verified-only, pristine)**

Copy the 5 reused entries verbatim from `docs/paper_3/references.bib`: `greshake-2023`, `guo-2024`, `jacovi-goldberg-2020`, `reiter-1978`, `berdoz-rugli-wattenhofer-2026` (keep the `%`-comment provenance, drop nothing). Then add 3 self-cite entries with canonical author-year-suffix keys so narrative cites round-trip:

```bibtex
% Provenance: ARES Paper 1 self-cite. Canonical PDF at
%   docs/paper_1/ARES_Preprint_Asymmetric_Calibration_Failure.pdf.
@article{gmys-casiano-2026a,
  author  = {Gmys-Casiano, Daniel},
  title   = {The Problem Is Inside the Black Box: Asymmetric Calibration Failure in Multi-Agent {LLM} Debate},
  year    = {2026},
  journal = {Preprint}
}
% Provenance: ARES Paper 2 self-cite (deterministic Skeptic primitive).
@article{gmys-casiano-2026b,
  author  = {Gmys-Casiano, Daniel},
  title   = {The Deterministic Skeptic: Four Rules Match an {LLM} Agent in Adversarial Cybersecurity Threat Analysis},
  year    = {2026},
  journal = {Preprint}
}
% Provenance: ARES Paper 3 self-cite (decision determinism, explanation drift).
@article{gmys-casiano-2026c,
  author  = {Gmys-Casiano, Daniel},
  title   = {Decision Determinism, Explanation Drift: Decoupling Verdict Stability from Explanation Stability in Adversarial Multi-Agent {LLM} Pipelines},
  year    = {2026},
  journal = {Preprint}
}
```
Do NOT add the 3 unverified new keys here — they live in the skeleton's `bibkeys_needed_unverified` until Phase 3 web-verification (Sabet-hallucination discipline).

- [ ] **Step 3: Write `tests/paper_4/test_citation_existence.py`**

Port `tests/paper_3/test_citation_existence.py`, importing from `docs.paper_4.build_references` and reading `docs/paper_4/{references.bib,skeleton_v1_0.json}`. Required offline assertions (drop or `@pytest.mark.live_llm`-gate the network class — arxiv/doi/url resolution — exactly as Paper 3 does):

```python
import json
from pathlib import Path
import pytest
from docs.paper_4.build_references import parse_bib_file, extract_citations, citation_to_bibkey

REPO = Path(__file__).resolve().parents[2]
BIB = REPO / "docs" / "paper_4" / "references.bib"
SKELETON = REPO / "docs" / "paper_4" / "skeleton_v1_0.json"

@pytest.fixture
def bib_entries():
    return parse_bib_file(BIB)

@pytest.fixture
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}

@pytest.fixture
def skeleton():
    return json.loads(SKELETON.read_text(encoding="utf-8"))

def test_references_bib_parses(bib_entries):
    assert len(bib_entries) == 8  # 5 reused + 3 self-cites

def test_expected_verified_keys_present(bib_keys):
    for k in ("greshake-2023", "guo-2024", "jacovi-goldberg-2020",
              "reiter-1978", "berdoz-rugli-wattenhofer-2026",
              "gmys-casiano-2026a", "gmys-casiano-2026b", "gmys-casiano-2026c"):
        assert k in bib_keys, k

def test_every_entry_has_author_and_year(bib_entries):
    for e in bib_entries:
        assert e.get("author") and e.get("year")

def test_no_needed_suffix_in_real_bib(bib_keys):
    assert not any(k.endswith("-needed") for k in bib_keys)

def test_unverified_slugs_from_skeleton_not_in_bib(skeleton, bib_keys):
    for b in skeleton["bibkeys_needed_unverified"]:
        assert b["slug"] not in bib_keys

def test_self_cites_round_trip_from_narrative_prose():
    # "Gmys-Casiano (2026)" must resolve to a real key shape.
    cites = extract_citations("As shown by Gmys-Casiano (2026), ...")
    assert citation_to_bibkey(cites[0]) == "gmys-casiano-2026"

def test_every_skeleton_required_bibkey_resolves(skeleton, bib_keys):
    for s in skeleton["sections"]:
        for k in s["bibkeys_required"]:
            assert k in bib_keys, (s["section_id"], k)
```

(Self-cite round-trip caveat: `gmys-casiano-2026` collides across Papers 1–3. Phase 3 prose must cite them with disambiguating context, e.g. `(Gmys-Casiano, 2026a)`. Add a `test_self_cite_disambiguation_documented` xfail/skip noting this is a Phase-3 prose concern, OR key the entries so the year-suffix survives `citation_to_bibkey`. Decide at build; the offline gate above only requires the keys exist.)

- [ ] **Step 4: Run, verify PASS**

Run: `python -m pytest tests/paper_4/test_citation_existence.py -q`
Expected: PASS. Fix bib/skeleton until green.

- [ ] **Step 5: Commit**

```bash
git add docs/paper_4/build_references.py docs/paper_4/references.bib tests/paper_4/test_citation_existence.py
git commit -F - <<'EOF'
feat(s093): Paper 4 references.bib (verified-only) + citation gate

5 reused verified entries + 3 self-cites; new keys tracked unverified
in the skeleton. Ports Paper 3 bib helpers verbatim.
EOF
```

---

## Task 3: `number_check.py` + Paper-4 resolvers + number-check gate

**Files:**
- Create: `docs/paper_4/number_check.py`
- Create: `tests/paper_4/test_number_check.py`
- Reference: `docs/paper_3/number_check.py`, `tests/paper_3/test_number_check.py`, the 3 artifact schemas

- [ ] **Step 1: Copy the harness, strip Paper 3 resolvers**

```bash
cp docs/paper_3/number_check.py docs/paper_4/number_check.py
```
Keep verbatim: `Claim`, `CheckResult`, `run_checks`, `render_report`, `write_report`, `prose_substring_claims` (re-seed for Paper 4 — see below), `extract_docx_text`/`check_prose_substrings` (dormant until Phase 3), `build_arg_parser`/`main`. Replace the resolver block + `default_claims` + the artifact-path constants.

- [ ] **Step 2: Write the Paper-4 artifact constants + resolvers**

```python
REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_4" / "skeleton_v1_0.json"
FRONTIER_DIR = REPO_ROOT / "data" / "paper_4" / "read_depth_frontier"
OOV_DIR = REPO_ROOT / "data" / "paper_4" / "read_depth_oov"
TIER4 = FRONTIER_DIR / "tier4_summary.json"
OOV_SUMMARY = OOV_DIR / "oov_summary.json"
OOV_AUDIT = OOV_DIR / "oov_audit.json"

def _load(p: Path) -> dict:
    return json.loads(p.read_text(encoding="utf-8"))

def _tier4_coord(view: str, field: str):
    for c in _load(TIER4)["coordinates"]:
        if c["view"] == view:
            return c[field]
    raise LookupError(f"tier4 view {view!r} not found")

def _resolve_cumulative_j_cap() -> float:
    return _tier4_coord("cumulative", "youden_j")          # 0.25

def _resolve_llm_standalone_j() -> float:
    return _tier4_coord("standalone", "youden_j")          # 0.75

def _resolve_llm_standalone_x_semantic() -> float:
    return _tier4_coord("standalone", "x_semantic")        # 0.125

def _resolve_syn001_flip_pvalue() -> float:
    rec = next(r for r in _load(TIER4)["records"]
               if r["scenario_id"] == "RDF-M-SYN-001")
    flipped = [o for o in rec["operator_records"] if o["flipped"]]
    if not flipped:
        raise LookupError("no flipped operator for SYN-001")
    return min(o["p_value"] for o in flipped)              # 0.0005

def _resolve_oov_verdict() -> str:
    return _load(OOV_SUMMARY)["verdict"]                   # SUPPORTED_STRONG

def _resolve_oov_black_evaded() -> tuple:
    s = next(a for a in _load(OOV_SUMMARY)["arm_summaries"] if a["arm"] == "black")
    return tuple(sorted(s["scenarios_evaded"]))            # (LEX-002, SYN-001)

def _resolve_oov_named_ioc_flip_count() -> int:
    """Named-IOC scenarios (LEX-001, PATCH-001) must have ZERO canonical flips."""
    named = {"RDF-M-LEX-001", "RDF-M-PATCH-001"}
    return sum(1 for r in _load(OOV_SUMMARY)["records"]
               if r["scenario_id"] in named and r["canonical_flipped"])  # 0

def _resolve_oov_cost() -> float:
    return _load(OOV_SUMMARY)["total_cost_usd"]            # 0.106

def _resolve_audit_verdict() -> str:
    return _load(OOV_AUDIT)["audit_verdict"]               # ROBUST

def _resolve_audit_controls_pass() -> bool:
    return _load(OOV_AUDIT)["controls_passed"]             # True

def _resolve_audit_confirmed_count() -> int:
    return sum(1 for e in _load(OOV_AUDIT)["evading"]
               if e["classification"] == "independent_confirmed")  # 15

def _resolve_audit_split_count() -> int:
    return sum(1 for e in _load(OOV_AUDIT)["evading"]
               if e["classification"] == "independent_split")      # 3

def _resolve_test_floor_from_skeleton(skeleton: dict) -> int:
    return int(skeleton["build_start_test_floor"])
```

- [ ] **Step 3: Write `default_claims(skeleton)`**

```python
def default_claims(skeleton: dict) -> tuple[Claim, ...]:
    return (
        Claim("cumulative Youden J cap (0.25)", 0.25, _resolve_cumulative_j_cap),
        Claim("LLM standalone Youden J (0.75)", 0.75, _resolve_llm_standalone_j),
        Claim("LLM standalone X_semantic (0.125)", 0.125, _resolve_llm_standalone_x_semantic),
        Claim("SYN-001 framing-flip p-value (0.0005)", 0.0005, _resolve_syn001_flip_pvalue),
        Claim("OOV verdict (SUPPORTED_STRONG)", "SUPPORTED_STRONG", _resolve_oov_verdict),
        Claim("OOV black-arm scenarios evaded", ("RDF-M-LEX-002", "RDF-M-SYN-001"), _resolve_oov_black_evaded),
        Claim("named-IOC canonical flips (0)", 0, _resolve_oov_named_ioc_flip_count),
        Claim("OOV run-2 cost (0.106)", 0.106, _resolve_oov_cost),
        Claim("audit verdict (ROBUST)", "ROBUST", _resolve_audit_verdict),
        Claim("audit controls pass (True)", True, _resolve_audit_controls_pass),
        Claim("audit independent_confirmed (15)", 15, _resolve_audit_confirmed_count),
        Claim("audit independent_split (3)", 3, _resolve_audit_split_count),
        Claim("test floor from skeleton", _resolve_test_floor_from_skeleton(skeleton),
              lambda: _resolve_test_floor_from_skeleton(skeleton)),
    )
```

- [ ] **Step 4: Re-seed `prose_substring_claims()` for Phase 3 (dormant now)**

Replace Paper 3's list with Paper 4's load-bearing substrings: `"SUPPORTED_STRONG"`, `"ROBUST"`, `"0.25"`, `"0.75"`, `"0.125"`, `"0.0005"`, `"RDF-M-LEX-002"`, `"RDF-M-SYN-001"`, `"RDF-M-LEX-001"`, `"RDF-M-PATCH-001"`, `"lsass"`, `"procdump"`, `"v2_canonical"`, `"9401b7188ba790a5"`, `"a4ea1d0645152ffa"`, `"15"`, `"18"`, `"GPT-4o"`, `"Gemini"`, `"trilemma"`, `"\\$0.106"`, `"\\$0.0093"`.

- [ ] **Step 5: Write `tests/paper_4/test_number_check.py`**

Port the Paper 3 test shape. One test per resolver asserting the locked value, plus harness tests:

```python
from docs.paper_4 import number_check as nc

class TestResolvers:
    def test_cumulative_cap_is_025(self):
        assert nc._resolve_cumulative_j_cap() == 0.25
    def test_llm_standalone_j_is_075(self):
        assert nc._resolve_llm_standalone_j() == 0.75
    def test_syn001_pvalue_is_00005(self):
        assert nc._resolve_syn001_flip_pvalue() == 0.0005
    def test_oov_verdict_supported_strong(self):
        assert nc._resolve_oov_verdict() == "SUPPORTED_STRONG"
    def test_named_ioc_zero_flips(self):
        assert nc._resolve_oov_named_ioc_flip_count() == 0
    def test_audit_verdict_robust(self):
        assert nc._resolve_audit_verdict() == "ROBUST"
    def test_audit_confirmed_is_15(self):
        assert nc._resolve_audit_confirmed_count() == 15
    def test_audit_split_is_3(self):
        assert nc._resolve_audit_split_count() == 3

class TestHarness:
    def test_run_checks_all_pass(self):
        import json, pathlib
        sk = json.loads((pathlib.Path(nc.__file__).resolve().parents[2]
                         / "docs/paper_4/skeleton_v1_0.json").read_text("utf-8"))
        results = nc.run_checks(nc.default_claims(sk))
        assert all(r.passed for r in results), [r.label for r in results if not r.passed]
    def test_main_exits_zero(self, tmp_path):
        rc = nc.main(["--out-report", str(tmp_path / "r.md")])
        assert rc == 0
```

- [ ] **Step 6: Run, verify PASS**

Run: `python -m pytest tests/paper_4/test_number_check.py -q`
Expected: PASS. If a resolver mismatches, the artifact value is canonical — fix the skeleton/expected, never the artifact.

- [ ] **Step 7: Generate the report + commit**

```bash
python -m docs.paper_4.number_check --out-report docs/paper_4/number_check_report.md
git add docs/paper_4/number_check.py docs/paper_4/number_check_report.md tests/paper_4/test_number_check.py
git commit -F - <<'EOF'
feat(s093): Paper 4 number-check gate locked to S088/S089-run2/S090 artifacts

13 resolvers reading tier4_summary / oov_summary(run-2) / oov_audit.
Locks SUPPORTED_STRONG, ROBUST, cumulative J=0.25, SYN-001 p=0.0005,
named-IOC zero-flips, 15/3 confirmed/split.
EOF
```

---

## Task 4: Full-suite regression + scaffold sign-off

**Files:** none (verification only)

- [ ] **Step 1: Run the Paper 4 gate set**

Run: `python -m pytest tests/paper_4/ -q`
Expected: all PASS (skeleton audit + citation existence + number check).

- [ ] **Step 2: Run the full suite to confirm zero regressions**

Run: `python -m pytest tests/ ares/ -q`
Expected: prior floor + the new Paper 4 tests, 0 failures. Record the new count.

- [ ] **Step 3: Confirm no artifact was mutated**

Run: `git status --short data/paper_4/`
Expected: empty (resolvers are read-only; we never edit result artifacts).

---

## Task 5: Skeleton-vs-source consistency cross-check (the SSOT lock)

**Files:**
- Modify: `tests/paper_4/test_number_check.py` (add one class)

- [ ] **Step 1: Add a test asserting every skeleton `numbers_preregistered` value is backed by a passing resolver**

```python
class TestSkeletonSourceConsistency:
    def test_every_skeleton_number_has_passing_resolver(self):
        import json, pathlib
        sk = json.loads((pathlib.Path(nc.__file__).resolve().parents[2]
                         / "docs/paper_4/skeleton_v1_0.json").read_text("utf-8"))
        resolved = {str(r.actual) for r in nc.run_checks(nc.default_claims(sk)) if r.passed}
        # Every numeric/string value claimed in the skeleton that the
        # number_check covers must appear in the resolved set.
        covered = {"0.25", "0.75", "0.125", "0.0005", "SUPPORTED_STRONG",
                   "ROBUST", "0", "15", "3", "0.106", "True"}
        for n in sk["numbers_preregistered"]:
            v = str(n["value"])
            if v in covered:
                assert v in resolved, v
```

- [ ] **Step 2: Run, verify PASS, commit**

Run: `python -m pytest tests/paper_4/test_number_check.py::TestSkeletonSourceConsistency -q`
Expected: PASS.

```bash
git add tests/paper_4/test_number_check.py
git commit -F - <<'EOF'
test(s093): lock skeleton numbers_preregistered to number_check resolvers
EOF
```

---

## Task 6: CLAUDE.md update + branch housekeeping (session close)

**Files:**
- Modify: `CLAUDE.md`

- [ ] **Step 1: Add Paper 4 scaffold to CLAUDE.md**

Under **Canonical Artifacts**, add the Paper 4 skeleton/bib/number_check paths. Under **Key Code Locations**, add a `### Paper 4 tooling` block mirroring the Paper 3 one. Bump **Test count floor (passing)** to the count recorded in Task 4 Step 2. Add a session-ledger line for this scaffold session.

- [ ] **Step 2: Add the pending Branch-section squash records (carried from the crystal)**

Add to the **Branch** section: S090 squashes `92cc0e6` (instrument) + `0814e27` (live); S091 `bd72bdb` (generator cost fix); and this scaffold session's squash (fill after merge).

- [ ] **Step 3: Confirm CLAUDE.md freshness test passes**

Run: `python -m pytest tests/test_claude_md_freshness.py -q`
Expected: PASS (declared floor <= actual count; canonical paths exist).

- [ ] **Step 4: Commit**

```bash
git add CLAUDE.md
git commit -F - <<'EOF'
docs(s093): CLAUDE.md Paper 4 scaffold + floor bump + S090/S091 branch records
EOF
```

---

## Self-Review (completed during plan authoring)

**Spec coverage:** spec §1 (thesis) → skeleton meta + finding story (Task 1); §2 (P1/P2/P3) → numbers + figure 2 (Tasks 1, 3); §3 (contributions) → `contribution_claims` (Task 1); §5 (sections) → skeleton sections (Task 1); §6 (evidence map) → number_check resolvers (Task 3) + reconciliation table; §8 (gates) → Tasks 1–3; §9 (anchors already exist) → `anchor_tests_required` references existing tests (Task 1); §10 (limitations) → carried into the §10 skeleton section (Task 1); §11 (scope cut) → this plan is scaffold-only, figures/prose/acmart deferred. Figures/prose/acmart are explicitly follow-on plans (Scope section), not gaps.

**Placeholder scan:** resolvers are concrete (real artifact keys). The skeleton `claims`/`narrative_arc` per section are derived from the committed spec §5 + verdict notes — pointer to a concrete, existing source, not "fill in later." New bibkeys are intentionally tracked-as-unverified (Paper 3 discipline), not placeholders-in-bib.

**Type consistency:** resolver names match between Task 3 Step 2 (definitions) and Step 3 (`default_claims`) and Step 5 (tests). Artifact keys (`youden_j`, `x_semantic`, `view`, `arm_summaries`, `scenarios_evaded`, `classification`, `controls_passed`, `per_scenario_confirmed`) match the schemas read from disk.

---

## Execution Handoff

After this plan is approved, build it with **subagent-driven-development** (recommended) — fresh subagent per task, two-stage review between tasks — or **executing-plans** (inline batches). The scaffold is small and self-contained; either works. The follow-on Phases 2–4 (figures, prose, acmart) each get their own plan when their session arrives.
