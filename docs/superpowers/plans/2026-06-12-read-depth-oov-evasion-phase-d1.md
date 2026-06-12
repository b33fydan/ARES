# OOV Adversarial Evasion Generator — Phase D1 Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Build the offline, deterministic instrument for the OOV adversarial evasion experiment (LLM-adversary generator + deterministic validity gate + LLM-judge meaning-oracle + frozen-corpus measurement + report + CLI) plus the committed Phase D pre-registration, with the live LLM behind injectable seams so the entire build is testable with zero API spend.

**Architecture:** Five new peer modules under `ares/dialectic/measurement/` (`read_depth_oov_{schema,generator,validator,runner,report}.py`), a CLI `scripts/run_session_089.py`, and a pre-registration doc `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md`. The LLM appears only behind `generate_fn` / `judge_fn` seams (the S088 `make_live_cycle_fn` pattern); once candidates are validated and frozen, all measurement is pure-Python and reproducible. Existing modules (tiers, corpus, mutator, metrics) are imported, never modified.

**Tech Stack:** Python 3.11, frozen dataclasses, pytest. Reuses `light_skeptic_v2_{lexical,canonical}`, `read_depth_corpus`, `read_depth_frontier_metrics`, `paired_scenario_mutator`, `client_factory`.

---

## Conventions for every task

- Run tests from repo root `C:\ares-phase-zero`.
- Single test: `python -m pytest <path>::<test> -v`.
- Module test file: `python -m pytest <path> -v`.
- Commit only the files named in each task (the working tree has unrelated untracked files; never `git add -A`).
- Commit messages: use `git commit -F <msgfile>` (the Bash tool mangles parens/here-strings); end the message with the `Co-Authored-By: Claude Opus 4.8 <noreply@anthropic.com>` trailer.
- Branch is already `session/089-read-depth-oov-evasion`.

---

## Task 1: Schema + verdict constants + classifier

**Files:**
- Create: `ares/dialectic/measurement/read_depth_oov_schema.py`
- Test: `tests/dialectic/measurement/test_read_depth_oov_schema.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_schema.py
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, ARMS,
    READ_DEPTH_OOV_HARD_CEILING_USD, FALSIFIED_REQUIRES_ZERO_EVASIONS,
    VERDICT_SUPPORTED_STRONG, VERDICT_SUPPORTED_MODERATE,
    VERDICT_FALSIFIED, VERDICT_INSTRUMENT_FAILURE,
    OOVCandidate, OOVArmSummary, OOVEvasionRecord, OOVFrontierSummary,
    classify_oov_verdict, oov_corpus_digest,
)


def _arm(arm, *, n_accepted, evaded):
    return OOVArmSummary(
        arm=arm, n_candidates=n_accepted, n_accepted=n_accepted,
        n_rejected_skeleton=0, n_rejected_novelty=0, n_rejected_judge=0,
        scenarios_evaded=tuple(evaded),
        adversarial_x_scenario=len(evaded) / 4.0,
        per_candidate_flip_rate=0.0, n_malign_scenarios=4,
    )


def test_constants():
    assert READ_DEPTH_OOV_HARD_CEILING_USD == 10.0
    assert FALSIFIED_REQUIRES_ZERO_EVASIONS is True
    assert ARMS == (ARM_BLACK, ARM_WHITE)


def test_black_hole_is_supported_strong():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=["RDF-M-LEX-001"]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_SUPPORTED_STRONG


def test_white_only_hole_is_supported_moderate():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=["RDF-M-LEX-002"]))
    assert classify_oov_verdict(arms) == VERDICT_SUPPORTED_MODERATE


def test_survives_both_is_falsified():
    arms = (_arm(ARM_BLACK, n_accepted=5, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_FALSIFIED


def test_empty_accepted_arm_is_instrument_failure():
    arms = (_arm(ARM_BLACK, n_accepted=0, evaded=[]),
            _arm(ARM_WHITE, n_accepted=5, evaded=[]))
    assert classify_oov_verdict(arms) == VERDICT_INSTRUMENT_FAILURE


def test_corpus_digest_is_order_independent_and_stable():
    c1 = OOVCandidate("RDF-M-LEX-001", ARM_BLACK, (("f1", "a"), ("f2", "b")))
    c2 = OOVCandidate("RDF-M-LEX-002", ARM_WHITE, (("f3", "c"),))
    assert oov_corpus_digest((c1, c2)) == oov_corpus_digest((c2, c1))
    assert len(oov_corpus_digest((c1, c2))) == 16


def test_summary_json_roundtrip():
    arm = _arm(ARM_BLACK, n_accepted=1, evaded=["RDF-M-LEX-001"])
    rec = OOVEvasionRecord("RDF-M-LEX-001", ARM_BLACK, True, False)
    summ = OOVFrontierSummary(
        arm_summaries=(arm,), records=(rec,), verdict=VERDICT_SUPPORTED_STRONG,
        corpus_digest="9401b7188ba790a5", oov_corpus_digest="deadbeefdeadbeef",
        total_cost_usd=1.23, model="claude-sonnet-4-20250514",
        provider="anthropic", k=8,
    )
    back = OOVFrontierSummary.from_dict(summ.to_dict())
    assert back == summ
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_schema.py -v`
Expected: FAIL with `ModuleNotFoundError: ... read_depth_oov_schema`.

- [ ] **Step 3: Write the implementation**

```python
# ares/dialectic/measurement/read_depth_oov_schema.py
"""Frozen schema + verdict rule for the OOV adversarial evasion experiment
(read-depth frontier Phase D). Peer to read_depth_tier4_schema.

The LLM appears only in generation/judging; these types carry the frozen,
reproducible record of what was generated, what survived validation, and the
deterministic flip outcomes that decide the verdict.
"""
from __future__ import annotations

import hashlib
import json
from dataclasses import asdict, dataclass
from typing import Any, Mapping, Optional, Tuple

READ_DEPTH_OOV_HARD_CEILING_USD = 10.0

# A FALSIFIED ("the deterministic recipe is real") verdict requires the
# adversary to evade ZERO scenarios in the arm under test: any meaning-
# preserving hole proves the matcher is evadable.
FALSIFIED_REQUIRES_ZERO_EVASIONS = True

ARM_BLACK = "black"
ARM_WHITE = "white"
ARMS: Tuple[str, str] = (ARM_BLACK, ARM_WHITE)

VERDICT_SUPPORTED_STRONG = "SUPPORTED_STRONG"
VERDICT_SUPPORTED_MODERATE = "SUPPORTED_MODERATE"
VERDICT_FALSIFIED = "FALSIFIED"
VERDICT_INSTRUMENT_FAILURE = "INSTRUMENT_FAILURE"


@dataclass(frozen=True)
class OOVCandidate:
    """One LLM-proposed disguise: per-fact value rewrites for a scenario."""

    scenario_id: str
    arm: str
    value_rewrites: Tuple[Tuple[str, str], ...]  # (fact_id, new_value)
    provenance: str = ""

    def rewrites_dict(self) -> dict[str, str]:
        return {fid: val for fid, val in self.value_rewrites}

    def to_dict(self) -> dict[str, Any]:
        return {"scenario_id": self.scenario_id, "arm": self.arm,
                "value_rewrites": [list(p) for p in self.value_rewrites],
                "provenance": self.provenance}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVCandidate":
        return cls(scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
                   value_rewrites=tuple((str(a), str(b))
                                        for a, b in d["value_rewrites"]),
                   provenance=str(d.get("provenance", "")))


@dataclass(frozen=True)
class OOVValidationResult:
    """The outcome of running one candidate through the validity gate."""

    candidate: OOVCandidate
    skeleton_ok: bool
    novel: bool
    judge_malign: Optional[bool]
    accepted: bool
    reject_reason: str


@dataclass(frozen=True)
class OOVEvasionRecord:
    """Per-accepted-candidate flip outcome on the string-reading tiers."""

    scenario_id: str
    arm: str
    canonical_flipped: bool
    lexical_flipped: bool

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVEvasionRecord":
        return cls(scenario_id=str(d["scenario_id"]), arm=str(d["arm"]),
                   canonical_flipped=bool(d["canonical_flipped"]),
                   lexical_flipped=bool(d["lexical_flipped"]))


@dataclass(frozen=True)
class OOVArmSummary:
    """Aggregate metrics for one threat-model arm."""

    arm: str
    n_candidates: int
    n_accepted: int
    n_rejected_skeleton: int
    n_rejected_novelty: int
    n_rejected_judge: int
    scenarios_evaded: Tuple[str, ...]
    adversarial_x_scenario: float
    per_candidate_flip_rate: float
    n_malign_scenarios: int

    def to_dict(self) -> dict[str, Any]:
        d = asdict(self)
        d["scenarios_evaded"] = list(self.scenarios_evaded)
        return d

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVArmSummary":
        return cls(arm=str(d["arm"]), n_candidates=int(d["n_candidates"]),
                   n_accepted=int(d["n_accepted"]),
                   n_rejected_skeleton=int(d["n_rejected_skeleton"]),
                   n_rejected_novelty=int(d["n_rejected_novelty"]),
                   n_rejected_judge=int(d["n_rejected_judge"]),
                   scenarios_evaded=tuple(str(s) for s in d["scenarios_evaded"]),
                   adversarial_x_scenario=float(d["adversarial_x_scenario"]),
                   per_candidate_flip_rate=float(d["per_candidate_flip_rate"]),
                   n_malign_scenarios=int(d["n_malign_scenarios"]))


@dataclass(frozen=True)
class OOVFrontierSummary:
    arm_summaries: Tuple[OOVArmSummary, ...]
    records: Tuple[OOVEvasionRecord, ...]
    verdict: str
    corpus_digest: str
    oov_corpus_digest: str
    total_cost_usd: float
    model: str
    provider: str
    k: int

    def to_dict(self) -> dict[str, Any]:
        return {"arm_summaries": [a.to_dict() for a in self.arm_summaries],
                "records": [r.to_dict() for r in self.records],
                "verdict": self.verdict, "corpus_digest": self.corpus_digest,
                "oov_corpus_digest": self.oov_corpus_digest,
                "total_cost_usd": self.total_cost_usd, "model": self.model,
                "provider": self.provider, "k": self.k}

    @classmethod
    def from_dict(cls, d: Mapping[str, Any]) -> "OOVFrontierSummary":
        return cls(
            arm_summaries=tuple(OOVArmSummary.from_dict(a)
                                for a in d["arm_summaries"]),
            records=tuple(OOVEvasionRecord.from_dict(r) for r in d["records"]),
            verdict=str(d["verdict"]), corpus_digest=str(d["corpus_digest"]),
            oov_corpus_digest=str(d["oov_corpus_digest"]),
            total_cost_usd=float(d["total_cost_usd"]), model=str(d["model"]),
            provider=str(d["provider"]), k=int(d["k"]))

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), sort_keys=True, indent=2)


def classify_oov_verdict(arm_summaries: Tuple[OOVArmSummary, ...]) -> str:
    """Apply the pre-registered 3-way rule. Any arm with zero accepted
    candidates is an instrument failure (no fair evasion was produced)."""
    for s in arm_summaries:
        if s.n_accepted == 0:
            return VERDICT_INSTRUMENT_FAILURE
    by_arm = {s.arm: s for s in arm_summaries}
    black = by_arm.get(ARM_BLACK)
    white = by_arm.get(ARM_WHITE)
    if black is not None and black.scenarios_evaded:
        return VERDICT_SUPPORTED_STRONG
    if white is not None and white.scenarios_evaded:
        return VERDICT_SUPPORTED_MODERATE
    return VERDICT_FALSIFIED


def oov_corpus_digest(candidates: Tuple[OOVCandidate, ...]) -> str:
    """Deterministic, order-independent digest over accepted candidates."""
    parts = sorted(
        f"{c.scenario_id}|{c.arm}|"
        + ";".join(f"{fid}={val}" for fid, val in c.value_rewrites)
        for c in candidates
    )
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()[:16]
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_schema.py -v`
Expected: PASS (7 tests).

- [ ] **Step 5: Commit**

```
git add ares/dialectic/measurement/read_depth_oov_schema.py tests/dialectic/measurement/test_read_depth_oov_schema.py
git commit -F <msgfile>   # feat(s089): OOV schema + 3-way verdict classifier
```

---

## Task 2: Adversary generator (prompts + parser + lazy live fn)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_oov_generator.py`
- Test: `tests/dialectic/measurement/test_read_depth_oov_generator.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_generator.py
from ares.dialectic.measurement.read_depth_corpus import get_entry
from ares.dialectic.measurement.read_depth_oov_schema import ARM_BLACK, ARM_WHITE
from ares.dialectic.measurement.read_depth_oov_generator import (
    build_prompt, parse_candidates,
)

_SC = get_entry("RDF-M-LEX-001").scenario


def test_black_box_prompt_omits_matcher_internals():
    system, user = build_prompt(_SC, ARM_BLACK)
    assert "_SYNONYMS" not in user and "_SYNONYMS" not in system
    # the malign values are shown
    assert "procdump.exe" in user
    # each fact is keyed by fact_id so the model can return rewrites
    assert "rdf-m-lex-001-fact-002" in user


def test_white_box_prompt_includes_matcher_internals():
    system, user = build_prompt(_SC, ARM_WHITE)
    blob = system + user
    # white-box exposes the canonicalizer synonyms and an exe pattern token
    assert "binary" in blob and "temp" in blob
    assert ".exe" in blob or "exe" in blob


def test_parse_candidates_builds_skeleton_keyed_rewrites():
    raw = '''Here are disguises:
    [
      {"rdf-m-lex-001-fact-002": "C:/Users/Public/pd-utility"},
      {"rdf-m-lex-001-fact-003": "pd-utility dumps the auth process memory"}
    ]
    Done.'''
    cands = parse_candidates(_SC, ARM_BLACK, raw)
    assert len(cands) == 2
    assert cands[0].arm == ARM_BLACK
    assert cands[0].scenario_id == "RDF-M-LEX-001"
    assert cands[0].value_rewrites == (("rdf-m-lex-001-fact-002",
                                        "C:/Users/Public/pd-utility"),)


def test_parse_candidates_tolerates_garbage():
    assert parse_candidates(_SC, ARM_BLACK, "no json here") == []
    assert parse_candidates(_SC, ARM_BLACK, "[not, valid, json}") == []
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_generator.py -v`
Expected: FAIL with `ModuleNotFoundError: ... read_depth_oov_generator`.

- [ ] **Step 3: Write the implementation**

```python
# ares/dialectic/measurement/read_depth_oov_generator.py
"""LLM-adversary generator for the OOV evasion experiment (Phase D).

generate_fn(scenario, arm, k) -> (List[OOVCandidate], cost_usd). The live fn
asks the model to invent meaning-preserving disguises; tests inject a fake.
Black-box sees only the values; white-box additionally sees the matcher source.
"""
from __future__ import annotations

import json
import re
from typing import Callable, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_canonical import _SYNONYMS
from ares.dialectic.agents.light_skeptic_v2_lexical import (
    _CRED_TOOLING, _EXECUTABLE_EXT, _USER_WRITABLE_DIR,
)
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_WHITE, OOVCandidate,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# (scenario, arm, k) -> (candidates, cost_usd)
GenerateFn = Callable[[BenchmarkScenario, str, int], Tuple[List[OOVCandidate], float]]

# Anthropic Sonnet-4 list price (USD per token).
_PRICE_IN = 3.0 / 1_000_000
_PRICE_OUT = 15.0 / 1_000_000

_SYSTEM = (
    "You are a red-team adversary testing a security log scanner. Given "
    "telemetry facts that describe a real attack, rewrite the string VALUES "
    "so an automated keyword scanner would miss them, while a competent SOC "
    "analyst reading the rewrite would still recognize the SAME threat. "
    "Preserve meaning; only disguise wording/encoding/paths. Do not invent a "
    "benign story. Return ONLY a JSON array; each element is an object mapping "
    "a fact_id to its rewritten value. Rewrite only the facts you choose to "
    "disguise."
)


def _facts_block(scenario: BenchmarkScenario) -> str:
    lines = []
    for f in scenario.packet.get_all_facts():
        if isinstance(f.value, str):
            lines.append(f"[{f.fact_id}] {f.field} = {f.value}")
    return "\n".join(lines)


def _matcher_block() -> str:
    syn = ", ".join(f"{k}->{v}" for k, v in _SYNONYMS.items())
    return (
        "The scanner canonicalizes each value (lowercase, '\\'->'/', collapse "
        "whitespace, fold synonyms) then matches these patterns:\n"
        f"- user-writable path: {_USER_WRITABLE_DIR.pattern}\n"
        f"- executable extension: {_EXECUTABLE_EXT.pattern}\n"
        f"- credential tooling: {_CRED_TOOLING.pattern}\n"
        f"- synonym folds (already undone, do NOT rely on these): {syn}\n"
    )


def build_prompt(scenario: BenchmarkScenario, arm: str) -> Tuple[str, str]:
    """Return (system, user) for the given arm."""
    user = (
        f"Threat: {scenario.metadata.name}\n\nFacts:\n{_facts_block(scenario)}\n"
    )
    if arm == ARM_WHITE:
        user += "\n" + _matcher_block()
    user += (
        "\nReturn a JSON array of disguise objects (fact_id -> rewritten "
        "value). Each object is one independent disguise attempt."
    )
    return _SYSTEM, user


def parse_candidates(
    scenario: BenchmarkScenario, arm: str, raw: str
) -> List[OOVCandidate]:
    """Parse a model reply into candidates; tolerant of surrounding prose."""
    m = re.search(r"\[.*\]", raw, re.DOTALL)
    if not m:
        return []
    try:
        data = json.loads(m.group(0))
    except (ValueError, TypeError):
        return []
    if not isinstance(data, list):
        return []
    out: List[OOVCandidate] = []
    for obj in data:
        if not isinstance(obj, dict):
            continue
        rewrites = tuple(
            (str(k), str(v)) for k, v in obj.items() if isinstance(v, str)
        )
        if rewrites:
            out.append(OOVCandidate(
                scenario_id=scenario.metadata.scenario_id, arm=arm,
                value_rewrites=rewrites))
    return out


def _call_cost(usage_in: int, usage_out: int) -> float:
    return usage_in * _PRICE_IN + usage_out * _PRICE_OUT


def make_live_generate_fn(model: str, provider: str = "anthropic") -> GenerateFn:
    """Build the real generate_fn (lazy network import). CLI use only."""
    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(provider, model)

    def _fn(scenario, arm, k):
        system, user = build_prompt(scenario, arm)
        user = user + f"\n\nProduce {k} distinct disguise attempts."
        resp = client.complete(system=system, user=user)
        cands = parse_candidates(scenario, arm, resp.content)
        cost = _call_cost(resp.usage_input_tokens, resp.usage_output_tokens)
        return cands, cost

    return _fn
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_generator.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```
git add ares/dialectic/measurement/read_depth_oov_generator.py tests/dialectic/measurement/test_read_depth_oov_generator.py
git commit -F <msgfile>   # feat(s089): OOV adversary generator (black/white prompts + parser)
```

---

## Task 3: Validity gate + novelty + judge orchestration

**Files:**
- Create: `ares/dialectic/measurement/read_depth_oov_validator.py`
- Test: `tests/dialectic/measurement/test_read_depth_oov_validator.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_validator.py
from ares.dialectic.measurement.read_depth_corpus import get_entry
from ares.dialectic.measurement.read_depth_oov_schema import ARM_BLACK, OOVCandidate
from ares.dialectic.measurement.read_depth_oov_validator import (
    apply_candidate, check_skeleton, is_novel, validate_candidate,
)

_SC = get_entry("RDF-M-LEX-001").scenario  # facts: fact-001/002/003


def _cand(rewrites):
    return OOVCandidate("RDF-M-LEX-001", ARM_BLACK, tuple(rewrites.items()))


def _judge_yes(orig, evaded):
    return True, 0.005


def _judge_no(orig, evaded):
    return False, 0.005


def test_apply_preserves_skeleton():
    evaded = apply_candidate(
        _SC, _cand({"rdf-m-lex-001-fact-002": "C:/Users/Public/pd-utility"}))
    ok, reason = check_skeleton(_SC, evaded)
    assert ok, reason


def test_unknown_fact_id_rejected_as_skeleton_failure():
    res, cost = validate_candidate(
        _SC, _cand({"no-such-fact": "x"}), _judge_yes)
    assert res.accepted is False and res.skeleton_ok is False
    assert "unknown_fact_id" in res.reject_reason and cost == 0.0


def test_no_op_rewrite_rejected():
    # rewrite a fact to its own value -> no value_hash differs -> no-op
    same = _SC.packet.get_fact("rdf-m-lex-001-fact-002").value
    res, _ = validate_candidate(_SC, _cand({"rdf-m-lex-001-fact-002": same}),
                                _judge_yes)
    assert res.accepted is False and res.skeleton_ok is False


def test_in_vocab_only_disguise_is_not_novel():
    # introduces only "binary" (a known synonym fold) -> non-novel -> rejected
    res, cost = validate_candidate(
        _SC, _cand({"rdf-m-lex-001-fact-002": "C:/Users/Public/procdump binary"}),
        _judge_yes)
    assert res.skeleton_ok is True and res.novel is False
    assert res.accepted is False and cost == 0.0  # judge never called


def test_oov_disguise_accepted_when_judge_confirms_malign():
    res, cost = validate_candidate(
        _SC,
        _cand({"rdf-m-lex-001-fact-003": "pd-utility dumps auth-process memory"}),
        _judge_yes)
    assert res.skeleton_ok and res.novel and res.judge_malign is True
    assert res.accepted is True and cost == 0.005


def test_oov_disguise_rejected_when_judge_says_benign():
    res, _ = validate_candidate(
        _SC,
        _cand({"rdf-m-lex-001-fact-003": "routine software update downloaded"}),
        _judge_no)
    assert res.novel is True and res.judge_malign is False
    assert res.accepted is False and res.reject_reason == "judge_benign"
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_validator.py -v`
Expected: FAIL with `ModuleNotFoundError: ... read_depth_oov_validator`.

- [ ] **Step 3: Write the implementation**

```python
# ares/dialectic/measurement/read_depth_oov_validator.py
"""Deterministic validity gate + LLM-judge orchestration (Phase D).

A candidate is ACCEPTED iff it (1) only rewrites existing facts' values
preserving the skeleton and is not a no-op, (2) is NOVEL (its new tokens are
not merely the canonicalizer's own synonym words), and (3) the LLM-judge
confirms it is still the same threat. Only (3) costs API; (1)-(2) are free.
"""
from __future__ import annotations

import re
from typing import Callable, Tuple

from ares.dialectic.agents.light_skeptic_v2_canonical import _SYNONYMS
from ares.dialectic.measurement.read_depth_oov_schema import (
    OOVCandidate, OOVValidationResult,
)
from ares.dialectic.schemas.skeleton_equivalence import skeleton_hash
from ares.dialectic.scripts.non_interference.paired_scenario_mutator import (
    MutationOperator, MutatedScenarioPair, SkeletonInvariantError,
    _apply_value_replacements,
)
from ares.dialectic.scripts.scenario_corpus import BenchmarkScenario

# (original_scenario, evaded_scenario) -> (still_malign, cost_usd)
JudgeFn = Callable[[BenchmarkScenario, BenchmarkScenario], Tuple[bool, float]]

_PRICE_IN = 3.0 / 1_000_000
_PRICE_OUT = 15.0 / 1_000_000

# Tokens the canonicalizer itself folds; a disguise built only from these is
# the in-vocabulary case S088 already measured, not a new disguise.
_KNOWN_FOLD_VOCAB = set(_SYNONYMS.keys()) | set(_SYNONYMS.values())

_TOKEN = re.compile(r"[a-z0-9]+")

# Validation-only synthetic operator (its transform is never invoked; the pair
# constructor only checks invariants). family must be a valid mutator family.
_SYNTH_OP = MutationOperator(
    operator_name="oov_adversarial_evasion", family="synonym",
    description="LLM-discovered OOV evasion (validation only)",
    transform=lambda s, seed: s,
)


def apply_candidate(
    scenario: BenchmarkScenario, candidate: OOVCandidate
) -> BenchmarkScenario:
    """Apply the candidate's value rewrites. Raises KeyError on unknown ids."""
    return _apply_value_replacements(scenario, candidate.rewrites_dict())


def check_skeleton(
    original: BenchmarkScenario, evaded: BenchmarkScenario
) -> Tuple[bool, str]:
    """True iff the pair preserves the skeleton and changed >= 1 value."""
    try:
        MutatedScenarioPair(
            baseline_scenario=original, mutated_scenario=evaded,
            operator_applied=_SYNTH_OP,
            skeleton_hash=skeleton_hash(original.packet))
    except SkeletonInvariantError as exc:
        return False, str(exc)
    return True, ""


def _tokens(scenario: BenchmarkScenario) -> set:
    out: set = set()
    for f in scenario.packet.get_all_facts():
        if isinstance(f.value, str):
            out.update(_TOKEN.findall(f.value.lower()))
    return out


def is_novel(original: BenchmarkScenario, evaded: BenchmarkScenario) -> bool:
    """Novel unless the only new tokens are the canonicalizer's own synonyms."""
    introduced = _tokens(evaded) - _tokens(original)
    if introduced and introduced.issubset(_KNOWN_FOLD_VOCAB):
        return False
    return True


def validate_candidate(
    scenario: BenchmarkScenario, candidate: OOVCandidate, judge_fn: JudgeFn
) -> Tuple[OOVValidationResult, float]:
    """Run the full gate. Returns (result, cost_usd). Judge is only called on
    candidates that pass the free skeleton + novelty gates."""
    try:
        evaded = apply_candidate(scenario, candidate)
    except KeyError as exc:
        return OOVValidationResult(
            candidate, skeleton_ok=False, novel=False, judge_malign=None,
            accepted=False, reject_reason=f"unknown_fact_id: {exc}"), 0.0

    ok, reason = check_skeleton(scenario, evaded)
    if not ok:
        return OOVValidationResult(
            candidate, skeleton_ok=False, novel=False, judge_malign=None,
            accepted=False, reject_reason=f"skeleton: {reason}"), 0.0

    if not is_novel(scenario, evaded):
        return OOVValidationResult(
            candidate, skeleton_ok=True, novel=False, judge_malign=None,
            accepted=False, reject_reason="non_novel_in_vocab"), 0.0

    malign, cost = judge_fn(scenario, evaded)
    accepted = bool(malign)
    return OOVValidationResult(
        candidate, skeleton_ok=True, novel=True, judge_malign=bool(malign),
        accepted=accepted, reject_reason="" if accepted else "judge_benign"), cost


def _call_cost(usage_in: int, usage_out: int) -> float:
    return usage_in * _PRICE_IN + usage_out * _PRICE_OUT


def make_live_judge_fn(model: str, provider: str = "anthropic") -> JudgeFn:
    """Build the real judge_fn (lazy network import). CLI use only."""
    from ares.dialectic.agents.strategies.client_factory import make_client
    client = make_client(provider, model)
    system = (
        "You are a senior SOC analyst. You will be shown security telemetry "
        "facts. Answer with a single word: YES if they still describe a real "
        "security THREAT (e.g. credential dumping, a dropper in a user-writable "
        "path, an ineffective-patch claim), or NO if they read as benign. "
        "Answer ONLY yes or no."
    )

    def _fn(original, evaded):
        facts = "\n".join(
            f"{f.field} = {f.value}" for f in evaded.packet.get_all_facts()
            if isinstance(f.value, str))
        resp = client.complete(system=system, user=f"Facts:\n{facts}")
        malign = resp.content.strip().lower().startswith("y")
        return malign, _call_cost(resp.usage_input_tokens,
                                  resp.usage_output_tokens)

    return _fn
```

Note for the implementer: `EvidencePacket.get_fact(fact_id)` is used in the test to read a fact's current value; if that accessor does not exist, read via `next(f for f in _SC.packet.get_all_facts() if f.fact_id == "rdf-m-lex-001-fact-002").value` instead. Verify the accessor name before running Step 2.

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_validator.py -v`
Expected: PASS (6 tests).

- [ ] **Step 5: Commit**

```
git add ares/dialectic/measurement/read_depth_oov_validator.py tests/dialectic/measurement/test_read_depth_oov_validator.py
git commit -F <msgfile>   # feat(s089): OOV validity gate (skeleton + novelty + judge)
```

---

## Task 4: Runner (orchestrate generate -> validate -> freeze -> measure)

**Files:**
- Create: `ares/dialectic/measurement/read_depth_oov_runner.py`
- Test: `tests/dialectic/measurement/test_read_depth_oov_runner.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_runner.py
from ares.dialectic.measurement.read_depth_corpus import MALIGN_ENTRIES
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, OOVCandidate,
    VERDICT_SUPPORTED_STRONG, VERDICT_FALSIFIED, VERDICT_INSTRUMENT_FAILURE,
)
from ares.dialectic.measurement.read_depth_oov_runner import (
    OOVConfig, estimate_cost_usd, run_oov_experiment, run_preflight,
)

# A disguise that strips every threat token -> canonical can no longer match.
_EVADE = {
    "RDF-M-LEX-001": {"rdf-m-lex-001-fact-002": "C:/Users/Public/pd-utility",
                      "rdf-m-lex-001-fact-003": "pd-utility reads auth memory"},
    "RDF-M-LEX-002": {"rdf-m-lex-002-fact-001": "C:/Users/Public/refresh-tool",
                      "rdf-m-lex-002-fact-003": "C:/Users/Public/refresh-tool 1.2MB"},
    "RDF-M-SYN-001": {"rdf-m-syn-001-fact-001": "payload placed in public area"},
    "RDF-M-PATCH-001": {"rdf-m-patch-001-fact-002": "pd-utility reads auth memory",
                        "rdf-m-patch-001-fact-003": "C:/Users/Public/pd-utility"},
}


def _gen_evade(scenario, arm, k):
    sid = scenario.metadata.scenario_id
    rewrites = _EVADE.get(sid, {})
    return [OOVCandidate(sid, arm, tuple(rewrites.items()))], 0.01


def _gen_weak(scenario, arm, k):
    # introduces an OOV token but keeps the threat literally present
    sid = scenario.metadata.scenario_id
    f = next(x for x in scenario.packet.get_all_facts()
             if isinstance(x.value, str))
    return [OOVCandidate(sid, arm, ((f.fact_id, f.value + " (oov-marker-xyz)"),))], 0.01


def _gen_empty(scenario, arm, k):
    return [], 0.0


def _judge_yes(orig, evaded):
    return True, 0.002


def test_preflight_is_free_and_reports_estimate():
    pf = run_preflight(OOVConfig(k=8))
    assert pf["estimate_usd"] > 0.0
    assert pf["corpus_digest"] == "9401b7188ba790a5"
    assert pf["n_malign"] == len(MALIGN_ENTRIES)


def test_estimate_scales_with_arms_and_k():
    one = estimate_cost_usd(OOVConfig(k=8, arms=(ARM_BLACK,)), per_call_usd=0.02)
    two = estimate_cost_usd(OOVConfig(k=8, arms=(ARM_BLACK, ARM_WHITE)),
                            per_call_usd=0.02)
    assert two > one


def test_canonical_evaded_in_black_box_is_supported_strong():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_evade,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_SUPPORTED_STRONG
    black = next(a for a in summ.arm_summaries if a.arm == ARM_BLACK)
    assert black.adversarial_x_scenario == 1.0          # all 4 evaded
    assert set(black.scenarios_evaded) == {e.scenario_id for e in MALIGN_ENTRIES}
    assert summ.total_cost_usd > 0.0
    assert len(summ.oov_corpus_digest) == 16


def test_canonical_holds_is_falsified():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_weak,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_FALSIFIED
    for a in summ.arm_summaries:
        assert a.adversarial_x_scenario == 0.0
        assert a.n_accepted > 0


def test_empty_generation_is_instrument_failure():
    summ = run_oov_experiment(OOVConfig(k=2), generate_fn=_gen_empty,
                              judge_fn=_judge_yes)
    assert summ.verdict == VERDICT_INSTRUMENT_FAILURE
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_runner.py -v`
Expected: FAIL with `ModuleNotFoundError: ... read_depth_oov_runner`.

- [ ] **Step 3: Write the implementation**

```python
# ares/dialectic/measurement/read_depth_oov_runner.py
"""Offline orchestrator for the OOV evasion experiment (Phase D).

generate -> validate -> freeze accepted corpus -> measure flips on the string
tiers -> classify. The LLM is reached only via injected generate_fn / judge_fn;
all flip measurement and the verdict are deterministic.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Tuple

from ares.dialectic.agents.light_skeptic_v2_ladder import DETERMINISTIC_TIERS
from ares.dialectic.measurement.read_depth_corpus import (
    MALIGN_ENTRIES, corpus_digest,
)
from ares.dialectic.measurement.read_depth_frontier_metrics import (
    flip_rate, is_malign_verdict,
)
from ares.dialectic.measurement.read_depth_frontier_runner import (
    _neutral_architect,
)
from ares.dialectic.measurement.read_depth_oov_generator import GenerateFn
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARMS, OOVArmSummary, OOVCandidate, OOVEvasionRecord, OOVFrontierSummary,
    classify_oov_verdict, oov_corpus_digest,
)
from ares.dialectic.measurement.read_depth_oov_validator import (
    JudgeFn, apply_candidate, validate_candidate,
)

_DEFAULT_MODEL = "claude-sonnet-4-20250514"


@dataclass(frozen=True)
class OOVConfig:
    k: int = 8
    seed: int = 0
    model: str = _DEFAULT_MODEL
    provider: str = "anthropic"
    arms: Tuple[str, ...] = ARMS


def estimate_cost_usd(cfg: OOVConfig, *, per_call_usd: float = 0.02) -> float:
    """Upper-bound estimate: one generation call per (arm, scenario) plus up to
    k judge calls per (arm, scenario)."""
    n_gen = len(cfg.arms) * len(MALIGN_ENTRIES)
    n_judge = len(cfg.arms) * len(MALIGN_ENTRIES) * cfg.k
    return round((n_gen + n_judge) * per_call_usd, 4)


def run_preflight(cfg: OOVConfig) -> Dict[str, object]:
    return {"estimate_usd": estimate_cost_usd(cfg),
            "corpus_digest": corpus_digest(),
            "n_malign": len(MALIGN_ENTRIES), "arms": list(cfg.arms), "k": cfg.k}


def _is_malign(tier_fn, packet, arch) -> bool:
    return is_malign_verdict(tier_fn(packet, arch), 0.0)


def run_oov_experiment(
    cfg: OOVConfig, *, generate_fn: GenerateFn, judge_fn: JudgeFn
) -> OOVFrontierSummary:
    arch = _neutral_architect()
    canonical = DETERMINISTIC_TIERS["v2_canonical"]
    lexical = DETERMINISTIC_TIERS["v2_lexical"]

    total_cost = 0.0
    accepted_all: List[OOVCandidate] = []
    records: List[OOVEvasionRecord] = []
    arm_summaries: List[OOVArmSummary] = []

    for arm in cfg.arms:
        n_cand = n_acc = n_rej_sk = n_rej_nov = n_rej_judge = 0
        evaded: set = set()
        arm_flips = 0
        for e in MALIGN_ENTRIES:
            cands, gcost = generate_fn(e.scenario, arm, cfg.k)
            total_cost += gcost
            n_cand += len(cands)
            base_canon = _is_malign(canonical, e.scenario.packet, arch)
            base_lex = _is_malign(lexical, e.scenario.packet, arch)
            for cand in cands:
                res, vcost = validate_candidate(e.scenario, cand, judge_fn)
                total_cost += vcost
                if not res.accepted:
                    if not res.skeleton_ok:
                        n_rej_sk += 1
                    elif not res.novel:
                        n_rej_nov += 1
                    else:
                        n_rej_judge += 1
                    continue
                n_acc += 1
                accepted_all.append(cand)
                evaded_sc = apply_candidate(e.scenario, cand)
                canon_flip = base_canon and not _is_malign(
                    canonical, evaded_sc.packet, arch)
                lex_flip = base_lex and not _is_malign(
                    lexical, evaded_sc.packet, arch)
                if canon_flip:
                    evaded.add(e.scenario_id)
                    arm_flips += 1
                records.append(OOVEvasionRecord(
                    e.scenario_id, arm, canon_flip, lex_flip))
        arm_summaries.append(OOVArmSummary(
            arm=arm, n_candidates=n_cand, n_accepted=n_acc,
            n_rejected_skeleton=n_rej_sk, n_rejected_novelty=n_rej_nov,
            n_rejected_judge=n_rej_judge,
            scenarios_evaded=tuple(sorted(evaded)),
            adversarial_x_scenario=flip_rate(len(MALIGN_ENTRIES), len(evaded)),
            per_candidate_flip_rate=flip_rate(n_acc, arm_flips),
            n_malign_scenarios=len(MALIGN_ENTRIES)))

    verdict = classify_oov_verdict(tuple(arm_summaries))
    return OOVFrontierSummary(
        arm_summaries=tuple(arm_summaries), records=tuple(records),
        verdict=verdict, corpus_digest=corpus_digest(),
        oov_corpus_digest=oov_corpus_digest(tuple(accepted_all)),
        total_cost_usd=round(total_cost, 4), model=cfg.model,
        provider=cfg.provider, k=cfg.k)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_runner.py -v`
Expected: PASS (5 tests).

If `test_canonical_evaded_in_black_box_is_supported_strong` fails because a chosen `_EVADE` rewrite still trips the canonical regex, inspect the failure, adjust that scenario's rewrite in the test so canonical truly stops matching (the goal: no `_USER_WRITABLE_DIR`+`_EXECUTABLE_CANON` co-occurrence and no `_CRED_TOOLING` token after canonicalization), and re-run. This is test-data tuning, not an implementation change.

- [ ] **Step 5: Commit**

```
git add ares/dialectic/measurement/read_depth_oov_runner.py tests/dialectic/measurement/test_read_depth_oov_runner.py
git commit -F <msgfile>   # feat(s089): OOV experiment runner + cost estimate + preflight
```

---

## Task 5: Report renderer

**Files:**
- Create: `ares/dialectic/measurement/read_depth_oov_report.py`
- Test: `tests/dialectic/measurement/test_read_depth_oov_report.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_report.py
from ares.dialectic.measurement.read_depth_oov_schema import (
    ARM_BLACK, ARM_WHITE, OOVArmSummary, OOVEvasionRecord, OOVFrontierSummary,
    VERDICT_SUPPORTED_STRONG,
)
from ares.dialectic.measurement.read_depth_oov_report import render_oov_report


def _summary():
    black = OOVArmSummary(ARM_BLACK, 8, 6, 1, 1, 0, ("RDF-M-LEX-001",),
                          0.25, 0.1667, 4)
    white = OOVArmSummary(ARM_WHITE, 8, 7, 0, 1, 0, ("RDF-M-LEX-001",),
                          0.25, 0.1429, 4)
    rec = OOVEvasionRecord("RDF-M-LEX-001", ARM_BLACK, True, True)
    return OOVFrontierSummary((black, white), (rec,), VERDICT_SUPPORTED_STRONG,
                              "9401b7188ba790a5", "abcdef0123456789", 1.5,
                              "claude-sonnet-4-20250514", "anthropic", 8)


def test_report_has_verdict_table_and_caveats():
    md = render_oov_report(_summary())
    assert "SUPPORTED_STRONG" in md
    assert "black" in md and "white" in md
    assert "adversarial" in md.lower()
    assert "RDF-M-LEX-001" in md
    # the honest caveats are stated
    assert "small" in md.lower() and "caveat" in md.lower()
    # the non-falsifier framing is named
    assert "v2_canonical" in md
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_report.py -v`
Expected: FAIL with `ModuleNotFoundError: ... read_depth_oov_report`.

- [ ] **Step 3: Write the implementation**

```python
# ares/dialectic/measurement/read_depth_oov_report.py
"""Markdown renderer for the OOV evasion experiment verdict (Phase D)."""
from __future__ import annotations

from ares.dialectic.measurement.read_depth_oov_schema import OOVFrontierSummary

_VERDICT_GLOSS = {
    "SUPPORTED_STRONG": "a blind (black-box) adversary evaded v2_canonical — "
                        "framing-robustness was blindness, not defense.",
    "SUPPORTED_MODERATE": "v2_canonical survived the blind adversary but fell "
                          "to a source-reading (white-box) one.",
    "FALSIFIED": "v2_canonical held against adversarial OOV disguises in both "
                 "arms — the deterministic content-robustness recipe is real.",
    "INSTRUMENT_FAILURE": "an arm produced zero accepted disguises; the judge "
                          "rejected everything. No verdict is read.",
}


def render_oov_report(summary: OOVFrontierSummary) -> str:
    lines = []
    lines.append("# OOV Adversarial Evasion — Phase D Verdict")
    lines.append("")
    lines.append(f"## Verdict: **{summary.verdict}**")
    lines.append("")
    lines.append(_VERDICT_GLOSS.get(summary.verdict, summary.verdict))
    lines.append("")
    lines.append(f"Model `{summary.model}` ({summary.provider}), K={summary.k}, "
                 f"base corpus `{summary.corpus_digest}`, OOV corpus "
                 f"`{summary.oov_corpus_digest}`, spend ${summary.total_cost_usd}.")
    lines.append("")
    lines.append("## Per-arm frontier (verdict tier = v2_canonical)")
    lines.append("")
    lines.append("| arm | candidates | accepted | rej(skel/nov/judge) | "
                 "scenarios evaded | adversarial X (scenario) | per-candidate flip |")
    lines.append("|---|---:|---:|---|---|---:|---:|")
    for a in summary.arm_summaries:
        rej = f"{a.n_rejected_skeleton}/{a.n_rejected_novelty}/{a.n_rejected_judge}"
        evaded = ", ".join(a.scenarios_evaded) or "(none)"
        lines.append(
            f"| {a.arm} | {a.n_candidates} | {a.n_accepted} | {rej} | "
            f"{evaded} | {a.adversarial_x_scenario:.3f} | "
            f"{a.per_candidate_flip_rate:.3f} |")
    lines.append("")
    lines.append("## Honest caveats")
    lines.append("")
    lines.append("- **Small N:** four malign string-borne scenarios; the "
                 "per-candidate flip-rate is the higher-N magnitude beside the "
                 "scenario-level verdict.")
    lines.append("- **Single adversary model:** one family's disguise "
                 "imagination is sampled.")
    lines.append("- **Judge dependence:** the meaning-preservation oracle is "
                 "itself an LLM; reject counts are reported, not hidden.")
    lines.append("")
    return "\n".join(lines)
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_report.py -v`
Expected: PASS (1 test).

- [ ] **Step 5: Commit**

```
git add ares/dialectic/measurement/read_depth_oov_report.py tests/dialectic/measurement/test_read_depth_oov_report.py
git commit -F <msgfile>   # feat(s089): OOV verdict report renderer
```

---

## Task 6: Pre-registration doc + SSOT band-guard test

**Files:**
- Create: `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md`
- Test: `tests/paper_4/test_oov_prereg_bands_match_code.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/paper_4/test_oov_prereg_bands_match_code.py
from pathlib import Path

from ares.dialectic.measurement.read_depth_oov_schema import (
    FALSIFIED_REQUIRES_ZERO_EVASIONS, READ_DEPTH_OOV_HARD_CEILING_USD,
    VERDICT_FALSIFIED, VERDICT_SUPPORTED_MODERATE, VERDICT_SUPPORTED_STRONG,
)

_DOC = (Path(__file__).resolve().parents[2]
        / "docs" / "paper_4" / "PREREGISTRATION_oov_evasion_phase_d.md")


def test_prereg_doc_exists():
    assert _DOC.is_file()


def test_prereg_states_the_any_hole_rule_matching_code():
    text = _DOC.read_text(encoding="utf-8")
    assert FALSIFIED_REQUIRES_ZERO_EVASIONS is True
    assert "zero evaded scenarios" in text
    assert f"${READ_DEPTH_OOV_HARD_CEILING_USD:.0f}" in text  # $10


def test_prereg_names_all_three_verdict_labels():
    text = _DOC.read_text(encoding="utf-8")
    for label in (VERDICT_SUPPORTED_STRONG, VERDICT_SUPPORTED_MODERATE,
                  VERDICT_FALSIFIED):
        assert label in text


def test_prereg_names_corpus_arms_and_falsifier():
    text = _DOC.read_text(encoding="utf-8").lower()
    assert "9401b7188ba790a5" in text
    assert "black-box" in text and "white-box" in text
    assert "falsif" in text
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/paper_4/test_oov_prereg_bands_match_code.py -v`
Expected: FAIL on `test_prereg_doc_exists` (doc missing).

- [ ] **Step 3: Write the pre-registration doc**

Create `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md` with exactly this content:

```markdown
# Pre-Registration — OOV Adversarial Evasion (Read-Depth Frontier, Phase D)

**Committed:** 2026-06-12 (before the live adversary run). **Frozen on commit.**
**Base corpus:** Adaptive Corpus C, digest `9401b7188ba790a5` (4 malign string-borne scenarios).

## What this resolves

S088 closed Phase C with the trilemma SUPPORTED, resting on one named non-falsifier:
`v2_canonical`'s `X_lexical = 0` is true **by construction** (the Phase B evasion operators emit
only in-vocabulary tokens the canonicalizer folds). This experiment turns `X_lexical` into a
measured adversarial quantity by letting an LLM adversary invent out-of-vocabulary disguises.

## Observed vs predicted ledger

- **OBSERVED (frozen, S088):** `v2_canonical` standalone `TPR = 1.000` (catches all 4 malign
  string scenarios); `X_lexical = 0` by construction.
- **PREDICTED (this pre-registration):** the adversarial `X_lexical` of `v2_canonical` under
  LLM-discovered OOV disguises is the only unobserved quantity. Its decision rule is committed
  before the run.

## Decision rule (frozen, 3-way graded)

Direction (corrected from the S088 note's crossed clause): **OOV evasion succeeds => SUPPORTED**
(canonical is evadable, leaves the good corner); **OOV evasion fails => FALSIFIED** (the recipe is
real).

- `SUPPORTED_STRONG` — `v2_canonical` is evaded in the **black-box** arm (a blind attacker beats it).
- `SUPPORTED_MODERATE` — survives black-box, evaded in the **white-box** arm.
- `FALSIFIED` — survives **both** arms with detection intact.

**Threshold (any hole):** a `FALSIFIED` verdict requires **zero evaded scenarios** in the arm under
test. A meaning-preserving disguise that flips `v2_canonical` on even one of the four malign
scenarios proves evadability. (Equivalent to a 0.10 ceiling on the scenario-level rate, whose
smallest non-zero value is 0.25.)

**Validity precondition:** the rule is read only on a non-empty accepted corpus per arm. An arm whose
judge rejects every candidate yields `INSTRUMENT_FAILURE`, not a verdict.

## Falsifier and non-falsifier

- **Falsifier:** `v2_canonical` survives both arms (`SUPPORTED`/`FALSIFIED` are symmetric publishable
  outcomes; "the recipe exists" is the FALSIFIED branch).
- **Named non-falsifier (now under test):** the S088 standalone-corner position of `v2_canonical`,
  which this experiment exists to convert from assumption to measurement.

## Protocol (frozen)

- Adversary + judge: `claude-sonnet-4-20250514`, both arms (black-box / white-box), K disguise
  attempts per malign scenario.
- A candidate is ACCEPTED iff skeleton-invariant, novel (new tokens not merely the canonicalizer's
  own synonyms), and judged still-malign.
- Flip = `v2_canonical` malign->benign on an accepted disguise. Measurement is deterministic on the
  frozen accepted corpus.
- `$10` hard cost cap (generation + judging only; all measurement is free).

## Honest caveats (stated before the run)

- **Small N:** four malign string-borne scenarios; the per-candidate flip-rate is reported as the
  higher-N magnitude.
- **Single adversary model.**
- **Judge dependence:** the meaning-preservation oracle is an LLM; reject rates are reported.
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/paper_4/test_oov_prereg_bands_match_code.py -v`
Expected: PASS (4 tests).

- [ ] **Step 5: Commit**

```
git add docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md tests/paper_4/test_oov_prereg_bands_match_code.py
git commit -F <msgfile>   # docs(s089): Phase D pre-registration + SSOT band guard
```

---

## Task 7: CLI (`run_session_089.py`)

**Files:**
- Create: `scripts/run_session_089.py`
- Test: `tests/dialectic/measurement/test_run_session_089_cli.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_run_session_089_cli.py
from scripts.run_session_089 import main


def test_cost_ceiling_over_hard_cap_refuses(capsys):
    rc = main(["--provider", "anthropic", "--cost-ceiling", "999"])
    assert rc == 2
    assert "hard cap" in capsys.readouterr().err


def test_dry_run_prints_estimate_and_exits_zero(capsys):
    rc = main(["--provider", "anthropic", "--dry-run"])
    assert rc == 0
    assert "estimate" in capsys.readouterr().out.lower()


def test_live_without_confirm_halts(capsys):
    rc = main(["--provider", "anthropic"])
    assert rc == 1
    assert "confirm-live" in capsys.readouterr().err
```

- [ ] **Step 2: Run test to verify it fails**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_089_cli.py -v`
Expected: FAIL with `ModuleNotFoundError: ... run_session_089`.

- [ ] **Step 3: Write the implementation**

```python
# scripts/run_session_089.py
"""Session 089 — OOV adversarial evasion experiment (read-depth Phase D).

Mirrors run_session_088.py: UTF-16 .env load, preflight -> --confirm-live gate,
$10 hard cap, pre-registration-file gate. Offline by default (--dry-run prints
the cost estimate). The live run requires --confirm-live and the committed
pre-registration.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

_REPO_ROOT = Path(__file__).resolve().parents[1]
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

_PREREG = _REPO_ROOT / "docs" / "paper_4" / "PREREGISTRATION_oov_evasion_phase_d.md"


def _load_env() -> int:
    env_path = _REPO_ROOT / ".env"
    if not env_path.exists():
        return 0
    with open(env_path, "r", encoding="utf-16") as f:
        content = f.read()
    loaded = 0
    import os
    for line in content.strip().splitlines():
        line = line.strip()
        if "=" in line and not line.startswith("#"):
            key, _, value = line.partition("=")
            if key.strip() and value.strip():
                os.environ[key.strip()] = value.strip()
                loaded += 1
    return loaded


def main(argv=None) -> int:
    from ares.dialectic.measurement.read_depth_oov_schema import (
        ARM_BLACK, ARM_WHITE, ARMS, READ_DEPTH_OOV_HARD_CEILING_USD,
    )
    from ares.dialectic.measurement.read_depth_oov_runner import (
        OOVConfig, estimate_cost_usd, run_oov_experiment,
    )
    p = argparse.ArgumentParser(description="Session 089 — OOV evasion (Phase D)")
    p.add_argument("--provider", required=True)
    p.add_argument("--model", default="claude-sonnet-4-20250514")
    p.add_argument("--k", type=int, default=8)
    p.add_argument("--arm", choices=["black", "white", "both"], default="both")
    p.add_argument("--cost-ceiling", type=float, default=10.0)
    p.add_argument("--dry-run", action="store_true")
    p.add_argument("--preflight-only", action="store_true")
    p.add_argument("--confirm-live", action="store_true")
    args = p.parse_args(argv)

    if args.cost_ceiling > READ_DEPTH_OOV_HARD_CEILING_USD:
        print(f"[FATAL] cost_ceiling ${args.cost_ceiling} > hard cap "
              f"${READ_DEPTH_OOV_HARD_CEILING_USD}; refusing.", file=sys.stderr)
        return 2

    arms = ARMS if args.arm == "both" else (
        ARM_BLACK if args.arm == "black" else ARM_WHITE,)
    cfg = OOVConfig(k=args.k, model=args.model, provider=args.provider, arms=arms)
    est = estimate_cost_usd(cfg)
    print(f"[preflight] cost estimate ${est} (ceiling ${args.cost_ceiling})")

    if args.dry_run or args.preflight_only:
        return 0
    if not args.confirm_live:
        print("[halt] live run needs --confirm-live", file=sys.stderr)
        return 1
    if not _PREREG.is_file():
        print("[halt] pre-registration doc missing; commit it first.",
              file=sys.stderr)
        return 1
    if est > args.cost_ceiling:
        print(f"[halt] estimate ${est} exceeds ceiling ${args.cost_ceiling}",
              file=sys.stderr)
        return 1

    print(f"[env] loaded {_load_env()} keys from .env (UTF-16 LE)")
    from ares.dialectic.measurement.read_depth_oov_generator import (
        make_live_generate_fn,
    )
    from ares.dialectic.measurement.read_depth_oov_validator import (
        make_live_judge_fn,
    )
    from ares.dialectic.measurement.read_depth_oov_report import render_oov_report
    summary = run_oov_experiment(
        cfg, generate_fn=make_live_generate_fn(args.model, args.provider),
        judge_fn=make_live_judge_fn(args.model, args.provider))
    out_dir = _REPO_ROOT / "data" / "paper_4" / "read_depth_oov"
    out_dir.mkdir(parents=True, exist_ok=True)
    (out_dir / "oov_summary.json").write_text(summary.to_json(), encoding="utf-8")
    (out_dir / "oov_report.md").write_text(render_oov_report(summary),
                                           encoding="utf-8")
    print(f"[done] verdict {summary.verdict}; spent ${summary.total_cost_usd}; "
          f"wrote oov_summary.json + oov_report.md")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
```

- [ ] **Step 4: Run test to verify it passes**

Run: `python -m pytest tests/dialectic/measurement/test_run_session_089_cli.py -v`
Expected: PASS (3 tests).

- [ ] **Step 5: Commit**

```
git add scripts/run_session_089.py tests/dialectic/measurement/test_run_session_089_cli.py
git commit -F <msgfile>   # feat(s089): Phase D CLI (preflight-gated, $10 cap, prereg gate)
```

---

## Task 8: Anchor test (zero-LLM / zero-network on the deterministic gate)

**Files:**
- Test: `tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py`

- [ ] **Step 1: Write the failing test**

```python
# tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py
"""The deterministic seam (schema, validator gate, runner with injected fns)
must carry no module-level LLM/network dependency — mirrors the v1 anchor."""
import sys


def test_schema_and_validator_do_not_import_anthropic_at_module_load():
    for mod in ("ares.dialectic.measurement.read_depth_oov_schema",
                "ares.dialectic.measurement.read_depth_oov_validator",
                "ares.dialectic.measurement.read_depth_oov_runner"):
        __import__(mod)
    assert "anthropic" not in sys.modules, (
        "a Phase-D measurement module imported anthropic at load time; the "
        "live client must stay behind make_live_* lazy imports")


def test_runner_executes_with_injected_fakes_only():
    from ares.dialectic.measurement.read_depth_oov_runner import (
        OOVConfig, run_oov_experiment,
    )

    def gen(scenario, arm, k):
        return [], 0.0

    def judge(orig, evaded):
        raise AssertionError("judge must not be called when no candidates exist")

    summ = run_oov_experiment(OOVConfig(k=1, arms=("black",)),
                              generate_fn=gen, judge_fn=judge)
    assert summ.total_cost_usd == 0.0
```

Note: if another already-imported test in the same session pulled in `anthropic`, run this file in isolation (`python -m pytest tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py -p no:cacheprovider -v`) so `sys.modules` reflects only this module's imports.

- [ ] **Step 2: Run to verify it passes immediately** (the modules from Tasks 1/3/4 already satisfy it — this is a guard, not new behavior)

Run: `python -m pytest tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py -v`
Expected: PASS (2 tests). If `test_schema_and_validator_...` fails, a module added a top-level `import anthropic` or a non-lazy `make_client` import — move it inside `make_live_*`.

- [ ] **Step 3: Commit**

```
git add tests/dialectic/measurement/test_read_depth_oov_no_network_anchor.py
git commit -F <msgfile>   # test(s089): zero-network anchor on the Phase D deterministic seam
```

---

## Task 9: Full-suite verification + ledger update

**Files:**
- Modify: `CLAUDE.md` (ledger entry + key code locations + test floor + Last updated)

- [ ] **Step 1: Run the full suite, confirm zero regressions**

Run: `python -m pytest tests/ ares/ -q`
Expected: all pass; count is the prior floor (4,291) + the new Phase D tests (~26: 7 schema + 4 generator + 6 validator + 5 runner + 1 report + 4 prereg + 3 CLI + 2 anchor − any that share a parametrization). Record the exact passing number from the run.

- [ ] **Step 2: Run the CLAUDE.md freshness gate specifically**

Run: `python -m pytest tests/test_claude_md_freshness.py -v`
Expected: PASS. If it fails on the declared floor, that is Step 3's job.

- [ ] **Step 3: Update `CLAUDE.md`**

- Bump `**Last updated:**` to today and `**Test count floor (passing):**` to the exact number from Step 1.
- Add a `### Read-depth Phase D — OOV adversarial evasion (Session 089)` block under Key Code Locations listing the five `read_depth_oov_*` modules, `scripts/run_session_089.py`, and `docs/paper_4/PREREGISTRATION_oov_evasion_phase_d.md`.
- Add a Session 089 line to the condensed ledger: "Read-Depth Frontier Phase D1: OOV adversarial evasion instrument (LLM-adversary generator + deterministic skeleton/novelty gate + LLM-judge + frozen-corpus measurement of v2_canonical adversarial flip-rate) + Phase D pre-registration; black/white graded 3-way verdict; offline/free, live run gated. +~26 tests."

- [ ] **Step 4: Re-run the freshness gate + full suite**

Run: `python -m pytest tests/test_claude_md_freshness.py tests/ ares/ -q`
Expected: all pass with the updated floor.

- [ ] **Step 5: Commit**

```
git add CLAUDE.md
git commit -F <msgfile>   # docs(s089): CLAUDE.md ledger + Phase D code locations + test floor
```

---

## Self-review (completed during planning)

- **Spec coverage:** §4 components 1-5 -> Tasks 2,3,4,5 (+ schema Task 1); §5 arms -> generator `build_prompt` + runner arm loop; §6 metrics -> runner `adversarial_x_scenario` + `per_candidate_flip_rate`; §7 3-way rule + any-hole + empty-corpus guard -> `classify_oov_verdict` (Task 1) + prereg (Task 6); §8 constraints -> new-files-only, injectable seams, anchor (Task 8); §9 file plan -> Tasks 1-7; §11 error handling -> validator reject paths + CLI gates; §12 testing -> every task is TDD + Task 8 anchor + Task 6 SSOT; §13 cost -> `estimate_cost_usd` + `$10` cap; §16 caveats -> report + prereg.
- **Placeholder scan:** none; every code step is complete.
- **Type consistency:** `OOVCandidate.value_rewrites: Tuple[Tuple[str,str],...]`, `rewrites_dict()`, `GenerateFn=(scenario,arm,k)->(list,cost)`, `JudgeFn=(orig,evaded)->(bool,cost)`, `classify_oov_verdict(tuple)->str`, `OOVArmSummary` field names are identical across schema/runner/report/tests.
- **Known verification points flagged inline:** `EvidencePacket.get_fact` accessor name (Task 3 note); `_EVADE` test-data tuning so canonical truly stops matching (Task 4 note); `sys.modules` isolation for the anchor (Task 8 note).
