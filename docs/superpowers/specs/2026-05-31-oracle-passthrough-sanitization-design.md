# Design: Oracle `supporting_fact_ids` sanitization (peer, opt-in)

**Date:** 2026-05-31
**Session:** 078
**Status:** Draft — awaiting Dan's review
**Branch:** `session/078-oracle-passthrough-sanitization`

**Related:**
- Leak surface: `ares/dialectic/agents/oracle.py:89,102,116`
- Anchor test that locks the leak (Paper 3 Finding 2): `ares/dialectic/tests/agents/test_oracle_supporting_fact_ids_passthrough.py`
- Measurement that observed it live: S059 broad-kill; S075 cross-model (60–78% LLM-path divergence)
- Controlled measurement of the framing component: S077 (`docs/superpowers/specs/2026-05-29-architect-path-measurement-design.md`)

---

## 1. Problem

`OracleJudge.compute_verdict` receives the `EvidencePacket` (oracle.py:67) but **never reads it**. Under `THREAT_CONFIRMED` it copies the Architect's LLM-chosen citations into the authoritative verdict, verbatim:

```
arch_facts = architect_msg.get_all_fact_ids()      # oracle.py:89
...
supporting_facts = frozenset(arch_facts)           # oracle.py:102
...
supporting_fact_ids=supporting_facts,              # oracle.py:116
```

The verdict's **decision surface** (`outcome`, `confidence`) is computed deterministically by the decision table. The verdict's **explanation surface** (`supporting_fact_ids`) is an unvalidated passthrough of framing-sensitive LLM output.

In the leakage harness, the **oracle layer's `cited_facts_changed` bit** is the symmetric difference of `Verdict.supporting_fact_ids` between a baseline and a framing-mutated sibling (`influence_leakage.cited_facts_changed`). Because that set tracks the Architect's citations, a framing change flips the bit → contributes weight `0.20 > KILL_THRESHOLD (0.0)` → the **oracle broad-kill fires**. S059/S075 confirmed the *outcome* and *confidence* at the oracle layer do **not** drift — only this cited-facts bit. So the oracle-layer broad-kill is entirely attributable to the passthrough.

## 2. Goal & success criteria

Make `supporting_fact_ids` **framing-invariant** by deriving it deterministically from the packet (not from the Architect's citations), so the oracle layer's `cited_facts_changed` bit is `False` across framing mutations.

Success (all verifiable **offline**, zero API spend):
1. A new invariance anchor test proves: under the existing passthrough-anchor drift scenario, the sanitized `supporting_fact_ids` is **equal** baseline-vs-mutated, while `outcome` and `confidence` are preserved.
2. Unit tests cover every branch of the derivation rule + edge cases.
3. An integration test shows the opt-in factory produces a verdict whose narrator cites only the sanitized set.

## 3. Non-goals / out of scope

- **No live run.** Invariance is provable offline (see §6); a live re-run is deferred.
- **No edits to existing files.** `oracle.py`, the passthrough anchor test, `firewall.py`, `light_skeptic.py`, the cycles, and the `InfluenceLeakage` schema/weights are all untouched.
- **No production cutover.** This delivers the sanitizer + an opt-in seam. Wiring it into a *named* production cycle is a separate, later step.
- **Paper 3 stays reproducible on HEAD.** Because the default Oracle is unchanged, a reviewer who reruns the leakage harness on HEAD still observes Finding 2.

## 4. Constraints honored (CLAUDE.md non-negotiables)

- **New files only** — one new module, two new test files. Nothing existing is modified.
- **Frozen dataclasses** — `Verdict` is frozen; the sanitizer returns a new instance via `dataclasses.replace`.
- **Oracle stays deterministic, no LLM** — the sanitizer is pure Python over the packet.
- **Peer modules, not wrappers** — the factory composes the same primitives (`OracleJudge`, `OracleNarrator`) as `create_oracle_verdict`.

## 5. Design

### 5.1 Module & placement

One new module: **`ares/dialectic/agents/verdict_sanitizer.py`** — pure, deterministic, stateless.

It lives in `agents/` (not `coordinator/`) because every dependency points that way: `Verdict`/`VerdictOutcome` (`agents.patterns`), `OracleJudge`/`OracleNarrator` (`agents.oracle`), `_STAGE_MAP`/`_DEFAULT_STAGE` (`agents.light_skeptic`), and the firewall field-sets (`coordinator.firewall` — the same agents→coordinator direction `light_skeptic` already uses). Placing it in `coordinator/` would invert that edge and risk an import cycle.

Reusing the module-private constants `_STAGE_MAP`, `_DEFAULT_STAGE`, `_AUTHORIZATION_FACT_FIELDS`, `_BENIGN_INDICATOR_FIELDS` follows existing precedent (`architect_framing_control.py` already imports `_STAGE_MAP`/`_DEFAULT_STAGE`; `light_skeptic.py` already imports the firewall field-sets). Reusing the single source of truth is preferred over duplicating the stage map (which would risk drift).

### 5.2 Components (three public functions)

**`relevant_fact_ids(packet, outcome) -> frozenset[str]`** — the deterministic kill-chain rule, packet-only:

```
facts = packet.get_all_facts()
if not facts:                      # empty packet
    return frozenset()

if outcome == THREAT_CONFIRMED:
    stage = {f.fact_id: _STAGE_MAP.get(f.field, _DEFAULT_STAGE) for f in facts}
    top = max(stage.values())
    return frozenset(fid for fid, s in stage.items() if s == top)   # max-stage facts (ties → all)

if outcome == THREAT_DISMISSED:
    exculpatory_fields = _AUTHORIZATION_FACT_FIELDS | _BENIGN_INDICATOR_FIELDS
    exculpatory = frozenset(f.fact_id for f in facts if f.field in exculpatory_fields)
    return exculpatory or frozenset(f.fact_id for f in facts)        # fallback: whole packet

# INCONCLUSIVE
return frozenset(f.fact_id for f in facts)
```

**`sanitize_verdict(verdict, packet) -> Verdict`**:

```
return dataclasses.replace(
    verdict,
    supporting_fact_ids=relevant_fact_ids(packet, verdict.outcome),
)
```

Touches only `supporting_fact_ids`; every other field is carried through unchanged.

**`create_sanitized_oracle_verdict(architect_msg, skeptic_msg, packet) -> tuple[Verdict, OracleNarrator]`** — the opt-in seam, mirroring `oracle.create_oracle_verdict`:

```
verdict   = OracleJudge.compute_verdict(architect_msg, skeptic_msg, packet)
sanitized = sanitize_verdict(verdict, packet)
narrator  = OracleNarrator(verdict=sanitized)
narrator.observe(packet)
return sanitized, narrator
```

Building the narrator from the *sanitized* verdict means the VERDICT message cites the sanitized set too — no inconsistency between the verdict object and its explanation. A caller opts in by invoking this instead of `create_oracle_verdict`.

### 5.3 Data flow

```
architect_msg + skeptic_msg + packet
        │
        ▼
OracleJudge.compute_verdict   →  Verdict{outcome, confidence, supporting_fact_ids = raw passthrough, …}
        │                                         (decision surface)        (framing-sensitive)
        ▼
sanitize_verdict(verdict, packet)
        │   re-derive supporting_fact_ids = relevant_fact_ids(packet, outcome)
        ▼
Verdict{ same outcome/confidence/architect_confidence/skeptic_confidence/reasoning,
         supporting_fact_ids = packet-derived }   →  OracleNarrator cites sanitized set
```

The decision surface is preserved byte-for-byte; only `supporting_fact_ids` is replaced.

### 5.4 Edge cases

- **Empty packet** → `frozenset()` (non-raising; the narrator already handles an empty supporting set, oracle.py:319–325).
- **Ties at the top stage** (CONFIRMED) → all tied fact_ids included.
- **DISMISSED with no authorization/benign field present** → fall back to the whole packet's fact_ids (keeps the set non-empty and packet-derived).
- **Uniform-stage packet** (CONFIRMED) → degenerates to all fact_ids; acceptable and still invariant.

## 6. Why it closes the leak — by construction (honest framing)

The framing mutators change framing text / `fact.value`; they never change the packet's **fact-id set** or per-fact **`field`**. Every branch of `relevant_fact_ids` is a function of only those invariant inputs, so it returns an identical fact-id set for a baseline and its framing-mutated sibling → the oracle layer's `cited_facts_changed` bit is `False` → no oracle broad-kill.

This invariance is **true by construction, not empirically discovered** — the same epistemic status as the narrow result (the post-S076 caveat). The fix genuinely closes the channel; we are not claiming an empirical surprise. A live re-run would *demonstrate* the wiring end-to-end, not *discover* anything, which is why it is deferred.

## 7. Testing plan (offline, two new test files)

**`ares/dialectic/tests/agents/test_verdict_sanitizer.py`** — unit + integration:
- `relevant_fact_ids`: CONFIRMED max-stage selection; ties at top stage; DISMISSED exculpatory selection; DISMISSED no-exculpatory → whole-packet fallback; INCONCLUSIVE → whole packet; empty packet → empty.
- `sanitize_verdict`: preserves `outcome`, `confidence`, `architect_confidence`, `skeptic_confidence`, `reasoning`; replaces only `supporting_fact_ids`; returns a distinct frozen `Verdict`.
- `create_sanitized_oracle_verdict`: returns `(sanitized_verdict, narrator)`; the narrator's VERDICT message cites only the sanitized set; mirrors `create_oracle_verdict`'s contract otherwise.

**`ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py`** — the **inverse** of the passthrough anchor (it complements, never edits, the existing one):
- Reuse the passthrough anchor's drift scenario: baseline Architect cites `{A1,A2,A3}`, mutated cites `{A2,A3}`, same packet, both `THREAT_CONFIRMED`.
- Assert through `sanitize_verdict` / `create_sanitized_oracle_verdict` that the sanitized `supporting_fact_ids` are **equal** baseline-vs-mutated (drift no longer propagates), while `outcome` and `confidence` remain equal — the documentary proof-of-fix.

## 8. Files

| File | Status |
|---|---|
| `ares/dialectic/agents/verdict_sanitizer.py` | NEW |
| `ares/dialectic/tests/agents/test_verdict_sanitizer.py` | NEW |
| `ares/dialectic/tests/agents/test_verdict_sanitizer_invariance_anchor.py` | NEW |
| `oracle.py`, passthrough anchor, `firewall.py`, `light_skeptic.py`, cycles, `influence_leakage.py` | UNTOUCHED |

## 9. Risks / open items

- **Semantic shift:** `supporting_fact_ids` changes meaning from "what the Architect cited" to "the packet-derived relevant facts." This is intended (it is the fix) and only takes effect on the opt-in path; the default Oracle is unchanged.
- **Private-constant imports:** depends on `_STAGE_MAP`, `_DEFAULT_STAGE`, `_AUTHORIZATION_FACT_FIELDS`, `_BENIGN_INDICATOR_FIELDS` staying where they are. Precedent exists for importing them; if any moves, this module's import breaks loudly (caught by tests), not silently.
- **Opt-in only:** nothing consumes the sanitized path yet. That is deliberate for this session (offline scope); production cutover is a separate decision.
