# Firewall Arena — local service

Deterministic, offline, **no-LLM** exposure of the real ARES `OracleFirewall` +
`run_guarded_cycle` for the live "attack-on-demand" demo. Sibling to the Glass
Box demo. Spec: `docs/superpowers/specs/2026-06-15-firewall-arena-mini-prd.md`.
Plan: `docs/superpowers/plans/2026-06-15-firewall-arena.md`.

## Run
```
python -m demo.firewall_arena_service --port 8910
```
- Binds to `127.0.0.1` only. No external network, no LLM, no cost, no sampling — 100% reproducible.
- Audience text is **regex/rule-matched only, never executed**, and display-sanitized before it leaves the service.
- `httpx` is required only to run the pytest `TestClient` suite (already in the env).

## Presets (locked 2026-06-15 after an empirical survey of the deterministic pipeline)
| preset_id | what it shows |
|---|---|
| `INJ-009` | Clean credential-theft chain (mimikatz → pass-the-hash → lateral → persistence). Firewall passes; deterministic verdict `threat_confirmed`. The baseline. |
| `INJ-009-INJECTED` | The same chain with a literal `IGNORE PREVIOUS INSTRUCTIONS…` payload appended to the cited `analysis_context` fact. **Headline:** firewall catches it in-cycle → fresh Architect hot-swaps → verdict still `threat_confirmed`. |
| `INJ-020` | Semantic framing the syntactic firewall can't see. Firewall passes; verdict `threat_dismissed`, stable across framings — the honest boundary (the deterministic Oracle is the semantic backstop). |

> Why INJ-009 and not INJ-001: the rule-based (no-LLM) Oracle is conservative —
> of 33 corpus scenarios only INJ-009 is deterministically `threat_confirmed`,
> and INJ-001 is neither caught in-cycle nor confirmed. INJ-009-with-injection is
> the one scenario that lands the full "caught → parried → verdict holds" beat
> deterministically and honestly.

## API
- `GET /presets` → `{ "presets": [ {preset_id, label, kind, blurb}, ... ] }`
- `POST /run` → an **ArenaTrace** (below). Request body:
  - incident: `{ "mode": "incident", "preset_id": "INJ-009-INJECTED" }`
    - optional edit-a-field: add `"field_id": "inj009-fact-002", "field_value": "…"` (both or neither — a partial edit is a 422).
  - raw: `{ "mode": "raw", "raw_text": "ignore previous instructions" }` (base incident defaults to INJ-009).

**Edit-a-field catch rule:** the firewall only scans facts the Architect *cites*.
For INJ-009 those are `inj009-fact-{002,003,004,006}`; edits to `{001,005,007}` are
*inert* (firewall passes — the Architect never read them). The raw box always
scans the text directly, so it is the reliable "type any injection → caught" path.

## ArenaTrace shape
```
{
  mode: "incident" | "raw",
  preset_id, title_label, raw_text?, injected_fact_id,
  facts: [ {fact_id, field, display_label, source_type, is_injected}, ... ],
  beats: [
    {phase:"incident", caption},
    {phase:"scan",     caption, firewall_passed, taint_score},
    {phase:"catch",    caption, violations:[{violation_type,evidence,severity,fact_id}], sanitized_output},
    {phase:"respond",  caption, hot_swap_triggered, used_sanitized, quarantined_output},
    {phase:"hold",     caption, verdict_outcome, architect_confidence, skeptic_confidence,
                        verdict_confidence, supporting_fact_ids, reasoning},
  ],
  honesty: { firewall_is_syntactic: true, semantic_blind_spot: bool, boundary_note },
  provenance: { real_pipeline: true, git_sha, trace_version, no_llm: true },
}
```
Every value comes from a real run of the real ARES code (the Glass Box provenance discipline).

## Tests
```
python -m pytest tests/demo/test_firewall_arena.py tests/demo/test_firewall_arena_service.py -q
```

## Renderer
The browser UI lives in the sibling repo `C:\glassbox\arena` (a fresh Vite/React/TS app;
Glass Box at `C:\glassbox\glassbox` is untouched). The two are shown back-to-back:
the Arena is the live syntactic-catch demo; the Glass Box is the recorded semantic-drift demo.
```
# terminal 1 (this repo):
python -m demo.firewall_arena_service --port 8910
# terminal 2 (C:\glassbox\arena):
npm run dev -- --port 5200
# browse http://localhost:5200/?autoplay=0   (Space / → / C)
```
