# Phase 7 Step 0 Results

- Mode: `dry_run`
- Model: `rule_based_dry_run`
- Cache availability: `False`
- Cache finding: Cache insufficient: prior artifacts preserve summarized verdict rows only, not Architect/Skeptic messages, Light judgments, or support refs. Step 0 requires a fresh rerun unless an external cache is supplied.
- Scenario count: 2
- Full V2 correct: 1
- Light V2 correct: 1
- Delta correct: +0
- Outcome band: **SUPPORTED**
- ARTIFACTUAL HOLD: `false`
- McNemar: b=0, c=0, statistic=0.0000, p=1.0000
- JSON: `results/phase_7/step_0/step_0_results.json`
- CSV: `results/phase_7/step_0/step_0_transition_matrix.csv`

## Per-Scenario Transition Matrix

| scenario | expected | old full | old light | full V2 | light V2 | full path | light path | light rules | support refs | cause |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| INJ-005 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-006 | INCONCLUSIVE | THREAT_DISMISSED | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |

## v1.2 Disposition

Dry-run smoke only. Do not treat this as Step 0 ratification; run fresh_live_rerun with ANTHROPIC_API_KEY or supply a message-level cache.
