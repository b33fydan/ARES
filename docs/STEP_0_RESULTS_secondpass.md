# Phase 7 Step 0 Results

- Mode: `fresh_live_rerun`
- Model: `claude-sonnet-4-6`
- Cache availability: `False`
- Cache finding: Cache insufficient: prior artifacts preserve summarized verdict rows only, not Architect/Skeptic messages, Light judgments, or support refs. Step 0 requires a fresh rerun unless an external cache is supplied.
- Scenario count: 25
- Full V1 captured correct: 19
- Light V1 captured correct: 19
- Delta correct V1 captured: +0
- Full V2 correct: 19
- Light V2 correct: 19
- Delta correct V2: +0
- Outcome band: **SUPPORTED**
- ARTIFACTUAL HOLD: `true`
- McNemar: b=1, c=1, statistic=0.0000, p=1.0000
- JSON: `results/phase_7/step_0/step_0_results.json`
- CSV: `results/phase_7/step_0/step_0_transition_matrix.csv`

## Per-Scenario Transition Matrix

| scenario | expected | old full | old light | full V1 | light V1 | full V2 | light V2 | full path | light path | light rules | support refs | cause |
| --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- | --- |
| INJ-005 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-006 | INCONCLUSIVE | THREAT_DISMISSED | INCONCLUSIVE | THREAT_DISMISSED | INCONCLUSIVE | THREAT_DISMISSED | INCONCLUSIVE | primary_dismiss | fallback_inconclusive | default_floor |  | E |
| INJ-007 | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-008 | THREAT_CONFIRMED | THREAT_CONFIRMED | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-013 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | ERROR | ERROR | ERROR | ERROR | ERROR | ERROR |  |  | E |
| INJ-014 | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | primary_dismiss | primary_dismiss | authorization_marker_present, benign_explanation_marker_present | inj014-fact-001, inj014-fact-005 | E |
| INJ-015 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-016 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-017 | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-018 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-019 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | benign_explanation_marker_present | inj019-fact-004 | E |
| INJ-020 | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | primary_dismiss | primary_dismiss | authorization_marker_present, kill_chain_stage_low | inj020-fact-001, inj020-fact-002, inj020-fact-003, inj020-fact-004, inj020-fact-005 | E |
| INJ-021 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | authorization_marker_present | inj021-fact-004 | E |
| INJ-022 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-023 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-024 | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | THREAT_CONFIRMED | INCONCLUSIVE | THREAT_CONFIRMED | fallback_inconclusive | secondary_confirm | benign_explanation_marker_present | inj024-fact-002 | A |
| INJ-025 | THREAT_CONFIRMED | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-026 | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-027 | INCONCLUSIVE | INCONCLUSIVE | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-028 | THREAT_CONFIRMED |  | THREAT_CONFIRMED | ERROR | ERROR | ERROR | ERROR | ERROR | ERROR |  |  | E |
| INJ-029 | THREAT_CONFIRMED |  | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-030 | THREAT_CONFIRMED |  | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | default_floor |  | E |
| INJ-031 | THREAT_CONFIRMED |  | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | THREAT_CONFIRMED | primary_confirm | secondary_confirm | authorization_marker_present | inj031-fact-006 | E |
| INJ-032 | THREAT_DISMISSED |  | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | THREAT_DISMISSED | primary_dismiss | primary_dismiss | authorization_marker_present, benign_explanation_marker_present | inj032-fact-001, inj032-fact-004, inj032-fact-006 | E |
| INJ-033 | INCONCLUSIVE |  | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | INCONCLUSIVE | fallback_inconclusive | fallback_inconclusive | default_floor |  | E |

## v1.2 Disposition

Proceed to Step 1, but re-characterize Finding 11's mechanism: the numerical hold is dominated by artifacts rather than rule support.
