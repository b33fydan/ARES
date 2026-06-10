# Read-Depth Robustness Frontier — Phase B (deterministic tiers)

Corpus digest: `9401b7188ba790a5`  |  operating point: malign_score > 0.0

Semantic operators: framing_prefix_v1, framing_suffix_v1
Lexical operators: exe_to_binary_v1, temp_to_temporary_v1

No frontier verdict here — that requires the Phase-C LLM anchor (tier 4) and the pre-registration commit.

## View: standalone

| tier | X_semantic | X_lexical | TPR | FPR | Youden J |
|------|-----------:|----------:|----:|----:|---------:|
| v1_field | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_structured | 0.000 | 0.000 | 1.000 | 0.750 | 0.250 |
| v2_lexical | 0.000 | 0.400 | 0.750 | 0.250 | 0.500 |
| v2_canonical | 0.000 | 0.000 | 1.000 | 0.250 | 0.750 |

## View: cumulative

| tier | X_semantic | X_lexical | TPR | FPR | Youden J |
|------|-----------:|----------:|----:|----:|---------:|
| v1_field | 0.000 | 0.000 | 0.000 | 0.000 | 0.000 |
| v2_structured | 0.000 | 0.000 | 1.000 | 0.750 | 0.250 |
| v2_lexical | 0.000 | 0.000 | 1.000 | 0.750 | 0.250 |
| v2_canonical | 0.000 | 0.000 | 1.000 | 0.750 | 0.250 |

## Positive control (inject genuine authorization)

Standalone verdict MOVED in 4 (tier, scenario) cells — expected: the structural tier swings benign, value tiers hold.

> Note: "tier 1 is blind to value-borne attacks" is precise only for the `high_threat_field` (M1) rule; `high_stage_without_authorization` (M2) still fires via the field-name-derived kill-chain stage.
