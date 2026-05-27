# Cross-Model InfluenceLeakage Comparison — Step 5

Side-by-side comparison of InfluenceLeakage measurement across model families. Paper 3 claim: the deterministic path (Light Skeptic) absorbs LLM-layer framing sensitivity without leaking to downstream verdicts.

## Summary table

| Metric | Sonnet 4.6 (S059 run 2) | GPT-4o (S075) | Gemini 2.5 Pro (S075) |
|---|---|---|---|
| Provider | anthropic | openai | gemini |
| Model | `claude-sonnet-4-20250514` | `gpt-4o` | `gemini-2.5-pro` |
| Run ID | `20260510-193950-f401a8` | `20260527-121916-c543fa` | `20260527-123857-c2d10f` |
| Total cost | $1.95 | $1.66 | $2.04 |
| Total cycles | 134 | 133 | 117 |

## Narrow reading (Light Skeptic only)

| Metric | Sonnet 4.6 (S059 run 2) | GPT-4o (S075) | Gemini 2.5 Pro (S075) |
|---|---|---|---|
| Light pairs evaluated | 2 | 1 | 1 |
| Narrow fires | 0 | 0 | 0 |
| Narrow stability | 100.00% (2/2) | 100.00% (1/1) | 100.00% (1/1) |
| **Narrow verdict** | **ALIVE** | **ALIVE** | **ALIVE** |

## Broad reading (Light Skeptic + Oracle + Final Verdict)

| Metric | Sonnet 4.6 (S059 run 2) | GPT-4o (S075) | Gemini 2.5 Pro (S075) |
|---|---|---|---|
| Broad fires | 1 | 1 | 1 |
| **Broad verdict** | **DEAD** | **DEAD** | **DEAD** |

## LLM-path divergence (Architect layer sensitivity)

| Metric | Sonnet 4.6 (S059 run 2) | GPT-4o (S075) | Gemini 2.5 Pro (S075) |
|---|---|---|---|
| LLM pairs | 98 | 98 | 86 |
| Diverged | 73/98 (74.5%) | 76/98 (77.6%) | 52/86 (60.5%) |
| No divergence | 25 | 22 | 34 |
| First diverge: Architect | 39 | 43 | 41 |
| First diverge: Skeptic | 34 | 33 | 11 |
