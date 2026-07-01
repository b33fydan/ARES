# Paper 5 number_check report

**Overall: PASS (20 / 20 claims validated)**

| claim | expected | actual | pass |
|---|---:|---:|:---:|
| max undefended ASR == 0.0 (no-headroom contingency) | 0.0 | 0.0 | PASS |
| full_defense ASR == 0.0 (by construction) | 0.0 | 0.0 | PASS |
| full_defense gate denials == 2 (empirical non-vacuity) | 2 | 2 | PASS |
| undefended gate denials == 0 | 0 | 0 | PASS |
| gate_off gate denials == 0 | 0 | 0 | PASS |
| undefended utility == 0.5 | 0.5 | 0.5 | PASS |
| full_defense utility == 0.3 | 0.3 | 0.3 | PASS |
| gate_off utility == 0.45 | 0.45 | 0.45 | PASS |
| sonnet/important_instructions undefended utility == 0.75 | 0.75 | 0.75 | PASS |
| conclusion-integrity == 0.95 | 0.95 | 0.95 | PASS |
| echo rate == 0.05 | 0.05 | 0.05 | PASS |
| benign false-block == 0.2 | 0.2 | 0.2 | PASS |
| benign denials == 4 | 4 | 4 | PASS |
| N == 20 | 20 | 20 | PASS |
| eligible banking injection tasks == 9 | 9 | 9 | PASS |
| rollouts == 96 | 96 | 96 | PASS |
| tau_asr == 0.2 | 0.2 | 0.2 | PASS |
| selected_cell null + contingency fired | True | True | PASS |
| fallback cell == haiku-4-5/important_instructions/banking | ('haiku-4-5', 'important_instructions', 'banking') | ('haiku-4-5', 'important_instructions', 'banking') | PASS |
| test floor parses to int | 4476 | 4476 | PASS |

---

## Prose substring check (Phase 3 activation)

When Paper 5 prose source exists, every value in ``prose_substring_claims()`` must appear in the prose body. Currently dormant — no prose yet.