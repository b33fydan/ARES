# Paper 4 number_check report

**Overall: PASS (13 / 13 claims validated)**

| claim | expected | actual | pass |
|---|---:|---:|:---:|
| cumulative Youden J cap (0.25) | 0.25 | 0.25 | PASS |
| LLM standalone Youden J (0.75) | 0.75 | 0.75 | PASS |
| LLM standalone X_semantic (0.125) | 0.125 | 0.125 | PASS |
| SYN-001 framing-flip p-value (0.0005) | 0.0005 | 0.0005 | PASS |
| OOV verdict (SUPPORTED_STRONG) | SUPPORTED_STRONG | SUPPORTED_STRONG | PASS |
| OOV black-arm scenarios evaded | ('RDF-M-LEX-002', 'RDF-M-SYN-001') | ('RDF-M-LEX-002', 'RDF-M-SYN-001') | PASS |
| named-IOC canonical flips (0) | 0 | 0 | PASS |
| OOV run-2 cost (0.106) | 0.106 | 0.106 | PASS |
| audit verdict (ROBUST) | ROBUST | ROBUST | PASS |
| audit controls pass (True) | True | True | PASS |
| audit independent_confirmed (15) | 15 | 15 | PASS |
| audit independent_split (3) | 3 | 3 | PASS |
| test floor from skeleton | 4188 | 4188 | PASS |

---

## Prose substring check (Phase 3 activation)

When a Paper 4 prose docx exists, every value in ``prose_substring_claims()`` must appear in the prose body. Currently dormant — no prose yet.