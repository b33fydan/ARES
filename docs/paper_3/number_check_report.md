# Paper 3 number_check report

**Overall: PASS (12 / 12 claims validated)**

| claim | expected | actual | pass |
|---|---:|---:|:---:|
| narrow paired-trial count (98) | 98 | 98 | PASS |
| narrow byte-stable count (98/98) | 98 | 98 | PASS |
| LLM-path divergence count (73 of 98) | 73 | 73 | PASS |
| LLM-path no-divergence count (25) | 25 | 25 | PASS |
| LLM-path first-diverging at architect (39) | 39 | 39 | PASS |
| LLM-path first-diverging at skeptic_llm (34) | 34 | 34 | PASS |
| light_skeptic.py anchor line (185) | 185 | 185 | PASS |
| oracle.py passthrough range start (89) | 89 | 89 | PASS |
| oracle.py passthrough range end (116) | 116 | 116 | PASS |
| leakage run count on disk (>=3 expected) | 3 | 3 | PASS |
| test floor at Session 064 build start (3737) | 3737 | 3737 | PASS |
| verdict_class_passthrough_map (§6.6 lock) | {'THREAT_CONFIRMED': 'architect', 'THREAT_DISMISSED': 'skeptic', 'INCONCLUSIVE': 'union'} | {'THREAT_CONFIRMED': 'architect', 'THREAT_DISMISSED': 'skeptic', 'INCONCLUSIVE': 'union'} | PASS |

---

## Prose substring check (Session 065+ activation)

When ``docs/paper_3/PAPER3_DRAFT_v1_0.docx`` exists, every value in ``prose_substring_claims()`` must appear in the prose body. Currently dormant — no prose yet.