# Session 040 — PentAGI Integration + Pentest Benchmark Baseline

**Date:** 2026-04-01
**Goal:** Integrate PentAGI autonomous pentest output into ARES dialectical pipeline and ARES-VISION
**Tests:** 2,246 → 2,350 (+104), 0 failures
**Cost:** ~$0.25 (2 live runs: 1 solo PT-001 + 6-scenario full suite)

---

## What We Built

### PentAGIExtractor (`ares/dialectic/evidence/extractors/pentagi.py`)
New evidence extractor implementing `ExtractorProtocol`. Parses PentAGI action JSON into typed Facts with `PENTEST_TOOL` provenance. Handles 7 tool types (nmap, sqlmap, metasploit, nuclei, nikto, gobuster, hydra) plus generic fallback for unknown tools.

### PentAGI Benchmark Scenarios (`ares/dialectic/scripts/pentagi_scenarios.py`)
Six scenarios (PT-001 through PT-006) covering the full verdict/tier matrix. Each scenario constructs PentAGI action JSON, passes it through the extractor, and loads Facts into a frozen EvidencePacket — demonstrating the full integration path.

### ARES-VISION Wiring (`ares/visual/scripts/run_live.py`)
Added `--mode pentagi` to run_live.py. Corpus loader upgraded from `get_full_corpus_v2()` (33 SC scenarios) to `get_pentagi_corpus()` (33 SC + 6 PT = 39 scenarios). Zero frontend changes needed — the visualizer handles PT scenarios identically to SC scenarios.

---

## Baseline Benchmark Results (6 PT Scenarios)

Run: `--mode pentagi --speed 0.5`, total time 103.2s

| Scenario | Facts | Architect | Skeptic | Delta | Verdict | Expected | Result |
|----------|-------|-----------|---------|-------|---------|----------|--------|
| PT-001 SQLi → Root Shell | 33 | 0.9500 | 0.3000 | +0.65 | CONFIRMED | CONFIRMED | correct |
| PT-002 Hardened Target | 24 | 0.5500 | 0.6000 | -0.05 | INCONCLUSIVE | DISMISSED | MISS |
| PT-003 Vulns No Exploit | 44 | 0.7500 | 0.4000 | +0.35 | CONFIRMED | INCONCLUSIVE | MISS |
| PT-004 SSH Brute Force → Shell | 26 | 0.9500 | 0.3000 | +0.65 | CONFIRMED | CONFIRMED | correct |
| PT-005 Critical CVEs (no exploit) | 46 | 0.9500 | 0.4000 | +0.55 | CONFIRMED | INCONCLUSIVE* | MISS |
| PT-006 Failed Exploits | 27 | 0.7500 | 0.4000 | +0.35 | CONFIRMED | DISMISSED | MISS |

**Accuracy: 2/6 (33.3%)** after PT-005 verdict patch

*PT-005 expected verdict patched from THREAT_CONFIRMED to INCONCLUSIVE post-baseline — under closed-world assumption, confirmed vulnerability != confirmed compromise (same logic as SC-011/SC-017 patches in Session 032).

---

## Key Finding: Confidence Calibration is Source-Agnostic

The Architect exhibits the same 0.75 confidence floor on pentest evidence that was diagnosed on SC-xxx security event evidence in Sessions 025-031:

- **PT-003** (vulns, no exploitation): Architect 0.75 — should be lower, attack chain incomplete
- **PT-006** (all exploits fail): Architect 0.75 — should be much lower, every attack bounced
- **PT-002** (hardened, nothing found): Architect 0.55 — better but still not dismissing

This confirms the CONFIDENCE_CALIBRATION failure mode is **not specific to the evidence type**. The Architect over-asserts threat regardless of whether it's analyzing Windows event logs, syslog, netflow, or pentest tool output. The 0.75 floor appears to be a property of the prompt/model interaction, not the evidence domain.

**This is a cross-validation of the Phase 4 diagnosis across a completely independent evidence source.**

---

## Failure Classification

| Scenario | Failure Type | Diagnosis |
|----------|-------------|-----------|
| PT-002 | CONFIDENCE_CALIBRATION | Architect 0.55 on empty findings; Skeptic 0.60 not confident enough to dismiss |
| PT-003 | CONFIDENCE_CALIBRATION | Architect 0.75 on incomplete attack chain; should be ~0.50 |
| PT-005 | CONFIDENCE_CALIBRATION | Architect 0.95 on vulnerability scan with zero exploitation; overweights CVE severity |
| PT-006 | CONFIDENCE_CALIBRATION | Architect 0.75 when every exploit explicitly failed; ignores negative evidence |

All 4 misses are CONFIDENCE_CALIBRATION. Zero EVIDENCE_GAP or AMBIGUITY_MISMATCH failures in the PT corpus.

---

## Files Changed

**New:**
- `ares/dialectic/evidence/extractors/pentagi.py` — PentAGIExtractor (7 tools + generic)
- `ares/dialectic/scripts/pentagi_scenarios.py` — 6 PT benchmark scenarios
- `ares/dialectic/tests/evidence/extractors/test_pentagi.py` — 63 tests
- `ares/dialectic/tests/scripts/test_pentagi_scenarios.py` — 41 tests

**Modified:**
- `ares/dialectic/evidence/provenance.py` — Added PENTEST_TOOL to SourceType enum
- `ares/dialectic/evidence/extractors/__init__.py` — Export PentAGIExtractor
- `ares/dialectic/tests/evidence/test_provenance.py` — Updated expected source types
- `ares/visual/scripts/run_live.py` — Added --mode pentagi, PENTAGI_IDS, get_pentagi_corpus()

---

## Architecture Decision

PentAGI integration follows the "peer modules, not wrappers" pattern. The extractor is a peer to WindowsEventExtractor, SyslogExtractor, and NetflowExtractor — same protocol, same output type, same pipeline. No special-casing downstream. The orchestrator, agents, and visualizer don't know or care that the evidence came from a pentest tool.

---

## Next Steps (Not Started)

1. Prompt tuning for pentest evidence (Architect needs to weight negative findings: `exploited: false`, `vulnerable: false`)
2. Consider Skeptic prompt enhancement to explicitly cite failed exploitation as counter-evidence
3. Full 39-scenario benchmark run (SC + PT combined) once calibration is addressed
4. Optional: GraphQL connector for live PentAGI → ARES streaming
