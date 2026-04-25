# SESSION 042 — PRD: Kill Chain Awareness
## Architect Prompt Intervention + Benchmark Validation

**Date:** 2026-04-02
**Starting State:** 2,369 tests, commit `e469d4a`, Session 041 complete
**Previous Session:** V2 Oracle sweep — delta=0.30 wins (74.4%), PT unchanged at 2/6

---

## Problem Statement

The Architect cannot distinguish penetration depth. It treats the *presence* of offensive security tool output as threat signal, regardless of whether the attack actually progressed through the kill chain. Three specific failure modes on PT evidence:

| Scenario | What Happened | Architect Read | Correct Read |
|----------|--------------|----------------|-------------|
| PT-003 (vulns, no exploit) | Nikto/gobuster found admin panels, directory listings. No exploitation attempted. | 0.75 — "vulnerabilities exist, threat confirmed" | INCONCLUSIVE — findings without exploitation are intermediate |
| PT-005 (critical CVEs) | Nuclei found Log4Shell + Confluence CVEs. Zero proof of compromise. | 0.95 — "critical vulnerabilities, threat confirmed" | INCONCLUSIVE — CVE existence ≠ exploitation |
| PT-006 (failed exploits) | Every tool ran, every exploit bounced. Patched server. | 0.75 — "offensive tools targeted this host" | DISMISSED — attack was attempted and failed |

**Root cause:** The v4 Architect prompt has no concept of kill chain progression. It knows facts exist. It doesn't know *where in the attack lifecycle* those facts sit. Reconnaissance ≠ exploitation ≠ post-exploitation, but the Architect weights them equally.

---

## The Kill Chain Stage Model

Teach the Architect to assess threat based on *how far the attack traveled*, not just *what tools were used*.

### Stage Definitions

```
STAGE 1 — RECONNAISSANCE
  Tools: nmap, gobuster, nikto (scanning mode)
  Signals: open ports, service versions, directory listings
  Threat weight: LOW — information gathering only, no compromise
  
STAGE 2 — VULNERABILITY IDENTIFICATION  
  Tools: nuclei, nikto (vuln mode), sqlmap (detection only)
  Signals: CVE matches, injectable parameters detected, misconfigurations found
  Threat weight: MODERATE — attack surface mapped but not exploited

STAGE 3 — EXPLOITATION
  Tools: sqlmap (exploitation), metasploit, hydra (successful)
  Signals: shell obtained, credentials cracked, code execution achieved
  Threat weight: HIGH — active compromise confirmed

STAGE 4 — POST-EXPLOITATION
  Tools: meterpreter, post/ modules, privilege escalation
  Signals: persistence installed, lateral movement, data exfiltration
  Threat weight: CRITICAL — attacker has sustained access
```

### Confidence Mapping

The Architect should calibrate confidence based on the *highest stage reached*:

| Highest Stage Reached | Architect Confidence Guidance |
|----------------------|-------------------------------|
| Stage 1 only (recon) | 0.30–0.45 — scanning is not attacking |
| Stage 2 (vulns found, no exploit) | 0.45–0.60 — risk exists but is unrealized |
| Stage 3 (exploitation confirmed) | 0.75–0.90 — active compromise |
| Stage 4 (post-exploitation) | 0.90–0.95 — sustained threat |
| All stages failed | 0.25–0.40 — attack attempted and defeated |

### How This Fixes the Misses

- **PT-003** (vulns, no exploit): Highest stage = 2. Architect confidence drops to 0.45–0.60 range. With Skeptic at 0.40, delta is small → INCONCLUSIVE. **Correct.**
- **PT-005** (critical CVEs, no exploit): Highest stage = 2. Same logic. Confidence drops from 0.95 to 0.50–0.60. **Correct.**
- **PT-006** (failed exploits): Highest stage = attempted 3, failed. Confidence drops to 0.25–0.40. Skeptic wins → DISMISSED. **Correct.**
- **PT-001** (SQL injection → root): Highest stage = 4. Confidence stays 0.90–0.95. **Still correct.**
- **PT-004** (brute force → SSH): Highest stage = 3-4. Confidence stays high. **Still correct.**

---

## Session Scope

### What Gets Built

**1. Prompt v5 — Kill Chain Aware Architect (`llm_strategy_v5.py`)**

New file. The Architect prompt gains a kill chain assessment framework. The Skeptic and Narrator prompts are carried forward from v4 with minimal changes (Skeptic may get complementary language about kill chain incompleteness as a defense argument).

Key additions to the Architect system prompt:
- Kill chain stage definitions with examples
- Explicit confidence calibration guidance tied to highest stage reached
- Instruction to identify the highest stage reached before assigning confidence
- Emphasis on negative findings: "tool ran but failed" is evidence of defense, not offense

**2. Benchmark Validation**

Run all 39 scenarios through the sweep pipeline with v5 prompts:
- Single live run (39 API calls)
- Rescore at delta=0.30 (the Session 041 winner)
- Compare v5+V2 results against v4+V1 baseline and v4+V2 baseline

**Binary forcing function:** Do v5 prompts improve PT accuracy without regressing SC scenarios?

### What Does NOT Get Built (Deferred)

- Kill chain visualization in ARES-Vision (Session 043+)
- Agent reasoning stream to frontend (Session 043+)
- Temporal flow rendering / directed edges (Session 043+)
- Skeptic-specific kill chain prompting beyond minimal updates

---

## Risk Assessment

**Primary risk:** Kill chain guidance improves PT scenarios but over-constrains the Architect on SC scenarios where there IS no kill chain concept. SC evidence is security telemetry snapshots, not sequential tool output.

**Mitigation:** The kill chain framework should be *additive* — "when pentest tool evidence is present, assess kill chain progression." It should not override general threat assessment for non-pentest evidence. The prompt needs a conditional: if source_type includes PENTEST_TOOL, apply kill chain reasoning; otherwise, use standard threat assessment.

**Secondary risk:** LLM run-to-run variance. Session 041 showed SC accuracy can swing ±2 scenarios between identical runs. A v5 run that shows SC at 25/33 might be variance, not regression. 

**Mitigation:** If results are ambiguous, run twice and compare. Budget for 78 API calls (~$2.34) instead of 39.

---

## Success Criteria

| Criterion | Requirement |
|-----------|-------------|
| `llm_strategy_v5.py` exists | Kill chain aware Architect + carried-forward Skeptic/Narrator |
| PT accuracy improves | ≥ 3/6 (currently 2/6) with at least 1 new correct verdict |
| SC accuracy holds | ≥ 26/33 (no regression from Session 041 baseline) |
| Combined accuracy improves | > 74.4% (Session 041 best) |
| Zero-regression at delta=0.30 | No scenario that v4+V2 got right now fails |
| All tests pass | 2,369+ collected, 0 failures |

**Stretch:** PT ≥ 4/6 and combined ≥ 80%.

---

## Full Kill Chain Awareness Vision (Future Sessions)

This PRD covers the prompt intervention (Session 042). The complete vision has three pillars:

### Pillar 1: Teach the Architect the river (THIS SESSION)
Kill chain stage model in prompts → better PT accuracy.

### Pillar 2: Show the river in ARES-Vision (Session 043)
- Temporal X-axis ordering (recon → exploitation → post-exploitation)
- Directed flow edges between facts (nmap output → sqlmap input → metasploit target)
- Color-coded kill chain stages (blue → cyan → red → white)
- "Tagged species" tracking — follow a single finding through the chain

### Pillar 3: Expose agent reasoning alongside the river (Session 043-044)
- New `agent_reasoning` event type streaming Architect/Skeptic full text to frontend
- Split-panel visualization: evidence graph left, reasoning text right
- Cited facts highlight in the graph as agents reference them
- Real-time chain-of-thought transparency

Pillars 2 and 3 are the theatrics. Pillar 1 is the data. Data first.
