# SESSION 042 — Claude Code Prompt
## Kill Chain Aware Architect (Prompt v5) + Benchmark Validation

**Objective:** Create v5 Architect prompts with kill chain stage awareness for pentest evidence, then benchmark all 39 scenarios to validate PT accuracy improvement with zero SC regressions.

---

## CRITICAL CONSTRAINTS

- **NEW FILES ONLY.** Do not modify `llm_strategy_v4.py` or any existing file.
- **Frozen dataclasses** for any new data structures.
- **Zero regressions.** All 2,369+ existing tests must pass.
- **Branch:** `session/042-kill-chain-prompts`

---

## STEP 1 — Read Before Writing

Read these files to understand the current prompt structure:

```
ares/dialectic/agents/strategies/llm_strategy_v4.py   # Current production prompts — study the Architect system prompt closely
ares/dialectic/agents/strategies/live_cycle.py          # How strategies are called
ares/dialectic/evidence/provenance.py                   # SourceType enum — find PENTEST_TOOL
ares/dialectic/scripts/pentagi_scenarios.py             # PT scenario construction — understand what facts look like
ares/dialectic/scripts/sweep_oracle_v2.py               # You'll use this to benchmark
```

Pay special attention to:
- How the v4 Architect prompt structures its analysis
- How confidence calibration guidance is worded in v4
- What fields are available on each Fact (entity_type, source_type, provenance)
- How PentAGI facts carry tool information (tool name, action type, success/failure)

---

## STEP 2 — Build `llm_strategy_v5.py`

**Location:** `ares/dialectic/agents/strategies/llm_strategy_v5.py`

Create `LLMThreatAnalyzerV5`, `LLMExplanationFinderV5`, `LLMNarrativeGeneratorV5`.

### Architect Changes (the core intervention)

The v5 Architect system prompt adds a **Kill Chain Assessment Framework** to the existing v4 prompt structure. This is ADDITIVE — keep everything from v4 that works, and layer the kill chain reasoning on top.

**Add this framework to the Architect system prompt:**

```
KILL CHAIN ASSESSMENT (apply when pentest/offensive tool evidence is present):

Before assigning confidence, determine the HIGHEST STAGE reached in the evidence:

STAGE 1 — RECONNAISSANCE ONLY
  Indicators: port scans, service enumeration, directory listing, banner grabbing
  Tools: nmap, gobuster, nikto (scanning), dig, whois
  Confidence guidance: 0.30–0.45
  Reasoning: Information gathering does not constitute a threat. Open ports and 
  exposed services are findings, not compromises.

STAGE 2 — VULNERABILITY IDENTIFIED (not exploited)
  Indicators: CVE matches, injectable parameters detected, misconfigurations found,
  admin panels discovered, BUT no evidence of successful exploitation
  Tools: nuclei, sqlmap --level (detection only), nikto (vuln reporting)
  Key signal: Look for "exploited: false", absence of shells/sessions/credentials
  Confidence guidance: 0.45–0.60
  Reasoning: Identified vulnerabilities represent risk, not compromise. 
  The attack surface is mapped but the boundary is not breached.

STAGE 3 — EXPLOITATION CONFIRMED
  Indicators: shell obtained, credentials cracked, code execution achieved,
  SQL injection data extracted, reverse connection established
  Tools: sqlmap (exploitation mode), metasploit (successful), hydra (cracked)
  Key signal: Evidence of actual access — sessions, extracted data, shell prompts
  Confidence guidance: 0.75–0.90
  Reasoning: Active compromise confirmed. The attacker crossed the boundary.

STAGE 4 — POST-EXPLOITATION
  Indicators: privilege escalation after initial access, persistence mechanisms,
  lateral movement, data exfiltration, meterpreter/C2 session
  Confidence guidance: 0.90–0.95
  Reasoning: Sustained adversary access with expanded capabilities.

FAILED ATTACK (special case)
  Indicators: Tools ran but all exploits failed, connection refused, 
  access denied, no sessions established, patched/hardened target
  Key signal: Presence of tool output WITH failure indicators
  Confidence guidance: 0.25–0.40
  Reasoning: An attempted attack that was defeated by defenses is evidence 
  of security, not threat. The attempt matters less than the outcome.

IMPORTANT: State the highest stage reached explicitly in your analysis 
before assigning confidence. Example: "Highest stage reached: STAGE 2 
(vulnerability identification). Nuclei detected CVE-2021-44228 but no 
evidence of exploitation. Confidence: 0.55"
```

### Conditional Application

The kill chain framework should activate when pentest evidence is present but not interfere with standard security telemetry analysis. Add this to the prompt:

```
If the evidence packet contains PENTEST_TOOL source types (nmap, sqlmap, 
metasploit, nuclei, nikto, gobuster, hydra output), apply the Kill Chain 
Assessment Framework above to calibrate your confidence.

If the evidence contains only security telemetry (Windows events, syslog, 
NetFlow), use standard threat assessment without the kill chain framework.

If mixed sources are present, apply kill chain assessment to the pentest 
evidence and standard assessment to the telemetry, then synthesize.
```

### Skeptic Changes (minimal)

Add complementary language to the v5 Skeptic prompt:

```
When challenging pentest/offensive tool evidence, consider:
- Did the attack actually succeed, or were vulnerabilities merely identified?
- Are there failure indicators (connection refused, access denied, no session)?
- Reconnaissance alone is not grounds for THREAT_CONFIRMED
- Vulnerability existence without exploitation proof supports INCONCLUSIVE or DISMISSED
```

### Narrator Changes

Carry forward from v4 with no changes. The Narrator explains the verdict — it doesn't influence it.

### Class Structure

Mirror the v4 class structure exactly:

```python
class LLMThreatAnalyzerV5:
    """Kill chain aware Architect — v5 prompts."""
    # Same interface as V4, different system prompt

class LLMExplanationFinderV5:
    """Kill chain aware Skeptic — v5 prompts."""
    
class LLMNarrativeGeneratorV5:
    """Narrator — carried forward from v4."""
```

---

## STEP 3 — Tests for v5 Strategies

**Location:** `ares/dialectic/tests/agents/strategies/test_llm_strategy_v5.py`

Mirror the v4 test structure. Test that:

```python
# v5 classes instantiate correctly
# v5 Architect prompt contains "Kill Chain" or "STAGE" language
# v5 Architect prompt contains "PENTEST_TOOL" conditional
# v5 Architect prompt contains confidence guidance for each stage
# v5 Skeptic prompt contains kill chain defense language
# v5 classes follow the same protocol as v4
# v5 system prompts are different from v4 (not identical copies)
# v5 Architect prompt preserves all v4 closed-world constraint language
# v5 Architect prompt preserves all v4 fact citation requirements
```

Target: ~15 tests. These are prompt content validation tests, not live LLM tests.

---

## STEP 4 — Benchmark with v5 Prompts

Modify the sweep script invocation to use v5 strategies. Two approaches:

### Option A (preferred): Add `--prompts v5` flag to sweep_oracle_v2.py

If the sweep script supports strategy injection, add a flag:
```bash
python -m ares.dialectic.scripts.sweep_oracle_v2 --prompts v5
```

### Option B: One-off benchmark script

If modifying the sweep is cleaner, create `scripts/benchmark_v5.py`:

```python
"""Run v5 prompts through the 39-scenario corpus and compare to v4 baseline."""
```

Either way, the output must be:

1. **V4+V1 baseline** (from Session 041 saved results): 28/39 (71.8%)
2. **V5+V1 results** (new live run): ?/39
3. **V5+V2 (delta=0.30) rescore**: ?/39
4. **Per-scenario comparison**: which scenarios flipped, in which direction

### Expected Output Format

```
V5 KILL CHAIN PROMPT BENCHMARK
═══════════════════════════════════════════════════════════
Config           SC (33)    PT (6)     Combined    vs V4+V1
───────────────────────────────────────────────────────────
V4+V1 (baseline) 26/33      2/6        28/39       --
V5+V1            ??/33      ??/6       ??/39       +? / -?
V5+V2 (0.30)     ??/33      ??/6       ??/39       +? / -?
═══════════════════════════════════════════════════════════

CHANGES (V5+V1 vs V4+V1):
  IMPROVEMENT PT-003: ... [arch confidence dropped from 0.75 to 0.??]
  IMPROVEMENT PT-006: ... [arch confidence dropped from 0.75 to 0.??]
  REGRESSION  SC-???: ... [if any]
```

---

## STEP 5 — Run the Benchmark

1. Run `pytest` — confirm 0 failures with new tests
2. Run the v5 benchmark live (39 API calls, ~$1.17)
3. Capture the comparison table
4. Report results verbatim

**If PT accuracy improves to ≥ 3/6 with 0 SC regressions:** Session is a success. Commit.
**If PT improves but SC regresses:** Report which SC scenarios regressed and why. Do not tune further — bring the data back.
**If PT doesn't improve:** Report the raw confidence values. The Architect may be ignoring the kill chain guidance (LLM compliance issue). Bring the data back.

---

## STEP 6 — Commit

Branch: `session/042-kill-chain-prompts`
Commit message format:
```
Session 042: Kill chain aware Architect (v5 prompts) — PT ?/6, SC ?/33, combined ?/39 (??.?%)
```

---

## EXPECTED OUTPUT

**New files (2-3):**
```
ares/dialectic/agents/strategies/llm_strategy_v5.py          # v5 prompts
ares/dialectic/tests/agents/strategies/test_llm_strategy_v5.py  # prompt validation tests
ares/dialectic/scripts/benchmark_v5.py                        # benchmark script (if Option B)
benchmark_results/v5_killchain/results.json                   # live results
```

**Modified files: 0**
**Target test count:** 2,369 + ~15 = ~2,384+
**API cost:** ~$1.17 (single 39-scenario run) or ~$2.34 (if double-run for variance check)

---

## WHAT SUCCESS LOOKS LIKE

The benchmark table prints. PT accuracy is ≥ 3/6. SC accuracy is ≥ 26/33. The confidence values for PT-003, PT-005, and PT-006 show measurable drops from the 0.75–0.95 range toward the 0.45–0.60 range. The kill chain framework worked.

Report the table verbatim. I'll bring it back to the strategy window.
