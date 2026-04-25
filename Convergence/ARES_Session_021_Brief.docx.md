

**A.R.E.S.**

Adversarial Reasoning Engine System

**SESSION 021**

*Verification \+ Corpus Expansion*

Strategy Brief \+ Claude Code Execution Prompt

Skyframe Innovations · March 2026

Previous: Session 020 (Conviction Anchoring) · 1,595 Tests · Zero Regressions

**PART 1: STRATEGY BRIEF**

*Read this first. Understand the context before executing.*

# **Context**

ARES has completed 20 development sessions with 1,595 passing tests and zero regressions. The core finding from Sessions 013–020: multi-turn debate underperforms single-turn by 16+ points (66.7% vs. 83.3%), caused by asymmetric calibration dynamics (Architect retreat, Skeptic rigidity). A targeted protocol fix (conviction anchoring) traded one failure mode for another with zero net improvement.

A post-Session-020 strategic review (the Tribunal) was conducted by three external AI systems (GPT 5.4 Pro, Gemini 3.1 Pro, Perplexity). All three unanimously recommended the same direction: ship single-turn as production, pursue per-claim debate as research, and expand the scenario corpus.

Session 021 is the first execution session of Phase 3\. It has two objectives: data verification and corpus expansion.

# **Objective 1: SC-017 Verification (COMPLETE)**

**STATUS: RESOLVED.** The Compendium Vol. I narrative claimed SC-017 was a debate win (multi-turn corrected to INCONCLUSIVE at 0.503). Benchmark data confirms SC-017 is wrong in all three modes across two independent runs. The narrative was based on stale or misread data.

The actual debate wins are SC-011 (debate corrected over-dismissal to correct INCONCLUSIVE) and SC-016 (debate reinforced justified conviction to correct THREAT\_CONFIRMED). Both wins belong exclusively to the original multi-turn protocol; the anchored variant loses both.

Compendium Vol. I has been corrected. All SC-017 flagship references replaced with SC-011/SC-016 evidence.

# **Objective 2: Corpus Expansion**

The current corpus has 18 scenarios. The Tribunal unanimously flagged this as statistically insufficient for claims about complementary accuracy patterns or ensemble strategies. Session 021 expands to 30–35 scenarios.

## **Scenario Design Requirements**

New scenarios must follow the established pattern:

* **Frozen dataclass definition.** Each scenario is a ScenarioDefinition with scenario\_id, description, evidence\_packets (list of frozen EvidencePacket), expected\_verdict, and difficulty\_tier.

* **Evidence source coverage.** Mix of Windows-only, Syslog-only, NetFlow-only, and cross-source (2–3 sources) scenarios.

* **Four difficulty tiers.** CLEAR\_THREAT, CLEAR\_BENIGN, AMBIGUOUS, MIXED\_SIGNALS.

* **Ground truth verdicts.** Each scenario has exactly one correct verdict: THREAT\_CONFIRMED, THREAT\_DISMISSED, or INCONCLUSIVE.

## **Tier Distribution for New Scenarios**

The corpus expansion should weight toward ambiguity, since that is where selective escalation will be tested most rigorously:

| Difficulty Tier | Current | Target | Rationale |
| :---- | :---- | :---- | :---- |
| **CLEAR\_THREAT** | 5 | 7–8 | Need sufficient clear cases to confirm single-turn holds. Add 2–3. |
| **CLEAR\_BENIGN** | 4 | 6–7 | Under-represented. Add 2–3 benign scenarios that look suspicious but are legitimate. |
| **AMBIGUOUS** | 5 | 10–12 | Highest priority. This is where escalation will trigger. Add 5–7 genuinely ambiguous cases. |
| **MIXED\_SIGNALS** | 4 | 7–8 | Cross-source scenarios with conflicting indicators. Add 3–4. |

## **Ambiguity Scenario Categories**

New ambiguity-tier scenarios should cover attack patterns that genuinely resist binary classification:

* **Dual-use tools:** PowerShell/PsExec/WMI usage that could be admin or attacker. Legitimate sysadmin behavior that mirrors lateral movement.

* **Exfiltration ambiguity:** Large outbound transfers that could be backups, syncs, or data theft. Cloud storage uploads at unusual hours.

* **Credential patterns:** Multiple failed logins followed by success — could be brute force or a user who forgot their password.

* **Timing anomalies:** After-hours access that could be an overseas employee, a compromised account, or scheduled maintenance.

* **Network scanning:** Port scans that could be vulnerability assessment tools, asset discovery, or reconnaissance.

## **Error Type Classification (NEW)**

Session 021 adds false positive / false negative tracking to the benchmark output. Every wrong answer is classified as:

* **False Positive (FP):** Benign activity incorrectly classified as threat. Operational cost: alert fatigue, wasted analyst time.

* **False Negative (FN):** Genuine threat incorrectly dismissed. Operational cost: missed attack, potential breach.

* **Miscalibrated Ambiguity:** Clear cases classified as INCONCLUSIVE, or ambiguous cases forced to a binary verdict. Operational cost: decision paralysis or false confidence.

# **Deliverables Checklist**

| \# | Deliverable | Acceptance Criteria |
| :---- | :---- | :---- |
| **1** | 12–17 new scenario definitions as frozen dataclasses | All pass schema validation. Total corpus: 30–35. |
| **2** | Full compare-all benchmark run on expanded corpus | All 3 modes run. Results table saved. |
| **3** | FP/FN classification for every wrong answer across all modes | New columns in benchmark output. |
| **4** | Per-tier accuracy breakdown (CLEAR\_THREAT, CLEAR\_BENIGN, AMBIGUOUS, MIXED\_SIGNALS) | New section in benchmark report. |
| **5** | All existing 1,595 tests still pass | Zero regressions. |

# **Non-Negotiables**

* **New files only.** Do not modify existing scenario files or benchmark scripts. Create new files.

* **Frozen dataclasses everywhere.** New ScenarioDefinition instances are frozen. New EvidencePackets are frozen.

* **Session branch.** Work on session-021 branch. Squash merge to main only after all tests pass.

* **Zero regressions.** Run full test suite before merge.

**PART 2: CLAUDE CODE EXECUTION PROMPT**

*Copy everything below this line and hand it to Claude Code.*

**SESSION 021: VERIFICATION \+ CORPUS EXPANSION**

**You are executing Session 021 of the ARES project. Read CLAUDE.md first for full project context. This session has two parts.**

**PART A: CORPUS EXPANSION**

The current benchmark corpus has 18 scenarios (SC-001 through SC-018). Expand it to 30–35 scenarios by adding 12–17 new scenario definitions.

**RULES:**

1. Create NEW scenario definition files. Do NOT modify existing scenario files.

2. Each scenario is a frozen dataclass following the exact pattern of existing scenarios in the codebase.

3. Each scenario must have: scenario\_id (SC-019 through SC-035), description, evidence\_packets (list of frozen EvidencePacket), expected\_verdict (THREAT\_CONFIRMED, THREAT\_DISMISSED, or INCONCLUSIVE), and difficulty\_tier (CLEAR\_THREAT, CLEAR\_BENIGN, AMBIGUOUS, or MIXED\_SIGNALS).

4. New scenarios must use the existing evidence extractor outputs (WindowsEventEvidence, SyslogEvidence, NetFlowEvidence) as source types in the EvidencePackets.

5. Write comprehensive tests for each new scenario definition.

**TIER DISTRIBUTION FOR NEW SCENARIOS:**

* CLEAR\_THREAT: 2–3 new scenarios (e.g., obvious ransomware indicators, clear C2 beaconing)

* CLEAR\_BENIGN: 2–3 new scenarios (e.g., legitimate admin tools that look suspicious, scheduled backup transfers)

* AMBIGUOUS: 5–7 new scenarios (HIGHEST PRIORITY — these are the cases where selective escalation will be tested)

* MIXED\_SIGNALS: 3–4 new scenarios (cross-source scenarios with conflicting indicators from different evidence types)

**AMBIGUITY SCENARIOS MUST INCLUDE:**

* Dual-use tool execution (PowerShell/PsExec/WMI that could be admin or attacker)

* Exfiltration ambiguity (large transfers that could be backup or data theft)

* Credential patterns (failed logins followed by success — brute force or forgot password?)

* Timing anomalies (after-hours access — overseas employee or compromised account?)

* Network scanning (port scans — vulnerability assessment or reconnaissance?)

**PART B: BENCHMARK INFRASTRUCTURE EXTENSION**

Extend the benchmark runner output to include error type classification and per-tier accuracy. Create NEW files — do not modify existing benchmark scripts.

**NEW METRICS TO ADD:**

1. For every wrong answer: classify as FP (benign classified as threat), FN (threat classified as benign), or MISCALIBRATED (clear case called INCONCLUSIVE, or ambiguous case forced to binary).

2. Add a per-tier accuracy section to the benchmark output: accuracy broken down by CLEAR\_THREAT, CLEAR\_BENIGN, AMBIGUOUS, MIXED\_SIGNALS.

3. Add a summary section showing FP count, FN count, Miscalibrated count per mode.

**PART C: RUN THE BENCHMARK**

After creating the new scenarios and extending the benchmark infrastructure:

4. Run the full test suite. All 1,595+ existing tests must pass. Report the new total test count.

5. Run compare-all mode on the FULL expanded corpus (all 30–35 scenarios). Save the complete output.

6. Report: total accuracy per mode, per-tier accuracy per mode, FP/FN/Miscalibrated counts per mode.

**SESSION COMPLETE WHEN:**

* 12–17 new scenarios created with tests

* Benchmark runner extended with FP/FN/Miscalibrated classification and per-tier breakdown

* Full compare-all run on expanded corpus completed and output saved

* All tests pass (existing \+ new). Zero regressions.

* Report the new total test count

**BRANCH: session-021**

**MERGE: Squash merge to main only after all tests pass.**

*End of Session 021 Brief. Execute in order: Part A, Part B, Part C.*