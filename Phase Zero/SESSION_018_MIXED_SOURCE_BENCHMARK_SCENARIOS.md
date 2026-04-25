# Claude Code Execution Prompt

## Context

Continuing ARES build. Sessions 016–017 added Syslog and NetFlow extractors, giving ARES three telemetry sources:

1. **Windows Event Logs** (host-layer): logon events, privilege escalation, process creation
2. **Syslog** (network-layer): SSH auth, firewall blocks/allows, sudo, service events
3. **NetFlow** (traffic metadata): flow duration, volume, direction, TCP flags

The original 12 benchmark scenarios (SC-001 through SC-012) use only Windows Event Log facts. The multi-turn thesis test (Sessions 013–014) peaked at 75% accuracy vs 91.7% single-turn. The diagnosed cause: agents debating over a single evidence source lack cross-source contradictions and correlations that would make multi-round debate structurally valuable.

Session 018 goal: Build 6 new mixed-source scenarios (SC-013 through SC-018) that require cross-source correlation to reach the correct verdict. Every scenario MUST include facts from at least 2 of the 3 source types, and at least 2 scenarios must draw from all 3. These scenarios will be used in live experiments (run manually by Dan after this session) to re-test single-turn and multi-turn accuracy against a richer evidence distribution.

**This session is FULLY DETERMINISTIC — no live LLM calls.** All scenarios are verified through rule-based benchmark runs only.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/018-mixed-source-scenarios

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** All 1,503 existing tests must pass unchanged.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **No live LLM calls.** This session is fully deterministic.
4. **Type hints on everything. Docstrings on all public methods.**
5. **Test naming convention:** `test_<what>_<condition>_<expected>`
6. **Every scenario MUST use facts from multiple SourceTypes.**

---

## Existing Files (ALL DO NOT MODIFY)

The full file tree is in CLAUDE.md. Key files for this session:

```
ares/dialectic/evidence/
├── provenance.py                    # Provenance, SourceType (includes WINDOWS_EVENT_LOG, SYSLOG, NETFLOW)
├── fact.py                          # Fact, EntityType
├── packet.py                        # EvidencePacket
└── extractors/
    ├── protocol.py                  # ExtractionResult, ExtractorProtocol
    ├── windows.py                   # WindowsEventExtractor
    ├── syslog.py                    # SyslogExtractor
    └── netflow.py                   # NetFlowExtractor

ares/dialectic/scripts/
├── scenario_corpus.py               # SC-001 through SC-012, get_all_scenarios(), ScenarioMetadata, BenchmarkScenario
├── benchmark_runner.py              # run_benchmark(), ScenarioResult, BenchmarkRun
├── benchmark_report.py              # generate_report()
├── multi_turn_benchmark.py          # run_multi_turn_benchmark()
├── multi_turn_benchmark_report.py   # generate_multi_turn_report(), generate_comparison_report()
└── run_multi_turn_llm_benchmark.py  # CLI with --strategy, --max-rounds, --compare-single-turn

ares/dialectic/agents/strategies/
├── protocol.py                      # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
├── rule_based.py                    # RuleBasedThreatAnalyzer, etc.
├── llm_strategy.py                  # LLMThreatAnalyzer, etc.
├── multi_turn_strategies.py         # MultiTurnLLMThreatAnalyzer, etc.
└── multi_turn_prompts.py            # Round-aware prompt builders
```

**DO NOT MODIFY any of these files.**

---

## Step 1 — Review Before Writing

Read these files to understand the patterns you must follow:

1. `ares/dialectic/scripts/scenario_corpus.py` — How existing scenarios are built. Study `build_sc010_multi_vector_campaign()` closely — it has the most complex fact structure. Note the `ScenarioMetadata` fields, `BenchmarkScenario` wrapper, `get_all_scenarios()` API.
2. `ares/dialectic/evidence/provenance.py` — `SourceType` enum values available (WINDOWS_EVENT_LOG, SYSLOG, NETFLOW)
3. `ares/dialectic/evidence/fact.py` — `Fact`, `EntityType` — what entity types and attribute patterns exist
4. `ares/dialectic/evidence/packet.py` — `EvidencePacket` construction pattern (`add_fact()`, `freeze()`)
5. `ares/dialectic/scripts/benchmark_runner.py` — `run_benchmark()` signature — your scenarios must work with this runner unchanged
6. `ares/dialectic/scripts/sample_packets.py` — Original hand-built packet pattern

**Understand the existing scenario construction pattern thoroughly.** Your new scenarios must follow identical structural conventions: same Fact construction, same provenance stamping, same metadata fields.

---

## Step 2 — Create New File Structure

```
ares/dialectic/scripts/
├── mixed_source_scenarios.py          # NEW: SC-013 through SC-018 + combined corpus API
└── run_combined_benchmark.py          # NEW: CLI script for combined 18-scenario benchmarks

ares/dialectic/tests/scripts/
└── test_mixed_source_scenarios.py     # NEW: ~50-70 tests
```

**Three new files.**

---

## Step 3 — Implement `mixed_source_scenarios.py`

### 3.1 Imports and API

```python
from ares.dialectic.scripts.scenario_corpus import (
    ScenarioMetadata,
    BenchmarkScenario,
    get_all_scenarios,
    get_scenario_by_id,
)

def get_mixed_source_scenarios() -> tuple[BenchmarkScenario, ...]:
    """Return the 6 mixed-source scenarios (SC-013 through SC-018)."""
    ...

def get_combined_corpus() -> tuple[BenchmarkScenario, ...]:
    """Return all 18 scenarios: original 12 + 6 mixed-source."""
    return get_all_scenarios() + get_mixed_source_scenarios()

def get_mixed_scenario_by_id(scenario_id: str) -> BenchmarkScenario:
    """Return a specific mixed-source scenario by ID. Raises KeyError if not found."""
    ...
```

### 3.2 The 6 Mixed-Source Scenarios

Each scenario function builds an `EvidencePacket` by hand with Facts from multiple `SourceType` values, freezes it, and wraps it with `ScenarioMetadata`.

**IMPORTANT:** Use scenario-specific fact_id prefixes: `"sc013-fact-001"`, `"sc014-fact-001"`, etc.
**IMPORTANT:** Every fact must have valid `Provenance` with appropriate `SourceType` and realistic `source_ref`.
**IMPORTANT:** The `fact_count` in metadata MUST match the actual number of facts in the packet.
**IMPORTANT:** Each scenario MUST include facts from at least 2 different SourceTypes.

---

#### SC-013: Coordinated Brute Force Attack
**Sources:** Syslog + NetFlow + Windows Event Log (all 3)
**MITRE:** T1110 (Brute Force)
**Difficulty Tier:** 2
**Expected Verdict:** THREAT_CONFIRMED
**Expected Winner:** ARCHITECT

**Narrative:** An external attacker brute-forces SSH on a Linux server, gets blocked by the firewall, then shifts to RDP on a Windows host and succeeds.

**Facts to build (15-18 total):**

From Syslog (SourceType.SYSLOG):
- 5 SSH failed login attempts from same external IP (203.0.113.50) to webserver01
- 1 SSH invalid user attempt
- 2 UFW BLOCK entries for the same source IP
- source_ref: `"webserver01:auth:2026-03-04"`

From NetFlow (SourceType.NETFLOW):
- 5-6 short-duration SYN-only flows from 203.0.113.50 to 10.0.1.100 on port 22 (matching the SSH attempts)
- 1 longer-duration flow from 203.0.113.50 to 10.0.1.200 on port 3389 (RDP pivot)
- source_ref: `"router01:netflow:2026-03-04"`

From Windows Event Log (SourceType.WINDOWS_EVENT_LOG):
- 1 successful logon (Event 4624) from 203.0.113.50 via RDP (logon type 10) on the Windows host
- 1 privilege assignment (Event 4672) for the logged-in user
- source_ref: `"dc01:Security:2026-03-04T14:25:00Z"`

**Why cross-source matters:** Syslog shows the failed attempts. NetFlow shows the volume and pivot. Windows shows the successful compromise. No single source tells the full story.

---

#### SC-014: Data Exfiltration with Cover Traffic
**Sources:** NetFlow + Windows Event Log (2 sources)
**MITRE:** T1041 (Exfiltration Over C2 Channel) + T1560 (Archive Collected Data)
**Difficulty Tier:** 3
**Expected Verdict:** THREAT_CONFIRMED
**Expected Winner:** ARCHITECT

**Narrative:** An insider archives sensitive files and exfiltrates them over HTTPS. The exfiltration flow is hidden among normal browsing traffic.

**Facts to build (12-15 total):**

From Windows Event Log (SourceType.WINDOWS_EVENT_LOG):
- Process creation: 7z.exe compressing files from `C:\Confidential\` to `C:\Users\jsmith\AppData\Local\Temp\update.7z`
- Process creation: curl.exe uploading `update.7z` to `https://storage.exfil-domain.com/upload`
- Process creation: del.exe removing the archive after upload
- source_ref: `"ws042:Security:2026-03-04T02:15:00Z"` (note: 2:15 AM — after hours)

From NetFlow (SourceType.NETFLOW):
- 5-6 normal HTTPS flows to common sites (cdn.microsoft.com, etc.) — cover traffic
- 1 large outbound flow (15MB+) to suspicious external IP on port 443 — the exfiltration
- 1 DNS query flow to the exfil domain
- Compute bytes_per_packet and flow_direction for all
- source_ref: `"router01:netflow:2026-03-04"`

**Why cross-source matters:** Windows shows the archiving and cleanup. NetFlow shows the volume anomaly among normal traffic. Together they tell an exfiltration story; separately each source is ambiguous.

---

#### SC-015: Legitimate Infrastructure Maintenance
**Sources:** Syslog + NetFlow + Windows Event Log (all 3)
**MITRE:** None (false positive scenario)
**Difficulty Tier:** 3
**Expected Verdict:** THREAT_DISMISSED
**Expected Winner:** SKEPTIC

**Narrative:** A sysadmin performs routine maintenance: SSH into servers, runs updates, restarts services, transfers config backups. Everything looks suspicious in isolation but is completely normal.

**Facts to build (15-18 total):**

From Syslog (SourceType.SYSLOG):
- SSH accepted login from internal IP (10.0.1.10) as `admin` to webserver01
- sudo commands: `apt update`, `apt upgrade`, `systemctl restart nginx`
- Service events: nginx stopped, nginx started
- source_ref: `"webserver01:auth:2026-03-04"`

From NetFlow (SourceType.NETFLOW):
- SSH session flow (internal to internal, moderate duration ~30 min, moderate bytes)
- SCP/SFTP flow (port 22, higher byte count — config backup transfer)
- HTTP flow to Ubuntu package mirrors (archive.ubuntu.com) — the apt update
- source_ref: `"router01:netflow:2026-03-04"`

From Windows Event Log (SourceType.WINDOWS_EVENT_LOG):
- Admin logon to management workstation (Event 4624, logon type 2 — interactive)
- Scheduled task: `BackupConfigs` (legitimate backup job)
- source_ref: `"mgmt01:Security:2026-03-04T10:00:00Z"` (note: business hours)

**Why cross-source matters:** SSH + sudo + service restarts + file transfers look like lateral movement and exfiltration. But the timing (business hours), source (internal admin IP), and context (package updates, config backups) all point to legitimate operations. The Skeptic needs cross-source context to dismiss effectively.

---

#### SC-016: C2 Beaconing with Lateral Movement
**Sources:** NetFlow + Syslog (2 sources)
**MITRE:** T1071 (Application Layer Protocol) + T1021 (Remote Services)
**Difficulty Tier:** 4
**Expected Verdict:** THREAT_CONFIRMED
**Expected Winner:** ARCHITECT

**Narrative:** A compromised host beacons to a C2 server at regular intervals, then begins lateral movement via SSH to internal hosts.

**Facts to build (14-16 total):**

From NetFlow (SourceType.NETFLOW):
- 4-5 outbound flows to same external IP (192.0.2.100) on port 8443, at ~60 minute intervals, similar byte counts (~2KB each) — beaconing pattern
- 2-3 internal flows from compromised host (10.0.1.100) to other internal hosts on port 22 — lateral movement
- 1 larger outbound flow (~5MB) to the C2 IP — possible data upload after lateral collection
- source_ref: `"router01:netflow:2026-03-04"`

From Syslog (SourceType.SYSLOG):
- SSH accepted logins on the target internal hosts from 10.0.1.100
- sudo commands on target hosts: `cat /etc/shadow`, `tar -czf /tmp/data.tar.gz /var/log/`
- UFW ALLOW entries for the internal SSH connections
- source_ref: `"db01:auth:2026-03-04"`

**Why cross-source matters:** NetFlow reveals the beaconing cadence (regular intervals = C2) and the lateral volume. Syslog shows what the attacker did once inside. Neither source alone is conclusive — regular outbound traffic could be legitimate polling, and SSH between internal hosts is normal admin activity. Together, the pattern is clear.

---

#### SC-017: Cloud Backup vs Exfiltration (Ambiguous)
**Sources:** NetFlow + Windows Event Log (2 sources)
**MITRE:** T1567 (Exfiltration Over Web Service) — or legitimate backup
**Difficulty Tier:** 4
**Expected Verdict:** INCONCLUSIVE
**Expected Winner:** BALANCED

**Narrative:** Large nightly data transfers to a cloud storage provider. Could be the scheduled backup job, could be exfiltration using the backup infrastructure as cover.

**Facts to build (10-12 total):**

From Windows Event Log (SourceType.WINDOWS_EVENT_LOG):
- Scheduled task execution: `CloudBackup.exe` (runs nightly)
- Process creation: `CloudBackup.exe` spawning child process with cloud storage API arguments
- No credential dumping, no lateral movement, no archive creation outside normal paths
- source_ref: `"fileserver01:Security:2026-03-04T01:00:00Z"` (1 AM — scheduled window)

From NetFlow (SourceType.NETFLOW):
- 1 very large outbound flow (~500MB) to cloud storage IP range on port 443
- Duration: ~20 minutes — consistent with large backup
- Byte count is 3x the typical nightly backup size (but not outside all historical variance)
- 1 DNS flow to cloud storage domain
- source_ref: `"router01:netflow:2026-03-04"`

**Why cross-source matters:** The Windows events show a legitimate backup process running on schedule. The NetFlow shows an unusually large transfer — but "unusually large" for a backup isn't definitive. There's no smoking gun (no exfil tools, no credential theft, no lateral movement). The system SHOULD express uncertainty. This is the new SC-011 — a scenario designed to test whether the system can say "I don't know."

---

#### SC-018: Multi-Source False Positive Cascade
**Sources:** Syslog + NetFlow + Windows Event Log (all 3)
**MITRE:** None (false positive scenario)
**Difficulty Tier:** 3
**Expected Verdict:** THREAT_DISMISSED
**Expected Winner:** SKEPTIC

**Narrative:** A vulnerability scanner runs its weekly scan, triggering firewall logs, failed connections, and security events. Everything looks like an attack but is authorized security tooling.

**Facts to build (16-20 total):**

From Syslog (SourceType.SYSLOG):
- Multiple UFW BLOCK entries from scanner IP (10.0.1.250) to various internal hosts on multiple ports
- SSH failed login attempts from scanner IP (expected — scanner tests default credentials)
- sudo command on scanner host: `/opt/nessus/sbin/nessusd` — the scanner process
- source_ref: `"fw01:kern:2026-03-04"` and `"scanner01:auth:2026-03-04"`

From NetFlow (SourceType.NETFLOW):
- Many short-duration flows from 10.0.1.250 to multiple internal IPs across many ports — port scanning pattern
- Flows are all internal (10.x → 10.x)
- Low byte counts, SYN-only flags — connection probing
- source_ref: `"router01:netflow:2026-03-04"`

From Windows Event Log (SourceType.WINDOWS_EVENT_LOG):
- Failed logon attempts (Event 4624 type 3 failures or Event 4625) from scanner IP
- Successful logon from scanner using service account `svc_scanner` — authorized
- Process creation showing scanner-related activity
- **Key fact:** An explicit `authorization_status: "approved"` or similar fact indicating this is a known scanner IP / authorized activity (same pattern as SC-009: Authorized Red Team Exercise)
- source_ref: `"dc01:Security:2026-03-04T08:00:00Z"` (business hours, scheduled scan window)

**Why cross-source matters:** The volume of firewall blocks + port scan flows + failed logins is a textbook attack pattern. But the authorization context from Windows, the internal-only scope from NetFlow, and the known scanner process from Syslog all point to authorized scanning. The Skeptic needs all three sources to dismiss confidently.

---

### 3.3 Scenario Summary Table

| ID | Name | Sources | Facts | Verdict | Winner | Tier |
|----|------|---------|-------|---------|--------|------|
| SC-013 | Coordinated Brute Force | Syslog + NetFlow + Windows | 15-18 | THREAT_CONFIRMED | ARCHITECT | 2 |
| SC-014 | Exfiltration with Cover | NetFlow + Windows | 12-15 | THREAT_CONFIRMED | ARCHITECT | 3 |
| SC-015 | Legitimate Maintenance | Syslog + NetFlow + Windows | 15-18 | THREAT_DISMISSED | SKEPTIC | 3 |
| SC-016 | C2 Beaconing + Lateral | NetFlow + Syslog | 14-16 | THREAT_CONFIRMED | ARCHITECT | 4 |
| SC-017 | Cloud Backup Ambiguity | NetFlow + Windows | 10-12 | INCONCLUSIVE | BALANCED | 4 |
| SC-018 | Scanner False Positive | Syslog + NetFlow + Windows | 16-20 | THREAT_DISMISSED | SKEPTIC | 3 |

**Verdict distribution:** 3 THREAT_CONFIRMED, 2 THREAT_DISMISSED, 1 INCONCLUSIVE
**Combined corpus (18 scenarios):** 7 THREAT_CONFIRMED/INCONCLUSIVE-leaning-threat, 4 THREAT_DISMISSED, 7 INCONCLUSIVE/BALANCED

---

## Step 4 — Implement `run_combined_benchmark.py`

A CLI script that runs both the original 12 and the combined 18 scenarios through benchmark infrastructure.

```python
"""CLI for running benchmarks against the combined 18-scenario corpus.

Usage:
    # Rule-based benchmark (all 18 scenarios)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based

    # Rule-based benchmark (mixed-source only)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based --mixed-only

    # LLM single-turn benchmark (all 18)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm

    # LLM single-turn + multi-turn comparison (all 18)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --compare-multi-turn --max-rounds 3

    # LLM multi-turn only (mixed-source scenarios)
    python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --multi-turn-only --mixed-only --max-rounds 3
"""
```

**CLI arguments:**
- `--strategy`: `rule_based` or `llm` (required)
- `--mixed-only`: Run only SC-013 through SC-018
- `--original-only`: Run only SC-001 through SC-012 (for regression check)
- `--compare-multi-turn`: After single-turn run, also run multi-turn and compare
- `--multi-turn-only`: Run multi-turn only (skip single-turn)
- `--max-rounds`: Max debate rounds for multi-turn (default 3)
- `--confidence-delta`: Convergence threshold for multi-turn (default 0.05)

**Implementation:**
- Import `get_combined_corpus`, `get_mixed_source_scenarios` from `mixed_source_scenarios.py`
- Import `get_all_scenarios` from `scenario_corpus.py`
- Import `run_benchmark` from `benchmark_runner.py`
- Import `generate_report` from `benchmark_report.py`
- For multi-turn: import `run_multi_turn_benchmark` from `multi_turn_benchmark.py`
- For multi-turn comparison: import `generate_comparison_report` from `multi_turn_benchmark_report.py`
- Use argparse for CLI
- Print reports to stdout
- Handle LLM client setup (read API key from env var `ANTHROPIC_API_KEY`)

---

## Step 5 — Implement Tests (`test_mixed_source_scenarios.py`)

Target: ~50-70 tests.

### Test Categories

**Scenario Construction Tests (~18, 3 per scenario):**
- Each scenario's packet is frozen
- fact_count matches actual facts in packet
- Facts contain provenance from the expected SourceTypes

**Cross-Source Validation Tests (~12, 2 per scenario):**
- Each scenario includes facts from at least 2 different SourceTypes
- SC-013, SC-015, SC-018 include all 3 SourceTypes
- Provenance source_refs are realistic and consistent per source type

**Metadata Tests (~6):**
- All scenario IDs are unique
- All scenario IDs follow SC-0XX format
- All expected verdicts are valid
- All difficulty tiers are 1-4
- All MITRE ATT&CK IDs follow Txxxx format (where present)
- No fact_id collisions across scenarios

**API Tests (~8):**
- `get_mixed_source_scenarios()` returns exactly 6 scenarios
- `get_combined_corpus()` returns exactly 18 scenarios
- `get_combined_corpus()` includes all original 12 + all 6 mixed
- `get_mixed_scenario_by_id("SC-013")` returns correct scenario
- `get_mixed_scenario_by_id("SC-099")` raises KeyError
- No duplicate scenario IDs in combined corpus
- Combined corpus ordering: SC-001 through SC-018

**Rule-Based Benchmark Integration Tests (~8):**
- All 6 mixed scenarios run through `run_benchmark()` without errors
- All 18 combined scenarios run through `run_benchmark()` without errors
- Results have valid verdict outcomes
- Results have valid confidence ranges (0.0-1.0)
- Fact coverage ratios are non-negative
- Duration is non-negative
- ScenarioResult scenario_ids match input scenarios

**Fact Structure Tests (~12):**
- All facts have non-empty fact_ids
- All fact_ids use correct prefixes (sc013-, sc014-, etc.)
- All facts have valid EntityType values
- All facts have non-empty attributes dictionaries
- No duplicate fact_ids within any scenario
- No duplicate fact_ids across all 6 mixed scenarios

**Edge Case Tests (~5):**
- Scenarios with maximum fact counts still work in benchmark
- `run_combined_benchmark.py` argparse handles --mixed-only correctly
- `run_combined_benchmark.py` argparse handles --original-only correctly
- Default behavior (no flags) uses all 18 scenarios

---

## Step 6 — Run Full Test Suite

```powershell
# Run ALL tests — existing + new
python -m pytest ares/ -v

# Expected: 1,503 existing + ~50-70 new = ~1,553-1,573 total, ALL PASSING
```

If any existing test fails, STOP. Do not proceed. Fix before continuing.

---

## Step 7 — Verify Rule-Based Benchmark Run

After all tests pass, run the combined benchmark to verify end-to-end:

```powershell
python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based
```

This should produce a report covering all 18 scenarios. Include this verification as a test if not already covered.

---

## Success Criteria

- [ ] All 1,503 existing tests pass (zero regressions)
- [ ] ~50-70 new tests pass
- [ ] 6 new scenarios (SC-013 through SC-018) all construction-valid
- [ ] Every scenario uses facts from 2+ SourceTypes
- [ ] SC-013, SC-015, SC-018 use all 3 SourceTypes
- [ ] All 18 scenarios run through rule-based benchmark without errors
- [ ] `get_combined_corpus()` returns 18 scenarios
- [ ] No fact_id collisions across any scenarios
- [ ] No duplicate scenario IDs in combined corpus
- [ ] `run_combined_benchmark.py` CLI works with --mixed-only, --original-only flags
- [ ] All new dataclasses are frozen
- [ ] No modifications to existing files
- [ ] Type hints on everything, docstrings on all public methods

---

## What Happens Next (Dan's Manual Steps After This Session)

After CC completes and Dan commits:

1. **Single-turn LLM benchmark (combined corpus):**
   ```powershell
   python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm
   ```

2. **Multi-turn LLM benchmark (combined corpus):**
   ```powershell
   python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --compare-multi-turn --max-rounds 3
   ```

3. **Multi-turn on mixed-source only:**
   ```powershell
   python -m ares.dialectic.scripts.run_combined_benchmark --strategy llm --multi-turn-only --mixed-only --max-rounds 3
   ```

These live runs will test whether richer cross-source evidence improves multi-turn debate accuracy relative to single-turn — the core thesis re-test.

---

## Style Notes

- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods and classes
- Test naming: `test_<what>_<condition>_<expected>`
- Keep tests focused and fast (all deterministic, no network calls)
- Match the existing scenario_corpus.py construction patterns exactly
- Import paths: `from ares.dialectic.scripts.mixed_source_scenarios import ...`

---

## Commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
python -m pytest ares/ -v

# Run just new tests
python -m pytest ares/dialectic/tests/scripts/test_mixed_source_scenarios.py -v

# Run rule-based benchmark (combined corpus)
python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based

# Run rule-based benchmark (mixed-source only)
python -m ares.dialectic.scripts.run_combined_benchmark --strategy rule_based --mixed-only
```