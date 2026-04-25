# SESSION 016: Syslog Evidence Extractor — Session Log

**Date:** March 18, 2026
**Branch:** session/016-syslog-extractor
**Starting State:** 1,282 tests, zero regressions, single-turn 91.7%
**Ending State:** 1,408 tests (126 new), zero regressions
**CC Execution Time:** ~8 minutes
**Files Created:** 2
**Files Modified:** 1 (CLAUDE.md only)

---

## Goal

Build ARES's second telemetry source — a BSD syslog (RFC 3164) evidence extractor. This follows the exact pattern established in Session 005 (Windows Event Extractor). Deterministic, boring, provenance-stamped. Sensors don't get opinions.

The strategic motivation: Sessions 013-014 found that multi-turn debate underperforms single-turn (75% vs 91.7%) partly because agents debate with limited evidence from a single source. Richer cross-source evidence should give multi-turn debate a structural advantage worth re-testing in Session 018.

---

## What Was Built

### `ares/dialectic/evidence/extractors/syslog.py`

`SyslogExtractor` — implements `ExtractorProtocol`, parses BSD-style syslog lines into Facts.

**Supported message types (8):**

| Category | Application | Facts Per Event | Entity ID Format |
|----------|-------------|-----------------|------------------|
| SSH Accepted | sshd | 7 | `user:name@hostname` |
| SSH Failed | sshd | 8 | `user:name@hostname` |
| SSH Invalid User | sshd | 6 | `user:name@hostname` |
| UFW Block | kernel | 10 | `connection:src:port->dst:port` |
| UFW Allow | kernel | 10 | `connection:src:port->dst:port` |
| Sudo Command | sudo | 8 | `user:name@hostname` |
| Sudo Auth Failure | sudo (PAM) | 5 | `user:name@hostname` |
| Systemd Start/Stop | systemd | 5 | `service:name@hostname` |

**Key design decisions:**
- `SourceType.SYSLOG` already existed in `provenance.py` — no modifications needed
- `EntityType.NODE` used for all facts (matching Windows extractor pattern; only NODE and EDGE exist)
- Year parameter for timestamps (syslog omits year), defaults to current year
- Application dispatch via `app_base = header.application.split("/")[0]` to handle variants like `sshd/auth`
- `SyslogHeader` frozen dataclass as intermediate parsed type
- Priority decoded into facility + severity, stored as facts on every event

**Error handling (matching Windows extractor exactly):**
- Strict mode (default): `ValueError` on first unparseable line
- Permissive mode: Collects `ExtractionError` objects, continues parsing
- Error types: `MALFORMED_HEADER`, `UNKNOWN_APPLICATION`, `MISSING_FIELD`, `INVALID_PRIORITY`
- Empty/blank-only input returns empty result (not an error)

### `ares/dialectic/tests/evidence/extractors/test_syslog.py`

126 tests across 16 test classes:

| Category | Tests |
|----------|-------|
| Protocol Compliance | 5 |
| SSH Accepted | 10 |
| SSH Failed | 6 |
| SSH Invalid User | 5 |
| Firewall Block | 10 |
| Firewall Allow | 4 |
| Sudo Command | 8 |
| Sudo Auth Failure | 4 |
| Systemd | 8 |
| Provenance | 10 |
| Strict Mode | 8 |
| Permissive Mode | 8 |
| ExtractionStats | 5 |
| Input Formats | 4 |
| Fact ID Uniqueness | 4 |
| Entity Types | 4 |
| Priority Parsing | 3 |
| Timestamp Parsing | 4 |
| Integration | 6 |
| Edge Cases | 11 |

---

## Key Observations

1. **`SourceType.SYSLOG` already existed** — provenance.py was designed for this from Session 002. Zero modifications to existing files required.

2. **Pattern matching is straightforward** — regex-based parsing of well-defined syslog formats. No ambiguity, no opinions. Pure sensor work.

3. **55-line brute-force stream** parses in milliseconds — performance is not a concern at this scale.

4. **Priority 38 is auth (facility 4), not authpriv (facility 10)** — caught by tests during development. `38 = 4*8 + 6`.

5. **EvidencePacket API** uses `add_fact()` + `freeze()` pattern, not constructor injection. Integration test confirmed extracted facts compose cleanly.

---

## Test Results

```
1,408 passed, 10 skipped (live LLM), 0 failed
126 new tests, 0 regressions
```

---

## What's Next

- **Session 017:** NetFlow Extractor (third telemetry source)
- **Session 018:** Mixed-Source Benchmark (cross-source scenarios, re-test single-turn AND multi-turn)
- **Session 019:** Redis Backend (persistent Memory Stream)
- **Session 020:** Checkpoint (binary pass/fail against expanded corpus)
