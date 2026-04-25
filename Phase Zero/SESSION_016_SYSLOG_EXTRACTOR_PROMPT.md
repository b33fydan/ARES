# SESSION 016: Syslog Evidence Extractor
# Claude Code Execution Prompt

## Context

Continuing ARES build. Sessions 013–014 tested the multi-turn thesis and found that debate amplifies commitment bias without improving accuracy beyond single-turn (91.7%). The diagnosis: agents are debating with limited evidence from a single source (Windows Event Logs). Richer cross-source evidence should give multi-turn debate a structural advantage worth re-testing in Session 018.

Session 016 goal: Build the Syslog evidence extractor — ARES's second telemetry source. This follows the exact pattern established in Session 005 (Windows Event Extractor). Deterministic, boring, provenance-stamped. Sensors don't get opinions.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/016-syslog-extractor

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** All 1,282 existing tests must pass unchanged.
2. **All new dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **No live LLM calls.** This session is fully deterministic.
4. **Type hints on everything. Docstrings on all public methods.**
5. **Test naming convention:** `test_<what>_<condition>_<expected>`
6. **Follow the ExtractorProtocol** established in `ares/dialectic/evidence/extractors/protocol.py`.

---

## Existing Extractor Architecture (DO NOT MODIFY)

```
ares/dialectic/evidence/extractors/
├── __init__.py              # DO NOT MODIFY
├── protocol.py              # ExtractionResult, ExtractionError, ExtractionStats, ExtractorProtocol — DO NOT MODIFY
└── windows.py               # WindowsEventExtractor — DO NOT MODIFY
```

**All other existing files: DO NOT MODIFY.**

---

## Step 1 — Review Before Writing

Read these files to understand the extractor pattern and types you must follow:

1. `ares/dialectic/evidence/extractors/protocol.py` — `ExtractionResult`, `ExtractionError`, `ExtractionStats`, `ExtractorProtocol`
2. `ares/dialectic/evidence/extractors/windows.py` — Reference implementation. Match this style exactly.
3. `ares/dialectic/evidence/fact.py` — `Fact`, `EntityType`
4. `ares/dialectic/evidence/provenance.py` — `Provenance`, `SourceType`
5. `ares/dialectic/tests/evidence/extractors/` — Existing test patterns for the Windows extractor

**Understand the Windows extractor thoroughly before writing a single line.** The Syslog extractor must follow the same structural patterns: same error handling approach, same provenance stamping, same strict/permissive mode behavior.

---

## Step 2 — Create New File Structure

```
ares/dialectic/evidence/extractors/
└── syslog.py                          # NEW: SyslogExtractor

ares/dialectic/tests/evidence/extractors/
└── test_syslog.py                     # NEW: ~60-80 tests
```

**Two new files. That's it.**

---

## Step 3 — Understand Syslog Format

The extractor parses BSD-style syslog messages (RFC 3164). Each line is a single log entry:

```
<priority>timestamp hostname application[pid]: message
```

Examples of security-relevant syslog messages the extractor should handle:

### 3.1 SSH Authentication (auth/authpriv facility)

```
<38>Mar  4 14:22:01 webserver01 sshd[12345]: Accepted publickey for admin from 10.0.1.50 port 52341 ssh2
<38>Mar  4 14:22:01 webserver01 sshd[12345]: Failed password for root from 203.0.113.50 port 44231 ssh2
<38>Mar  4 14:22:01 webserver01 sshd[12345]: Invalid user oracle from 198.51.100.23 port 39821
<38>Mar  4 14:25:00 webserver01 sshd[12346]: Connection closed by authenticating user admin 10.0.1.50 port 52341 [preauth]
```

### 3.2 Firewall/iptables (kern facility)

```
<4>Mar  4 14:30:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e:6f:70:80:90:a0:b0:08:00 SRC=203.0.113.50 DST=10.0.1.100 LEN=52 TTO=128 PROTO=TCP SPT=44231 DPT=22 WINDOW=65535 RES=0x00 SYN URGP=0
<4>Mar  4 14:30:01 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.1.100 PROTO=TCP SPT=52341 DPT=443
```

### 3.3 sudo/privilege escalation (auth facility)

```
<38>Mar  4 14:35:00 webserver01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update
<38>Mar  4 14:35:01 webserver01 sudo: pam_unix(sudo:auth): authentication failure; logname=admin uid=1000 euid=0 tty=/dev/pts/0 ruser=admin rhost=  user=admin
```

### 3.4 System service events (daemon facility)

```
<30>Mar  4 14:40:00 webserver01 systemd[1]: Started OpenSSH server daemon.
<30>Mar  4 14:40:01 webserver01 systemd[1]: Stopping firewalld - dynamic firewall daemon...
```

---

## Step 4 — Implement `syslog.py`

### 4.1 SyslogExtractor Class

```python
class SyslogExtractor:
    """Parses BSD syslog (RFC 3164) messages into Facts.
    
    Implements ExtractorProtocol. Handles SSH auth, firewall,
    sudo, and system service events from syslog streams.
    """
    
    VERSION: str = "syslog-extractor-v1.0"
    
    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True
    ) -> ExtractionResult:
        ...
```

### 4.2 Supported Message Types

The extractor must identify and parse these syslog message categories:

| Category | Application | Facts Emitted |
|----------|-------------|---------------|
| SSH Accepted | sshd | auth_method, username, source_ip, source_port, protocol |
| SSH Failed | sshd | auth_method, username, source_ip, source_port, failure_reason |
| SSH Invalid User | sshd | username, source_ip, source_port |
| Firewall Block | kernel (UFW/iptables) | action (BLOCK), src_ip, dst_ip, protocol, src_port, dst_port, interface |
| Firewall Allow | kernel (UFW/iptables) | action (ALLOW), src_ip, dst_ip, protocol, src_port, dst_port |
| Sudo Command | sudo | invoking_user, target_user, command, tty, working_directory |
| Sudo Auth Failure | sudo/pam | username, failure_reason |
| Service Start/Stop | systemd | service_name, action (started/stopped/stopping) |

### 4.3 Entity ID Formats

Follow the same pattern as the Windows extractor — entity IDs must be deterministic and unique:

- SSH events: `user:{username}@{hostname}` (EntityType.USER)
- Firewall events: `connection:{src_ip}:{src_port}->{dst_ip}:{dst_port}` (EntityType.NETWORK_CONNECTION or closest available EntityType)
- Sudo events: `user:{invoking_user}@{hostname}` (EntityType.USER)
- Service events: `service:{service_name}@{hostname}` (EntityType.PROCESS or closest available EntityType)

**IMPORTANT:** Check `EntityType` in `fact.py` for available types. Use the closest match. If no EntityType fits well for network connections, use the most appropriate existing type — do NOT add new EntityType values (that would modify an existing file).

### 4.4 Provenance

All Facts must have provenance stamped as:
- `source_type`: `SourceType.SYSLOG` — **CHECK if this exists in `provenance.py`.** If it doesn't exist, you'll need to handle this. Options:
  - If `SourceType` is an extensible enum or has a generic value, use that
  - If you can add to `SourceType` without breaking existing tests, add `SYSLOG`
  - If neither works, use the closest existing `SourceType` and document the decision
- `source_ref`: The `source_ref` parameter passed to `extract()` (e.g., `"webserver01:auth:2026-03-04"`)
- `extractor_version`: `SyslogExtractor.VERSION`
- `extracted_at`: UTC ISO timestamp of extraction time

### 4.5 Syslog Priority Parsing

BSD syslog priority = (facility * 8) + severity. Parse the `<priority>` field:
- Facility: 0=kern, 4=auth, 10=authpriv, 3=daemon, etc.
- Severity: 0=emergency through 7=debug
- Store facility and severity as fact attributes where useful

### 4.6 Timestamp Parsing

Syslog timestamps are in `MMM DD HH:MM:SS` format (no year). The extractor should:
- Parse the timestamp
- Since syslog doesn't include year, accept an optional `year` parameter (default: current year)
- Canonicalize to UTC ISO format, same as Windows extractor

### 4.7 Error Handling

Match the Windows extractor pattern exactly:
- **Strict mode (default):** Raise `ValueError` on first unparseable line
- **Permissive mode:** Collect `ExtractionError` objects, continue parsing, return partial results with `partial=True`
- Error types: `MALFORMED_HEADER`, `UNKNOWN_APPLICATION`, `MISSING_FIELD`, `INVALID_PRIORITY`
- Raw snippet auto-truncated to 200 chars (same as Windows extractor)

### 4.8 Multi-line Handling

Some syslog messages span multiple lines (stack traces, etc.). For v1.0:
- Treat each line as an independent message
- Lines that don't match the `<priority>timestamp hostname app[pid]: message` pattern are errors in strict mode, skipped in permissive mode
- This is a deliberate simplification. Multi-line support can be added in a future version.

---

## Step 5 — Implement Tests (`test_syslog.py`)

Target: ~60-80 tests. Follow the existing test patterns from the Windows extractor tests.

### Test Categories

**Parsing Tests (~20):**
- Each supported message type parses correctly
- Fact count matches expected for each message type
- Entity IDs follow the documented format
- Attributes contain expected keys and values
- Priority field parsed into correct facility/severity
- Timestamps canonicalized to ISO format

**Provenance Tests (~10):**
- source_ref propagated correctly
- extractor_version matches VERSION constant
- extracted_at is valid ISO timestamp
- SourceType is correct

**Strict Mode Tests (~10):**
- Malformed lines raise ValueError
- Missing priority raises ValueError
- Invalid application raises ValueError
- Empty input returns empty result (not an error)
- Single valid line among garbage raises on first garbage line

**Permissive Mode Tests (~10):**
- Malformed lines collected as ExtractionError
- Valid lines still parsed
- partial=True when errors present
- Error types correctly categorized
- Stats accurately reflect events_seen vs events_parsed vs events_dropped

**ExtractionStats Tests (~5):**
- events_seen counts all lines
- events_parsed counts successful parses
- events_dropped = events_seen - events_parsed
- facts_emitted counts total facts across all parsed events

**Integration Tests (~10):**
- Mixed message types in single input
- Large input (50+ lines) performance is reasonable
- Realistic syslog stream with interleaved message types
- Output Facts can be added to an EvidencePacket and frozen
- ExtractionResult fields all populated correctly

**Edge Cases (~10):**
- Empty input (bytes and str)
- Input with only blank lines
- Input with only unparseable lines (strict and permissive)
- Very long lines (>10000 chars)
- Non-ASCII characters in hostnames or messages
- Missing PID in application field (e.g., `sshd:` instead of `sshd[12345]:`)
- Duplicate timestamps (valid — syslog can have multiple events per second)

### Test Fixtures

Create realistic syslog fixtures as module-level constants:

```python
# Single-line fixtures
SSH_ACCEPTED = '<38>Mar  4 14:22:01 webserver01 sshd[12345]: Accepted publickey for admin from 10.0.1.50 port 52341 ssh2'
SSH_FAILED = '<38>Mar  4 14:22:02 webserver01 sshd[12345]: Failed password for root from 203.0.113.50 port 44231 ssh2'
SSH_INVALID_USER = '<38>Mar  4 14:22:03 webserver01 sshd[12345]: Invalid user oracle from 198.51.100.23 port 39821'
UFW_BLOCK = '<4>Mar  4 14:30:00 fw01 kernel: [UFW BLOCK] IN=eth0 OUT= MAC=00:1a:2b:3c:4d:5e SRC=203.0.113.50 DST=10.0.1.100 LEN=52 TTO=128 PROTO=TCP SPT=44231 DPT=22 WINDOW=65535 SYN'
UFW_ALLOW = '<4>Mar  4 14:30:01 fw01 kernel: [UFW ALLOW] IN=eth0 OUT= SRC=10.0.1.50 DST=10.0.1.100 PROTO=TCP SPT=52341 DPT=443'
SUDO_COMMAND = '<38>Mar  4 14:35:00 webserver01 sudo: admin : TTY=pts/0 ; PWD=/home/admin ; USER=root ; COMMAND=/usr/bin/apt update'
SUDO_AUTH_FAIL = '<38>Mar  4 14:35:01 webserver01 sudo: pam_unix(sudo:auth): authentication failure; logname=admin uid=1000 euid=0 tty=/dev/pts/0 ruser=admin rhost=  user=admin'
SYSTEMD_START = '<30>Mar  4 14:40:00 webserver01 systemd[1]: Started OpenSSH server daemon.'
SYSTEMD_STOP = '<30>Mar  4 14:40:01 webserver01 systemd[1]: Stopping firewalld - dynamic firewall daemon...'

# Multi-line realistic stream
REALISTIC_STREAM = '\n'.join([SSH_FAILED, SSH_FAILED, SSH_FAILED, UFW_BLOCK, SSH_ACCEPTED, SUDO_COMMAND])
```

---

## Step 6 — Run Full Test Suite

```powershell
# Run ALL tests — existing + new
python -m pytest ares/ -v

# Expected: 1,282 existing + ~60-80 new = ~1,342-1,362 total, ALL PASSING
```

If any existing test fails, STOP. Do not proceed. The failure is likely caused by an import side effect or file structure issue. Fix it before continuing.

---

## Step 7 — Verify ExtractorProtocol Compliance

After tests pass, verify that `SyslogExtractor` satisfies the `ExtractorProtocol`:

```python
from ares.dialectic.evidence.extractors.protocol import ExtractorProtocol
from ares.dialectic.evidence.extractors.syslog import SyslogExtractor

assert isinstance(SyslogExtractor(), ExtractorProtocol)
```

Include this as a test.

---

## Success Criteria

- [ ] All 1,282 existing tests pass (zero regressions)
- [ ] ~60-80 new tests pass
- [ ] SyslogExtractor satisfies ExtractorProtocol
- [ ] All 8 message types parse correctly with proper Facts
- [ ] Strict mode raises on first malformed line
- [ ] Permissive mode collects errors and returns partial results
- [ ] Provenance correctly stamped on all Facts
- [ ] Entity IDs follow documented formats
- [ ] ExtractionStats accurately reflects parse results
- [ ] Output Facts can be added to EvidencePacket and frozen
- [ ] All new dataclasses are frozen
- [ ] No modifications to existing files (except possibly adding SYSLOG to SourceType if needed and safe)
- [ ] Type hints on everything, docstrings on all public methods

---

## Style Notes

- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods and classes
- Test naming: `test_<what>_<condition>_<expected>`
- Keep tests focused and fast (all deterministic, no network calls)
- Match the Windows extractor's code style and structural patterns
- Import paths: `from ares.dialectic.evidence.extractors.syslog import SyslogExtractor`

---

## Commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
python -m pytest ares/ -v

# Run just new tests
python -m pytest ares/dialectic/tests/evidence/extractors/test_syslog.py -v

# Run all extractor tests (Windows + Syslog)
python -m pytest ares/dialectic/tests/evidence/extractors/ -v

# Run with coverage
python -m pytest ares/ --cov=ares --cov-report=term-missing
```
