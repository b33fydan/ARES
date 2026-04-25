# SESSION 017: NetFlow Evidence Extractor
# Claude Code Execution Prompt

## Context

Continuing ARES build. Session 016 added the Syslog extractor (126 tests, zero regressions). ARES now has two telemetry sources: Windows Event Logs (host-layer) and Syslog (network-layer). Session 017 adds the third: NetFlow (traffic metadata).

The strategic purpose: three diverse evidence sources enable cross-source correlation scenarios in Session 018, where multi-turn debate gets its honest re-test against a richer evidence distribution. NetFlow provides volume, duration, and connection metadata that neither Windows Event Logs nor Syslog capture — the "who talked to whom, how much, and for how long" layer.

Session 017 goal: Build the NetFlow evidence extractor following the established extractor pattern (Sessions 005, 016). Deterministic, boring, provenance-stamped. Sensors don't get opinions.

Project location: C:\ares-phase-zero
Run tests: python -m pytest ares/ -v
Git branch: session/017-netflow-extractor

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** All 1,408 existing tests must pass unchanged.
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
├── windows.py               # WindowsEventExtractor — DO NOT MODIFY
└── syslog.py                # SyslogExtractor — DO NOT MODIFY
```

**All other existing files: DO NOT MODIFY.**

---

## Step 1 — Review Before Writing

Read these files to understand the extractor pattern and types you must follow:

1. `ares/dialectic/evidence/extractors/protocol.py` — `ExtractionResult`, `ExtractionError`, `ExtractionStats`, `ExtractorProtocol`
2. `ares/dialectic/evidence/extractors/windows.py` — First extractor implementation
3. `ares/dialectic/evidence/extractors/syslog.py` — Second extractor implementation (most recent pattern)
4. `ares/dialectic/evidence/fact.py` — `Fact`, `EntityType`
5. `ares/dialectic/evidence/provenance.py` — `Provenance`, `SourceType` (note: SYSLOG was added in Session 016)
6. `ares/dialectic/tests/evidence/extractors/test_syslog.py` — Most recent test patterns

**Read both existing extractors.** The Syslog extractor is the freshest pattern. Match its structural conventions exactly.

---

## Step 2 — Create New File Structure

```
ares/dialectic/evidence/extractors/
└── netflow.py                          # NEW: NetFlowExtractor

ares/dialectic/tests/evidence/extractors/
└── test_netflow.py                     # NEW: ~60-80 tests
```

**Two new files. That's it.**

---

## Step 3 — Understand NetFlow Data Format

The extractor parses **CSV-format NetFlow export records** — the standard output from tools like nfdump, SiLK, and flow-tools. This is what analysts actually work with (not raw binary NetFlow v5/v9 packets).

Each row represents a completed network flow (a unidirectional sequence of packets sharing src_ip, dst_ip, src_port, dst_port, protocol).

### 3.1 CSV Format

The first line is a header row. Subsequent lines are flow records:

```csv
start_time,end_time,duration_ms,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,tcp_flags,tos
2026-03-04T14:00:00Z,2026-03-04T14:00:05Z,5000,10.0.1.50,203.0.113.10,52341,443,TCP,45,32400,SA,0
2026-03-04T14:00:01Z,2026-03-04T14:00:01Z,50,10.0.1.50,10.0.1.1,61234,53,UDP,2,180,0,0
2026-03-04T14:00:02Z,2026-03-04T14:05:02Z,300000,10.0.1.100,198.51.100.50,49152,22,TCP,1200,2450000,SAP,0
2026-03-04T14:00:03Z,2026-03-04T14:00:03Z,20,203.0.113.50,10.0.1.100,44231,22,TCP,3,180,S,0
2026-03-04T14:00:04Z,2026-03-04T14:30:04Z,1800000,10.0.1.100,192.0.2.50,48000,8443,TCP,8500,15000000,SAP,0
```

### 3.2 Field Definitions

| Field | Type | Description |
|-------|------|-------------|
| start_time | ISO 8601 | Flow start timestamp |
| end_time | ISO 8601 | Flow end timestamp |
| duration_ms | int | Flow duration in milliseconds |
| src_ip | string | Source IP address |
| dst_ip | string | Destination IP address |
| src_port | int | Source port |
| dst_port | int | Destination port |
| protocol | string | Transport protocol (TCP, UDP, ICMP, etc.) |
| packets | int | Total packets in flow |
| bytes | int | Total bytes in flow |
| tcp_flags | string | TCP flag summary (S=SYN, A=ACK, F=FIN, R=RST, P=PSH, U=URG) or "0" for non-TCP |
| tos | int | Type of Service / DSCP value |

### 3.3 Security-Relevant Flow Patterns

The extractor should parse ALL valid flow records, but the following patterns are what downstream agents will reason about:

- **Port scanning:** Many short flows from one source to one destination across many ports (low packets, low bytes, SYN-only flags)
- **Data exfiltration:** Long-duration high-byte flows to external IPs, especially on non-standard ports
- **Beaconing/C2:** Regular-interval flows to the same external destination (fixed duration, consistent byte counts)
- **DNS tunneling:** High volume of UDP/53 flows with unusual byte counts
- **Lateral movement:** Internal-to-internal flows on administrative ports (22, 3389, 445, 5985)
- **DDoS:** Many sources to one destination, high packet counts

The extractor does NOT classify these patterns — it just parses the flow data into Facts. Classification is the agents' job.

---

## Step 4 — Implement `netflow.py`

### 4.1 NetFlowExtractor Class

```python
class NetFlowExtractor:
    """Parses CSV-format NetFlow export records into Facts.
    
    Implements ExtractorProtocol. Handles standard flow fields
    including timing, addressing, volume metrics, and TCP flags.
    """
    
    VERSION: str = "netflow-extractor-v1.0"
    
    def extract(
        self,
        raw: bytes | str,
        *,
        source_ref: str,
        strict: bool = True
    ) -> ExtractionResult:
        ...
```

### 4.2 Facts Per Flow Record

Each valid flow record should produce Facts capturing these attributes:

| Fact Key | Value | Notes |
|----------|-------|-------|
| start_time | ISO timestamp | Flow start |
| end_time | ISO timestamp | Flow end |
| duration_ms | int as string | Flow duration |
| src_ip | IP address | Source |
| dst_ip | IP address | Destination |
| src_port | port as string | Source port |
| dst_port | port as string | Destination port — key for service identification |
| protocol | TCP/UDP/ICMP/etc | Transport protocol |
| packets | count as string | Volume metric |
| bytes | count as string | Volume metric |
| tcp_flags | flag string | TCP flags if applicable, "0" for non-TCP |
| tos | int as string | Type of service |
| bytes_per_packet | computed float as string | bytes/packets — useful for payload size analysis |
| flow_direction | "inbound"/"outbound"/"internal"/"external" | Computed from IP ranges if determinable, otherwise "unknown" |

**Implementation note on flow_direction:** Use RFC 1918 ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) to classify:
- internal: both src and dst are RFC 1918
- outbound: src is RFC 1918, dst is not
- inbound: dst is RFC 1918, src is not
- external: neither is RFC 1918

### 4.3 Entity ID Format

Each flow record maps to a single entity:
- `flow:{src_ip}:{src_port}->{dst_ip}:{dst_port}/{protocol}` 

Use the most appropriate `EntityType` from `fact.py`. Check what's available — if there's a NETWORK_CONNECTION or similar type, use it. Otherwise use the closest match, same approach as Session 016.

### 4.4 Provenance

- `source_type`: `SourceType.NETFLOW` — **CHECK if this exists in `provenance.py`.** If not, add it following the same pattern used for `SourceType.SYSLOG` in Session 016. Only add if it doesn't break existing tests.
- `source_ref`: The `source_ref` parameter passed to `extract()` (e.g., `"router01:netflow:2026-03-04"`)
- `extractor_version`: `NetFlowExtractor.VERSION`
- `extracted_at`: UTC ISO timestamp of extraction time

### 4.5 Header Handling

The extractor must handle:
- **Standard header:** First line matches expected column names → parse as header
- **No header:** If first line looks like data (contains IP addresses, numeric fields), treat all lines as data using positional mapping to the standard field order defined in 3.2
- **Custom header:** Column names may differ slightly (e.g., `source_ip` vs `src_ip`, `destination_port` vs `dst_port`). Support common aliases:
  - src_ip / source_ip / src_addr / source_address
  - dst_ip / dest_ip / destination_ip / dst_addr / destination_address
  - src_port / source_port
  - dst_port / dest_port / destination_port
  - duration_ms / duration / dur
  - packets / pkts / in_packets
  - bytes / octets / in_bytes

### 4.6 Error Handling

Match the Syslog extractor pattern:
- **Strict mode (default):** Raise `ValueError` on first unparseable row
- **Permissive mode:** Collect `ExtractionError` objects, continue parsing, return partial results with `partial=True`
- Error types: `MALFORMED_ROW`, `MISSING_FIELD`, `INVALID_IP`, `INVALID_PORT`, `INVALID_TIMESTAMP`, `INVALID_HEADER`
- Raw snippet auto-truncated to 200 chars

### 4.7 Validation Rules

- IP addresses must be valid IPv4 (basic format check: four octets 0-255)
- Ports must be 0-65535
- Packets and bytes must be non-negative integers
- duration_ms must be non-negative
- Protocol must be non-empty string
- start_time and end_time must be parseable timestamps (ISO 8601)
- end_time must be >= start_time (if both present)

---

## Step 5 — Implement Tests (`test_netflow.py`)

Target: ~60-80 tests. Follow the test patterns from `test_syslog.py`.

### Test Fixtures

Create realistic NetFlow fixtures as module-level constants:

```python
HEADER = "start_time,end_time,duration_ms,src_ip,dst_ip,src_port,dst_port,protocol,packets,bytes,tcp_flags,tos"

# Normal HTTPS session (outbound)
HTTPS_FLOW = "2026-03-04T14:00:00Z,2026-03-04T14:00:05Z,5000,10.0.1.50,203.0.113.10,52341,443,TCP,45,32400,SA,0"

# DNS query (outbound, UDP)
DNS_FLOW = "2026-03-04T14:00:01Z,2026-03-04T14:00:01Z,50,10.0.1.50,10.0.1.1,61234,53,UDP,2,180,0,0"

# Large SSH session (possible exfiltration)
LARGE_SSH = "2026-03-04T14:00:02Z,2026-03-04T14:05:02Z,300000,10.0.1.100,198.51.100.50,49152,22,TCP,1200,2450000,SAP,0"

# Port scan signature (SYN-only, low packets)
PORT_SCAN = "2026-03-04T14:00:03Z,2026-03-04T14:00:03Z,20,203.0.113.50,10.0.1.100,44231,22,TCP,3,180,S,0"

# Long-running C2 beacon (high duration, moderate bytes)
C2_BEACON = "2026-03-04T14:00:04Z,2026-03-04T14:30:04Z,1800000,10.0.1.100,192.0.2.50,48000,8443,TCP,8500,15000000,SAP,0"

# Internal lateral movement (RDP)
LATERAL_RDP = "2026-03-04T14:01:00Z,2026-03-04T14:10:00Z,540000,10.0.1.100,10.0.1.200,49500,3389,TCP,3200,1800000,SAP,0"

# DNS tunneling signature (many UDP/53 flows, unusual byte counts)
DNS_TUNNEL = "2026-03-04T14:02:00Z,2026-03-04T14:02:01Z,1000,10.0.1.100,8.8.8.8,55000,53,UDP,4,2400,0,0"

# ICMP flow (no ports)
ICMP_FLOW = "2026-03-04T14:03:00Z,2026-03-04T14:03:00Z,100,10.0.1.50,10.0.1.1,0,0,ICMP,4,256,0,0"

# Realistic mixed stream
REALISTIC_STREAM = '\n'.join([HEADER, HTTPS_FLOW, DNS_FLOW, LARGE_SSH, PORT_SCAN, C2_BEACON, LATERAL_RDP, DNS_TUNNEL, ICMP_FLOW])
```

### Test Categories

**Parsing Tests (~20):**
- Each flow type parses correctly
- Fact count per flow matches expected
- Entity IDs follow `flow:{src}:{sport}->{dst}:{dport}/{proto}` format
- All 14 fact attributes present and correctly valued
- bytes_per_packet computed correctly
- flow_direction computed correctly for inbound/outbound/internal/external
- Header row not treated as data
- Protocol field preserved correctly (TCP, UDP, ICMP)

**Provenance Tests (~8):**
- source_ref propagated correctly
- extractor_version matches VERSION constant
- extracted_at is valid ISO timestamp
- SourceType is correct (NETFLOW)

**Strict Mode Tests (~10):**
- Malformed row raises ValueError
- Invalid IP raises ValueError
- Invalid port (negative, >65535) raises ValueError
- Missing required field raises ValueError
- Empty input returns empty result (not an error)
- Header-only input returns empty result

**Permissive Mode Tests (~10):**
- Malformed rows collected as ExtractionError
- Valid rows still parsed
- partial=True when errors present
- Error types correctly categorized
- Stats accurately reflect flow counts

**ExtractionStats Tests (~5):**
- events_seen counts all data rows (not header)
- events_parsed counts successful parses
- events_dropped = events_seen - events_parsed
- facts_emitted counts total facts across all parsed flows

**Header Handling Tests (~8):**
- Standard header recognized
- Alias headers recognized (source_ip, dest_port, etc.)
- No-header input handled with positional mapping
- Invalid header in strict mode raises error
- Extra columns ignored gracefully
- Missing required columns detected

**Integration Tests (~8):**
- Mixed flow types in single input
- Large input (100+ rows) works correctly
- Output Facts can be added to EvidencePacket and frozen
- ExtractionResult fields all populated
- Realistic stream parses completely

**Edge Cases (~8):**
- Empty input (bytes and str)
- Header-only input
- Single flow record (no header)
- Single flow record (with header)
- Very long rows
- Zero-duration flows (duration_ms = 0)
- Zero-byte flows (bytes = 0, packets = 0) — valid for RST/timeout
- ICMP with port 0 (valid)
- Duplicate flow records (valid — different flows can have same 5-tuple at different times)
- Non-ASCII in CSV fields

---

## Step 6 — Run Full Test Suite

```powershell
# Run ALL tests — existing + new
python -m pytest ares/ -v

# Expected: 1,408 existing + ~60-80 new = ~1,468-1,488 total, ALL PASSING
```

If any existing test fails, STOP. Do not proceed. Fix before continuing.

---

## Step 7 — Verify ExtractorProtocol Compliance

```python
from ares.dialectic.evidence.extractors.protocol import ExtractorProtocol
from ares.dialectic.evidence.extractors.netflow import NetFlowExtractor

assert isinstance(NetFlowExtractor(), ExtractorProtocol)
```

Include this as a test.

---

## Success Criteria

- [ ] All 1,408 existing tests pass (zero regressions)
- [ ] ~60-80 new tests pass
- [ ] NetFlowExtractor satisfies ExtractorProtocol
- [ ] All CSV flow records parse correctly with proper Facts
- [ ] 14 fact attributes per flow (including computed bytes_per_packet and flow_direction)
- [ ] flow_direction correctly classifies inbound/outbound/internal/external via RFC 1918
- [ ] Header detection works (standard, alias, no-header)
- [ ] Strict mode raises on first malformed row
- [ ] Permissive mode collects errors and returns partial results
- [ ] Provenance correctly stamped on all Facts
- [ ] Entity IDs follow `flow:{src}:{sport}->{dst}:{dport}/{proto}` format
- [ ] ExtractionStats accurately reflects parse results
- [ ] Output Facts can be added to EvidencePacket and frozen
- [ ] All new dataclasses are frozen
- [ ] No modifications to existing files (except possibly adding NETFLOW to SourceType if needed and safe)
- [ ] Type hints on everything, docstrings on all public methods

---

## Style Notes

- Frozen dataclasses everywhere (immutability)
- Type hints on everything
- Docstrings for public methods and classes
- Test naming: `test_<what>_<condition>_<expected>`
- Keep tests focused and fast (all deterministic, no network calls)
- Match the Syslog extractor's code style and structural patterns
- Import paths: `from ares.dialectic.evidence.extractors.netflow import NetFlowExtractor`

---

## Commands

```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run all tests
python -m pytest ares/ -v

# Run just new tests
python -m pytest ares/dialectic/tests/evidence/extractors/test_netflow.py -v

# Run all extractor tests (Windows + Syslog + NetFlow)
python -m pytest ares/dialectic/tests/evidence/extractors/ -v

# Run with coverage
python -m pytest ares/ --cov=ares --cov-report=term-missing
```
