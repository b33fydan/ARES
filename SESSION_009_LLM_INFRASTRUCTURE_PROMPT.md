# SESSION 009 — LLM Infrastructure Layer (Strategy Pattern + Anthropic API)

## Context

Previous session: Session 008 — Multi-Turn Dialectical Cycles COMPLETE (65 new tests, 926 total)

ARES is a dialectical cybersecurity reasoning engine. Three agents debate:
- **Architect** (THESIS) — proposes threat hypotheses from evidence
- **Skeptic** (ANTITHESIS) — challenges with benign explanations
- **Oracle Judge** (SYNTHESIS) — deterministic verdict from structured assertions
- **Oracle Narrator** — explains verdict in natural language (constrained, cannot alter verdict)

Currently ALL reasoning is rule-based. This session introduces the **Strategy Pattern** to make reasoning pluggable, extracts existing logic into `RuleBasedStrategy`, and builds an `LLMStrategy` skeleton that wraps the Anthropic API with output validation and fallback.

## System State
- 926 tests passing on main, zero failures
- Full pipeline: Raw XML → Extractor → Facts → EvidencePacket → run_multi_turn_cycle() → MultiTurnCycleResult → to_cycle_result() → MemoryStream.store()
- All components deterministic — zero LLM calls

## Today's Goal

Build the LLM infrastructure layer using the Strategy Pattern. After this session:
1. Agents accept pluggable reasoning strategies at construction
2. Existing rule-based logic is extracted into strategy classes (zero behavior change)
3. LLM strategies wrap Anthropic API with output validation against EvidencePacket
4. LLM failure falls back to rule-based automatically
5. All 926 existing tests pass unchanged (rule-based is default)
6. ~80-100 new tests covering protocols, extraction, validation, mocking, and fallback

---

## CRITICAL CONSTRAINTS

### DO NOT MODIFY (these files have existing tests that must not break):
- `ares/dialectic/coordinator/validator.py` (26 tests)
- `ares/dialectic/coordinator/cycle.py` (50 tests)
- `ares/dialectic/coordinator/coordinator.py` (33 tests)
- `ares/dialectic/coordinator/orchestrator.py` (58 tests)
- `ares/dialectic/coordinator/multi_turn.py` (65 tests)
- `ares/dialectic/agents/context.py`
- `ares/dialectic/agents/base.py`
- `ares/dialectic/agents/patterns.py`
- `ares/dialectic/memory/*` (all memory files)
- `ares/dialectic/evidence/*` (all evidence files)
- `ares/dialectic/messages/*` (all message files)
- `ares/graph/*`

### MAY MODIFY (minimal changes only):
- `ares/dialectic/agents/architect.py` — Add optional `threat_analyzer` parameter to `__init__`, delegate `_detect_anomalies()` to it
- `ares/dialectic/agents/skeptic.py` — Add optional `explanation_finder` parameter to `__init__`, delegate `_find_benign_explanations()` to it  
- `ares/dialectic/agents/oracle.py` — Add optional `narrative_generator` parameter to `OracleNarrator.__init__`, delegate template logic to it
- `ares/dialectic/agents/__init__.py` — Add new exports if needed

### OracleJudge MUST REMAIN DETERMINISTIC
- `OracleJudge.compute_verdict()` — NO changes. No strategy injection. No LLM involvement. This is the architectural firewall.

---

## Existing Types (Read These Files First)

```python
# From ares.dialectic.agents.patterns (DO NOT MODIFY)
@dataclass(frozen=True)
class AnomalyPattern:
    pattern_type: str      # PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, etc.
    fact_ids: FrozenSet[str]
    confidence: float
    description: str

@dataclass(frozen=True)
class BenignExplanation:
    explanation_type: str  # MAINTENANCE_WINDOW, KNOWN_ADMIN, etc.
    fact_ids: FrozenSet[str]
    confidence: float
    description: str

class VerdictOutcome(Enum):
    THREAT_CONFIRMED = "threat_confirmed"
    THREAT_DISMISSED = "threat_dismissed"
    INCONCLUSIVE = "inconclusive"

@dataclass(frozen=True)
class Verdict:
    outcome: VerdictOutcome
    confidence: float
    supporting_fact_ids: FrozenSet[str]
    architect_confidence: float
    skeptic_confidence: float
    reasoning: str

# From ares.dialectic.evidence.packet (DO NOT MODIFY)
class EvidencePacket:
    # Has .facts property returning tuple of Fact objects
    # Has .packet_id, .snapshot_id
    # Must be frozen before use

# From ares.dialectic.messages.assertions (DO NOT MODIFY)
class Assertion:
    assertion_type: AssertionType  # ASSERT, LINK, ALT
    fact_ids: FrozenSet[str]
    content: str
    confidence: float

# From ares.dialectic.messages.protocol (DO NOT MODIFY)
class DialecticalMessage:
    # Contains assertions, phase, confidence, etc.
```

---

## Execution Order

**CRITICAL: Follow this order exactly.**

### Step 1 — Review Before Writing

Read these files to understand the current implementation you will extract from:

1. `ares/dialectic/agents/architect.py` — Study `_detect_anomalies()` implementation. This is the rule-based logic that becomes `RuleBasedThreatAnalyzer`. Note the method signature, what it accesses on the packet, and what it returns.

2. `ares/dialectic/agents/skeptic.py` — Study `_find_benign_explanations()` implementation. This becomes `RuleBasedExplanationFinder`. Note it takes an `Assertion` AND the packet.

3. `ares/dialectic/agents/oracle.py` — Study `OracleNarrator._compose_impl()`. The template-based explanation logic becomes `RuleBasedNarrativeGenerator`. Note the locked verdict constraint.

4. `ares/dialectic/agents/patterns.py` — Study all frozen dataclasses. Your strategies must return these exact types.

5. `ares/dialectic/evidence/packet.py` — Study the EvidencePacket interface, especially `.facts` and how fact_ids work.

6. `ares/dialectic/agents/base.py` — Study AgentBase constructor to understand how to add optional strategy parameters without breaking the inheritance chain.

**Do NOT write any code until you have read all six files.**

---

### Step 2 — Create the Strategy Protocols

**File: `ares/dialectic/agents/strategies/protocol.py`**

Define three Protocol classes (using `typing.Protocol`):

```python
class ThreatAnalyzer(Protocol):
    """Strategy for detecting anomaly patterns in evidence."""
    def analyze_threats(self, packet: EvidencePacket) -> List[AnomalyPattern]: ...

class ExplanationFinder(Protocol):
    """Strategy for finding benign explanations for assertions."""
    def find_explanations(
        self, assertion: Assertion, packet: EvidencePacket
    ) -> List[BenignExplanation]: ...

class NarrativeGenerator(Protocol):
    """Strategy for generating verdict explanations."""
    def generate_narrative(
        self, verdict: Verdict, packet: EvidencePacket,
        architect_msg: DialecticalMessage, skeptic_msg: DialecticalMessage
    ) -> str: ...
```

Three separate protocols because each agent has a different input signature. Do NOT combine them into a single class.

---

### Step 3 — Extract Rule-Based Strategies

**File: `ares/dialectic/agents/strategies/rule_based.py`**

Extract the EXISTING logic from the agents into strategy classes. This is a **mechanical extraction** — the code inside these classes must produce identical behavior to the current inline methods.

```python
class RuleBasedThreatAnalyzer:
    """Extracted from ArchitectAgent._detect_anomalies(). Zero behavior change."""
    def analyze_threats(self, packet: EvidencePacket) -> List[AnomalyPattern]:
        # EXACT same logic currently in architect.py._detect_anomalies()

class RuleBasedExplanationFinder:
    """Extracted from SkepticAgent._find_benign_explanations(). Zero behavior change."""
    def find_explanations(self, assertion: Assertion, packet: EvidencePacket) -> List[BenignExplanation]:
        # EXACT same logic currently in skeptic.py._find_benign_explanations()

class RuleBasedNarrativeGenerator:
    """Extracted from OracleNarrator template logic. Zero behavior change."""
    def generate_narrative(self, verdict: Verdict, packet: EvidencePacket,
                          architect_msg: DialecticalMessage, skeptic_msg: DialecticalMessage) -> str:
        # EXACT same template logic currently in oracle.py
```

**CRITICAL**: After extraction, the original methods in architect.py, skeptic.py, and oracle.py must delegate to the strategy. Example:

```python
# architect.py (modified)
class ArchitectAgent(AgentBase):
    def __init__(self, agent_id: str, *,
                 threat_analyzer: Optional[ThreatAnalyzer] = None):
        super().__init__(agent_id=agent_id, role=AgentRole.ARCHITECT)
        self._threat_analyzer = threat_analyzer or RuleBasedThreatAnalyzer()
    
    def _detect_anomalies(self, packet: EvidencePacket) -> List[AnomalyPattern]:
        return self._threat_analyzer.analyze_threats(packet)
```

The default is ALWAYS `RuleBasedXxx()`. Constructing an agent with no arguments produces identical behavior to before. This is what makes all 926 tests pass unchanged.

**Watch the constructor signatures carefully.** Read the existing `__init__` methods before modifying. Do not break any existing parameters or their defaults. The strategy parameter must be keyword-only and optional.

---

### Step 4 — Build the Anthropic Client

**File: `ares/dialectic/agents/strategies/client.py`**

Thin wrapper around the Anthropic Messages API:

```python
import os
from dataclasses import dataclass

@dataclass(frozen=True)
class LLMResponse:
    """Raw response from the LLM."""
    content: str
    model: str
    usage_input_tokens: int
    usage_output_tokens: int

class AnthropicClient:
    """Thin wrapper around the Anthropic Messages API."""
    
    def __init__(self, *,
                 api_key: Optional[str] = None,
                 model: str = "claude-sonnet-4-20250514",
                 max_tokens: int = 4096):
        self._api_key = api_key or os.environ.get("ANTHROPIC_API_KEY")
        if not self._api_key:
            raise ValueError("ANTHROPIC_API_KEY required (pass directly or set env var)")
        self._model = model
        self._max_tokens = max_tokens
    
    def complete(self, *, system: str, user: str) -> LLMResponse:
        """Send a completion request. Returns raw text response."""
        # Use the anthropic Python SDK: pip install anthropic
        # import anthropic
        # client = anthropic.Anthropic(api_key=self._api_key)
        # message = client.messages.create(
        #     model=self._model,
        #     max_tokens=self._max_tokens,
        #     system=system,
        #     messages=[{"role": "user", "content": user}]
        # )
        # return LLMResponse(
        #     content=message.content[0].text,
        #     model=message.model,
        #     usage_input_tokens=message.usage.input_tokens,
        #     usage_output_tokens=message.usage.output_tokens,
        # )
        ...
```

**Important:** Implement this fully using the `anthropic` Python SDK. The comments above show the pattern. The client does NOT handle JSON parsing — it returns raw text. The strategy handles parsing.

**Do NOT add retry logic, caching, or rate limiting.** Keep it thin. Those are Session 010 concerns.

---

### Step 5 — Build the LLM Strategies

**File: `ares/dialectic/agents/strategies/llm_strategy.py`**

Three LLM strategy classes with output validation:

```python
class LLMThreatAnalyzer:
    """Uses Anthropic API to detect anomaly patterns. Falls back to rule-based on failure."""
    
    def __init__(self, client: AnthropicClient, *,
                 fallback: Optional[ThreatAnalyzer] = None):
        self._client = client
        self._fallback = fallback or RuleBasedThreatAnalyzer()
    
    def analyze_threats(self, packet: EvidencePacket) -> List[AnomalyPattern]:
        try:
            response = self._client.complete(
                system=ARCHITECT_SYSTEM_PROMPT,
                user=self._build_user_prompt(packet)
            )
            raw_patterns = self._parse_json_response(response.content)
            validated = self._validate_patterns(raw_patterns, packet)
            if validated:
                return validated
            # LLM returned nothing usable → fallback
            return self._fallback.analyze_threats(packet)
        except Exception:
            return self._fallback.analyze_threats(packet)
    
    def _build_user_prompt(self, packet: EvidencePacket) -> str:
        """Serialize packet facts into a structured prompt."""
        ...
    
    def _parse_json_response(self, content: str) -> List[dict]:
        """Parse LLM JSON output. Handles markdown code fences."""
        ...
    
    def _validate_patterns(self, raw: List[dict], packet: EvidencePacket) -> List[AnomalyPattern]:
        """Validate against packet. CLOSED WORLD: reject hallucinated fact_ids."""
        valid_fact_ids = {f.fact_id for f in packet.facts}
        validated = []
        for item in raw:
            cited = frozenset(item.get("fact_ids", []))
            if not cited or (cited - valid_fact_ids):
                continue  # Skip — references facts not in packet
            confidence = max(0.0, min(1.0, float(item.get("confidence", 0.0))))
            validated.append(AnomalyPattern(
                pattern_type=item.get("pattern_type", "UNKNOWN"),
                fact_ids=cited,
                confidence=confidence,
                description=item.get("description", ""),
            ))
        return validated
```

**Same pattern for `LLMExplanationFinder` and `LLMNarrativeGenerator`.** Each has:
- Constructor with client + fallback
- Main method with try/except → fallback
- Prompt builder that serializes evidence
- JSON parser that handles markdown fences
- Validator that enforces closed-world (fact_ids must exist in packet)

The `LLMNarrativeGenerator.generate_narrative()` returns a `str`, not a dataclass. Validation ensures the narrative references actual fact_ids from the packet (check via string matching or structured output).

---

### Step 6 — Build Prompt Templates

**File: `ares/dialectic/agents/strategies/prompts.py`**

System and user prompt templates. These are the instructions the LLM receives.

```python
ARCHITECT_SYSTEM_PROMPT = """You are a cybersecurity threat analyst examining security telemetry evidence.

Your task: Identify potential threat patterns in the provided evidence facts.

RULES:
- You may ONLY reference fact_ids that exist in the provided evidence
- Each pattern must cite specific fact_ids as supporting evidence
- Confidence must be between 0.0 and 1.0
- Pattern types include: PRIVILEGE_ESCALATION, LATERAL_MOVEMENT, SUSPICIOUS_PROCESS, SERVICE_ABUSE, CREDENTIAL_ACCESS

Respond with a JSON array of threat patterns:
[
    {
        "pattern_type": "PRIVILEGE_ESCALATION",
        "fact_ids": ["fact-001", "fact-002"],
        "confidence": 0.85,
        "description": "User escalated to admin privileges from non-admin session"
    }
]

Respond ONLY with the JSON array. No explanation, no markdown, no preamble."""

SKEPTIC_SYSTEM_PROMPT = """You are a cybersecurity analyst providing alternative benign explanations for observed anomalies.

Your task: For the given threat assertion, propose legitimate explanations.

RULES:
- You may ONLY reference fact_ids that exist in the provided evidence
- Each explanation must cite specific fact_ids
- Confidence must be between 0.0 and 1.0
- Explanation types include: MAINTENANCE_WINDOW, KNOWN_ADMIN, SCHEDULED_TASK, SOFTWARE_UPDATE, LEGITIMATE_REMOTE

Respond with a JSON array of benign explanations:
[
    {
        "explanation_type": "KNOWN_ADMIN",
        "fact_ids": ["fact-001"],
        "confidence": 0.7,
        "description": "Actor is a recognized domain administrator"
    }
]

Respond ONLY with the JSON array. No explanation, no markdown, no preamble."""

NARRATOR_SYSTEM_PROMPT = """You are a security analyst writing a clear explanation of a threat assessment verdict.

You will receive: the verdict outcome, the architect's threat hypothesis, the skeptic's counter-arguments, and the evidence.

RULES:
- You MUST reference specific fact_ids from the evidence in your explanation
- You CANNOT change or contradict the verdict — only explain it
- Write 2-4 sentences, clear and professional
- Reference the key evidence that supports the verdict

Respond with ONLY the explanation text. No JSON, no markdown."""
```

**These prompts will be refined in Session 010.** The goal here is functional templates, not optimized prompts.

---

### Step 7 — Create Package Structure

```
ares/dialectic/agents/strategies/
├── __init__.py          # Export all public types
├── protocol.py          # ThreatAnalyzer, ExplanationFinder, NarrativeGenerator
├── rule_based.py        # RuleBasedThreatAnalyzer, RuleBasedExplanationFinder, RuleBasedNarrativeGenerator
├── llm_strategy.py      # LLMThreatAnalyzer, LLMExplanationFinder, LLMNarrativeGenerator
├── client.py            # AnthropicClient, LLMResponse
└── prompts.py           # System prompt templates
```

The `__init__.py` should export:
- All three protocol types
- All three rule-based implementations
- All three LLM implementations
- `AnthropicClient`, `LLMResponse`

---

### Step 8 — Write Tests

**Test file structure:**
```
ares/dialectic/tests/agents/strategies/
├── __init__.py
├── conftest.py           # Shared fixtures
├── test_protocol.py      # Protocol compliance
├── test_rule_based.py    # Extraction correctness
├── test_llm_strategy.py  # Mocked LLM behavior
├── test_client.py        # Client construction and error handling
├── test_validation.py    # Output validation edge cases
├── test_fallback.py      # Fallback mechanisms
└── test_integration.py   # End-to-end with strategies
```

#### conftest.py Fixtures

```python
@pytest.fixture
def sample_packet():
    """Frozen EvidencePacket with known facts for testing."""
    # Build a packet with 3-5 facts, freeze it
    # Reuse the fixture patterns from test_architect.py / test_skeptic.py

@pytest.fixture
def valid_fact_ids(sample_packet):
    """Set of fact_ids that exist in the sample packet."""
    return {f.fact_id for f in sample_packet.facts}

@pytest.fixture
def mock_client():
    """AnthropicClient mock that returns configurable responses."""
    # Use unittest.mock or a simple class with settable response

@pytest.fixture
def mock_llm_response_valid():
    """Valid JSON response matching AnomalyPattern schema."""
    return LLMResponse(
        content='[{"pattern_type": "PRIVILEGE_ESCALATION", "fact_ids": ["fact-001", "fact-002"], "confidence": 0.85, "description": "test"}]',
        model="claude-sonnet-4-20250514",
        usage_input_tokens=100,
        usage_output_tokens=50,
    )
```

#### Test Categories (~80-100 tests total)

**test_protocol.py (~15 tests):**
- RuleBasedThreatAnalyzer satisfies ThreatAnalyzer protocol
- RuleBasedExplanationFinder satisfies ExplanationFinder protocol
- RuleBasedNarrativeGenerator satisfies NarrativeGenerator protocol
- LLMThreatAnalyzer satisfies ThreatAnalyzer protocol
- LLMExplanationFinder satisfies ExplanationFinder protocol
- LLMNarrativeGenerator satisfies NarrativeGenerator protocol
- ArchitectAgent accepts ThreatAnalyzer at construction
- SkepticAgent accepts ExplanationFinder at construction
- OracleNarrator accepts NarrativeGenerator at construction
- Agents default to rule-based when no strategy provided
- Agents reject non-protocol objects (type checking if applicable)
- Custom strategy implementing protocol works with agents

**test_rule_based.py (~20 tests):**
- RuleBasedThreatAnalyzer produces identical output to old _detect_anomalies() for:
  - Packet with privilege escalation evidence
  - Packet with lateral movement evidence
  - Packet with suspicious process evidence
  - Packet with no anomalies (empty result)
  - Packet with multiple anomaly types
- RuleBasedExplanationFinder produces identical output to old _find_benign_explanations() for:
  - Assertion with maintenance window match
  - Assertion with known admin match
  - Assertion with no benign explanation (empty result)
  - Multiple explanations for one assertion
- RuleBasedNarrativeGenerator produces identical output to old template logic for:
  - THREAT_CONFIRMED verdict
  - THREAT_DISMISSED verdict
  - INCONCLUSIVE verdict
- All returned objects are correct frozen dataclass types
- Confidence values match original calculations

**test_llm_strategy.py (~25 tests):**
- LLMThreatAnalyzer with valid JSON response → correct AnomalyPattern list
- LLMThreatAnalyzer with JSON in markdown code fences → parsed correctly
- LLMThreatAnalyzer with empty array response → falls back to rule-based
- LLMThreatAnalyzer with null/missing fields → handled gracefully
- LLMExplanationFinder with valid response → correct BenignExplanation list
- LLMExplanationFinder with empty response → falls back
- LLMNarrativeGenerator with valid response → string returned
- LLMNarrativeGenerator with empty response → falls back to template
- Prompt builder serializes packet facts correctly
- Prompt builder includes fact_ids in user prompt
- Prompt builder handles empty packet gracefully
- System prompts are non-empty strings
- Response parsing handles extra whitespace
- Response parsing handles BOM characters

**test_client.py (~10 tests):**
- AnthropicClient requires API key (constructor raises ValueError without it)
- AnthropicClient accepts API key via parameter
- AnthropicClient reads API key from environment variable
- AnthropicClient parameter overrides environment variable
- LLMResponse is frozen dataclass
- LLMResponse stores all fields correctly
- Default model is claude-sonnet-4-20250514
- Default max_tokens is 4096
- Custom model and max_tokens accepted

**test_validation.py (~20 tests):**
- Valid fact_ids → pattern accepted
- fact_ids not in packet → pattern REJECTED (closed world)
- Mixed valid/invalid fact_ids in one pattern → pattern REJECTED (entire pattern, not partial)
- All patterns have invalid fact_ids → empty list → fallback triggered
- Confidence > 1.0 → clamped to 1.0
- Confidence < 0.0 → clamped to 0.0
- Confidence is string "0.8" → parsed to float
- Confidence is missing → defaults to 0.0
- Pattern type is empty string → accepted as "UNKNOWN" or empty (don't crash)
- Pattern type is novel (not in known set) → accepted (LLM may discover new patterns)
- fact_ids is not a list → pattern rejected
- fact_ids contains non-string → pattern rejected
- Duplicate fact_ids → deduplicated via frozenset
- Description is missing → defaults to empty string
- Entire response is not valid JSON → fallback
- Response is JSON object instead of array → fallback
- Response is JSON array of non-objects → individual items skipped
- BenignExplanation validation mirrors AnomalyPattern validation
- Narrative validation: empty string → fallback
- Narrative validation: very long response → accepted (no length limit)

**test_fallback.py (~10 tests):**
- API error (any Exception from client.complete) → rule-based result returned
- JSON parse error → rule-based result returned
- Validation rejects all patterns → rule-based result returned
- Fallback returns non-empty result for packet with anomalies
- Custom fallback strategy used when provided
- Default fallback is RuleBasedXxx when none provided
- Fallback does not re-raise exceptions
- Multiple consecutive fallbacks work (no state corruption)

**test_integration.py (~10 tests):**
- ArchitectAgent with RuleBasedThreatAnalyzer → same behavior as Session 004
- ArchitectAgent with mock LLM strategy → uses LLM result
- SkepticAgent with RuleBasedExplanationFinder → same behavior as Session 004
- SkepticAgent with mock LLM strategy → uses LLM result  
- OracleNarrator with RuleBasedNarrativeGenerator → same behavior as Session 004
- Full single-turn cycle with rule-based strategies → identical to current
- Full single-turn cycle with mock LLM strategies → produces valid CycleResult
- run_multi_turn_cycle still works (agents created internally use defaults)
- DialecticalOrchestrator still works unchanged
- Memory Stream stores results from strategy-powered cycles

---

### Step 9 — Run All Tests

```powershell
# Run ALL tests (must see 926 + new tests, ZERO failures)
pytest ares/ -v

# Run only new strategy tests
pytest ares/dialectic/tests/agents/strategies/ -v

# Run with coverage
pytest ares/ --cov=ares --cov-report=term-missing
```

**All 926 existing tests MUST pass unchanged.** If any existing test fails, STOP and fix the agent modification — do not modify the test.

---

### Step 10 — Git

```powershell
git checkout -b session/009-llm-infrastructure
# ... commits during work ...
# After all tests pass:
git add -A
git commit -m "Session 009: LLM Infrastructure Layer - XX new tests (XXX total)"
```

---

## Architecture Decision Record

### Why Three Protocols Instead of One

The Architect takes `(packet) → List[AnomalyPattern]`. The Skeptic takes `(assertion, packet) → List[BenignExplanation]`. The Narrator takes `(verdict, packet, arch_msg, skep_msg) → str`. A single `ReasoningStrategy` with all three methods would force the Architect to carry Skeptic methods it never uses, and would prevent independent substitution.

### Why Extract Before Inject

We could skip extraction and just build the LLM strategies. But extracting first proves that the extraction is lossless — the 926 existing tests serve as a regression suite for the extraction. If those tests pass with the delegation pattern, we know the seam is clean.

### Why Fallback Always Available

In production, LLM failures are inevitable (rate limits, outages, bad responses). The rule-based fallback means the system degrades gracefully from AI-powered to deterministic — it never stops working entirely. This is the "immune system" principle: the body doesn't shut down when one defense mechanism fails.

### Why OracleJudge Stays Untouched

The Judge is the architectural firewall between reasoning (subjective, non-deterministic, can hallucinate) and verdict (objective, deterministic, auditable). If the Judge used an LLM, verdict reproducibility would be destroyed. Every audit trail entry in Memory Stream depends on verdicts being the same given the same inputs.

---

## Dependencies

This session requires `anthropic` Python SDK:
```powershell
pip install anthropic
```

Add to requirements if one exists. The SDK is only imported inside `client.py` — all other code depends on the strategy protocols, not the SDK directly.

---

## Summary of Changes

| File | Action | Description |
|------|--------|-------------|
| `agents/strategies/__init__.py` | CREATE | Package exports |
| `agents/strategies/protocol.py` | CREATE | Three Protocol definitions |
| `agents/strategies/rule_based.py` | CREATE | Extracted rule-based logic |
| `agents/strategies/llm_strategy.py` | CREATE | LLM wrappers with validation |
| `agents/strategies/client.py` | CREATE | AnthropicClient + LLMResponse |
| `agents/strategies/prompts.py` | CREATE | System prompt templates |
| `agents/architect.py` | MODIFY | Add optional strategy parameter, delegate |
| `agents/skeptic.py` | MODIFY | Add optional strategy parameter, delegate |
| `agents/oracle.py` | MODIFY | Add optional strategy to OracleNarrator |
| `tests/agents/strategies/*` | CREATE | ~80-100 new tests |

**Estimated test count: 80-100 new tests → ~1010-1030 total**

---

## Established Patterns (Follow These)

- `raise ... from ...` for exception chaining
- `@dataclass(frozen=True)` for all output types
- `Protocol` from typing for structural subtyping
- `Optional[X] = None` with default factory for optional dependencies
- Tests use pytest, fixtures in conftest.py
- Each test file focuses on one concern
- Zero tolerance for test regressions
