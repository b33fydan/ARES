# SESSION 029: ARES Visual Emitter + nw_wrld Evidence Graph Module
## Claude Code Execution Prompt

## Context

ARES Phase 4 begins. 24 sessions of core architecture are complete. 1,881 tests, zero regressions. The debate hypothesis is closed with a definitive negative finding. Single-turn at 81.8% is the production path.

Now we make it visible.

nw_wrld (https://github.com/aagentah/nw_wrld) is an event-driven visual sequencer built on Electron + Three.js + p5.js + d3. It accepts external signals via HTTP/WebSocket and routes them to visual modules that render in a projector window. Users write JavaScript modules that define how visuals respond to incoming data.

Session 029 goal: Build a Python WebSocket server that replays an ARES scenario verdict as a stream of typed JSON events, and create the nw_wrld JavaScript module that receives those events and renders the evidence-reasoning chain as a live 3D graph. This is proof-of-concept — functional, not polished.

**Project location:** C:\ares-phase-zero
**Run tests:** python -m pytest ares/ -v
**Git branch:** session/029-visual-emitter

---

## CRITICAL CONSTRAINTS

1. **DO NOT MODIFY ANY EXISTING FILES.** All 1,881 existing tests must pass unchanged.
2. **All new Python dataclasses must be frozen.** `@dataclass(frozen=True)` everywhere.
3. **Type hints on everything. Docstrings on all public methods.**
4. **New files only.** Zero modifications to existing code.
5. **The WebSocket emitter is a NEW subsystem.** It lives under `ares/visual/` — a new top-level package within ares.
6. **The nw_wrld modules are standalone JavaScript files.** They go in `ares/visual/nw_wrld_modules/` as reference copies that Dan will symlink or copy into his nw_wrld project folder.

---

## Architecture Overview

```
ARES (Python)                          nw_wrld (Electron/JS)
┌─────────────────────┐                ┌─────────────────────────┐
│                     │   WebSocket    │                         │
│  ScenarioReplayer   │──────────────→ │  Remote API Input       │
│  (runs scenario,    │   JSON events  │  (receives signals)     │
│   emits events)     │                │         │               │
│                     │                │         ▼               │
│  VisualEmitter      │                │  EvidenceGraph module   │
│  (WebSocket server) │                │  (Three.js 3D render)   │
│                     │                │                         │
└─────────────────────┘                └─────────────────────────┘
```

The Python side runs a scenario through the existing single-turn pipeline, captures the full reasoning chain, and replays it as timed WebSocket events. The nw_wrld side receives those events and renders them.

---

## Files to Create

### Python Files (ARES codebase)

#### File 1: `ares/visual/__init__.py`
Empty init file. Establishes the `ares.visual` package.

#### File 2: `ares/visual/events.py`
The event schema — frozen dataclasses defining every event type the emitter can produce.

**Event types (all frozen dataclasses, all must serialize to JSON via a `to_dict()` method):**

```python
@dataclass(frozen=True)
class VisualEvent:
    """Base fields shared by all visual events."""
    event_type: str           # Discriminator field
    timestamp_ms: int         # Milliseconds since scenario start
    scenario_id: str          # Which scenario this belongs to

@dataclass(frozen=True)
class ScenarioStartEvent:
    """Emitted when a scenario begins processing."""
    event_type: str = "scenario_start"
    timestamp_ms: int
    scenario_id: str
    scenario_name: str
    expected_verdict: str     # "THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"
    fact_count: int           # Total facts in the evidence packet
    source_types: tuple[str, ...]  # Distinct source types present

@dataclass(frozen=True)
class FactIngestedEvent:
    """Emitted for each fact in the evidence packet."""
    event_type: str = "fact_ingested"
    timestamp_ms: int
    scenario_id: str
    fact_id: str
    entity_type: str          # From Fact.entity_type
    entity_id: str            # From Fact.entity_id
    source_type: str          # From provenance.source_type
    field_name: str           # The fact's primary field identifier
    # Position hints for the graph layout
    source_index: int         # Which source (0, 1, 2...) — for spatial grouping
    fact_index: int           # Order within the scenario — for temporal spacing

@dataclass(frozen=True)
class AssertionFormedEvent:
    """Emitted for each assertion the Architect produces."""
    event_type: str = "assertion_formed"
    timestamp_ms: int
    scenario_id: str
    assertion_id: str         # Generated unique ID
    assertion_type: str       # From AssertionType
    content: str              # The assertion text (interpretation field)
    cited_fact_ids: tuple[str, ...]  # Which facts this assertion references
    confidence: float         # Per-assertion confidence

@dataclass(frozen=True)
class VerdictRenderedEvent:
    """Emitted when the final verdict is produced."""
    event_type: str = "verdict_rendered"
    timestamp_ms: int
    scenario_id: str
    outcome: str              # "THREAT_CONFIRMED", "THREAT_DISMISSED", "INCONCLUSIVE"
    confidence: float
    correct: bool             # Whether it matches expected_verdict

@dataclass(frozen=True)
class MiscalibrationCheckEvent:
    """Emitted after the MiscalibrationDetector runs."""
    event_type: str = "miscalibration_check"
    timestamp_ms: int
    scenario_id: str
    flagged: bool
    patterns_triggered: tuple[str, ...]  # Pattern names
    risk_score: float
    recommendation: str       # "PASS" or "INSPECT"

@dataclass(frozen=True)
class ClaimAuditEvent:
    """Emitted after the ClaimAuditor runs (only if miscalibration flagged)."""
    event_type: str = "claim_audit"
    timestamp_ms: int
    scenario_id: str
    claims_total: int
    claims_supported: int
    claims_weak: int
    claims_unsupported: int
    audit_verdict: str        # "CONFIRMED" or "MISCALIBRATED"

@dataclass(frozen=True)
class ScenarioEndEvent:
    """Emitted when scenario processing is complete."""
    event_type: str = "scenario_end"
    timestamp_ms: int
    scenario_id: str
    duration_ms: int
```

Each event class must have a `to_dict()` method that returns a plain dict (JSON-serializable). Use a factory function `event_from_dict(d: dict) -> VisualEvent` for deserialization.

#### File 3: `ares/visual/replayer.py`
The ScenarioReplayer — takes an ARES scenario, runs it through the existing single-turn pipeline (rule-based, no LLM calls), and produces a sequence of VisualEvents.

**Class: ScenarioReplayer**

```python
class ScenarioReplayer:
    """
    Replays an ARES scenario as a sequence of timed visual events.
    
    Uses rule-based strategies only (no LLM calls).
    Processes a scenario through the existing pipeline:
    EvidencePacket → Orchestrator → Verdict → MiscalibrationDetector → ClaimAuditor
    
    Outputs a tuple of VisualEvents with synthetic timestamps
    that space out the events for visual effect.
    """
    
    def __init__(
        self,
        fact_delay_ms: int = 200,       # Delay between fact ingestion events
        assertion_delay_ms: int = 500,  # Delay between assertion events
        verdict_delay_ms: int = 1000,   # Delay before verdict
        check_delay_ms: int = 500,      # Delay before miscalibration check
    ): ...
    
    def replay(self, scenario) -> tuple[VisualEvent, ...]:
        """
        Process a scenario and return the full event sequence.
        
        Args:
            scenario: A scenario object from scenarios.py or expanded_scenarios.py
                      (must have .scenario_id, .name, .packet, .expected_verdict)
        
        Returns:
            Tuple of VisualEvents in chronological order with synthetic timestamps.
        """
```

**Replay logic:**
1. Emit `ScenarioStartEvent`
2. For each fact in `scenario.packet.facts`: emit `FactIngestedEvent` (spaced by `fact_delay_ms`)
3. Run the Orchestrator (rule-based) to get a CycleResult
4. For each assertion in the Architect's message: emit `AssertionFormedEvent` (spaced by `assertion_delay_ms`)
5. Emit `VerdictRenderedEvent` with the verdict
6. Run `MiscalibrationDetector.detect()` on the verdict
7. Emit `MiscalibrationCheckEvent`
8. If flagged: run `ClaimAuditor.audit()` and emit `ClaimAuditEvent`
9. Emit `ScenarioEndEvent`

**IMPORTANT:** Read the existing scenario objects to understand their exact structure. They come from `scenarios.py` and `expanded_scenarios.py`. Check what attributes they expose — `.scenario_id`, `.name`, `.packet`, `.expected_verdict` may not be the exact field names. Adapt accordingly.

#### File 4: `ares/visual/emitter.py`
The WebSocket server that streams events to connected clients.

**Class: VisualEmitter**

```python
class VisualEmitter:
    """
    WebSocket server that streams ARES visual events.
    
    Usage:
        emitter = VisualEmitter(host="localhost", port=8765)
        events = replayer.replay(scenario)
        await emitter.start()           # Start server
        await emitter.stream(events)    # Stream events with timing
        await emitter.stop()            # Shutdown
    """
    
    def __init__(self, host: str = "localhost", port: int = 8765): ...
    
    async def start(self) -> None:
        """Start the WebSocket server."""
    
    async def stream(self, events: tuple, realtime: bool = True) -> None:
        """
        Stream events to all connected clients.
        
        If realtime=True, sleeps between events based on timestamp_ms deltas.
        If realtime=False, sends all events immediately.
        """
    
    async def stop(self) -> None:
        """Shutdown the server."""
```

Use the `websockets` library (pip install websockets). Keep it simple — no authentication, no reconnection logic, no fancy protocol. This is proof-of-concept.

#### File 5: `ares/visual/scripts/run_visual.py`
CLI runner that starts the emitter and replays a scenario.

```powershell
# Replay a specific scenario
python -m ares.visual.scripts.run_visual --scenario SC-001

# Replay all scenarios in sequence
python -m ares.visual.scripts.run_visual --all

# Replay with faster timing
python -m ares.visual.scripts.run_visual --scenario SC-019 --speed 2.0

# List available scenarios
python -m ares.visual.scripts.run_visual --list
```

#### File 6: `ares/visual/tests/test_events.py`
Tests for event schema. **Target: 20+ tests.**

Test categories:
- Each event type constructs correctly
- `to_dict()` produces valid JSON-serializable dicts
- `event_from_dict()` round-trips correctly
- All events are frozen (immutability)
- Required fields are validated
- Timestamp ordering is preserved in sequences

#### File 7: `ares/visual/tests/test_replayer.py`
Tests for ScenarioReplayer. **Target: 20+ tests.**

Test categories:
- Replay produces correct event sequence (start → facts → assertions → verdict → checks → end)
- Event count matches scenario content (N facts → N FactIngestedEvents)
- Timestamps are monotonically increasing
- Timing delays are respected
- Integration with actual scenarios from the corpus
- Edge cases: empty packet, scenario with no assertions
- Miscalibration check events are produced
- ClaimAudit events only appear when miscalibration is flagged

---

### nw_wrld Module Files (JavaScript)

These go in `ares/visual/nw_wrld_modules/`. They are standalone JavaScript files that follow nw_wrld's module format. Dan will copy or symlink them into his nw_wrld project's `modules/` folder.

#### File 8: `ares/visual/nw_wrld_modules/AresEvidenceGraph.js`

A Three.js-based nw_wrld module that renders the ARES evidence-reasoning chain as a 3D graph.

**Module structure (follow nw_wrld module conventions):**

```javascript
/**
 * @nwWrld name AresEvidenceGraph
 * @nwWrld category Data Visualization
 * @nwWrld imports three
 */

export default AresEvidenceGraph;

function AresEvidenceGraph({ THREE, ctx, canvas }) {
    // State
    let scene, camera, renderer;
    let factNodes = new Map();     // fact_id → Three.js mesh
    let assertionNodes = new Map(); // assertion_id → Three.js mesh
    let edges = [];                // Three.js Line objects connecting assertions to facts
    let verdictMesh = null;        // Central verdict indicator
    
    // Colors
    const SOURCE_COLORS = {
        windows_event_log: 0x4A90D9,  // Blue
        syslog: 0x50C878,             // Green
        netflow: 0xFF8C00,            // Orange
        unknown: 0x888888             // Gray
    };
    
    const SUPPORT_COLORS = {
        supported: 0x00FF88,    // Bright green — thick edge
        weak: 0xFFAA00,         // Amber — thin edge
        unsupported: 0xFF0044   // Red — no edge, node floats
    };
    
    return {
        construct({ width, height }) {
            // Initialize Three.js scene
            // Dark background (near black: 0x0A0A0F)
            // Camera positioned to see the full graph
            // Ambient light + point light for depth
        },
        
        // Method: receive a fact_ingested event
        // Creates a sphere at a position determined by source_index and fact_index
        // Color mapped by source_type
        // Sphere appears with a scale-up animation
        addFact({ fact_id, entity_type, source_type, source_index, fact_index }) {
            // Position: spread facts in 3D space
            // X: based on source_index (group by source type)
            // Y: based on entity_type hash (cluster similar entities)  
            // Z: based on fact_index (temporal ordering)
            // Add small random jitter for organic feel
            
            // Geometry: small sphere (radius 0.3)
            // Material: MeshStandardMaterial with emissive glow matching source color
            // Store in factNodes map
        },
        
        // Method: receive an assertion_formed event
        // Creates a larger sphere for the assertion
        // Draws edges (Three.js Line) from assertion to each cited fact
        // Edge thickness/opacity reflects how many facts are cited
        addAssertion({ assertion_id, cited_fact_ids, confidence }) {
            // Position: calculated as centroid of cited fact positions + offset
            // Geometry: icosahedron (to visually distinguish from fact spheres)
            // Material: emissive intensity scaled by confidence
            // Size: scaled by confidence (0.3 to 0.8)
            
            // Edges: for each cited_fact_id, draw a line to the fact node
            // Line material: opacity = confidence, color = white/cyan
            // If zero cited facts: assertion floats with no edges (visually isolated)
        },
        
        // Method: receive a verdict_rendered event
        // Creates a central glowing object representing the verdict
        // Color: green (confirmed), blue (dismissed), amber (inconclusive)
        // Intensity: mapped to confidence
        showVerdict({ outcome, confidence, correct }) {
            // Position: center of the graph
            // Geometry: large torus or ring (distinctive shape)
            // Color: by outcome
            // If correct: steady glow. If wrong: pulsing red overlay
            // Point light at center, intensity = confidence
        },
        
        // Method: receive a miscalibration_check event
        // If flagged: visual disruption — screen flash, edge color shift
        showMiscalibration({ flagged, patterns_triggered, risk_score }) {
            // If not flagged: subtle green border flash, then return
            // If flagged:
            //   - Brief screen shake (camera position oscillation)
            //   - All edges flash red proportional to risk_score
            //   - Pattern-specific effects:
            //     EVIDENCE_STARVATION: unconnected nodes pulse brighter
            //     EVIDENCE_CONFLICT: conflicting nodes draw red line between them
            //     NARROW_SPREAD: all edges briefly uniform color (showing groupthink)
        },
        
        // Method: reset the scene for a new scenario
        reset() {
            // Remove all meshes, edges, lights
            // Clear maps
            // Reset camera position
        },
        
        // Called every frame
        render() {
            // Gentle scene rotation (orbiting camera)
            // Pulse emissive materials on fact nodes
            // Animate any pending transitions
            renderer.render(scene, camera);
        },
        
        resize({ width, height }) {
            // Update camera aspect ratio and renderer size
        },
        
        destroy() {
            // Dispose geometries, materials, renderer
        }
    };
}
```

**IMPORTANT NOTES ON nw_wrld MODULE FORMAT:**
- The docblock metadata (`@nwWrld`) is required
- The function receives `{ THREE, ctx, canvas }` as injected dependencies
- It returns an object with lifecycle methods: `construct`, `render`, `resize`, `destroy`
- Custom methods (addFact, addAssertion, etc.) are triggered by nw_wrld's signal routing
- The module must be a default export
- Read the nw_wrld starter modules for reference on exact patterns — the 16 starter modules in any nw_wrld project show the conventions

#### File 9: `ares/visual/nw_wrld_modules/AresConfidenceHeat.js`

A companion module that renders a particle system representing overall confidence state.

```javascript
/**
 * @nwWrld name AresConfidenceHeat
 * @nwWrld category Data Visualization
 * @nwWrld imports three
 */
```

This module is simpler:
- A particle system (Three.js Points) that fills the background
- Particle count, speed, and brightness scale with the current confidence level
- Low confidence: few particles, dim, slow drift
- High confidence: dense particles, bright, active movement
- When a miscalibration event fires with `flagged=true`: particles briefly turn red and scatter
- When verdict is rendered: particles converge toward the center, color shifts to verdict color
- Ambient layer — runs behind the evidence graph

#### File 10: `ares/visual/nw_wrld_modules/README.md`

Setup instructions for connecting the modules to nw_wrld:

```markdown
# ARES Visual Modules for nw_wrld

## Setup

1. Clone nw_wrld: `git clone https://github.com/aagentah/nw_wrld.git`
2. Install: `cd nw_wrld && npm install`
3. Start: `npm start`
4. Select or create a project folder when prompted
5. Copy these module files into your nw_wrld project's `modules/` folder:
   - `AresEvidenceGraph.js`
   - `AresConfidenceHeat.js`
6. nw_wrld will hot-reload the modules automatically

## Running the ARES Emitter

1. In a separate terminal, activate the ARES venv
2. Run: `python -m ares.visual.scripts.run_visual --scenario SC-019 --speed 0.5`
3. The emitter starts a WebSocket server on ws://localhost:8765
4. In nw_wrld, configure Remote API input to connect to ws://localhost:8765

## Signal Routing in nw_wrld

Map incoming WebSocket events to module methods:
- `fact_ingested` → AresEvidenceGraph.addFact
- `assertion_formed` → AresEvidenceGraph.addAssertion
- `verdict_rendered` → AresEvidenceGraph.showVerdict + AresConfidenceHeat.showVerdict
- `miscalibration_check` → AresEvidenceGraph.showMiscalibration + AresConfidenceHeat.showMiscalibration
- `scenario_start` → AresEvidenceGraph.reset + AresConfidenceHeat.reset
```

---

## Execution Order

1. **Install websockets:** `pip install websockets --break-system-packages` (or in venv)
2. **Read existing files:** `scenarios.py`, `expanded_scenarios.py` (scenario structure), `orchestrator.py` (how to run a cycle), `patterns.py` (Verdict), `protocol.py` (DialecticalMessage), `miscalibration.py` (MiscalibrationDetector), `claim_audit.py` (ClaimAuditor), `assertions.py` (Assertion types), `fact.py` (Fact), `provenance.py` (Provenance/SourceType).
3. **Create** `ares/visual/__init__.py`
4. **Create** `ares/visual/events.py` with all event dataclasses
5. **Create** `ares/visual/tests/test_events.py`. Run tests. Fix until all pass.
6. **Create** `ares/visual/replayer.py` with ScenarioReplayer
7. **Create** `ares/visual/tests/test_replayer.py`. Run tests. Fix until all pass.
8. **Create** `ares/visual/emitter.py` with VisualEmitter
9. **Create** `ares/visual/scripts/run_visual.py` CLI runner
10. **Create** the nw_wrld module files in `ares/visual/nw_wrld_modules/`
11. **Run full test suite:** `python -m pytest ares/ -v`. Confirm zero regressions.
12. **Smoke test the emitter:** Run `python -m ares.visual.scripts.run_visual --scenario SC-001` and verify WebSocket events are emitted (use a simple WebSocket client or just check console output).
13. **Report:** Total new tests, cumulative test count, emitter output sample for one scenario.

---

## Key Interfaces to Use (Do Not Reinvent)

- **From `scenarios.py` + `expanded_scenarios.py`:** Scenario definitions. READ THESE FIRST to understand the exact structure — field names, how to access the packet, how to get expected_verdict.
- **From `orchestrator.py`:** `DialecticalOrchestrator.run_cycle(packet)` — runs the full THESIS → ANTITHESIS → SYNTHESIS cycle with rule-based agents. Returns `CycleResult`.
- **From `patterns.py`:** `Verdict`, `VerdictOutcome` for verdict data.
- **From `protocol.py`:** `DialecticalMessage` for accessing assertions from the Architect's message.
- **From `miscalibration.py`:** `MiscalibrationDetector` for running the miscalibration check.
- **From `claim_audit.py`:** `ClaimAuditor` for per-claim audit (only when miscalibration flags).
- **From `fact.py`:** `Fact` for fact_id, entity_type, entity_id.
- **From `provenance.py`:** `Provenance`, `SourceType` for source classification.

**IMPORTANT:** The scenario objects from `scenarios.py` and `expanded_scenarios.py` may have different structures than you expect. READ THEM FIRST. Don't assume field names — verify.

---

## What Success Looks Like

When you're done:
1. `python -m pytest ares/ -v` shows **1,920+ tests passing with 0 failures**
2. `python -m ares.visual.scripts.run_visual --scenario SC-019` starts a WebSocket server and emits a stream of JSON events
3. The events follow the correct sequence: start → facts → assertions → verdict → miscalibration → [claim audit] → end
4. The nw_wrld modules exist and follow the correct module format
5. The README explains how to wire everything together

This session produces a working proof-of-concept. The visual output will be basic — but functional, data-driven, and real. Session 030 will add the AKIRA aesthetic layer.

---

**End of Session 029 execution prompt.**
