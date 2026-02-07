# ARES Development Project

## Context
Building ARES (Adversarial Reasoning Engine System) - a dialectical AI framework 
for cybersecurity defense using graph neural networks and multi-agent reasoning.

## Current Status
- Phase 0: Architecture Crystallization ✅
- Graph schema: COMPLETE (110 tests passing)
- Session 004: Agent foundations COMPLETE
- Next: Session 005 - Evidence Extractors (telemetry parsing)

## Tech Stack
- Python 3.11, PyTorch, PyTorch Geometric
- NetworkX (Phase 0/1), Neo4j (Phase 2+)
- Redis for Memory Stream
- Windows + PowerShell + venv

## Code Location
C:\ares-phase-zero

## Architecture Principles
1. **Closed-world assumption** - Only frozen EvidencePackets as truth
2. **Hallucinations = Schema violations** - Not mysterious AI behavior
3. **Deterministic first, neural later** - Rule-based agents before LLM injection
4. **Autoimmune metaphor** - Self/non-self discrimination guides design
5. **Five invariants as bedrock** - Schema violations, not runtime checks

## Key Files
- `ares_core/graph/schema.py` - Graph structure (evidence/claim/agent nodes)
- `ares_core/dialectic/protocol.py` - Message schemas for agent debate
- `ares_core/agents/` - Architect/Skeptic/Oracle implementations
- `tests/` - 110+ passing tests validating architecture
- Session logs in project root - Full development history

## Session Workflow
1. Start new chat in Claude.ai ARES project
2. Reference previous session number
3. State today's goal
4. Ask clarifying questions before coding
5. Document decisions in session logs

## Development Commands
```powershell
# Activate venv
.\venv\Scripts\Activate.ps1

# Run tests
pytest tests/ -v

# Run specific test file
pytest tests/graph/test_schema.py -v
```

## MCP/Skills Integration (Phase 2+)
- Filesystem MCP: Access session logs, threat intel
- PostgreSQL MCP: Live Coreframe telemetry queries
- Skills: Codify dialectical workflows, adversarial testing
- n8n: ClawdBot orchestration (future)

## Dan's Preferences
- Direct, technical communication
- Seek disconfirmation, honest feedback
- Document everything in session logs
- Test rigorously before moving forward
- Military-style acknowledgments (WILCO, SOLID, etc.)