"""ARES Dialectical Agents Module.

This module contains the agent implementations for the dialectical reasoning engine:

- AgentBase: Abstract base class with packet binding, evidence tracking, self-validation
- TurnContext: Immutable context container for agent turns
- DataRequest: Structured data request mechanism

Concrete Agent Implementations:
- ArchitectAgent: Observes evidence, proposes threat hypotheses (THESIS)
- SkepticAgent: Challenges claims, proposes alternatives (ANTITHESIS)
- OracleJudge: Deterministic verdict computation (not an agent - pure function)
- OracleNarrator: Constrained explanation generation (SYNTHESIS)

Pattern Dataclasses:
- AnomalyPattern: Detected threat patterns
- BenignExplanation: Alternative explanations for activity
- Verdict: Immutable judgment result
- VerdictOutcome: Possible verdict outcomes

The key invariant enforced by this module:
    NO AGENT CAN PRODUCE OUTPUT WITHOUT PROVING IT'S GROUNDED IN THE
    CURRENT EVIDENCEPACKET. HALLUCINATIONS BECOME SCHEMA VIOLATIONS.
"""

from ares.dialectic.agents.context import (
    # Enums
    AgentRole,
    RequestKind,
    RequestPriority,
    # Constants
    PHASE_ROLE_MAP,
    # Dataclasses
    DataRequest,
    TurnContext,
    TurnResult,
    # Type aliases
    DataRequests,
)

from ares.dialectic.agents.base import (
    # Enums
    AgentState,
    # Dataclasses
    AgentHealth,
    SelfValidationResult,
    WorkingMemoryEntry,
    # Exceptions
    AgentNotReadyError,
    PacketMismatchError,
    PhaseViolationError,
    SnapshotMismatchError,
    # Base class
    AgentBase,
)

from ares.dialectic.agents.patterns import (
    # Enums
    PatternType,
    ExplanationType,
    VerdictOutcome,
    # Dataclasses
    AnomalyPattern,
    BenignExplanation,
    Verdict,
)

from ares.dialectic.agents.architect import ArchitectAgent
from ares.dialectic.agents.skeptic import SkepticAgent
from ares.dialectic.agents.oracle import (
    OracleJudge,
    OracleNarrator,
    create_oracle_verdict,
)

# Re-export Phase from messages for convenience
from ares.dialectic.messages.protocol import Phase


__all__ = [
    # Enums
    "AgentRole",
    "AgentState",
    "Phase",
    "RequestKind",
    "RequestPriority",
    "PatternType",
    "ExplanationType",
    "VerdictOutcome",
    # Constants
    "PHASE_ROLE_MAP",
    # Dataclasses
    "AgentHealth",
    "DataRequest",
    "SelfValidationResult",
    "TurnContext",
    "TurnResult",
    "WorkingMemoryEntry",
    "AnomalyPattern",
    "BenignExplanation",
    "Verdict",
    # Exceptions
    "AgentNotReadyError",
    "PacketMismatchError",
    "PhaseViolationError",
    "SnapshotMismatchError",
    # Base class
    "AgentBase",
    # Type aliases
    "DataRequests",
    # Concrete agents
    "ArchitectAgent",
    "SkepticAgent",
    "OracleJudge",
    "OracleNarrator",
    # Convenience functions
    "create_oracle_verdict",
]
