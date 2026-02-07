# Coordinator Module
"""Dialectical cycle coordination and message validation."""

from .validator import (
    MessageValidator,
    ValidationError,
    ErrorCode,
    ValidationResult,
)
from .cycle import (
    CycleState,
    TerminationReason,
    CycleConfig,
    DialecticalCycle,
    InvalidStateError,
)
from .coordinator import (
    Coordinator,
    SubmissionResult,
    CoordinatorError,
    DuplicateCycleError,
    CycleNotFoundError,
    MessageRejectedError,
)
from .orchestrator import (
    DialecticalOrchestrator,
    CycleResult,
    CycleError,
)
from .multi_turn import (
    DebateRound,
    MultiTurnConfig,
    MultiTurnCycleResult,
    run_multi_turn_cycle,
)

__all__ = [
    # Validator
    "MessageValidator",
    "ValidationError",
    "ErrorCode",
    "ValidationResult",
    # Cycle
    "CycleState",
    "TerminationReason",
    "CycleConfig",
    "DialecticalCycle",
    "InvalidStateError",
    # Coordinator
    "Coordinator",
    "SubmissionResult",
    "CoordinatorError",
    "DuplicateCycleError",
    "CycleNotFoundError",
    "MessageRejectedError",
    # Orchestrator
    "DialecticalOrchestrator",
    "CycleResult",
    "CycleError",
    # Multi-Turn
    "DebateRound",
    "MultiTurnConfig",
    "MultiTurnCycleResult",
    "run_multi_turn_cycle",
]
