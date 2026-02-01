# Messages Module
"""Dialectical message protocol for agent communication."""

from .assertions import Assertion, AssertionType
from .protocol import (
    DialecticalMessage,
    MessageBuilder,
    MessageType,
    Phase,
    Priority,
    ValidationResult,
)

__all__ = [
    "Assertion",
    "AssertionType",
    "DialecticalMessage",
    "MessageBuilder",
    "MessageType",
    "Phase",
    "Priority",
    "ValidationResult",
]
