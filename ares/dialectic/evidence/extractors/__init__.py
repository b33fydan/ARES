"""Evidence extractors for parsing raw telemetry into Facts.

Extractors transform raw telemetry (Windows Event Logs, syslog, netflow, etc.)
into typed Facts that can be loaded into EvidencePackets for dialectical reasoning.
"""

from .protocol import (
    ExtractionError,
    ExtractionStats,
    ExtractionResult,
    ExtractorProtocol,
)
from .windows import WindowsEventExtractor

__all__ = [
    "ExtractionError",
    "ExtractionStats",
    "ExtractionResult",
    "ExtractorProtocol",
    "WindowsEventExtractor",
]
