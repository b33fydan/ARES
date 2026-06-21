"""First-class named-IOC detector.

The read-depth OOV experiments (S089/S090, audited ROBUST) showed named-IOC
matching resists meaning-preserving evasion in both arms while structural and
synonym matching do not -- "you cannot disguise lsass/procdump away and still
mean it." This rung promotes that lexicon into an explicit, coverage-audited
registry, extensible by adding (name, pattern) entries.
"""
import re
from dataclasses import dataclass

IOC_PATTERNS = (
    (
        "credential_access",
        re.compile(
            r"(?:mimikatz|procdump|sekurlsa|lsass\.dmp|-ma\s+lsass|ntds\.dit"
            r"|hashdump|samdump|pwdump|comsvcs\.dll)",
            re.IGNORECASE,
        ),
    ),
)


@dataclass(frozen=True)
class IOCMatch:
    ioc_name: str
    matched_text: str


def scan_iocs(text: str) -> tuple[IOCMatch, ...]:
    matches = []
    for name, pattern in IOC_PATTERNS:
        for m in pattern.finditer(text):
            matches.append(IOCMatch(ioc_name=name, matched_text=m.group(0)))
    return tuple(matches)
