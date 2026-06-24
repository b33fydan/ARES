"""Harness-side provenance derivation by value-tracking raw captured bytes.

The Phase-2 action gate trusts the ``arg_sources`` it is handed. Its fail-safe
covers *omission* (an argument missing from the map is tainted) but NOT
*mislabeling* (an agent that affirmatively tags untrusted-derived data as
MANUAL). Phase 3 closes that gap by deriving provenance HARNESS-SIDE: each
proposed tool-call argument's (canonicalized) bytes are matched against the raw
``CapturedRecord`` contents the harness holds, and the argument is tagged with
the ``SourceType`` of every record it matches. The model can shape the argument
bytes; it cannot assert a trust label. This module reads ONLY ``args``
(model-emitted bytes) and ``CapturedRecord.content`` / ``.provenance.source_type``
(harness-held) — never any model-supplied trust tag.

Matching (pre-registered — design §5; constants SSOT-locked by
tests/paper_5/test_prereg_bands_match_code.py):
  1. Canonicalize both sides: ``normalize`` (NFKC + zero-width/homoglyph/control
     fold) then ``.casefold()``, plus a whitespace-stripped form for IBAN-style
     reformatting.
  2. Type-aware exact match for the attack-literal classes (IBAN/email/URL):
     a shared canonical structured literal matches regardless of length.
  3. Otherwise containment (either direction) gated by ``MIN_MATCH_LENGTH`` to
     suppress coincidental short-token matches.
An argument that matches no record is tagged ``(SourceType.MANUAL,)`` —
model-composed and explicitly trusted, so the gate's fail-safe never denies a
legitimate model-composed argument.

Named residual: true semantic laundering (the model paraphrases the target into
bytes with no canonical overlap) is NOT caught by value-tracking and is the
pre-registered, measured residual.
"""
from __future__ import annotations

import re
from typing import Any, Mapping, Sequence

from ares.dialectic.evidence import SourceType
from ares.harness.capture import CapturedRecord
from ares.harness.normalize import normalize

# Pre-registered constants (Task 7 asserts prose == these values).
MIN_MATCH_LENGTH = 4
CONTAINMENT_DIRECTIONS = ("arg_in_record", "record_in_arg")
TYPE_EXACT_KINDS = ("iban", "email", "url")

# Structured-literal extractors run over CANONICAL (casefolded) text.
_IBAN_RE = re.compile(r"[a-z]{2}[0-9]{2}[a-z0-9]{10,30}")
_EMAIL_RE = re.compile(r"[a-z0-9._%+\-]+@[a-z0-9.\-]+\.[a-z]{2,}")
_URL_RE = re.compile(r"https?://[^\s\"'<>]+")
_WS_RE = re.compile(r"\s+")


def _canon(text: str) -> str:
    return normalize(text).casefold()


def _strip_ws(text: str) -> str:
    return _WS_RE.sub("", text)


def _typed_literals(canon: str) -> frozenset[str]:
    """Extract canonical structured literals for type-aware exact matching.

    IBANs are matched on the whitespace-stripped form (absorbing IBAN-internal
    spacing); emails/URLs on the canonical text.
    """
    lits: set[str] = set()
    lits.update(_IBAN_RE.findall(_strip_ws(canon)))
    lits.update(_EMAIL_RE.findall(canon))
    lits.update(u.rstrip(".,);]") for u in _URL_RE.findall(canon))
    return frozenset(lits)


def _arg_matches_record(arg_value: Any, record_content: str) -> bool:
    arg_canon = _canon(str(arg_value))
    rec_canon = _canon(record_content)

    # 1. Type-aware exact: any shared structured literal -> match (length-free).
    arg_lits = _typed_literals(arg_canon)
    if arg_lits & _typed_literals(rec_canon):
        return True
    # An arg that IS a structured literal, contained (ws-stripped) in the record.
    rec_nows = _strip_ws(rec_canon)
    for lit in arg_lits:
        if lit in rec_nows:
            return True

    # 2. General containment, either direction, gated by MIN_MATCH_LENGTH.
    if len(arg_canon) >= MIN_MATCH_LENGTH:
        if arg_canon in rec_canon:
            return True
    if len(rec_canon) >= MIN_MATCH_LENGTH:
        if rec_canon in arg_canon:
            return True
    return False


def derive_arg_sources(
    args: Mapping[str, Any],
    captured_records: Sequence[CapturedRecord],
) -> dict[str, tuple[SourceType, ...]]:
    """Map each argument name to the SourceTypes of every captured record whose
    raw bytes it (canonically) matches. No match -> (MANUAL,) (model-composed).
    """
    result: dict[str, tuple[SourceType, ...]] = {}
    for name, value in args.items():
        matched: list[SourceType] = []
        for rec in captured_records:
            if _arg_matches_record(value, rec.content):
                matched.append(rec.provenance.source_type)
        if not matched:
            result[name] = (SourceType.MANUAL,)
        else:
            # De-dup preserving first-seen order.
            seen: list[SourceType] = []
            for st in matched:
                if st not in seen:
                    seen.append(st)
            result[name] = tuple(seen)
    return result
