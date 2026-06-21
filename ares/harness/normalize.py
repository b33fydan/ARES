"""Deterministic text normalization for the ARES-Harness ingress path.

Folds the cheap, meaning-preserving obfuscations (zero-width chars, unicode
homoglyphs, fullwidth forms) that paraphrase-evade naive regex matchers
(the S089 OOV finding) BEFORE the firewall's detectors run. Newlines are
preserved so the firewall's structural-break detector still fires downstream.
"""
import re
import unicodedata

# Zero-width and joiner code points commonly used to split banned tokens.
# U+200B ZWSP, U+200C ZWNJ, U+200D ZWJ, U+2060 WORD JOINER, U+FEFF BOM
_ZERO_WIDTH = dict.fromkeys(
    map(ord, "​‌‍⁠﻿"), None
)

# Minimal, extensible Cyrillic->ASCII homoglyph map (NFKC does not fold these).
_HOMOGLYPHS = {
    "а": "a", "е": "e", "о": "o", "р": "p",
    "с": "c", "х": "x", "ѕ": "s", "і": "i",
}

# Non-whitespace control chars (keep \t \n \r).
_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
# Collapse runs of spaces/tabs only (NOT newlines).
_HSPACE = re.compile(r"[ \t]+")


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = text.translate(_ZERO_WIDTH)
    text = "".join(_HOMOGLYPHS.get(ch, ch) for ch in text)
    text = _CONTROL.sub("", text)
    text = _HSPACE.sub(" ", text)
    return text
