"""Bibliography helpers for Paper 3.

Session 064 scaffolding scope: the BibTeX parser plus the
regression-locked citation enumeration helpers
(``extract_citations`` and ``citation_to_bibkey``). The ACM/AISec
docx formatter and ``compile_references`` integration that exist in
Paper 2's ``docs/paper_2/build_references.py`` are deliberately out of
scope until prose lands (Session 065+). At that point the formatter
should be ported with the same shape, scoped to
``docs/paper_3/PAPER3_DRAFT_v1_0.docx``.

The helpers below are functionally identical to Paper 2's at Session
055 (which is when the narrative-form fix landed for the Hossain /
Lee silent-drop bug); see ``docs/paper_2/build_references.py``
docstring for the historical context.

The Paper 3 prose source (when it lands) is expected to use both
parenthetical ``(Author, YYYY)`` and narrative ``Author et al.
(YYYY)`` cite forms. Both must round-trip through ``extract_citations``
and ``citation_to_bibkey`` into a key that resolves against
``docs/paper_3/references.bib``.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path


# =============================================================================
# BibTeX parser (minimal — handles the entry shapes used by references.bib)
# =============================================================================


@dataclass(frozen=True)
class BibEntry:
    """One bibliography entry."""

    entry_type: str
    key: str
    fields: dict[str, str]

    def get(self, name: str, default: str = "") -> str:
        return self.fields.get(name, default)


_ENTRY_HEADER_RE = re.compile(
    r"@(\w+)\s*\{\s*([^,\s]+)\s*,",
    re.IGNORECASE,
)


def _scan_balanced(text: str, start: int, opener: str = "{", closer: str = "}") -> int:
    """Return the index AFTER the matching closer for the opener at start."""
    if text[start] != opener:
        raise ValueError(
            f"_scan_balanced: expected '{opener}' at index {start}, "
            f"got '{text[start]!r}'"
        )
    depth = 1
    i = start + 1
    while i < len(text) and depth > 0:
        c = text[i]
        if c == opener:
            depth += 1
        elif c == closer:
            depth -= 1
        i += 1
    if depth != 0:
        raise ValueError(
            f"_scan_balanced: unbalanced braces starting at {start}"
        )
    return i  # index AFTER the matching closer


def _parse_fields(body: str) -> dict[str, str]:
    """Parse the inside of an entry into field -> value."""
    fields: dict[str, str] = {}
    i = 0
    n = len(body)
    while i < n:
        # Skip whitespace and commas.
        while i < n and body[i] in " \t\r\n,":
            i += 1
        if i >= n:
            break
        # Read field name.
        m = re.match(r"(\w+)\s*=\s*", body[i:])
        if not m:
            # Not a field line; skip to next comma/newline.
            while i < n and body[i] != "\n":
                i += 1
            continue
        name = m.group(1).lower()
        i += m.end()
        if i >= n:
            break
        # Read value: braced {...} or quoted "..." or bare.
        if body[i] == "{":
            close = _scan_balanced(body, i, "{", "}")
            value = body[i + 1:close - 1]
            i = close
        elif body[i] == '"':
            close = body.find('"', i + 1)
            if close < 0:
                break
            value = body[i + 1:close]
            i = close + 1
        else:
            # Bare value — read until comma or newline.
            j = i
            while j < n and body[j] not in ",\n":
                j += 1
            value = body[i:j].strip()
            i = j
        fields[name] = " ".join(value.split())
    return fields


def parse_bib(text: str) -> tuple[BibEntry, ...]:
    """Parse a BibTeX-format string into a tuple of BibEntry."""
    entries: list[BibEntry] = []
    pos = 0
    while True:
        m = _ENTRY_HEADER_RE.search(text, pos)
        if not m:
            break
        entry_type = m.group(1).lower()
        key = m.group(2).strip()
        # Find the opening brace of the entry body.
        body_open = text.find("{", m.start())
        body_close = _scan_balanced(text, body_open, "{", "}")
        fields_text = text[m.end():body_close - 1]
        fields = _parse_fields(fields_text)
        entries.append(BibEntry(entry_type=entry_type, key=key, fields=fields))
        pos = body_close
    return tuple(entries)


def parse_bib_file(path: Path) -> tuple[BibEntry, ...]:
    return parse_bib(path.read_text(encoding="utf-8"))


# =============================================================================
# In-text citation resolution (regression-locked helpers)
# =============================================================================


# Parenthetical: ``(Author[, ...] [et al.], YYYY)`` — supports up to
# three authors joined by commas and "and" (Berdoz, Rugli, and
# Wattenhofer style).
_PAREN_CITATION_RE = re.compile(
    r"\(([A-Z][A-Za-z\-]+(?:,\s+[A-Za-z\-]+(?:,\s+and\s+[A-Za-z\-]+)?)?"
    r"(?:\s+et\s+al\.)?)\s*,\s*(\d{4})\)"
)
# Narrative: ``Author[ et al.] (YYYY)`` and ``Author1 and Author2 (YYYY)``
# — author name precedes the year, year alone is parenthesized.
# Paper 2 Session 055 patch: the narrative form was missing from the
# original implementation, which caused Hossain et al. (2025) and
# Lee et al. (2024) to silently drop from Session 052's coverage check.
_NARRATIVE_CITATION_RE = re.compile(
    r"\b([A-Z][A-Za-z\-]+"
    r"(?:\s+et\s+al\.)?"
    r"(?:\s+and\s+[A-Z][A-Za-z\-]+)?"
    r")\s*\((\d{4})\)"
)


def extract_citations(prose: str) -> tuple[tuple[str, str], ...]:
    """Return the unique ``(author_token, year)`` citations found in prose.

    Catches both parenthetical ``(Author, YYYY)`` and narrative
    ``Author et al. (YYYY)`` forms. Order-preserving deduplication.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for regex in (_PAREN_CITATION_RE, _NARRATIVE_CITATION_RE):
        for m in regex.finditer(prose):
            key = (m.group(1).strip(), m.group(2))
            if key not in seen:
                seen.add(key)
                out.append(key)
    return tuple(out)


def citation_to_bibkey(citation: tuple[str, str]) -> str:
    """Map a (author_token, year) citation to a canonical bib key.

    Examples:
        ("Gmys-Casiano", "2026") -> "gmys-casiano-2026"
        ("Hossain et al.", "2025") -> "hossain-2025"
        ("Berdoz, Rugli, and Wattenhofer", "2026") ->
            "berdoz-rugli-wattenhofer-2026"
        ("OWASP", "2025") -> "owasp-2025"
    """
    author, year = citation
    cleaned = author.replace(" et al.", "")
    parts = [p.strip().lower().replace(" ", "-") for p in cleaned.split(",")]
    parts = [re.sub(r"^and-", "", p) for p in parts if p]
    return "-".join(parts + [year])
