"""Citation existence audit tests for Paper 3.

Mirrors the Paper 2 pattern at ``tests/paper_2/test_citation_existence.py``
(Sessions 054 + 055) with Paper 3 scope:

    * Every citation in the prose has a matching bib entry (when prose
      exists; Session 064 has no prose yet, so this test is parametrized
      to gracefully skip until ``PAPER3_DRAFT_v1_0.docx`` lands).
    * Every bib entry carries a stable identifier.
    * Identifier formats parse cleanly.
    * Unverified bibkeys (from ``skeleton_v1_0.json``) stay OUT of
      ``references.bib`` until they are independently verified.
      Direct enforcement of the Sabet-discipline post-mortem rule.
    * (Opt-in) Identifiers resolve over the network.

LIMITATION (Sabet-class case, repeated from Paper 2): these tests do
NOT catch a bib entry that resolves to a real-but-unrelated paper, or
a bib entry whose title/authors diverge from the cited source.
Semantic verification of bib metadata against resolved paper metadata
is future work and will be done via human audit (mirror Paper 2's
``citation_audit_report.md``) when Paper 3 prose lands.

Network tests are opt-in via the ``ARES_RUN_NETWORK_TESTS`` environment
variable (set to ``1``, ``true``, or ``yes``). Offline pytest runs
remain fully green; CI runs with network access can flip the flag.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
BIB_PATH = REPO_ROOT / "docs" / "paper_3" / "references.bib"
SKELETON_PATH = REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json"
DOCX_PATH = REPO_ROOT / "docs" / "paper_3" / "PAPER3_DRAFT_v1_0.docx"
SOURCE_MD_PATH = (
    REPO_ROOT / "docs" / "paper_3" / "source" / "PAPER3_DRAFT_v1_0_source.md"
)


NETWORK_TESTS_ENABLED = os.environ.get(
    "ARES_RUN_NETWORK_TESTS", "",
).lower() in ("1", "true", "yes")
network_only = pytest.mark.skipif(
    not NETWORK_TESTS_ENABLED,
    reason="Set ARES_RUN_NETWORK_TESTS=1 to enable network identifier checks",
)


# Acknowledged PLACEHOLDER entries: bib keys without a stable
# identifier pending human resolution. Empty for Session 064 — the
# scaffolding rule is "no placeholders in references.bib"; unverified
# bibkeys live in skeleton_v1_0.json instead.
ACKNOWLEDGED_PLACEHOLDERS: frozenset[str] = frozenset()


# The verified bibkeys for Paper 3 v1.0. These must round-trip cleanly
# from natural-prose cite forms through extract_citations +
# citation_to_bibkey, per the Session 064 deviation from the brief's
# thematic key suggestions.
EXPECTED_VERIFIED_KEYS = frozenset({
    "gmys-casiano-2026",                 # Paper 2 self-cite
    "berdoz-rugli-wattenhofer-2026",     # ETH "Can AI Agents Agree?"
})


# ============================================================================
# Identifier extraction (mirror of Paper 2's IdentifierSet)
# ============================================================================


@dataclass(frozen=True)
class IdentifierSet:
    arxiv_id: str | None
    doi: str | None
    url: str | None
    canonical_path: str | None  # local-repo draft pointer
    isbn: str | None  # ISBN-10 / ISBN-13 for pre-DOI book references


_ARXIV_ID_RE = re.compile(r"^\d{4}\.\d{4,5}(v\d+)?$")
_DOI_RE = re.compile(r"^10\.\d{4,9}/[\w./\-]+$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://[^\s]+$")
_LOCAL_PATH_RE = re.compile(
    r"docs/paper_[123]/[A-Za-z0-9_/\.\-]+\.(?:pdf|docx)"
)
# ISBN-10 (10 digits, last may be X) or ISBN-13 (13 digits, starts with 978/979).
# Hyphens are tolerated by stripping them before match.
_ISBN_RE = re.compile(r"^(?:\d{9}[\dXx]|97[89]\d{10})$")


def extract_identifiers(entry) -> IdentifierSet:
    """Pull every kind of identifier recognized from a BibEntry."""
    arxiv = entry.get("eprint") or None
    doi = entry.get("doi") or None
    url = entry.get("url") or None
    isbn = entry.get("isbn") or None
    canonical = None
    note = entry.get("note") or ""
    m = _LOCAL_PATH_RE.search(note)
    if m:
        canonical = m.group(0)
    return IdentifierSet(
        arxiv_id=arxiv if arxiv else None,
        doi=doi if doi else None,
        url=url if url else None,
        canonical_path=canonical,
        isbn=isbn if isbn else None,
    )


def has_any_identifier(idset: IdentifierSet) -> bool:
    return any((
        idset.arxiv_id, idset.doi, idset.url,
        idset.canonical_path, idset.isbn,
    ))


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def bib_entries():
    from docs.paper_3.build_references import parse_bib_file
    return parse_bib_file(BIB_PATH)


@pytest.fixture(scope="module")
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}


@pytest.fixture(scope="module")
def skeleton():
    return json.loads(SKELETON_PATH.read_text(encoding="utf-8"))


# ============================================================================
# Enumeration helper tests (helpers were ported from Paper 2 Session 055)
# ============================================================================


class TestEnumerationHelpers:
    def test_handles_parenthetical_form(self):
        from docs.paper_3.build_references import extract_citations
        cites = extract_citations("Earlier work (Smith, 2024) showed X.")
        assert ("Smith", "2024") in cites

    def test_handles_narrative_form(self):
        from docs.paper_3.build_references import extract_citations
        cites = extract_citations("Smith et al. (2024) showed X.")
        assert ("Smith et al.", "2024") in cites

    def test_dedups_repeated_citations(self):
        from docs.paper_3.build_references import extract_citations
        text = "(Smith, 2024) ... and again (Smith, 2024)."
        cites = extract_citations(text)
        assert len([c for c in cites if c == ("Smith", "2024")]) == 1

    def test_citation_to_bibkey_canonical_author_year(self):
        from docs.paper_3.build_references import citation_to_bibkey
        assert (
            citation_to_bibkey(("Gmys-Casiano", "2026"))
            == "gmys-casiano-2026"
        )
        assert (
            citation_to_bibkey(("Berdoz, Rugli, and Wattenhofer", "2026"))
            == "berdoz-rugli-wattenhofer-2026"
        )

    def test_verified_keys_round_trip_from_natural_prose(self, bib_keys):
        """The two verified keys must be reachable from natural prose
        cite forms via the ported helpers."""
        from docs.paper_3.build_references import (
            extract_citations,
            citation_to_bibkey,
        )
        prose = (
            "Paper 2 introduced the deterministic Skeptic "
            "(Gmys-Casiano, 2026). Independent evidence from "
            "(Berdoz, Rugli, and Wattenhofer, 2026) corroborates."
        )
        cites = extract_citations(prose)
        keys = {citation_to_bibkey(c) for c in cites}
        unresolved = keys - bib_keys
        assert not unresolved, (
            f"Cite forms in natural prose failed to resolve against "
            f"references.bib: {unresolved}"
        )


# ============================================================================
# Structural invariants on references.bib (always-on)
# ============================================================================


class TestStructuralInvariants:
    def test_references_bib_parses(self, bib_entries):
        assert len(bib_entries) >= 2, (
            "Paper 3 v1.0 requires at least the two Required bibkeys"
        )

    def test_expected_verified_keys_present(self, bib_keys):
        missing = EXPECTED_VERIFIED_KEYS - bib_keys
        assert not missing, (
            f"Verified bib keys missing from references.bib: {missing}"
        )

    def test_every_bib_entry_has_identifier_or_acknowledged_placeholder(
        self, bib_entries,
    ):
        missing = []
        for entry in bib_entries:
            if entry.key in ACKNOWLEDGED_PLACEHOLDERS:
                continue
            if not has_any_identifier(extract_identifiers(entry)):
                missing.append(entry.key)
        assert not missing, (
            f"Bib entries with no stable identifier: {missing}"
        )

    def test_arxiv_ids_match_format(self, bib_entries):
        bad = []
        for entry in bib_entries:
            arxiv = entry.get("eprint")
            if arxiv and not _ARXIV_ID_RE.match(arxiv):
                bad.append((entry.key, arxiv))
        assert not bad, f"Malformed arXiv IDs: {bad}"

    def test_dois_match_format(self, bib_entries):
        bad = []
        for entry in bib_entries:
            doi = entry.get("doi")
            if doi and not _DOI_RE.match(doi):
                bad.append((entry.key, doi))
        assert not bad, f"Malformed DOIs: {bad}"

    def test_urls_are_well_formed(self, bib_entries):
        bad = []
        for entry in bib_entries:
            url = entry.get("url")
            if url and not _URL_RE.match(url):
                bad.append((entry.key, url))
        assert not bad, f"Malformed URLs: {bad}"

    def test_isbns_match_format(self, bib_entries):
        """ISBN-10 (9 digits + check digit) or ISBN-13 (978/979 + 10 digits)."""
        bad = []
        for entry in bib_entries:
            isbn = entry.get("isbn")
            if isbn:
                stripped = isbn.replace("-", "").replace(" ", "")
                if not _ISBN_RE.match(stripped):
                    bad.append((entry.key, isbn))
        assert not bad, f"Malformed ISBNs: {bad}"

    def test_every_entry_has_author_and_year(self, bib_entries):
        for entry in bib_entries:
            assert entry.get("author"), f"{entry.key} missing author"
            assert entry.get("year"), f"{entry.key} missing year"


# ============================================================================
# Sabet-discipline guards
# ============================================================================


class TestSabetDisciplineGuards:
    """Direct enforcement of the post-Sabet rule: unverified bibkeys
    stay OUT of references.bib until they are independently verified.
    This is the structural anti-hallucination guard."""

    def test_no_needed_suffix_in_real_bib(self, bib_keys):
        """The -needed suffix marks unverified slugs in
        skeleton_v1_0.json. None of them should leak into
        references.bib without verification + renaming."""
        leaked = [k for k in bib_keys if k.endswith("-needed")]
        assert not leaked, (
            f"-needed slugs must not appear in references.bib: "
            f"{leaked}. If verified, remove the suffix and update the "
            f"corresponding entry in skeleton_v1_0.json."
        )

    def test_unverified_slugs_from_skeleton_not_in_bib(
        self, bib_keys, skeleton,
    ):
        """The five Needed bibkeys from skeleton_v1_0.json must not
        accidentally land in references.bib without verification."""
        unverified_slugs = {
            e["slug"] for e in skeleton["bibkeys_needed_unverified"]
        }
        leaked = unverified_slugs & bib_keys
        assert not leaked, (
            f"Unverified skeleton slugs leaked into references.bib "
            f"without verification: {leaked}"
        )

    def test_unverified_bibkey_count_locked_at_one_post_session_068(self, skeleton):
        """Session 064 brief listed five Needed bibkeys. Session 068
        verified four of them (greshake / guo / reiter / jacovi) and
        moved them to bibkeys_required_verified; one (frozen-dataclass-
        pattern-needed) remains, scheduled for Phase C drop in the
        same session. If this count changes silently after Session 068,
        prose has drifted from the brief."""
        assert len(skeleton["bibkeys_needed_unverified"]) == 1

    def test_unverified_slugs_have_verification_instructions(self, skeleton):
        for entry in skeleton["bibkeys_needed_unverified"]:
            assert entry.get("verification_required_before_commit"), (
                f"Unverified slug {entry.get('slug', '?')!r} missing "
                f"verification_required_before_commit instructions — "
                f"required to prevent fabricated entries."
            )


# ============================================================================
# Forward-looking docx checks (skip until prose lands)
# ============================================================================


@pytest.mark.skipif(
    not DOCX_PATH.exists(),
    reason=(
        "Paper 3 docx not built yet (Session 064 is skeleton-only; "
        "docx lands Session 065+)"
    ),
)
class TestDocxCitationsResolveAgainstBib:
    """Activates once Session 065+ produces PAPER3_DRAFT_v1_0.docx."""

    def test_every_prose_cite_resolves_to_a_bib_entry(self, bib_keys):
        from docs.paper_2.number_check import extract_docx_text
        from docs.paper_3.build_references import (
            extract_citations,
            citation_to_bibkey,
        )
        text = extract_docx_text(DOCX_PATH)
        cite_keys = {citation_to_bibkey(c) for c in extract_citations(text)}
        unresolved = cite_keys - bib_keys
        assert not unresolved, (
            f"Cite keys in prose with no bib entry: {unresolved}"
        )


# ============================================================================
# Network checks (opt-in)
# ============================================================================


def _http_status(url: str, timeout: float = 10.0) -> int:
    """Return HTTP status code for a URL (HEAD if possible, then GET)."""
    req = urllib.request.Request(
        url, method="HEAD",
        headers={"User-Agent": "ARES-citation-audit/1.0"},
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status
    except urllib.error.HTTPError as e:
        if e.code == 405:
            try:
                req2 = urllib.request.Request(
                    url,
                    headers={"User-Agent": "ARES-citation-audit/1.0"},
                )
                with urllib.request.urlopen(req2, timeout=timeout) as resp:
                    return resp.status
            except urllib.error.HTTPError as e2:
                return e2.code
        return e.code


@network_only
class TestNetworkResolution:
    def test_arxiv_ids_resolve(self, bib_entries):
        failed = []
        for entry in bib_entries:
            arxiv = entry.get("eprint")
            if not arxiv:
                continue
            url = f"https://arxiv.org/abs/{arxiv}"
            status = _http_status(url)
            if not (200 <= status < 400):
                failed.append((entry.key, url, status))
        assert not failed, f"arXiv IDs that did not resolve: {failed}"

    def test_dois_resolve(self, bib_entries):
        failed = []
        for entry in bib_entries:
            doi = entry.get("doi")
            if not doi:
                continue
            url = f"https://doi.org/{doi}"
            status = _http_status(url)
            if not (200 <= status < 400):
                failed.append((entry.key, url, status))
        assert not failed, f"DOIs that did not resolve: {failed}"

    def test_urls_return_200(self, bib_entries):
        failed = []
        for entry in bib_entries:
            url = entry.get("url")
            if not url:
                continue
            status = _http_status(url)
            if not (200 <= status < 400):
                failed.append((entry.key, url, status))
        assert not failed, f"URLs that did not resolve: {failed}"
