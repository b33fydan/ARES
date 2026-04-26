"""Citation existence audit tests for Paper 2.

Enforces structural invariants on the cite-key ↔ bib-entry mapping for
``docs/paper_2/PAPER2_DRAFT_v1_1.docx``:

    * Every citation in the prose has a matching bib entry.
    * Every bib entry (excepting acknowledged PLACEHOLDERs) carries a
      stable identifier (arXiv ID / DOI / URL / canonical artifact path).
    * Identifier formats parse cleanly.
    * (Opt-in) Identifiers resolve over the network.

LIMITATION (Sabet-class case): these tests do NOT catch a bib entry
that resolves to a real-but-unrelated paper, or a bib entry whose
title/authors diverge from the cited source. Semantic verification of
bib metadata against the resolved paper's metadata is future work and
is currently performed only by the manual audit in
``docs/paper_2/citation_audit_report.md``.

Network tests are opt-in via the ``ARES_RUN_NETWORK_TESTS`` environment
variable (set to ``1``, ``true``, or ``yes``). Offline pytest runs
remain fully green; CI runs that have network access can flip the
flag.
"""

from __future__ import annotations

import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parents[2]
DOCX_PATH = REPO_ROOT / "docs/paper_2/PAPER2_DRAFT_v1_1.docx"
BIB_PATH = REPO_ROOT / "docs/paper_2/references.bib"
SOURCE_MD_PATH = REPO_ROOT / "docs/paper_2/source/PAPER2_DRAFT_v1_1_source.md"
AUDIT_REPORT_PATH = REPO_ROOT / "docs/paper_2/citation_audit_report.md"


NETWORK_TESTS_ENABLED = os.environ.get(
    "ARES_RUN_NETWORK_TESTS", "",
).lower() in ("1", "true", "yes")
network_only = pytest.mark.skipif(
    not NETWORK_TESTS_ENABLED,
    reason="Set ARES_RUN_NETWORK_TESTS=1 to enable network identifier checks",
)


# Acknowledged PLACEHOLDER entries: bib keys that are intentionally
# without a stable identifier pending human resolution. Surface in the
# audit report rather than failing the structural tests.
#
# Empty as of Session 055: sabet-2025 was the only acknowledged
# placeholder and it was removed from references.bib after B2
# remediation in v1.1 source. The frozenset stays in place so future
# placeholders can be added with the same exception semantics.
ACKNOWLEDGED_PLACEHOLDERS: frozenset[str] = frozenset()


# ============================================================================
# Citation enumeration (parenthetical + narrative forms)
# ============================================================================


_PAREN_CITE_RE = re.compile(
    r"\(([A-Z][A-Za-z\-]+"
    r"(?:\s+et\s+al\.)?"
    r"(?:,\s+[A-Z][A-Za-z\-]+(?:,\s+and\s+[A-Z][A-Za-z\-]+)?)?"
    r")\s*,\s*(\d{4})\)"
)
_NARRATIVE_CITE_RE = re.compile(
    r"\b([A-Z][A-Za-z\-]+"
    r"(?:\s+et\s+al\.)?"
    r"(?:\s+and\s+[A-Z][A-Za-z\-]+)?"
    r")\s*\((\d{4})\)"
)


def enumerate_citations(text: str) -> list[tuple[str, str]]:
    """Return unique ``(author_token, year)`` citations from prose.

    Catches both parenthetical ``(Author, YYYY)`` and narrative
    ``Author et al. (YYYY)`` forms. Order-preserving deduplication.
    """
    seen: set[tuple[str, str]] = set()
    out: list[tuple[str, str]] = []
    for regex in (_PAREN_CITE_RE, _NARRATIVE_CITE_RE):
        for m in regex.finditer(text):
            key = (m.group(1).strip(), m.group(2))
            if key not in seen:
                seen.add(key)
                out.append(key)
    return out


# ============================================================================
# Identifier extraction from bib entries
# ============================================================================


@dataclass(frozen=True)
class IdentifierSet:
    arxiv_id: str | None
    doi: str | None
    url: str | None
    canonical_path: str | None  # local-repo PDF / docx pointer


_ARXIV_ID_RE = re.compile(r"^\d{4}\.\d{4,5}(v\d+)?$")
_DOI_RE = re.compile(r"^10\.\d{4,9}/[\w./\-]+$", re.IGNORECASE)
_URL_RE = re.compile(r"^https?://[^\s]+$")
_LOCAL_PATH_RE = re.compile(r"docs/paper_1/[A-Za-z0-9_\.\-]+\.pdf")


def extract_identifiers(entry) -> IdentifierSet:
    """Pull every kind of identifier we recognize from a BibEntry."""
    arxiv = entry.get("eprint") or None
    doi = entry.get("doi") or None
    url = entry.get("url") or None
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
    )


def has_any_identifier(idset: IdentifierSet) -> bool:
    return any((idset.arxiv_id, idset.doi, idset.url, idset.canonical_path))


# ============================================================================
# Fixtures
# ============================================================================


@pytest.fixture(scope="module")
def bib_entries():
    from docs.paper_2.build_references import parse_bib_file
    return parse_bib_file(BIB_PATH)


@pytest.fixture(scope="module")
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}


@pytest.fixture(scope="module")
def docx_text():
    from docs.paper_2.number_check import extract_docx_text
    return extract_docx_text(DOCX_PATH)


@pytest.fixture(scope="module")
def all_cite_keys(docx_text):
    """Cite keys actually referenced by the v1.1 prose."""
    from docs.paper_2.build_references import citation_to_bibkey
    return [citation_to_bibkey(c) for c in enumerate_citations(docx_text)]


# ============================================================================
# Enumeration helper tests
# ============================================================================


class TestEnumerateCitations:
    def test_handles_parenthetical_form(self):
        cites = enumerate_citations("Earlier work (Smith, 2024) showed X.")
        assert ("Smith", "2024") in cites

    def test_handles_narrative_form(self):
        cites = enumerate_citations("Smith et al. (2024) showed X.")
        assert ("Smith et al.", "2024") in cites

    def test_dedups_repeated_citations(self):
        text = "(Smith, 2024) ... and again (Smith, 2024)."
        cites = enumerate_citations(text)
        assert len([c for c in cites if c == ("Smith", "2024")]) == 1

    def test_finds_all_five_in_v1_1_docx(self, docx_text):
        cites = enumerate_citations(docx_text)
        # Convert to keys to dedup author-spelling variants.
        from docs.paper_2.build_references import citation_to_bibkey
        keys = {citation_to_bibkey(c) for c in cites}
        expected = {
            "gmys-casiano-2026",
            "berdoz-rugli-wattenhofer-2026",
            "hossain-2025",
            "lee-2024",
            "owasp-2025",
        }
        assert expected.issubset(keys), f"Missing: {expected - keys}"

    def test_sabet_no_longer_present_in_v1_1_docx(self, docx_text):
        """Regression: Sabet citation was removed in Session 055."""
        cites = enumerate_citations(docx_text)
        from docs.paper_2.build_references import citation_to_bibkey
        keys = {citation_to_bibkey(c) for c in cites}
        assert "sabet-2025" not in keys, (
            "sabet-2025 was remediated in Session 055 and must not "
            "reappear in v1.1 prose"
        )


# ============================================================================
# Structural invariants (always run)
# ============================================================================


class TestStructuralInvariants:
    def test_every_prose_cite_has_bib_entry(self, all_cite_keys, bib_keys):
        unresolved = [k for k in all_cite_keys if k not in bib_keys]
        assert not unresolved, (
            f"Cite keys in prose with no bib entry: {unresolved}"
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
            f"Bib entries with no stable identifier "
            f"(and not in ACKNOWLEDGED_PLACEHOLDERS): {missing}"
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

    def test_five_expected_cite_keys_present_in_bib(self, bib_keys):
        expected = {
            "gmys-casiano-2026",
            "berdoz-rugli-wattenhofer-2026",
            "hossain-2025",
            "lee-2024",
            "owasp-2025",
        }
        missing = expected - bib_keys
        assert not missing, f"Missing bib entries: {missing}"

    def test_sabet_entry_no_longer_in_bib(self, bib_keys):
        """Regression: sabet-2025 was removed from references.bib in
        Session 055 after B2 remediation. The entry must not reappear
        without a corresponding prose citation."""
        assert "sabet-2025" not in bib_keys, (
            "sabet-2025 was removed Session 055; if reintroduced, the "
            "audit + remediation history in citation_audit_report.md "
            "and sabet_remediation_findings.md must be updated first"
        )

    def test_audit_report_exists_and_lists_status_table(self):
        assert AUDIT_REPORT_PATH.exists(), "Citation audit report missing"
        text = AUDIT_REPORT_PATH.read_text(encoding="utf-8")
        for label in ("VERIFIED", "HALLUCINATED", "sabet-2025"):
            assert label in text, f"Audit report missing token: {label}"


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
        # arXiv often returns 200 only on GET; try GET as fallback.
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
