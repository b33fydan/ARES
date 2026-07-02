"""Every required bibkey resolves in a verified-only references.bib."""
from __future__ import annotations

import json
from pathlib import Path

import pytest

from docs.paper_5.build_references import (
    parse_bib_file,
    extract_citations,
    citation_to_bibkey,
)

REPO = Path(__file__).resolve().parents[2]
BIB = REPO / "docs" / "paper_5" / "references.bib"
SKELETON = REPO / "docs" / "paper_5" / "skeleton_v1_0.json"

EXPECTED_VERIFIED_KEYS = [
    "greshake-2023",
    "albanie-2022",
    "gmys-casiano-2026a",
    "gmys-casiano-2026b",
    "gmys-casiano-2026c",
    "gmys-casiano-2026d",
    "debenedetti-2025-camel",
    "debenedetti-2024-agentdojo",
    "willison-2023-dualllm",
    "hines-2024-spotlighting",
    "wallace-2024-instruction-hierarchy",
    "chen-2024-struq",
    "chen-2024-secalign",
    "zhan-2024-injecagent",
    "yi-2023-bipia",
]


@pytest.fixture
def bib_entries():
    return parse_bib_file(BIB)


@pytest.fixture
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}


@pytest.fixture
def skeleton() -> dict:
    return json.loads(SKELETON.read_text(encoding="utf-8"))


def test_references_bib_parses(bib_entries):
    assert len(bib_entries) == len(EXPECTED_VERIFIED_KEYS)


def test_expected_verified_keys_present(bib_keys):
    for k in EXPECTED_VERIFIED_KEYS:
        assert k in bib_keys, f"missing verified bibkey {k}"


def test_every_entry_has_author_and_year(bib_entries):
    for e in bib_entries:
        # willison-2023-dualllm is a @misc blog; allow howpublished in place of year if needed
        assert e.get("author") or e.get("howpublished"), f"{e.key} has no author/howpublished"
        assert e.get("year"), f"{e.key} has no year"


def test_no_needed_suffix_in_real_bib(bib_keys):
    assert not any(k.endswith("-needed") for k in bib_keys)


def test_unverified_slugs_from_skeleton_not_in_bib(skeleton, bib_keys):
    # After Task 2 web-verification, bibkeys_needed_unverified should be empty;
    # but the invariant holds either way: no needed-slug appears as a real bib key.
    for u in skeleton["bibkeys_needed_unverified"]:
        assert u["slug"] not in bib_keys, f"unverified {u['slug']} leaked into bib"


def test_every_skeleton_required_bibkey_resolves(skeleton, bib_keys):
    for s in skeleton["sections"]:
        for k in s["bibkeys_required"]:
            assert k in bib_keys, f"{s['section_id']} requires {k} not in bib"


def test_self_cite_round_trips_from_narrative_prose():
    cites = extract_citations("As shown by Gmys-Casiano (2026), the gate holds.")
    assert citation_to_bibkey(cites[0]) == "gmys-casiano-2026"
