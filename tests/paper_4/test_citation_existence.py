import json
from pathlib import Path
import pytest
from docs.paper_4.build_references import parse_bib_file, extract_citations, citation_to_bibkey

REPO = Path(__file__).resolve().parents[2]
BIB = REPO / "docs" / "paper_4" / "references.bib"
SKELETON = REPO / "docs" / "paper_4" / "skeleton_v1_0.json"

@pytest.fixture
def bib_entries():
    return parse_bib_file(BIB)

@pytest.fixture
def bib_keys(bib_entries):
    return {e.key for e in bib_entries}

@pytest.fixture
def skeleton():
    return json.loads(SKELETON.read_text(encoding="utf-8"))

def test_references_bib_parses(bib_entries):
    assert len(bib_entries) == 11  # 5 reused + 3 self-cites + 3 new-lit (S094)

def test_expected_verified_keys_present(bib_keys):
    for k in ("greshake-2023", "guo-2024", "jacovi-goldberg-2020",
              "reiter-1978", "berdoz-rugli-wattenhofer-2026",
              "gmys-casiano-2026a", "gmys-casiano-2026b", "gmys-casiano-2026c",
              "jin-2020", "tsipras-2019", "albanie-2022"):
        assert k in bib_keys, k

def test_every_entry_has_author_and_year(bib_entries):
    for e in bib_entries:
        assert e.get("author") and e.get("year")

def test_no_needed_suffix_in_real_bib(bib_keys):
    assert not any(k.endswith("-needed") for k in bib_keys)

def test_unverified_slugs_from_skeleton_not_in_bib(skeleton, bib_keys):
    for b in skeleton["bibkeys_needed_unverified"]:
        assert b["slug"] not in bib_keys

def test_self_cites_round_trip_from_narrative_prose():
    # "Gmys-Casiano (2026)" must resolve to a real key shape.
    cites = extract_citations("As shown by Gmys-Casiano (2026), ...")
    assert citation_to_bibkey(cites[0]) == "gmys-casiano-2026"

def test_every_skeleton_required_bibkey_resolves(skeleton, bib_keys):
    for s in skeleton["sections"]:
        for k in s["bibkeys_required"]:
            assert k in bib_keys, (s["section_id"], k)

@pytest.mark.skip(reason="Phase-3 prose concern: 'Gmys-Casiano (2026)' collides across "
                         "Papers 1-3; prose must disambiguate with a/b/c suffixes. "
                         "Offline gate only requires the suffixed keys exist (they do).")
def test_self_cite_disambiguation_documented():
    pass
