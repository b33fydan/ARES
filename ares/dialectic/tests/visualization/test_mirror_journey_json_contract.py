"""Contract guard for the Mirror renderer artifact.

mirror-journey.json is consumed by skyframe-main/assets/ares/mirror.html.
Lock the shape AND the headline numbers so a regen that changes them fails
on the ARES side, not silently in the browser.
"""
from __future__ import annotations

import json
from pathlib import Path

import pytest

REPO_ROOT = Path(__file__).resolve().parents[4]
JOURNEY_PATH = REPO_ROOT / "docs" / "marketing" / "mirror-journey.json"

REQUIRED_TOP = frozenset({"schema_version", "run_id", "hero", "landscape"})
REQUIRED_AGENT = frozenset({"agent", "baseline_facts", "framed_facts",
                            "jaccard", "within_noise", "p_value", "direction"})


@pytest.fixture(scope="module")
def journey() -> dict:
    assert JOURNEY_PATH.exists(), f"mirror-journey.json missing at {JOURNEY_PATH}"
    with JOURNEY_PATH.open("r", encoding="utf-8") as fh:
        return json.load(fh)


def test_top_level_keys(journey):
    assert REQUIRED_TOP.issubset(journey.keys())
    assert journey["schema_version"] == "mirror-v1"


def test_hero_agents_shape(journey):
    for agent in ("architect", "skeptic"):
        a = journey["hero"][agent]
        assert REQUIRED_AGENT.issubset(a.keys()), f"{agent} missing keys"


def test_hero_real_numbers(journey):
    h = journey["hero"]
    assert h["scenario_id"] == "INJ-020"
    assert h["threat_fact"] == "inj020-fact-003"
    assert h["architect"]["jaccard"] == 0.8
    assert h["architect"]["direction"] == "collapse"
    assert h["architect"]["framed_facts"] == ["inj020-fact-003"]
    assert h["skeptic"]["jaccard"] == 0.4
    assert h["skeptic"]["direction"] == "expand"
    assert len(h["skeptic"]["framed_facts"]) == 5  # expands to all 5
    assert h["verdict"] == "threat_dismissed"
    assert h["verdict_held_fraction"] == 1.0
    # noise floor + p-value are the published S084 honesty numbers (scene 3)
    for agent in ("architect", "skeptic"):
        assert h[agent]["within_noise"] == 0.0
        assert h[agent]["p_value"] == 0.0


def test_landscape_real_numbers(journey):
    ls = journey["landscape"]
    assert (ls["opposed"], ls["aligned"], ls["single"], ls["none"]) == (4, 5, 20, 21)
    assert (ls["architect_real"], ls["skeptic_real"], ls["n_scenarios"]) == (11, 9, 17)


def test_threat_fact_in_facts(journey):
    assert journey["hero"]["threat_fact"] in journey["hero"]["facts"]
