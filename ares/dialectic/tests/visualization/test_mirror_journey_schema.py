from __future__ import annotations

import json

import pytest

from ares.dialectic.visualization.mirror_journey_schema import (
    AgentFraming,
    Hero,
    Landscape,
    MirrorJourney,
    mirror_journey_to_json,
)


def _agent(agent="architect", direction="collapse"):
    return AgentFraming(
        agent=agent,
        baseline_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
                        "inj020-fact-004", "inj020-fact-005"),
        framed_facts=("inj020-fact-003",),
        jaccard=0.8,
        within_noise=0.0,
        p_value=0.0,
        direction=direction,
    )


def _journey():
    hero = Hero(
        scenario_id="INJ-020",
        facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
               "inj020-fact-004", "inj020-fact-005"),
        threat_fact="inj020-fact-003",
        architect=_agent("architect", "collapse"),
        skeptic=AgentFraming(
            agent="skeptic",
            baseline_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-004"),
            framed_facts=("inj020-fact-001", "inj020-fact-002", "inj020-fact-003",
                          "inj020-fact-004", "inj020-fact-005"),
            jaccard=0.4, within_noise=0.0, p_value=0.0, direction="expand",
        ),
        verdict="threat_dismissed",
        verdict_held_fraction=1.0,
    )
    landscape = Landscape(opposed=4, aligned=5, single=20, none_=21,
                          architect_real=11, skeptic_real=9, n_scenarios=17)
    return MirrorJourney(schema_version="mirror-v1", run_id="RUNID",
                         hero=hero, landscape=landscape)


def test_agent_rejects_bad_direction():
    with pytest.raises(ValueError):
        AgentFraming(agent="architect", baseline_facts=(), framed_facts=(),
                     jaccard=0.0, within_noise=0.0, p_value=0.0, direction="wobble")


def test_agent_rejects_jaccard_out_of_range():
    with pytest.raises(ValueError):
        AgentFraming(agent="architect", baseline_facts=(), framed_facts=(),
                     jaccard=1.5, within_noise=0.0, p_value=0.0, direction="collapse")


def test_landscape_rejects_negative():
    with pytest.raises(ValueError):
        Landscape(opposed=-1, aligned=5, single=20, none_=21,
                  architect_real=11, skeptic_real=9, n_scenarios=17)


def test_to_json_is_deterministic_and_sorted():
    a = mirror_journey_to_json(_journey())
    b = mirror_journey_to_json(_journey())
    assert a == b
    parsed = json.loads(a)
    assert parsed["schema_version"] == "mirror-v1"
    # none_ serializes to the wire key "none"
    assert parsed["landscape"]["none"] == 21
    assert "none_" not in parsed["landscape"]
    assert parsed["hero"]["architect"]["jaccard"] == 0.8
    assert parsed["hero"]["threat_fact"] == "inj020-fact-003"
