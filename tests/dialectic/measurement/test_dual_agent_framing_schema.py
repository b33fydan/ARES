import pytest

from ares.dialectic.measurement.dual_agent_framing_schema import (
    AGENT_ARCHITECT, AGENT_SKEPTIC, DUAL_AGENT_FRAMING_HARD_CEILING_USD,
    DualAgentFramingConfig, DualAgentResampleRecord,
)


def test_record_to_dict_has_both_columns_as_lists():
    rec = DualAgentResampleRecord(
        scenario_id="INJ-020", condition="baseline", resample_index=0,
        architect_cited_facts=("a1", "a2"), skeptic_cited_facts=("s1",),
        architect_confidence=0.9, skeptic_confidence=0.3,
        final_outcome="threat_dismissed", oracle_supporting_facts=("s1",),
        cost_usd=0.01, elapsed_ms=12.0,
    )
    d = rec.to_dict()
    assert d["architect_cited_facts"] == ["a1", "a2"]
    assert d["skeptic_cited_facts"] == ["s1"]
    assert isinstance(d["architect_cited_facts"], list)
    assert isinstance(d["skeptic_cited_facts"], list)


def test_config_rejects_small_k():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(s059_traces_path="x", k_resamples=1)


def test_config_rejects_ceiling_over_hard_cap():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(
            s059_traces_path="x",
            cost_ceiling_usd=DUAL_AGENT_FRAMING_HARD_CEILING_USD + 1.0,
        )


def test_config_rejects_unknown_provider():
    with pytest.raises(ValueError):
        DualAgentFramingConfig(s059_traces_path="x", provider="nope")


def test_agent_constants():
    assert AGENT_ARCHITECT == "architect"
    assert AGENT_SKEPTIC == "skeptic"
