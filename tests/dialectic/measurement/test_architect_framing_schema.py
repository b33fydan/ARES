import pytest
from ares.dialectic.measurement.architect_framing_schema import (
    ArchitectFramingConfig, framing_condition, CONDITION_BASELINE, CONDITION_CONTROL,
    ARCHITECT_FRAMING_HARD_CEILING_USD,
)
from ares.dialectic.measurement.leakage_runner import PRE_REGISTERED_OPERATOR_NAMES


def test_defaults_are_pre_registered():
    cfg = ArchitectFramingConfig(s059_traces_path="x")
    assert cfg.operator_names == PRE_REGISTERED_OPERATOR_NAMES
    assert cfg.k_resamples == 8
    assert cfg.provider == "anthropic"


def test_condition_helpers():
    assert framing_condition("framing_prefix_v1") == "framing:framing_prefix_v1"
    assert CONDITION_BASELINE == "baseline"
    assert CONDITION_CONTROL == "control"


def test_k_resamples_must_be_at_least_two():
    with pytest.raises(ValueError, match="k_resamples"):
        ArchitectFramingConfig(s059_traces_path="x", k_resamples=1)


def test_cost_ceiling_hard_capped():
    with pytest.raises(ValueError, match="cost_ceiling"):
        ArchitectFramingConfig(s059_traces_path="x",
                               cost_ceiling_usd=ARCHITECT_FRAMING_HARD_CEILING_USD + 1)


def test_invalid_provider_rejected():
    with pytest.raises(ValueError, match="provider"):
        ArchitectFramingConfig(s059_traces_path="x", provider="bogus")
