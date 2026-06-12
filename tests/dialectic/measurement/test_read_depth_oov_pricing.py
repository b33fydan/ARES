# tests/dialectic/measurement/test_read_depth_oov_pricing.py
import pytest
from ares.dialectic.measurement.read_depth_oov_validator import (
    CostCeilingExceeded, PRICE_TABLE, cost_for, _call_cost,
)


def test_known_providers_priced_positive_and_distinct():
    a = cost_for("anthropic", 1000, 1000)
    o = cost_for("openai", 1000, 1000)
    g = cost_for("gemini", 1000, 1000)
    assert a > 0 and o > 0 and g > 0
    assert len({a, o, g}) == 3  # provider-distinct list prices


def test_unknown_provider_raises_never_silent():
    with pytest.raises(ValueError):
        cost_for("googol", 1, 1)


def test_call_cost_backcompat_is_anthropic():
    assert _call_cost(1234, 567) == cost_for("anthropic", 1234, 567)


def test_price_table_covers_the_three_live_providers():
    assert set(PRICE_TABLE) == {"anthropic", "openai", "gemini"}


def test_cost_ceiling_exceeded_is_runtime_error():
    assert issubclass(CostCeilingExceeded, RuntimeError)
