from dataclasses import FrozenInstanceError

import pytest
from ares.dialectic.visualization.data_loader import PairRecord


def test_pair_record_is_frozen():
    record = PairRecord(
        scenario_id="INJ-001",
        operator="framing_prefix_v1",
        narrow_leakage=False,
        broad_leakage=False,
        confidence_baseline=0.95,
        confidence_mutated=0.95,
        first_diverging_layer="None",
    )
    with pytest.raises(FrozenInstanceError):
        record.scenario_id = "INJ-002"


def test_pair_record_fields_required():
    with pytest.raises(TypeError):
        PairRecord()


def test_pair_record_first_diverging_layer_accepts_known_values():
    for layer in ("Architect", "Skeptic", "Oracle", "Final", "None"):
        record = PairRecord(
            scenario_id="INJ-001",
            operator="framing_prefix_v1",
            narrow_leakage=False,
            broad_leakage=False,
            confidence_baseline=0.95,
            confidence_mutated=0.95,
            first_diverging_layer=layer,
        )
        assert record.first_diverging_layer == layer
