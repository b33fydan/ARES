"""Tests for ares.visual.event_exporter — JSON export of visual events.

Session 030: Validates that EventExporter produces valid JSON files
whose contents round-trip through event_from_dict().
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from ares.visual.event_exporter import EventExporter
from ares.visual.events import event_from_dict
from ares.visual.replayer import ScenarioReplayer


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _get_scenario(scenario_id: str = "SC-001"):
    """Load a single benchmark scenario from the corpus."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    for s in get_full_corpus():
        if s.metadata.scenario_id == scenario_id:
            return s
    raise ValueError(f"Scenario {scenario_id} not found")


def _get_first_three_scenarios():
    """Load the first three scenarios for batch tests."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
    corpus = list(get_full_corpus())
    return corpus[:3]


# ---------------------------------------------------------------------------
# Construction
# ---------------------------------------------------------------------------

class TestEventExporterConstruction:
    """Tests for EventExporter instantiation."""

    def test_default_replayer(self):
        exporter = EventExporter()
        assert isinstance(exporter.replayer, ScenarioReplayer)

    def test_custom_replayer(self):
        replayer = ScenarioReplayer(fact_delay_ms=100)
        exporter = EventExporter(replayer=replayer)
        assert exporter.replayer is replayer
        assert exporter.replayer.fact_delay_ms == 100

    def test_repr(self):
        exporter = EventExporter()
        r = repr(exporter)
        assert "EventExporter" in r
        assert "ScenarioReplayer" in r


# ---------------------------------------------------------------------------
# Filename generation
# ---------------------------------------------------------------------------

class TestScenarioFilename:
    """Tests for canonical filename generation."""

    def test_standard_id(self):
        assert EventExporter.scenario_filename("SC-001") == "SC-001_events.json"

    def test_double_digit_id(self):
        assert EventExporter.scenario_filename("SC-019") == "SC-019_events.json"

    def test_triple_digit_id(self):
        assert EventExporter.scenario_filename("SC-100") == "SC-100_events.json"


# ---------------------------------------------------------------------------
# events_to_json
# ---------------------------------------------------------------------------

class TestEventsToJson:
    """Tests for JSON serialization of event tuples."""

    def test_produces_valid_json(self):
        scenario = _get_scenario("SC-001")
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        json_str = EventExporter.events_to_json(events)
        parsed = json.loads(json_str)
        assert isinstance(parsed, list)
        assert len(parsed) == len(events)

    def test_events_round_trip(self):
        """Every exported event can be deserialized via event_from_dict."""
        scenario = _get_scenario("SC-001")
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        json_str = EventExporter.events_to_json(events)
        parsed = json.loads(json_str)
        for d in parsed:
            event = event_from_dict(d)
            assert event.event_type == d["event_type"]
            assert event.scenario_id == d["scenario_id"]

    def test_first_event_is_scenario_start(self):
        scenario = _get_scenario("SC-001")
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        json_str = EventExporter.events_to_json(events)
        parsed = json.loads(json_str)
        assert parsed[0]["event_type"] == "scenario_start"

    def test_last_event_is_scenario_end(self):
        scenario = _get_scenario("SC-001")
        replayer = ScenarioReplayer()
        events = replayer.replay(scenario)
        json_str = EventExporter.events_to_json(events)
        parsed = json.loads(json_str)
        assert parsed[-1]["event_type"] == "scenario_end"

    def test_empty_tuple(self):
        json_str = EventExporter.events_to_json(())
        assert json.loads(json_str) == []


# ---------------------------------------------------------------------------
# Single scenario export
# ---------------------------------------------------------------------------

class TestExportScenario:
    """Tests for export_scenario (single file)."""

    def test_creates_file(self, tmp_path):
        scenario = _get_scenario("SC-001")
        exporter = EventExporter()
        path = exporter.export_scenario(scenario, tmp_path / "SC-001_events.json")
        assert path.exists()
        assert path.name == "SC-001_events.json"

    def test_file_contains_valid_json(self, tmp_path):
        scenario = _get_scenario("SC-001")
        exporter = EventExporter()
        path = exporter.export_scenario(scenario, tmp_path / "out.json")
        parsed = json.loads(path.read_text(encoding="utf-8"))
        assert isinstance(parsed, list)
        assert len(parsed) > 0

    def test_all_events_deserializable(self, tmp_path):
        scenario = _get_scenario("SC-001")
        exporter = EventExporter()
        path = exporter.export_scenario(scenario, tmp_path / "out.json")
        parsed = json.loads(path.read_text(encoding="utf-8"))
        for d in parsed:
            event = event_from_dict(d)
            assert hasattr(event, "timestamp_ms")

    def test_creates_parent_dirs(self, tmp_path):
        scenario = _get_scenario("SC-001")
        exporter = EventExporter()
        deep_path = tmp_path / "a" / "b" / "c" / "events.json"
        path = exporter.export_scenario(scenario, deep_path)
        assert path.exists()

    def test_scenario_id_in_events(self, tmp_path):
        scenario = _get_scenario("SC-019")
        exporter = EventExporter()
        path = exporter.export_scenario(scenario, tmp_path / "SC-019_events.json")
        parsed = json.loads(path.read_text(encoding="utf-8"))
        for d in parsed:
            assert d["scenario_id"] == "SC-019"


# ---------------------------------------------------------------------------
# Batch export
# ---------------------------------------------------------------------------

class TestExportAll:
    """Tests for export_all (batch export)."""

    def test_creates_one_file_per_scenario(self, tmp_path):
        scenarios = _get_first_three_scenarios()
        exporter = EventExporter()
        paths = exporter.export_all(scenarios, tmp_path)
        assert len(paths) == 3
        for path in paths:
            assert path.exists()
            assert path.suffix == ".json"

    def test_filenames_match_convention(self, tmp_path):
        scenarios = _get_first_three_scenarios()
        exporter = EventExporter()
        paths = exporter.export_all(scenarios, tmp_path)
        for scenario, path in zip(scenarios, paths):
            expected = EventExporter.scenario_filename(scenario.metadata.scenario_id)
            assert path.name == expected

    def test_all_files_valid_json(self, tmp_path):
        scenarios = _get_first_three_scenarios()
        exporter = EventExporter()
        paths = exporter.export_all(scenarios, tmp_path)
        for path in paths:
            parsed = json.loads(path.read_text(encoding="utf-8"))
            assert isinstance(parsed, list)
            assert len(parsed) > 0

    def test_creates_output_dir(self, tmp_path):
        scenarios = _get_first_three_scenarios()
        exporter = EventExporter()
        out_dir = tmp_path / "new_dir"
        paths = exporter.export_all(scenarios, out_dir)
        assert out_dir.exists()
        assert len(paths) == 3


# ---------------------------------------------------------------------------
# Custom timing propagation
# ---------------------------------------------------------------------------

class TestCustomTiming:
    """Verify that custom replayer timing is reflected in exported events."""

    def test_fast_timing(self, tmp_path):
        fast_replayer = ScenarioReplayer(
            fact_delay_ms=50,
            assertion_delay_ms=100,
            verdict_delay_ms=200,
            check_delay_ms=100,
        )
        scenario = _get_scenario("SC-001")
        exporter = EventExporter(replayer=fast_replayer)
        path = exporter.export_scenario(scenario, tmp_path / "fast.json")
        parsed = json.loads(path.read_text(encoding="utf-8"))

        # Check that fact events use the fast delay
        fact_events = [d for d in parsed if d["event_type"] == "fact_ingested"]
        if len(fact_events) >= 2:
            delta = fact_events[1]["timestamp_ms"] - fact_events[0]["timestamp_ms"]
            assert delta == 50
