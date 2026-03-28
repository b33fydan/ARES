"""Event Exporter — writes ARES visual events to JSON files for offline replay.

Session 030: Exports the replayed event sequences as JSON files that
nw_wrld modules can load via loadJson() without a running WebSocket server.
Each file contains a JSON array of event dicts, one per scenario.

Public API:
    EventExporter  — call .export_scenario() or .export_all()
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Sequence, Tuple

from ares.visual.events import VisualEvent, event_from_dict
from ares.visual.replayer import ScenarioReplayer


class EventExporter:
    """Exports ARES visual event sequences to JSON files.

    Replays scenarios through ScenarioReplayer and writes the resulting
    event tuples as JSON arrays. Output files are suitable for loading
    into nw_wrld modules via loadJson().

    Args:
        replayer: Optional pre-configured ScenarioReplayer.
                  If None, creates one with default timing.
    """

    def __init__(self, replayer: ScenarioReplayer | None = None) -> None:
        self._replayer = replayer or ScenarioReplayer()

    @property
    def replayer(self) -> ScenarioReplayer:
        """The replayer used for event generation."""
        return self._replayer

    @staticmethod
    def events_to_json(events: Tuple[VisualEvent, ...]) -> str:
        """Serialize an event tuple to a JSON string.

        Args:
            events: Tuple of VisualEvent instances.

        Returns:
            JSON string containing an array of event dicts.
        """
        return json.dumps(
            [e.to_dict() for e in events],
            indent=2,
        )

    @staticmethod
    def scenario_filename(scenario_id: str) -> str:
        """Generate the canonical filename for a scenario's event file.

        Args:
            scenario_id: Scenario ID like 'SC-001'.

        Returns:
            Filename like 'SC-001_events.json'.
        """
        return f"{scenario_id}_events.json"

    def export_scenario(
        self,
        scenario,
        output_path: str | Path,
    ) -> Path:
        """Replay a scenario and write events to a JSON file.

        Args:
            scenario: A BenchmarkScenario with .metadata and .packet.
            output_path: Path to write the JSON file.

        Returns:
            The Path that was written.
        """
        events = self._replayer.replay(scenario)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(self.events_to_json(events), encoding="utf-8")
        return path

    def export_all(
        self,
        scenarios: Sequence,
        output_dir: str | Path,
    ) -> list[Path]:
        """Replay all scenarios and write each to a separate JSON file.

        Args:
            scenarios: Sequence of BenchmarkScenario instances.
            output_dir: Directory to write JSON files into.

        Returns:
            List of Paths that were written.
        """
        out_dir = Path(output_dir)
        out_dir.mkdir(parents=True, exist_ok=True)

        paths: list[Path] = []
        for scenario in scenarios:
            sid = scenario.metadata.scenario_id
            filename = self.scenario_filename(sid)
            path = self.export_scenario(scenario, out_dir / filename)
            paths.append(path)

        return paths

    def __repr__(self) -> str:
        return f"EventExporter(replayer={self._replayer!r})"
