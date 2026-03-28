"""CLI runner for ARES visual event export to JSON files.

Session 030: Exports replayed scenario events as JSON files suitable
for loading into nw_wrld modules via loadJson(). Produces one file
per scenario, each containing a JSON array of event dicts.

Usage:
    python -m ares.visual.scripts.run_export --scenario SC-001
    python -m ares.visual.scripts.run_export --all --output-dir ./events
    python -m ares.visual.scripts.run_export --list
"""

from __future__ import annotations

import argparse
import sys


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARES Event Exporter — write scenario events to JSON files",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Scenario ID to export (e.g., SC-001)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Export all 33 scenarios",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios and exit",
    )
    parser.add_argument(
        "--output-dir",
        type=str,
        default=".",
        help="Directory for output JSON files (default: current directory)",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Timing multiplier (default: 1.0, higher = tighter timing)",
    )
    return parser


def _get_scenario(scenario_id: str):
    """Get a scenario by ID from the full corpus."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus

    for s in get_full_corpus():
        if s.metadata.scenario_id == scenario_id:
            return s
    print(f"ERROR: Scenario '{scenario_id}' not found")
    sys.exit(1)


def _list_scenarios() -> None:
    """Print all available scenarios."""
    from ares.dialectic.scripts.expanded_scenarios import get_full_corpus

    print(f"{'ID':<8} {'Name':<40} {'Expected':<20} {'Facts':>5}")
    print("-" * 75)
    for s in get_full_corpus():
        print(
            f"{s.metadata.scenario_id:<8} "
            f"{s.metadata.name[:39]:<40} "
            f"{s.metadata.expected_verdict:<20} "
            f"{s.metadata.fact_count:>5}"
        )


def main() -> None:
    """Entry point for the event exporter CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        _list_scenarios()
        return

    if not args.scenario and not args.all:
        parser.print_help()
        print("\nError: specify --scenario SC-XXX or --all")
        sys.exit(1)

    from ares.visual.event_exporter import EventExporter
    from ares.visual.replayer import ScenarioReplayer

    # Build replayer with timing adjustment
    replayer = ScenarioReplayer(
        fact_delay_ms=int(200 / args.speed),
        assertion_delay_ms=int(500 / args.speed),
        verdict_delay_ms=int(1000 / args.speed),
        check_delay_ms=int(500 / args.speed),
    )
    exporter = EventExporter(replayer=replayer)

    if args.all:
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus

        scenarios = list(get_full_corpus())
        print(f"Exporting {len(scenarios)} scenarios to {args.output_dir}/")
        paths = exporter.export_all(scenarios, args.output_dir)
        for path in paths:
            print(f"  {path.name}")
        print(f"\nDone. {len(paths)} files written.")
    else:
        scenario = _get_scenario(args.scenario)
        filename = EventExporter.scenario_filename(args.scenario)
        from pathlib import Path

        output_path = Path(args.output_dir) / filename
        path = exporter.export_scenario(scenario, output_path)
        print(f"Exported: {path}")


if __name__ == "__main__":
    main()
