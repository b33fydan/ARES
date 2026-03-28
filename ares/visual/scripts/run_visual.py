"""CLI runner for the ARES visual emitter.

Session 029: Starts a WebSocket server and replays ARES scenarios
as streams of typed JSON events for nw_wrld visualization.

Usage:
    python -m ares.visual.scripts.run_visual --scenario SC-001
    python -m ares.visual.scripts.run_visual --all
    python -m ares.visual.scripts.run_visual --scenario SC-019 --speed 2.0
    python -m ares.visual.scripts.run_visual --list
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARES Visual Emitter — stream scenario events via WebSocket",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Scenario ID to replay (e.g., SC-001)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Replay all 33 scenarios in sequence",
    )
    parser.add_argument(
        "--list",
        action="store_true",
        help="List available scenarios and exit",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=1.0,
        help="Playback speed multiplier (default: 1.0, higher = faster)",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="WebSocket server port (default: 8765)",
    )
    parser.add_argument(
        "--no-server",
        action="store_true",
        help="Print events to stdout instead of WebSocket",
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


async def _run_with_server(scenarios, replayer, port: int, speed: float) -> None:
    """Run scenarios through the WebSocket emitter."""
    from ares.visual.emitter import VisualEmitter

    emitter = VisualEmitter(port=port)
    await emitter.start()
    print(f"WebSocket server running on ws://localhost:{port}")
    print("Waiting for clients to connect... (press Ctrl+C to stop)")

    # Wait a moment for clients to connect
    await asyncio.sleep(2)

    for scenario in scenarios:
        sid = scenario.metadata.scenario_id
        print(f"\nReplaying: {sid} — {scenario.metadata.name}")

        # Adjust replayer timing by speed
        adjusted = type(replayer)(
            fact_delay_ms=int(replayer.fact_delay_ms / speed),
            assertion_delay_ms=int(replayer.assertion_delay_ms / speed),
            verdict_delay_ms=int(replayer.verdict_delay_ms / speed),
            check_delay_ms=int(replayer.check_delay_ms / speed),
        )
        events = adjusted.replay(scenario)

        print(f"  Streaming {len(events)} events...")
        await emitter.stream(events, realtime=True)
        print(f"  Done ({events[-1].timestamp_ms}ms)")

        # Brief pause between scenarios
        if len(scenarios) > 1:
            await asyncio.sleep(2)

    print("\nAll scenarios complete. Server still running (Ctrl+C to stop).")

    # Keep server alive
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

    await emitter.stop()


def _run_to_stdout(scenarios, replayer, speed: float) -> None:
    """Print events to stdout as JSON lines."""
    from ares.visual.replayer import ScenarioReplayer

    adjusted = ScenarioReplayer(
        fact_delay_ms=int(replayer.fact_delay_ms / speed),
        assertion_delay_ms=int(replayer.assertion_delay_ms / speed),
        verdict_delay_ms=int(replayer.verdict_delay_ms / speed),
        check_delay_ms=int(replayer.check_delay_ms / speed),
    )

    for scenario in scenarios:
        sid = scenario.metadata.scenario_id
        print(f"# Scenario: {sid} — {scenario.metadata.name}", file=sys.stderr)

        events = adjusted.replay(scenario)
        for event in events:
            print(json.dumps(event.to_dict()))

        print(f"# {len(events)} events emitted", file=sys.stderr)


def main() -> None:
    """Entry point for the visual emitter CLI."""
    parser = build_parser()
    args = parser.parse_args()

    if args.list:
        _list_scenarios()
        return

    if not args.scenario and not args.all:
        parser.print_help()
        print("\nError: specify --scenario SC-XXX or --all")
        sys.exit(1)

    # Collect scenarios
    if args.all:
        from ares.dialectic.scripts.expanded_scenarios import get_full_corpus
        scenarios = list(get_full_corpus())
    else:
        scenarios = [_get_scenario(args.scenario)]

    from ares.visual.replayer import ScenarioReplayer
    replayer = ScenarioReplayer()

    logging.basicConfig(level=logging.INFO, format="%(message)s")

    if args.no_server:
        _run_to_stdout(scenarios, replayer, args.speed)
    else:
        try:
            asyncio.run(_run_with_server(scenarios, replayer, args.port, args.speed))
        except KeyboardInterrupt:
            print("\nShutdown.")


if __name__ == "__main__":
    main()
