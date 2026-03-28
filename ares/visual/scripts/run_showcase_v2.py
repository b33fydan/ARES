"""Showcase runner v2 — WebSocket-enabled visual replay for the browser.

Session 036: Starts the WebSocket emitter server and streams real
benchmark events for the standalone visualizer (index.html) or nw_wrld.

Usage:
    python -m ares.visual.scripts.run_showcase_v2 --mode capture --speed 0.3
    python -m ares.visual.scripts.run_showcase_v2 --mode demo --speed 1.0
    python -m ares.visual.scripts.run_showcase_v2 --scenario SC-010 --speed 0.5
    python -m ares.visual.scripts.run_showcase_v2 --list-showcase
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional


DEFAULT_RESULTS = "ares/dialectic/scripts/benchmark_results/v4_corpus_v2.json"


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="ARES Showcase v2 — WebSocket streaming for browser visualizer",
    )
    parser.add_argument(
        "--mode",
        choices=["capture", "demo"],
        default="demo",
        help="capture = slow cinematic (0.3x), demo = normal speed",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=None,
        help="Playback speed override",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Single scenario deep-dive (e.g., SC-010)",
    )
    parser.add_argument(
        "--list-showcase",
        action="store_true",
        help="List curated showcase scenarios and exit",
    )
    parser.add_argument(
        "--results",
        type=str,
        default=DEFAULT_RESULTS,
        help="Path to benchmark results JSON",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="WebSocket server port (default: 8765)",
    )
    return parser


async def _stream(events, port: int) -> None:
    """Start WebSocket server and stream events to connected clients."""
    from ares.visual.emitter import VisualEmitter

    emitter = VisualEmitter(port=port)
    await emitter.start()

    print(f"\nWebSocket server running on ws://localhost:{port}")
    print(f"Open the visualizer in your browser:")
    print(f"  ares/visual/visualizer/index.html?ws=ws://localhost:{port}")
    print(f"\nWaiting for browser to connect... (Ctrl+C to stop)")

    # Wait for client
    wait = 0
    while emitter.client_count == 0 and wait < 60:
        await asyncio.sleep(0.5)
        wait += 0.5
        if int(wait) % 5 == 0 and wait > 0:
            print(f"  Still waiting... ({int(wait)}s)")

    if emitter.client_count == 0:
        print("No client connected after 60s. Streaming anyway.")
    else:
        print(f"Client connected! ({emitter.client_count} client(s))")
        await asyncio.sleep(1)  # Brief pause before starting

    # Stream events with timing
    prev_ts = 0
    for ts, event in events:
        if ts > prev_ts:
            delay_s = (ts - prev_ts) / 1000.0
            await asyncio.sleep(delay_s)

        payload = json.dumps(event.to_dict())
        if emitter._clients:
            await asyncio.gather(
                *(client.send(payload) for client in emitter._clients),
                return_exceptions=True,
            )

        # Console log
        etype = event.event_type
        if etype == 'scenario_start':
            sid = event.scenario_id
            name = getattr(event, 'scenario_name', '')
            print(f"\n  {sid}: {name}")
        elif etype == 'verdict_rendered':
            mark = '+' if event.correct else 'MISS'
            print(f"    -> {event.outcome} (conf={event.confidence:.2f}) [{mark}]")
        elif etype == 'accuracy_milestone':
            print(f"    accuracy: {event.scenarios_correct}/{event.scenarios_completed} "
                  f"({event.running_accuracy:.1%})")

        prev_ts = ts

    print(f"\nReplay complete. Server still running (Ctrl+C to stop).")

    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

    await emitter.stop()


def main(argv: Optional[list[str]] = None) -> None:
    """Entry point."""
    parser = build_parser()
    args = parser.parse_args(argv)

    results_path = Path(args.results)
    if not results_path.exists():
        print(f"ERROR: Results file not found: {results_path}")
        sys.exit(1)

    from ares.visual.benchmark_replayer import BenchmarkResultReplayer

    replayer = BenchmarkResultReplayer(str(results_path))

    if args.list_showcase:
        showcase = replayer.get_showcase_scenarios()
        data = replayer.load_results()
        by_id = {r["scenario_id"]: r for r in data["results"]}
        print(f"Showcase scenarios ({len(showcase)}):")
        for sid in showcase:
            r = by_id.get(sid, {})
            print(f"  {sid}: {r.get('verdict_outcome', '?')} "
                  f"(arch={r.get('architect_confidence', 0):.2f}, "
                  f"facts={r.get('total_facts_available', 0)})")
        return

    # Determine speed
    if args.speed is not None:
        speed = args.speed
    elif args.mode == "capture":
        speed = 0.3
    else:
        speed = 1.0

    # Generate events
    if args.scenario:
        print(f"Replaying: {args.scenario} (speed={speed}x)")
        events = replayer.replay_scenario(args.scenario, speed=speed)
    elif args.mode == "capture":
        showcase = replayer.get_showcase_scenarios()
        print(f"Content capture: {len(showcase)} showcase scenarios (speed={speed}x)")
        print(f"Scenarios: {', '.join(showcase)}")
        events = replayer.replay_all(speed=speed, scenario_ids=showcase)
    else:
        print(f"Demo: all {len(replayer.scenario_ids)} scenarios (speed={speed}x)")
        events = replayer.replay_all(speed=speed)

    print(f"Total events: {len(events)}")

    try:
        asyncio.run(_stream(events, args.port))
    except KeyboardInterrupt:
        print("\nShutdown.")


if __name__ == "__main__":
    main()
