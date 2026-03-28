"""Multi-turn showcase runner — visualize debate evolution in the browser.

Session 037: Streams multi-turn benchmark results with per-round
confidence events. Shows how debate degrades accuracy in real-time.

Usage:
    python -m ares.visual.scripts.run_showcase_multiturn --speed 0.5
    python -m ares.visual.scripts.run_showcase_multiturn --scenario SC-001 --speed 0.3
    python -m ares.visual.scripts.run_showcase_multiturn --dry-run
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Optional


DEFAULT_RESULTS = "ares/dialectic/scripts/benchmark_results/multiturn_v2.json"


def build_parser() -> argparse.ArgumentParser:
    """Build the CLI argument parser."""
    parser = argparse.ArgumentParser(
        description="Multi-turn showcase — visualize debate evolution",
    )
    parser.add_argument(
        "--speed",
        type=float,
        default=0.5,
        help="Playback speed (default: 0.5x for cinematic pacing)",
    )
    parser.add_argument(
        "--scenario",
        type=str,
        help="Single scenario (e.g., SC-001)",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Print events to console instead of WebSocket",
    )
    parser.add_argument(
        "--results",
        type=str,
        default=DEFAULT_RESULTS,
        help="Path to multi-turn benchmark results JSON",
    )
    parser.add_argument(
        "--port",
        type=int,
        default=8765,
        help="WebSocket server port",
    )
    return parser


def _print_event(ts: int, event) -> None:
    """Print a single event to console."""
    d = event.to_dict()
    etype = d["event_type"]

    if etype == "scenario_start":
        print(f"\n{'=' * 60}")
        print(f"  {d['scenario_id']}: {d.get('scenario_name', '')} ({d.get('fact_count', 0)} facts)")
        print(f"  Expected: {d.get('expected_verdict', '')}")
        print(f"{'=' * 60}")
    elif etype == "fact_ingested":
        print(f"  [{ts:>6d}ms] fact: {d['fact_id']} ({d['source_type']})")
    elif etype == "round_start":
        print(f"  [{ts:>6d}ms] --- ROUND {d['round_number']}/{d['max_rounds']} ---")
    elif etype == "round_confidence":
        print(f"  [{ts:>6d}ms] R{d['round_number']}: "
              f"arch={d['architect_confidence']:.2f} skep={d['skeptic_confidence']:.2f}  "
              f"new_facts: arch={d['architect_new_facts']} skep={d['skeptic_new_facts']}")
    elif etype == "debate_evolution":
        traj = " -> ".join(f"({a:.2f}/{s:.2f})" for a, s in d["confidence_trajectory"])
        print(f"  [{ts:>6d}ms] EVOLUTION: {traj}")
        print(f"           {d['total_rounds']} rounds, terminated: {d['termination_reason']}")
    elif etype == "verdict_rendered":
        mark = "+" if d["correct"] else "MISS"
        print(f"  [{ts:>6d}ms] VERDICT: {d['outcome']} (conf={d['confidence']:.2f}) [{mark}]")
    elif etype == "accuracy_milestone":
        print(f"  [{ts:>6d}ms] accuracy: {d['scenarios_correct']}/{d['scenarios_completed']} "
              f"({d['running_accuracy']:.1%})")
    elif etype == "scenario_end":
        print(f"  [{ts:>6d}ms] --- end ---")


async def _stream(events, port: int) -> None:
    """Start WebSocket server and stream events."""
    from ares.visual.emitter import VisualEmitter

    emitter = VisualEmitter(port=port)
    await emitter.start()

    print(f"\nWebSocket server on ws://localhost:{port}")
    print(f"Open: ares/visual/visualizer/index.html?ws=ws://localhost:{port}")
    print("Waiting for browser... (Ctrl+C to stop)")

    wait = 0
    while emitter.client_count == 0 and wait < 60:
        await asyncio.sleep(0.5)
        wait += 0.5

    if emitter.client_count > 0:
        print(f"Client connected!")
        await asyncio.sleep(1)

    prev_ts = 0
    for ts, event in events:
        if ts > prev_ts:
            await asyncio.sleep((ts - prev_ts) / 1000.0)

        payload = json.dumps(event.to_dict())
        if emitter._clients:
            await asyncio.gather(
                *(client.send(payload) for client in emitter._clients),
                return_exceptions=True,
            )

        _print_event(ts, event)
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
        print("Run the multi-turn benchmark first:")
        print("  python -m ares.dialectic.scripts.run_037_multiturn_benchmark")
        sys.exit(1)

    from ares.visual.multiturn_replayer import MultiTurnReplayer

    replayer = MultiTurnReplayer(str(results_path))

    if args.scenario:
        print(f"Multi-turn replay: {args.scenario} (speed={args.speed}x)")
        events = replayer.replay_scenario(args.scenario, speed=args.speed)
    else:
        print(f"Multi-turn replay: all {len(replayer.scenario_ids)} scenarios (speed={args.speed}x)")
        events = replayer.replay_all(speed=args.speed)

    print(f"Total events: {len(events)}")

    if args.dry_run:
        print(f"\n--- DRY RUN ---\n")
        for ts, event in events:
            _print_event(ts, event)
        print(f"\n--- {len(events)} events ---")
    else:
        try:
            asyncio.run(_stream(events, args.port))
        except KeyboardInterrupt:
            print("\nShutdown.")


if __name__ == "__main__":
    main()
