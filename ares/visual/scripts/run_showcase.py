"""Showcase runner — content capture and demo replay for ARES visuals.

Session 035: Replays real benchmark results through the visual pipeline
for content capture (slow, cinematic) or demo playback (normal speed).

Usage:
    python -m ares.visual.scripts.run_showcase --mode capture --speed 0.3
    python -m ares.visual.scripts.run_showcase --mode demo --speed 1.0
    python -m ares.visual.scripts.run_showcase --scenario SC-010 --speed 0.5
    python -m ares.visual.scripts.run_showcase --list-showcase
    python -m ares.visual.scripts.run_showcase --scenario SC-010 --dry-run
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
        description="ARES Showcase Runner — content capture and demo replay",
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
        help="Playback speed override (default: 0.3 for capture, 1.0 for demo)",
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
        "--dry-run",
        action="store_true",
        help="Print events to console instead of WebSocket",
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


def _print_event(ts: int, event) -> None:
    """Print a single event to console."""
    d = event.to_dict()
    etype = d["event_type"]
    sid = d.get("scenario_id", "")

    if etype == "scenario_start":
        print(f"\n{'=' * 60}")
        print(f"  {sid}: {d.get('scenario_name', '')} ({d.get('fact_count', 0)} facts)")
        print(f"  Expected: {d.get('expected_verdict', '')}")
        print(f"{'=' * 60}")
    elif etype == "fact_ingested":
        print(f"  [{ts:>6d}ms] fact: {d['fact_id']} ({d['source_type']}, {d['field_name']})")
    elif etype == "fact_cited":
        role = d["agent_role"]
        n = len(d["fact_ids"])
        cov = d["coverage_ratio"]
        print(f"  [{ts:>6d}ms] {role} cited {n} facts (coverage: {cov:.0%})")
    elif etype == "confidence_update":
        print(f"  [{ts:>6d}ms] confidence: arch={d['architect_confidence']:.2f} "
              f"skep={d['skeptic_confidence']:.2f} delta={d['delta']:+.2f}")
    elif etype == "debate_summary":
        mark = "+" if d["is_correct"] else "X"
        print(f"  [{ts:>6d}ms] debate: {d['architect_assertion_count']} arch vs "
              f"{d['skeptic_assertion_count']} skep assertions")
    elif etype == "verdict_rendered":
        mark = "+" if d["correct"] else "X"
        print(f"  [{ts:>6d}ms] VERDICT: {d['outcome']} "
              f"(conf={d['confidence']:.2f}) [{mark}]")
    elif etype == "accuracy_milestone":
        print(f"  [{ts:>6d}ms] accuracy: {d['scenarios_correct']}/{d['scenarios_completed']} "
              f"({d['running_accuracy']:.1%})")
    elif etype == "scenario_end":
        print(f"  [{ts:>6d}ms] --- end ({d['duration_ms']}ms) ---")


async def _stream_events(events, port: int, speed: float) -> None:
    """Stream events via WebSocket with timing delays."""
    from ares.visual.emitter import VisualEmitter

    emitter = VisualEmitter(port=port)
    await emitter.start()
    print(f"WebSocket server running on ws://localhost:{port}")
    print("Waiting for clients... (Ctrl+C to stop)")
    await asyncio.sleep(2)

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

        _print_event(ts, event)
        prev_ts = ts

    print("\nReplay complete. Server still running (Ctrl+C to stop).")
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
    if not results_path.exists() and not args.list_showcase:
        print(f"ERROR: Results file not found: {results_path}")
        print("Run the v4 benchmark first or specify --results path")
        sys.exit(1)

    from ares.visual.benchmark_replayer import BenchmarkResultReplayer

    if args.list_showcase:
        if not results_path.exists():
            print(f"ERROR: Results file not found: {results_path}")
            sys.exit(1)
        replayer = BenchmarkResultReplayer(str(results_path))
        showcase = replayer.get_showcase_scenarios()
        print(f"Showcase scenarios ({len(showcase)}):")
        data = replayer.load_results()
        by_id = {r["scenario_id"]: r for r in data["results"]}
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

    replayer = BenchmarkResultReplayer(str(results_path))

    # Generate events
    if args.scenario:
        print(f"Replaying single scenario: {args.scenario} (speed={speed}x)")
        events = replayer.replay_scenario(args.scenario, speed=speed)
    elif args.mode == "capture":
        showcase = replayer.get_showcase_scenarios()
        print(f"Content capture mode: {len(showcase)} showcase scenarios (speed={speed}x)")
        events = replayer.replay_all(speed=speed, scenario_ids=showcase)
    else:
        print(f"Demo mode: all {len(replayer.scenario_ids)} scenarios (speed={speed}x)")
        events = replayer.replay_all(speed=speed)

    if args.dry_run:
        print(f"\n--- DRY RUN ({len(events)} events) ---\n")
        for ts, event in events:
            _print_event(ts, event)
        print(f"\n--- {len(events)} events total ---")
    else:
        try:
            asyncio.run(_stream_events(events, args.port, speed))
        except KeyboardInterrupt:
            print("\nShutdown.")


if __name__ == "__main__":
    main()
