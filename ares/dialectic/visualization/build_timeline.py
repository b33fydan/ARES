"""CLI: read Session 059 traces, write pinscreen-timeline.json.

Usage:
    python -m ares.dialectic.visualization.build_timeline \\
        --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \\
        --output docs/marketing/pinscreen-timeline.json
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.data_loader import load_run
from ares.dialectic.visualization.pin_mapper import map_pairs_to_pins
from ares.dialectic.visualization.timeline_builder import build_timeline, timeline_to_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", required=True, type=Path,
                        help="Path to traces.jsonl from a leakage run")
    parser.add_argument("--output", required=True, type=Path,
                        help="Where to write the timeline JSON")
    args = parser.parse_args()

    try:
        pairs = load_run(args.traces)
    except FileNotFoundError as e:
        print(f"ERROR: {e}", file=sys.stderr)
        return 1

    states = map_pairs_to_pins(pairs)
    timeline = build_timeline(states)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(timeline_to_json(timeline), encoding="utf-8")
    print(f"Wrote {len(timeline.pins)} pins to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
