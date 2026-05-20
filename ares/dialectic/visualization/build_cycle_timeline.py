"""CLI: read leakage-run traces.jsonl, write prism-timeline.json (v2).

Usage:
    python -m ares.dialectic.visualization.build_cycle_timeline \\
        --traces data/paper_3/leakage_runs/20260510-193950-f401a8/traces.jsonl \\
        --output docs/marketing/prism-timeline.json \\
        --run-id 20260510-193950-f401a8
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.cycle_trace import cycle_timeline_to_json
from ares.dialectic.visualization.cycle_trace_builder import build_cycle_timeline


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--traces", required=True, type=Path,
        help="Path to traces.jsonl from a leakage run",
    )
    parser.add_argument(
        "--output", required=True, type=Path,
        help="Where to write the v2 timeline JSON",
    )
    parser.add_argument(
        "--run-id", required=True, type=str,
        help="Run identifier embedded in the JSON",
    )
    args = parser.parse_args()

    try:
        timeline = build_cycle_timeline(args.traces, run_id=args.run_id)
    except FileNotFoundError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1
    except ValueError as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(cycle_timeline_to_json(timeline), encoding="utf-8")
    n = len(timeline.pairs)
    print(
        f"Wrote {n} pair{'s' if n != 1 else ''} to {args.output}"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
