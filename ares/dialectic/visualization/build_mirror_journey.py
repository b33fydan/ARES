"""CLI: read an S084 dual-agent traces.jsonl, write mirror-journey.json.

Usage:
    python -m ares.dialectic.visualization.build_mirror_journey \\
        --traces data/paper_3/leakage_runs/20260605-194137-713674/traces.jsonl \\
        --output docs/marketing/mirror-journey.json \\
        --run-id 20260605-194137-713674
"""

import argparse
import sys
from pathlib import Path

from ares.dialectic.visualization.mirror_journey_builder import build_mirror_journey
from ares.dialectic.visualization.mirror_journey_schema import mirror_journey_to_json


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--traces", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--run-id", required=True, type=str)
    args = parser.parse_args()

    try:
        journey = build_mirror_journey(args.traces, run_id=args.run_id)
    except (FileNotFoundError, ValueError) as exc:
        print(f"ERROR: {exc}", file=sys.stderr)
        return 1

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(mirror_journey_to_json(journey), encoding="utf-8")
    print(f"Wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
