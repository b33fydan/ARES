"""Live Analysis Runner — real-time LLM visualization.

Session 039: Runs live LLM analysis on ARES scenarios and streams
events to the browser visualizer in real-time. The viewer watches
ARES think as it thinks — not a replay.

Usage:
    python -m ares.visual.scripts.run_live --scenario SC-010
    python -m ares.visual.scripts.run_live --scenario PT-001
    python -m ares.visual.scripts.run_live --mode showcase --speed 0.5
    python -m ares.visual.scripts.run_live --mode pentagi
    python -m ares.visual.scripts.run_live --mode full
    python -m ares.visual.scripts.run_live --scenarios PT-001,PT-003,PT-005
    python -m ares.visual.scripts.run_live --scenario SC-010 --max-cost 0.10
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import sys
import time
from typing import List, Optional

logger = logging.getLogger("ares.visual.live")

# Showcase scenario IDs — curated for visual impact
SHOWCASE_IDS = ("SC-001", "SC-005", "SC-010", "SC-016", "SC-018", "SC-027")

# PentAGI scenario IDs — pentest evidence through dialectical debate
PENTAGI_IDS = ("PT-001", "PT-002", "PT-003", "PT-004", "PT-005", "PT-006")

# Rough cost estimate per scenario (Claude Sonnet, ~2 calls per scenario)
ESTIMATED_COST_PER_SCENARIO = 0.035


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ARES Live Analysis — real-time LLM visualization",
    )
    parser.add_argument(
        "--scenario", type=str,
        help="Single scenario ID (e.g. SC-010)",
    )
    parser.add_argument(
        "--scenarios", type=str,
        help="Comma-separated scenario IDs (e.g. SC-002,SC-010,SC-018)",
    )
    parser.add_argument(
        "--mode", choices=["showcase", "pentagi", "full"],
        help="showcase = 6 curated SC scenarios, pentagi = 6 PT scenarios, full = all 39",
    )
    parser.add_argument(
        "--speed", type=float, default=1.0,
        help="Delay multiplier (0.5 = slower/dramatic, 2.0 = fast)",
    )
    parser.add_argument(
        "--port", type=int, default=8765,
        help="WebSocket server port (default: 8765)",
    )
    parser.add_argument(
        "--max-cost", type=float, default=5.00,
        help="Maximum estimated API cost in dollars (default: $5.00)",
    )
    parser.add_argument(
        "--no-wait", action="store_true",
        help="Don't wait for Enter before starting (for scripted use)",
    )
    return parser


def _resolve_scenarios(args) -> List[str]:
    """Resolve CLI args to a list of scenario IDs."""
    if args.scenario:
        return [args.scenario.upper()]
    if args.scenarios:
        return [s.strip().upper() for s in args.scenarios.split(",")]
    if args.mode == "showcase":
        return list(SHOWCASE_IDS)
    if args.mode == "pentagi":
        return list(PENTAGI_IDS)
    if args.mode == "full":
        return []  # empty = all
    # Default to showcase
    return list(SHOWCASE_IDS)


async def _run(args) -> None:
    """Core async runner."""
    import websockets
    from ares.visual.live_emitter import LiveAnalysisEmitter

    # --- Load corpus (SC + PT scenarios) ---
    from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_corpus
    corpus = get_pentagi_corpus()
    by_id = {s.metadata.scenario_id: s for s in corpus}

    requested_ids = _resolve_scenarios(args)
    if not requested_ids:
        requested_ids = sorted(by_id.keys())

    scenarios = []
    for sid in requested_ids:
        if sid not in by_id:
            print(f"[LIVE] WARNING: {sid} not found in corpus, skipping")
            continue
        scenarios.append(by_id[sid])

    if not scenarios:
        print("[LIVE] ERROR: No valid scenarios to analyze")
        return

    # --- Cost guard ---
    estimated_cost = len(scenarios) * ESTIMATED_COST_PER_SCENARIO
    if estimated_cost > args.max_cost:
        print(f"[LIVE] ERROR: Estimated cost ${estimated_cost:.2f} exceeds "
              f"--max-cost ${args.max_cost:.2f}")
        print(f"[LIVE] Raise the limit: --max-cost {estimated_cost + 1:.2f}")
        return

    print(f"[LIVE] Scenarios: {len(scenarios)} "
          f"(est. cost: ${estimated_cost:.2f}, limit: ${args.max_cost:.2f})")
    for s in scenarios:
        print(f"  {s.metadata.scenario_id}: {s.metadata.name} "
              f"({s.metadata.fact_count} facts)")

    # --- Load API key (env var first, then .env file) ---
    import os
    from pathlib import Path

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        env_path = Path(__file__).resolve().parent.parent.parent.parent / ".env"
        if env_path.exists():
            try:
                raw = env_path.read_bytes()
                for enc in ("utf-8", "utf-16"):
                    try:
                        text = raw.decode(enc)
                        for line in text.splitlines():
                            line = line.strip()
                            if line.startswith("ANTHROPIC_API_KEY="):
                                api_key = line.split("=", 1)[1].strip()
                                break
                        if api_key:
                            break
                    except (UnicodeDecodeError, ValueError):
                        continue
            except OSError:
                pass

    if not api_key:
        print("[LIVE] ERROR: ANTHROPIC_API_KEY not found in environment or .env file")
        return

    # --- Build LLM strategies ---
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.llm_strategy_v4 import (
        LLMThreatAnalyzerV4,
        LLMExplanationFinderV4,
        LLMNarrativeGeneratorV4,
    )

    try:
        client = AnthropicClient(api_key=api_key)
    except ValueError as e:
        print(f"[LIVE] ERROR: {e}")
        return

    threat_analyzer = LLMThreatAnalyzerV4(client)
    explanation_finder = LLMExplanationFinderV4(client)
    narrative_generator = LLMNarrativeGeneratorV4(client)

    # --- Start WebSocket server ---
    clients = set()

    async def handler(websocket, path=None):
        clients.add(websocket)
        logger.info("Client connected (%d total)", len(clients))
        try:
            async for _ in websocket:
                pass
        finally:
            clients.discard(websocket)

    server = await websockets.serve(handler, "localhost", args.port)
    print(f"\n[LIVE] WebSocket server started on ws://localhost:{args.port}")
    print(f"[LIVE] Open in browser:")
    print(f"  ares/visual/visualizer/index_v3.html?ws=ws://localhost:{args.port}")
    print(f"\n[LIVE] Waiting for browser connection...")

    # Wait for client
    wait = 0
    while not clients and wait < 120:
        await asyncio.sleep(0.5)
        wait += 0.5
        if int(wait) % 10 == 0 and wait > 0:
            print(f"  Still waiting... ({int(wait)}s)")

    if not clients:
        print("[LIVE] No client connected after 120s. Proceeding anyway.")
    else:
        print(f"[LIVE] Browser connected! ({len(clients)} client(s))")

    if not args.no_wait:
        print("\n[LIVE] Press Enter to begin live analysis...")
        await asyncio.get_event_loop().run_in_executor(None, input)

    # --- Send function ---
    async def send_to_all(payload: str) -> None:
        if clients:
            await asyncio.gather(
                *(c.send(payload) for c in clients),
                return_exceptions=True,
            )

    # --- Run live analysis ---
    emitter = LiveAnalysisEmitter(send_fn=send_to_all, speed=args.speed)
    total_start = time.monotonic()
    results = []

    for scenario in scenarios:
        meta = scenario.metadata
        print(f"\n[LIVE] {meta.scenario_id}: {meta.name} ({meta.fact_count} facts)")
        print(f"[LIVE]   Loading evidence... {meta.fact_count} facts streaming")

        sc_start = time.monotonic()
        r = await emitter.analyze_scenario_live(
            scenario, threat_analyzer, explanation_finder, narrative_generator,
        )
        results.append(r)

        if r.error:
            print(f"[LIVE]   ERROR: {r.error}")
        else:
            elapsed = r.duration_ms / 1000
            mark = "correct" if r.correct else "MISS"
            print(f"[LIVE]   Response received in {elapsed:.1f}s")
            print(f"[LIVE]   Architect: {r.architect_confidence:.4f} | "
                  f"Skeptic: {r.skeptic_confidence:.4f} | "
                  f"Delta: {r.architect_confidence - r.skeptic_confidence:+.2f}")
            print(f"[LIVE]   Verdict: {r.verdict_outcome.upper()} ({mark})")

        # Inter-scenario gap
        if scenario != scenarios[-1]:
            await asyncio.sleep(3.0 * args.speed)

    # --- Summary ---
    total_time = time.monotonic() - total_start
    correct_count = sum(1 for r in results if r.correct)
    total_count = len(results)
    accuracy = correct_count / total_count if total_count else 0

    print(f"\n[LIVE] === COMPLETE ===")
    print(f"[LIVE] Scenarios: {total_count} | "
          f"Correct: {correct_count}/{total_count} ({accuracy:.1%}) | "
          f"Time: {total_time:.1f}s")

    # Keep server alive
    print(f"\n[LIVE] Server still running (Ctrl+C to stop)")
    try:
        while True:
            await asyncio.sleep(1)
    except asyncio.CancelledError:
        pass

    server.close()
    await server.wait_closed()


def main(argv: Optional[list] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    logging.basicConfig(
        level=logging.WARNING,
        format="%(levelname)s %(name)s: %(message)s",
    )

    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[LIVE] Shutdown.")


if __name__ == "__main__":
    main()
