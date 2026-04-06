"""Live Analysis session export — v6 kill chain showcase.

Session 043: Extends run_live_export to support PT scenarios and v5 prompts.
Generates session JSON for kill chain visualizer (index_v6.html).

Usage:
    # Kill chain showcase (SC + PT mix)
    python -m ares.visual.scripts.run_live_export_v6 --mode showcase -o sessions/showcase_v6.json

    # Headless (no browser needed)
    python -m ares.visual.scripts.run_live_export_v6 --mode showcase -o sessions/showcase_v6.json --no-ws

    # Full corpus (39 scenarios)
    python -m ares.visual.scripts.run_live_export_v6 --mode full -o sessions/full_v6.json --max-cost 2.00

    # Then replay: index_v6.html?session=sessions/showcase_v6.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import time
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("ares.visual.live_export_v6")

# Curated showcase: mix of SC + PT for kill chain demo
SHOWCASE_V6_IDS = (
    "PT-001",  # Full kill chain: SQLi → root shell (all stages)
    "PT-002",  # Hardened target: recon only (blue only, DISMISSED)
    "PT-006",  # Failed exploits: tools ran, everything bounced
    "SC-002",  # Suspicious process chain: clear threat, no kill chain
    "SC-008",  # Benign AV update: Skeptic wins, DISMISSED
    "SC-010",  # Multi-vector campaign: 16 facts, dense graph
)

ESTIMATED_COST_PER_SCENARIO = 0.035


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ARES v6 session export — kill chain showcase",
    )
    parser.add_argument("--scenario", type=str, help="Single scenario ID")
    parser.add_argument("--scenarios", type=str, help="Comma-separated scenario IDs")
    parser.add_argument(
        "--mode", choices=["showcase", "pentagi", "full"],
        help="showcase=6 curated SC+PT, pentagi=6 PT, full=all 39",
    )
    parser.add_argument("--speed", type=float, default=1.0, help="Delay multiplier")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket port")
    parser.add_argument("--max-cost", type=float, default=5.00, help="Max API cost")
    parser.add_argument("--no-wait", action="store_true", help="Skip Enter prompt")
    parser.add_argument(
        "--output", "-o", type=str, required=True,
        help="Output path for session JSON",
    )
    parser.add_argument(
        "--no-ws", action="store_true",
        help="Headless mode — no WebSocket server",
    )
    return parser


PENTAGI_IDS = ("PT-001", "PT-002", "PT-003", "PT-004", "PT-005", "PT-006")


def _resolve_scenarios(args) -> List[str]:
    if args.scenario:
        return [args.scenario.upper()]
    if args.scenarios:
        return [s.strip().upper() for s in args.scenarios.split(",")]
    if args.mode == "showcase":
        return list(SHOWCASE_V6_IDS)
    if args.mode == "pentagi":
        return list(PENTAGI_IDS)
    if args.mode == "full":
        return []  # empty = all
    return list(SHOWCASE_V6_IDS)


async def _run(args) -> None:
    from ares.visual.live_emitter import LiveAnalysisEmitter

    # --- Load full corpus (SC + PT) ---
    from ares.dialectic.scripts.pentagi_scenarios import get_pentagi_corpus
    corpus = get_pentagi_corpus()
    by_id = {s.metadata.scenario_id: s for s in corpus}

    requested_ids = _resolve_scenarios(args)
    if not requested_ids:
        requested_ids = sorted(by_id.keys())

    scenarios = [by_id[sid] for sid in requested_ids if sid in by_id]
    missing = [sid for sid in requested_ids if sid not in by_id]
    if missing:
        print(f"[EXPORT-V6] WARNING: Not in corpus: {missing}")
    if not scenarios:
        print("[EXPORT-V6] ERROR: No valid scenarios")
        return

    estimated_cost = len(scenarios) * ESTIMATED_COST_PER_SCENARIO
    if estimated_cost > args.max_cost:
        print(f"[EXPORT-V6] ERROR: Est. ${estimated_cost:.2f} > limit ${args.max_cost:.2f}")
        return

    print(f"[EXPORT-V6] Scenarios: {len(scenarios)} (est. ${estimated_cost:.2f})")
    for s in scenarios:
        pt = "PT" if s.metadata.scenario_id.startswith("PT") else "SC"
        print(f"  [{pt}] {s.metadata.scenario_id}: {s.metadata.name} "
              f"({s.metadata.fact_count} facts)")

    # --- Load API key ---
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
        print("[EXPORT-V6] ERROR: ANTHROPIC_API_KEY not found")
        return

    # --- Build v5 strategies ---
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.llm_strategy_v5 import (
        LLMThreatAnalyzerV5,
        LLMExplanationFinderV5,
        LLMNarrativeGeneratorV5,
    )
    client = AnthropicClient(api_key=api_key)
    threat_analyzer = LLMThreatAnalyzerV5(client)
    explanation_finder = LLMExplanationFinderV5(client)
    narrative_generator = LLMNarrativeGeneratorV5(client)

    # --- Event capture ---
    session_events = []
    session_start_time = None
    ws_clients = set()

    async def capture_send(payload: str) -> None:
        nonlocal session_start_time
        now = time.time() * 1000
        if session_start_time is None:
            session_start_time = now
        event_data = json.loads(payload)
        session_events.append({
            "timestamp_ms": int(now - session_start_time),
            "event": event_data,
        })
        if ws_clients:
            await asyncio.gather(
                *(c.send(payload) for c in ws_clients),
                return_exceptions=True,
            )

    # --- Optional WebSocket ---
    server = None
    if not args.no_ws:
        import websockets

        async def handler(websocket, path=None):
            ws_clients.add(websocket)
            try:
                async for _ in websocket:
                    pass
            finally:
                ws_clients.discard(websocket)

        server = await websockets.serve(handler, "localhost", args.port)
        print(f"\n[EXPORT-V6] WebSocket on ws://localhost:{args.port}")
        print(f"[EXPORT-V6] Open: index_v6.html?ws=ws://localhost:{args.port}")

        wait = 0
        while not ws_clients and wait < 60:
            await asyncio.sleep(0.5)
            wait += 0.5

        if ws_clients:
            print(f"[EXPORT-V6] Browser connected!")
        else:
            print(f"[EXPORT-V6] No browser — proceeding headless")

        if not args.no_wait:
            print(f"\n[EXPORT-V6] Press Enter to begin...")
            await asyncio.get_event_loop().run_in_executor(None, input)
    else:
        print(f"\n[EXPORT-V6] Headless mode")

    # --- Run analysis ---
    emitter = LiveAnalysisEmitter(send_fn=capture_send, speed=args.speed)
    total_start = time.monotonic()

    for scenario in scenarios:
        meta = scenario.metadata
        print(f"\n[EXPORT-V6] {meta.scenario_id}: {meta.name} ({meta.fact_count} facts)")

        r = await emitter.analyze_scenario_live(
            scenario, threat_analyzer, explanation_finder, narrative_generator,
        )

        if r.error:
            print(f"[EXPORT-V6]   ERROR: {r.error}")
        else:
            mark = "correct" if r.correct else "MISS"
            print(f"[EXPORT-V6]   {r.duration_ms/1000:.1f}s | "
                  f"A:{r.architect_confidence:.4f} S:{r.skeptic_confidence:.4f} | "
                  f"{r.verdict_outcome.upper()} ({mark})")

        if scenario != scenarios[-1]:
            await asyncio.sleep(3.0 * args.speed)

    total_time = time.monotonic() - total_start
    correct = sum(1 for e in session_events
                  if e["event"].get("event_type") == "verdict_rendered"
                  and e["event"].get("correct"))
    total = sum(1 for e in session_events
                if e["event"].get("event_type") == "verdict_rendered")

    # --- Write session file ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    session = {
        "ares_version": "v6",
        "prompt_version": "v5",
        "captured_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "scenario_count": len(scenarios),
        "scenario_ids": [s.metadata.scenario_id for s in scenarios],
        "total_events": len(session_events),
        "duration_ms": int(total_time * 1000),
        "accuracy": f"{correct}/{total}" if total else "0/0",
        "events": session_events,
    }

    output_path.write_text(json.dumps(session, indent=2), encoding="utf-8")
    size_kb = output_path.stat().st_size / 1024
    print(f"\n[EXPORT-V6] === SESSION EXPORTED ===")
    print(f"[EXPORT-V6] File: {output_path}")
    print(f"[EXPORT-V6] Events: {len(session_events)} | Size: {size_kb:.1f} KB")
    print(f"[EXPORT-V6] Accuracy: {correct}/{total} | Time: {total_time:.1f}s")
    print(f"[EXPORT-V6]")
    print(f"[EXPORT-V6] To replay:")
    print(f"[EXPORT-V6]   index_v6.html?session={output_path}")

    if server:
        server.close()
        await server.wait_closed()


def main(argv: Optional[list] = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)
    logging.basicConfig(level=logging.WARNING)
    try:
        asyncio.run(_run(args))
    except KeyboardInterrupt:
        print("\n[EXPORT-V6] Shutdown.")


if __name__ == "__main__":
    main()
