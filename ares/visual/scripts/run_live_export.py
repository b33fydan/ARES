"""Live Analysis Runner with session export — capture once, replay forever.

Session 039+: Wraps run_live.py's analysis pipeline but captures every
WebSocket event into a JSON session file. The session file can be loaded
by the visualizer for zero-cost replay on any website.

Usage:
    # Run live + export session file
    python -m ares.visual.scripts.run_live_export --scenario SC-010 --output sessions/sc010.json

    # Run showcase + export
    python -m ares.visual.scripts.run_live_export --mode showcase --output sessions/showcase.json

    # Then load in browser (no API calls, no Python needed):
    # index_v5.html?session=sessions/showcase.json
"""

from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
import sys
import time
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("ares.visual.live_export")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="ARES Live Analysis with session export",
    )
    parser.add_argument("--scenario", type=str, help="Single scenario ID")
    parser.add_argument("--scenarios", type=str, help="Comma-separated scenario IDs")
    parser.add_argument("--mode", choices=["showcase", "full"], help="showcase=6, full=33")
    parser.add_argument("--speed", type=float, default=1.0, help="Delay multiplier")
    parser.add_argument("--port", type=int, default=8765, help="WebSocket port")
    parser.add_argument("--max-cost", type=float, default=5.00, help="Max API cost")
    parser.add_argument("--no-wait", action="store_true", help="Skip Enter prompt")
    parser.add_argument(
        "--output", "-o", type=str, required=True,
        help="Output path for session JSON (e.g. sessions/showcase.json)",
    )
    parser.add_argument(
        "--no-ws", action="store_true",
        help="Skip WebSocket server — just run analysis and export (headless)",
    )
    return parser


SHOWCASE_IDS = ("SC-001", "SC-005", "SC-010", "SC-016", "SC-018", "SC-027")
ESTIMATED_COST_PER_SCENARIO = 0.035


def _resolve_scenarios(args) -> List[str]:
    if args.scenario: return [args.scenario.upper()]
    if args.scenarios: return [s.strip().upper() for s in args.scenarios.split(",")]
    if args.mode == "showcase": return list(SHOWCASE_IDS)
    if args.mode == "full": return []
    return list(SHOWCASE_IDS)


async def _run(args) -> None:
    import websockets
    from ares.visual.live_emitter import LiveAnalysisEmitter

    # --- Load corpus ---
    from ares.dialectic.scripts.scenario_corpus_v2 import get_full_corpus_v2
    corpus = get_full_corpus_v2()
    by_id = {s.metadata.scenario_id: s for s in corpus}

    requested_ids = _resolve_scenarios(args)
    if not requested_ids:
        requested_ids = sorted(by_id.keys())

    scenarios = [by_id[sid] for sid in requested_ids if sid in by_id]
    if not scenarios:
        print("[EXPORT] ERROR: No valid scenarios"); return

    estimated_cost = len(scenarios) * ESTIMATED_COST_PER_SCENARIO
    if estimated_cost > args.max_cost:
        print(f"[EXPORT] ERROR: Est. ${estimated_cost:.2f} > limit ${args.max_cost:.2f}"); return

    print(f"[EXPORT] Scenarios: {len(scenarios)} (est. ${estimated_cost:.2f})")
    for s in scenarios:
        print(f"  {s.metadata.scenario_id}: {s.metadata.name} ({s.metadata.fact_count} facts)")

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
                        if api_key: break
                    except (UnicodeDecodeError, ValueError): continue
            except OSError: pass
    if not api_key:
        print("[EXPORT] ERROR: ANTHROPIC_API_KEY not found"); return

    # --- Build strategies ---
    from ares.dialectic.agents.strategies.client import AnthropicClient
    from ares.dialectic.agents.strategies.llm_strategy_v4 import (
        LLMThreatAnalyzerV4, LLMExplanationFinderV4, LLMNarrativeGeneratorV4,
    )
    client = AnthropicClient(api_key=api_key)
    threat_analyzer = LLMThreatAnalyzerV4(client)
    explanation_finder = LLMExplanationFinderV4(client)
    narrative_generator = LLMNarrativeGeneratorV4(client)

    # --- Event capture buffer ---
    session_events = []
    session_start_time = None

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
        # Also forward to WebSocket clients if server is running
        if ws_clients:
            await asyncio.gather(
                *(c.send(payload) for c in ws_clients),
                return_exceptions=True,
            )

    # --- Optional WebSocket server ---
    ws_clients = set()
    server = None

    if not args.no_ws:
        async def handler(websocket, path=None):
            ws_clients.add(websocket)
            try:
                async for _ in websocket: pass
            finally: ws_clients.discard(websocket)

        server = await websockets.serve(handler, "localhost", args.port)
        print(f"\n[EXPORT] WebSocket on ws://localhost:{args.port}")
        print(f"[EXPORT] Open: index_v5.html?ws=ws://localhost:{args.port}")
        print(f"[EXPORT] Waiting for browser...")

        wait = 0
        while not ws_clients and wait < 60:
            await asyncio.sleep(0.5); wait += 0.5

        if ws_clients:
            print(f"[EXPORT] Browser connected!")
        else:
            print(f"[EXPORT] No browser — proceeding (events still captured)")

        if not args.no_wait:
            print(f"\n[EXPORT] Press Enter to begin...")
            await asyncio.get_event_loop().run_in_executor(None, input)
    else:
        print(f"\n[EXPORT] Headless mode — no WebSocket server")

    # --- Run analysis ---
    emitter = LiveAnalysisEmitter(send_fn=capture_send, speed=args.speed)
    total_start = time.monotonic()

    for scenario in scenarios:
        meta = scenario.metadata
        print(f"\n[EXPORT] {meta.scenario_id}: {meta.name} ({meta.fact_count} facts)")

        r = await emitter.analyze_scenario_live(
            scenario, threat_analyzer, explanation_finder, narrative_generator,
        )

        if r.error:
            print(f"[EXPORT]   ERROR: {r.error}")
        else:
            mark = "correct" if r.correct else "MISS"
            print(f"[EXPORT]   {r.duration_ms/1000:.1f}s | "
                  f"A:{r.architect_confidence:.4f} S:{r.skeptic_confidence:.4f} | "
                  f"{r.verdict_outcome.upper()} ({mark})")

        if scenario != scenarios[-1]:
            await asyncio.sleep(3.0 * args.speed)

    total_time = time.monotonic() - total_start
    correct = sum(1 for e in session_events if e["event"].get("event_type") == "verdict_rendered" and e["event"].get("correct"))
    total = sum(1 for e in session_events if e["event"].get("event_type") == "verdict_rendered")

    # --- Write session file ---
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    session = {
        "ares_version": "v5",
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
    print(f"\n[EXPORT] === SESSION EXPORTED ===")
    print(f"[EXPORT] File: {output_path}")
    print(f"[EXPORT] Events: {len(session_events)} | Size: {size_kb:.1f} KB")
    print(f"[EXPORT] Accuracy: {correct}/{total} | Time: {total_time:.1f}s")
    print(f"[EXPORT]")
    print(f"[EXPORT] To replay (zero API cost, works on any website):")
    print(f"[EXPORT]   index_v5.html?session={output_path}")

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
        print("\n[EXPORT] Shutdown.")


if __name__ == "__main__":
    main()
