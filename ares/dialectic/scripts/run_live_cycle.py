#!/usr/bin/env python3
"""ARES Live Dialectical Cycle Runner.

Runs a full LLM-powered dialectical cycle against real security telemetry
and displays detailed diagnostic output.

Usage:
    python -m ares.dialectic.scripts.run_live_cycle
    python -m ares.dialectic.scripts.run_live_cycle --multi-turn
    python -m ares.dialectic.scripts.run_live_cycle --rule-based
    python -m ares.dialectic.scripts.run_live_cycle --store

Requires ANTHROPIC_API_KEY environment variable (unless --rule-based).
"""

from __future__ import annotations

import argparse
import logging
import os
import sys


def build_sample_packet():
    """Build a realistic EvidencePacket for the privilege escalation scenario."""
    from ares.dialectic.scripts.sample_packets import build_privilege_escalation_packet
    return build_privilege_escalation_packet()


def run_single_turn(packet, *, use_llm=True, call_logger=None):
    """Run a single-turn dialectical cycle."""
    from ares.dialectic.agents.strategies.live_cycle import run_cycle_with_strategies

    if use_llm:
        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.llm_strategy import (
            LLMExplanationFinder,
            LLMNarrativeGenerator,
            LLMThreatAnalyzer,
        )

        client = AnthropicClient()
        return run_cycle_with_strategies(
            packet,
            threat_analyzer=LLMThreatAnalyzer(client, call_logger=call_logger),
            explanation_finder=LLMExplanationFinder(client, call_logger=call_logger),
            narrative_generator=LLMNarrativeGenerator(client, call_logger=call_logger),
        )
    else:
        return run_cycle_with_strategies(packet)


def run_multi_turn(packet, *, use_llm=True, call_logger=None, max_rounds=3):
    """Run a multi-turn dialectical cycle."""
    from ares.dialectic.agents.strategies.live_cycle import (
        run_multi_turn_with_strategies,
    )

    if use_llm:
        from ares.dialectic.agents.strategies.client import AnthropicClient
        from ares.dialectic.agents.strategies.llm_strategy import (
            LLMExplanationFinder,
            LLMNarrativeGenerator,
            LLMThreatAnalyzer,
        )

        client = AnthropicClient()
        return run_multi_turn_with_strategies(
            packet,
            threat_analyzer=LLMThreatAnalyzer(client, call_logger=call_logger),
            explanation_finder=LLMExplanationFinder(client, call_logger=call_logger),
            narrative_generator=LLMNarrativeGenerator(client, call_logger=call_logger),
            max_rounds=max_rounds,
        )
    else:
        return run_multi_turn_with_strategies(packet, max_rounds=max_rounds)


def print_diagnostics(call_logger, cycle_result):
    """Print detailed diagnostic output."""
    print("\n" + "=" * 70)
    print("ARES DIALECTICAL CYCLE — DIAGNOSTIC REPORT")
    print("=" * 70)

    # Print verdict
    print(f"\nVERDICT: {cycle_result.verdict.outcome.value}")
    print(f"Confidence: {cycle_result.verdict.confidence:.2f}")
    print(f"Architect confidence: {cycle_result.verdict.architect_confidence:.2f}")
    print(f"Skeptic confidence: {cycle_result.verdict.skeptic_confidence:.2f}")
    print(f"Reasoning: {cycle_result.verdict.reasoning}")

    # Print messages
    print(f"\n--- ARCHITECT MESSAGE ---")
    print(f"Phase: {cycle_result.architect_message.phase.value}")
    print(f"Confidence: {cycle_result.architect_message.confidence:.2f}")
    print(f"Assertions: {len(cycle_result.architect_message.assertions)}")
    for a in cycle_result.architect_message.assertions:
        print(f"  - {a.interpretation}")

    print(f"\n--- SKEPTIC MESSAGE ---")
    print(f"Phase: {cycle_result.skeptic_message.phase.value}")
    print(f"Confidence: {cycle_result.skeptic_message.confidence:.2f}")
    print(f"Assertions: {len(cycle_result.skeptic_message.assertions)}")
    for a in cycle_result.skeptic_message.assertions:
        print(f"  - {a.interpretation}")

    if cycle_result.narrator_message:
        print(f"\n--- NARRATOR MESSAGE ---")
        print(f"Narrative: {cycle_result.narrator_message.narrative}")

    # Print LLM call details
    if call_logger:
        print(f"\n--- LLM CALL LOG ({len(call_logger.records)} calls) ---")
        for i, record in enumerate(call_logger.records):
            print(f"\nCall {i+1}: {record.strategy_type}")
            print(f"  Model: {record.model}")
            print(f"  Latency: {record.latency_ms:.0f}ms")
            print(f"  Tokens: {record.input_tokens} in / {record.output_tokens} out")
            print(f"  Fallback used: {record.fallback_used}")
            if record.fallback_reason:
                print(f"  Fallback reason: {record.fallback_reason}")
            if record.validation_errors:
                print(f"  Validation errors ({len(record.validation_errors)}):")
                for err in record.validation_errors:
                    print(f"    - {err}")
            print(f"  Raw response (first 500 chars):")
            print(f"    {record.raw_response[:500]}")

        # Print summary
        summary = call_logger.summary()
        print(f"\n--- COST SUMMARY ---")
        print(f"Total calls: {summary['total_calls']}")
        print(
            f"Total tokens: {summary['total_input_tokens']} in / "
            f"{summary['total_output_tokens']} out"
        )
        print(f"Estimated cost: ${summary['estimated_cost_usd']:.6f}")
        print(f"Fallbacks: {summary['fallback_count']}")
        print(f"Errors: {summary['error_count']}")

    print(f"\nCycle duration: {cycle_result.duration_ms}ms")
    print("\n" + "=" * 70)


def main():
    parser = argparse.ArgumentParser(
        description="ARES Live Dialectical Cycle Runner"
    )
    parser.add_argument(
        "--multi-turn", action="store_true",
        help="Run multi-turn cycle",
    )
    parser.add_argument(
        "--rule-based", action="store_true",
        help="Run with rule-based strategies (baseline comparison)",
    )
    parser.add_argument(
        "--verbose", "-v", action="store_true",
        help="Enable verbose logging",
    )
    parser.add_argument(
        "--store", action="store_true",
        help="Store result in Memory Stream",
    )
    parser.add_argument(
        "--max-rounds", type=int, default=3,
        help="Max rounds for multi-turn (default: 3)",
    )
    args = parser.parse_args()

    # Configure logging
    level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=level,
        format="%(name)s | %(levelname)s | %(message)s",
    )

    # Check API key
    if not args.rule_based and not os.environ.get("ANTHROPIC_API_KEY"):
        print("ERROR: ANTHROPIC_API_KEY environment variable not set")
        print("Set it with: $env:ANTHROPIC_API_KEY = 'sk-ant-...'")
        sys.exit(1)

    # Build evidence
    print("Building sample evidence packet...")
    packet = build_sample_packet()
    print(f"Packet: {packet.packet_id} ({len(packet.facts)} facts)")

    # Create call logger
    call_logger = None
    if not args.rule_based:
        from ares.dialectic.agents.strategies.observability import LLMCallLogger
        call_logger = LLMCallLogger()

    # Run cycle
    use_llm = not args.rule_based
    mode = "multi-turn" if args.multi_turn else "single-turn"
    strategy = "LLM" if use_llm else "rule-based"
    print(f"Running {mode} cycle with {strategy} strategies...")

    if args.multi_turn:
        result = run_multi_turn(
            packet,
            use_llm=use_llm,
            call_logger=call_logger,
            max_rounds=args.max_rounds,
        )
    else:
        result = run_single_turn(
            packet,
            use_llm=use_llm,
            call_logger=call_logger,
        )

    # Print diagnostics
    print_diagnostics(call_logger, result)

    # Optionally store in Memory Stream
    if args.store:
        from ares.dialectic.memory.stream import MemoryStream
        from ares.dialectic.memory.backends.in_memory import InMemoryBackend

        stream = MemoryStream(backend=InMemoryBackend())
        entry = stream.store(result)
        print(f"\nStored in Memory Stream: entry_id={entry.entry_id}")
        print(f"Chain integrity: {stream.verify_chain_integrity()}")


if __name__ == "__main__":
    main()
