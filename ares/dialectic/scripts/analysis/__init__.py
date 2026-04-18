"""Post-run analysis utilities for ARES benchmark outputs.

Each module in this package consumes the ``raw_results.json`` emitted
by a runner and produces aggregated tables, CSVs, and markdown
summaries. The modules never mutate the source of truth — they read
results, aggregate, and write separate artifacts.
"""
