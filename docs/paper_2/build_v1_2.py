"""Build PAPER2_DRAFT_v1_2.docx by integrating the v1.2 prose source.

The v1.2 build inherits all structural and rendering logic from
``build_v1_1.py``; it overrides only the default source and output
paths so that ``python -m docs.paper_2.build_v1_2`` produces the
v1.2 docx without a CLI flag dance. The v1.2 source contains one
additional Discussion paragraph (the data-integrity reframe) plus
two abstract/preamble counter updates ("four" -> "five" generalizable
observations) over the v1.1 source; structure, sections, and figure
placements are unchanged.

Usage::

    python -m docs.paper_2.build_v1_2
    python -m docs.paper_2.build_v1_2 \\
        --source docs/paper_2/source/PAPER2_DRAFT_v1_2_source.md \\
        --out docs/paper_2/PAPER2_DRAFT_v1_2.docx \\
        --figures-dir docs/paper_2/figures
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Iterable, Optional

from docs.paper_2.build_v1_1 import (
    REQUIRED_SECTION_IDS,
    build_document,
    parse_source,
)


# Re-exported for tests / downstream tooling that import from build_v1_2.
__all__ = ("REQUIRED_SECTION_IDS", "build_arg_parser", "main")


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Integrate Paper 2 v1.2 prose into the v1.1 build pipeline.",
    )
    parser.add_argument(
        "--source", type=Path,
        default=Path("docs/paper_2/source/PAPER2_DRAFT_v1_2_source.md"),
    )
    parser.add_argument(
        "--out", type=Path,
        default=Path("docs/paper_2/PAPER2_DRAFT_v1_2.docx"),
    )
    parser.add_argument(
        "--figures-dir", type=Path,
        default=Path("docs/paper_2/figures"),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    source = parse_source(args.source.resolve())
    doc = build_document(source, args.figures_dir.resolve())
    args.out.parent.mkdir(parents=True, exist_ok=True)
    doc.save(str(args.out))
    print(f"[V1.2 BUILD] wrote {args.out}")
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
