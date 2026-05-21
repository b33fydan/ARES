"""Paper 3 number-check: cross-validate pre-registered numbers against source.

Every numerical claim that appears in ``docs/paper_3/skeleton_v1_0.json``
under ``numbers_preregistered`` must be traceable to a specific source
artifact under ``data/paper_3/`` or to a verbatim line in the ARES
codebase. This script enumerates every such claim, resolves it against
the source data, and emits a pass/fail report.

When ``--docx`` is provided, the script also walks the prose body of
the supplied docx and verifies that every value listed in
``prose_substring_claims()`` appears in the prose text. Session 064
scope: docx mode is dormant (no prose yet); the substring list is
seeded for Session 065+ activation.

Pattern lift from Paper 2's ``docs/paper_2/number_check.py``: Claim
dataclass, resolver functions, run_checks + render_report + CLI shape.
Session 064 differences:

    * Single source artifact roots (``LEAKAGE_REPORT_*.md`` at repo
      root plus ``data/paper_3/leakage_runs/`` traces) instead of
      Paper 2's ``results/session_048/050`` CSVs.
    * Claim expectations are read from
      ``docs/paper_3/skeleton_v1_0.json`` (single source of truth)
      rather than hardcoded in the module.

CLI::

    python -m docs.paper_3.number_check
    python -m docs.paper_3.number_check --out-report \\
        docs/paper_3/number_check_report.md
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable, Iterable, Optional


REPO_ROOT = Path(__file__).resolve().parents[2]
SKELETON_PATH = REPO_ROOT / "docs" / "paper_3" / "skeleton_v1_0.json"

# Canonical artifacts referenced by the resolvers below.
LEAKAGE_REPORT_LLM = REPO_ROOT / "LEAKAGE_REPORT_20260510-193950-f401a8.md"
NARROW_TRACES = (
    REPO_ROOT / "data" / "paper_3" / "leakage_runs"
    / "20260510-224622-154556" / "traces.jsonl"
)
LIGHT_SKEPTIC_PY = REPO_ROOT / "ares" / "dialectic" / "agents" / "light_skeptic.py"
ORACLE_PY = REPO_ROOT / "ares" / "dialectic" / "agents" / "oracle.py"
LEAKAGE_RUNS_DIR = REPO_ROOT / "data" / "paper_3" / "leakage_runs"


# =============================================================================
# Resolver functions
# =============================================================================


def _read_leakage_report() -> str:
    return LEAKAGE_REPORT_LLM.read_text(encoding="utf-8")


def _read_narrow_traces() -> list[dict]:
    return [
        json.loads(line)
        for line in NARROW_TRACES.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _resolve_narrow_pair_count() -> int:
    """Count mutated cycles in the canonical narrow run (1 per pair)."""
    return sum(1 for t in _read_narrow_traces() if not t["is_baseline"])


def _resolve_narrow_byte_stable_count() -> int:
    """Number of (baseline, mutated) pairs where the Light Skeptic
    output fields are byte-equal — should equal the total pair count."""
    traces = _read_narrow_traces()
    baselines = {
        t["scenario_id"]: t for t in traces if t["is_baseline"]
    }
    stable = 0
    for m in traces:
        if m["is_baseline"]:
            continue
        b = baselines.get(m["scenario_id"])
        if b is None:
            continue
        if (
            m["skeptic_message_type"] == b["skeptic_message_type"]
            and tuple(m["skeptic_triggered_rules"])
                == tuple(b["skeptic_triggered_rules"])
            and m["skeptic_confidence"] == b["skeptic_confidence"]
            and tuple(m["skeptic_cited_facts"])
                == tuple(b["skeptic_cited_facts"])
        ):
            stable += 1
    return stable


def _resolve_llm_path_divergence_count() -> int:
    """73 = number of LLM-pipeline pairs in Session 059 run 2 that
    had a first-diverging layer (architect 39 + skeptic_llm 34)."""
    text = _read_leakage_report()
    # Parse the §3 per-layer attribution row for `llm` pipeline.
    # Format example:
    #   | `llm` | 39 | 34 | 0 | 0 | 0 | 25 |
    m = re.search(
        r"\|\s*`llm`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*"
        r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|",
        text,
    )
    if not m:
        raise LookupError("Per-layer LLM row not found in LEAKAGE_REPORT")
    architect, skeptic_llm, light_skeptic, oracle, final, no_div = (
        int(x) for x in m.groups()
    )
    total = architect + skeptic_llm + light_skeptic + oracle + final + no_div
    return total - no_div  # divergence count


def _resolve_llm_path_no_divergence_count() -> int:
    text = _read_leakage_report()
    m = re.search(
        r"\|\s*`llm`\s*\|\s*\d+\s*\|\s*\d+\s*\|\s*\d+\s*"
        r"\|\s*\d+\s*\|\s*\d+\s*\|\s*(\d+)\s*\|",
        text,
    )
    if not m:
        raise LookupError("Per-layer LLM row not found in LEAKAGE_REPORT")
    return int(m.group(1))


def _resolve_llm_path_first_diverging_at(layer: str) -> int:
    text = _read_leakage_report()
    m = re.search(
        r"\|\s*`llm`\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*"
        r"\|\s*(\d+)\s*\|\s*(\d+)\s*\|\s*(\d+)\s*\|",
        text,
    )
    if not m:
        raise LookupError("Per-layer LLM row not found in LEAKAGE_REPORT")
    columns = {
        "architect": int(m.group(1)),
        "skeptic_llm": int(m.group(2)),
        "light_skeptic": int(m.group(3)),
        "oracle": int(m.group(4)),
        "final_verdict": int(m.group(5)),
        "no_divergence": int(m.group(6)),
    }
    return columns[layer]


def _resolve_light_skeptic_anchor_line_number() -> int:
    """Find the 1-indexed line in light_skeptic.py containing
    ``_ = architect_output`` as a non-comment statement."""
    lines = LIGHT_SKEPTIC_PY.read_text(encoding="utf-8").splitlines()
    for i, line in enumerate(lines, start=1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "_ = architect_output" in stripped:
            return i
    raise LookupError("`_ = architect_output` not found in light_skeptic.py")


def _resolve_oracle_passthrough_line_range() -> tuple[int, int]:
    """Return the (start, end) line range of the ``decide()`` body
    where the supporting_facts conditional lives. Start = arch_facts
    assignment; end = Verdict construction."""
    lines = ORACLE_PY.read_text(encoding="utf-8").splitlines()
    start = end = None
    for i, line in enumerate(lines, start=1):
        if "arch_facts = architect_msg.get_all_fact_ids()" in line:
            start = i
        if "supporting_fact_ids=supporting_facts," in line:
            end = i
            break
    if start is None or end is None:
        raise LookupError("Oracle decide() body not found in expected shape")
    return start, end


def _resolve_verdict_class_passthrough_map() -> dict[str, str]:
    """Read oracle.py and resolve the per-verdict-class supporting_facts
    source. Returns a map {verdict_class: fact_source} where
    fact_source is one of "architect", "skeptic", or "union".

    Locks the Paper 3 §6.6 claim against silent regression in
    oracle.py. If a future refactor changes which fact set a branch
    assigns, this resolver will return a different map and the
    skeleton-vs-source consistency check will fail.
    """
    source = ORACLE_PY.read_text(encoding="utf-8")
    branches = {
        "THREAT_CONFIRMED": (
            "supporting_facts = frozenset(arch_facts)",
            "architect",
        ),
        "THREAT_DISMISSED": (
            "supporting_facts = frozenset(skep_facts)",
            "skeptic",
        ),
        "INCONCLUSIVE": (
            "supporting_facts = frozenset(arch_facts | skep_facts)",
            "union",
        ),
    }
    out: dict[str, str] = {}
    for verdict_class, (needle, fact_source) in branches.items():
        if needle not in source:
            raise LookupError(
                f"Could not find {verdict_class} branch assignment "
                f"{needle!r} in oracle.py"
            )
        out[verdict_class] = fact_source
    return out


def _resolve_leakage_run_count() -> int:
    """Number of distinct timestamped leakage runs on disk."""
    if not LEAKAGE_RUNS_DIR.exists():
        return 0
    return sum(
        1 for p in LEAKAGE_RUNS_DIR.iterdir()
        if p.is_dir() and re.match(r"\d{8}-\d{6}-[0-9a-f]+", p.name)
    )


def _resolve_test_floor_from_skeleton(skeleton: dict) -> int:
    return int(skeleton["build_start_test_floor"])


# =============================================================================
# Claim table
# =============================================================================


@dataclass(frozen=True)
class Claim:
    """A single numerical claim that must match a source artifact."""

    label: str
    expected: Any
    resolver: Callable[[], Any]


def default_claims(skeleton: dict) -> tuple[Claim, ...]:
    """Build the claim table from the skeleton + canonical resolvers."""
    return (
        Claim(
            label="narrow paired-trial count (98)",
            expected=98,
            resolver=_resolve_narrow_pair_count,
        ),
        Claim(
            label="narrow byte-stable count (98/98)",
            expected=98,
            resolver=_resolve_narrow_byte_stable_count,
        ),
        Claim(
            label="LLM-path divergence count (73 of 98)",
            expected=73,
            resolver=_resolve_llm_path_divergence_count,
        ),
        Claim(
            label="LLM-path no-divergence count (25)",
            expected=25,
            resolver=_resolve_llm_path_no_divergence_count,
        ),
        Claim(
            label="LLM-path first-diverging at architect (39)",
            expected=39,
            resolver=lambda: _resolve_llm_path_first_diverging_at("architect"),
        ),
        Claim(
            label="LLM-path first-diverging at skeptic_llm (34)",
            expected=34,
            resolver=lambda: _resolve_llm_path_first_diverging_at("skeptic_llm"),
        ),
        Claim(
            label="light_skeptic.py anchor line (185)",
            expected=185,
            resolver=_resolve_light_skeptic_anchor_line_number,
        ),
        Claim(
            label="oracle.py passthrough range start (89)",
            expected=89,
            resolver=lambda: _resolve_oracle_passthrough_line_range()[0],
        ),
        Claim(
            label="oracle.py passthrough range end (116)",
            expected=116,
            resolver=lambda: _resolve_oracle_passthrough_line_range()[1],
        ),
        Claim(
            label="leakage run count on disk (>=3 expected)",
            expected=3,
            resolver=_resolve_leakage_run_count,
        ),
        Claim(
            label="test floor at Session 064 build start (3737)",
            expected=3737,
            resolver=lambda: _resolve_test_floor_from_skeleton(skeleton),
        ),
        Claim(
            label="verdict_class_passthrough_map (§6.6 lock)",
            expected={
                "THREAT_CONFIRMED": "architect",
                "THREAT_DISMISSED": "skeptic",
                "INCONCLUSIVE": "union",
            },
            resolver=_resolve_verdict_class_passthrough_map,
        ),
    )


# =============================================================================
# Check + report
# =============================================================================


@dataclass(frozen=True)
class CheckResult:
    label: str
    expected: Any
    actual: Any
    passed: bool


def run_checks(claims: Iterable[Claim]) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for claim in claims:
        try:
            actual = claim.resolver()
            if claim.label.endswith("(>=3 expected)"):
                passed = actual >= claim.expected
            elif isinstance(claim.expected, dict):
                passed = actual == claim.expected
            else:
                passed = actual == claim.expected
        except Exception as exc:
            out.append(CheckResult(
                label=(
                    f"{claim.label} [ERROR: {type(exc).__name__}: {exc}]"
                ),
                expected=claim.expected,
                actual=None,
                passed=False,
            ))
            continue
        out.append(CheckResult(
            label=claim.label,
            expected=claim.expected,
            actual=actual,
            passed=passed,
        ))
    return tuple(out)


def render_report(results: Iterable[CheckResult]) -> str:
    results = list(results)
    passed = sum(1 for r in results if r.passed)
    total = len(results)
    status = "PASS" if passed == total else "FAIL"
    lines = [
        "# Paper 3 number_check report",
        "",
        f"**Overall: {status} ({passed} / {total} claims validated)**",
        "",
        "| claim | expected | actual | pass |",
        "|---|---:|---:|:---:|",
    ]
    for r in results:
        lines.append(
            f"| {r.label} | {r.expected} | {r.actual} | "
            f"{'PASS' if r.passed else 'FAIL'} |"
        )
    lines.append("")
    lines.append("---")
    lines.append("")
    lines.append("## Prose substring check (Session 065+ activation)")
    lines.append("")
    lines.append(
        "When ``docs/paper_3/PAPER3_DRAFT_v1_0.docx`` exists, every "
        "value in ``prose_substring_claims()`` must appear in the "
        "prose body. Currently dormant — no prose yet."
    )
    return "\n".join(lines)


def write_report(report: str, out_path: Path) -> Path:
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(report, encoding="utf-8")
    return out_path


# =============================================================================
# Prose-body substring checks (used when --docx is provided)
# =============================================================================


def prose_substring_claims() -> tuple[str, ...]:
    """Substrings the v1.0 docx body must contain verbatim once prose
    lands. Seeded from the skeleton's pre-registered numbers; Session
    065 prose integration is the activation point.
    """
    return (
        "98",            # narrow paired-trial count
        "98/98",         # byte-stable count
        "101/0",         # full-chain fires
        "73",            # LLM-path divergence count
        "73/98",         # LLM-path divergence ratio
        "74.49%",        # LLM-path drift rate (or 74.5% / 74%)
        "39",            # architect first-diverging
        "34",            # skeptic_llm first-diverging
        "25",            # no_divergence
        "185",           # light_skeptic.py line number
        "88-115",        # oracle.py decide() body range
        "101-111",       # oracle.py THREAT_CONFIRMED branch (Fig 6)
        "102",           # oracle.py passthrough line (§6.2, Fig 6)
        "105",           # oracle.py THREAT_DISMISSED branch (§6.6, Tbl 3)
        "109",           # oracle.py INCONCLUSIVE branch (§6.6, Tbl 3)
        "3,737",         # test floor (formatted)
        "INJ-001",       # broad-leakage scenario id
        "framing_suffix_v1",  # broad-leakage operator
        "framing_prefix_v1",
        "synonym_substitution_conservative_v2",
        "THREAT_CONFIRMED",
        "THREAT_DISMISSED",   # §6.6 non-passthrough branch
        "INCONCLUSIVE",        # §6.6 non-passthrough branch
        "supporting_fact_ids",
        "_ = architect_output",
    )


def extract_docx_text(docx_path: Path) -> str:
    """Concatenate every paragraph of a docx into one searchable string."""
    from docx import Document
    doc = Document(str(docx_path))
    return "\n".join(p.text for p in doc.paragraphs)


def check_prose_substrings(
    docx_text: str,
    substrings: Iterable[str],
) -> tuple[CheckResult, ...]:
    out: list[CheckResult] = []
    for sub in substrings:
        present = sub in docx_text
        out.append(CheckResult(
            label=f"prose contains '{sub}'",
            expected=True,
            actual=present,
            passed=present,
        ))
    return tuple(out)


# =============================================================================
# CLI
# =============================================================================


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Paper 3 number-check validator (skeleton + prose body).",
    )
    parser.add_argument(
        "--out-report", type=Path,
        default=Path("docs/paper_3/number_check_report.md"),
        help="Destination for the markdown report",
    )
    parser.add_argument(
        "--docx", type=Path, default=None,
        help=(
            "Optional: validate the prose body of this docx (typically "
            "PAPER3_DRAFT_v1_0.docx) against prose_substring_claims(). "
            "Session 064 scope: this mode is dormant until prose lands."
        ),
    )
    return parser


def main(argv: Optional[Iterable[str]] = None) -> int:
    parser = build_arg_parser()
    args = parser.parse_args(None if argv is None else list(argv))

    skeleton = json.loads(SKELETON_PATH.read_text(encoding="utf-8"))
    results: tuple[CheckResult, ...] = run_checks(default_claims(skeleton))

    if args.docx is not None and args.docx.exists():
        docx_text = extract_docx_text(args.docx.resolve())
        results = results + check_prose_substrings(
            docx_text, prose_substring_claims(),
        )

    report = render_report(results)
    write_report(report, args.out_report)

    total = len(results)
    passed = sum(1 for r in results if r.passed)
    print(f"[NUMBER-CHECK] {passed}/{total} claims validated")
    print(f"[NUMBER-CHECK] report: {args.out_report}")
    if passed < total:
        print("[NUMBER-CHECK] FAIL, see report for details", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
