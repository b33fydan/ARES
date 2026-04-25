"""Self-validating ground truth checks on CLAUDE.md.

CLAUDE.md is treated as the single source of truth for project state.
This module enforces that:

    * The file exists and parses.
    * It declares a test-count floor that holds against actual
      collection.
    * It declares canonical-artifact paths that exist on disk.
    * Its last-updated date is a parseable ISO date.

Drift in any of these surfaces here as a CI failure rather than as
silent stale documentation.

Adding new tests anywhere in the suite raises the actual collected
count, so the floor in CLAUDE.md is a *minimum* and is updated only
when tests are deliberately retired.
"""

from __future__ import annotations

import re
import subprocess
import sys
from datetime import date
from pathlib import Path

import pytest


REPO_ROOT = Path(__file__).resolve().parent.parent
CLAUDE_MD = REPO_ROOT / "CLAUDE.md"


# Markers expected in CLAUDE.md. These are the public contract
# between CLAUDE.md and downstream tooling (this test module, future
# session prompts, etc.). Changing the surface form requires updating
# the regex; changing the value requires updating CLAUDE.md.
_FLOOR_RE = re.compile(
    r"\*\*Test count floor \(passing\):\*\*\s*([\d,]+)",
)
_LAST_UPDATED_RE = re.compile(
    r"\*\*Last updated:\*\*\s*(\d{4}-\d{2}-\d{2})",
)
_CANONICAL_PATH_RE = re.compile(
    r"^\s*-\s+\*\*([^:*]+):\*\*\s+`([^`]+)`",
    re.MULTILINE,
)


@pytest.fixture(scope="module")
def claude_md_text() -> str:
    return CLAUDE_MD.read_text(encoding="utf-8")


def _parse_floor(text: str) -> int:
    m = _FLOOR_RE.search(text)
    if not m:
        raise ValueError(
            "Could not find '**Test count floor (passing):** N' marker "
            "in CLAUDE.md"
        )
    return int(m.group(1).replace(",", ""))


def _parse_last_updated(text: str) -> date:
    m = _LAST_UPDATED_RE.search(text)
    if not m:
        raise ValueError(
            "Could not find '**Last updated:** YYYY-MM-DD' marker in CLAUDE.md"
        )
    y, mo, d = m.group(1).split("-")
    return date(int(y), int(mo), int(d))


def _parse_canonical_paths(text: str) -> list[tuple[str, str]]:
    """Return (label, path) for every entry under '## Canonical Artifacts'."""
    section_match = re.search(
        r"## Canonical Artifacts\n(.*?)(?=\n## )",
        text, re.DOTALL,
    )
    if not section_match:
        raise ValueError(
            "Could not find '## Canonical Artifacts' section in CLAUDE.md"
        )
    return [
        (label.strip(), path.strip())
        for label, path in _CANONICAL_PATH_RE.findall(section_match.group(1))
    ]


def _collect_test_count() -> int:
    """Run pytest --collect-only on the canonical test paths."""
    result = subprocess.run(
        [
            sys.executable, "-m", "pytest",
            "tests/", "ares/dialectic/tests/",
            "--collect-only", "-q", "--no-header",
        ],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        timeout=180,
    )
    m = re.search(r"(\d[\d,]*)\s+tests?\s+collected", result.stdout)
    if not m:
        raise RuntimeError(
            "pytest --collect-only produced no parseable count.\n"
            f"stdout tail:\n{result.stdout[-2000:]}\n"
            f"stderr tail:\n{result.stderr[-2000:]}"
        )
    return int(m.group(1).replace(",", ""))


# ============================================================================
# Tests
# ============================================================================


def test_claude_md_exists_and_parses(claude_md_text):
    assert CLAUDE_MD.exists(), "CLAUDE.md not found at repo root"
    assert len(claude_md_text) > 500, "CLAUDE.md is suspiciously small"
    assert claude_md_text.startswith("# CLAUDE.md"), (
        "CLAUDE.md does not begin with the expected '# CLAUDE.md' header"
    )


def test_declared_test_floor_is_parseable_and_sane(claude_md_text):
    floor = _parse_floor(claude_md_text)
    assert 1000 < floor < 100_000, (
        f"Declared test floor {floor:,} is outside the sane range"
    )


def test_actual_test_count_meets_declared_floor(claude_md_text):
    """Drift prevention: deleting tests below the floor surfaces here."""
    floor = _parse_floor(claude_md_text)
    actual = _collect_test_count()
    assert actual >= floor, (
        f"Test count drift detected: CLAUDE.md declared floor of "
        f"{floor:,}, but pytest --collect-only found only {actual:,}. "
        f"Either restore the missing tests or, if removal was intentional, "
        f"update the floor in CLAUDE.md."
    )


def test_canonical_paths_exist_on_disk(claude_md_text):
    paths = _parse_canonical_paths(claude_md_text)
    assert paths, "## Canonical Artifacts section parsed empty"
    missing = [
        (label, p) for label, p in paths
        if not (REPO_ROOT / p).exists()
    ]
    assert not missing, (
        "Declared canonical paths are missing from disk:\n"
        + "\n".join(f"  - {label}: {p}" for label, p in missing)
    )


def test_last_updated_is_parseable_iso_date(claude_md_text):
    parsed = _parse_last_updated(claude_md_text)
    today = date.today()
    assert parsed <= today, (
        f"Last-updated date {parsed} is in the future relative to {today}"
    )
    assert parsed.year >= 2026, (
        f"Last-updated date {parsed} predates the project (Jan 2026)"
    )
